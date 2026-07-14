#include "wifi_manager.h"
#include "identity.h"
#include "log.h"
#include <WiFi.h>
#include <ESPmDNS.h>
#include <Preferences.h>
#include <esp_wifi.h>     // esp_wifi_set_country — kanały 12-13 (EU)
#include "data_sender.h"  // FW_VERSION

bool g_wifi_connected = false;
char g_wifi_ssid[64]  = {0};
char g_local_ip[16]   = {0};

// Region WiFi: bez tego ESP32 NIE widzi AP na kanałach 12-13 (legalne i częste w EU) →
// NO_AP_FOUND mimo działającego radia (potwierdzone: NerdMiner na tej samej płytce łączył się,
// nasz FW nie — bo nie ustawialiśmy regionu). "01"+MANUAL 1-13 = całe pasmo 2.4GHz, globalnie.
static void wifi_apply_country() {
    wifi_country_t c = { .cc = "01", .schan = 1, .nchan = 13, .max_tx_power = 78,
                         .policy = WIFI_COUNTRY_POLICY_MANUAL };
    esp_err_t e = esp_wifi_set_country(&c);
    if (e != ESP_OK) LOGW("wifi", "set_country: %d", (int)e);
}

bool wifi_has_config() {
    Preferences prefs;
    prefs.begin("sensmos_wifi", true);
    bool has = prefs.isKey("ssid");
    prefs.end();
    return has;
}

// TRIM SSID: apka/klawiatura telefonu potrafi dokleić spację/CR/LF na końcu (autocomplete).
// Zapisany "GladiLANtor " ≠ realny "GladiLANtor" → skan „NOT VISIBLE" + connect NO_AP_FOUND,
// mimo że AP jest o -16 dBm obok. (Diagnoza 2026-07-12, N16R8 gościa.) Whitespace = zawsze błąd
// w SSID. Hasła NIE trimujemy (spacja w haśle bywa poprawna).
static void trim_ws(char* s) {
    if (!s) return;
    size_t n = strlen(s);
    while (n && (s[n-1]==' '||s[n-1]=='\t'||s[n-1]=='\r'||s[n-1]=='\n')) s[--n] = 0;
    size_t i = 0; while (s[i]==' '||s[i]=='\t'||s[i]=='\r'||s[i]=='\n') i++;
    if (i) memmove(s, s+i, strlen(s+i)+1);
}
// Normalizacja do OSTATNIEJ deski ratunku przy dopasowaniu do WIDZIANEGO AP: usuń WSZYSTKIE
// białe znaki + lowercase (ASCII). Bezpieczne, bo i tak łączymy po BSSID realnie widzianego AP
// (nie po nazwie) — łapie „My Home WiFi" gdy user wpisał „MyHomeWiFi"/„myhome wifi" itp.
static void norm_ssid(char* dst, size_t dsz, const char* src) {
    size_t j = 0;
    for (size_t i = 0; src && src[i] && j + 1 < dsz; i++) {
        char ch = src[i];
        if (ch==' '||ch=='\t'||ch=='\r'||ch=='\n') continue;   // pomiń wszystkie spacje
        if (ch>='A'&&ch<='Z') ch = (char)(ch + 32);            // lowercase
        dst[j++] = ch;
    }
    dst[j] = 0;
}
// Usuń TYLKO spacje (wielkość liter ZACHOWANA) — do próby na UKRYTY SSID, który wymaga
// dokładnej nazwy: user mógł dokleić/pominąć spacje, ale case wpisał świadomie.
static void strip_spaces(char* dst, size_t dsz, const char* src) {
    size_t j = 0;
    for (size_t i = 0; src && src[i] && j + 1 < dsz; i++) {
        char ch = src[i];
        if (ch==' '||ch=='\t'||ch=='\r'||ch=='\n') continue;
        dst[j++] = ch;
    }
    dst[j] = 0;
}
void wifi_save_config(const char* ssid, const char* password) {
    char clean[64]; strncpy(clean, ssid ? ssid : "", sizeof(clean)-1); clean[sizeof(clean)-1]=0;
    trim_ws(clean);
    if (strcmp(clean, ssid ? ssid : "") != 0)
        LOGW("wifi", "SSID trimmed: '%s' -> '%s' (miał whitespace na brzegu)", ssid, clean);
    Preferences prefs;
    prefs.begin("sensmos_wifi", false);
    prefs.putString("ssid",     clean);
    prefs.putString("password", password);
    prefs.end();
    node_deleted_set(false);   // zapis nowego WiFi = re-onboarding → zdejmij flagę „deleted"
    LOGI("wifi", "config saved: '%s'", clean);
}

// Flaga „deleted" (owner skasował noda z apki; BE przysłał podpisaną komendę WS „deleted").
// Node TRZYMA tożsamość/klucze, ale bootuje prosto w BLE onboarding — czeka na ponowne dodanie.
// NS „sensmos" wspólny z boot_force_ble. Czyszczona przy zapisie nowego configu WiFi (wyżej).
bool node_deleted_get() {
    Preferences p; p.begin("sensmos", true);
    bool v = p.getBool("deleted", false); p.end();
    return v;
}
void node_deleted_set(bool v) {
    Preferences p; p.begin("sensmos", false);
    p.putBool("deleted", v); p.end();
}

void wifi_clear_config() {
    Preferences prefs;
    prefs.begin("sensmos_wifi", false);
    prefs.clear();
    prefs.end();
    LOGI("wifi", "config cleared");
}

// Zwraca kod: 0=OK, 1=zle haslo, 2=brak sieci(SSID), 3=timeout
int wifi_connect_result(const char* ssid, const char* password) {
    LOGI("wifi", "connecting to %s", ssid);
    // Reset WiFi stack przed próbą — usuwa stary stan
    WiFi.disconnect(true);   // rozłącz i wyczyść creds
    WiFi.mode(WIFI_OFF);
    delay(500);              // daj stackowi czas na reset
    WiFi.mode(WIFI_STA);
    WiFi.setSleep(false);
    wifi_apply_country();    // kanały 12-13 (EU) — inaczej NO_AP_FOUND na hotspotach EU
    delay(100);
    WiFi.begin(ssid, password);

    int attempts = 0;
    while (attempts < 24) {  // max ~12s
        wl_status_t st = WiFi.status();
        if (st == WL_CONNECTED) {
            g_wifi_connected = true;
            strncpy(g_wifi_ssid, ssid, sizeof(g_wifi_ssid));
            strncpy(g_local_ip, WiFi.localIP().toString().c_str(), sizeof(g_local_ip));
            LOGI("wifi", "connected, ip %s", g_local_ip);
            return 0;  // mDNS uruchomimy PO wysłaniu notify (mniej obciążenia naraz)
        }
        if (st == WL_CONNECT_FAILED) { LOGW("wifi", "wrong password"); return 1; }
        if (st == WL_NO_SSID_AVAIL)  { LOGW("wifi", "SSID not found"); return 2; }
        delay(500);
        attempts++;
    }
    LOGW("wifi", "connect timeout");
    return 3;
}

// Ostatni kod przyczyny rozłączenia (ESP-IDF wifi_err_reason_t) — do diagnozy „connect failed".
static volatile uint8_t g_last_disc_reason = 0;
static const char* wifi_reason_name(uint8_t r) {
    switch (r) {
        case 2:   return "AUTH_EXPIRE";
        case 4:   return "ASSOC_EXPIRE";
        case 15:  return "4WAY_HANDSHAKE_TIMEOUT/bad-password";
        case 201: return "NO_AP_FOUND (RF/antenna/wrong SSID/5GHz-only)";
        case 202: return "AUTH_FAIL (bad password)";
        case 203: return "ASSOC_FAIL";
        case 204: return "HANDSHAKE_TIMEOUT";
        case 205: return "CONNECTION_FAIL";
        default:  return "see esp_wifi_types.h";
    }
}
uint8_t wifi_last_disc_reason() { return g_last_disc_reason; }
// Czeka na połączenie do maxAttempts×500ms; true jeśli WL_CONNECTED.
static bool wifi_wait_connected(int maxAttempts) {
    int a = 0;
    while (WiFi.status() != WL_CONNECTED && a < maxAttempts) { delay(500); a++; }
    return WiFi.status() == WL_CONNECTED;
}

bool wifi_connect(const char* ssid, const char* password) {
    LOGI("wifi", "connecting to %s", ssid);
    if (WiFi.getMode() != WIFI_STA) WiFi.mode(WIFI_STA);
    WiFi.setSleep(false);
    wifi_apply_country();    // kanały 12-13 (EU)
    g_last_disc_reason = 0;
    static bool s_evt_reg = false;
    if (!s_evt_reg) {                 // złap reason z eventu STA_DISCONNECTED (raz)
        WiFi.onEvent([](arduino_event_id_t, arduino_event_info_t info) {
            g_last_disc_reason = info.wifi_sta_disconnected.reason;
        }, ARDUINO_EVENT_WIFI_STA_DISCONNECTED);
        s_evt_reg = true;
    }
    // Skan na CZYSTYM radiu PRZED connectem (skan PO begin zwracał fałszywe 0). ROBUST: łączymy
    // do AP który REALNIE widzimy — dopasowanie luźne (trim+case-insensitive), potem connect po
    // DOKŁADNYCH bajtach + BSSID + kanale tego AP. Omija każdą różnicę w SSID (spacja/unicode/
    // ukryty znak/literówka — po którejkolwiek stronie). Hex zapisanego SSID obnaża ukryty znak.
    WiFi.scanDelete();
    int n = WiFi.scanNetworks(false, true);
    LOGI("wifi", "scan: %d APs visible", n < 0 ? 0 : n);
    char want[64]; strncpy(want, ssid ? ssid : "", sizeof(want)-1); want[sizeof(want)-1]=0; trim_ws(want);
    { char hx[130] = ""; for (size_t k = 0; ssid && ssid[k] && k < 32; k++) sprintf(hx+strlen(hx), "%02X ", (uint8_t)ssid[k]);
      LOGI("wifi", "cfg SSID hex: %s(len %d)", hx, ssid ? (int)strlen(ssid) : 0); }
    // Dopasowanie 3-poziomowe do WIDZIANEGO AP (łączymy potem po jego BSSID):
    //   exact  = bajt-w-bajt,
    //   loose  = trim brzegów, case-SENSITIVE (whitespace na brzegach),
    //   fuzzy  = bez WSZYSTKICH spacji + lowercase (ostatnia deska — pomyłka w spacjach/wielkości).
    // Priorytet exact>loose>fuzzy; wśród pasujących (mesh/2 pasma) NAJSILNIEJSZY.
    // Nie łapie ukrytego SSID (w skanie pusty) — ten idzie fallbackiem WiFi.begin(dokładna nazwa).
    char wantN[64]; norm_ssid(wantN, sizeof(wantN), ssid);
    int exactIdx = -1, exactR = -999, looseIdx = -1, looseR = -999, fuzzyIdx = -1, fuzzyR = -999;
    for (int i = 0; i < n && i < 20; i++) {
        String s = WiFi.SSID(i);
        bool em = (s == ssid);
        char g[64]; strncpy(g, s.c_str(), sizeof(g)-1); g[sizeof(g)-1]=0; trim_ws(g);
        bool lm = !em && (strcmp(g, want) == 0);   // case-sensitive: nie łapie sąsiada o innym case
        char gN[64]; norm_ssid(gN, sizeof(gN), s.c_str());
        bool fm = !em && !lm && gN[0] && (strcmp(gN, wantN) == 0);   // bez spacji + lowercase
        int r = WiFi.RSSI(i);
        if (em && r > exactR) { exactIdx = i; exactR = r; }
        else if (lm && r > looseR) { looseIdx = i; looseR = r; }
        else if (fm && r > fuzzyR) { fuzzyIdx = i; fuzzyR = r; }
        LOGI("wifi", "  %s%s rssi=%d ch=%d enc=%d",
             em ? "*>" : (lm ? "~>" : (fm ? "?>" : "  ")), s.c_str(), r, WiFi.channel(i), (int)WiFi.encryptionType(i));
    }
    bool exact = (exactIdx >= 0);
    int matchIdx = exact ? exactIdx : (looseIdx >= 0 ? looseIdx : fuzzyIdx);   // exact>loose>fuzzy
    // Zapamiętaj dane dopasowanego AP PRZED scanDelete (potem WiFi.SSID/BSSID znikają)
    char apSsid[64] = ""; uint8_t apBssid[6] = {0}; int apCh = 0; bool haveMatch = (matchIdx >= 0);
    if (haveMatch) { strncpy(apSsid, WiFi.SSID(matchIdx).c_str(), sizeof(apSsid)-1);
                     memcpy(apBssid, WiFi.BSSID(matchIdx), 6); apCh = WiFi.channel(matchIdx); }
    LOGI("wifi", "target '%s' %s", ssid,
         exact ? "VISIBLE" : (haveMatch ? "LOOSE-MATCH — SSID różni się bajtowo, łączę po BSSID"
                                        : "NOT VISIBLE (5GHz-only? out of range? hidden?)"));
    WiFi.scanDelete();

    // ── Próby połączenia ──
    const char* connName = ssid;   // nazwa, którą realnie się połączyliśmy (do g_wifi_ssid)
    if (haveMatch && !exact) {
        LOGW("wifi", "connect via seen AP '%s' ch%d BSSID %02X:%02X:%02X:%02X:%02X:%02X (saved SSID byte-mismatch)",
             apSsid, apCh, apBssid[0],apBssid[1],apBssid[2],apBssid[3],apBssid[4],apBssid[5]);
        WiFi.begin(apSsid, password, apCh, apBssid);
        connName = apSsid;
    } else {
        WiFi.begin(ssid, password);   // dokładna nazwa — obsługuje też UKRYTY SSID (supplicant probuje)
    }
    bool ok = wifi_wait_connected(40);   // ~20s

    // UKRYTY SSID z inną liczbą spacji niż user wpisał: brak widocznego dopasowania + SSID ma
    // wewnętrzne spacje → próba bez spacji (case zachowany — ukryty AP wymaga dokładnej nazwy).
    // Jak zaskoczy, zapisz poprawioną nazwę → następny boot łączy od razu (bez tej próby).
    if (!ok && !haveMatch) {
        char noSp[64]; strip_spaces(noSp, sizeof(noSp), ssid);
        if (noSp[0] && strcmp(noSp, ssid) != 0) {
            LOGW("wifi", "hidden? retry bez spacji: '%s'", noSp);
            WiFi.disconnect(false); delay(200);
            WiFi.begin(noSp, password);
            ok = wifi_wait_connected(30);   // ~15s
            if (ok) {
                connName = noSp;
                Preferences p; p.begin("sensmos_wifi", false); p.putString("ssid", noSp); p.end();
                LOGI("wifi", "zapisano poprawioną nazwę SSID: '%s'", noSp);
            }
        }
    }

    if (ok && WiFi.status() == WL_CONNECTED) {
        g_wifi_connected = true;
        strncpy(g_wifi_ssid, connName, sizeof(g_wifi_ssid));
        strncpy(g_local_ip, WiFi.localIP().toString().c_str(), sizeof(g_local_ip));
        LOGI("wifi", "connected, ip %s", g_local_ip);
        wifi_setup_mdns();
        return true;
    }

    // reason= z eventu (wiarygodne — złe hasło daje 15, brak sieci 201). Skan wyżej (pre-connect).
    LOGW("wifi", "connect failed reason=%u (%s)", g_last_disc_reason, wifi_reason_name(g_last_disc_reason));
    g_wifi_connected = false;
    return false;
}

bool wifi_init() {
    if (!wifi_has_config()) {
        LOGW("wifi", "no config — needs BLE provisioning");
        return false;
    }

    Preferences prefs;
    prefs.begin("sensmos_wifi", true);
    char ssid[64]     = {0};
    char password[64] = {0};
    prefs.getString("ssid",     ssid,     sizeof(ssid));
    prefs.getString("password", password, sizeof(password));
    prefs.end();

    return wifi_connect(ssid, password);
}

// ── mDNS — wykrywalność w sieci lokalnej (dla apki) ───────────
void wifi_setup_mdns() {
    // Nazwa hosta: sensmos-XXXXXX (6 znaków device_id)
    char hostname[32];
    snprintf(hostname, sizeof(hostname), "sensmos-%.6s", g_device_id);

    if (MDNS.begin(hostname)) {
        // Ogłoś usługę sensmos przez mDNS
        MDNS.addService("sensmos", "tcp", 80);
        MDNS.addServiceTxt("sensmos", "tcp", "device_id", (const char*)g_device_id);
        MDNS.addServiceTxt("sensmos", "tcp", "version", (const char*)FW_VERSION);
        // Standardowy HTTP też
        MDNS.addService("http", "tcp", 80);
        LOGI("wifi", "mDNS: %s.local", hostname);
    } else {
        LOGW("wifi", "mDNS start failed");
    }
}