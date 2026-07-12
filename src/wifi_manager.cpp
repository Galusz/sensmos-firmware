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

void wifi_save_config(const char* ssid, const char* password) {
    Preferences prefs;
    prefs.begin("sensmos_wifi", false);
    prefs.putString("ssid",     ssid);
    prefs.putString("password", password);
    prefs.end();
    node_deleted_set(false);   // zapis nowego WiFi = re-onboarding → zdejmij flagę „deleted"
    LOGI("wifi", "config saved: %s", ssid);
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
    WiFi.begin(ssid, password);
    int attempts = 0;
    while (WiFi.status() != WL_CONNECTED && attempts < 60) {
        delay(500);
        attempts++;
    }

    if (WiFi.status() == WL_CONNECTED) {
        g_wifi_connected = true;
        strncpy(g_wifi_ssid, ssid, sizeof(g_wifi_ssid));
        strncpy(g_local_ip, WiFi.localIP().toString().c_str(), sizeof(g_local_ip));
        LOGI("wifi", "connected, ip %s", g_local_ip);
        wifi_setup_mdns();
        return true;
    }

    // On failure: print the reason code + a scan (sees any AP? is our SSID there? RSSI?) —
    // separates "sees no network" (RF/antenna, reason 201) from "can't authenticate" (auth).
    LOGW("wifi", "connect failed reason=%u (%s)", g_last_disc_reason, wifi_reason_name(g_last_disc_reason));
    int n = WiFi.scanNetworks(false, true);   // sync, include hidden
    LOGW("wifi", "scan: %d APs visible", n < 0 ? 0 : n);
    bool seen = false;
    for (int i = 0; i < n && i < 20; i++) {
        bool match = (WiFi.SSID(i) == ssid);
        if (match) seen = true;
        LOGW("wifi", "  %s%s rssi=%d ch=%d enc=%d",
             match ? "*>" : "  ", WiFi.SSID(i).c_str(), WiFi.RSSI(i), WiFi.channel(i), (int)WiFi.encryptionType(i));
    }
    LOGW("wifi", "target '%s' %s on 2.4GHz scan", ssid, seen ? "VISIBLE" : "NOT VISIBLE (5GHz-only? out of range? hidden?)");
    WiFi.scanDelete();
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