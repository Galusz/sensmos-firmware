/**
 * SENSMOS BLE Config v2 — z challenge-response
 *
 * Flow:
 *  1. auth {pin}
 *     → ESP generuje nonce (random + timestamp)
 *     → odpowiedź: {ok, device_id, nonce}
 *
 *  2. register {owner, sig_wallet, backend_url, ssid, password}
 *     sig_wallet = wallet.signMessage(nonce)
 *     → ESP weryfikuje sig (opcjonalnie), podpisuje nonce własnym kluczem
 *     → zapisuje config (WiFi, backend, owner)
 *     → odpowiedź: {ok, sig_esp, proof, pubkey_esp, message}
 *     → proof = sha256(nonce + sig_esp_hex + device_id)
 *
 *  3. App → Backend: POST /v1/register {message, sig_esp, sig_wallet, pubkey_esp, proof}
 *
 *  4. App disconnect BLE
 *     ESP zatrzymuje BLE, łączy WiFi
 *
 *  5. App skanuje mDNS → znajdzie node → POST /node/confirm
 *     Jeśli nie znajdzie (telefon w innej podsieci) — node i tak jest już
 *     zarejestrowany w BE (apka robi to przed mDNS od wersji 1.4.9)
 *
 *  6. ESP watchdog: 60 s po WiFi bez potwierdzenia → factory reset.
 *     Potwierdzenie = /node/confirm od apki LUB udany WS identify (0.64+)
 */

#include "ble_config.h"
#include "wifi_manager.h"
#include "identity.h"
#include "log.h"
#include <NimBLEDevice.h>
#include <ArduinoJson.h>
#include <Preferences.h>
#include <mbedtls/sha256.h>
#include <esp_random.h>

// ── Watchdog ──────────────────────────────────────────────────
// 60 s po WiFi na potwierdzenie onboardingu, potem factory reset. Potwierdzenie =
// lokalny POST /node/confirm od apki ALBO (0.64+) udany WS identify — skoro BE zna
// device i wpuścił, onboarding jest domknięty (apka mogła być w innej podsieci, mDNS głuchy)
static unsigned long s_wdg_deadline = 0;
static bool          s_wdg_active   = false;
static bool          s_wdg_confirmed= false;

void watchdog_start() {
    // Jeśli node był już potwierdzony wcześniej — nie resetuj
    Preferences p;
    p.begin("sensmos", true);
    bool already = p.getBool("node_confirmed", false);
    p.end();
    if (already) {
        s_wdg_active    = false;
        s_wdg_confirmed = true;
        LOGD("wdg", "node already confirmed — inactive");
        return;
    }
    s_wdg_deadline  = millis() + 60UL * 1000;  // 60 sekund
    s_wdg_active    = true;
    s_wdg_confirmed = false;
    LOGI("wdg", "armed — 60s for /node/confirm");
}
void watchdog_confirm() {
    // Idempotentne — wołane też z on_identified (każdy WS reconnect); bez guarda
    // pisalibyśmy NVS przy każdym połączeniu (zużycie flasha)
    if (s_wdg_confirmed) return;
    s_wdg_confirmed = true;
    // Zapisz do NVS — po restarcie nie potrzeba ponownego confirm
    Preferences p;
    p.begin("sensmos", false);
    p.putBool("node_confirmed", true);
    p.end();
    LOGI("wdg", "confirmed and saved to NVS");
}
void watchdog_tick() {
    if (!s_wdg_active || s_wdg_confirmed) return;
    if (millis() > s_wdg_deadline) {
        LOGW("wdg", "timeout — factory reset");
        Preferences p;
        p.begin("sensmos",      false); p.clear(); p.end();
        p.begin("sensmos_wifi", false); p.clear(); p.end();
        delay(500); ESP.restart();
    }
}

// ── Globals ───────────────────────────────────────────────────
bool g_ble_active       = false;
char g_owner_address[43]= {0};
char g_backend_url[128] = {0};

// ── Callback wywoływany gdy WiFi OK (ustawiany z .ino) ────────
static void (*s_on_wifi_ready)() = nullptr;
void ble_set_wifi_ready_cb(void (*cb)()) { s_on_wifi_ready = cb; }

// ── Internal ──────────────────────────────────────────────────
static NimBLEServer*      s_server       = nullptr;
static NimBLECharacteristic* s_char_r       = nullptr;
static NimBLECharacteristic* s_char_w       = nullptr;
static bool               s_connected    = false;
static bool               s_auth_ok      = false;
static bool               s_wifi_pending = false;
static bool               s_ble_initialized = false;
static char               s_pin[32]      = {0};
static char               s_nonce[65]    = {0};  // 32 bajty hex

// ── Trust ceremony (W2) ───────────────────────────────────────
// Rundy challenge-response (timing) + podpis atestu kluczem noda.
// App: trust_round xN → trust_sign {seed, owner} → evidence do BE.
#define TRUST_MAX_ROUNDS 8
// NVS namespace kopii portfela — przeżywa factory reset (czyszczone tylko ręcznie)
#define NVS_NS_WALLET "wallet_bak"
// budżet/rundę = max c (64) + r_hex (64); odporne na maks. długość challenge
#define ROUNDS_BUF_LEN (TRUST_MAX_ROUNDS * 128 + 1)
static char*         s_rounds_buf   = nullptr;   // heap w ble_start (RAM-AUDIT 0.49): w trybie
static int           s_rounds_count = 0;         // WiFi BLE nie działa, bufor byłby martwym .bss
static unsigned long s_ble_start_ms = 0;  // timeout powrotu do WiFi (re-atestacja)

// Duże bufory handlerów: task NimBLE ma ~4KB stosu (mbedTLS zjada 2-3KB), więc nie
// na stosie — ale zapisy BLE są sekwencyjne (request-response), handlery nie żyją
// naraz → UNIA zamiast osobnych static char[] (3.9KB → 1.6KB .bss).
// Heap w ble_start (nie .bss): BLE to osobny boot, w trybie WiFi unia byłaby martwa.
union BleBuf {
    struct { char resp[256]; } auth;
    struct { char message[256]; char sig_esp_hex[145]; char pubkey_hex[131];
             char proof_input[512]; char resp[512]; } reg;
    struct { char input[140]; } round;
    struct { char attest[480]; char sig_hex[145]; char pubkey_hex[131]; char resp[512]; } sign;
    struct { char resp[700]; } wallet;
};
static BleBuf* s_buf_p = nullptr;
#define s_buf (*s_buf_p)

// Rate limiter
static unsigned long s_req_times[10] = {0};
static int           s_req_idx = 0;
static bool rate_ok() {
    unsigned long now = millis();
    int n = 0;
    for (int i = 0; i < 10; i++)
        if (s_req_times[i] && now - s_req_times[i] < 60000) n++;
    s_req_times[s_req_idx++ % 10] = now;
    return n < 10;
}

// ── Helpers ───────────────────────────────────────────────────
static void notify(const char* json) {
    if (!s_char_r || !s_connected) return;
    s_char_r->setValue(json);
    s_char_r->notify();
    LOGD("ble", "-> %s", json);
}
static void ble_ok(const char* cmd) {
    char b[64]; snprintf(b, sizeof(b),
        "{\"status\":\"ok\",\"cmd\":\"%s\"}", cmd);
    notify(b);
}
static void ble_err(const char* cmd, const char* msg) {
    char b[96]; snprintf(b, sizeof(b),
        "{\"status\":\"error\",\"cmd\":\"%s\",\"msg\":\"%s\"}", cmd, msg);
    notify(b);
}

// ── Generuj nonce ─────────────────────────────────────────────
static void gen_nonce() {
    uint8_t rnd[32];
    esp_fill_random(rnd, 32);
    bytes_to_hex(rnd, 32, s_nonce);
}

// ── Load config ───────────────────────────────────────────────
static void load_config() {
    Preferences p; p.begin("sensmos", true);
    p.getString("ble_pin",       "").toCharArray(s_pin,           sizeof(s_pin));
    p.getString("owner_addr",    "").toCharArray(g_owner_address, sizeof(g_owner_address));
    p.getString("backend_url",   "").toCharArray(g_backend_url,   sizeof(g_backend_url));
    p.end();
    if (!strlen(s_pin)) strcpy(s_pin, "123456");
    if (!strlen(g_backend_url)) strcpy(g_backend_url, "https://api.sensmos.com/v1");
}

// ── Callbacks ─────────────────────────────────────────────────
class ConnCB : public NimBLEServerCallbacks {
    void onConnect(NimBLEServer*, NimBLEConnInfo&) override {
        s_connected = true; s_auth_ok = false;
        LOGI("ble", "connected");
    }
    void onDisconnect(NimBLEServer*, NimBLEConnInfo&, int) override {
        s_connected = false; s_auth_ok = false;
        if (g_ble_active && !s_wifi_pending) {
            delay(100);
            NimBLEDevice::startAdvertising();
            LOGD("ble", "advertising resumed");
        }
    }
};

// Kolejka 1-slotowa: callback NimBLE NIE robi zadnej roboty — task hosta NimBLE ma
// ~4KB stosu, a JSON+mbedTLS (trust_sign/register: podpis ECDSA = 2-3KB stosu) go
// przepelnialy na klasycznym ESP32 (Guru Meditation: Double exception przy 191B
// trust_sign; S3 przezywal, bo mial wiecej luzu). Obsluga w ble_tick() = loop task (8KB).
// Protokol jest request-response, wiec 1 slot wystarcza (busy = apka i tak czeka).
#define CMD_BUF_LEN 576
static char*         s_cmd_buf = nullptr;   // heap w ble_start (RAM-AUDIT 0.49)
static volatile bool s_cmd_pending = false;

class WriteCB : public NimBLECharacteristicCallbacks {
    void onWrite(NimBLECharacteristic* ch, NimBLEConnInfo&) override {
        NimBLEAttValue val = ch->getValue();
        if (!val.length()) return;
        if (s_cmd_pending) { LOGW("ble", "busy — write rejected"); return; }
        size_t n = val.length() < CMD_BUF_LEN - 1 ? val.length() : CMD_BUF_LEN - 1;
        memcpy(s_cmd_buf, val.data(), n);
        s_cmd_buf[n] = 0;
        s_cmd_pending = true;
    }
};

// Wlasciwa obsluga komendy — wolane WYLACZNIE z ble_tick() (loop task, 8KB stosu)
static void ble_process_cmd() {
        if (!rate_ok()) { ble_err("?", "rate_limit"); return; }
        LOGD("ble", "<- (%d B)", (int)strlen(s_cmd_buf));

        JsonDocument doc;
        if (deserializeJson(doc, s_cmd_buf)) { ble_err("?", "invalid_json"); return; }
        const char* cmd = doc["cmd"];
        if (!cmd) { ble_err("?", "no_cmd"); return; }

        // ── factory_reset ────────────────────────────────────
        if (!strcmp(cmd, "factory_reset")) {
            ble_ok(cmd); delay(300);
            Preferences p;
            p.begin("sensmos",      false); p.clear(); p.end();
            p.begin("sensmos_wifi", false); p.clear(); p.end();
            p.begin("sensmos_api",  false); p.clear(); p.end();
            delay(500); ESP.restart();
        }

        // ── auth {pin} ────────────────────────────────────────
        // Odpowiedź: {ok, device_id, nonce}
        if (!strcmp(cmd, "auth")) {
            const char* pin = doc["pin"];
            if (!pin) { ble_err(cmd, "missing_pin"); return; }

            bool first;
            { Preferences p; p.begin("sensmos",true); first = !p.isKey("ble_pin"); p.end(); }

            if (first) {
                Preferences p; p.begin("sensmos",false);
                p.putString("ble_pin", pin); p.end();
                strncpy(s_pin, pin, sizeof(s_pin)-1);
            } else if (strcmp(pin, s_pin)) {
                ble_err(cmd, "wrong_pin"); return;
            }

            s_auth_ok = true;
            gen_nonce();  // świeży nonce przy każdym auth
            s_rounds_buf[0] = '\0';  // świeża ceremonia trust
            s_rounds_count  = 0;

            char* resp = s_buf.auth.resp;
            snprintf(resp, sizeof(s_buf.auth.resp),
                "{\"status\":\"ok\",\"cmd\":\"auth\","
                "\"device_id\":\"%s\","
                "\"nonce\":\"%s\","
                "\"first_time\":%s}",
                g_device_id, s_nonce, first ? "true" : "false");
            notify(resp);
            return;
        }

        if (!s_auth_ok) { ble_err(cmd, "not_authenticated"); return; }

        // ── set_device_id {id} — odtworzenie ID po reflashu (apka pamięta MAC↔ID) ──
        // Node adoptuje POPRZEDNIE device_id (stała tożsamość), klucze zostają świeże —
        // rejestracja pod starym ID z nowym pubkey (BE unieważnia trust przy zmianie klucza).
        // MUSI przyjść PRZED register (sig/proof budowane z g_device_id).
        if (!strcmp(cmd, "set_device_id")) {
            const char* id = doc["id"];
            if (!id || !identity_set_override(id)) { ble_err(cmd, "bad_id"); return; }
            // Podmień nazwę BLE na SENSMOS-<nowe ID> — nazwa jest liczona z device_id, a atest
            // sprawdza SENSMOS-<device_id[:6]>. Bez tego restore = ble_name_mismatch. Aktualizujemy
            // GAP name (0x2A00) i nazwę w advertisingu; apka bierze nową nazwę z odpowiedzi.
            char newName[24];
            snprintf(newName, sizeof(newName), "SENSMOS-%.6s", g_device_id);
            NimBLEDevice::setDeviceName(newName);
            NimBLEDevice::getAdvertising()->setName(newName);
            char resp[160];
            snprintf(resp, sizeof(resp),
                "{\"status\":\"ok\",\"cmd\":\"set_device_id\",\"device_id\":\"%s\",\"ble_name\":\"%s\"}",
                g_device_id, newName);
            notify(resp);
            return;
        }

        // ── register {owner, sig_wallet, backend_url, ssid, password} ──
        // Zawiera wszystko — challenge + config + WiFi w jednej komendzie
        if (!strcmp(cmd, "register")) {
            const char* owner       = doc["owner"];
            const char* sig_wallet  = doc["sig_wallet"];
            const char* backend_url = doc["backend_url"];
            const char* ssid        = doc["ssid"];
            const char* password    = doc["password"] | "";

            if (!owner || strlen(owner) < 20) { ble_err(cmd, "missing_owner"); return; }
            if (!sig_wallet)                   { ble_err(cmd, "missing_sig_wallet"); return; }
            if (!ssid || !strlen(ssid))        { ble_err(cmd, "missing_ssid"); return; }
            if (!backend_url || strlen(backend_url) < 7) { ble_err(cmd, "missing_backend"); return; }

            // Zapisz konfigurację
            strncpy(g_owner_address, owner,       sizeof(g_owner_address)-1);
            strncpy(g_backend_url,   backend_url, sizeof(g_backend_url)-1);
            wifi_save_config(ssid, password);
            LOGI("ble", "config: backend=%s ssid=%s owner=%.10s...", backend_url, ssid, owner);

            Preferences p; p.begin("sensmos", false);
            p.putString("owner_addr",  owner);
            p.putString("backend_url", backend_url);
            p.end();

            // ── Challenge-Response ────────────────────────────
            // Zbuduj message NAJPIERW — to on zostanie podpisany
            // Backend weryfikuje: verify(message, sig_esp, pubkey_esp)
            // Duże bufory STATIC — task BLEWriteCB (NimBLE) ma tylko 4096 B stosu, a
            // identity_sign (mbedTLS secp256k1) sam zżera ~2-3KB. Zapisy BLE są sekwencyjne
            // (request-response), więc współdzielenie static jest bezpieczne.
            char* message = s_buf.reg.message;
            snprintf(message, sizeof(s_buf.reg.message),
                "{\"device_id\":\"%s\",\"owner\":\"%s\","
                "\"nonce\":\"%s\",\"ts\":0}",
                g_device_id, owner, s_nonce);

            // ESP podpisuje sha256(message) — identycznie jak backend weryfikuje
            uint8_t msg_hash[32];
            sha256_string(message, msg_hash);

            uint8_t sig_raw[72]; size_t sig_len = 0;
            char* sig_esp_hex = s_buf.reg.sig_esp_hex; sig_esp_hex[0] = 0;
            if (identity_sign(msg_hash, sig_raw, &sig_len)) {
                bytes_to_hex(sig_raw, sig_len, sig_esp_hex);
            }

            // Pubkey ESP
            char* pubkey_hex = s_buf.reg.pubkey_hex;
            identity_get_pubkey_hex(pubkey_hex, sizeof(s_buf.reg.pubkey_hex));

            // proof = sha256(nonce + sig_esp_hex + device_id)
            char* proof_input = s_buf.reg.proof_input;
            snprintf(proof_input, sizeof(s_buf.reg.proof_input), "%s%s%s",
                s_nonce, sig_esp_hex, g_device_id);
            uint8_t proof_hash[32];
            sha256_string(proof_input, proof_hash);
            char proof_hex[65] = {0};
            bytes_to_hex(proof_hash, 32, proof_hex);

            // Odpowiedź do apki — minimalna (mieści się w MTU 512)
            // sig_wallet apka już ma, message apka rekonstruuje z known fields
            // Wysyłamy tylko: sig_esp, pubkey_esp, proof, ts
            char* resp = s_buf.reg.resp;
            snprintf(resp, sizeof(s_buf.reg.resp),
                "{\"status\":\"ok\",\"cmd\":\"register\","
                "\"sig_esp\":\"%s\","
                "\"pubkey_esp\":\"%s\","
                "\"proof\":\"%s\","
                "\"ts\":%lu}",
                sig_esp_hex, pubkey_hex, proof_hex, millis()/1000);

            LOGD("ble", "register resp: %d B", strlen(resp));
            // Wyślij wielokrotnie z dłuższym delay — apka musi odebrać PRZED restartem
            for (int i = 0; i < 5; i++) { notify(resp); delay(500); }
            delay(500);  // dodatkowy bufor

            LOGD("ble", "challenge ok — proof: %.16s...", proof_hex);

            // Trigger WiFi w loop()
            s_wifi_pending = true;
            return;
        }

        // ── trust_round {c} — runda timing challenge-response ──
        // r = sha256(c + device_id); rundy akumulowane do digestu
        // podpisywanego w trust_sign. Szybka odpowiedź (sam sha256)
        // — apka mierzy czas rundy, BE odrzuca wolne (proxy).
        if (!strcmp(cmd, "trust_round")) {
            const char* c = doc["c"];
            if (!c || strlen(c) < 16 || strlen(c) > 64) {
                ble_err(cmd, "bad_challenge"); return;
            }
            if (s_rounds_count >= TRUST_MAX_ROUNDS) {
                ble_err(cmd, "too_many_rounds"); return;
            }

            char* input = s_buf.round.input;
            snprintf(input, sizeof(s_buf.round.input), "%s%s", c, g_device_id);
            uint8_t h[32];
            sha256_string(input, h);
            char r_hex[65];
            bytes_to_hex(h, 32, r_hex);

            // Akumuluj c+r do digestu rund
            size_t used = strlen(s_rounds_buf);
            snprintf(s_rounds_buf + used, ROUNDS_BUF_LEN - used,
                     "%s%s", c, r_hex);
            s_rounds_count++;

            char resp[128];
            snprintf(resp, sizeof(resp),
                "{\"status\":\"ok\",\"cmd\":\"trust_round\",\"r\":\"%s\",\"i\":%d}",
                r_hex, s_rounds_count);
            notify(resp);
            return;
        }

        // ── trust_sign {seed, owner, resume?} — podpis atestu ──
        // Node podpisuje kanoniczny atest; apka i BE rekonstruują
        // identyczny string z pól odpowiedzi (jak przy register).
        if (!strcmp(cmd, "trust_sign")) {
            const char* seed   = doc["seed"];
            const char* owner  = doc["owner"];
            bool        resume = doc["resume"] | false;
            if (!seed || strlen(seed) < 16 || strlen(seed) > 64) {
                ble_err(cmd, "bad_seed"); return;
            }
            if (!owner || strlen(owner) < 20) {
                ble_err(cmd, "missing_owner"); return;
            }

            // Nonce ceremonii — 8B
            uint8_t nrnd[8]; char nonce_hex[17];
            esp_fill_random(nrnd, 8);
            bytes_to_hex(nrnd, 8, nonce_hex);

            // Digest rund ("-" gdy brak)
            char rounds_hex[65];
            if (s_rounds_count > 0) {
                uint8_t rh[32];
                sha256_string(s_rounds_buf, rh);
                bytes_to_hex(rh, 32, rounds_hex);
            } else {
                strcpy(rounds_hex, "-");
            }

            // MAC-i: BLE (widziany z powietrza przez apkę) + bazowy eFuse
            uint8_t mac[6];
            esp_read_mac(mac, ESP_MAC_BT);
            char ble_mac[18];
            snprintf(ble_mac, sizeof(ble_mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                     mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
            esp_read_mac(mac, ESP_MAC_WIFI_STA);
            char efuse_mac[13];
            bytes_to_hex(mac, 6, efuse_mac);

            unsigned long up = millis() / 1000;

            // GPS (opcjonalny) — jako STRINGI, wstawiane verbatim (bez re-formatowania float,
            // inaczej podpis by sie rozjechal miedzy FW/APP/BE). Obecny → atest v2, brak → v1.
            const char* gps_lat = doc["gps_lat"] | "";
            const char* gps_lon = doc["gps_lon"] | "";
            bool has_gps = strlen(gps_lat) > 0 && strlen(gps_lon) > 0 &&
                           strlen(gps_lat) < 16 && strlen(gps_lon) < 16;

            // Kanoniczny atest — DOKŁADNIE ten string weryfikuje BE (static: patrz register)
            char* attest = s_buf.sign.attest;
            if (has_gps) {
                snprintf(attest, sizeof(s_buf.sign.attest),
                    "{\"v\":2,\"device_id\":\"%s\",\"owner\":\"%s\","
                    "\"seed\":\"%s\",\"nonce\":\"%s\",\"ble_mac\":\"%s\","
                    "\"efuse_mac\":\"%s\",\"rounds\":\"%s\",\"uptime_s\":%lu,"
                    "\"gps_lat\":\"%s\",\"gps_lon\":\"%s\"}",
                    g_device_id, owner, seed, nonce_hex, ble_mac,
                    efuse_mac, rounds_hex, up, gps_lat, gps_lon);
            } else {
                snprintf(attest, sizeof(s_buf.sign.attest),
                    "{\"v\":1,\"device_id\":\"%s\",\"owner\":\"%s\","
                    "\"seed\":\"%s\",\"nonce\":\"%s\",\"ble_mac\":\"%s\","
                    "\"efuse_mac\":\"%s\",\"rounds\":\"%s\",\"uptime_s\":%lu}",
                    g_device_id, owner, seed, nonce_hex, ble_mac,
                    efuse_mac, rounds_hex, up);
            }

            uint8_t ah[32];
            sha256_string(attest, ah);
            uint8_t sig_raw[72]; size_t sig_len = 0;
            char* sig_hex = s_buf.sign.sig_hex; sig_hex[0] = 0;
            if (!identity_sign(ah, sig_raw, &sig_len)) {
                ble_err(cmd, "sign_failed"); return;
            }
            bytes_to_hex(sig_raw, sig_len, sig_hex);

            char* pubkey_hex = s_buf.sign.pubkey_hex;
            identity_get_pubkey_hex(pubkey_hex, sizeof(s_buf.sign.pubkey_hex));

            // Krótkie klucze — odpowiedź musi zmieścić się w MTU 512
            char* resp = s_buf.sign.resp;
            snprintf(resp, sizeof(s_buf.sign.resp),
                "{\"status\":\"ok\",\"cmd\":\"trust_sign\","
                "\"n\":\"%s\",\"bm\":\"%s\",\"em\":\"%s\",\"rd\":\"%s\","
                "\"up\":%lu,\"sig\":\"%s\",\"pk\":\"%s\",\"gv\":%d}",
                nonce_hex, ble_mac, efuse_mac, rounds_hex, up,
                sig_hex, pubkey_hex, has_gps ? 2 : 1);

            LOGD("ble", "trust_sign: %d rounds, resp %d B%s",
                s_rounds_count, strlen(resp), resume ? " (resume)" : "");

            // Reset rund — ceremonia jednorazowa
            s_rounds_buf[0] = '\0';
            s_rounds_count  = 0;

            if (resume) {
                // Re-atestacja: odeślij kilkukrotnie i wróć do WiFi
                for (int i = 0; i < 3; i++) { notify(resp); delay(400); }
                s_wifi_pending = true;
            } else {
                notify(resp);
            }
            return;
        }

        // ── wallet_status — czy node ma kopię portfela + czy skonfig. ──
        // Apka po auth pyta o stan, by rozgałęzić onboarding/recovery.
        if (!strcmp(cmd, "wallet_status")) {
            Preferences p; p.begin(NVS_NS_WALLET, true);
            bool has = p.isKey("blob");
            String addr = p.getString("addr", "");
            p.end();
            char resp[180];
            snprintf(resp, sizeof(resp),
                "{\"status\":\"ok\",\"cmd\":\"wallet_status\","
                "\"has_backup\":%s,\"configured\":%s,\"addr\":\"%s\"}",
                has ? "true" : "false",
                wifi_has_config() ? "true" : "false",
                addr.c_str());
            notify(resp);
            return;
        }

        // ── wallet_backup {blob, addr} — zapis zaszyfrowanej kopii ──
        // Node trzyma blob nieprzezroczyście (szyfr po stronie apki, PIN-em).
        if (!strcmp(cmd, "wallet_backup")) {
            const char* blob = doc["blob"];
            const char* addr = doc["addr"] | "";
            if (!blob || strlen(blob) < 16 || strlen(blob) > 600) {
                ble_err(cmd, "bad_blob"); return;
            }
            Preferences p; p.begin(NVS_NS_WALLET, false);
            p.putString("blob", blob);
            p.putString("addr", addr);
            p.end();
            LOGI("ble", "wallet_backup saved (%d B, %.10s)", strlen(blob), addr);
            ble_ok(cmd);
            return;
        }

        // ── wallet_restore — zwróć zaszyfrowaną kopię (deszyfr w apce) ──
        // Tylko przez BLE (auth) — wymaga fizycznej bliskości.
        if (!strcmp(cmd, "wallet_restore")) {
            Preferences p; p.begin(NVS_NS_WALLET, true);
            String blob = p.getString("blob", "");
            String addr = p.getString("addr", "");
            p.end();
            if (blob.length() == 0) { ble_err(cmd, "no_backup"); return; }
            char* resp = s_buf.wallet.resp;
            snprintf(resp, sizeof(s_buf.wallet.resp),
                "{\"status\":\"ok\",\"cmd\":\"wallet_restore\","
                "\"blob\":\"%s\",\"addr\":\"%s\"}",
                blob.c_str(), addr.c_str());
            for (int i = 0; i < 3; i++) { notify(resp); delay(300); }
            return;
        }

        // ── wifi_set {ssid, password} — zmiana WiFi bez re-rejestracji ──
        if (!strcmp(cmd, "wifi_set")) {
            const char* ssid = doc["ssid"];
            const char* password = doc["password"] | "";
            if (!ssid || !strlen(ssid)) { ble_err(cmd, "missing_ssid"); return; }
            wifi_save_config(ssid, password);
            LOGI("ble", "WiFi changed: ssid=%s", ssid);
            ble_ok(cmd);
            delay(300);
            s_wifi_pending = true;  // restart w WiFi w loop()
            return;
        }

        ble_err(cmd, "unknown");
}

// ── Public API ────────────────────────────────────────────────
void ble_load_config() { load_config(); }

void ble_start() {
    if (g_ble_active) return;
    load_config();

    // Bufory BLE na heapie dopiero tu (RAM-AUDIT 0.49): tryb WiFi nigdy ich nie alokuje
    // (~3.2KB zostaje w heapie). BLE kończy się restartem — nie zwalniamy.
    if (!s_buf_p)      s_buf_p      = (BleBuf*)calloc(1, sizeof(BleBuf));
    if (!s_rounds_buf) s_rounds_buf = (char*)calloc(1, ROUNDS_BUF_LEN);
    if (!s_cmd_buf)    s_cmd_buf    = (char*)calloc(1, CMD_BUF_LEN);
    if (!s_buf_p || !s_rounds_buf || !s_cmd_buf) { LOGE("ble", "buf alloc failed"); return; }

    char name[24];
    snprintf(name, sizeof(name), "SENSMOS-%.6s", g_device_id);

    if (!s_ble_initialized) {
        NimBLEDevice::init(name);
        NimBLEDevice::setMTU(512);
        s_server = NimBLEDevice::createServer();
        s_server->setCallbacks(new ConnCB());
        NimBLEService* svc = s_server->createService(BLE_SERVICE_UUID);
        s_char_w = svc->createCharacteristic(BLE_CHAR_WRITE_UUID,
            NIMBLE_PROPERTY::WRITE);
        s_char_w->setCallbacks(new WriteCB());
        s_char_r = svc->createCharacteristic(BLE_CHAR_READ_UUID,
            NIMBLE_PROPERTY::READ | NIMBLE_PROPERTY::NOTIFY);
        s_char_r->setValue("{\"status\":\"ready\"}");
        svc->start();
        s_ble_initialized = true;
    }

    NimBLEAdvertising* adv = NimBLEDevice::getAdvertising();
    adv->addServiceUUID(BLE_SERVICE_UUID);
    adv->enableScanResponse(true);
    // NimBLE NIE wrzuca nazwy do advertisingu sam (Bluedroid robil to w init) — bez tego
    // telefony pokazuja nazwe z cache po MAC (stara tozsamosc po re-flashu) i apka nie znajduje noda
    adv->setName(name);
    NimBLEDevice::startAdvertising();
    g_ble_active    = true;
    s_wifi_pending  = false;
    s_auth_ok       = false;
    s_ble_start_ms  = millis();
    LOGI("ble", "started: %s", name);
}

void ble_stop() {
    if (!g_ble_active) return;
    NimBLEDevice::stopAdvertising();
    g_ble_active = false;
    s_connected  = false;
    s_auth_ok    = false;
    LOGI("ble", "stopped");
}

void ble_tick() {
    if (s_cmd_pending) {
        ble_process_cmd();
        s_cmd_pending = false;   // zwolnij slot dopiero PO obsludze (busy w miedzyczasie)
    }
    if (!s_wifi_pending) {
        // Tryb re-atestacji (force_ble przy skonfigurowanym WiFi):
        // bez ceremonii w 5 min i bez aktywnego połączenia → wróć do WiFi
        if (wifi_has_config() && !s_connected &&
            millis() - s_ble_start_ms > 300000UL) {
            LOGI("ble", "BLE mode timeout — back to WiFi");
            NimBLEDevice::deinit(true);   // czysty handoff radia BLE→WiFi (patrz niżej)
            delay(300);
            ESP.restart();
        }
        return;
    }
    s_wifi_pending = false;

    // Zrestartuj — zwalnia pamięć BLE, node wystartuje czysto na WiFi
    // Apka już odebrała notify z register (opóźnienie 3s przy wysyłaniu)
    LOGI("ble", "config saved — restarting in 2s");
    delay(2000);
    // KLUCZOWE: ubij kontroler BT PRZED resetem. SW_CPU_RESET nie zawsze resetuje kontroler
    // radia, a BLE i WiFi dzielą to samo radio → po sesji BLE WiFi RX potrafi wstać MARTWE
    // (0 AP, NO_AP_FOUND — mimo sprawnej anteny). Deinit = czysty handoff radia BLE→WiFi.
    LOGI("ble", "shutting down BT radio before reset");
    NimBLEDevice::deinit(true);
    delay(300);
    ESP.restart();
}
