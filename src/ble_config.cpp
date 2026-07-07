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
 *     Jeśli nie znajdzie w 30s → błąd, retry
 *
 *  6. ESP watchdog: 3 min po WiFi bez /node/confirm → factory reset
 */

#include "ble_config.h"
#include "wifi_manager.h"
#include "identity.h"
#include <NimBLEDevice.h>
#include <ArduinoJson.h>
#include <Preferences.h>
#include <mbedtls/sha256.h>
#include <esp_random.h>

// ── Watchdog ──────────────────────────────────────────────────
// 3 minuty po WiFi na POST /node/confirm, potem factory reset
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
        Serial.println("[WDG] Node już potwierdzony — watchdog nieaktywny");
        return;
    }
    s_wdg_deadline  = millis() + 60UL * 1000;  // 60 sekund
    s_wdg_active    = true;
    s_wdg_confirmed = false;
    Serial.println("[WDG] Start — 60s na /node/confirm");
}
void watchdog_confirm() {
    s_wdg_confirmed = true;
    // Zapisz do NVS — po restarcie nie potrzeba ponownego confirm
    Preferences p;
    p.begin("sensmos", false);
    p.putBool("node_confirmed", true);
    p.end();
    Serial.println("[WDG] Potwierdzone i zapisane w NVS");
}
void watchdog_tick() {
    if (!s_wdg_active || s_wdg_confirmed) return;
    if (millis() > s_wdg_deadline) {
        Serial.println("[WDG] Timeout — factory reset!");
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
static char          s_rounds_buf[TRUST_MAX_ROUNDS * 128 + 1] = {0};
static int           s_rounds_count = 0;
static unsigned long s_ble_start_ms = 0;  // timeout powrotu do WiFi (re-atestacja)

// Duże bufory handlerów: task NimBLE ma ~4KB stosu (mbedTLS zjada 2-3KB), więc nie
// na stosie — ale zapisy BLE są sekwencyjne (request-response), handlery nie żyją
// naraz → UNIA zamiast osobnych static char[] (3.9KB → 1.6KB .bss).
static union {
    struct { char resp[256]; } auth;
    struct { char message[256]; char sig_esp_hex[145]; char pubkey_hex[131];
             char proof_input[512]; char resp[512]; } reg;
    struct { char input[140]; } round;
    struct { char attest[480]; char sig_hex[145]; char pubkey_hex[131]; char resp[512]; } sign;
    struct { char resp[700]; } wallet;
} s_buf;

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
    Serial.printf("[BLE] → %s\n", json);
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
        Serial.println("[BLE] Połączono");
    }
    void onDisconnect(NimBLEServer*, NimBLEConnInfo&, int) override {
        s_connected = false; s_auth_ok = false;
        if (g_ble_active && !s_wifi_pending) {
            delay(100);
            NimBLEDevice::startAdvertising();
            Serial.println("[BLE] Advertising wznowiony");
        }
    }
};

class WriteCB : public NimBLECharacteristicCallbacks {
    void onWrite(NimBLECharacteristic* ch, NimBLEConnInfo&) override {
        if (!rate_ok()) { ble_err("?", "rate_limit"); return; }
        NimBLEAttValue val = ch->getValue();
        if (!val.length()) return;
        Serial.printf("[BLE] ← (%d B)\n", val.length());

        JsonDocument doc;
        if (deserializeJson(doc, val.c_str())) { ble_err("?", "invalid_json"); return; }
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
            Serial.printf("[BLE] Config: backend=%s ssid=%s owner=%.10s...\n",
                backend_url, ssid, owner);

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

            Serial.printf("[BLE] Register resp: %d B\n", strlen(resp));
            // Wyślij wielokrotnie z dłuższym delay — apka musi odebrać PRZED restartem
            for (int i = 0; i < 5; i++) { notify(resp); delay(500); }
            delay(500);  // dodatkowy bufor

            Serial.printf("[BLE] Challenge OK — proof: %.16s...\n", proof_hex);

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
            snprintf(s_rounds_buf + used, sizeof(s_rounds_buf) - used,
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

            Serial.printf("[BLE] trust_sign: %d rund, resp %d B%s\n",
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
            Serial.printf("[BLE] wallet_backup zapisany (%d B, %.10s)\n",
                strlen(blob), addr);
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
            Serial.printf("[BLE] WiFi zmienione: ssid=%s\n", ssid);
            ble_ok(cmd);
            delay(300);
            s_wifi_pending = true;  // restart w WiFi w loop()
            return;
        }

        ble_err(cmd, "unknown");
    }
};

// ── Public API ────────────────────────────────────────────────
void ble_load_config() { load_config(); }

void ble_start() {
    if (g_ble_active) return;
    load_config();

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
    Serial.printf("[BLE] Started: %s\n", name);
}

void ble_stop() {
    if (!g_ble_active) return;
    NimBLEDevice::stopAdvertising();
    g_ble_active = false;
    s_connected  = false;
    s_auth_ok    = false;
    Serial.println("[BLE] Stopped");
}

void ble_tick() {
    if (!s_wifi_pending) {
        // Tryb re-atestacji (force_ble przy skonfigurowanym WiFi):
        // bez ceremonii w 5 min i bez aktywnego połączenia → wróć do WiFi
        if (wifi_has_config() && !s_connected &&
            millis() - s_ble_start_ms > 300000UL) {
            Serial.println("[BLE] Timeout trybu BLE — powrót do WiFi");
            delay(500);
            ESP.restart();
        }
        return;
    }
    s_wifi_pending = false;

    // Zrestartuj — zwalnia pamięć BLE, node wystartuje czysto na WiFi
    // Apka już odebrała notify z register (opóźnienie 3s przy wysyłaniu)
    Serial.println("[BLE] Config zapisany — restartuję za 2s...");
    delay(2000);
    ESP.restart();
}
