/**
 * SENSMOS Firmware — HTTP Core
 * WebServer, PIN, podpisywanie żądań, rejestracja tras.
 * Handlery w http_data/http_messages/http_remote/http_config/http_node.
 */
#include "http_internal.h"
#include "http_server.h"
#include "entity_store.h"
#include "ws_client.h"
#include "identity.h"
#include "ble_config.h"
#include "wifi_manager.h"
#include "ntp_time.h"
#include "data_sender.h"   // FW_VERSION
#include "push_notify.h"
#include "fw_digest.h"
#include "message_router.h"
#include "lora_scan.h"     // /info.lora — marker radia dla integracji (HA)
#include "log.h"
#include <ArduinoJson.h>
#include <Preferences.h>

WebServer server(80);

// Scheme-aware begin: TLS (insecure) dla https://, plain dla http://.
// setInsecure = bez walidacji certu; żądania HTTP do BE i tak podpisane secp256k1 (http_sign_request).
// `sec` musi przezyc caly request (deklaruj lokalnie w wywolujacym).
bool http_begin_url(HTTPClient& http, WiFiClientSecure& sec, const String& url) {
    if (url.startsWith("https://")) {
        sec.setInsecure();
        return http.begin(sec, url);
    }
    return http.begin(url);
}

// PIN: jeden system — sensmos/ble_pin (BLE i HTTP wspólne)
bool check_pin() {
    server.sendHeader("Access-Control-Allow-Origin", "*");
    // K4: rate-limit brute-force PIN-u na lokalnym API — 5 zlych prob => 30s lockout
    static uint8_t       s_pin_fails = 0;
    static unsigned long s_pin_lock  = 0;
    unsigned long now = millis();
    if (s_pin_lock && now < s_pin_lock) {
        server.send(429, "application/json", "{\"error\":\"too_many_attempts\"}");
        return false;
    }
    String auth = server.header("Authorization");
    Preferences p; p.begin("sensmos", true);
    String pin = p.getString("ble_pin", "123456");
    p.end();
    if (auth == String("Bearer ") + pin) { s_pin_fails = 0; s_pin_lock = 0; return true; }
    if (++s_pin_fails >= 5) { s_pin_lock = now + 30000UL; s_pin_fails = 0; }
    server.send(403, "application/json", "{\"error\":\"invalid_pin\"}");
    return false;
}

// Podpis żądań HTTP do BE
void http_sign_request(HTTPClient& http, const char* method, const char* url) {
    uint32_t ts = ntp_synced() ? ntp_unix_time() : (uint32_t)(millis() / 1000);
    char msg[256];
    snprintf(msg, sizeof(msg), "%s:%s:%lu", method, url, (unsigned long)ts);
    uint8_t hash[32];
    sha256_string(msg, hash);
    uint8_t sig[72]; size_t sig_len = 0;
    identity_sign(hash, sig, &sig_len);
    char sig_hex[145];
    bytes_to_hex(sig, sig_len, sig_hex);
    http.addHeader("X-Device-ID", g_device_id);
    http.addHeader("X-Signature", sig_hex);
    char ts_str[16];
    snprintf(ts_str, sizeof(ts_str), "%lu", (unsigned long)ts);
    http.addHeader("X-Timestamp", ts_str);
}

// Alias noda (etykieta usera) — NVS "meta"/"alias". Sanityzacja w setterze: bez cudzysłowu,
// backslasha i znaków kontrolnych (leci 1:1 do JSON-ów), UTF-8 dozwolony ("Garaż"), ≤24 B.
static char s_alias[25] = "";

const char* node_alias() { return s_alias; }

void node_alias_set(const char* alias) {
    size_t p = 0;
    for (const char* c = alias ? alias : ""; *c && p < sizeof(s_alias) - 1; c++) {
        const unsigned char u = (unsigned char)*c;
        if (u < 0x20 || u == '"' || u == '\\') continue;
        s_alias[p++] = *c;
    }
    s_alias[p] = 0;
    Preferences pr; pr.begin("meta", false);
    pr.putString("alias", s_alias);
    pr.end();
}

// GET / lub /info — status (publiczny, bez PIN)
static void handle_root() {
    JsonDocument doc;
    doc["device_id"]     = g_device_id;
    doc["firmware"]      = FW_VERSION;
    if (s_alias[0]) doc["alias"] = s_alias;
    doc["owner_address"] = g_owner_address;
    doc["ip"]            = g_local_ip;
    doc["ws_connected"]  = ws_client_connected();
    doc["ntp_synced"]    = ntp_synced();
    doc["entity_count"]  = entity_count();
    doc["uptime_s"]      = millis() / 1000;
#if LORA_ENABLED
    // Marker LoRa dla integracji (HA wykrywa po LAN noda z radiem). Tylko gdy sonda
    // pinów FAKTYCZNIE znalazła SX1262 — bin lora na płytce bez radia nie udaje.
    if (lora_available()) {
        JsonObject l = doc["lora"].to<JsonObject>();
        l["board"]  = lora_board_name();
        l["role"]   = lora_link_role();
        l["rx_key"] = lora_rx_key_present();
        l["open"]   = lora_rx_open_get();
    }
#endif
    if (ntp_synced()) doc["time"] = ntp_time_str();
    String out; serializeJson(doc, out);
    server.send(200, "application/json", out);
}

void http_server_init() {
    push_init();
    message_router_init();
    { Preferences pr; pr.begin("meta", true);
      strlcpy(s_alias, pr.getString("alias", "").c_str(), sizeof(s_alias)); pr.end(); }

    const char* headers[] = {"Authorization"};
    server.collectHeaders(headers, 1);

    server.on("/",     HTTP_GET, handle_root);
    server.on("/info", HTTP_GET, handle_root);

    register_data_routes();
    register_messages_routes();
    register_remote_routes();
    register_config_routes();
    register_node_routes();
    register_fw_digest_routes();

    server.onNotFound([]() {
        server.send(404, "application/json", "{\"error\":\"not found\"}");
    });

    server.begin();
    LOGI("http", "server on http://%s", g_local_ip);
}

void http_server_handle() {
    server.handleClient();
}
