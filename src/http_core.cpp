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
#include "message_router.h"
#include "log.h"
#include <ArduinoJson.h>
#include <Preferences.h>

WebServer server(80);

// Scheme-aware begin: TLS (insecure) dla https://, plain dla http://.
// setInsecure = bez walidacji certu; batche i tak podpisane secp256k1.
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

// GET / lub /info — status (publiczny, bez PIN)
static void handle_root() {
    JsonDocument doc;
    doc["device_id"]     = g_device_id;
    // BLE MAC (format jak w skanie BLE w apce) — apka uzupełnia nim zapisane nody,
    // żeby po reflashu rozpoznać ten sam sprzęt i zaproponować odtworzenie device_id.
    uint8_t btm[6];
    esp_read_mac(btm, ESP_MAC_BT);
    char btm_s[18];
    snprintf(btm_s, sizeof(btm_s), "%02X:%02X:%02X:%02X:%02X:%02X",
             btm[0], btm[1], btm[2], btm[3], btm[4], btm[5]);
    doc["ble_mac"]       = btm_s;
    doc["firmware"]      = FW_VERSION;
    doc["owner_address"] = g_owner_address;
    doc["ip"]            = g_local_ip;
    doc["ws_connected"]  = ws_client_connected();
    doc["ntp_synced"]    = ntp_synced();
    doc["entity_count"]  = entity_count();
    doc["uptime_s"]      = millis() / 1000;
    if (ntp_synced()) doc["time"] = ntp_time_str();
    String out; serializeJson(doc, out);
    server.send(200, "application/json", out);
}

void http_server_init() {
    push_init();
    message_router_init();

    const char* headers[] = {"Authorization"};
    server.collectHeaders(headers, 1);

    server.on("/",     HTTP_GET, handle_root);
    server.on("/info", HTTP_GET, handle_root);

    register_data_routes();
    register_messages_routes();
    register_remote_routes();
    register_config_routes();
    register_node_routes();

    server.onNotFound([]() {
        server.send(404, "application/json", "{\"error\":\"not found\"}");
    });

    server.begin();
    LOGI("http", "server on http://%s", g_local_ip);
}

void http_server_handle() {
    server.handleClient();
}
