#include "http_internal.h"
#include "node_log.h"
#include "identity.h"
#include "ble_config.h"
#include <ArduinoJson.h>
#include <Preferences.h>

// GET /wallet/balance
static void handle_wallet_balance() {
    if (!check_pin()) return;
    if (strlen(g_owner_address) == 0) {
        server.send(400, "application/json", "{\"error\":\"no owner address\"}"); return;
    }
    if (strlen(g_backend_url) == 0) {
        server.send(503, "application/json", "{\"error\":\"no backend url\"}"); return;
    }
    String url = String(g_backend_url) + "/wallet/" + g_owner_address;
    HTTPClient http;
    WiFiClientSecure sec;
    http_begin_url(http, sec, url);
    http_sign_request(http, "GET", url.c_str());
    http.setTimeout(5000);
    int code = http.GET();
    String resp = http.getString();
    http.end();
    server.send(code == 200 ? 200 : 502, "application/json",
        code == 200 ? resp : "{\"error\":\"backend error\"}");
}

// GET /wallet/proof
static void handle_wallet_proof() {
    if (!check_pin()) return;
    if (strlen(g_owner_address) == 0) {
        server.send(400, "application/json", "{\"error\":\"no owner address\"}"); return;
    }
    if (strlen(g_backend_url) == 0) {
        server.send(503, "application/json", "{\"error\":\"no backend url\"}"); return;
    }
    String url = String(g_backend_url) + "/wallet/" + g_owner_address + "/proof";
    HTTPClient http;
    WiFiClientSecure sec;
    http_begin_url(http, sec, url);
    http_sign_request(http, "GET", url.c_str());
    http.setTimeout(8000);
    int code = http.GET();
    String resp = http.getString();
    http.end();
    server.send(code > 0 ? code : 502, "application/json",
        resp.length() > 0 ? resp : "{\"error\":\"backend error\"}");
}

// POST /node/confirm — apka potwierdza konfigurację (wyłącza watchdog)
static void handle_node_confirm() {
    watchdog_confirm();
    Serial.println("[WDG] Potwierdzono konfigurację — watchdog wyłączony");
    server.send(200, "application/json", "{\"status\":\"ok\"}");
}

// POST /node/ble_mode — restart w czysty tryb BLE (ceremonia trust)
// Node wraca do WiFi sam: po trust_sign{resume} albo po 5 min bez ceremonii.
static void handle_ble_mode() {
    if (!check_pin()) return;
    server.send(200, "application/json",
        "{\"status\":\"ok\",\"msg\":\"restarting_to_ble\"}");
    Preferences p;
    p.begin("sensmos", false);
    p.putBool("force_ble", true);
    p.end();
    Serial.println("[HTTP] Restart w tryb BLE (ceremonia trust)");
    delay(500);
    ESP.restart();
}

// POST /factory-reset
static void handle_factory_reset() {
    if (!check_pin()) return;
    server.send(200, "application/json", "{\"status\":\"ok\",\"msg\":\"resetting\"}");
    delay(300);
    Preferences p;
    p.begin("sensmos",      false); p.clear(); p.end();
    p.begin("sensmos_wifi", false); p.clear(); p.end();
    Serial.println("[HTTP] Factory reset!");
    delay(500);
    ESP.restart();
}

void register_node_routes() {
    server.on("/wallet/balance", HTTP_GET,  handle_wallet_balance);
    server.on("/wallet/proof",   HTTP_GET,  handle_wallet_proof);
    server.on("/node/confirm",   HTTP_POST, handle_node_confirm);
    server.on("/node/ble_mode",  HTTP_POST, handle_ble_mode);
    server.on("/node/log",       HTTP_GET,  handle_node_log);
    server.on("/factory-reset",  HTTP_POST, handle_factory_reset);
}
