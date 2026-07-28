#include "http_internal.h"
#include "node_log.h"
#include "identity.h"
#include "ble_config.h"
#include "lora_scan.h"
#include "log.h"
#include <ArduinoJson.h>
#include <Preferences.h>

// 0.73: /wallet/balance i /wallet/proof SKASOWANE. Były proxy PUBLICZNYCH odczytów BE
// (GET /v1/wallet/:address — bez auth), otwierały niepotrzebny TLS w kontekście loop.
// Apka czyta BE wprost (jak ekran Portfel). Saldo i tak publiczne (on-chain Polygon + /epochs).

// POST /node/confirm — apka potwierdza konfigurację (wyłącza watchdog)
static void handle_node_confirm() {
    watchdog_confirm();   // loguje "confirmed and saved to NVS"
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
    LOGI("http", "restart into BLE mode (trust ceremony)");
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
    LOGW("http", "factory reset");
    delay(500);
    ESP.restart();
}

#if LORA_ENABLED
// GET /lora/last — ostatnie pomiary radia. Bez PIN-u: to odczyt widma w miejscu, gdzie
// node stoi, nie dane właściciela — a dostęp i tak wymaga bycia w jego sieci lokalnej.
static void handle_lora_last() {
    String j; lora_json(j);
    server.send(200, "application/json", j);
}
#endif

void register_node_routes() {
#if LORA_ENABLED
    server.on("/lora/last",      HTTP_GET,  handle_lora_last);
#endif
    server.on("/node/confirm",   HTTP_POST, handle_node_confirm);
    server.on("/node/ble_mode",  HTTP_POST, handle_ble_mode);
    server.on("/node/log",       HTTP_GET,  handle_node_log);
    server.on("/factory-reset",  HTTP_POST, handle_factory_reset);
}
