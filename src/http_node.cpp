#include "http_internal.h"
#include "node_log.h"
#include "identity.h"
#include "ble_config.h"
#include "lora_scan.h"
#include "pairing.h"
#include "ext_auth.h"
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

// POST /node/reboot — zwykły restart po LAN (0.89, KNOWN-ISSUES #7): dotąd jedyną zdalną
// drogą był objazd przez /node/ble_mode (5 min trybu BLE), a WS-owa komenda "reboot"
// wymaga żywego WS — czyli nie działa dokładnie wtedy, gdy jest najbardziej potrzebna.
static void handle_reboot() {
    if (!check_pin()) return;
    server.send(200, "application/json", "{\"status\":\"ok\",\"msg\":\"rebooting\"}");
    LOGW("http", "reboot na zadanie (LAN)");
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

// ── Parowanie (klucz zdalnego dostępu) ───────────────────────────────────────
// Celowo TYLKO po LAN i za PIN-em — to jedyny kanał, którego BE nie widzi, więc
// jedyne miejsce, gdzie sekret może powstać poza jego zasięgiem. Nie ma i nie może
// być odpowiednika po WS: gdyby BE potrafił ustawić klucz, cały mechanizm nie
// chroniłby przed niczym (dokładnie tak było ze skasowaną flagą remote_ok).

// POST /node/pair  {"key":"<64 hex>"}
static void handle_pair_set() {
    if (!check_pin()) return;
    JsonDocument doc;
    if (deserializeJson(doc, server.arg("plain"))) {
        server.send(400, "application/json", "{\"error\":\"bad json\"}"); return;
    }
    const char* hex = doc["key"] | "";
    if (strlen(hex) != PAIR_KEY_LEN * 2) {
        server.send(400, "application/json", "{\"error\":\"key must be 64 hex chars\"}"); return;
    }
    uint8_t key[PAIR_KEY_LEN];
    for (int i = 0; i < PAIR_KEY_LEN; i++) {
        unsigned v;
        if (sscanf(hex + i * 2, "%2x", &v) != 1) {
            server.send(400, "application/json", "{\"error\":\"key not hex\"}"); return;
        }
        key[i] = (uint8_t)v;
    }
    if (!pairing_add(key)) {
        server.send(400, "application/json", "{\"error\":\"key rejected\"}"); return;
    }
    char resp[64];
    snprintf(resp, sizeof(resp), "{\"status\":\"ok\",\"keys\":%d}", pairing_count());
    server.send(200, "application/json", resp);
}

// DELETE /node/pair — kasuje wszystkie klucze = wyłącza zdalny dostęp.
static void handle_pair_clear() {
    if (!check_pin()) return;
    pairing_clear();
    server.send(200, "application/json", "{\"status\":\"ok\",\"keys\":0}");
}

// GET /node/pair — ile kluczy (BEZ ich ujawniania; do UI apki „czy sparowany").
static void handle_pair_status() {
    if (!check_pin()) return;
    char resp[64];
    snprintf(resp, sizeof(resp), "{\"paired\":%s,\"keys\":%d}",
             pairing_has_key() ? "true" : "false", pairing_count());
    server.send(200, "application/json", resp);
}

// ── Autoryzacja przystawki (sprzęt zewnętrzny w LAN-ie właściciela) ──────────
// Za PIN-em, bo to jedyne, co odróżnia właściciela od dowolnego hosta w tej sieci.
// Nieblokująco: handler tylko wysyła prośbę do BE i wraca. Blokowanie pętli na czas
// rundy po WS zatrzymałoby cały WebServer, a to ta sama pętla, która obsługuje WS.

// POST /ext/authorize  {kind:lora-gw,name:RAK7289,scopes:radio.frames,radio.spectrum}
static void handle_ext_auth_begin() {
    if (!check_pin()) return;
    JsonDocument doc;
    if (deserializeJson(doc, server.arg("plain"))) {
        server.send(400, "application/json", "{\"error\":\"bad json\"}"); return;
    }
    const char* kind   = doc["kind"]   | "";
    const char* name   = doc["name"]   | "";
    const char* scopes = doc["scopes"] | "";
    if (!*kind || !*scopes) {
        server.send(400, "application/json", "{\"error\":\"kind and scopes required\"}"); return;
    }
    char req[17]; const char* err = "";
    if (!ext_auth_begin(kind, name, scopes, req, sizeof(req), &err)) {
        char e[96];
        snprintf(e, sizeof(e), "{\"error\":\"%s\"}", err);
        server.send(strcmp(err, "ws_offline") == 0 ? 503 : 429, "application/json", e);
        return;
    }
    char resp[96];
    snprintf(resp, sizeof(resp), "{\"status\":\"pending\",\"req\":\"%s\"}", req);
    server.send(202, "application/json", resp);
}

// GET /ext/authorize?req=<id> — odpytywanie do skutku. Token wychodzi TYLKO tędy, więc PIN.
static void handle_ext_auth_poll() {
    if (!check_pin()) return;
    String req = server.arg("req");
    char resp[256];
    switch (ext_auth_state(req.c_str())) {
        case EXT_AUTH_PENDING:
            server.send(200, "application/json", "{\"status\":\"pending\"}");
            return;
        case EXT_AUTH_GRANTED:
            snprintf(resp, sizeof(resp),
                     "{\"status\":\"granted\",\"id\":\"%s\",\"token\":\"%s\",\"exp\":%lu}",
                     ext_auth_id(), ext_auth_token(), (unsigned long)ext_auth_exp());
            server.send(200, "application/json", resp);
            return;
        case EXT_AUTH_DENIED:
            snprintf(resp, sizeof(resp), "{\"status\":\"denied\",\"reason\":\"%s\"}",
                     ext_auth_reason());
            server.send(200, "application/json", resp);
            return;
        default:
            server.send(404, "application/json", "{\"status\":\"unknown\"}");
    }
}

void register_node_routes() {
#if LORA_ENABLED
    server.on("/lora/last",      HTTP_GET,    handle_lora_last);
#endif
    server.on("/node/confirm",   HTTP_POST,   handle_node_confirm);
    server.on("/node/ble_mode",  HTTP_POST,   handle_ble_mode);
    server.on("/node/reboot",    HTTP_POST,   handle_reboot);
    server.on("/node/log",       HTTP_GET,    handle_node_log);
    server.on("/node/pair",      HTTP_POST,   handle_pair_set);
    server.on("/node/pair",      HTTP_DELETE, handle_pair_clear);
    server.on("/node/pair",      HTTP_GET,    handle_pair_status);
    server.on("/ext/authorize", HTTP_POST,   handle_ext_auth_begin);
    server.on("/ext/authorize", HTTP_GET,    handle_ext_auth_poll);
    server.on("/factory-reset",  HTTP_POST,   handle_factory_reset);
}
