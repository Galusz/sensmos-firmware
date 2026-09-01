#include "http_internal.h"
#include "http_server.h"   // node_alias_set/node_alias (POST /node/alias)
#include "node_log.h"
#include "identity.h"
#include "ble_config.h"
#include "lora_scan.h"
#include "pairing.h"
#include "ext_auth.h"
#include "mqtt_pub.h"
#include "config.h"
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

// GET /node/mqtt — stan klienta (bez hasła). POST /node/mqtt — config brokera za PIN.
// Ustawienie NODA (nie integracja tunelowa): apka w LAN wysyła config, hasło idzie tylko po
// lokalnym HTTP → NVS, NIGDY do chmury (broker jest lokalny).
static void handle_mqtt_status() {
    char out[256];
    mqtt_pub_status_json(out, sizeof(out));
    server.send(200, "application/json", out);
}
// POST /node/mqtt  {"on":true,"host":"192.168.1.10","port":1883,"user":"","pass":""}
static void handle_mqtt_set() {
    if (!check_pin()) return;
    JsonDocument doc;
    if (deserializeJson(doc, server.arg("plain"))) {
        server.send(400, "application/json", "{\"error\":\"bad json\"}"); return;
    }
    bool        on   = doc["on"]   | false;
    const char* host = doc["host"] | "";
    int         port = doc["port"] | MQTT_PORT_DEF;
    const char* user = doc["user"] | "";
    const char* pass = doc["pass"] | "";
    if (on && !host[0]) {
        server.send(400, "application/json", "{\"error\":\"host required\"}"); return;
    }
    mqtt_pub_set_config(on, host, port, user, pass);
    char out[256];
    mqtt_pub_status_json(out, sizeof(out));
    server.send(200, "application/json", out);
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

// GET /node/lora_emerg — zestaw + stan (bez hasła). POST za PIN: {"eids":["pub.x",...]}.
// Ustawienie NODA jak /node/mqtt: apka w LAN wybiera ≤4 encje, które przy padzie uplinku
// doklejają się do beaconu (LoRa awaryjne 0.91). NVS i zgłoszenie do BE robi lora_scan.
static void handle_lora_emerg_get() {
    String j; lora_emerg_json(j);
    server.send(200, "application/json", j);
}

// GET /lora/inbox — OSOBNY inbox LoRa (komendy CMD; Faza 2: ramki publiczne). Za PIN:
// treść komend to dane właściciela, nie pomiar środowiska jak /lora/last.
static void handle_lora_inbox() {
    if (!check_pin()) return;
    String j; lora_inbox_json(j);
    server.send(200, "application/json", j);
}
static void handle_lora_emerg_set() {
    if (!check_pin()) return;
    JsonDocument doc;
    if (deserializeJson(doc, server.arg("plain"))) {
        server.send(400, "application/json", "{\"error\":\"bad json\"}"); return;
    }
    JsonArray arr = doc["eids"].as<JsonArray>();
    if (arr.isNull()) {
        server.send(400, "application/json", "{\"error\":\"eids required\"}"); return;
    }
    char eids[LORA_EMERG_MAX][36];
    uint8_t n = 0;
    for (JsonVariant v : arr) {
        const char* e = v.as<const char*>();
        if (!e || !e[0] || strlen(e) >= 36 || !strchr(e, '.')) continue;
        if (n >= LORA_EMERG_MAX) break;
        strlcpy(eids[n++], e, 36);
    }
    lora_emerg_set(eids, n);
    // Webhook dla komend CMD (opcjonalny; "" kasuje). Tylko http(s) w LAN, bez znaków,
    // które rozwaliłyby JSON konfigu (cudzysłów/backslash). webhook_get: GET zamiast POST.
    if (doc["webhook"].is<const char*>()) {
        const char* wh = doc["webhook"] | "";
        if (!*wh || (strncmp(wh, "http", 4) == 0 && !strchr(wh, '"') && !strchr(wh, '\\')))
            lora_cmd_hook_set(wh, (bool)(doc["webhook_get"] | false));
    }
    String j; lora_emerg_json(j);
    server.send(200, "application/json", j);
}
#endif

// POST /node/alias {"alias":"Garaż"} — etykieta noda (NVS, widoczna w /info). Za PIN;
// "" kasuje. Apka dosyła ją przy zmianie nazwy, gdy node jest w LAN.
static void handle_alias_set() {
    if (!check_pin()) return;
    JsonDocument doc;
    if (deserializeJson(doc, server.arg("plain"))) {
        server.send(400, "application/json", "{\"error\":\"bad json\"}"); return;
    }
    node_alias_set(doc["alias"] | "");
    char resp[48];
    snprintf(resp, sizeof(resp), "{\"alias\":\"%s\"}", node_alias());
    server.send(200, "application/json", resp);
}

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
    server.on("/lora/inbox",     HTTP_GET,    handle_lora_inbox);
    server.on("/node/lora_emerg", HTTP_GET,   handle_lora_emerg_get);
    server.on("/node/lora_emerg", HTTP_POST,  handle_lora_emerg_set);
#endif
    server.on("/node/alias",     HTTP_POST,   handle_alias_set);
    server.on("/node/confirm",   HTTP_POST,   handle_node_confirm);
    server.on("/node/ble_mode",  HTTP_POST,   handle_ble_mode);
    server.on("/node/reboot",    HTTP_POST,   handle_reboot);
    server.on("/node/mqtt",      HTTP_GET,    handle_mqtt_status);
    server.on("/node/mqtt",      HTTP_POST,   handle_mqtt_set);
    server.on("/node/log",       HTTP_GET,    handle_node_log);
    server.on("/node/pair",      HTTP_POST,   handle_pair_set);
    server.on("/node/pair",      HTTP_DELETE, handle_pair_clear);
    server.on("/node/pair",      HTTP_GET,    handle_pair_status);
    server.on("/ext/authorize", HTTP_POST,   handle_ext_auth_begin);
    server.on("/ext/authorize", HTTP_GET,    handle_ext_auth_poll);
    server.on("/factory-reset",  HTTP_POST,   handle_factory_reset);
}
