#include "node_integration.h"
/**
 * SENSMOS Firmware — WebSocket Client
 * Połączenie z backendem, routing wiadomości.
 */
#include "ws_client.h"
#include "entity_store.h"
#include "identity.h"
#include "ble_config.h"
#include "wifi_manager.h"
#include "subscription_map.h"
#include "http_server.h"
#include "node_log.h"
#include "message_router.h"
#include "checknet.h"
#include <ArduinoJson.h>
#include <WebSocketsClient.h>

static WebSocketsClient ws;
static bool             g_ws_connected = false;
static unsigned long    g_last_reconnect = 0;
#define RECONNECT_INTERVAL 5000

// Session token — generowany przez BE po identify, używany w HTTP requests
static String g_session_token  = "";

// ── Publiczny dostęp do cache ──────────────────────────────────
const char* ws_get_session_token()  { return g_session_token.c_str(); }
bool        ws_has_session_token()  { return g_session_token.length() > 0; }

// ── Parsowanie URL ─────────────────────────────────────────────
static bool parseUrl(const char* url, char* host, int* port, char* path_out, bool* secure) {
    const char* p = url;
    *secure = false;
    int defPort = 80;
    if      (strncmp(p, "https://", 8) == 0) { p += 8; *secure = true; defPort = 443; }
    else if (strncmp(p, "http://",  7) == 0) { p += 7; }

    const char* colon = strchr(p, ':');
    const char* slash = strchr(p, '/');

    if (colon && (!slash || colon < slash)) {
        strncpy(host, p, colon - p);
        host[colon - p] = '\0';
        *port = atoi(colon + 1);
    } else if (slash) {
        strncpy(host, p, slash - p);
        host[slash - p] = '\0';
        *port = defPort;
    } else {
        strcpy(host, p);
        *port = defPort;
    }

    if (slash) snprintf(path_out, 64, "%s/ws", slash);
    else       strcpy(path_out, "/v1/ws");
    return true;
}

// ── Identify ──────────────────────────────────────────────────
static void send_identify() {
    unsigned long ts = millis() / 1000;

    char msg_to_sign[128];
    snprintf(msg_to_sign, sizeof(msg_to_sign),
        "identify:%s:%lu", g_device_id, ts);

    uint8_t hash[32];
    sha256_string(msg_to_sign, hash);
    uint8_t sig[72]; size_t sig_len = 0;
    identity_sign(hash, sig, &sig_len);
    char sig_hex[145];
    bytes_to_hex(sig, sig_len, sig_hex);

    JsonDocument doc;
    doc["type"]      = "identify";
    doc["device_id"] = g_device_id;
    doc["timestamp"] = (uint32_t)ts;
    doc["msg"]       = msg_to_sign;
    doc["signature"] = sig_hex;

    String packet;
    serializeJson(doc, packet);
    ws.sendTXT(packet);
    Serial.printf("[WS] Identify wysłany (%d B)\n", packet.length());
}

// ── Zapis danych subskrypcji do entity_store ──────────────────
// Prefix z lokalnej mapy subskrypcji po device_id nadawcy (from); default "sub".
static void push_remote_entities(JsonObject user_obj, JsonArray pub_arr,
                                 const char* from) {
    char prefix[16];
    if (!from || !sub_map_get(from, prefix, sizeof(prefix)))
        strcpy(prefix, "sub");

    if (!user_obj.isNull()) {
        for (JsonPair kv : user_obj) {
            const char* k = kv.key().c_str();
            if (strncmp(k, "pub.", 4) == 0) k += 4;
            char eid[64], val[64];
            snprintf(eid, sizeof(eid), "%s.%s", prefix, k);
            if (kv.value().is<const char*>()) {
                strncpy(val, kv.value().as<const char*>(), 63);
            } else {
                float fv = kv.value().as<float>();
                (fv == (int)fv)
                    ? snprintf(val, sizeof(val), "%d",   (int)fv)
                    : snprintf(val, sizeof(val), "%.2f", fv);
            }
            entity_push(eid, val, "");
        }
    }

    if (!pub_arr.isNull()) {
        for (JsonObject e : pub_arr) {
            const char* eid  = e["entity_id"] | "";
            const char* val  = e["value"]     | "";
            const char* unit = e["unit"]      | "";
            const char* base = (strncmp(eid, "pub.", 4) == 0) ? eid + 4 : eid;
            char full_eid[64];
            snprintf(full_eid, sizeof(full_eid), "%s.%s", prefix, base);
            entity_push(full_eid, val, unit);
        }
    }
}

// ── Handlery per typ wiadomości ───────────────────────────────
static void on_identified(JsonDocument& doc) {
    g_ws_connected = true;
    Serial.println("[WS] ✓ Zidentyfikowano");
    node_integration_push("ws_connected", "{}");

    // Czas serwera (informacyjnie)
    uint32_t st = doc["server_time"] | 0;
    if (st > 0) Serial.printf("[WS] Server time: %u\n", st);

    // Załaduj native_entities
    int loaded = 0;
    for (JsonObject e : doc["entities"].as<JsonArray>()) {
        const char* eid = e["entity_id"] | "";
        if (strlen(eid) > 0) { entity_load_native(eid); loaded++; }
    }
    if (loaded > 0) Serial.printf("[WS] Native entities: %d\n", loaded);

    // Zapisz session token
    const char* token = doc["session_token"] | "";
    if (strlen(token) > 0) {
        g_session_token = String(token);
        Serial.println("[WS] Session token otrzymany");
    }
}

static void on_message_recv(JsonDocument& doc) {
    const char* from       = doc["from"]    | "unknown";
    const char* message_id = doc["eid"]     | "unknown";
    const char* pl         = doc["payload"] | "";

    http_inbox_push(from, message_id, pl);
    Serial.printf("[WS] Message: %s od %.8s\n", message_id, from);
    message_router_dispatch(from, message_id, pl);
}

static void on_message_sent(JsonDocument& doc) {
    bool delivered = doc["delivered"] | false;
    if (!delivered) Serial.println("[WS] Message: odbiorca offline");
}

static void on_batch_ack(JsonDocument& doc) {
    int saved = doc["entities_saved"] | 0;
    Serial.printf("[WS] Batch ACK: %d encji\n", saved);
    char detail[32], sse[64];
    snprintf(detail, sizeof(detail), "%d entities saved", saved);
    snprintf(sse,    sizeof(sse),    "{\"entities_saved\":%d}", saved);
    node_log_push("batch", detail, true);
    node_integration_push("batch_sent", sse);
}

static void on_batch_error(JsonDocument& doc) {
    Serial.printf("[WS] Batch ERROR: %s\n", doc["error"] | "?");
}

static void on_tasks_update(JsonDocument& doc) {
    extern int script_engine_load(const JsonArray&);
    extern int script_engine_load_user();
    int n = script_engine_load(doc["scripts"].as<JsonArray>());
    script_engine_load_user();
    Serial.printf("[WS] Tasks: %d BE skryptów\n", n);
}

static void on_tasks_clear(JsonDocument& doc) {
    extern void script_engine_clear();
    script_engine_clear();
    Serial.println("[WS] Skrypty wyczyszczone");
}

static void on_subscription_push(JsonDocument& doc) {
    const char* from = doc["from"] | "?";
    char detail[48], sse[96];
    snprintf(detail, sizeof(detail), "from:%.8s", from);
    snprintf(sse,    sizeof(sse),    "{\"from\":\"%.8s...\"}",  from);
    node_log_push("sub_push", detail, true);
    node_integration_push("sub_received", sse);
    Serial.printf("[WS] Sub push od %.8s\n", from);
    push_remote_entities(
        doc["user"].as<JsonObject>(),
        doc["pub"].as<JsonArray>(),
        from
    );
}

static void on_error(JsonDocument& doc) {
    Serial.printf("[WS] Backend error: %s\n", doc["msg"] | "?");
}

static void on_check_jobs(JsonDocument& doc) {
    if (doc["tr"].is<JsonObject>()) {   // opcjonalna konfiguracja traceroute z BE
        JsonObject tr = doc["tr"];
        checknet_set_trace_cfg(tr["enabled"] | true, tr["max_ttl"] | 0, tr["probes"] | 0, tr["timeout_ms"] | 0);
    }
    checknet_on_jobs(doc["jobs"].as<JsonArray>());
}

// ── Tablica dispatchu ─────────────────────────────────────────
typedef void (*ws_handler_t)(JsonDocument&);
struct WsEntry { const char* type; ws_handler_t fn; };

static const WsEntry WS_TABLE[] = {
    { "identified",        on_identified },
    { "message",           on_message_recv },
    { "message_sent",      on_message_sent },
    { "batch_ack",         on_batch_ack },
    { "batch_error",       on_batch_error },
    { "tasks_update",      on_tasks_update },
    { "tasks_clear",       on_tasks_clear },
    { "subscription_push", on_subscription_push },
    { "check_jobs",        on_check_jobs },
    { "error",             on_error },
};

// ── Obsługa wiadomości ────────────────────────────────────────
static void handle_message(const char* payload) {
    JsonDocument doc;
    if (deserializeJson(doc, payload)) {
        Serial.println("[WS] Błąd parsowania JSON");
        return;
    }
    const char* type = doc["type"] | "";

    if (strcmp(type, "pong") == 0) return;

    for (const WsEntry& e : WS_TABLE) {
        if (strcmp(type, e.type) == 0) { e.fn(doc); return; }
    }
    Serial.printf("[WS] Nieznany typ: %s\n", type);
}

// ── WS Events ─────────────────────────────────────────────────
static void wsEvent(WStype_t event, uint8_t* payload, size_t length) {
    switch (event) {
        case WStype_CONNECTED:
            Serial.printf("[WS] Połączono (free=%u largest=%u)\n",
                          ESP.getFreeHeap(), ESP.getMaxAllocHeap());
            send_identify();
            break;
        case WStype_DISCONNECTED:
            g_ws_connected = false;
            Serial.printf("[WS] Rozłączono (free=%u largest=%u minFree=%u",
                          ESP.getFreeHeap(), ESP.getMaxAllocHeap(), ESP.getMinFreeHeap());
            if (payload && length) Serial.printf(" powód=%.*s", (int)length, (char*)payload);
            Serial.println(")");
            break;
        case WStype_TEXT:
            handle_message((char*)payload);
            break;
        case WStype_ERROR:
            Serial.printf("[WS] Błąd (free=%u", ESP.getFreeHeap());
            if (payload && length) Serial.printf(" msg=%.*s", (int)length, (char*)payload);
            Serial.println(")");
            break;
        case WStype_PING: Serial.println("[WS] ping→"); break;
        case WStype_PONG: Serial.println("[WS] ←pong"); break;
        default: break;
    }
}

// ── API ───────────────────────────────────────────────────────
void ws_client_init() {
    if (!g_wifi_connected || strlen(g_backend_url) == 0) return;

    char host[64] = {0}, path[64] = {0};
    int  port = 80; bool secure = false;
    if (!parseUrl(g_backend_url, host, &port, path, &secure)) {
        Serial.println("[WS] Błąd parsowania URL");
        return;
    }

#if WS_PLAINTEXT
    secure = false;               // WS bez TLS → ~70KB heapu więcej (dane i tak podpisane)
    port   = WS_PLAINTEXT_PORT;   // ws://host:80/v1/ws (nginx → :3000). Fetch/HTTP zostają https.
#endif

    Serial.printf("[WS] Łączę: %s://%s:%d%s (free=%u largest=%u)\n",
                  secure ? "wss" : "ws", host, port, path,
                  ESP.getFreeHeap(), ESP.getMaxAllocHeap());
    if (secure) ws.beginSSL(host, port, path);
    else        ws.begin(host, port, path);
    ws.onEvent(wsEvent);
    ws.setReconnectInterval(RECONNECT_INTERVAL);
    ws.enableHeartbeat(30000, 10000, 2);  // ping co 30s, timeout 10s
}

void ws_client_send_push(const char* title, const char* body) {
    // Wysyła token + treść do BE — BE wysyła FCM
    // Token nie jest przechowywany na BE — wysyłany przy każdym pushu
    extern String push_get_token();
    String token = push_get_token();
    if (token.length() == 0) {
        Serial.println("[Push] Brak tokenu — push nie wysłany");
        return;
    }
    char buf[384];
    snprintf(buf, sizeof(buf),
        "{\"type\":\"push\","
        "\"push_token\":\"%s\","
        "\"push_title\":\"%s\","
        "\"push_body\":\"%s\"}",
        token.c_str(), title, body);
    ws_client_send_raw(buf);
    Serial.printf("[Push] Wysłano: %s\n", title);
}

bool ws_client_send_raw(const char* json_msg) {
    if (!g_ws_connected) return false;
    return ws.sendTXT(json_msg);
}

bool ws_client_connected() { return g_ws_connected; }
void ws_client_tick()      { ws.loop(); }
