#include "node_integration.h"
/**
 * SENSMOS Firmware — WebSocket Client
 * Połączenie z backendem, routing wiadomości.
 */
#include "ws_client.h"
#include "ota.h"
#include "entity_store.h"
#include "identity.h"
#include "ble_config.h"
#include "wifi_manager.h"
#include "subscription_map.h"
#include "http_server.h"
#include "node_log.h"
#include "message_router.h"
#include "checknet.h"
#include "monitors.h"
#include "data_sender.h"
#include "log.h"
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

    // host = bufor char[64] u wywolujacego → clamp do 63, inaczej dlugi host = stack overflow
    const size_t HOST_MAX = 63;
    if (colon && (!slash || colon < slash)) {
        size_t n = (size_t)(colon - p); if (n > HOST_MAX) n = HOST_MAX;
        strncpy(host, p, n); host[n] = '\0';
        *port = atoi(colon + 1);
    } else if (slash) {
        size_t n = (size_t)(slash - p); if (n > HOST_MAX) n = HOST_MAX;
        strncpy(host, p, n); host[n] = '\0';
        *port = defPort;
    } else {
        strncpy(host, p, HOST_MAX); host[HOST_MAX] = '\0';
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
    doc["nonce"]     = data_sender_new_nonce();   // K3: bootstrap nonce — BE ma go od 1. wiadomości (komendy tuż po connect)
    doc["firmware"]  = FW_VERSION;
    // Dane plytki RAZ na polaczenie (nie w kazdym batchu): model/rev/MHz/flash ->
    // devices.chip; korelacja czasow TLS/probe ze sprzetem
    static char s_chip[48] = {0};
    if (!s_chip[0])
        snprintf(s_chip, sizeof(s_chip), "%s r%d @%luMHz %luMB",
                 ESP.getChipModel(), (int)ESP.getChipRevision(),
                 (unsigned long)ESP.getCpuFreqMHz(),
                 (unsigned long)(ESP.getFlashChipSize() / (1024UL*1024UL)));
    doc["chip"] = s_chip;

    String packet;
    serializeJson(doc, packet);
    ws.sendTXT(packet);
    LOGD("ws", "identify sent (%dB)", packet.length());
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
    node_integration_push("ws_connected", "{}");

    uint32_t st = doc["server_time"] | 0;   // czas serwera (informacyjnie)

    // Załaduj native_entities
    int loaded = 0;
    for (JsonObject e : doc["entities"].as<JsonArray>()) {
        const char* eid = e["entity_id"] | "";
        if (strlen(eid) > 0) { entity_load_native(eid); loaded++; }
    }

    // Zapisz session token
    const char* token = doc["session_token"] | "";
    if (strlen(token) > 0) g_session_token = String(token);

    LOGI("ws", "identified (%d native entities, server_time=%u)", loaded, st);
}

static void on_message_recv(JsonDocument& doc) {
    const char* from       = doc["from"]    | "unknown";
    const char* message_id = doc["eid"]     | "unknown";
    const char* pl         = doc["payload"] | "";

    http_inbox_push(from, message_id, pl);
    LOGD("ws", "message %s from %.8s", message_id, from);
    message_router_dispatch(from, message_id, pl);
}

static void on_message_sent(JsonDocument& doc) {
    bool delivered = doc["delivered"] | false;
    if (!delivered) LOGD("ws", "message: recipient offline");
}

static void on_batch_ack(JsonDocument& doc) {
    int saved = doc["entities_saved"] | 0;
    LOGD("ws", "batch ack: %d entities", saved);
    char detail[32], sse[64];
    snprintf(detail, sizeof(detail), "%d entities saved", saved);
    snprintf(sse,    sizeof(sse),    "{\"entities_saved\":%d}", saved);
    node_log_push("batch", detail, true);
    node_integration_push("batch_sent", sse);
}

static void on_batch_error(JsonDocument& doc) {
    LOGW("ws", "batch error: %s", doc["error"] | "?");
}

static void on_tasks_update(JsonDocument& doc) {
    extern int script_engine_load(const JsonArray&);
    extern int script_engine_load_user();
    int n = script_engine_load(doc["scripts"].as<JsonArray>());
    script_engine_load_user();
    LOGD("ws", "tasks: %d BE scripts", n);
}

static void on_tasks_clear(JsonDocument& doc) {
    extern void script_engine_clear();
    script_engine_clear();
    LOGD("ws", "scripts cleared");
}

// K3: komenda zmieniająca stan musi być PODPISANA kluczem BE + nieść świeży nonce (anti-replay).
// BE podpisuje sha256("type:nonce") kluczem BE_priv; node weryfikuje kluczem BE_pub wbudowanym w FW.
// Chroni przed wstrzyknięciem komend przez plaintext WS (rogue AP / MITM w LAN).
static bool cmd_authorized(JsonDocument& doc, const char* type) {
    const char* sig_hex = doc["sig"]   | "";
    const char* nonce   = doc["nonce"] | "";
    if (!*sig_hex || !*nonce) { LOGW("ws", "%s: missing sig/nonce — rejected", type); return false; }
    if (!data_sender_nonce_valid(nonce)) { LOGW("ws", "%s: stale nonce (replay?) — rejected", type); return false; }
    size_t sl = strlen(sig_hex) / 2;
    if (sl == 0 || sl > 80) return false;
    uint8_t sig[80];
    for (size_t i = 0; i < sl; i++) { unsigned v; if (sscanf(sig_hex + i*2, "%2x", &v) != 1) return false; sig[i] = (uint8_t)v; }
    char msg[80];
    snprintf(msg, sizeof(msg), "%s:%s", type, nonce);
    if (!identity_verify_be(msg, sig, sl)) { LOGW("ws", "%s: bad BE signature — rejected", type); return false; }
    LOGD("ws", "%s: BE signature ok", type);
    data_sender_burn_nonce(nonce);   // single-use — zużyty nonce znika z puli (3 ostatnich)
    data_sender_send_ping();         // wymuś świeży nonce → BE od razu dostaje nowy
    return true;
}

// Zdalny restart (BE admin) — czyści wyciekłą pamięć bez fizycznego dostępu. Wymaga podpisu BE (K3).
static void on_reboot(JsonDocument& doc) {
    if (!cmd_authorized(doc, "reboot")) return;
    LOGW("ws", "remote reboot — restarting");
    delay(300);
    ESP.restart();
}

static void on_subscription_push(JsonDocument& doc) {
    const char* from = doc["from"] | "?";
    char detail[48], sse[96];
    snprintf(detail, sizeof(detail), "from:%.8s", from);
    snprintf(sse,    sizeof(sse),    "{\"from\":\"%.8s...\"}",  from);
    node_log_push("sub_push", detail, true);
    node_integration_push("sub_received", sse);
    LOGD("ws", "sub push from %.8s", from);
    push_remote_entities(
        doc["user"].as<JsonObject>(),
        doc["pub"].as<JsonArray>(),
        from
    );
}

static void on_error(JsonDocument& doc) {
    LOGW("ws", "backend error: %s", doc["msg"] | "?");
}

static void on_check_jobs(JsonDocument& doc) {
    checknet_on_jobs(doc["jobs"].as<JsonArray>());
}

// Config checknetu z BE (interwał adaptacyjny wg floty + limity). Stary FW ignoruje ten typ.
static void on_cn_config(JsonDocument& doc) {
    bool     en = doc["enabled"]    | true;
    uint32_t iv = (uint32_t)(doc["interval_s"] | 600) * 1000UL;
    int      mj = doc["max_jobs"]   | 6;
    int      pc = doc["ping_count"] | 5;
    checknet_set_config(en, iv, mj, pc);
}

// R3 monitory kierowane (v0.30+): deskryptor/odwolanie z BE. Stary FW ignoruje te typy.
static void on_monitor_set(JsonDocument& doc) {
    monitors_on_set(doc["monitor"].as<JsonObject>());
}
static void on_monitor_clear(JsonDocument& doc) {
    monitors_on_clear((int32_t)(doc["id"] | 0));
}

// OTA (v0.35+): podpis BE nad parametrami weryfikuje ota_handle. Stary FW ignoruje typ.
static void on_ota(JsonDocument& doc) {
    ota_handle(doc);
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
    { "reboot",            on_reboot },
    { "subscription_push", on_subscription_push },
    { "check_jobs",        on_check_jobs },
    { "cn_config",         on_cn_config },
    { "monitor_set",       on_monitor_set },
    { "monitor_clear",     on_monitor_clear },
    { "ota",               on_ota },
    { "error",             on_error },
};

// ── Obsługa wiadomości ────────────────────────────────────────
static void handle_message(const char* payload) {
    JsonDocument doc;
    if (deserializeJson(doc, payload)) {
        LOGW("ws", "JSON parse error");
        return;
    }
    const char* type = doc["type"] | "";

    if (strcmp(type, "pong") == 0) return;

    for (const WsEntry& e : WS_TABLE) {
        if (strcmp(type, e.type) == 0) { e.fn(doc); return; }
    }
    LOGD("ws", "unknown type: %s", type);
}

// ── WS Events ─────────────────────────────────────────────────
static void wsEvent(WStype_t event, uint8_t* payload, size_t length) {
    switch (event) {
        case WStype_CONNECTED:
            LOGI("ws", "connected (heap %uk)", ESP.getFreeHeap() / 1024);
            send_identify();
            break;
        case WStype_DISCONNECTED:
            g_ws_connected = false;
            if (payload && length) LOGW("ws", "disconnected: %.*s", (int)length, (char*)payload);
            else                   LOGW("ws", "disconnected");
            break;
        case WStype_TEXT:
            handle_message((char*)payload);
            break;
        case WStype_ERROR:
            if (payload && length) LOGE("ws", "error: %.*s", (int)length, (char*)payload);
            else                   LOGE("ws", "error");
            break;
        case WStype_PING: LOGD("ws", "ping"); break;
        case WStype_PONG: LOGD("ws", "pong"); break;
        default: break;
    }
}

// ── API ───────────────────────────────────────────────────────
void ws_client_init() {
    if (!g_wifi_connected || strlen(g_backend_url) == 0) return;

    char host[64] = {0}, path[64] = {0};
    int  port = 80; bool secure = false;
    if (!parseUrl(g_backend_url, host, &port, path, &secure)) {
        LOGE("ws", "URL parse error");
        return;
    }

#if WS_PLAINTEXT
    secure = false;               // WS bez TLS → ~70KB heapu więcej (dane i tak podpisane)
    port   = WS_PLAINTEXT_PORT;   // ws://host:80/v1/ws (nginx → :3000). Fetch/HTTP zostają https.
#endif

    LOGI("ws", "connecting %s://%s:%d%s", secure ? "wss" : "ws", host, port, path);
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
        LOGD("push", "no token — push skipped");
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
    LOGD("push", "sent: %s", title);
}

bool ws_client_send_raw(const char* json_msg) {
    if (!g_ws_connected) return false;
    return ws.sendTXT(json_msg);
}

bool ws_client_connected() { return g_ws_connected; }
void ws_client_tick()      { ws.loop(); }
