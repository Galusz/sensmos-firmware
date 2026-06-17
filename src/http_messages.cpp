#include "http_internal.h"
#include "http_server.h"
#include "node_log.h"
#include "node_integration.h"
#include "ws_client.h"
#include "identity.h"
#include "ntp_time.h"
#include "config.h"
#include <ArduinoJson.h>

// ── Inbox ─────────────────────────────────────────────────────
#define INBOX_MSG_LEN 256

struct InboxMsg {
    char from[67];
    char message_id[32];
    char payload[INBOX_MSG_LEN];
    bool read;
};
static InboxMsg inbox[INBOX_SIZE];
static int      inbox_count = 0;

void http_inbox_push(const char* from, const char* message_id, const char* payload) {
    if (inbox_count >= INBOX_SIZE) {
        for (int i = 0; i < INBOX_SIZE - 1; i++) inbox[i] = inbox[i+1];
        inbox_count = INBOX_SIZE - 1;
    }
    char _log_detail[64];
    snprintf(_log_detail, sizeof(_log_detail), "from:%.8s id:%s", from, message_id);
    node_log_push("message_recv", _log_detail, true);
    char _sse_data[128];
    snprintf(_sse_data, sizeof(_sse_data),
        "{\"message_id\":\"%s\",\"from\":\"%.8s...\"}", message_id, from);
    node_integration_push("message_received", _sse_data);
    strncpy(inbox[inbox_count].from,       from,       66);
    strncpy(inbox[inbox_count].message_id, message_id, 31);
    strncpy(inbox[inbox_count].payload,    payload,    INBOX_MSG_LEN - 1);
    inbox[inbox_count].read = false;
    inbox_count++;
}

// POST /message/send — wyślij wiadomość przez WS
static void handle_message_send() {
    if (!check_pin()) return;
    if (!server.hasArg("plain")) {
        server.send(400, "application/json", "{\"error\":\"no body\"}"); return;
    }
    JsonDocument doc;
    if (deserializeJson(doc, server.arg("plain"))) {
        server.send(400, "application/json", "{\"error\":\"invalid json\"}"); return;
    }
    const char* to         = doc["to"];
    const char* message_id = doc["message_id"];
    if (!to || strlen(to) == 0) {
        server.send(400, "application/json", "{\"error\":\"missing to\"}"); return;
    }
    if (!message_id || strlen(message_id) == 0) {
        server.send(400, "application/json", "{\"error\":\"missing message_id\"}"); return;
    }

    JsonDocument msg;
    msg["from"]      = g_device_id;
    msg["to"]        = to;
    msg["type"]      = "message";
    msg["eid"]       = message_id;
    msg["timestamp"] = ntp_synced() ? ntp_unix_time() : (uint32_t)(millis() / 1000);

    if (doc["payload"].is<JsonObject>()) {
        String pl; serializeJson(doc["payload"], pl);
        msg["payload"] = pl;
    } else if (doc["entities"].is<JsonObject>()) {
        String pl; serializeJson(doc["entities"], pl);
        msg["payload"] = pl;
    } else {
        msg["payload"] = doc["payload"] | "{}";
    }

    String out; serializeJson(msg, out);
    if (ws_client_send_raw(out.c_str())) {
        Serial.printf("[Message] Wysłany: %s → %.8s\n", message_id, to);
        char log_detail[64];
        snprintf(log_detail, sizeof(log_detail), "→ %.8s mid:%s", to, message_id);
        node_log_push("message_sent", log_detail, true);
        server.send(200, "application/json", "{\"status\":\"ok\"}");
    } else {
        server.send(503, "application/json", "{\"error\":\"ws_not_connected\"}");
    }
}

// GET /message/inbox
static void handle_message_inbox() {
    if (!check_pin()) return;
    JsonDocument doc;
    doc["inbox_count"] = inbox_count;
    doc["inbox_max"]   = INBOX_SIZE;
    JsonArray arr = doc["messages"].to<JsonArray>();
    for (int i = 0; i < inbox_count; i++) {
        JsonObject m    = arr.add<JsonObject>();
        m["from"]       = inbox[i].from;
        m["message_id"] = inbox[i].message_id;
        m["payload"]    = inbox[i].payload;
        m["age_s"]      = 0;
        m["read"]       = inbox[i].read;
        inbox[i].read   = true;
    }
    String out; serializeJson(doc, out);
    server.send(200, "application/json", out);
}

// POST /message/ack — usuń wiadomości od nadawcy (lub przeczytane)
static void handle_message_ack() {
    if (!check_pin()) return;
    if (!server.hasArg("plain")) {
        server.send(400, "application/json", "{\"error\":\"no body\"}"); return;
    }
    JsonDocument doc;
    if (deserializeJson(doc, server.arg("plain"))) {
        server.send(400, "application/json", "{\"error\":\"invalid json\"}"); return;
    }
    const char* from = doc["from"] | "";
    int new_count = 0;
    if (strlen(from) == 0) {
        for (int i = 0; i < inbox_count; i++)
            if (!inbox[i].read) inbox[new_count++] = inbox[i];
    } else {
        for (int i = 0; i < inbox_count; i++)
            if (strcmp(inbox[i].from, from) != 0) inbox[new_count++] = inbox[i];
    }
    inbox_count = new_count;
    server.send(200, "application/json", "{\"status\":\"ok\"}");
}

void register_messages_routes() {
    server.on("/message/send",  HTTP_POST, handle_message_send);
    server.on("/message/inbox", HTTP_GET,  handle_message_inbox);
    server.on("/message/ack",   HTTP_POST, handle_message_ack);
}
