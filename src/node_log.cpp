#include "node_log.h"
#include "http_internal.h"
#include "config.h"
#include <ArduinoJson.h>

struct NodeLogEntry {
    char     type[16];
    char     detail[64];
    uint32_t ts_s;
    bool     ok;
};

static NodeLogEntry g_node_log[NODE_LOG_SIZE];
static int          g_log_count = 0;
static int          g_log_head  = 0;

void node_log_push(const char* type, const char* detail, bool ok) {
    NodeLogEntry& e = g_node_log[g_log_head % NODE_LOG_SIZE];
    strncpy(e.type,   type,   sizeof(e.type)   - 1);
    strncpy(e.detail, detail, sizeof(e.detail) - 1);
    e.ts_s = millis() / 1000;
    e.ok   = ok;
    g_log_head++;
    if (g_log_count < NODE_LOG_SIZE) g_log_count++;
}

void handle_node_log() {
    if (!check_pin()) return;
    JsonDocument doc;
    doc["uptime_s"] = millis() / 1000;
    JsonArray arr = doc["log"].to<JsonArray>();
    int total = min(g_log_count, NODE_LOG_SIZE);
    for (int i = total - 1; i >= 0; i--) {
        int idx = (g_log_head - 1 - i + NODE_LOG_SIZE * 2) % NODE_LOG_SIZE;
        NodeLogEntry& e = g_node_log[idx];
        JsonObject o = arr.add<JsonObject>();
        o["type"]   = e.type;
        o["detail"] = e.detail;
        o["ts_s"]   = e.ts_s;
        o["ok"]     = e.ok;
        o["ago_s"]  = (long)(millis()/1000) - (long)e.ts_s;
    }
    String out; serializeJson(doc, out);
    server.send(200, "application/json", out);
}
