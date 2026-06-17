#include "http_internal.h"
#include "entity_store.h"
#include "data_sender.h"
#include "identity.h"
#include <ArduinoJson.h>

// GET /data/native — lista natywnych encji załadowanych z BE
static void handle_data_native() {
    if (!check_pin()) return;
    JsonDocument doc;
    doc["count"] = entity_native_count();
    JsonArray arr = doc["entities"].to<JsonArray>();
    for (int i = 0; i < entity_native_count(); i++) {
        const char* name = entity_get_native(i);
        if (!name) continue;
        JsonObject e = arr.add<JsonObject>();
        e["entity_id"] = name;
        e["pub_id"]    = String("pub.") + name;
        char pub_eid[36]; snprintf(pub_eid, sizeof(pub_eid), "pub.%s", name);
        char val[64]="", unit[16]=""; unsigned long ts=0;
        bool found = false;
        int cnt = entity_count();
        for (int j = 0; j < cnt; j++) {
            char eid[32], ev[64], eu[16]; unsigned long ets;
            entity_get(j, eid, ev, eu, &ets);
            if (strcmp(eid, pub_eid)==0 || strcmp(eid, name)==0) {
                strncpy(val,  ev, sizeof(val)-1);
                strncpy(unit, eu, sizeof(unit)-1);
                ts = ets; found = true; break;
            }
        }
        if (found) {
            e["value"] = val;
            e["unit"]  = unit;
            e["age_s"] = (long)(millis()/1000 - ts);
        } else {
            e["value"] = nullptr;
        }
    }
    String out; serializeJson(doc, out);
    server.send(200, "application/json", out);
}

// GET /data/status — podgląd buforów (pub/own/pool, pełne prefixy)
static void handle_data_status() {
    if (!check_pin()) return;
    JsonDocument doc;
    doc["device_id"]    = g_device_id;
    doc["buffer_count"] = entity_count();
    doc["uptime_s"]     = millis() / 1000;
    JsonArray pub_arr  = doc["pub"].to<JsonArray>();
    JsonArray own_arr  = doc["own"].to<JsonArray>();
    JsonArray pool_arr = doc["pool"].to<JsonArray>();

    for (int i = 0; i < entity_pub_count(); i++) {
        char eid[36], val[64], unit[12]; unsigned long ts;
        if (!entity_get_pub(i, eid, val, unit, &ts)) continue;
        JsonObject e = pub_arr.add<JsonObject>();
        e["entity_id"] = eid;
        e["value"] = val; e["unit"] = unit;
        e["age_s"] = (long)(millis()/1000 - ts);
    }
    for (int i = 0; i < entity_own_count(); i++) {
        char eid[36], val[64], unit[12]; unsigned long ts;
        if (!entity_get_own(i, eid, val, unit, &ts)) continue;
        JsonObject e = own_arr.add<JsonObject>();
        e["entity_id"] = eid;
        e["value"] = val; e["unit"] = unit;
        e["age_s"] = (long)(millis()/1000 - ts);
    }
    for (int i = 0; i < entity_pool_count(); i++) {
        char eid[36], val[64], unit[12]; unsigned long ts;
        if (!entity_get_pool(i, eid, val, unit, &ts)) continue;
        JsonObject e = pool_arr.add<JsonObject>();
        e["entity_id"] = eid;
        e["value"] = val; e["unit"] = unit;
        e["age_s"] = (long)(millis()/1000 - ts);
    }
    String out; serializeJson(doc, out);
    server.send(200, "application/json", out);
}

// POST /data — dodaj encję (auto pub./own.)
static void handle_data_post() {
    if (!check_pin()) return;
    if (!server.hasArg("plain")) {
        server.send(400, "application/json", "{\"error\":\"no body\"}"); return;
    }
    JsonDocument doc;
    if (deserializeJson(doc, server.arg("plain"))) {
        server.send(400, "application/json", "{\"error\":\"invalid json\"}"); return;
    }
    const char* eid  = doc["entity_id"];
    const char* val  = doc["value"];
    const char* unit = doc["unit"] | "";
    if (!eid || !val) {
        server.send(400, "application/json", "{\"error\":\"missing fields\"}"); return;
    }
    if (strncmp(eid, "pub.", 4) == 0 && !entity_is_native(eid + 4)) {
        server.send(400, "application/json", "{\"error\":\"unknown public entity\"}"); return;
    }
    char full[36];
    bool is_pub = entity_classify(eid, full, sizeof(full));
    entity_push(full, val, unit);
    if (is_pub) data_sender_trigger();
    Serial.printf("[HTTP] %s = %s\n", full, val);
    server.send(200, "application/json", "{\"status\":\"ok\"}");
}

// POST /data/batch — wiele encji naraz
static void handle_data_batch() {
    if (!check_pin()) return;
    if (!server.hasArg("plain")) {
        server.send(400, "application/json", "{\"error\":\"no body\"}"); return;
    }
    JsonDocument doc;
    if (deserializeJson(doc, server.arg("plain"))) {
        server.send(400, "application/json", "{\"error\":\"invalid json\"}"); return;
    }
    JsonArray entities = doc["entities"].as<JsonArray>();
    int saved = 0;
    bool any_pub = false;
    for (JsonObject e : entities) {
        const char* eid  = e["entity_id"] | "";
        const char* val  = e["value"]     | "";
        const char* unit = e["unit"]      | "";
        if (strlen(eid) == 0 || strlen(val) == 0) continue;
        char full[36];
        bool is_pub = entity_classify(eid, full, sizeof(full));
        entity_push(full, val, unit);
        if (is_pub) any_pub = true;
        saved++;
    }
    if (any_pub) data_sender_trigger();
    char resp[64];
    snprintf(resp, sizeof(resp), "{\"status\":\"ok\",\"saved\":%d}", saved);
    server.send(200, "application/json", resp);
}

void register_data_routes() {
    server.on("/data",        HTTP_POST, handle_data_post);
    server.on("/data/batch",  HTTP_POST, handle_data_batch);
    server.on("/data/status", HTTP_GET,  handle_data_status);
    server.on("/data/native", HTTP_GET,  handle_data_native);
}
