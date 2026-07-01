#include "http_internal.h"
#include "node_log.h"
#include "push_notify.h"
#include "node_integration.h"
#include "ws_client.h"
#include "identity.h"
#include "ble_config.h"
#include "wifi_manager.h"
#include "entity_store.h"
#include "message_router.h"
#include "script_engine.h"
#include <ArduinoJson.h>
#include <Preferences.h>

#define NVS_NS_SCRIPTS "uscripts"

// GET/POST /config — centralna konfiguracja noda
static void handle_config() {
    if (!check_pin()) return;

    if (server.method() == HTTP_GET) {
        JsonDocument doc;
        doc["device_id"]    = g_device_id;
        doc["ip"]           = g_local_ip;
        doc["ws_connected"] = ws_client_connected();
        doc["push_token"]        = push_get_token();
        doc["integration_url"]   = node_integration_get_url();
        doc["native_entities_loaded"] = entity_native_count();
        String out; serializeJson(doc, out);
        server.send(200, "application/json", out);
        return;
    }

    if (server.method() == HTTP_POST) {
        if (!server.hasArg("plain")) {
            server.send(400, "application/json", "{\"error\":\"no body\"}"); return;
        }
        JsonDocument doc;
        if (deserializeJson(doc, server.arg("plain"))) {
            server.send(400, "application/json", "{\"error\":\"invalid json\"}"); return;
        }

        if (doc["push_token"].is<const char*>())
            push_set_token(doc["push_token"]);
        if (doc["integration_url"].is<const char*>())
            node_integration_set_url(doc["integration_url"]);
        if (doc["pin"].is<const char*>()) {
            const char* newPin = doc["pin"];
            if (strlen(newPin) >= 4) {
                Preferences p; p.begin("sensmos", false);
                p.putString("ble_pin", newPin); p.end();
                Serial.println("[Config] PIN zmieniony");
            }
        }

        // App-proof geo: apka podaje WYŁĄCZNIE GPS telefonu. FW go NIE przechowuje —
        // tylko przekazuje do BE przez node_config (WS); BE (setAppLocation) jest źródłem
        // prawdy i nakłada fuzz (domyślnie true). Pozycji nie ustawia się ręcznie.
        bool locationChanged = false;
        const char* gpsLat = doc["gps_lat"] | "";
        const char* gpsLon = doc["gps_lon"] | "";
        bool fuzz = doc["fuzz"] | true;
        if (strlen(gpsLat) > 0 && strlen(gpsLon) > 0) {
            float latF = atof(gpsLat);
            float lonF = atof(gpsLon);
            if (latF >= -90.0f && latF <= 90.0f && lonF >= -180.0f && lonF <= 180.0f) {
                char wsMsg[180];
                snprintf(wsMsg, sizeof(wsMsg),
                    "{\"type\":\"node_config\",\"gps_lat\":%s,\"gps_lon\":%s,\"fuzz\":%s}",
                    gpsLat, gpsLon, fuzz ? "true" : "false");
                locationChanged = ws_client_send_raw(wsMsg);
                Serial.printf("[Config] GPS app-proof -> BE: %s,%s fuzz=%d sent=%d\n",
                    gpsLat, gpsLon, fuzz, locationChanged);
                node_log_push("config", locationChanged ? "location sent" : "location send failed (ws off)", locationChanged);
            }
        }

        server.send(200, "application/json",
            locationChanged
                ? "{\"status\":\"ok\",\"location_sent\":true}"
                : "{\"status\":\"ok\"}");
        return;
    }
    server.send(405, "application/json", "{\"error\":\"method not allowed\"}");
}

// ── /config/scripts (UserScripts w NVS) ───────────────────────
static void handle_scripts_get() {
    if (!check_pin()) return;
    Preferences prefs;
    prefs.begin(NVS_NS_SCRIPTS, true);
    int count = prefs.getInt("count", 0);
    JsonDocument doc;
    doc["count"] = count;
    doc["max"]   = MAX_USERSCRIPTS;
    JsonArray arr = doc["scripts"].to<JsonArray>();
    for (int i = 0; i < count; i++) {
        char key[8];
        snprintf(key, sizeof(key), "us_%d", i);
        if (prefs.isKey(key)) {
            String s = prefs.getString(key);
            JsonDocument sdoc;
            if (!deserializeJson(sdoc, s)) arr.add(sdoc.as<JsonObject>());
        }
    }
    prefs.end();
    String out; serializeJson(doc, out);
    server.send(200, "application/json", out);
}

static void handle_scripts_post() {
    if (!check_pin()) return;
    if (!server.hasArg("plain")) {
        server.send(400, "application/json", "{\"error\":\"no body\"}"); return;
    }
    JsonDocument doc;
    if (deserializeJson(doc, server.arg("plain"))) {
        server.send(400, "application/json", "{\"error\":\"invalid json\"}"); return;
    }
    const char* id = doc["id"] | "";
    if (strlen(id) == 0) {
        server.send(400, "application/json", "{\"error\":\"missing id\"}"); return;
    }

    Preferences prefs;
    prefs.begin(NVS_NS_SCRIPTS, false);
    int count = prefs.getInt("count", 0);

    int slot = -1;
    for (int i = 0; i < count; i++) {
        char key[8]; snprintf(key, sizeof(key), "us_%d", i);
        if (prefs.isKey(key)) {
            String s = prefs.getString(key);
            JsonDocument sd;
            if (!deserializeJson(sd, s))
                if (strcmp(sd["id"] | "", id) == 0) { slot = i; break; }
        }
    }

    if (slot < 0) {
        if (count >= MAX_USERSCRIPTS) {
            prefs.end();
            server.send(400, "application/json", "{\"error\":\"max scripts reached\"}"); return;
        }
        slot = count;
        count++;
        prefs.putInt("count", count);
    }

    doc.remove("private");
    String body; serializeJson(doc, body);
    char key[8]; snprintf(key, sizeof(key), "us_%d", slot);
    prefs.putString(key, body);
    prefs.end();

    extern int script_engine_load_user();
    script_engine_load_user();

    Serial.printf("[Scripts] User script saved: %s (slot %d)\n", id, slot);
    server.send(200, "application/json", "{\"status\":\"ok\"}");
}

static void handle_scripts_delete() {
    if (!check_pin()) return;
    String id = server.arg("id");
    if (id.isEmpty()) {
        server.send(400, "application/json", "{\"error\":\"missing id\"}"); return;
    }

    Preferences prefs;
    prefs.begin(NVS_NS_SCRIPTS, false);
    int count = prefs.getInt("count", 0);
    bool found = false;

    for (int i = 0; i < count; i++) {
        char key[8]; snprintf(key, sizeof(key), "us_%d", i);
        if (prefs.isKey(key)) {
            String s = prefs.getString(key);
            JsonDocument sd;
            if (!deserializeJson(sd, s)) {
                if (strcmp(sd["id"] | "", id.c_str()) == 0) {
                    prefs.remove(key);
                    for (int j = i; j < count - 1; j++) {
                        char src[8], dst[8];
                        snprintf(src, sizeof(src), "us_%d", j+1);
                        snprintf(dst, sizeof(dst), "us_%d", j);
                        if (prefs.isKey(src)) {
                            prefs.putString(dst, prefs.getString(src));
                            prefs.remove(src);
                        }
                    }
                    count--;
                    prefs.putInt("count", count);
                    found = true;
                    break;
                }
            }
        }
    }
    prefs.end();

    if (found) {
        extern int script_engine_load_user();
        script_engine_load_user();
        Serial.printf("[Scripts] User script deleted: %s\n", id.c_str());
        server.send(200, "application/json", "{\"status\":\"ok\"}");
    } else {
        server.send(404, "application/json", "{\"error\":\"not found\"}");
    }
}

// ── /config/messages (message_router) ─────────────────────────
static void handle_messages_get() {
    if (!check_pin()) return;
    server.send(200, "application/json", message_router_get_config_json());
}

static void handle_messages_post() {
    if (!check_pin()) return;
    if (!server.hasArg("plain")) {
        server.send(400, "application/json", "{\"error\":\"no body\"}"); return;
    }
    JsonDocument doc;
    if (deserializeJson(doc, server.arg("plain"))) {
        server.send(400, "application/json", "{\"error\":\"invalid json\"}"); return;
    }

    const char* mid = doc["message_id"] | "";
    if (strlen(mid) == 0) {
        server.send(400, "application/json", "{\"error\":\"missing message_id\"}"); return;
    }

    MessageAction action;
    memset(&action, 0, sizeof(action));
    strncpy(action.message_id, mid,                sizeof(action.message_id)-1);
    strncpy(action.webhook,    doc["webhook"] | "", sizeof(action.webhook)-1);
    strncpy(action.script_id,  doc["script"]  | "", sizeof(action.script_id)-1);

    const char* raw_pfx = doc["prefix"] | "";
    if (strcmp(raw_pfx,"pub")==0 || strcmp(raw_pfx,"own")==0 || strcmp(raw_pfx,"tmp")==0) {
        server.send(400, "application/json", "{\"error\":\"prefix reserved\"}"); return;
    }
    strncpy(action.prefix, raw_pfx, sizeof(action.prefix)-1);

    if (doc["push"].is<JsonObject>()) {
        strncpy(action.push_title, doc["push"]["title"] | "", sizeof(action.push_title)-1);
        strncpy(action.push_body,  doc["push"]["body"]  | "", sizeof(action.push_body)-1);
    }

    if (!message_router_set_by_id(action)) {
        server.send(409, "application/json", "{\"error\":\"max 3 message actions\"}"); return;
    }
    Serial.printf("[Config] message_action set: %s\n", mid);
    server.send(200, "application/json", "{\"status\":\"ok\"}");
}

static void handle_messages_delete() {
    if (!check_pin()) return;
    String mid = server.arg("id");
    if (mid.length() == 0) {
        server.send(400, "application/json", "{\"error\":\"missing id\"}"); return;
    }
    if (!message_router_delete_by_id(mid.c_str())) {
        server.send(404, "application/json", "{\"error\":\"not found\"}"); return;
    }
    Serial.printf("[Config] message_action deleted: %s\n", mid.c_str());
    server.send(200, "application/json", "{\"status\":\"ok\"}");
}

void register_config_routes() {
    server.on("/config",          handle_config);
    server.on("/config/scripts",  HTTP_GET,    handle_scripts_get);
    server.on("/config/scripts",  HTTP_POST,   handle_scripts_post);
    server.on("/config/scripts",  HTTP_DELETE, handle_scripts_delete);
    server.on("/config/messages", HTTP_GET,    handle_messages_get);
    server.on("/config/messages", HTTP_POST,   handle_messages_post);
    server.on("/config/messages", HTTP_DELETE, handle_messages_delete);
}
