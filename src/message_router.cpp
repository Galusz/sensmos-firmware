#include "message_router.h"
#include "entity_store.h"
#include "template_engine.h"
#include "http_client_util.h"
#include "ws_client.h"
#include "script_engine.h"
#include "log.h"
#include <Preferences.h>
#include <ArduinoJson.h>

static MessageAction _actions[MAX_MESSAGE_SLOTS];

// ── NVS ───────────────────────────────────────────────────────

static void nvsSet(const char* key, const char* val) {
    Preferences p; p.begin("mrouter", false);
    p.putString(key, val); p.end();
}
static String nvsGet(const char* key, const char* def = "") {
    Preferences p; p.begin("mrouter", true);
    String v = p.getString(key, def); p.end(); return v;
}

// ── Init ──────────────────────────────────────────────────────

void message_router_init() {
    memset(_actions, 0, sizeof(_actions));
    char k[12];
    for (int i = 0; i < MAX_MESSAGE_SLOTS; i++) {
        snprintf(k,sizeof(k),"mid%d",i); strncpy(_actions[i].message_id, nvsGet(k).c_str(), sizeof(_actions[i].message_id)-1);
        snprintf(k,sizeof(k),"mwh%d",i); strncpy(_actions[i].webhook,    nvsGet(k).c_str(), sizeof(_actions[i].webhook)-1);
        snprintf(k,sizeof(k),"mph%d",i); strncpy(_actions[i].push_title, nvsGet(k).c_str(), sizeof(_actions[i].push_title)-1);
        snprintf(k,sizeof(k),"mpb%d",i); strncpy(_actions[i].push_body,  nvsGet(k).c_str(), sizeof(_actions[i].push_body)-1);
        snprintf(k,sizeof(k),"msi%d",i); strncpy(_actions[i].script_id,  nvsGet(k).c_str(), sizeof(_actions[i].script_id)-1);
        snprintf(k,sizeof(k),"mpx%d",i); strncpy(_actions[i].prefix,     nvsGet(k).c_str(), sizeof(_actions[i].prefix)-1);
    }
    LOGI("router", "init");
}

// ── Helper — match ────────────────────────────────────────────

bool message_router_id_matches(const char* slot_id, const char* message_id) {
    if (!slot_id || strlen(slot_id) == 0) return false;
    return strcmp(slot_id, message_id) == 0 || strcmp(slot_id, "*") == 0;
}

// ── Dispatch helpers ──────────────────────────────────────────

static void run_entity_save(int i, const char* payload) {
    const char* pfx = _actions[i].prefix;
    if (!*pfx || strcmp(pfx,"pub")==0 || strcmp(pfx,"own")==0 || strcmp(pfx,"tmp")==0) return;
    if (!payload || !*payload) return;
    JsonDocument doc;
    if (deserializeJson(doc, payload) || !doc.is<JsonObject>()) return;
    int saved = 0;
    if (doc["entities"].is<JsonArray>()) {
        for (JsonObject e : doc["entities"].as<JsonArray>()) {
            const char* eid_raw = e["entity_id"] | "";
            const char* val     = e["value"]     | "";
            const char* unit    = e["unit"]      | "";
            if (!*eid_raw || !*val) continue;
            const char* k = eid_raw;
            if (strncmp(k,"pub.",4)==0||strncmp(k,"own.",4)==0||
                strncmp(k,"sub.",4)==0||strncmp(k,"tmp.",4)==0) k += 4;
            char eid[36]; snprintf(eid, sizeof(eid), "%s.%s", pfx, k);
            entity_push(eid, val, unit);
            saved++;
        }
    } else {
        for (JsonPair kv : doc.as<JsonObject>()) {
            const char* k = kv.key().c_str();
            if      (strncmp(k,"pub.",4)==0) k += 4;
            else if (strncmp(k,"own.",4)==0) k += 4;
            else if (strncmp(k,"sub.",4)==0) k += 4;
            else if (strncmp(k,"msg.",4)==0) k += 4;
            else if (strncmp(k,"tmp.",4)==0) k += 4;
            char eid[36]; snprintf(eid, sizeof(eid), "%s.%s", pfx, k);
            char val[64] = "";
            if (kv.value().is<const char*>())
                strncpy(val, kv.value().as<const char*>(), sizeof(val)-1);
            else {
                float fv = kv.value().as<float>();
                (fv==(int)fv) ? snprintf(val,sizeof(val),"%d",(int)fv)
                              : snprintf(val,sizeof(val),"%.2f",fv);
            }
            entity_push(eid, val, "");
            saved++;
        }
    }
    LOGD("router", "slot%d -> %d %s.*", i, saved, pfx);
}

static void run_webhook(int i, const char* from, const char* message_id, const char* payload) {
    if (!*_actions[i].webhook) return;
    JsonDocument doc;
    doc["message_id"] = message_id;
    doc["from"]       = from ? from : "";
    doc["ts"]         = millis();
    if (payload && *payload) {
        JsonDocument pd;
        if (!deserializeJson(pd, payload)) doc["data"] = pd;
        else doc["data"] = payload;
    }
    String body; serializeJson(doc, body);
    int code = http_post_json(_actions[i].webhook, body.c_str(), HTTP_TIMEOUT_WEBHOOK);
    LOGD("router", "webhook slot%d HTTP %d", i, code);
}

static void run_push(int i, const char* from, const char* payload) {
    if (!*_actions[i].push_title) return;
    char title[64] = "", body[128] = "";
    fill_template(_actions[i].push_title, title, sizeof(title), from, payload);
    fill_template(_actions[i].push_body,  body,  sizeof(body),  from, payload);
    LOGD("router", "push slot%d: %s", i, title);
    ws_client_send_push(title, body);
}

static void run_script(int i) {
    if (!*_actions[i].script_id) return;
    LOGD("router", "script slot%d -> %s", i, _actions[i].script_id);
    script_engine_run_by_id(_actions[i].script_id);
}

// ── Dispatch ──────────────────────────────────────────────────

void message_router_dispatch(const char* from, const char* message_id, const char* payload) {
    if (!message_id) return;
    LOGD("router", "message_id=%s from=%.8s", message_id, from ? from : "?");
    for (int i = 0; i < MAX_MESSAGE_SLOTS; i++) {
        if (!message_router_id_matches(_actions[i].message_id, message_id)) continue;
        run_entity_save(i, payload);
        run_webhook(i, from, message_id, payload);
        run_push(i, from, payload);
        run_script(i);
    }
}

// ── Gettery / Settery ─────────────────────────────────────────

void message_router_set(int slot, const MessageAction& action) {
    if (slot < 0 || slot >= MAX_MESSAGE_SLOTS) return;
    _actions[slot] = action;
    char k[12];
    snprintf(k,sizeof(k),"mid%d",slot); nvsSet(k, action.message_id);
    snprintf(k,sizeof(k),"mwh%d",slot); nvsSet(k, action.webhook);
    snprintf(k,sizeof(k),"mph%d",slot); nvsSet(k, action.push_title);
    snprintf(k,sizeof(k),"mpb%d",slot); nvsSet(k, action.push_body);
    snprintf(k,sizeof(k),"msi%d",slot); nvsSet(k, action.script_id);
    snprintf(k,sizeof(k),"mpx%d",slot); nvsSet(k, action.prefix);
}

MessageAction message_router_get(int slot) {
    if (slot < 0 || slot >= MAX_MESSAGE_SLOTS) return MessageAction{};
    return _actions[slot];
}

static int _find_slot(const char* message_id) {
    for (int i = 0; i < MAX_MESSAGE_SLOTS; i++)
        if (strcmp(_actions[i].message_id, message_id) == 0) return i;
    return -1;
}

static int _find_empty_slot() {
    for (int i = 0; i < MAX_MESSAGE_SLOTS; i++)
        if (strlen(_actions[i].message_id) == 0) return i;
    return -1;
}

bool message_router_set_by_id(const MessageAction& action) {
    if (strlen(action.message_id) == 0) return false;
    int slot = _find_slot(action.message_id);
    if (slot < 0) slot = _find_empty_slot();
    if (slot < 0) return false;
    message_router_set(slot, action);
    return true;
}

bool message_router_delete_by_id(const char* message_id) {
    int slot = _find_slot(message_id);
    if (slot < 0) return false;
    MessageAction empty; memset(&empty, 0, sizeof(empty));
    message_router_set(slot, empty);
    return true;
}

String message_router_get_config_json() {
    JsonDocument doc;
    JsonArray arr = doc["message_actions"].to<JsonArray>();
    for (int i = 0; i < MAX_MESSAGE_SLOTS; i++) {
        if (strlen(_actions[i].message_id) == 0) continue;
        JsonObject o = arr.add<JsonObject>();
        o["message_id"] = _actions[i].message_id;
        o["prefix"]     = _actions[i].prefix;
        o["webhook"]    = _actions[i].webhook;
        JsonObject push = o["push"].to<JsonObject>();
        push["title"]   = _actions[i].push_title;
        push["body"]    = _actions[i].push_body;
        o["script"]     = _actions[i].script_id;
    }
    doc["count"] = (int)arr.size();
    doc["max"]   = MAX_MESSAGE_SLOTS;
    String out; serializeJson(doc, out);
    return out;
}
