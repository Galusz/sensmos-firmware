#include "script_engine.h"
#include "script_async.h"
#include "entity_store.h"
#include "template_engine.h"
#include "http_client_util.h"
#include "ws_client.h"
#include "checknet.h"
#include "config.h"
#include <math.h>

// Zapis float do encji (store) jako string
static void store_float(const char* store, float v, const char* unit = "") {
    if (!store || !*store) return;
    char sv[24];
    snprintf(sv, sizeof(sv), "%.4f", v);
    entity_push(store, sv, unit);
}

// ══════════════════════════════════════════════════════════════
// Akcje
// ══════════════════════════════════════════════════════════════

static void run_ping(Script& s, ScriptStep& step) {
    script_async_push_ping(s.id, step.host, step.timeout_ms, step.store);
}

static void run_fetch(Script& s, ScriptStep& step) {
    script_async_push_fetch(s.id, step.url, step.store, step.fetch_path);
}

static void run_aggregate(Script& s, ScriptStep& step) {
    // zbieraj próbki przy każdym odpaleniu; po N wyślij do async
    float val = script_resolve_var(step.entity);
    if (!isnan(val) && step.agg_count < 16)
        step.agg_buf[step.agg_count++] = val;

    if (step.samples > 0 && step.agg_count >= step.samples) {
        script_async_push_aggregate(s.id, step.entity, step.func,
                                    step.agg_buf, step.agg_count, step.store);
        step.agg_count = 0;
    }
}

static void run_calc(Script& s, ScriptStep& step) {
    (void)s;
    float result = script_eval_expr(step.expr);
    if (isnan(result)) return;
    // bez prefixu → tmp.
    char eid[MAX_ENTITY_LEN + 4];
    if (strchr(step.store, '.') == nullptr)
        snprintf(eid, sizeof(eid), "tmp.%s", step.store);
    else
        strncpy(eid, step.store, sizeof(eid) - 1), eid[sizeof(eid) - 1] = '\0';
    store_float(eid, result);
    Serial.printf("[Script] calc %s = %.2f\n", eid, result);
}

static void run_find(Script& s, ScriptStep& step) {
    (void)s;
    float found_val = NAN;
    bool  found     = false;

    // pub + own + pool
    int count = entity_count();
    for (int ei = 0; ei < count && !found; ei++) {
        char eid[36], eval_s[64], eunit[12];
        unsigned long ets;
        if (!entity_get(ei, eid, eval_s, eunit, &ets)) continue;

        if (*step.find_in) {
            char prefix[16];
            snprintf(prefix, sizeof(prefix), "%s.", step.find_in);
            if (strncmp(eid, prefix, strlen(prefix)) != 0) continue;
        }
        if (*step.find_key && !strstr(eid, step.find_key)) continue;

        // string equals / contains
        if (*step.find_equals) {
            if (strcmp(eval_s, step.find_equals) == 0 ||
                strstr(eval_s, step.find_equals)) {
                found = true; found_val = 1.0f;
            }
            continue;
        }

        // warunki numeryczne
        float fval = atof(eval_s);
        bool ok = true;
        if (step.find_has_gt  && !(fval >  step.find_gt))  ok = false;
        if (step.find_has_lt  && !(fval <  step.find_lt))  ok = false;
        if (step.find_has_gte && !(fval >= step.find_gte)) ok = false;
        if (step.find_has_lte && !(fval <= step.find_lte)) ok = false;
        if (ok) { found = true; found_val = fval; }
    }

    // tmp.*
    for (int pi = 0; pi < entity_tmp_count() && !found; pi++) {
        char tk[36] = "", tv[64] = "", tu[12] = "";
        if (!entity_get_tmp(pi, tk, tv, tu, nullptr)) continue;
        if (*step.find_in && strcmp(step.find_in, "tmp") != 0) continue;
        if (*step.find_key && !strstr(tk, step.find_key)) continue;
        float pv = atof(tv);
        if (step.find_has_gt  && !(pv >  step.find_gt))  continue;
        if (step.find_has_lt  && !(pv <  step.find_lt))  continue;
        if (step.find_has_gte && !(pv >= step.find_gte)) continue;
        if (step.find_has_lte && !(pv <= step.find_lte)) continue;
        found = true; found_val = pv;
    }

    float out = found ? (isnan(found_val) ? 1.0f : found_val) : 0.0f;
    store_float(step.store, out);
    Serial.printf("[Script] find → %s = %.2f\n", step.store, out);
}

static void run_webhook(Script& s, ScriptStep& step) {
    (void)s;
    if (!*step.url) return;
    char body[256] = "{}";
    if (*step.body_tmpl)
        fill_template(step.body_tmpl, body, sizeof(body), nullptr, nullptr, true);
    Serial.printf("[Script] webhook body: %s\n", body);
    int code = http_post_json(step.url, body, HTTP_TIMEOUT_WEBHOOK);
    Serial.printf("[Script] webhook HTTP %d\n", code);
}

static void run_push(Script& s, ScriptStep& step) {
    (void)s;
    char title[64] = "", body[128] = "";
    fill_template(step.push_title, title, sizeof(title));
    fill_template(step.push_body,  body,  sizeof(body));
    Serial.printf("[Script] push: %s\n", title);
    ws_client_send_push(title, body);
}

static void run_report(Script& s, ScriptStep& step) {
    // DataScript only — raport do BE (mapa/DB)
    JsonDocument payload_doc;

    if (*step.value_key) {
        float val = script_resolve_var(step.value_key);
        if (!isnan(val)) payload_doc["value"] = val;
    }

    if (*step.payload_map) {
        char pmap[sizeof(step.payload_map)];
        strncpy(pmap, step.payload_map, sizeof(pmap) - 1);
        pmap[sizeof(pmap) - 1] = '\0';
        char* tok = strtok(pmap, ",");
        while (tok) {
            char* colon = strchr(tok, ':');
            if (colon) {
                *colon = '\0';
                float val = script_resolve_var(colon + 1);
                if (!isnan(val)) payload_doc[tok] = val;
            }
            tok = strtok(nullptr, ",");
        }
    }

    String payload_str;
    serializeJson(payload_doc, payload_str);

    char msg[384];
    snprintf(msg, sizeof(msg),
        "{\"type\":\"script_report\","
        "\"script_id\":\"%s\","
        "\"report_id\":\"%s\","
        "\"severity\":\"%s\","
        "\"payload\":%s,"
        "\"ts\":%lu}",
        s.id, step.report_id,
        *step.severity ? step.severity : "info",
        payload_str.c_str(),
        millis() / 1000);
    ws_client_send_raw(msg);
}

static void run_send(Script& s, ScriptStep& step) {
    // UserScript only — wiadomość do innego noda
    (void)s;
    if (!*step.send_to || !*step.message_id) return;
    char payload[128] = "{}";
    fill_template(step.payload_tmpl, payload, sizeof(payload), nullptr, nullptr, true);

    char msg[512];
    snprintf(msg, sizeof(msg),
        "{\"type\":\"event\","          // Etap E: → "message"
        "\"to\":\"%s\","
        "\"eid\":\"%s\","
        "\"payload\":\"%s\"}",
        step.send_to, step.message_id, payload);
    ws_client_send_raw(msg);
}

// ══════════════════════════════════════════════════════════════
// Dispatch
// ══════════════════════════════════════════════════════════════

void script_fire_step(Script& s, ScriptStep& step) {
    const char* a = step.action;
    if      (!strcmp(a, "ping"))      run_ping(s, step);
    else if (!strcmp(a, "fetch"))     run_fetch(s, step);
    else if (!strcmp(a, "aggregate")) run_aggregate(s, step);
    else if (!strcmp(a, "calc"))      run_calc(s, step);
    else if (!strcmp(a, "find"))      run_find(s, step);
    else if (!strcmp(a, "webhook"))   run_webhook(s, step);
    else if (!strcmp(a, "push"))      run_push(s, step);
    else if (!strcmp(a, "report"))    run_report(s, step);
    else if (!strcmp(a, "send"))      run_send(s, step);
    else if (!strcmp(a, "checknet"))  checknet_run();
    else Serial.printf("[Script] nieznana akcja: %s\n", a);
}
