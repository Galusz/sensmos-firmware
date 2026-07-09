#include "script_engine.h"
#include "net_worker.h"
#include "log.h"
#include "entity_store.h"
#include "template_engine.h"
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

// store bez kropki → tmp.<store> (konwencja probe)
static void norm_store(const char* store, char* out, size_t out_len) {
    if (strchr(store, '.') == nullptr) snprintf(out, out_len, "tmp.%s", store);
    else { strncpy(out, store, out_len - 1); out[out_len - 1] = '\0'; }
}

// ── Raporty wyników async do BE (format WS jak dawny script_async) ──
static void _send_result(const char* script_id, const char* action,
                          const char* key, float value, int status = 0) {
    char msg[256];
    snprintf(msg, sizeof(msg),
        "{\"type\":\"script_async_result\","
        "\"script_id\":\"%s\","
        "\"action\":\"%s\","
        "\"%s\":%.4f,"
        "\"status\":%d,"
        "\"ts\":%lu}",
        script_id, action, key, value, status, millis()/1000);
    ws_client_send_raw(msg);
    LOGD("script", "%s.%s = %.2f (status=%d)", script_id, action, value, status);
}

static void _send_result_str(const char* script_id, const char* action,
                              const char* payload) {
    char msg[512];
    snprintf(msg, sizeof(msg),
        "{\"type\":\"script_async_result\","
        "\"script_id\":\"%s\","
        "\"action\":\"%s\","
        "\"data\":%s,"
        "\"ts\":%lu}",
        script_id, action, payload, millis()/1000);
    ws_client_send_raw(msg);
}

// ══════════════════════════════════════════════════════════════
// Akcje SIECIOWE → net_worker ("wór", ASYNC-QUEUE §8)
// Kolejkują job (lo-prio) i zwracają true = skrypt zawisa; wynik wraca przez
// script_apply_net_result i silnik wznawia od kroku+1. Enqueue nieudany → false
// (krok pominięty w tym przebiegu — jak dawny DEFER, bez fałszywego faila).
// ══════════════════════════════════════════════════════════════

static bool q_ping(Script& s, int idx, ScriptStep& step) {
    if (!step.host[0]) return false;
    uint32_t tok = script_engine_register_await(s.id, idx, "ping", step.store);
    if (!tok) return false;
    NetJob nj; memset(&nj, 0, sizeof(nj));
    nj.src = NW_SCRIPT; nj.ref_id = (int32_t)tok; nj.ref_idx = (int16_t)idx;
    strlcpy(nj.job.kind, "icmp", sizeof(nj.job.kind));
    strlcpy(nj.job.host, step.host, sizeof(nj.job.host));
    nj.job.count = 3;
    if (!net_worker_enqueue(nj, false)) { script_engine_cancel_await(tok); return false; }
    return true;
}

static bool q_probe(Script& s, int idx, ScriptStep& step) {
    if (!step.host[0] || !step.probe_kind[0]) return false;
    uint32_t tok = script_engine_register_await(s.id, idx, "probe", step.store);
    if (!tok) return false;
    NetJob nj; memset(&nj, 0, sizeof(nj));
    nj.src = NW_SCRIPT; nj.ref_id = (int32_t)tok; nj.ref_idx = (int16_t)idx;
    strlcpy(nj.job.kind, step.probe_kind, sizeof(nj.job.kind));
    strlcpy(nj.job.host, step.host, sizeof(nj.job.host));
    nj.job.port       = step.port;
    nj.job.timeout_ms = step.timeout_ms;
    strlcpy(nj.job.path, step.fetch_path[0] ? step.fetch_path : "/", sizeof(nj.job.path));
    strlcpy(nj.job.expected, step.expected, sizeof(nj.job.expected));
    nj.job.https    = (step.port == 80) ? 0 : 1;
    nj.job.http_get = 1;
    if (!net_worker_enqueue(nj, false)) { script_engine_cancel_await(tok); return false; }
    return true;
}

static bool q_fetch(Script& s, int idx, ScriptStep& step) {
    if (!step.url[0]) return false;
    uint32_t tok = script_engine_register_await(s.id, idx, "fetch", step.store);
    if (!tok) return false;
    NetJob nj; memset(&nj, 0, sizeof(nj));
    nj.src = NW_SCRIPT; nj.ref_id = (int32_t)tok; nj.ref_idx = (int16_t)idx;
    strlcpy(nj.job.kind, "fetch", sizeof(nj.job.kind));
    strlcpy(nj.url, step.url, sizeof(nj.url));
    strlcpy(nj.fetch_path, step.fetch_path, sizeof(nj.fetch_path));
    if (!net_worker_enqueue(nj, false)) { script_engine_cancel_await(tok); return false; }
    return true;
}

static bool q_webhook(Script& s, int idx, ScriptStep& step) {
    if (!step.url[0]) return false;
    uint32_t tok = script_engine_register_await(s.id, idx, "webhook", "");
    if (!tok) return false;
    NetJob nj; memset(&nj, 0, sizeof(nj));
    nj.src = NW_SCRIPT; nj.ref_id = (int32_t)tok; nj.ref_idx = (int16_t)idx;
    strlcpy(nj.job.kind, "whook", sizeof(nj.job.kind));
    strlcpy(nj.url, step.url, sizeof(nj.url));
    // template wypelniany TERAZ (wartosci z chwili odpalenia kroku, nie z chwili POST-a)
    strlcpy(nj.body, "{}", sizeof(nj.body));
    if (*step.body_tmpl)
        fill_template(step.body_tmpl, nj.body, sizeof(nj.body), nullptr, nullptr, true);
    LOGD("script", "webhook body: %s", nj.body);
    if (!net_worker_enqueue(nj, false)) { script_engine_cancel_await(tok); return false; }
    return true;
}

// ── Zastosuj wynik kroku sieciowego (dispatch w loop, przed resume) ──
void script_apply_net_result(const char* action, const char* store,
                             const char* script_id, const NetResult& nr) {
    // DEFER (TLS bez heapu): nic nie pisz — brak fałszywego faila, resume idzie dalej
    if (nr.deferred) {
        LOGD("script", "%s %s deferred — blk %u (low heap)", script_id, action, (unsigned)nr.heap_largest);
        return;
    }
    const CnResult& r = nr.res;

    if (!strcmp(action, "ping")) {
        float rtt = r.ok ? r.rtt_ms : -1.0f;
        _send_result(script_id, "ping", "rtt_ms", rtt, r.ok ? 1 : 0);
        if (store && *store) {
            char sv[24]; snprintf(sv, sizeof(sv), "%.0f", rtt);
            entity_push(store, sv, "ms");
        }
        LOGD("script", "ping %.0fms reachable=%d", rtt, r.ok ? 1 : 0);
        return;
    }
    if (!strcmp(action, "probe")) {
        bool ok = r.ok;   // dns hijack juz sciety w monitors? nie — tu:
        if (r.resolved_ip[0] && !r.match) ok = false;   // dns: niezgodny expected = fail
        char eid[MAX_ENTITY_LEN + 4];
        norm_store(store, eid, sizeof(eid));
        if (store && *store) {
            char val[16]; snprintf(val, sizeof(val), "%.1f", ok ? r.rtt_ms : -1.0f);
            entity_push(eid, val, "ms");
        }
        LOGD("script", "probe ok=%d %.0fms", ok, r.rtt_ms);
        return;
    }
    if (!strcmp(action, "fetch")) {
        if (nr.has_value && store && *store) {
            char sv[24]; snprintf(sv, sizeof(sv), "%.4f", nr.store_val);
            entity_push(store, sv, "");
        }
        if (nr.payload[0]) _send_result_str(script_id, "fetch", nr.payload);
        LOGD("script", "fetch HTTP %d val=%s", r.status_code, nr.has_value ? "ok" : "-");
        return;
    }
    if (!strcmp(action, "webhook")) {
        LOGD("script", "webhook HTTP %d", r.status_code);
        return;
    }
}

// Timeout/zgubiony wynik: ping/probe → -1 (konwencja "nieosiągalny"); fetch/webhook
// bez zapisu (nie wstrzykiwać śmieci do encji danych). Resume robi silnik.
void script_apply_net_fail(const char* action, const char* store, const char* script_id) {
    if (!strcmp(action, "ping")) {
        _send_result(script_id, "ping", "rtt_ms", -1.0f, 0);
        if (store && *store) entity_push(store, "-1", "ms");
        return;
    }
    if (!strcmp(action, "probe") && store && *store) {
        char eid[MAX_ENTITY_LEN + 4];
        norm_store(store, eid, sizeof(eid));
        entity_push(eid, "-1", "ms");
    }
}

// ══════════════════════════════════════════════════════════════
// Akcje INLINE (natychmiastowe, bez sieci)
// ══════════════════════════════════════════════════════════════

static void run_aggregate(Script& s, ScriptStep& step) {
    // zbieraj próbki przy każdym odpaleniu; po N policz INLINE (czysta matematyka)
    float val = script_resolve_var(step.entity);
    if (!isnan(val) && step.agg_count < 16)
        step.agg_buf[step.agg_count++] = val;

    if (step.samples <= 0 || step.agg_count < step.samples) return;

    int   n = step.agg_count;
    float result = 0.0f;
    if (strcmp(step.func, "avg") == 0) {
        for (int i = 0; i < n; i++) result += step.agg_buf[i];
        result /= n;
    } else if (strcmp(step.func, "min") == 0) {
        result = step.agg_buf[0];
        for (int i = 1; i < n; i++) if (step.agg_buf[i] < result) result = step.agg_buf[i];
    } else if (strcmp(step.func, "max") == 0) {
        result = step.agg_buf[0];
        for (int i = 1; i < n; i++) if (step.agg_buf[i] > result) result = step.agg_buf[i];
    } else if (strcmp(step.func, "sum") == 0) {
        for (int i = 0; i < n; i++) result += step.agg_buf[i];
    }
    step.agg_count = 0;

    if (*step.store) store_float(step.store, result);
    char payload[128];
    snprintf(payload, sizeof(payload),
        "{\"entity\":\"%s\",\"func\":\"%s\",\"samples\":%d,\"result\":%.4f}",
        step.entity, step.func, n, result);
    _send_result_str(s.id, "aggregate", payload);
    LOGD("script", "aggregate %s.%s(%d) = %.2f", step.entity, step.func, n, result);
}

static void run_calc(Script& s, ScriptStep& step) {
    (void)s;
    float result = script_eval_expr(step.expr);
    if (isnan(result)) return;
    char eid[MAX_ENTITY_LEN + 4];
    norm_store(step.store, eid, sizeof(eid));
    store_float(eid, result);
    LOGD("script", "calc %s = %.2f", eid, result);
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
    LOGD("script", "find %s = %.2f", step.store, out);
}

static void run_push(Script& s, ScriptStep& step) {
    (void)s;
    char title[64] = "", body[128] = "";
    fill_template(step.push_title, title, sizeof(title));
    fill_template(step.push_body,  body,  sizeof(body));
    LOGD("script", "push: %s", title);
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
// Dispatch — true = krok sieciowy zakolejkowany (skrypt zawisa)
// ══════════════════════════════════════════════════════════════

bool script_fire_step(Script& s, int step_idx) {
    ScriptStep& step = s.steps[step_idx];
    const char* a = step.action;
    if      (!strcmp(a, "ping"))      return q_ping(s, step_idx, step);
    else if (!strcmp(a, "probe"))     return q_probe(s, step_idx, step);
    else if (!strcmp(a, "fetch"))     return q_fetch(s, step_idx, step);
    else if (!strcmp(a, "webhook"))   return q_webhook(s, step_idx, step);
    else if (!strcmp(a, "aggregate")) run_aggregate(s, step);
    else if (!strcmp(a, "calc"))      run_calc(s, step);
    else if (!strcmp(a, "find"))      run_find(s, step);
    else if (!strcmp(a, "push"))      run_push(s, step);
    else if (!strcmp(a, "report"))    run_report(s, step);
    else if (!strcmp(a, "send"))      run_send(s, step);
    else if (!strcmp(a, "checknet"))  checknet_run();
    else LOGW("script", "unknown action: %s", a);
    return false;
}
