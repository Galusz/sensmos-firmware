#pragma once
/**
 * SENSMOS Firmware — Script Engine
 *
 * Dwa typy skryptów (wspólny format "steps"):
 *   DataScript  — z BE przez WS tasks_update, sloty 0..MAX_DATASCRIPTS-1
 *   UserScript  — z NVS noda (/config/scripts), sloty MAX_DATASCRIPTS..MAX_SCRIPTS-1
 *                 NIE chodzi w ticku — odpalany przez message_router (run_by_id)
 *
 * Format skryptu:
 * {
 *   "id": "nazwa",
 *   "steps": [
 *     { "action": "ping|fetch|aggregate|calc|find|webhook|push|report|send",
 *       "if": "pub.grid_v > 245",        // opcjonalny warunek
 *       "cooldown_s": 60,                // min odstęp między odpaleniami
 *       "duration_s": 0,                 // warunek musi trwać N sekund
 *       "data": { ...parametry akcji... } }
 *   ]
 * }
 *
 * Akcje i parametry (data):
 *   ping      host, timeout_ms, store          → async, wynik do store
 *   fetch     url, path, store                 → async, JSON path do store
 *   aggregate entity, func(avg|min|max|sum), samples, store → async
 *   calc      expr, store                      → wyrażenie arytmetyczne
 *   find      in, key, equals, gt/lt/gte/lte, store → szukaj w buforze
 *   webhook   url, body (template)             → HTTP POST
 *   push      title, body (template)           → FCM przez BE
 *   report    report_id, severity, value, payload{k:entity} → WS do BE (DataScript)
 *   send      to, message_id, payload (template) → wiadomość node↔node (UserScript)
 *
 * Template w body/payload: {pub.x} {own.x} {tmp.x} {sub.x} — wartości z bufora.
 * store: pełna nazwa encji ("tmp.x", "own.x"); "pub.*" zablokowane.
 */
#include <Arduino.h>
#include <ArduinoJson.h>
#include "config.h"

// ── Struktury ─────────────────────────────────────────────────

struct ScriptStep {
    // wspólne
    char  action[12];
    char  condition[MAX_EXPR_LEN];   // "if"
    int   cooldown_s;
    int   duration_s;

    // ping / probe (tcp|dns|http — executory checknet, FW≥0.33)
    char  host[48];
    int   timeout_ms;
    char  probe_kind[6];             // tcp|dns|http (akcja "probe")
    int   port;                      // tcp/http
    char  expected[40];              // dns: oczekiwany IP-prefix (integralność)

    // fetch / webhook
    char  url[MAX_DATA_LEN];
    char  fetch_path[48];            // JSON path np. "data.amount"

    // wynik async/calc/find → encja
    char  store[MAX_ENTITY_LEN];

    // aggregate
    char  entity[MAX_ENTITY_LEN];
    char  func[8];                   // avg|min|max|sum
    int   samples;

    // calc
    char  expr[MAX_EXPR_LEN];

    // webhook
    char  body_tmpl[128];

    // push
    char  push_title[48];
    char  push_body[96];

    // report
    char  report_id[MAX_ID_LEN];
    char  severity[10];              // info|warning|alert
    char  value_key[MAX_ENTITY_LEN]; // pojedyncza wartość
    char  payload_map[96];           // "k1:ent1,k2:ent2,..."

    // find
    char  find_in[12];               // prefix lub "" (wszystkie)
    char  find_key[MAX_ENTITY_LEN];  // fragment nazwy lub ""
    char  find_equals[32];           // string equals/contains
    float find_gt, find_lt, find_gte, find_lte;
    bool  find_has_gt, find_has_lt, find_has_gte, find_has_lte;

    // send
    char  send_to[67];               // device_id odbiorcy
    char  message_id[MAX_ID_LEN];
    char  payload_tmpl[128];

    // runtime
    unsigned long last_fired_ms;
    unsigned long cond_start_ms;     // dla duration_s
    float agg_buf[16];               // próbki aggregate
    int   agg_count;
};

struct Script {
    char       id[MAX_ID_LEN];
    int        version;
    bool       active;
    bool       is_datascript;        // true=BE, false=user
    int        step_count;
    ScriptStep* steps;               // heap, alokowane per REALNA liczbe krokow (<=MAX_STEPS);
                                     // ScriptStep ~1.2KB - sztywne [4] marnowalo ~3.5KB/skrypt
};

// ── API ───────────────────────────────────────────────────────

struct NetResult;   // net_worker.h (fwd — unikamy cyklu include)

void  script_engine_init();
void  script_engine_tick();                          // co TICK_INTERVAL_MS; pomija UserScript
int   script_engine_load(const JsonArray& scripts);  // DataScripts z BE (tasks_update)
int   script_engine_load_user();                     // UserScripts z NVS
void  script_engine_clear();                         // czyści DataScripts (user zostaje)
int   script_engine_count();
bool  script_engine_run_by_id(const char* script_id); // event-driven (message_router)

// Wznawialna maszyna stanów (v0.39, ASYNC-QUEUE §8): krok sieciowy (ping/probe/fetch/
// webhook) idzie na net_worker, skrypt zawisa (max 1 job w locie per skrypt), wynik
// wznawia wykonanie od kroku+1. Timeout/fail też wznawia (skrypt nigdy nie utyka).
void     script_engine_on_net_result(const NetResult& nr);   // dispatch z loop()
uint32_t script_engine_register_await(const char* script_id, int step_idx,
                                      const char* action, const char* store);  // 0 = brak slotu
void     script_engine_cancel_await(uint32_t token);         // enqueue nie wszedł — zwolnij

// ── Współdzielone z script_actions.cpp ────────────────────────

float script_resolve_var(const char* name);          // wartość encji lub NAN
float script_eval_expr(const char* expr);            // wyrażenie arytmetyczne
bool  script_fire_step(Script& s, int step_idx);     // true = krok sieciowy zakolejkowany (suspend)
// Zastosuj wynik/fail kroku sieciowego: zapis do store + raport WS (script_actions.cpp)
void  script_apply_net_result(const char* action, const char* store,
                              const char* script_id, const NetResult& nr);
void  script_apply_net_fail(const char* action, const char* store, const char* script_id);
