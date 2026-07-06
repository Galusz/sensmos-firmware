/**
 * SENSMOS Firmware — Script Engine (rdzeń)
 * Parser wyrażeń, tick, ładowanie skryptów.
 * Wykonanie akcji: script_actions.cpp
 */
#include "script_engine.h"
#include "entity_store.h"
#include <Preferences.h>
#include <math.h>
#include <string.h>

// ELASTYCZNA alokacja (heap): dokładnie tyle slotów ile realnie skryptów —
// DataScripts (BE) w [0..g_ds_count-1], UserScripts (NVS) za nimi. Zero skryptów =
// zero heapu. Script ~4.8KB, więc typowy node (2-3 DS) zużywa ~10-15KB zamiast
// stałych ~34KB — reszta heapu zostaje CIĄGŁA dla TLS/monitorów/checknet.
static Script* g_scripts  = nullptr;
static int     g_ds_count = 0;   // DataScripts (BE)
static int     g_us_count = 0;   // UserScripts (NVS), sloty [g_ds_count..]
static int     g_script_count = 0;
static unsigned long g_last_tick_ms = 0;

static int  total_slots() { return g_ds_count + g_us_count; }
static void recount_active() {
    int t = 0;
    for (int i = 0; i < total_slots(); i++) if (g_scripts[i].active) t++;
    g_script_count = t;
}

#define NVS_NS_USERSCRIPTS "uscripts"

// ══════════════════════════════════════════════════════════════
// Resolve — wartość encji po nazwie
// ══════════════════════════════════════════════════════════════

float script_resolve_var(const char* name) {
    if (!name || !*name) return NAN;
    float v = entity_get_float(name);
    if (!isnan(v)) return v;
    // bez prefixu → spróbuj tmp.
    if (strchr(name, '.') == nullptr) {
        char tmp_name[MAX_ENTITY_LEN + 4];
        snprintf(tmp_name, sizeof(tmp_name), "tmp.%s", name);
        return entity_get_float(tmp_name);
    }
    return NAN;
}

// ══════════════════════════════════════════════════════════════
// Parser wyrażeń arytmetycznych i warunków
//   expr   := term (('+'|'-') term)*
//   term   := factor (('*'|'/') factor)*
//   factor := liczba | nazwa_encji | '(' expr ')'
//   cond   := cmp (('&&'|'||') cmp)*
//   cmp    := expr [op expr]   op: > < >= <= == !=
// ══════════════════════════════════════════════════════════════

static float parse_expr(const char*& p);

static void skip_ws(const char*& p) { while (*p == ' ') p++; }

static float parse_factor(const char*& p) {
    skip_ws(p);
    if (*p == '(') {
        p++;
        float v = parse_expr(p);
        skip_ws(p);
        if (*p == ')') p++;
        return v;
    }
    if (isdigit(*p) || (*p == '-' && isdigit(p[1]))) {
        char* end;
        float v = strtof(p, &end);
        p = end;
        return v;
    }
    // nazwa encji: [a-zA-Z_][a-zA-Z0-9_.]*
    if (isalpha(*p) || *p == '_') {
        char name[MAX_ENTITY_LEN + 8] = {0};
        int n = 0;
        while ((isalnum(*p) || *p == '_' || *p == '.') && n < (int)sizeof(name) - 1)
            name[n++] = *p++;
        return script_resolve_var(name);
    }
    return NAN;
}

static float parse_term(const char*& p) {
    float v = parse_factor(p);
    for (;;) {
        skip_ws(p);
        if (*p == '*') { p++; v *= parse_factor(p); }
        else if (*p == '/') {
            p++;
            float d = parse_factor(p);
            v = (d != 0.0f) ? v / d : NAN;
        }
        else return v;
    }
}

static float parse_expr(const char*& p) {
    float v = parse_term(p);
    for (;;) {
        skip_ws(p);
        if (*p == '+') { p++; v += parse_term(p); }
        else if (*p == '-' && p[1] != '=') { p++; v -= parse_term(p); }
        else return v;
    }
}

float script_eval_expr(const char* expr) {
    if (!expr || !*expr) return NAN;
    const char* p = expr;
    return parse_expr(p);
}

// Pojedyncze porównanie
static bool parse_comparison(const char*& p) {
    float left = parse_expr(p);
    skip_ws(p);

    char op[3] = {0};
    if ((*p == '>' || *p == '<' || *p == '=' || *p == '!')) {
        op[0] = *p++;
        if (*p == '=') op[1] = *p++;
    } else {
        // brak operatora → prawda jeśli wartość niezerowa i nie NAN
        return !isnan(left) && left != 0.0f;
    }

    float right = parse_expr(p);
    if (isnan(left) || isnan(right)) return false;

    if (!strcmp(op, ">"))  return left >  right;
    if (!strcmp(op, "<"))  return left <  right;
    if (!strcmp(op, ">=")) return left >= right;
    if (!strcmp(op, "<=")) return left <= right;
    if (!strcmp(op, "==")) return fabsf(left - right) < 0.0001f;
    if (!strcmp(op, "!=")) return fabsf(left - right) >= 0.0001f;
    return false;
}

// Warunek z && / ||  (lewostronnie, && nie ma priorytetu nad ||)
static bool eval_condition(const char* cond) {
    if (!cond || !*cond) return true;   // pusty warunek = zawsze
    const char* p = cond;
    bool result = parse_comparison(p);
    for (;;) {
        skip_ws(p);
        if (p[0] == '&' && p[1] == '&') { p += 2; result = parse_comparison(p) && result; }
        else if (p[0] == '|' && p[1] == '|') { p += 2; result = parse_comparison(p) || result; }
        else break;
    }
    return result;
}

// ══════════════════════════════════════════════════════════════
// Tick
// ══════════════════════════════════════════════════════════════

static void tick_script(Script& s) {
    if (!s.active) return;
    unsigned long now_ms = millis();

    for (int si = 0; si < s.step_count; si++) {
        ScriptStep& step = s.steps[si];

        // cooldown
        if (step.last_fired_ms > 0 &&
            (now_ms - step.last_fired_ms) < (unsigned long)step.cooldown_s * 1000UL)
            continue;

        // warunek
        if (!eval_condition(step.condition)) {
            step.cond_start_ms = 0;
            continue;
        }

        // duration_s — warunek musi trwać
        if (step.duration_s > 0) {
            if (step.cond_start_ms == 0) { step.cond_start_ms = now_ms; continue; }
            if ((now_ms - step.cond_start_ms) < (unsigned long)step.duration_s * 1000UL)
                continue;
        }

        Serial.printf("[Script] %s → %s\n", s.id, step.action);
        script_fire_step(s, step);
        step.last_fired_ms = now_ms;
        step.cond_start_ms = 0;
    }
}

void script_engine_tick() {
    unsigned long now = millis();
    if (now - g_last_tick_ms < TICK_INTERVAL_MS) return;
    g_last_tick_ms = now;

    for (int i = 0; i < total_slots(); i++) {
        if (!g_scripts[i].active) continue;
        // UserScript NIE chodzi w ticku — tylko run_by_id (message_router)
        if (!g_scripts[i].is_datascript) continue;
        tick_script(g_scripts[i]);
    }
}

bool script_engine_run_by_id(const char* script_id) {
    if (!script_id || !*script_id) return false;
    for (int i = 0; i < total_slots(); i++) {
        if (g_scripts[i].active && strcmp(g_scripts[i].id, script_id) == 0) {
            tick_script(g_scripts[i]);
            return true;
        }
    }
    Serial.printf("[Script] run_by_id: brak '%s'\n", script_id);
    return false;
}

// ══════════════════════════════════════════════════════════════
// Parse
// ══════════════════════════════════════════════════════════════

static void parse_step(JsonObject js, ScriptStep& step) {
    memset(&step, 0, sizeof(step));

    strncpy(step.action,    js["action"] | "",        sizeof(step.action) - 1);
    strncpy(step.condition, js["if"]     | "",        sizeof(step.condition) - 1);
    step.cooldown_s = js["cooldown_s"] | 60;
    step.duration_s = js["duration_s"] | 0;

    JsonObject data = js["data"];
    if (data.isNull()) return;

    // ping
    strncpy(step.host, data["host"] | "", sizeof(step.host) - 1);
    step.timeout_ms = data["timeout_ms"] | 1000;

    // fetch / webhook
    strncpy(step.url,        data["url"]  | "", sizeof(step.url) - 1);
    strncpy(step.fetch_path, data["path"] | "", sizeof(step.fetch_path) - 1);

    // store
    strncpy(step.store, data["store"] | "", sizeof(step.store) - 1);

    // aggregate
    strncpy(step.entity, data["entity"] | "",    sizeof(step.entity) - 1);
    strncpy(step.func,   data["func"]   | "avg", sizeof(step.func) - 1);
    step.samples = data["samples"] | 10;
    if (step.samples > 16) step.samples = 16;

    // calc
    strncpy(step.expr, data["expr"] | "", sizeof(step.expr) - 1);

    // webhook body
    strncpy(step.body_tmpl, data["body"] | "{}", sizeof(step.body_tmpl) - 1);

    // push
    strncpy(step.push_title, data["title"] | "", sizeof(step.push_title) - 1);
    strncpy(step.push_body,  data["body"]  | "", sizeof(step.push_body) - 1);

    // report
    strncpy(step.report_id, data["report_id"] | "",     sizeof(step.report_id) - 1);
    strncpy(step.severity,  data["severity"]  | "info", sizeof(step.severity) - 1);
    strncpy(step.value_key, data["value"]     | "",     sizeof(step.value_key) - 1);

    // report payload map: {"k":"encja",...} → "k:encja,..."
    if (data["payload"].is<JsonObject>()) {
        char pmap[sizeof(step.payload_map)] = "";
        for (JsonPair kv : data["payload"].as<JsonObject>()) {
            char entry[40];
            snprintf(entry, sizeof(entry), "%s:%s,",
                     kv.key().c_str(), kv.value().as<const char*>());
            strncat(pmap, entry, sizeof(pmap) - strlen(pmap) - 1);
        }
        strncpy(step.payload_map, pmap, sizeof(step.payload_map) - 1);
    }

    // find
    strncpy(step.find_in,     data["in"]     | "", sizeof(step.find_in) - 1);
    strncpy(step.find_key,    data["key"]    | "", sizeof(step.find_key) - 1);
    strncpy(step.find_equals, data["equals"] | "", sizeof(step.find_equals) - 1);
    step.find_has_gt  = !data["gt"].isNull();
    step.find_has_lt  = !data["lt"].isNull();
    step.find_has_gte = !data["gte"].isNull();
    step.find_has_lte = !data["lte"].isNull();
    step.find_gt  = data["gt"]  | 0.0f;
    step.find_lt  = data["lt"]  | 0.0f;
    step.find_gte = data["gte"] | 0.0f;
    step.find_lte = data["lte"] | 0.0f;

    // send
    strncpy(step.send_to,      data["to"]         | "",   sizeof(step.send_to) - 1);
    strncpy(step.message_id,   data["message_id"] | "",   sizeof(step.message_id) - 1);
    strncpy(step.payload_tmpl, data["payload"]    | "{}", sizeof(step.payload_tmpl) - 1);
}

static void parse_script(JsonObject js, Script& s, bool is_datascript) {
    memset(&s, 0, sizeof(Script));
    strncpy(s.id, js["id"] | "unknown", sizeof(s.id) - 1);
    s.version       = js["version"] | 1;
    s.active        = true;
    s.is_datascript = is_datascript;

    JsonArray steps = js["steps"];
    for (JsonObject step_js : steps) {
        if (s.step_count >= MAX_STEPS) break;
        parse_step(step_js, s.steps[s.step_count]);
        s.step_count++;
    }
    Serial.printf("[Script] +%s (%s v%d, %d kroków)\n",
        s.id, is_datascript ? "Data" : "User", s.version, s.step_count);
}

// ══════════════════════════════════════════════════════════════
// Load
// ══════════════════════════════════════════════════════════════

// Przebuduj tablicę na (ds_n + us_n) slotów. Zwraca nową (wyzerowaną) lub nullptr
// przy 0 slotów / OOM. Stara tablica NIE jest ruszana (caller kopiuje i zwalnia).
static Script* alloc_slots(int total) {
    if (total <= 0) return nullptr;
    Script* nw = (Script*)calloc(total, sizeof(Script));
    if (!nw) Serial.printf("[Script] OOM przy %d slotach (%uB) — zostawiam stare\n",
                           total, (unsigned)(total * sizeof(Script)));
    return nw;
}

int script_engine_load(const JsonArray& scripts_json) {
    // ile DataScripts przychodzi (≤ MAX_DATASCRIPTS)
    int incoming = 0;
    for (JsonObject js : scripts_json) { (void)js; if (++incoming >= MAX_DATASCRIPTS) break; }

    // zachowaj cooldowny DataScripts między reloadami (po indeksie — BE śle stałą kolejność)
    unsigned long saved[MAX_DATASCRIPTS][MAX_STEPS] = {};
    for (int i = 0; i < g_ds_count && i < MAX_DATASCRIPTS; i++)
        for (int s = 0; s < MAX_STEPS; s++)
            saved[i][s] = g_scripts[i].steps[s].last_fired_ms;

    int total = incoming + g_us_count;
    Script* nw = alloc_slots(total);
    if (total > 0 && !nw) return 0;              // OOM → stare skrypty zostają nietknięte

    // UserScripts przenieś z ogona starej tablicy
    for (int u = 0; u < g_us_count; u++) nw[incoming + u] = g_scripts[g_ds_count + u];

    int count = 0;
    for (JsonObject js : scripts_json) {
        if (count >= incoming) break;
        parse_script(js, nw[count], true);
        for (int s = 0; s < nw[count].step_count; s++)
            nw[count].steps[s].last_fired_ms = saved[count][s];
        count++;
    }

    free(g_scripts);
    g_scripts = nw; g_ds_count = count;
    recount_active();
    Serial.printf("[Script] Data: %d, User: %d (heap: %uB na %d slotów, free=%u)\n",
                  count, g_us_count, (unsigned)(total * sizeof(Script)), total, ESP.getFreeHeap());
    return count;
}

int script_engine_load_user() {
    Preferences prefs;
    prefs.begin(NVS_NS_USERSCRIPTS, true);
    int stored = prefs.getInt("count", 0);

    // zbierz surowe JSON-y (żeby znać liczbę PRZED alokacją)
    String raw[MAX_USERSCRIPTS];
    int found = 0;
    for (int i = 0; i < stored && found < MAX_USERSCRIPTS; i++) {
        char key[8];
        snprintf(key, sizeof(key), "us_%d", i);
        if (!prefs.isKey(key)) continue;
        raw[found] = prefs.getString(key);
        if (raw[found].length() > 0) found++;
    }
    prefs.end();

    int total = g_ds_count + found;
    Script* nw = alloc_slots(total);
    if (total > 0 && !nw) return 0;              // OOM → stare zostają

    for (int i = 0; i < g_ds_count; i++) nw[i] = g_scripts[i];   // DataScripts bez zmian

    int loaded = 0;
    for (int i = 0; i < found; i++) {
        JsonDocument doc;
        if (deserializeJson(doc, raw[i])) continue;
        parse_script(doc.as<JsonObject>(), nw[g_ds_count + loaded], false);
        loaded++;
    }

    free(g_scripts);
    g_scripts = nw; g_us_count = loaded;
    recount_active();
    Serial.printf("[Script] UserScripts: %d (sloty=%d, free=%u)\n",
                  loaded, total_slots(), ESP.getFreeHeap());
    return loaded;
}

void script_engine_clear() {
    // czyści DataScripts; UserScripts zostają (przepakowane na początek)
    if (g_us_count == 0) {
        free(g_scripts); g_scripts = nullptr;
        g_ds_count = 0; g_script_count = 0;
        return;
    }
    Script* nw = alloc_slots(g_us_count);
    if (!nw) return;                             // OOM → zostaw jak jest
    for (int u = 0; u < g_us_count; u++) nw[u] = g_scripts[g_ds_count + u];
    free(g_scripts);
    g_scripts = nw; g_ds_count = 0;
    recount_active();
}

void script_engine_init() {
    free(g_scripts);
    g_scripts = nullptr;
    g_ds_count = 0; g_us_count = 0; g_script_count = 0;
    g_last_tick_ms = 0;
    entity_tmp_clear();
    Serial.println("[Script] Engine OK (sloty alokowane per-load)");
}

int script_engine_count() { return g_script_count; }
