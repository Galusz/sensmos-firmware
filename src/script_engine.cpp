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

static Script g_scripts[MAX_SCRIPTS];
static int    g_script_count = 0;
static unsigned long g_last_tick_ms = 0;

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

    for (int i = 0; i < MAX_SCRIPTS; i++) {
        if (!g_scripts[i].active) continue;
        // UserScript NIE chodzi w ticku — tylko run_by_id (message_router)
        if (i >= MAX_DATASCRIPTS) continue;
        tick_script(g_scripts[i]);
    }
}

bool script_engine_run_by_id(const char* script_id) {
    if (!script_id || !*script_id) return false;
    for (int i = 0; i < MAX_SCRIPTS; i++) {
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

int script_engine_load(const JsonArray& scripts_json) {
    // zachowaj cooldowny DataScripts między reloadami
    unsigned long saved[MAX_DATASCRIPTS][MAX_STEPS] = {};
    for (int i = 0; i < MAX_DATASCRIPTS; i++)
        for (int s = 0; s < MAX_STEPS; s++)
            saved[i][s] = g_scripts[i].steps[s].last_fired_ms;

    for (int i = 0; i < MAX_DATASCRIPTS; i++)
        memset(&g_scripts[i], 0, sizeof(Script));

    int count = 0;
    for (JsonObject js : scripts_json) {
        if (count >= MAX_DATASCRIPTS) break;
        parse_script(js, g_scripts[count], true);
        for (int s = 0; s < g_scripts[count].step_count; s++)
            g_scripts[count].steps[s].last_fired_ms = saved[count][s];
        count++;
    }

    int user_count = 0;
    for (int i = MAX_DATASCRIPTS; i < MAX_SCRIPTS; i++)
        if (g_scripts[i].active) user_count++;

    g_script_count = count + user_count;
    Serial.printf("[Script] Data: %d, User: %d\n", count, user_count);
    return count;
}

int script_engine_load_user() {
    for (int i = MAX_DATASCRIPTS; i < MAX_SCRIPTS; i++)
        memset(&g_scripts[i], 0, sizeof(Script));

    Preferences prefs;
    prefs.begin(NVS_NS_USERSCRIPTS, true);
    int stored = prefs.getInt("count", 0);
    int loaded = 0;

    for (int i = 0; i < stored && loaded < MAX_USERSCRIPTS; i++) {
        char key[8];
        snprintf(key, sizeof(key), "us_%d", i);
        if (!prefs.isKey(key)) continue;
        String raw = prefs.getString(key);
        JsonDocument doc;
        if (deserializeJson(doc, raw)) continue;
        parse_script(doc.as<JsonObject>(), g_scripts[MAX_DATASCRIPTS + loaded], false);
        loaded++;
    }
    prefs.end();

    // przelicz licznik
    int total = 0;
    for (int i = 0; i < MAX_SCRIPTS; i++)
        if (g_scripts[i].active) total++;
    g_script_count = total;

    Serial.printf("[Script] UserScripts: %d\n", loaded);
    return loaded;
}

void script_engine_clear() {
    for (int i = 0; i < MAX_DATASCRIPTS; i++)
        memset(&g_scripts[i], 0, sizeof(Script));
    int uc = 0;
    for (int i = MAX_DATASCRIPTS; i < MAX_SCRIPTS; i++)
        if (g_scripts[i].active) uc++;
    g_script_count = uc;
}

void script_engine_init() {
    memset(g_scripts, 0, sizeof(g_scripts));
    g_script_count = 0;
    g_last_tick_ms = 0;
    entity_tmp_clear();
    Serial.println("[Script] Engine OK");
}

int script_engine_count() { return g_script_count; }
