#include "entity_store.h"
#include "script_async.h"
#include "config.h"
#include "ws_client.h"
#include "identity.h"
#include <HTTPClient.h>
#include "http_internal.h"
#include <WiFi.h>
#include <ArduinoJson.h>

#define ASYNC_THROTTLE_MS 600

struct AsyncJob {
    enum Type { NONE, FETCH, PING, AGGREGATE } type = NONE;
    char script_id[24];
    // fetch
    char url[128];
    // ping
    char host[64];
    int  timeout_ms;
    // aggregate
    char  agg_entity[32];
    char  agg_func[8];
    float samples[16];
    int   sample_count;
    // store (tmp.key)
    char  store[32];
    // fetch path (np. "bpi.USD.rate_float")
    char  path[64];
};

static AsyncJob   _queue[SCRIPT_ASYNC_QUEUE_SIZE];
static int        _head  = 0;
static int        _tail  = 0;
static int        _count = 0;
static unsigned long _last_ms = 0;

void script_async_init() {
    memset(_queue, 0, sizeof(_queue));
    _head = _tail = _count = 0;
}

static void _enqueue(AsyncJob& job) {
    if (_count >= SCRIPT_ASYNC_QUEUE_SIZE) {
        Serial.println("[Async] Queue full — drop oldest");
        _tail = (_tail + 1) % SCRIPT_ASYNC_QUEUE_SIZE;
        _count--;
    }
    _queue[_head] = job;
    _head = (_head + 1) % SCRIPT_ASYNC_QUEUE_SIZE;
    _count++;
    Serial.printf("[Async] Queued %d (type=%d)\n", _count, job.type);
}

void script_async_push_fetch(const char* script_id, const char* url, const char* store, const char* path) {
    AsyncJob j; memset(&j, 0, sizeof(j));
    j.type = AsyncJob::FETCH;
    strncpy(j.script_id, script_id, sizeof(j.script_id)-1);
    strncpy(j.url,       url,       sizeof(j.url)-1);
    if (store) strncpy(j.store, store, sizeof(j.store)-1);
    if (path)  strncpy(j.path,  path,  sizeof(j.path)-1);
    _enqueue(j);
}

void script_async_push_ping(const char* script_id, const char* host, int timeout_ms, const char* store) {
    AsyncJob j; memset(&j, 0, sizeof(j));
    j.type       = AsyncJob::PING;
    j.timeout_ms = timeout_ms > 0 ? timeout_ms : 1000;
    strncpy(j.script_id, script_id, sizeof(j.script_id)-1);
    strncpy(j.host,      host,      sizeof(j.host)-1);
    if (store) strncpy(j.store, store, sizeof(j.store)-1);
    _enqueue(j);
}

void script_async_push_aggregate(const char* script_id, const char* entity,
                                  const char* func, float* samples, int count, const char* store) {
    AsyncJob j; memset(&j, 0, sizeof(j));
    j.type         = AsyncJob::AGGREGATE;
    j.sample_count = min(count, 16);
    strncpy(j.script_id,   script_id, sizeof(j.script_id)-1);
    strncpy(j.agg_entity,  entity,    sizeof(j.agg_entity)-1);
    strncpy(j.agg_func,    func,      sizeof(j.agg_func)-1);
    memcpy(j.samples, samples, j.sample_count * sizeof(float));
    if (store) strncpy(j.store, store, sizeof(j.store)-1);
    _enqueue(j);
}

// Wyślij wynik do BE przez WS
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
    Serial.printf("[Async] Result %s.%s = %.2f (status=%d)\n",
        script_id, action, value, status);
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

// Pobierz wartość z JSON po ścieżce "a.b.0.c" (obsługuje array indices)
static float _json_path(JsonDocument& doc, const char* path) {
    if (!path || strlen(path) == 0) {
        // Brak path — pierwsza wartość numeryczna
        if (doc.is<JsonObject>()) {
            for (JsonPair kv : doc.as<JsonObject>()) {
                if (kv.value().is<float>() || kv.value().is<int>())
                    return kv.value().as<float>();
            }
        } else if (doc.is<float>() || doc.is<int>()) {
            return doc.as<float>();
        }
        return NAN;
    }
    // Przejdź po ścieżce "a.b.0.c"
    char buf[64]; strncpy(buf, path, sizeof(buf)-1); buf[sizeof(buf)-1]='\0';
    JsonVariant node = doc.as<JsonVariant>();
    char* tok = strtok(buf, ".");
    while (tok && !node.isNull()) {
        // Sprawdź czy to indeks liczbowy (array)
        bool is_num = true;
        for (int i = 0; tok[i]; i++) if (!isdigit(tok[i])) { is_num = false; break; }
        if (is_num && node.is<JsonArray>())
            node = node.as<JsonArray>()[atoi(tok)];
        else
            node = node[tok];
        tok = strtok(nullptr, ".");
    }
    if (node.is<float>() || node.is<int>()) return node.as<float>();
    if (node.is<const char*>()) {
        float v = atof(node.as<const char*>());
        return (v != 0.0f || strcmp(node.as<const char*>(),"0")==0) ? v : NAN;
    }
    return NAN;
}

static void _run_fetch(AsyncJob& j) {
    if (WiFi.status() != WL_CONNECTED) return;
    HTTPClient http;
    WiFiClientSecure sec;
    http_begin_url(http, sec, String(j.url));
    http.setTimeout(HTTP_TIMEOUT_FETCH);
    int code = http.GET();
    Serial.printf("[Async] Fetch %s HTTP %d\n", j.url, code);

    if (code == 200) {
        // Limit 2KB
        String body = http.getString().substring(0, FETCH_BODY_LIMIT);

        // Strip znaków kontrolnych (newline, tab, CR) które psują JSON
        String clean = "";
        clean.reserve(body.length());
        for (int i = 0; i < (int)body.length(); i++) {
            char ch = body[i];
            if (ch >= 0x20 || ch == '\0') clean += ch;
        }

        JsonDocument doc;
        DeserializationError err = deserializeJson(doc, clean);
        if (!err) {
            // Wyciągnij wartość przez path
            float val = _json_path(doc, strlen(j.path) > 0 ? j.path : nullptr);
            if (!isnan(val)) {
                if (strlen(j.store) > 0) {
                    char _sv[24]; snprintf(_sv, sizeof(_sv), "%.4f", val);
                    entity_push(j.store, _sv, "");
                }
                char payload[64];
                snprintf(payload, sizeof(payload),
                    "{\"value\":%.4f,\"path\":\"%s\"}", val, j.path);
                _send_result_str(j.script_id, "fetch", payload);
            } else {
                // Brak wartości numerycznej
                char raw[128]; serializeJson(doc, raw, sizeof(raw));
                _send_result_str(j.script_id, "fetch", raw);
            }
        } else {
            // Nie JSON — spróbuj jako plain number
            float plain = atof(clean.c_str());
            if (plain != 0.0f) {
                if (strlen(j.store) > 0) {
                    char _sv[24]; snprintf(_sv, sizeof(_sv), "%.4f", plain);
                    entity_push(j.store, _sv, "");
                }
                char payload[48];
                snprintf(payload, sizeof(payload), "{\"value\":%.4f}", plain);
                _send_result_str(j.script_id, "fetch", payload);
            } else {
                Serial.printf("[Async] Fetch parse error: %s\n", err.c_str());
                _send_result(j.script_id, "fetch", "parse_error", 0, 0);
            }
        }
    } else {
        _send_result(j.script_id, "fetch", "http_error", code, code);
    }
    http.end();
}

static void _run_ping(AsyncJob& j) {
    if (WiFi.status() != WL_CONNECTED) return;
    // Ping przez HTTP HEAD jako proxy — ICMP nie jest dostępny bez uprawnień
    // Alternatywnie TCP connect na port 80
    HTTPClient http;
    char url[80];
    snprintf(url, sizeof(url), "http://%s", j.host);
    http.begin(url);
    http.setTimeout(j.timeout_ms);
    unsigned long t0 = millis();
    int code = http.GET();
    unsigned long rtt = millis() - t0;
    http.end();
    int reachable = (code > 0) ? 1 : 0;
    _send_result(j.script_id, "ping", "rtt_ms", reachable ? (float)rtt : -1.0f, reachable);
    if (strlen(j.store) > 0) { char _sv[24]; snprintf(_sv,sizeof(_sv),"%.0f",reachable?(float)rtt:-1.0f); entity_push(j.store[0]?j.store:"tmp.result",_sv,"ms"); }
    Serial.printf("[Async] Ping %s rtt=%lums reachable=%d\n", j.host, rtt, reachable);
}

static void _run_aggregate(AsyncJob& j) {
    if (j.sample_count == 0) return;
    float result = 0.0f;
    if (strcmp(j.agg_func, "avg") == 0) {
        float sum = 0;
        for (int i = 0; i < j.sample_count; i++) sum += j.samples[i];
        result = sum / j.sample_count;
    } else if (strcmp(j.agg_func, "min") == 0) {
        result = j.samples[0];
        for (int i = 1; i < j.sample_count; i++) if (j.samples[i] < result) result = j.samples[i];
    } else if (strcmp(j.agg_func, "max") == 0) {
        result = j.samples[0];
        for (int i = 1; i < j.sample_count; i++) if (j.samples[i] > result) result = j.samples[i];
    } else if (strcmp(j.agg_func, "sum") == 0) {
        for (int i = 0; i < j.sample_count; i++) result += j.samples[i];
    }
    char payload[128];
    snprintf(payload, sizeof(payload),
        "{\"entity\":\"%s\",\"func\":\"%s\",\"samples\":%d,\"result\":%.4f}",
        j.agg_entity, j.agg_func, j.sample_count, result);
    if (strlen(j.store) > 0) { char _sv[24]; snprintf(_sv,sizeof(_sv),"%.4f",result); entity_push(j.store[0]?j.store:"tmp.result",_sv,""); }
    _send_result_str(j.script_id, "aggregate", payload);
    Serial.printf("[Async] Aggregate %s.%s(%d) = %.2f\n",
        j.agg_entity, j.agg_func, j.sample_count, result);
}

void script_async_update() {
    if (_count == 0) return;
    if (WiFi.status() != WL_CONNECTED) return;
    unsigned long now = millis();
    if (now - _last_ms < ASYNC_THROTTLE_MS) return;
    _last_ms = now;

    AsyncJob& j = _queue[_tail];
    switch (j.type) {
        case AsyncJob::FETCH:     _run_fetch(j);     break;
        case AsyncJob::PING:      _run_ping(j);      break;
        case AsyncJob::AGGREGATE: _run_aggregate(j); break;
        default: break;
    }
    j.type = AsyncJob::NONE;
    _tail  = (_tail + 1) % SCRIPT_ASYNC_QUEUE_SIZE;
    _count--;
}
