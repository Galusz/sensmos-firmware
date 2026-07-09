#include "node_integration.h"
#include "identity.h"
#include "log.h"
#include <Preferences.h>
#include <HTTPClient.h>
#include "http_internal.h"
#include <WiFi.h>
#include <ArduinoJson.h>

#define NI_QUEUE_SIZE 6  // max zdarzeń w kolejce

struct NiEvent {
    char action [24];
    char payload[128];
    bool pending;
};

static String    _url = "";
static NiEvent   _queue[NI_QUEUE_SIZE];
static int       _q_head = 0;
static int       _q_tail = 0;
static int       _q_count = 0;
static unsigned long _last_send_ms = 0;
#define NI_MIN_INTERVAL_MS 500  // min 500ms między requestami

void node_integration_init() {
    Preferences p; p.begin("ni", true);
    _url = p.getString("url", "");
    p.end();
    memset(_queue, 0, sizeof(_queue));
    if (_url.length() > 0)
        LOGI("ni", "integration URL: %s", _url.c_str());
}

void node_integration_set_url(const char* url) {
    _url = String(url);
    Preferences p; p.begin("ni", false);
    p.putString("url", _url);
    p.end();
    LOGI("ni", "integration URL set: %s", url);
}

String node_integration_get_url() { return _url; }

void node_integration_push(const char* action, const char* payload_json) {
    if (_url.length() == 0) return;  // nie skonfigurowany — skip
    if (_q_count >= NI_QUEUE_SIZE) {
        // Kolejka pełna — nadpisz najstarszy
        LOGD("ni", "queue full — dropping oldest");
        _q_tail = (_q_tail + 1) % NI_QUEUE_SIZE;
        _q_count--;
    }
    NiEvent& e = _queue[_q_head];
    strncpy(e.action,  action,       sizeof(e.action)  - 1);
    strncpy(e.payload, payload_json, sizeof(e.payload) - 1);
    e.pending = true;
    _q_head = (_q_head + 1) % NI_QUEUE_SIZE;
    _q_count++;
    LOGD("ni", "queued: %s (%d in queue)", action, _q_count);
}

void node_integration_update() {
    if (_q_count == 0) return;
    if (_url.length() == 0) return;
    if (WiFi.status() != WL_CONNECTED) return;

    // Throttle — min 500ms między requestami
    unsigned long now = millis();
    if (now - _last_send_ms < NI_MIN_INTERVAL_MS) return;

    // Pobierz najstarsze zdarzenie z kolejki
    NiEvent& e = _queue[_q_tail];
    if (!e.pending) { _q_tail = (_q_tail+1)%NI_QUEUE_SIZE; _q_count--; return; }

    // Zbuduj payload
    JsonDocument doc;
    doc["device_id"] = g_device_id;
    doc["action"]    = e.action;
    doc["uptime_s"]  = millis() / 1000;

    // Dołącz payload eventu jeśli jest
    if (strlen(e.payload) > 2) {
        JsonDocument pd;
        if (!deserializeJson(pd, e.payload))
            doc["data"] = pd;
        else
            doc["data"] = e.payload;
    }

    String body; serializeJson(doc, body);

    // Wyślij HTTP POST (blokujące ale z krótkim timeout)
    HTTPClient http;
    WiFiClientSecure sec;
    http_begin_url(http, sec, _url);
    http.addHeader("Content-Type", "application/json");
    http.addHeader("X-Sensmos-Device", g_device_id);
    http.setTimeout(2000);  // 2s max
    int code = http.POST(body);
    http.end();

    LOGD("ni", "%s -> HTTP %d", e.action, code);

    // Usuń z kolejki
    e.pending = false;
    _q_tail   = (_q_tail + 1) % NI_QUEUE_SIZE;
    _q_count--;
    _last_send_ms = millis();
}
