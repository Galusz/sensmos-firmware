#include "http_internal.h"
#include "entity_store.h"
#include "identity.h"
#include "ble_config.h"
#include "subscription_map.h"
#include "config.h"
#include <ArduinoJson.h>

// GET /remote/data?esp_id=X&prefix=xxx — kup dane z innego noda
// prefix opcjonalny — brak: dane tylko w odpowiedzi, bez zapisu do bufora
static void handle_remote_data() {
    if (!check_pin()) return;
    String esp_id = server.arg("esp_id");
    String prefix = server.arg("prefix");
    if (esp_id.isEmpty()) {
        server.send(400, "application/json", "{\"error\":\"missing esp_id\"}"); return;
    }
    if (prefix == "pub" || prefix == "own" || prefix == "tmp") {
        server.send(400, "application/json", "{\"error\":\"prefix reserved\"}"); return;
    }
    if (strlen(g_backend_url) == 0) {
        server.send(503, "application/json", "{\"error\":\"no backend url\"}"); return;
    }

    JsonDocument req;
    req["from"] = g_device_id;
    req["to"]   = esp_id.c_str();
    String body; serializeJson(req, body);

    String url = String(g_backend_url) + "/data/query";
    HTTPClient http;
    WiFiClientSecure sec;
    http_begin_url(http, sec, url);
    http.addHeader("Content-Type", "application/json");
    http_sign_request(http, "POST", url.c_str());
    http.setTimeout(HTTP_TIMEOUT_QUERY);
    int code = http.POST(body);

    if (code == 200) {
        String resp = http.getString();
        http.end();
        if (prefix.length() > 0) {
            JsonDocument rdoc;
            if (!deserializeJson(rdoc, resp)) {
                int saved = 0;
                JsonArray pub_arr = rdoc["pub"].as<JsonArray>();
                if (!pub_arr.isNull()) {
                    for (JsonObject e : pub_arr) {
                        const char* eid  = e["entity_id"] | "";
                        const char* val  = e["value"]     | "";
                        const char* unit = e["unit"]      | "";
                        if (!strlen(eid)||!strlen(val)) continue;
                        char full[48];
                        snprintf(full, sizeof(full), "%s.%s", prefix.c_str(), eid);
                        entity_push(full, val, unit);
                        saved++;
                    }
                }
                JsonObject own = rdoc["own"].as<JsonObject>();
                if (!own.isNull()) {
                    for (JsonPair kv : own) {
                        char eid[48], val[64];
                        snprintf(eid, sizeof(eid), "%s.%s", prefix.c_str(), kv.key().c_str());
                        if (kv.value().is<const char*>())
                            strncpy(val, kv.value().as<const char*>(), 63);
                        else {
                            float fv = kv.value().as<float>();
                            (fv==(int)fv) ? snprintf(val,sizeof(val),"%d",(int)fv)
                                          : snprintf(val,sizeof(val),"%.2f",fv);
                        }
                        entity_push(eid, val, "");
                        saved++;
                    }
                }
                Serial.printf("[Remote] %d encji z %s → %s.*\n",
                    saved, esp_id.substring(0,8).c_str(), prefix.c_str());
            }
        }
        server.send(200, "application/json", resp);
    } else if (code == 402) {
        http.end();
        server.send(402, "application/json", "{\"error\":\"insufficient_balance\"}");
    } else if (code == 429) {
        String resp = http.getString();
        http.end();
        server.send(429, "application/json", resp);
    } else {
        String err = http.getString();
        http.end();
        server.send(code > 0 ? code : 503, "application/json",
            err.length() > 0 ? err : "{\"error\":\"backend error\"}");
    }
}

// POST /remote/subscribe — subskrybuj dane noda (prefix prywatny, lokalny)
static void handle_remote_subscribe() {
    if (!check_pin()) return;
    if (!server.hasArg("plain")) {
        server.send(400, "application/json", "{\"error\":\"no body\"}"); return;
    }
    JsonDocument doc;
    if (deserializeJson(doc, server.arg("plain"))) {
        server.send(400, "application/json", "{\"error\":\"invalid json\"}"); return;
    }
    const char* esp_id = doc["esp_id"] | "";
    int days = doc["days"] | 7;
    const char* raw_pfx = doc["prefix"] | "sub";
    const char* prefix = (strcmp(raw_pfx,"pub")==0 ||
                          strcmp(raw_pfx,"own")==0 ||
                          strcmp(raw_pfx,"tmp")==0)
                         ? "sub" : raw_pfx;
    if (strlen(esp_id) == 0) {
        server.send(400, "application/json", "{\"error\":\"missing esp_id\"}"); return;
    }
    if (strlen(g_backend_url) == 0) {
        server.send(503, "application/json", "{\"error\":\"no backend url\"}"); return;
    }

    // Prefix prywatny dla subskrybenta — zapis lokalny, NIE do BE
    sub_map_set(esp_id, prefix);

    JsonDocument req;
    req["from"] = g_device_id;
    req["to"]   = esp_id;
    req["days"] = days;
    String body; serializeJson(req, body);

    String url = String(g_backend_url) + "/data/subscribe";
    HTTPClient http;
    WiFiClientSecure sec;
    http_begin_url(http, sec, url);
    http.addHeader("Content-Type", "application/json");
    http_sign_request(http, "POST", url.c_str());
    http.setTimeout(HTTP_TIMEOUT_BACKEND);
    int code = http.POST(body);

    if (code == 200) {
        String resp = http.getString();
        http.end();
        Serial.printf("[Remote] Sub od %s days=%d\n", esp_id, days);
        server.send(200, "application/json", resp);
    } else {
        String err = http.getString();
        http.end();
        server.send(code > 0 ? code : 503, "application/json",
            err.length() > 0 ? err : "{\"error\":\"backend error\"}");
    }
}

// GET /remote/available — co udostępnia inny node
static void handle_remote_available() {
    if (!check_pin()) return;
    String esp_id = server.arg("esp_id");
    if (esp_id.isEmpty()) {
        server.send(400, "application/json", "{\"error\":\"missing esp_id\"}"); return;
    }
    if (strlen(g_backend_url) == 0) {
        server.send(503, "application/json", "{\"error\":\"no backend url\"}"); return;
    }

    String url = String(g_backend_url) + "/data/available/" + esp_id;
    HTTPClient http;
    WiFiClientSecure sec;
    http_begin_url(http, sec, url);
    http_sign_request(http, "GET", url.c_str());
    http.setTimeout(5000);
    int code = http.GET();
    if (code == 200) {
        String resp = http.getString();
        http.end();
        server.send(200, "application/json", resp);
    } else {
        http.end();
        server.send(code > 0 ? code : 503, "application/json", "{\"error\":\"backend error\"}");
    }
}

void register_remote_routes() {
    server.on("/remote/data",      HTTP_GET,  handle_remote_data);
    server.on("/remote/subscribe", HTTP_POST, handle_remote_subscribe);
    server.on("/remote/available", HTTP_GET,  handle_remote_available);
}
