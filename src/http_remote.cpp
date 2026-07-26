#include "http_internal.h"
#include "entity_store.h"
#include "identity.h"
#include "ble_config.h"
#include "subscription_map.h"
#include "ws_client.h"
#include "config.h"
#include "log.h"
#include <ArduinoJson.h>

// GET /remote/data?esp_id=X&prefix=xxx — trigger zakupu danych z innego noda.
// 0.73: fire-and-forget przez WS (koniec lokalnego TLS w kontekście loop). BE nalicza GALU
// i odsyła dane pushem (subscription_push) — node zapisuje je z prefixem z sub_map. Apka nie
// potrzebuje zwrotki (te same dane widać z mapy); brak salda BE zgłosi ewentualnie osobnym pushem.
static void handle_remote_data() {
    if (!check_pin()) return;
    String esp_id = server.arg("esp_id");
    String prefix = server.arg("prefix");
    if (esp_id.isEmpty()) {
        server.send(400, "application/json", "{\"error\":\"missing esp_id\"}"); return;
    }
    if (prefix == "pub" || prefix == "own" || prefix == "tmp" || prefix == "mon") {
        server.send(400, "application/json", "{\"error\":\"prefix reserved\"}"); return;
    }
    if (prefix.length() > 0) sub_map_set(esp_id.c_str(), prefix.c_str());  // push wyniku dostanie prefix
    char msg[160];
    snprintf(msg, sizeof(msg),
        "{\"type\":\"data_query\",\"to\":\"%s\",\"prefix\":\"%s\"}",
        esp_id.c_str(), prefix.c_str());
    bool ok = ws_client_send_raw(msg);
    server.send(ok ? 202 : 503, "application/json",
        ok ? "{\"status\":\"queued\"}" : "{\"error\":\"ws not ready\"}");
}

// POST /remote/subscribe — trigger subskrypcji (prefix prywatny, lokalny).
// 0.73: fire-and-forget przez WS. BE zakłada subskrypcję; dane spływają batch-pushem.
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
                          strcmp(raw_pfx,"tmp")==0 ||
                          strcmp(raw_pfx,"mon")==0)
                         ? "sub" : raw_pfx;
    if (strlen(esp_id) == 0) {
        server.send(400, "application/json", "{\"error\":\"missing esp_id\"}"); return;
    }
    sub_map_set(esp_id, prefix);  // prefix prywatny dla subskrybenta — zapis lokalny
    char msg[160];
    snprintf(msg, sizeof(msg),
        "{\"type\":\"data_subscribe\",\"to\":\"%s\",\"days\":%d,\"prefix\":\"%s\"}",
        esp_id, days, prefix);
    bool ok = ws_client_send_raw(msg);
    server.send(ok ? 202 : 503, "application/json",
        ok ? "{\"status\":\"queued\"}" : "{\"error\":\"ws not ready\"}");
}

void register_remote_routes() {
    server.on("/remote/data",      HTTP_GET,  handle_remote_data);
    server.on("/remote/subscribe", HTTP_POST, handle_remote_subscribe);
    // /remote/available skasowane (0.73) — apka czyta BE /v1/data/available/<id> wprost (publiczne)
}
