#include "http_client_util.h"
#include "http_internal.h"   // http_begin_url — JEDYNE miejsce z logika scheme/TLS klienta
#include <HTTPClient.h>
#include <WiFiClientSecure.h>
#include <WiFi.h>

int http_post_json(const char* url, const char* body, int timeout_ms) {
    if (WiFi.status() != WL_CONNECTED) return -1;
    HTTPClient http;
    WiFiClientSecure sec;
    if (!http_begin_url(http, sec, String(url))) return -1;
    http.addHeader("Content-Type", "application/json");
    http.setTimeout(timeout_ms);
    int code = http.POST((uint8_t*)body, strlen(body));   // bez kopii do String
    http.end();
    return code;
}
