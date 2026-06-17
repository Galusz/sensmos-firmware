#include "http_client_util.h"
#include <HTTPClient.h>
#include <WiFiClientSecure.h>
#include <WiFi.h>

int http_post_json(const char* url, const char* body, int timeout_ms) {
    if (WiFi.status() != WL_CONNECTED) return -1;
    HTTPClient http;
    WiFiClientSecure sec;
    String u(url);
    if (u.startsWith("https://")) { sec.setInsecure(); http.begin(sec, u); }
    else http.begin(u);
    http.addHeader("Content-Type", "application/json");
    http.setTimeout(timeout_ms);
    int code = http.POST(String(body));
    http.end();
    return code;
}
