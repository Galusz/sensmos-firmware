#pragma once
#include <Arduino.h>
#include <WebServer.h>
#include <HTTPClient.h>
#include <WiFiClientSecure.h>

//Współdzielone między modułami http_*.cpp (nie publiczne API noda).

extern WebServer server;

bool check_pin();
void http_sign_request(HTTPClient& http, const char* method, const char* url);
// Begin HTTPClient: TLS insecure dla https://, plain dla http://. `sec` musi przezyc request.
bool http_begin_url(HTTPClient& http, WiFiClientSecure& sec, const String& url);

// Rejestracja tras — każdy moduł rejestruje własne endpointy na `server`.
void register_data_routes();
void register_messages_routes();
void register_remote_routes();
void register_config_routes();
void register_node_routes();
