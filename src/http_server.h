#pragma once
#include <Arduino.h>

// Publiczne API serwera HTTP noda.
void http_server_init();
void http_server_handle();

// Inbox — wywoływane przez ws_client przy odbiorze wiadomości.
void http_inbox_push(const char* from, const char* message_id, const char* payload);
