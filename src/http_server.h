#pragma once
#include <Arduino.h>

// Publiczne API serwera HTTP noda.
void http_server_init();
void http_server_handle();

// Inbox — wywoływane przez ws_client przy odbiorze wiadomości.
void http_inbox_push(const char* from, const char* message_id, const char* payload);

// Alias noda (etykieta usera, np. "Garaż") — NVS, widoczny w GET /info; ustawiany
// POST /node/alias (za PIN). Puste = brak aliasu.
void node_alias_set(const char* alias);
const char* node_alias();
