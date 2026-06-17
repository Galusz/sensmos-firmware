#pragma once
#include <Arduino.h>

// ── Node Integration Webhook ──────────────────────────────────
// Jeden dedykowany webhook który wysyła przy każdym zdarzeniu.
// Asynchroniczna kolejka — nie blokuje pętli głównej.
// Konfiguracja: POST /config {"integration_url": "http://..."}

void node_integration_init();
void node_integration_update();  // wywołaj z loop()

// Wypchnij zdarzenie do kolejki
void node_integration_push(const char* action, const char* payload_json);

// Konfiguracja
void   node_integration_set_url(const char* url);
String node_integration_get_url();
