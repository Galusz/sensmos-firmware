#pragma once
#include <Arduino.h>

#define FW_VERSION "0.22"

void data_sender_init();
void data_sender_tick();
void data_sender_trigger();
const char* data_sender_cmd_nonce();          // K3: bieżący nonce
bool        data_sender_nonce_valid(const char* nonce);  // K3: czy nonce w historii ostatnich (okno wyścigu)
void data_sender_update_basics();  // stub — zachowane dla kompatybilności
void data_sender_fetch_entities(); // stub — entities przez WS
