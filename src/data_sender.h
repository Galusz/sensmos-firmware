#pragma once
#include <Arduino.h>

#define FW_VERSION "0.21"

void data_sender_init();
void data_sender_tick();
void data_sender_trigger();
const char* data_sender_cmd_nonce();   // K3: bieżący nonce (do weryfikacji podpisu komend BE→node)
void data_sender_update_basics();  // stub — zachowane dla kompatybilności
void data_sender_fetch_entities(); // stub — entities przez WS
