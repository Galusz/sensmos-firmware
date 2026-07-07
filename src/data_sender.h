#pragma once
#include <Arduino.h>

#define FW_VERSION "0.38"

void data_sender_init();
void data_sender_tick();
void data_sender_trigger();
const char* data_sender_new_nonce();                     // K3: nowy nonce (dopisany do historii) → identify/ping
bool        data_sender_nonce_valid(const char* nonce);  // K3: czy nonce w historii ostatnich (okno wyścigu)
void        data_sender_burn_nonce(const char* nonce);   // K3: spal zużyty nonce (single-use)
void        data_sender_send_ping();                     // K3: ping z nowym nonce (periodyczny + wymuszany po użyciu)
void data_sender_update_basics();  // stub — zachowane dla kompatybilności
void data_sender_fetch_entities(); // stub — entities przez WS
