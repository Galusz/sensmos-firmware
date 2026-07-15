#pragma once
#include <Arduino.h>

#define FW_VERSION "0.58"

struct NetResult;   // net_worker.h (fwd)

// Współdzielony bufor TX (RAM-AUDIT 0.49): batch (final payload) i checknet (results JSON)
// budują duże JSON-y NAPRZEMIENNIE w kontekście loop() — nigdy równolegle. Jeden scratch
// zamiast osobnych staticów (2800+3072) oszczędza ~2.8KB .bss. NIE używać z innych tasków.
#define TX_SCRATCH_LEN 3072
extern char g_tx_scratch[TX_SCRATCH_LEN];

void data_sender_init();
void data_sender_tick();
void data_sender_on_net_result(const NetResult& nr);  // wynik skanu WiFi z wora
void data_sender_trigger();
const char* data_sender_new_nonce();                     // K3: nowy nonce (dopisany do historii) → identify/ping
bool        data_sender_nonce_valid(const char* nonce);  // K3: czy nonce w historii ostatnich (okno wyścigu)
void        data_sender_burn_nonce(const char* nonce);   // K3: spal zużyty nonce (single-use)
void        data_sender_send_ping();                     // K3: ping z nowym nonce (periodyczny + wymuszany po użyciu)
void data_sender_update_basics();  // stub — zachowane dla kompatybilności
void data_sender_fetch_entities(); // stub — entities przez WS
