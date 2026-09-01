#pragma once
#include <Arduino.h>
#include "lora_config.h"   // LORA_ENABLED — dokleja sufiks do wersji (niżej)

// Jeden numer bazowy dla obu wariantow — podbijasz go w JEDNYM miejscu przy wydaniu.
// Sufiks "-lora" dokleja sie sam z flagi kompilacji, zeby build radiowy dalo sie odroznic
// w panelu i zeby rollout floty nigdy nie zlapal plytek z radiem (rozne stringi wersji).
#define FW_BASE "0.95"
#if LORA_ENABLED
  #define FW_VERSION FW_BASE "-lora5"
#else
  #define FW_VERSION FW_BASE
#endif

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
void        data_sender_send_ping();                     // heartbeat: heap + metryki wora (q_lag/q_busy/...)
void data_sender_update_basics();  // stub — zachowane dla kompatybilności
void data_sender_fetch_entities(); // stub — entities przez WS
