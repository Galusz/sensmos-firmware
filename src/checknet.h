#pragma once
#include <ArduinoJson.h>

// checknet: pomiary jakości internetu sterowane przez BE.
// Cykl: checknet_run() -> WS check_assign -> BE odsyła check_jobs -> mierzymy ICMP
// (rtt/jitter/loss, async, nie blokuje pętli) -> WS check_result.
void checknet_init();
void checknet_run();                    // wyzwól cykl (rdzeń samonapędza; akcja skryptu deprecated)
void checknet_update();                 // wołaj z loop() — samonapęd + maszyna stanów
void checknet_on_jobs(JsonArray jobs);  // z ws_client przy check_jobs
// Config z BE (WS cn_config): enabled + interwał (adaptacyjny wg floty) + limity. Persist w NVS.
void checknet_set_config(bool enabled, uint32_t interval_ms, int max_jobs, int ping_count);
