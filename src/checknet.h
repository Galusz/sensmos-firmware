#pragma once
#include <ArduinoJson.h>

// checknet: pomiary jakości internetu sterowane przez BE.
// Cykl: checknet_run() -> WS check_assign -> BE odsyła check_jobs -> mierzymy ICMP
// (rtt/jitter/loss, async, nie blokuje pętli) -> WS check_result.
void checknet_init();
void checknet_run();                    // wyzwól cykl (z akcji skryptu "checknet")
void checknet_update();                 // wołaj z loop()
void checknet_on_jobs(JsonArray jobs);  // z ws_client przy check_jobs
