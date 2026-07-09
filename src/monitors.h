#pragma once
#include <ArduinoJson.h>

// R3 Directed Monitoring (node-heavy): BE przydziela deskryptory monitorów (WS monitor_set),
// node sam planuje pomiary (scheduler + jitter), mierzy executorami checknet (R2),
// trzyma histerezę UP/DOWN i wysyła TYLKO zmiany stanu (monitor_alert) + kompaktowe
// rollupy (monitor_report). Persist NVS — przydziały przeżywają reboot.
struct NetResult;   // net_worker.h (fwd — unikamy cyklu include)

void monitors_init();
void monitors_update();                 // wołaj z loop() — kolejkuje należne pomiary na worker
void monitors_on_set(JsonObject m);     // z ws_client: monitor_set
void monitors_on_clear(int32_t id);     // z ws_client: monitor_clear
void monitors_on_net_result(const NetResult& nr);  // wynik sondy z net_worker (dispatch w loop)
// EMA opóźnienia harmonogramu (actual/target interval; 1.0 = na czas, 0 = brak danych).
// Sygnał admission dla BE (ASYNC-QUEUE §10) — raportowany w pingu jako q_lag.
float monitors_qlag();
int   monitors_count();   // aktywne sloty monitorów (do [health])
