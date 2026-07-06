#pragma once
#include <ArduinoJson.h>

// R3 Directed Monitoring (node-heavy): BE przydziela deskryptory monitorów (WS monitor_set),
// node sam planuje pomiary (scheduler + jitter), mierzy executorami checknet (R2),
// trzyma histerezę UP/DOWN i wysyła TYLKO zmiany stanu (monitor_alert) + kompaktowe
// rollupy (monitor_report). Persist NVS — przydziały przeżywają reboot.
void monitors_init();
void monitors_update();                 // wołaj z loop() — max jeden blocking probe/przebieg
void monitors_on_set(JsonObject m);     // z ws_client: monitor_set
void monitors_on_clear(int32_t id);     // z ws_client: monitor_clear
