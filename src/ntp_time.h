#pragma once
#include <Arduino.h>

void     ntp_init();              // wywołaj po połączeniu WiFi
bool     ntp_synced();            // czy czas jest zsynchronizowany
uint32_t ntp_unix_time();         // aktualny Unix timestamp (0 jeśli brak sync)
String   ntp_time_str();          // czytelny czas np. "2026-06-01 14:32:10"
void     ntp_tick();               // wywołuj w loop() — resync co 24h