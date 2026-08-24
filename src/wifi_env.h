#pragma once
#include <Arduino.h>

// SENSMOS — fingerprint otoczenia WiFi (prywatnościowy).
// Co WIFI_ENV_EVERY_MS: skan na worze (kind "wenv" — serializacja z TLS jak "scan"),
// top-8 sieci po RSSI, per sieć SHA256(BSSID)[0..7] + SHA256(trim(SSID))[0..7] + RSSI.
// Surowe MAC-i/nazwy NIGDY nie opuszczają noda — do BE lecą wyłącznie hashe (wifi_env po WS).
// Cel: BE porównuje zbiory w czasie (podobieństwo) = sygnał „node zmienił lokalizację"
// pod re-atestację (decyzja: zmiana WiFi = pełna atestacja GPS).

struct NetResult;   // net_worker.h (fwd)
struct NetJob;

void wifi_env_init();
void wifi_env_tick();                               // w loop(): planuje skan co WIFI_ENV_EVERY_MS
void wifi_env_on_net_result(const NetResult& nr);   // wynik z wora → wysyłka ramki po WS
void wifi_env_run_scan(NetResult& out);             // WYKONANIE na worze (woła net_worker, kind "wenv")
