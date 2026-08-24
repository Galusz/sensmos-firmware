#pragma once
#include <Arduino.h>

// SENSMOS — minimalny publisher MQTT (TYLKO wychodzący: CONNECT + PUBLISH + PING).
// Świadomie NIE PubSubClient: subskrypcji/karmienia nie robimy (decyzja 2026-08-22), więc
// callbacki i bufory RX byłyby martwym balastem. Klient publikuje diagnostykę noda na broker
// w LAN usera (obok Home Assistant) — działa też (zwłaszcza) gdy WAN leży, bo to kanał lokalny.
// Model jak reszta FW: statyczny bufor, nieblokujący tick w loop, preflight sondą TCP na worze.

struct NetResult;   // net_worker.h (fwd — bez cyklu include)

void mqtt_pub_init();                              // wczytaj config z NVS (po WiFi)
void mqtt_pub_tick();                              // w loop() za ws_client_tick
void mqtt_pub_on_net_result(const NetResult& nr);  // wynik preflight-sondy (NW_MQTT)

// Config z HTTP /node/mqtt (za PIN) → NVS. on=false wyłącza i rozłącza.
bool mqtt_pub_set_config(bool on, const char* host, int port, const char* user, const char* pass);
// Stan do GET /node/mqtt i /info: {"on":..,"connected":..,"err":"..","host":"..","tx":N}
void mqtt_pub_status_json(char* out, size_t cap);

// Most wiadomości Sensmos→HA: wołane z ws_client przy odebranej 'message'.
// No-op gdy MQTT wyłączone/rozłączone — nie buforujemy (wiadomość i tak jest w inbox HTTP).
void mqtt_pub_message(const char* from, const char* eid, const char* payload);
