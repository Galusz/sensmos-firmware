#pragma once
#include <Arduino.h>

void        ws_client_init();
void        ws_client_tick();
bool        ws_client_connected();
bool        ws_client_send_raw(const char* json_msg);
void        ws_client_send_push(const char* title, const char* body);

// Czas UTC z BE (server_time z identified) + millis() od tamtej chwili. 0 = jeszcze nie znamy.
// Dokładność ±0.5 s — wystarcza do slotów LoRa (ramka SF9 leci ~200 ms, odbiorca słucha ciągle).
uint32_t    ws_epoch_now();

