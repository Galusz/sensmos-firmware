#pragma once
#include <Arduino.h>

// Mapa lokalna {target_device_id → prefix} dla subskrypcji.
// Ring buffer (max 8) — przy przepełnieniu wypada najstarszy wpis.
// Prefix jest prywatny dla subskrybenta; BE go nie zna.

#define SUB_MAP_MAX 8

void sub_map_init();
void sub_map_set(const char* target_id, const char* prefix);
// Zwraca prefix dla targeta do out (true), lub false jeśli brak wpisu.
bool sub_map_get(const char* target_id, char* out, size_t out_len);
