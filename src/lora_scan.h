#pragma once
#include "lora_config.h"

#if LORA_ENABLED
#include <Arduino.h>

// Radio chodzi we własnym tasku — wszystkie funkcje poniżej tylko wrzucają zlecenie
// do kolejki i wracają. Skany trwają dziesiątki sekund (łowca sync worda kilka minut),
// więc NIC z tego nie może się wykonywać w loop().
void lora_scan_init();

bool lora_available();    // radio wystartowało (płytka faktycznie ma SX1262)
bool lora_busy();         // trwa zlecenie

// Zwracają false gdy radia nie ma albo kolejka zajęta.
bool lora_sweep(float from, float to, float step);
bool lora_camp(float freq, uint16_t secs);
bool lora_listen(float freq, float bw, uint8_t sf, uint8_t cr, uint8_t sync, uint16_t secs);
bool lora_cad(float freq, float bw, uint8_t sf, uint16_t secs);   // detekcja preambuły — bez sync worda
bool lora_hunt(float freq, float bw, uint8_t sf, uint8_t cr, uint16_t dwell_ms);

void lora_json(String& out);   // stan pomiarowy dla GET /lora/last
void lora_bg_set(bool on);
bool lora_bg_get();
void lora_status();
#endif
