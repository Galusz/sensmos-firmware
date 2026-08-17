#pragma once
#include "lora_config.h"

#if LORA_ENABLED
#include <Arduino.h>

// Radio chodzi we własnym tasku — wszystkie funkcje poniżej tylko wrzucają zlecenie
// do kolejki i wracają. Skany trwają dziesiątki sekund (łowca sync worda kilka minut),
// więc NIC z tego nie może się wykonywać w loop().
void lora_scan_init();

bool lora_available();    // radio wystartowało (płytka faktycznie ma SX1262)
const char* lora_board_name();   // nazwa wykrytej płytki albo nullptr
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

// ── Tryb LINK (beacon + ciągły nasłuch + uplink po WS) ────────
// Konfiguracja przychodzi z BE ramką lora_cfg; parsuje ją ws_client i woła to.
// mode 0 = LoRa (sf/cr/sync), mode 1 = FSK (br/dev/syncb + flagi).
// Pole bw służy obu: dla LoRa to szerokość pasma, dla FSK szerokość filtru odbiornika.
struct LoraLinkCh {
    float   freq;
    float   bw;
    uint8_t sf;
    uint8_t cr;
    uint8_t sync;
    uint8_t mode;        // 0 LoRa | 1 FSK
    float   br;          // FSK: kbps
    float   dev;         // FSK: dewiacja kHz
    uint8_t syncn;       // FSK: ile bajtów sync (0 = bez sync worda)
    uint8_t syncb[8];    // FSK: bajty sync worda
    uint8_t flags;       // FSK: bit0 = CRC 2B, bit1 = whitening, bit2 = stała długość
    uint8_t len;         // FSK: długość ramki przy stałej długości
};
void lora_link_set(bool on, bool beacon, uint8_t slot, uint16_t beacon_s,
                   uint8_t min_per_ch, const LoraLinkCh* chans, uint8_t n_chans);
bool lora_link_on();
void lora_link_status_json(String& out);
#endif
