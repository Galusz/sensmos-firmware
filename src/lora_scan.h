#pragma once
#include "lora_config.h"

#if LORA_ENABLED
#include <Arduino.h>

// Radio chodzi we własnym tasku — wszystkie funkcje poniżej tylko wrzucają zlecenie
// do kolejki i wracają. Skany trwają dziesiątki sekund (łowca sync worda kilka minut),
// więc NIC z tego nie może się wykonywać w loop().
void lora_scan_init();

// Z loop(): opróżnia skrzynkę nadawczą taska radiowego. MUSI być wołane z pętli — task
// nie może sam pisać po WS, bo ws_client trzyma jeden bufor enc i licznik sekwencji
// bezpieczne wyłącznie w kontekście loop.
void lora_pump();

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
// Seed kodu beaconu NIE jest parametrem (0.92): node liczy go sam z ECDH przy starcie
// (ws_enc_beacon_seed) — deterministyczny, przeżywa restart, nic nie jest przesyłane.
// role (model v2): 0 = skaner (rotacja planu, sloty), 1 = PUNKT (camp scan[0], ALOHA/CAD).
void lora_link_set(bool on, bool beacon, uint8_t slot, uint16_t beacon_s,
                   uint8_t min_per_ch, const LoraLinkCh* chans, uint8_t n_chans,
                   uint8_t role = 0);
bool lora_link_on();
void lora_link_status_json(String& out);

// ── LoRa awaryjne (0.91): ≤4 encje doklejane do beaconu przy padzie uplinku ──
// Zestaw wybiera właściciel (POST /node/lora_emerg), trzymany w NVS, zgłaszany do BE
// po każdym connect (BE mapuje pozycyjne wartości z ramki E1 na eidy).
void lora_emerg_set(const char (*eids)[36], uint8_t n);
void lora_emerg_json(String& out);      // {"eids":[...],"active":bool,"webhook":"..."}
bool lora_emerg_active();

// Inbox LoRa (OSOBNY od inboxu wiadomości WS, ROZDZIELONE kubełki komendy/ramki):
// {"cmds":{"count":n,"items":[{"ts":epoch,"payload":"..."}]},"frames":{...}}
// `frames` = ramki publiczne DATA (Faza 2 — struktura już jest, ring dojdzie).
void lora_inbox_json(String& out);

// Webhook dla komend emergency (CMD 0x03, model v2): node po odebraniu komendy strzela
// na URL w LAN (np. UniFi Protect). use_get=false → POST {"source":"lora_cmd","cmd":...};
// use_get=true → GET <url>?cmd=<enc> (proste systemy bez POST). Puste = off. NVS.
void lora_cmd_hook_set(const char* url, bool use_get);

// ── Radio na zlecenie BE (baza pod ramkę CMD 0x03 — model v2, Krok 3) ──
// Downlink z BE (komenda WS lora_tx): nadaj gotową surową ramkę binarną (hex). BE zbudował
// i uwierzytelnił ją seedem ODBIORCY. false = zły hex / nie nasza ramka / kolejka / brak radia.
bool lora_tx_raw_hex(const char* frame_hex);

// Owner-seed per-owner z BE (po szyfrowanym WS) — 32-B klucz kodeka SMOM (CMD). Cache NVS.
void lora_owner_seed_set(const uint8_t seed[32]);

// ── DATA 0x02 — ramki publiczne (Faza 2, zero-knowledge; decyzje 2026-09-01) ──
// [0xE0][0x02][flags][dst 4B][sub 1B][payload][CRC32 LE] / z flags bit0: [nonce 4B][AES(...)].
// Klucz = SHA256(frazy) TYLKO w NVS nodów/czujników; BE routuje po dst na ślepo.
int  lora_data_send(const char* dst8, uint8_t sub, const uint8_t* payload, size_t plen, bool aes);
void lora_data_rx_ws(const char* hex);   // zwrotka z BE (WS lora_frame) — dekod jak z radia
void lora_rx_key_set(const char* phrase);   // "" kasuje; NVS
bool lora_rx_key_present();
#endif
