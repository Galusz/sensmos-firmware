#pragma once

// ══════════════════════════════════════════════════════════════
// LoRa (SX1262) — build LOKALNY/EKSPERYMENTALNY.
//
// LORA_ENABLED 0 = ani jednej instrukcji w binie → biny floty bez zmian.
// Włączane TYLKO na potrzeby testów na płytce z radiem.
//
// Radio pracuje WYŁĄCZNIE w odbiorze. Nigdzie w tym module nie ma transmit() —
// odbiór nie podlega duty cycle i nie wymaga zgodności z pasmem, więc nie da się
// tym naruszyć przepisów radiowych nawet przy złej konfiguracji.
// ══════════════════════════════════════════════════════════════

#ifndef LORA_ENABLED
#define LORA_ENABLED 0
#endif

// ── Płytka (pinout SX1262) ────────────────────────────────────
// Piny NIE są wybierane w kompilacji. Przy starcie próbujemy kolejnych pinoutów z tablicy,
// aż SX1262 odpowie — dzięki temu JEDEN bin radiowy obsługuje wszystkie płytki, a dołożenie
// nowej to jeden wiersz zamiast: bloku #if, nazwy targetu OTA, wpisu w build-all.ps1, wpisu
// w CHIPS po stronie BE i kolejnego pliku do wydawania na zawsze.
//
// Znika też cała klasa cichych awarii: bin zbudowany pod XIAO, wgrany na Helteca, pukał
// w piny 41/39/42/40 zamiast 8/14/12/13 — node wstawał, WiFi działało, tylko radio było
// głuche i wyglądało to na usterkę anteny.
//
// Sonda jest bezpieczna: nic nie nadajemy, RadioLib zwraca RADIOLIB_ERR_CHIP_NOT_FOUND, gdy
// układ nie odpowiada na odczyt rejestru — to realne pytanie do krzemu, nie zgadywanka po
// czasie. Nieudana próba dotyka jednak 7 GPIO, które na innej płytce mogą należeć do
// wyświetlacza albo Vext, dlatego lista jest KRÓTKA i celowo nie zawiera wszystkich 27
// pinoutów znanych z Meshtastica (pełna tabela: DOCS/dev/LORA-PINOUTS.md).

#include <stdint.h>

struct LoraPinout {
    const char* name;
    int8_t nss, dio1, rst, busy, sck, miso, mosi, rxen;   // rxen < 0 = brak przełącznika
    float  tcxo;                                          // napięcie TCXO z DIO3
};

// Kolejność: najpierw to, co mamy we własnej flocie, potem popularne. Wpisy zweryfikowane
// z variants/*/variant.h Meshtastica; XIAO i Heltec dodatkowo potwierdzone na naszym sprzęcie.
//                      nazwa           nss dio1 rst busy  sck miso mosi rxen  tcxo
#define LORA_PINOUTS { \
    { "xiao-s3",       41, 39, 42, 40,   7,   8,   9,  38, 1.8f },  /* Seeed XIAO S3 + Wio-SX1262 (B2B)                    */ \
    { "heltec-s3",      8, 14, 12, 13,   9,  11,  10,  -1, 1.6f },  /* Heltec V3/V4/Wireless Paper/WSL/Vision/Tracker       */ \
    { "heltec-s3@1v8",  8, 14, 12, 13,   9,  11,  10,  -1, 1.8f },  /* te same piny — Meshtastic podaje 1.8 zamiast 1.6     */ \
    { "lilygo-t3s3",    7, 33,  8, 34,   5,   3,   6,  -1, 1.8f },  /* LilyGo T3-S3, T3-S3 e-paper, CDEBYTE EoRa-S3         */ \
    { "tbeam-s3-core", 10,  1,  5,  4,  12,  13,  11,  -1, 1.8f },  /* LilyGo T-Beam S3 Core                                */ \
    { "rak3312",        7, 47,  8, 48,   5,   3,   6,  -1, 1.8f },  /* RAK3312, RAK WisMesh Tap v2                          */ \
}

// Furtka: LORA_PIN_FORCE=<indeks> wymusza jeden pinout i pomija sondowanie. Do użycia, gdyby
// jakaś płytka źle znosiła próbowanie cudzych pinów.
#ifndef LORA_PIN_FORCE
#define LORA_PIN_FORCE -1
#endif

// ── Plan kanałów tła (EU863-870) ──────────────────────────────
// 868.1/868.3/868.5 = domyślne kanały uplinku LoRaWAN EU868.
// 869.525 = tam siedzi mesh (Meshtastic/MeshCore) — podpasmo o luźniejszym duty cycle.
#define LORA_BG_CHANNELS   { 868.1f, 868.3f, 868.5f, 867.1f, 869.525f }
#define LORA_BG_SFS        { 7, 9, 11 }

// Preset okna nasłuchu w cyklu tła — domyślnie LoRaWAN EU868 SF7 (sync 0x34 = publiczny).
#define LORA_BG_FREQ      868.1f
#define LORA_BG_BW        125.0f
#define LORA_BG_SF        7
#define LORA_BG_CR        5
#define LORA_BG_SYNC      0x34
#define LORA_BG_LISTEN_S  20

#define LORA_BG_PERIOD_S  300      // pełny cykl tła co 5 min
#define LORA_BG_DEFAULT   true     // czy tło startuje samo po boocie

#define LORA_BUSY_MARGIN_DB  6     // ile dB nad szumem = kanał zajęty
#define LORA_SWEEP_SAMPLES  40     // próbek RSSI na kanał

// ══ Tryb LINK (beacon + ciągły nasłuch + uplink ramek po WS) ══
// Harmonogram bez negocjacji: WSZYSTKIE nody liczą kanał tym samym wzorem z zegara UTC
// (ws_epoch_now), więc w tej samej minucie siedzą na tej samej częstotliwości. Nasłuch to
// stan spoczynkowy radia — okien odbioru nie planujemy, planujemy tylko sloty NADAWANIA.
#define LORA_LINK_DEFAULT     false   // tryb link startuje wyłączony (BE włącza przez lora_cfg)
#define LORA_LINK_MAX_CH      6       // ile pozycji planu kanałów maksymalnie
#define LORA_LINK_MIN_PER_CH  10      // domyślnie: zmiana kanału co 10 min
#define LORA_LINK_GUARD_S     3       // ±3 s wokół zmiany kanału: nikt nie nadaje (tam robimy sweep)
#define LORA_LINK_SLOT0_S     10      // pierwszy slot beaconu: 10 s po pełnej minucie
#define LORA_LINK_SLOT_GAP_S  7       // odstęp między slotami nadawców
#define LORA_LINK_TX_POWER    14      // dBm — 14 = limit EU868 (ERP 25 mW) dla 868.1/.3/.5

// Duty cycle EU868: 1% na godzinę w podpaśmie. Licznik pilnuje budżetu ZAMIAST dobrej woli —
// beacon odmawia nadania po przekroceniu, nawet gdy BE każe nadawać częściej.
#define LORA_LINK_DUTY_MS_H   36000UL // 1% z 3600 s = 36 s airtime/h

// Nasza ramka: 0xE0 (LoRaWAN "Proprietary" — kulturalnie mówimy obcym bramkom "to nie uplink")
// + ASCII "SMOS <id8> <seq>". Bez szyfrowania: w środku nie ma nic tajnego, a czytelność
// w logach cudzych bramek jest tu zaletą, nie wyciekiem.
#define LORA_BEACON_MAGIC     0xE0
#define LORA_BEACON_PREFIX    "SMOS "
#define LORA_RX_BATCH_MAX     6       // ramek w paczce (mniej, bo payload urósł do 128 B)
#define LORA_RX_CAP_PER_MIN   60      // twardy limit uplinku — w mieście 868.1 potrafi tętnić
// 128 B: ramka wM-Bus po dekodowaniu 3-z-6 traci 1/3 długości, więc przy 32 B zostawało
// 21 B treści — za mało, by rozłożyć nagłówek (L, C, producent, nr seryjny, typ medium).
#define LORA_RX_HEX_MAX       128     // bajtów payloadu wysyłanych jako hex (reszta = same metadane)
