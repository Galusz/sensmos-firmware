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
#define LORA_BOARD_HELTEC_S3  1   // Heltec Wireless Paper / WiFi LoRa 32 V3 — POTWIERDZONE (LoRaScan chodził)
#define LORA_BOARD_XIAO_S3    2   // Seeed XIAO ESP32S3 + Wio-SX1262 przez złącze B2B —
                                  // piny z variants/esp32s3/seeed_xiao_s3/variant.h (Meshtastic)

#ifndef LORA_BOARD
#define LORA_BOARD LORA_BOARD_HELTEC_S3
#endif

#if LORA_BOARD == LORA_BOARD_HELTEC_S3
  #define LORA_NSS    8
  #define LORA_DIO1  14
  #define LORA_RST   12
  #define LORA_BUSY  13
  #define LORA_SCK    9
  #define LORA_MISO  11
  #define LORA_MOSI  10
  #define LORA_TCXO  1.6f          // Heltec V3+ ma TCXO 1.6V; przy błędzie -706/-2 spróbuj 1.8 albo 0
#elif LORA_BOARD == LORA_BOARD_XIAO_S3
  #define LORA_NSS   41
  #define LORA_DIO1  39
  #define LORA_RST   42
  #define LORA_BUSY  40
  #define LORA_SCK    7
  #define LORA_MISO   8
  #define LORA_MOSI   9
  #define LORA_TCXO  1.8f          // TCXO z DIO3 przy 1.8V — 1.6V (jak Heltec) tu NIE zadziała
  // Zewnętrzny przełącznik antenowy. DIO2 obsługuje RadioLib samo (begin() woła
  // setDio2AsRfSwitch(true)), ale RXEN trzeba podać jawnie — bez tego tor odbiorczy
  // jest odcięty i radio jest głuche mimo poprawnego begin().
  #define LORA_RXEN  38
#else
  #error "nieznany LORA_BOARD"
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
