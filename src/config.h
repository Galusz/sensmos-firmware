#pragma once
/**
 * SENSMOS Firmware — Konfiguracja globalna
 * Wszystkie stałe kompilacji w jednym miejscu.
 */

// ── Script engine ─────────────────────────────────────────────
// TESTY: 30s. Docelowo (produkcja): 5000
#define TICK_INTERVAL_MS     30000

#define MAX_DATASCRIPTS      4    // skrypty z BE
#define MAX_USERSCRIPTS      2    // skrypty usera (NVS)
#define MAX_SCRIPTS          (MAX_DATASCRIPTS + MAX_USERSCRIPTS)
#define MAX_STEPS            4    // kroków per skrypt
#define MAX_EXPR_LEN         48
#define MAX_ID_LEN           20
#define MAX_ENTITY_LEN       28
#define MAX_DATA_LEN         96   // url itp.

// ── Entity store ──────────────────────────────────────────────
#define ENTITY_PUB_MAX       16
#define ENTITY_OWN_MAX       16
#define ENTITY_TMP_MAX        8
#define ENTITY_POOL_MAX      64
// own.* nieodświeżone przez ten czas są usuwane z bufora (anty „wiszące" encje).
// Musi być > cyklu odświeżania źródła (HA pushuje ~5 min). 0 = wyłączone.
#define OWN_TTL_S          1800

// ── Message router ────────────────────────────────────────────
#define MAX_MESSAGE_SLOTS     3

// ── Przycisk serwisowy ────────────────────────────────────────
// BOOT/GPIO0 (active LOW, INPUT_PULLUP). 3s→tryb BLE serwisowy, 10s→factory reset.
// Zmień na inny GPIO jeśli Twoja płytka ma dedykowany przycisk.
#define SERVICE_BUTTON_PIN     0
#define SERVICE_BTN_BLE_MS     3000
#define SERVICE_BTN_RESET_MS  10000

// ── HTTP server (node) ────────────────────────────────────────
#define INBOX_SIZE            6
#define NODE_LOG_SIZE        12

// ── Timeouty HTTP (ms) ────────────────────────────────────────
#define HTTP_TIMEOUT_WEBHOOK   3000
#define HTTP_TIMEOUT_FETCH     4000
#define HTTP_TIMEOUT_BACKEND   8000
#define HTTP_TIMEOUT_QUERY    10000

// ── Fetch (script_async) ──────────────────────────────────────
#define FETCH_BODY_LIMIT     8192   // max body w RAM

// ── Data sender ───────────────────────────────────────────────
#define BATCH_MIN_INTERVAL_MS   (1UL * 60 * 1000)   // min odstęp między batchami
#define BATCH_FORCE_INTERVAL_MS (3UL * 60 * 1000)   // wymuszony batch
