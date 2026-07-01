#pragma once
/**
 * SENSMOS Firmware — Konfiguracja globalna
 * Wszystkie stałe kompilacji w jednym miejscu.
 */

// ── Script engine ─────────────────────────────────────────────
// TESTY: 30s. Docelowo (produkcja): 5000
#define TICK_INTERVAL_MS     30000

#define MAX_DATASCRIPTS      5    // skrypty z BE (align z limitem 5/node w BE)
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

// ── WebSocket ─────────────────────────────────────────────────
// WS plaintext (ws://host:80/v1/ws) — trwały TLS zjadałby ~70KB heapu, a ESP32 tego nie ma.
// Dane i tak podpisane kryptograficznie (integralność niezależna od TLS). HTTP/fetch zostają
// po https (połączenia chwilowe — alokują TLS tylko na czas i zwalniają). 0 = wss jak z backend_url.
#define WS_PLAINTEXT          1
#define WS_PLAINTEXT_PORT     80

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

// ── checknet (sondy jakości internetu) ────────────────────────
#define CHECKNET_MAX_JOBS          6      // ile jobów na cykl (BE wysyła max 6: 2 cele + 4 peery)
#define CHECKNET_PING_COUNT        5      // pakietów ICMP na pomiar (jitter/loss)
#define CHECKNET_PING_TIMEOUT_MS   1000   // timeout jednego pakietu
#define CHECKNET_PING_INTERVAL_MS  200    // odstęp między pakietami
#define CHECKNET_ASSIGN_TIMEOUT_MS 10000  // ile czekać na check_jobs z BE

// ── traceroute last-hop (gdy peer blokuje ICMP) — defaulty, BE może nadpisać ──
#define TRACE_ENABLED        1
#define TRACE_MAX_TTL        24
#define TRACE_PROBES         2
#define TRACE_TIMEOUT_MS     500
