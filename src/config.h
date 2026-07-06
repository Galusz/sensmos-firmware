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
#define ENTITY_POOL_MAX      16   // sub.* — bylo 64 (7.4KB); 16 starcza, heap dla TLS/monitorow
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

// checknet w RDZENIU (v0.28+): sam napędza cykl, kadencję nadpisuje BE przez cn_config.
// Poniższe to TYLKO fallback offline — BE stroi interwał adaptacyjnie wg rozmiaru floty.
#define CHECKNET_ENABLED_DEFAULT       true
#define CHECKNET_INTERVAL_MS_DEFAULT   600000UL  // 10 min — konserwatywny fallback (anty-stampede)
#define CHECKNET_JITTER_MS             20000UL   // ±20s losowy rozrzut per node (anty thundering-herd)
#define CHECKNET_START_DELAY_MS        45000UL   // nie odpalaj tuż po boot (WS/NTP/batch najpierw)

// ── R3 monitory kierowane (v0.30+): deskryptory z BE (monitor_set), persist NVS ──
#define MONITORS_MAX_SLOTS         6      // max monitorów per node (BE pilnuje budżetu przy przydziale)
#define MONITORS_RING_MAX          40     // próbki rtt do percentyli rollupu (per slot)
#define MONITORS_START_DELAY_MS    60000UL // pierwszy pomiar po boot (WS/NTP najpierw)
#define MONITORS_HTTP_MIN_HEAP     45000  // http/TLS wymaga ~45KB ciaglego bloku; mniej -> DEFER (nie fail)

// traceroute last-hop robi teraz BE (serwerowy, peer_probes) — node nie dotyka raw-socketu.
