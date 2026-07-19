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

// ── Fetch (akcja skryptu, wykonywana na net_worker) ───────────
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
// v0.40: pomiary na net_worker (nie blokują loop) → slotów 32, ale to tylko BEZPIECZNIK
// RAM (32×~0.4KB=12.6KB .bss). Realny limit steruje BE z metryki q_lag (admission/shed —
// ASYNC-QUEUE §10). Stare FW (<0.39, blokująca pętla) dostają od BE max 6.
#define MONITORS_MAX_SLOTS         24     // bezpiecznik RAM; realną liczbę steruje BE (q_lag)
#define MONITORS_RING_MAX          40     // próbki rtt do percentyli rollupu (per slot, uint16 ms)
#define MONITORS_START_DELAY_MS    60000UL // pierwszy pomiar po boot (WS/NTP najpierw)
// mbedTLS alokuje bufory in/out OSOBNO (po ~17KB) — nie potrzebuje 45KB jednym kawalkiem.
// 45000 bylo przestrzelone: fragmentacja (drobiazg pety w srodku regionu po TLS) regularnie
// zbija largest do ~38K, a sondy i tak dzialaly. 30K = 17K + margines na najgorszy podzial.
#define MONITORS_HTTP_MIN_HEAP     30000  // prog guarda TLS (DEFER, nie fail, gdy ponizej)

// ── Trace (v0.37) ─────────────────────────────────────────────
#define TRACE_COOLDOWN_MS   600000UL  // ten sam cel nie jest re-trace'owany przez 10 min
#define TRACE_COOLDOWN_SLOTS 10       // rolling lista ostatnio trace'owanych celi

// ── Async net worker ("wór", v0.39+) — DOCS/dev/ASYNC-QUEUE.md ─
// Jeden task na core 1 serializuje CALA prace sieciowa (checknet+monitory): zawsze
// max 1 TLS naraz (heap-safe), a loop() nie blokuje sie na sondach. Stos zmierzony
// spikiem: TLS GET zjada ~3.7KB → 8KB z zapasem na podpisywane requesty.
#define NET_WORKER_STACK    8192
#define NET_JOBQ_DEPTH      8         // per kolejka (hi=monitory, lo=checknet+skrypty); NetJob ~0.6KB →
                                      // 16 slotów było ~21KB heapu. Backpressure (retry przy pełnej)
                                      // jest u WSZYSTKICH callerów, więc 8 wystarcza (RAM-AUDIT 0.49).
#define NET_RESQ_DEPTH      4
#define NET_COLLECT_TIMEOUT_MS 60000UL // checknet: awaryjny limit zebrania wynikow cyklu
// Skrypty na worze (v0.39, ASYNC-QUEUE §8): krok sieciowy zawiesza skrypt, wynik wznawia
// od kroku+1. Timeout = awaryjne wznowienie jako fail (zgubiony wynik nie wiesza skryptu).
#define NET_AWAIT_TIMEOUT_MS       20000UL
#define SCRIPT_NET_COOLDOWN_MIN_S  60     // min cooldown akcji sieciowych (defensywnie; BE też tnie)

// ── Zewnętrzne sondy (checknow/monitor/fetch): widzieć stronę JAK BROWSER ──────
// UA: wiele serwerów odsyła śmieci/redirect nieznanemu klientowi (domyślny to "ESP32HTTPClient").
// Follow-redirects: goły 301 (kanonizacja www/https) bez tego kończył sondę na przekierowaniu —
// fałszywe "301" na check-now i zła strona do change-watchera. NIE dotyczy podpisanych wywołań do BE.
#define HTTP_PROBE_UA "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
#define HTTP_PROBE_REDIRECT_MAX 5

// ── OTA (v0.35+) ──────────────────────────────────────────────
#define OTA_CONFIRM_TIMEOUT_MS  300000UL  // brak WS w 5 min po aktualizacji -> rollback na stary slot

// traceroute last-hop robi teraz BE (serwerowy, peer_probes) — node nie dotyka raw-socketu.
