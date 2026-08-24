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
#define ENTITY_PUB_MAX       16   // telemetria NET poszla do mon[] (mon-split), wiec pub[] znowu ma zapas:
                                  // realny node ma max 9 sensorow nie-NET. 40 przekraczalo TX_SCRATCH_LEN
                                  // (~3365B > 3072) = CICHY drop calego batcha.
// 12 -> 18: doszlo 5 encji radiowych (mon.lora_*, kategoria RF w BE). Przy 12 slotach
// i 11 encjach NET zapas byl jeden, wiec entity_push wypychal NAJSTARSZY wpis — a NET
// jest zapisywany co batch, LoRa raz na 5 min, wiec to zawsze radiowe wylatywalo tuz
// przed wyslaniem paczki. Efekt: kategoria RF istniala w BE i nigdy nie dostawala danych.
#define ENTITY_MON_MAX       18   // 11 NET + 5 RF + 2 zapasu
#define ENTITY_OWN_MAX       16
#define ENTITY_TMP_MAX        8
#define ENTITY_POOL_MAX      16   // sub.* — bylo 64 (7.4KB); 16 starcza, heap dla TLS/monitorow
                                  // (uwaga: >16 sub.* subskrypcji -> ten sam flapping co pub; sticky w HA 0.4.11 maskuje)
// own.* nieodświeżone przez ten czas są usuwane z bufora (anty „wiszące" encje).
// Musi być > cyklu odświeżania źródła (HA pushuje ~5 min). 0 = wyłączone.
#define OWN_TTL_S          1800
// Encja pub.* nieodswiezona przez dobe wypada z tablicy. Do 2026-08-18 pub[] NIE MIAL
// zadnego wygasania: wartosc wpisana raz (np. 222 V z odlaczonej integracji HA) jechala
// w KAZDYM batchu w nieskonczonosc i trzymala slot. Przy 16 slotach kilka przestawien
// integracji wypelnia tablice trupami, ktore zaczynaja wypychac zywe encje — dokladnie ten
// mechanizm zjadl encje LoRa w mon[12].
//
// Nie skraca okna nagrody: BE liczy swiezosc z last_updated (wieku odczytu), wiec
// przyciecie tu niczego nie zmienia w rozliczeniu — tylko przestaje wysylac martwe dane.
#define PUB_TTL_S          86400

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
// Dane i tak uwierzytelnione kryptograficznie (WS enc: AES-GCM + seq, integralność niezależna od TLS). HTTP/fetch zostają
// po https (połączenia chwilowe — alokują TLS tylko na czas i zwalniają). 0 = wss jak z backend_url.
#define WS_PLAINTEXT          1
#define WS_PLAINTEXT_PORT     80

// ── WS-watchdog (KNOWN-ISSUES #7; spec usera 2026-08-22) ──────
// Po restarcie nginxa na VPS 1 node z 263 zaklinował się w stanie „WiFi stoi, WS martwy,
// zero prób" i wisiał godzinami. Przebieg: WS pada przy żywym WiFi → sonda TCP na endpoint
// WS rusza OD RAZU (pierwsze 5 min co 20 s, potem co 60 s). Restart „zawieszka": sonda
// przechodzi, a WS leży nieprzerwanie >= WS_WD_GRACE_MS — karencja jest konieczna, bo
// każdy deploy BE zrywa WS całej flocie na 10-30 s przy żywym nginx (TCP OK); bez niej
// deploy równałby się restartowi 263 nodów naraz. Restart PROFILAKTYCZNY: WS i TCP martwe
// nieprzerwanie WS_WD_PROPH_MS (długa awaria internetu = cykl co ~2h — świadoma decyzja;
// zgłoszenie zaniku WS ramką LoRa dojdzie osobno: plan lora emergency beacon).
#define WS_WD_PROBE_FAST_MS  (20UL * 1000)           // kadencja sondy w oknie karencji
#define WS_WD_PROBE_MS       (60UL * 1000)           // kadencja sondy po karencji
#define WS_WD_GRACE_MS       (5UL * 60 * 1000)       // TCP OK + WS martwy >= tyle → restart
#define WS_WD_PROPH_MS       (2UL * 60 * 60 * 1000)  // WS+TCP leżą tak długo → restart profilaktyczny

// ── MQTT publisher (LEKKIE, tylko wychodzące — mqtt_pub.cpp) ───
// Broker w LAN usera (obok HA). Własny minimalny klient: CONNECT+PUBLISH+PING, bez subscribe.
#define MQTT_PORT_DEF          1883
#define MQTT_BUF_SIZE          1536      // wspólny bufor pakietu (single-writer: loop)
#define MQTT_KEEPALIVE_S       60
#define MQTT_SOCK_TIMEOUT_MS   3000      // connect/CONNACK — krótko, żeby nie wisieć w loop
#define MQTT_STATE_EVERY_MS    30000     // publish snapshot state co 30 s
#define MQTT_ENT_EVERY_MS      60000     // publish encji (pub+own, retained) co 60 s
#define MQTT_DISC_MAX          40        // cache eid-ów z wysłanym HA-discovery (per połączenie)
#define MQTT_RECONNECT_MS      5000      // backoff start
#define MQTT_RECONNECT_MAX_MS  300000    // backoff cap (5 min)

// ── WiFi env fingerprint (wifi_env.cpp) ───────────────────────
// Hashe otoczenia WiFi (SHA256→8B per BSSID/SSID) do BE — sygnał zmiany lokalizacji noda.
#define WIFI_ENV_EVERY_MS      (6UL * 60 * 60 * 1000)  // pełny skan co 6h (skan rwie RX ~2-7 s)
#define WIFI_ENV_BOOT_DELAY_MS (3UL * 60 * 1000)       // pierwszy: 3 min po boocie
#define WIFI_ENV_TOP           8                       // top-N sieci po RSSI

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
#define MON_INTERVAL_MS         (3UL * 60 * 1000)   // ramka telemetrii NET; checknet i tak liczy co ~600s

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
#define MONITORS_MAX_SLOTS         16     // bezpiecznik RAM (0.72: 24→16, ~2.3KB BSS); realną liczbę steruje BE (q_lag + workerSlots)
#define MONITORS_RING_MAX          40     // próbki rtt do percentyli rollupu (per slot, uint16 ms)
#define MONITORS_START_DELAY_MS    60000UL // pierwszy pomiar po boot (WS/NTP najpierw)
// mbedTLS alokuje bufory in/out OSOBNO (po ~17KB) — nie potrzebuje 45KB jednym kawalkiem.
// 45000 bylo przestrzelone: fragmentacja (drobiazg pety w srodku regionu po TLS) regularnie
// zbija largest do ~38K, a sondy i tak dzialaly. 30K = 17K + margines na najgorszy podzial.
#define MONITORS_HTTP_MIN_HEAP     30000  // TLS wymaga ~34KB CIAGLEGO bloku (2x16.4KB in/out mbedTLS osobno)
#define TUNNEL_TLS_RESERVE         20000  // gdy tunel aktywny — dodatkowa rezerwa nad progiem TLS (ochrona sesji terminalowej)
// 0.71 — UNIWERSALNA bramka RAM wora (gate na TOTAL free, nie tylko blok — to byla dziura 0.70 OOM).
// Jeden WiFiClientSecure GET zjada ~50KB TOTALU; nie startuj joba, jesli po jego szczycie zostaloby
// za malo dla loop()/WebServer (crash: WebServer `new` na wyczerpanym heapie → bad_alloc → terminate).
#define HEAP_GATE_TLS              68000  // http/fetch: ~50k TLS + ~18k zapasu na loop/WS/WebServer
#define HEAP_GATE_MED              42000  // trace: pbufy/rdns
#define HEAP_GATE_LIGHT            26000  // icmp/tcp/dns/punch/stun/scan: kilka KB + zapas

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
// KNOWN-ISSUES #8: pętla brownout/crash na starcie nowego FW resetuje millis(), więc timer
// wyżej jest nieosiągalny. Licznik bootów z pending w NVS — po tylu nieudanych bootach
// rollback JUŻ w ota_init, przed szczytem poboru przy inicjalizacji radia.
#define OTA_CONFIRM_BOOTS_MAX   3

// traceroute: node robi autonomiczny trace do głuchych peerów przez statyczny raw ICMP pcb
// (LWIP), wołany z checknet i net_worker; BE robi komplementarny trace od siebie (peer_probes).
