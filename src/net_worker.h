#pragma once
#include <Arduino.h>
#include "config.h"       // MAX_DATA_LEN
#include "checknet.h"     // CnJob, CnResult (deskryptor sondy + wynik)
#include "traceroute.h"   // TrHop

// Async net worker ("wór") — DOCS/dev/ASYNC-QUEUE.md.
// Jeden task na core 1 pobiera po jednym jobie z kolejek (hi=monitory > lo=checknet),
// wykonuje sonde (JEDEN TLS/socket naraz — heap-safe) i odsyla wynik do resultQ.
// loop() tylko kolejkuje (enqueue) i konsumuje wyniki (poll) — nigdy nie blokuje sie na TLS.

enum NetSrc : uint8_t { NW_CHECKNET = 0, NW_MONITOR = 1, NW_SCRIPT = 2, NW_SYSTEM = 3 };

struct NetJob {
    uint8_t src;        // NetSrc — steruje priorytetem (hi/lo) i routingiem wyniku
    int32_t ref_id;     // monitor: id monitora; skrypt: token await; checknet: nieuzywane
    int16_t ref_idx;    // monitor: slot; checknet: indeks joba; skrypt: indeks kroku
    uint32_t enq_ms;    // stemplowane w net_worker_enqueue (metryka czekania w kolejce)
    CnJob   job;        // job.kind decyduje o executorze: icmp|tcp|dns|http|trace|fetch|whook
    // skrypty (fetch/webhook): pelny URL + body (template wypelniony przy odpaleniu kroku)
    char    url[MAX_DATA_LEN];
    char    body[256];      // whook: POST body
    char    fetch_path[48]; // fetch: JSON path (ekstrakcja na workerze)
};

struct NetResult {
    uint8_t  src;
    int32_t  ref_id;
    int16_t  ref_idx;
    bool     deferred;  // http/TLS pominiete (za maly ciagly blok) — retry, nie licz jako fail
    uint32_t heap_largest;  // largest-block z CHWILI decyzji o defer (log w loop bylby mylacy)
    bool     is_trace;  // wynik traceroute (hops[] wypelnione)
    CnResult res;
    // fetch: wartosc wyciagnieta JSON-path na workerze + payload raportu do BE
    float    store_val;
    bool     has_value;
    char     payload[128];
    TrHop    hops[16];
    int16_t  hop_n;
    bool     reached;
};

bool     net_worker_init();                      // twórz task + kolejki (po WiFi/traceroute_init)
bool     net_worker_enqueue(const NetJob& j, bool hi);  // hi=true → priorytet monitorów
bool     net_worker_poll(NetResult& out);        // pobierz jeden gotowy wynik (nieblokujące)
uint16_t net_worker_pending();                   // głębokość kolejek hi+lo (metryka)
bool     net_worker_busy();                       // job aktualnie wykonywany na workerze
// Metryki saturacji (ASYNC-QUEUE §10) — wołaj 1/min z pinga; busy% liczone od
// poprzedniego wywołania (okno = okres raportowania), wait = EMA czekania w kolejce.
void     net_worker_stats(uint16_t* wait_ms, uint8_t* busy_pct, uint16_t* depth);
uint8_t  net_worker_last_busy();   // ostatni policzony busy% (bez resetu okna) — do [health]
