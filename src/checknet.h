#pragma once
#include <ArduinoJson.h>

// checknet: pomiary jakości internetu sterowane przez BE.
// Cykl: checknet_run() -> WS check_assign -> BE odsyła check_jobs -> mierzymy ICMP
// (rtt/jitter/loss, async, nie blokuje pętli) -> WS check_result.
struct NetResult;   // net_worker.h (fwd — unikamy cyklu include)

void checknet_init();
void checknet_run();                    // wyzwól cykl (rdzeń samonapędza; akcja skryptu deprecated)
void checknet_update();                 // wołaj z loop() — samonapęd + maszyna stanów
void checknet_on_jobs(JsonArray jobs);  // z ws_client przy check_jobs
void checknet_on_net_result(const NetResult& nr);  // wynik sondy z net_worker (dispatch w loop)
// Config z BE (WS cn_config): enabled + interwał (adaptacyjny wg floty) + limity
// + globalny cooldown autonomicznego trace (trace_cd_s). Persist w NVS.
void checknet_set_config(bool enabled, uint32_t interval_ms, int max_jobs, int ping_count, uint32_t trace_cd_s);
bool checknet_busy();                   // cykl w toku

// ── Współdzielone typy sond (używa też monitors.cpp — REUSE executorów R2) ──
struct CnJob {
    char kind[6];            // icmp|tcp|dns|http
    char host[64];
    char target_kind[8];
    char to_region[8];
    char to_lat[16];
    char to_lon[16];
    int  count;              // icmp: pakiety
    int  port;               // tcp/http
    int  timeout_ms;         // per-probe (0 = default per kind)
    char path[64];           // http
    char expected[40];       // dns: oczekiwane IP (prefix); integralność
    uint16_t expected_status; // http (0 = dowolny 2xx/3xx)
    uint8_t  https;          // http: 1=https
    uint8_t  http_get;       // http: 0=HEAD, 1=GET
    uint8_t  phases;         // http: 1 = zmierz DNS i TCP-connect OSOBNO (check-now)
};
struct CnResult {
    bool  ok;
    float rtt_ms;            // pierwotna latencja: rtt(icmp)/connect(tcp)/resolve(dns)/total(http)
    float jitter_ms;         // icmp
    float loss_pct;          // icmp
    int   samples;           // icmp
    float ttfb_ms;           // http
    int   status_code;       // http
    bool  match;             // dns (vs expected)
    char  resolved_ip[40];   // dns; http+phases: IP celu z fazy DNS (jest TEŻ gdy sonda padnie)
    // http+phases — rozbicie na fazy. Sens: http total = DNS+TCP+TLS+czas_myślenia_serwera,
    // więc jako miara ODLEGŁOŚCI jest bezużyteczny. Czysty TCP-connect to dokładnie 1 RTT
    // bez przetwarzania serwera → jedyna uczciwa linijka (porównywalna z podłogą pingu).
    float dns_ms;            // -1 = nie mierzono, 0 = z cache
    float tcp_ms;            // -1 = nie mierzono / connect padł
};

// Egzekutory blokujące (tcp/dns/http) — współdzielone z monitors.cpp
void cn_probe_tcp(CnJob& j, CnResult& r);
void cn_probe_dns(CnJob& j, CnResult& r);
void cn_probe_http(CnJob& j, CnResult& r);
