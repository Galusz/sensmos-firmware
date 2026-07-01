#pragma once
/**
 * SENSMOS Firmware — traceroute (last-hop)
 * Gdy peer blokuje ICMP (loss 100%), robimy TTL-sweep i bierzemy OSTATNI odpowiadający
 * hop (zwykle brzeg ISP celu, blisko niego geograficznie) → przybliżony ping regionu
 * + liczba hopów (głębokość topologii). Raw ICMP przez socket API lwip (SOCK_RAW),
 * blokujący, więc uruchamiany w osobnym tasku FreeRTOS (async: start/busy/done/result).
 */
#include <stdint.h>

struct TraceResult {
    bool     ok;          // znaleziono jakikolwiek odpowiadający hop
    bool     reached;     // dotarliśmy do samego targetu (Echo Reply)
    uint8_t  hops;        // TTL ostatniego odpowiadającego hopa
    uint32_t rtt_ms;      // RTT do ostatniego hopa
    char     last_hop[16];// IP ostatniego odpowiadającego hopa
};

// Start asynchroniczny (jeden na raz). target_ip = literał IPv4. false = zajęte/zły target.
bool trace_start(const char* target_ip, uint8_t max_ttl, uint8_t probes, uint16_t timeout_ms);
bool trace_busy();
bool trace_done();
const TraceResult& trace_result();
