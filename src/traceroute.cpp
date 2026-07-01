#include "traceroute.h"
#include <Arduino.h>
#include <string.h>
#include <esp_random.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/sockets.h"
#include "lwip/inet.h"
#include "lwip/ip4_addr.h"

#ifndef IP_PROTO_ICMP
#define IP_PROTO_ICMP 1     // numer protokołu ICMP (lwip nie zawsze eksportuje IPPROTO_ICMP)
#endif
#ifndef IP_TTL
#define IP_TTL 2            // setsockopt(IPPROTO_IP, IP_TTL) — lwip
#endif

struct __attribute__((packed)) IcmpEcho {
    uint8_t  type;   // 8 = echo request
    uint8_t  code;
    uint16_t chksum;
    uint16_t id;
    uint16_t seq;
    uint8_t  payload[8];
};

static TraceResult   g_tr;
static volatile bool g_busy = false;
static volatile bool g_done = false;
struct TrArgs { char target[40]; uint8_t max_ttl; uint8_t probes; uint16_t timeout_ms; };
static TrArgs g_args;

// Internet checksum (endian-neutralny): sumuj 16-bit słowa "jak leżą", ~sum.
static uint16_t icmp_cksum(const void* data, int len) {
    const uint16_t* p = (const uint16_t*)data;
    uint32_t sum = 0;
    while (len > 1) { sum += *p++; len -= 2; }
    if (len) sum += *(const uint8_t*)p;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (uint16_t)~sum;
}

static void trace_task(void*) {
    TraceResult out; memset(&out, 0, sizeof(out));
    const uint8_t  max_ttl = g_args.max_ttl;
    const uint8_t  probes  = g_args.probes;
    const uint16_t timeout = g_args.timeout_ms;

    ip4_addr_t target;
    int s = -1;
    if (ip4addr_aton(g_args.target, &target))
        s = socket(AF_INET, SOCK_RAW, IP_PROTO_ICMP);

    if (s >= 0) {
        struct sockaddr_in to; memset(&to, 0, sizeof(to));
        to.sin_family = AF_INET;
        to.sin_addr.s_addr = target.addr;
        const uint16_t id = (uint16_t)(esp_random() & 0xFFFF);
        bool found_any = false;
        int  silent = 0;

        for (uint8_t ttl = 1; ttl <= max_ttl; ttl++) {
            int ittl = ttl;
            setsockopt(s, IPPROTO_IP, IP_TTL, &ittl, sizeof(ittl));

            bool responded = false, reached = false;
            char hop[16] = {0};
            uint32_t best = 0;

            for (uint8_t pr = 0; pr < probes; pr++) {
                IcmpEcho pkt; memset(&pkt, 0, sizeof(pkt));
                pkt.type = 8;
                pkt.id   = htons(id);
                pkt.seq  = htons(((uint16_t)ttl << 8) | pr);
                memcpy(pkt.payload, "SENSMOS", 7);
                pkt.chksum = icmp_cksum(&pkt, sizeof(pkt));

                const uint32_t t0 = millis();
                if (sendto(s, &pkt, sizeof(pkt), 0, (struct sockaddr*)&to, sizeof(to)) < 0) continue;

                for (;;) {
                    const uint32_t el = millis() - t0;
                    if (el >= timeout) break;
                    const uint32_t rem = timeout - el;
                    struct timeval tv; tv.tv_sec = rem / 1000; tv.tv_usec = (rem % 1000) * 1000;
                    fd_set rf; FD_ZERO(&rf); FD_SET(s, &rf);
                    if (select(s + 1, &rf, NULL, NULL, &tv) <= 0) break;

                    uint8_t buf[128];
                    int n = recvfrom(s, buf, sizeof(buf), 0, NULL, NULL);
                    if (n <= 0) break;
                    const int ihl = (buf[0] & 0x0F) * 4;         // SOCK_RAW → bufor zaczyna się od nagłówka IP
                    if (n < ihl + 8) continue;
                    const uint8_t type = buf[ihl];
                    const uint32_t rtt = millis() - t0;
                    // źródło pakietu = hop (offset 12..15 nagłówka IP)
                    char src[16];
                    snprintf(src, sizeof(src), "%u.%u.%u.%u", buf[12], buf[13], buf[14], buf[15]);

                    if (type == 0) {            // Echo Reply — target (weryfikuj id)
                        const uint16_t rid = ((uint16_t)buf[ihl + 4] << 8) | buf[ihl + 5];
                        if (rid != id) continue;
                        reached = responded = true;
                        strncpy(hop, src, sizeof(hop) - 1);
                        if (!best || rtt < best) best = rtt;
                        break;
                    } else if (type == 11) {    // Time Exceeded — hop pośredni
                        responded = true;
                        strncpy(hop, src, sizeof(hop) - 1);
                        if (!best || rtt < best) best = rtt;
                        break;
                    }
                    // inny typ ICMP → czytaj dalej do timeoutu
                }
                if (reached) break;
            }

            if (responded) {
                found_any = true; silent = 0;
                strncpy(out.last_hop, hop, sizeof(out.last_hop) - 1);
                out.hops = ttl; out.rtt_ms = best; out.ok = true;
                if (reached) { out.reached = true; break; }
            } else if (found_any && ++silent >= 3) {
                break;   // 3 ciche hopy po ostatnim znalezionym → cel blisko, kończymy
            }
        }
        close(s);
    }

    g_tr = out;
    g_done = true;
    g_busy = false;
    vTaskDelete(NULL);
}

bool trace_start(const char* target_ip, uint8_t max_ttl, uint8_t probes, uint16_t timeout_ms) {
    if (g_busy || !target_ip || !*target_ip) return false;
    strlcpy(g_args.target, target_ip, sizeof(g_args.target));
    g_args.max_ttl    = (max_ttl == 0 || max_ttl > 40) ? 24 : max_ttl;
    g_args.probes     = probes == 0 ? 1 : (probes > 3 ? 3 : probes);
    g_args.timeout_ms = timeout_ms == 0 ? 500 : timeout_ms;
    memset(&g_tr, 0, sizeof(g_tr));
    g_done = false; g_busy = true;
    // Task trace na heapie (4KB, transient — tylko podczas trace, potem vTaskDelete zwalnia).
    // Statyczny stos zabierał 4KB z .bss na stałe → mniej heapu → handshake TLS WS padał.
    if (xTaskCreate(trace_task, "trace", 4096, NULL, 5, NULL) != pdPASS) {
        g_busy = false;
        return false;
    }
    return true;
}
bool trace_busy() { return g_busy; }
bool trace_done() { return g_done; }
const TraceResult& trace_result() { return g_tr; }
