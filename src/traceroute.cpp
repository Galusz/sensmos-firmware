#include "traceroute.h"
#include "log.h"
#include <WiFi.h>
#include "lwip/raw.h"
#include "lwip/icmp.h"
#include "lwip/inet_chksum.h"
#include "lwip/ip_addr.h"
#include "lwip/tcpip.h"
#include "lwip/pbuf.h"
#include "lwip/udp.h"          // punch-trace: UDP z portu sesji, TTL per-pakiet (pcb->ttl)

#define TR_ID          0x534D      // 'SM' — nasz identyfikator ICMP echo (filtr w recv)
#define TR_PKT_LEN     12          // 8B nagłówek echo + 4B magic
#define TR_TOTAL_BUDGET_MS 30000UL // twardy limit całego trace (nie blokuj pętli w nieskończoność)
#define TR_MAX_SILENT      5       // tyle głuchych TTL z rzędu = koniec trasy (za last-hopem cisza)

static struct raw_pcb*   s_pcb     = nullptr;   // JEDEN, nigdy nie zamykany
static volatile bool     s_waiting = false;
static volatile uint16_t s_seq     = 0;
static volatile uint8_t  s_ttl     = 1;
static volatile uint32_t s_hop_ip  = 0;
static volatile bool     s_reached = false;
static volatile bool     s_got     = false;
static ip_addr_t         s_target;
// Tryb UDP (v0.60, punch-trace przez dziurę): probe = UDP z portu sesji, a nie ICMP echo.
// time-exceeded ma wtedy w środku nasz UDP (proto 17) — matchujemy po portach, nie po TR_ID.
static volatile bool     s_udp_mode = false;
static volatile uint16_t s_udp_src  = 0;    // nasz port sesji (47777) — src wewn. UDP
static volatile uint16_t s_udp_dst  = 0;    // port peera — dst wewn. UDP
static struct udp_pcb*   s_upcb     = nullptr;

// ── recv (wątek tcpip): zjadamy TYLKO nasze pakiety, resztę oddajemy ─────────
static u8_t tr_recv_cb(void*, struct raw_pcb*, struct pbuf* p, const ip_addr_t* addr) {
    if (!s_waiting || !p) return 0;
    uint8_t buf[64];
    u16_t n = pbuf_copy_partial(p, buf, sizeof(buf), 0);
    if (n < 28) return 0;                              // IP(20) + ICMP(8) minimum
    int ihl = (buf[0] & 0x0F) * 4;
    if (n < (u16_t)(ihl + 8)) return 0;
    uint8_t type = buf[ihl];

    if (type == ICMP_ER) {                             // echo reply — czy nasz?
        uint16_t id  = ((uint16_t)buf[ihl + 4] << 8) | buf[ihl + 5];
        uint16_t seq = ((uint16_t)buf[ihl + 6] << 8) | buf[ihl + 7];
        if (id != TR_ID || seq != s_seq) return 0;     // nie nasz (esp_ping) — oddaj
        s_hop_ip = ip_addr_get_ip4_u32(addr);
        s_reached = true; s_got = true;
        pbuf_free(p);
        return 1;
    }
    if (type == ICMP_TE) {                             // time exceeded: w środku NASZ probe?
        int inner = ihl + 8;                           // wewnętrzny nagłówek IP
        if (n < (u16_t)(inner + 20 + 8)) return 0;
        int iihl = (buf[inner] & 0x0F) * 4;
        if (n < (u16_t)(inner + iihl + 8)) return 0;
        if (s_udp_mode) {                              // punch-trace: wewn. pakiet to UDP (proto 17)
            uint8_t  iproto = buf[inner + 9];          // pole protocol w wewn. IP
            uint16_t isrc   = ((uint16_t)buf[inner + iihl + 0] << 8) | buf[inner + iihl + 1];
            uint16_t idst   = ((uint16_t)buf[inner + iihl + 2] << 8) | buf[inner + iihl + 3];
            if (iproto != 17 || isrc != s_udp_src || idst != s_udp_dst) return 0;
        } else {                                       // zwykły trace: wewn. ICMP echo (TR_ID/seq)
            uint8_t  itype = buf[inner + iihl];
            uint16_t iid   = ((uint16_t)buf[inner + iihl + 4] << 8) | buf[inner + iihl + 5];
            uint16_t iseq  = ((uint16_t)buf[inner + iihl + 6] << 8) | buf[inner + iihl + 7];
            if (itype != ICMP_ECHO || iid != TR_ID || iseq != s_seq) return 0;
        }
        s_hop_ip = ip_addr_get_ip4_u32(addr);
        s_reached = false; s_got = true;
        pbuf_free(p);
        return 1;
    }
    return 0;                                          // inne ICMP — nie nasze
}

// ── init + send: wykonywane w wątku tcpip (tcpip_callback) ───────────────────
static void tr_init_in_tcpip(void*) {
    if (s_pcb) return;
    s_pcb = raw_new(IP_PROTO_ICMP);
    if (s_pcb) {
        raw_recv(s_pcb, tr_recv_cb, nullptr);
        raw_bind(s_pcb, IP_ADDR_ANY);
    }
}

static void tr_send_in_tcpip(void*) {
    if (!s_pcb) return;
    struct pbuf* p = pbuf_alloc(PBUF_IP, TR_PKT_LEN, PBUF_RAM);
    if (!p) return;
    struct icmp_echo_hdr* h = (struct icmp_echo_hdr*)p->payload;
    ICMPH_TYPE_SET(h, ICMP_ECHO);
    ICMPH_CODE_SET(h, 0);
    h->id     = lwip_htons(TR_ID);
    h->seqno  = lwip_htons(s_seq);
    ((uint8_t*)p->payload)[8]  = 'S';
    ((uint8_t*)p->payload)[9]  = 'N';
    ((uint8_t*)p->payload)[10] = 'M';
    ((uint8_t*)p->payload)[11] = 'S';
    h->chksum = 0;
    h->chksum = inet_chksum(h, TR_PKT_LEN);
    s_pcb->ttl = s_ttl;
    raw_sendto(s_pcb, p, &s_target);
    pbuf_free(p);                                      // nasz pbuf — zwalniamy ZAWSZE
}

void traceroute_init() {
    if (s_pcb) return;
    tcpip_callback(tr_init_in_tcpip, nullptr);
}

int traceroute_run(const char* host, TrHop* hops, int max_hops,
                   uint32_t per_hop_ms, bool* reached) {
    *reached = false;
    s_udp_mode = false;                                // tryb ICMP (współdzielony pcb z UDP-trace)
    if (!host || !*host || max_hops < 1) return 0;
    if (!s_pcb) {
        traceroute_init();
        delay(50);                                     // daj tcpip czas na init
        if (!s_pcb) { LOGW("trace", "no pcb"); return 0; }
    }

    // Rozwiąż cel (IPv4)
    memset(&s_target, 0, sizeof(s_target));
    if (ipaddr_aton(host, &s_target) == 0) {
        IPAddress ip;
        if (!WiFi.hostByName(host, ip)) return 0;
        IP_ADDR4(&s_target, ip[0], ip[1], ip[2], ip[3]);
    }

    int n = 0, silent = 0;
    unsigned long t_start = millis();
    for (int ttl = 1; ttl <= max_hops && n < max_hops; ttl++) {
        if (millis() - t_start > TR_TOTAL_BUDGET_MS) break;
        if (silent >= TR_MAX_SILENT) break;
        s_seq++;
        s_ttl     = (uint8_t)ttl;
        s_hop_ip  = 0;
        s_got     = false;
        s_waiting = true;
        unsigned long t0 = millis();
        tcpip_callback(tr_send_in_tcpip, nullptr);
        while (!s_got && millis() - t0 < per_hop_ms) delay(10);
        s_waiting = false;

        hops[n].ttl = (uint8_t)ttl;
        hops[n].ip  = s_got ? s_hop_ip : 0;
        hops[n].ms  = s_got ? (float)(millis() - t0) : -1.0f;
        n++;
        silent = s_got ? 0 : silent + 1;
        if (s_got && s_reached) { *reached = true; break; }
        yield();
    }
    LOGD("trace", "%s: %d hops, reached=%d", host, n, *reached);
    return n;
}

// ── Tryb UDP (v0.60): trace PRZEZ wybitą dziurę NAT ──────────────────────────
// Punch otworzył mapowanie (LAN:srcPort → peer). Wysyłamy UDP tą samą 5-tuplą z rosnącym
// TTL; time-exceeded odnoszące się do AKTYWNEJ sesji UDP wracają przez conntrack (RFC5508),
// czego ICMP-echo trace nie osiąga. udp_pcb daje kontrolę TTL per-pakiet (WiFiUDP nie umie).
static void tr_udp_init_in_tcpip(void* arg) {
    if (s_upcb) { udp_remove(s_upcb); s_upcb = nullptr; }
    struct udp_pcb* pcb = udp_new();
    if (!pcb) return;
    ip_set_option(pcb, SOF_REUSEADDR);                 // port dopiero co zwolniony przez WiFiUDP
    if (udp_bind(pcb, IP_ADDR_ANY, (uint16_t)(uintptr_t)arg) != ERR_OK) { udp_remove(pcb); return; }
    s_upcb = pcb;
}
static void tr_udp_remove_in_tcpip(void*) {
    if (s_upcb) { udp_remove(s_upcb); s_upcb = nullptr; }
}
static void tr_udp_send_in_tcpip(void*) {
    if (!s_upcb) return;
    struct pbuf* p = pbuf_alloc(PBUF_TRANSPORT, 8, PBUF_RAM);
    if (!p) return;
    memcpy(p->payload, "SPTsnms", 7); ((char*)p->payload)[7] = 0;   // payload i tak ucinany na routerach
    s_upcb->ttl = s_ttl;                               // rosnący TTL = kolejny hop
    udp_sendto(s_upcb, p, &s_target, s_udp_dst);
    pbuf_free(p);
}

int traceroute_run_udp(const char* host, uint16_t dstPort, uint16_t srcPort,
                       TrHop* hops, int max_hops, uint32_t per_hop_ms, bool* reached) {
    *reached = false;                                  // peer połyka UDP (nasłuchuje) — last-mile z puncha
    if (!host || !*host || dstPort == 0 || max_hops < 1) return 0;
    if (!s_pcb) { traceroute_init(); delay(50); if (!s_pcb) { LOGW("trace", "no pcb"); return 0; } }

    memset(&s_target, 0, sizeof(s_target));
    if (ipaddr_aton(host, &s_target) == 0) {
        IPAddress ip;
        if (!WiFi.hostByName(host, ip)) return 0;
        IP_ADDR4(&s_target, ip[0], ip[1], ip[2], ip[3]);
    }

    tcpip_callback(tr_udp_init_in_tcpip, (void*)(uintptr_t)srcPort);
    delay(30);                                         // daj tcpip czas na bind
    if (!s_upcb) { LOGW("trace", "udp bind %u failed", srcPort); return 0; }

    s_udp_mode = true; s_udp_src = srcPort; s_udp_dst = dstPort;
    int n = 0, silent = 0;
    unsigned long t_start = millis();
    for (int ttl = 1; ttl <= max_hops && n < max_hops; ttl++) {
        if (millis() - t_start > TR_TOTAL_BUDGET_MS) break;
        if (silent >= TR_MAX_SILENT) break;            // za last-hopem cisza (peer połyka)
        s_ttl = (uint8_t)ttl; s_hop_ip = 0; s_got = false; s_waiting = true;
        unsigned long t0 = millis();
        tcpip_callback(tr_udp_send_in_tcpip, nullptr);
        while (!s_got && millis() - t0 < per_hop_ms) delay(10);
        s_waiting = false;
        hops[n].ttl = (uint8_t)ttl;
        hops[n].ip  = s_got ? s_hop_ip : 0;
        hops[n].ms  = s_got ? (float)(millis() - t0) : -1.0f;
        n++;
        silent = s_got ? 0 : silent + 1;
        yield();
    }
    s_udp_mode = false;
    tcpip_callback(tr_udp_remove_in_tcpip, nullptr);
    LOGD("trace", "udp %s:%u: %d hops", host, dstPort, n);
    return n;
}
