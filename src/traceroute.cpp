#include "traceroute.h"
#include <WiFi.h>
#include "lwip/raw.h"
#include "lwip/icmp.h"
#include "lwip/inet_chksum.h"
#include "lwip/ip_addr.h"
#include "lwip/tcpip.h"
#include "lwip/pbuf.h"

#define TR_ID          0x534D      // 'SM' — nasz identyfikator ICMP echo (filtr w recv)
#define TR_PKT_LEN     12          // 8B nagłówek echo + 4B magic
#define TR_TOTAL_BUDGET_MS 20000UL // twardy limit całego trace (nie blokuj pętli w nieskończoność)

static struct raw_pcb*   s_pcb     = nullptr;   // JEDEN, nigdy nie zamykany
static volatile bool     s_waiting = false;
static volatile uint16_t s_seq     = 0;
static volatile uint8_t  s_ttl     = 1;
static volatile uint32_t s_hop_ip  = 0;
static volatile bool     s_reached = false;
static volatile bool     s_got     = false;
static ip_addr_t         s_target;

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
    if (type == ICMP_TE) {                             // time exceeded: w środku NASZE echo?
        int inner = ihl + 8;                           // wewnętrzny nagłówek IP
        if (n < (u16_t)(inner + 20 + 8)) return 0;
        int iihl = (buf[inner] & 0x0F) * 4;
        if (n < (u16_t)(inner + iihl + 8)) return 0;
        uint8_t  itype = buf[inner + iihl];
        uint16_t iid   = ((uint16_t)buf[inner + iihl + 4] << 8) | buf[inner + iihl + 5];
        uint16_t iseq  = ((uint16_t)buf[inner + iihl + 6] << 8) | buf[inner + iihl + 7];
        if (itype != ICMP_ECHO || iid != TR_ID || iseq != s_seq) return 0;
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
    if (!host || !*host || max_hops < 1) return 0;
    if (!s_pcb) {
        traceroute_init();
        delay(50);                                     // daj tcpip czas na init
        if (!s_pcb) { Serial.println("[trace] brak pcb"); return 0; }
    }

    // Rozwiąż cel (IPv4)
    memset(&s_target, 0, sizeof(s_target));
    if (ipaddr_aton(host, &s_target) == 0) {
        IPAddress ip;
        if (!WiFi.hostByName(host, ip)) return 0;
        IP_ADDR4(&s_target, ip[0], ip[1], ip[2], ip[3]);
    }

    int n = 0;
    unsigned long t_start = millis();
    for (int ttl = 1; ttl <= max_hops && n < max_hops; ttl++) {
        if (millis() - t_start > TR_TOTAL_BUDGET_MS) break;
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
        if (s_got && s_reached) { *reached = true; break; }
        yield();
    }
    Serial.printf("[trace] %s: %d hopów, reached=%d, free=%u\n",
                  host, n, *reached, ESP.getFreeHeap());
    return n;
}
