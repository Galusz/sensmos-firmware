#include "rdns.h"
#include "log.h"
#include <WiFi.h>
#include <WiFiUdp.h>

// Parsuj nazwę DNS (etykiety + kompresja RFC1035) z odpowiedzi → out ("a.b.c").
static bool dns_read_name(const uint8_t* pkt, int len, int pos, char* out, size_t outlen) {
    size_t o = 0; int guard = 0;
    while (pos < len && guard++ < 40) {
        uint8_t l = pkt[pos];
        if (l == 0) break;
        if ((l & 0xC0) == 0xC0) {                       // wskaźnik kompresji
            if (pos + 1 >= len) return false;
            pos = ((l & 0x3F) << 8) | pkt[pos + 1];
            continue;
        }
        if (pos + 1 + l > len || o + l + 2 >= outlen) return false;
        if (o) out[o++] = '.';
        memcpy(out + o, pkt + pos + 1, l); o += l;
        pos += l + 1;
    }
    out[o] = 0;
    return o > 0;
}

bool rdns_ptr(uint32_t ip_netorder, char* out, size_t outlen, uint32_t timeout_ms) {
    if (!out || outlen < 8) return false;
    out[0] = 0;
    IPAddress dns = WiFi.dnsIP();
    if (dns == IPAddress((uint32_t)0)) return false;

    uint8_t a =  ip_netorder        & 0xFF, b = (ip_netorder >> 8)  & 0xFF,
            c = (ip_netorder >> 16) & 0xFF, d = (ip_netorder >> 24) & 0xFF;
    char qname[40];
    snprintf(qname, sizeof(qname), "%u.%u.%u.%u.in-addr.arpa", d, c, b, a);

    // Zapytanie: nagłówek(12) + QNAME + QTYPE=PTR + QCLASS=IN
    uint8_t pkt[64]; size_t n = 0;
    uint16_t id = (uint16_t)esp_random();
    pkt[n++] = id >> 8; pkt[n++] = id & 0xFF;
    pkt[n++] = 0x01; pkt[n++] = 0x00;                   // RD=1
    pkt[n++] = 0; pkt[n++] = 1;                         // QDCOUNT=1
    for (int i = 0; i < 6; i++) pkt[n++] = 0;           // AN/NS/AR=0
    const char* p = qname;
    while (*p) {
        const char* dot = strchr(p, '.');
        size_t l = dot ? (size_t)(dot - p) : strlen(p);
        pkt[n++] = (uint8_t)l; memcpy(pkt + n, p, l); n += l;
        p += l + (dot ? 1 : 0);
    }
    pkt[n++] = 0;
    pkt[n++] = 0; pkt[n++] = 12;                        // QTYPE=PTR
    pkt[n++] = 0; pkt[n++] = 1;                         // QCLASS=IN

    WiFiUDP udp;
    if (!udp.begin(0)) return false;
    udp.beginPacket(dns, 53); udp.write(pkt, n); udp.endPacket();

    unsigned long t0 = millis();
    while (millis() - t0 < timeout_ms) {
        int sz = udp.parsePacket();
        if (sz > 0) {
            uint8_t rb[320];
            int rn = udp.read(rb, sizeof(rb));
            udp.stop();
            if (rn < 12 || rb[0] != (id >> 8) || rb[1] != (id & 0xFF)) return false;
            if ((rb[3] & 0x0F) != 0) return false;      // RCODE != 0 (NXDOMAIN itp.)
            uint16_t ancount = (rb[6] << 8) | rb[7];
            if (!ancount) return false;
            int i = 12;                                  // pomiń pytanie: QNAME + 4B
            while (i < rn && rb[i]) {
                if ((rb[i] & 0xC0) == 0xC0) { i++; break; }
                i += rb[i] + 1;
            }
            i += 5;
            for (uint16_t rec = 0; rec < ancount && i < rn; rec++) {
                if ((rb[i] & 0xC0) == 0xC0) i += 2;      // NAME rekordu
                else { while (i < rn && rb[i]) i += rb[i] + 1; i++; }
                if (i + 10 > rn) return false;
                uint16_t type  = (rb[i] << 8) | rb[i + 1];
                uint16_t rdlen = (rb[i + 8] << 8) | rb[i + 9];
                i += 10;
                if (type == 12) return dns_read_name(rb, rn, i, out, outlen);
                i += rdlen;                              // CNAME itp. — pomiń
            }
            return false;
        }
        delay(10);
    }
    udp.stop();
    return false;
}
