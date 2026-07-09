#include "punch.h"
#include "net_worker.h"
#include "ws_client.h"
#include "log.h"
#include <WiFi.h>
#include <WiFiUdp.h>

#define PUNCH_LOCAL_PORT 47777   // stały lokalny port = jedno mapowanie NAT (STUN i punch)

// JEDEN statyczny socket UDP: STUN otwiera mapowanie w NAT, punch musi wyjść z TEGO
// SAMEGO portu — inaczej NAT peera nie skojarzy flow i pakiety zginą.
static WiFiUDP g_udp;
static bool    g_bound = false;

// Gate: między STUN a punch wór nie może utknąć w 30s trace z lo-kolejki —
// okno czasowe punch (BE ~4s po STUN) by przepadło.
static volatile unsigned long g_gate_until = 0;
bool punch_gate_active() { return (long)(g_gate_until - millis()) > 0; }

// Sesja (max 1 naraz — BE paruje node raz na rundę): metadane do raportu
static struct { char host[64]; char to_region[8]; char to_lat[16]; char to_lon[16]; } g_sess;

static void geo_field(JsonDocument& doc, const char* key, char* out, size_t outlen) {
    if (doc[key].is<const char*>()) strlcpy(out, doc[key] | "", outlen);
    else { float v = doc[key] | 0.0f; snprintf(out, outlen, "%.6f", v); }
}

// ── WS → joby na wór (hi: punch jest sterowany zegarem BE, nie może czekać za trace) ──
void punch_on_stun(JsonDocument& doc) {
    NetJob nj; memset(&nj, 0, sizeof(nj));
    nj.src = NW_PUNCH; nj.ref_id = 1;
    strlcpy(nj.job.kind, "stun", sizeof(nj.job.kind));
    strlcpy(nj.job.host, doc["host"] | "", sizeof(nj.job.host));
    nj.job.port = doc["port"] | 0;
    strlcpy(nj.job.path, doc["token"] | "", sizeof(nj.job.path));
    if (!nj.job.host[0] || !nj.job.port || !nj.job.path[0]) return;
    if (!net_worker_enqueue(nj, true)) LOGW("punch", "stun enqueue failed (queue full)");
}

void punch_on_punch(JsonDocument& doc) {
    memset(&g_sess, 0, sizeof(g_sess));
    strlcpy(g_sess.host,      doc["host"]      | "",    sizeof(g_sess.host));
    strlcpy(g_sess.to_region, doc["to_region"] | "ANY", sizeof(g_sess.to_region));
    geo_field(doc, "to_lat", g_sess.to_lat, sizeof(g_sess.to_lat));
    geo_field(doc, "to_lon", g_sess.to_lon, sizeof(g_sess.to_lon));

    NetJob nj; memset(&nj, 0, sizeof(nj));
    nj.src = NW_PUNCH; nj.ref_id = 2;
    strlcpy(nj.job.kind, "punch", sizeof(nj.job.kind));
    strlcpy(nj.url, doc["ip"] | "", sizeof(nj.url));           // endpoint z STUN (cel spray)
    nj.job.port = doc["port"] | 0;
    strlcpy(nj.job.path,     doc["token"]      | "", sizeof(nj.job.path));      // własny token
    strlcpy(nj.job.expected, doc["peer_token"] | "", sizeof(nj.job.expected));  // token peera
    nj.job.timeout_ms = doc["dur_ms"] | 4000;
    strlcpy(nj.job.host, g_sess.host, sizeof(nj.job.host));
    if (!nj.url[0] || !nj.job.port) return;
    if (!net_worker_enqueue(nj, true)) LOGW("punch", "punch enqueue failed (queue full)");
}

// ── Executory (kontekst wora — wolno blokować) ────────────────────────────────
void punch_exec_stun(const NetJob& j, NetResult& out) {
    CnResult& r = out.res; r.ok = false; r.loss_pct = 100;
    if (!g_bound) g_bound = g_udp.begin(PUNCH_LOCAL_PORT) != 0;
    if (!g_bound) { LOGW("punch", "udp bind failed"); return; }
    IPAddress ip;
    if (!WiFi.hostByName(j.job.host, ip)) return;

    char buf[64];
    snprintf(buf, sizeof(buf), "SM1 %s", j.job.path);
    for (int att = 0; att < 4 && !r.ok; att++) {
        unsigned long t0 = millis();
        g_udp.beginPacket(ip, (uint16_t)j.job.port);
        g_udp.write((const uint8_t*)buf, strlen(buf));
        g_udp.endPacket();
        while (millis() - t0 < 500) {
            if (g_udp.parsePacket() > 0) {
                char rb[64]; int n = g_udp.read(rb, sizeof(rb) - 1); rb[n > 0 ? n : 0] = 0;
                if (strstr(rb, j.job.path) && strstr(rb, "OK")) {
                    r.ok = true; r.rtt_ms = (float)(millis() - t0); r.loss_pct = 0;
                    break;
                }
            }
            delay(5);
        }
    }
    if (r.ok) g_gate_until = millis() + 10000;   // trzymaj lo-joby z dala do przyjścia punch
}

void punch_exec_punch(const NetJob& j, NetResult& out) {
    CnResult& r = out.res; r.ok = false; r.loss_pct = 100;
    g_gate_until = 0;
    if (!g_bound) return;                        // bez STUN nie ma mapowania — nie strzelaj
    IPAddress tgt;
    if (!tgt.fromString(j.url)) return;
    const char* tok  = j.job.path;
    const char* ptok = j.job.expected;
    uint32_t dur = j.job.timeout_ms > 0 ? (uint32_t)j.job.timeout_ms : 4000;

    const int MAXS = 8;
    float rtts[MAXS]; int got = 0;
    uint8_t seq = 0;
    bool contact = false;                        // pierwszy pakiet OD peera = dziura otwarta
    int sent_after = 0;                          // loss liczony dopiero PO otwarciu dziury
    unsigned long t_end = millis() + dur, t_probe = 0;
    char buf[96];

    while ((long)(t_end - millis()) > 0) {
        unsigned long now = millis();
        if (now - t_probe >= 300) {              // probe/echo-req co 300ms
            t_probe = now;
            snprintf(buf, sizeof(buf), "SP1 %s %u %lu", tok, (unsigned)seq, (unsigned long)now);
            g_udp.beginPacket(tgt, (uint16_t)j.job.port);
            g_udp.write((const uint8_t*)buf, strlen(buf));
            g_udp.endPacket();
            seq++;
            if (contact) sent_after++;
        }
        if (g_udp.parsePacket() > 0) {
            char rb[96]; int n = g_udp.read(rb, sizeof(rb) - 1); rb[n > 0 ? n : 0] = 0;
            char rtok[40]; unsigned rseq; unsigned long rt;
            if (sscanf(rb, "SP1 %39s %u %lu", rtok, &rseq, &rt) == 3 && !strcmp(rtok, ptok)) {
                contact = true;                  // probe peera → odbij echo (jego token/seq/czas)
                snprintf(buf, sizeof(buf), "SP2 %s %u %lu", rtok, rseq, rt);
                g_udp.beginPacket(g_udp.remoteIP(), g_udp.remotePort());
                g_udp.write((const uint8_t*)buf, strlen(buf));
                g_udp.endPacket();
            } else if (sscanf(rb, "SP2 %39s %u %lu", rtok, &rseq, &rt) == 3 && !strcmp(rtok, tok)) {
                contact = true;                  // echo naszego probe → próbka RTT
                if (got < MAXS) rtts[got++] = (float)(millis() - rt);
            }
        }
        delay(5);
    }
    if (!got) { LOGI("punch", "%s: no exchange (CGNAT/symmetric NAT?)", j.job.host); return; }

    float sum = 0; for (int i = 0; i < got; i++) sum += rtts[i];
    r.rtt_ms = sum / got;
    float jd = 0; for (int i = 1; i < got; i++) jd += fabsf(rtts[i] - rtts[i - 1]);
    r.jitter_ms = got > 1 ? jd / (got - 1) : 0;
    r.samples = got;
    r.loss_pct = sent_after > 0 ? (float)(sent_after - got) * 100.0f / sent_after : 0;
    if (r.loss_pct < 0) r.loss_pct = 0;
    r.ok = true;
}

// ── Wynik z wora → raport WS (loop, single-writer) ────────────────────────────
void punch_on_net_result(const NetResult& nr) {
    if (nr.ref_id == 1) {                        // STUN: nic nie raportujemy (BE widzi pakiet)
        LOGD("punch", "stun ok=%d rtt=%.0fms", nr.res.ok, nr.res.rtt_ms);
        return;
    }
    const CnResult& r = nr.res;
    static char buf[512];
    int n = snprintf(buf, sizeof(buf),
        "{\"type\":\"check_result\",\"results\":[{\"id\":0,\"kind\":\"punch\",\"host\":\"%s\","
        "\"target_kind\":\"peer\",\"to_region\":\"%s\",\"to_lat\":\"%s\",\"to_lon\":\"%s\","
        "\"ok\":%s,\"loss_pct\":%.1f,\"samples\":%d",
        g_sess.host, g_sess.to_region, g_sess.to_lat, g_sess.to_lon,
        r.ok ? "true" : "false", r.loss_pct, r.samples);
    if (r.ok) n += snprintf(buf + n, sizeof(buf) - n, ",\"rtt_ms\":%.1f,\"jitter_ms\":%.1f",
                            r.rtt_ms, r.jitter_ms);
    n += snprintf(buf + n, sizeof(buf) - n, "}]}");
    if (n < (int)sizeof(buf)) ws_client_send_raw(buf);
    LOGI("punch", "%s ok=%d rtt=%.0fms n=%d loss=%.0f%%",
         g_sess.host, r.ok, r.rtt_ms, r.samples, r.loss_pct);
}
