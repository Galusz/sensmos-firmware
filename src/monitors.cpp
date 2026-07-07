/**
 * SENSMOS Firmware — R3 Directed Monitoring (spec: BE DOCS/dev/R3-DIRECTED-MONITORING.md)
 *
 * Node-heavy: deskryptor monitora przychodzi RAZ (monitor_set), node sam planuje
 * (interval_s + jitter), mierzy (REUSE executorów checknet R2: tcp/dns/http; własny
 * blocking icmp), trzyma histerezę UP/DOWN i wysyła tylko ZMIANY STANU + rollupy.
 * Jeden blocking probe per update; gdy checknet mierzy — odraczamy (checknet_busy).
 * Monitory TYLKO w RAM — BE re-pushuje komplet na identify (NVS-persist usunięty).
 */
#include "monitors.h"
#include "checknet.h"
#include "config.h"
#include "ws_client.h"
#include "wifi_manager.h"
#include <WiFi.h>
#include <esp_random.h>
#include <time.h>
#include "ping/ping_sock.h"
#include "lwip/ip_addr.h"

// ── Deskryptor (RAM) + runtime ────────────────────────────────
struct MonCfg {
    int32_t  id;             // 0 = slot wolny
    char     kind[6];        // icmp|tcp|dns|http
    char     host[64];
    uint16_t port;
    char     path[48];
    char     expected[48];
    uint32_t interval_s;
    uint32_t rollup_s;
    uint8_t  fail_n, ok_n;
    uint16_t max_ms;         // 0 = bez progu latencji
    uint8_t  http_get;       // http: 1=GET (domyślnie, uptime), 0=HEAD
};
struct MonRun {
    int8_t   state;          // -1 unknown, 0 down, 1 up
    uint8_t  cfail, cok;     // liczniki histerezy
    unsigned long next_run;
    unsigned long rollup_at;
    uint16_t ok_cnt, fail_cnt;
    float    ring[MONITORS_RING_MAX];   // udane rtt do percentyli rollupu
    uint8_t  ring_n;
    float    last_ms;
};

static MonCfg g_cfg[MONITORS_MAX_SLOTS];
static MonRun g_run[MONITORS_MAX_SLOTS];

// ── ICMP blocking (własne akumulatory — nie kolidują z sesją checknet) ──
static volatile int   m_recv = 0;
static volatile float m_sum  = 0;
static volatile bool  m_done = false;
static void m_on_ok(esp_ping_handle_t h, void*)  {
    uint32_t el = 0; esp_ping_get_profile(h, ESP_PING_PROF_TIMEGAP, &el, sizeof(el));
    m_recv++; m_sum += (float)el;
}
static void m_on_to(esp_ping_handle_t, void*)  {}
static void m_on_end(esp_ping_handle_t, void*) { m_done = true; }

static void mon_probe_icmp(MonCfg& c, CnResult& r) {
    ip_addr_t target; memset(&target, 0, sizeof(target));
    if (ipaddr_aton(c.host, &target) == 0) {
        IPAddress ip;
        if (!WiFi.hostByName(c.host, ip)) { r.ok = false; return; }
        IP_ADDR4(&target, ip[0], ip[1], ip[2], ip[3]);
    }
    m_recv = 0; m_sum = 0; m_done = false;
    esp_ping_config_t cfg = ESP_PING_DEFAULT_CONFIG();
    cfg.target_addr = target;
    cfg.count       = 3;
    cfg.timeout_ms  = CHECKNET_PING_TIMEOUT_MS;
    cfg.interval_ms = CHECKNET_PING_INTERVAL_MS;
    cfg.task_stack_size = 2560;
    esp_ping_callbacks_t cbs = {};
    cbs.on_ping_success = m_on_ok; cbs.on_ping_timeout = m_on_to; cbs.on_ping_end = m_on_end;
    esp_ping_handle_t s = nullptr;
    if (esp_ping_new_session(&cfg, &cbs, &s) != ESP_OK || !s) { r.ok = false; return; }
    esp_ping_start(s);
    unsigned long t0 = millis();
    while (!m_done && millis() - t0 < 3UL * (CHECKNET_PING_TIMEOUT_MS + CHECKNET_PING_INTERVAL_MS) + 500) delay(20);
    esp_ping_stop(s); esp_ping_delete_session(s);
    r.ok = m_recv > 0;
    r.rtt_ms = m_recv > 0 ? m_sum / m_recv : 0;
}

// Monitory TYLKO w RAM — BE re-pushuje komplet na identify (1.5s po połączeniu),
// więc NVS-persist był zbędny (offline i tak nie wyśle alertu) i psuł się przy
// każdej zmianie rozmiaru struktury (blob-mismatch → "0 monitorów z NVS").

static void mon_reset_run(int i) {
    MonRun& r = g_run[i];
    memset(&r, 0, sizeof(r));
    r.state = -1;
    // start szybko, z rozrzutem (anty-stampede po reboot/re-push)
    r.next_run  = millis() + 3000 + (esp_random() % 10000);
    r.rollup_at = millis() + g_cfg[i].rollup_s * 1000UL;
}

// ── Wysyłki ───────────────────────────────────────────────────
static void mon_send_alert(int i) {
    MonCfg& c = g_cfg[i]; MonRun& r = g_run[i];
    char buf[160];
    snprintf(buf, sizeof(buf),
        "{\"type\":\"monitor_alert\",\"id\":%ld,\"state\":\"%s\",\"last_ms\":%.1f,\"fails\":%d}",
        (long)c.id, r.state == 1 ? "up" : "down", r.last_ms, r.cfail);
    ws_client_send_raw(buf);
    Serial.printf("[monitors] #%ld %s -> %s (last=%.1fms)\n",
                  (long)c.id, c.host, r.state == 1 ? "UP" : "DOWN", r.last_ms);
}

static int cmp_float(const void* a, const void* b) {
    float d = *(const float*)a - *(const float*)b;
    return d < 0 ? -1 : d > 0 ? 1 : 0;
}

static void mon_send_rollup(int i) {
    MonCfg& c = g_cfg[i]; MonRun& r = g_run[i];
    if (r.ok_cnt + r.fail_cnt == 0) return;      // pusty bucket — nic
    float p50 = 0, p95 = 0;
    if (r.ring_n > 0) {
        static float tmp[MONITORS_RING_MAX];
        memcpy(tmp, r.ring, r.ring_n * sizeof(float));
        qsort(tmp, r.ring_n, sizeof(float), cmp_float);
        p50 = tmp[r.ring_n / 2];
        int i95 = (int)(r.ring_n * 0.95f); if (i95 >= r.ring_n) i95 = r.ring_n - 1;
        p95 = tmp[i95];
    }
    time_t now = time(nullptr);
    unsigned long bucket = now > 1000000000 ? (unsigned long)now : 0;   // 0 → BE bierze NOW()
    char buf[220];
    snprintf(buf, sizeof(buf),
        "{\"type\":\"monitor_report\",\"id\":%ld,\"bucket\":%lu,\"ok\":%u,\"fail\":%u,"
        "\"p50\":%.1f,\"p95\":%.1f,\"ttfb_p50\":%.1f,\"samples\":%u}",
        (long)c.id, bucket, r.ok_cnt, r.fail_cnt, p50, p95,
        strcmp(c.kind, "http") == 0 ? p50 : 0.0f, (unsigned)(r.ok_cnt + r.fail_cnt));
    ws_client_send_raw(buf);
    r.ok_cnt = 0; r.fail_cnt = 0; r.ring_n = 0;
}

// ── Pomiar jednego monitora ───────────────────────────────────
static void mon_run_probe(int i) {
    MonCfg& c = g_cfg[i]; MonRun& r = g_run[i];

    // http = TLS = potrzebuje ~45KB CIĄGŁEGO bloku. Przy fragmentacji odpuść ten cykl
    // (NIE licz jako fail — inaczej fałszywe DOWN z braku pamięci), spróbuj w kolejnym.
    if (strcmp(c.kind, "http") == 0 && ESP.getMaxAllocHeap() < MONITORS_HTTP_MIN_HEAP) {
        Serial.printf("[monitors] probe #%ld http DEFER — largest=%u < %u (za mało na TLS)\n",
                      (long)c.id, ESP.getMaxAllocHeap(), (unsigned)MONITORS_HTTP_MIN_HEAP);
        return;
    }

    CnResult res; memset(&res, 0, sizeof(res));

    if (strcmp(c.kind, "icmp") == 0) {
        mon_probe_icmp(c, res);
    } else {
        CnJob j; memset(&j, 0, sizeof(j));
        strlcpy(j.kind, c.kind, sizeof(j.kind));
        strlcpy(j.host, c.host, sizeof(j.host));
        j.port = c.port;
        strlcpy(j.path, c.path, sizeof(j.path));
        strlcpy(j.expected, c.expected, sizeof(j.expected));
        j.https    = (c.port == 80) ? 0 : 1;     // http: domyślnie https, chyba że jawnie :80
        j.http_get = c.http_get;                 // monitoring uptime = GET (domyślnie); HEAD gdy BE tak każe
        if      (strcmp(c.kind, "tcp")  == 0) cn_probe_tcp(j, res);
        else if (strcmp(c.kind, "dns")  == 0) cn_probe_dns(j, res);
        else if (strcmp(c.kind, "http") == 0) cn_probe_http(j, res);
        else return;
        if (strcmp(c.kind, "dns") == 0 && res.ok && !res.match) res.ok = false;  // hijack = fail
    }

    bool ok = res.ok && (c.max_ms == 0 || res.rtt_ms <= (float)c.max_ms);
    r.last_ms = res.rtt_ms;

    Serial.printf("[monitors] probe #%ld %s %s -> ok=%d code=%d ms=%.1f free=%u largest=%u\n",
                  (long)c.id, c.kind, c.host, ok, res.status_code, res.rtt_ms,
                  ESP.getFreeHeap(), ESP.getMaxAllocHeap());

    // akumulacja rollupu
    if (ok) { r.ok_cnt++; if (r.ring_n < MONITORS_RING_MAX) r.ring[r.ring_n++] = res.rtt_ms; }
    else    { r.fail_cnt++; }

    // histereza + alert TYLKO na zmianie stanu (unknown→up też — BE musi znać stan przydziału)
    if (ok) { r.cok++; r.cfail = 0; } else { r.cfail++; r.cok = 0; }
    if (r.state != 0 && r.cfail >= c.fail_n) { r.state = 0; mon_send_alert(i); }
    else if (r.state != 1 && r.cok >= c.ok_n) { r.state = 1; mon_send_alert(i); }
}

// ── API ───────────────────────────────────────────────────────
void monitors_init() {
    memset(g_cfg, 0, sizeof(g_cfg));
    memset(g_run, 0, sizeof(g_run));
    Serial.println("[monitors] init: RAM-only — czekam na monitor_set z BE (identify)");
}

void monitors_on_set(JsonObject m) {
    int32_t id = m["id"] | 0;
    if (id <= 0) return;
    int slot = -1;
    for (int i = 0; i < MONITORS_MAX_SLOTS; i++) if (g_cfg[i].id == id) { slot = i; break; }
    if (slot < 0) for (int i = 0; i < MONITORS_MAX_SLOTS; i++) if (g_cfg[i].id == 0) { slot = i; break; }
    if (slot < 0) { Serial.printf("[monitors] brak slotu dla #%ld\n", (long)id); return; }

    MonCfg& c = g_cfg[slot];
    // Idempotencja (v0.37): identyczny config -> NIE resetuj ringa/licznikow.
    // Re-push z BE (watchdog/reconnect) z tym samym configiem nie moze kasowac
    // dojrzewajacego rollupu (churn = plaski wykres po stronie BE).
    if (c.id == id) {
        MonCfg tmp; memset(&tmp, 0, sizeof(tmp));
        tmp.id = id;
        strlcpy(tmp.kind,     m["kind"]     | "icmp", sizeof(tmp.kind));
        strlcpy(tmp.host,     m["host"]     | "",     sizeof(tmp.host));
        strlcpy(tmp.path,     m["path"]     | "",     sizeof(tmp.path));
        strlcpy(tmp.expected, m["expected"] | "",     sizeof(tmp.expected));
        tmp.port       = m["port"]       | 0;
        tmp.interval_s = m["interval_s"] | 300;
        tmp.rollup_s   = m["rollup_s"]   | 3600;
        tmp.fail_n     = m["fail_n"]     | 3;
        tmp.ok_n       = m["ok_n"]       | 2;
        tmp.max_ms     = m["max_ms"]     | 0;
        tmp.http_get   = (strcmp(m["method"] | "GET", "HEAD") == 0) ? 0 : 1;
        if (tmp.interval_s < 60) tmp.interval_s = 60;
        if (tmp.rollup_s < 300)  tmp.rollup_s   = 300;
        if (tmp.fail_n < 1)      tmp.fail_n     = 1;
        if (tmp.ok_n < 1)        tmp.ok_n       = 1;
        if (memcmp(&tmp, &c, sizeof(MonCfg)) == 0) {
            Serial.printf("[monitors] set #%ld — bez zmian, licznik zachowany\n", (long)id);
            return;
        }
    }
    memset(&c, 0, sizeof(c));
    c.id = id;
    strlcpy(c.kind,     m["kind"]     | "icmp", sizeof(c.kind));
    strlcpy(c.host,     m["host"]     | "",     sizeof(c.host));
    strlcpy(c.path,     m["path"]     | "",     sizeof(c.path));
    strlcpy(c.expected, m["expected"] | "",     sizeof(c.expected));
    c.port       = m["port"]       | 0;
    c.interval_s = m["interval_s"] | 300;
    c.rollup_s   = m["rollup_s"]   | 3600;
    c.fail_n     = m["fail_n"]     | 3;
    c.ok_n       = m["ok_n"]       | 2;
    c.max_ms     = m["max_ms"]     | 0;
    c.http_get   = (strcmp(m["method"] | "GET", "HEAD") == 0) ? 0 : 1;   // domyślnie GET (uptime)
    if (c.interval_s < 60)   c.interval_s = 60;      // sanity
    if (c.rollup_s < 300)    c.rollup_s   = 300;
    if (c.fail_n < 1)        c.fail_n     = 1;
    if (c.ok_n < 1)          c.ok_n       = 1;
    if (strlen(c.host) == 0) { c.id = 0; return; }

    mon_reset_run(slot);
    Serial.printf("[monitors] set #%ld %s %s co %lus (rollup %lus)\n",
                  (long)id, c.kind, c.host, (unsigned long)c.interval_s, (unsigned long)c.rollup_s);
}

void monitors_on_clear(int32_t id) {
    for (int i = 0; i < MONITORS_MAX_SLOTS; i++) {
        if (g_cfg[i].id != id) continue;
        g_cfg[i].id = 0;
        Serial.printf("[monitors] clear #%ld\n", (long)id);
        return;
    }
}

void monitors_update() {
    if (!g_wifi_connected) return;
    if (checknet_busy()) return;             // jeden blocking probe/przebieg — checknet ma priorytet

    for (int i = 0; i < MONITORS_MAX_SLOTS; i++) {
        MonCfg& c = g_cfg[i];
        if (c.id == 0) continue;
        MonRun& r = g_run[i];

        // rollup (niezależnie od pomiaru — tani)
        if ((long)(millis() - r.rollup_at) >= 0) {
            if (ws_client_connected()) mon_send_rollup(i);
            r.rollup_at = millis() + c.rollup_s * 1000UL;
        }

        // pomiar — max JEDEN na przebieg loop()
        if ((long)(millis() - r.next_run) >= 0) {
            long jitter = (long)(esp_random() % (c.interval_s * 100UL)) - (long)(c.interval_s * 50UL); // ±5%
            r.next_run = millis() + c.interval_s * 1000UL + jitter;
            mon_run_probe(i);
            return;                          // yield — kolejne sloty w następnych przebiegach
        }
    }
}
