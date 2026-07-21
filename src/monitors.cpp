/**
 * SENSMOS Firmware — R3 Directed Monitoring (spec: BE DOCS/dev/R3-DIRECTED-MONITORING.md)
 *
 * Node-heavy: deskryptor monitora przychodzi RAZ (monitor_set), node sam planuje
 * (interval_s + jitter), a POMIAR wykonuje net_worker ("wór", v0.39) — monitory
 * tylko kolejkują należne sondy (hi-prio) i przetwarzają wyniki (dispatch w loop):
 * histereza UP/DOWN, alerty na zmianie stanu, kompaktowe rollupy. Zero blokowania loop().
 * Monitory TYLKO w RAM — BE re-pushuje komplet na identify.
 */
#include "monitors.h"
#include "net_worker.h"
#include "checknet.h"
#include "config.h"
#include "log.h"
#include "ws_client.h"
#include "wifi_manager.h"
#include <WiFi.h>
#include <esp_random.h>
#include <time.h>

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
    bool     awaiting;       // sonda w kolejce/na workerze — nie kolejkuj drugiej
    unsigned long next_run;
    unsigned long rollup_at;
    unsigned long last_done_ms;   // poprzedni wynik — do q_lag (actual/target interval)
    uint16_t ok_cnt, fail_cnt;
    uint16_t ring[MONITORS_RING_MAX];   // udane rtt (ms, zaokrąglone) do percentyli rollupu
                                        // — float marnował 2B/próbkę × 40 × sloty (RAM-AUDIT 0.49)
    uint8_t  ring_n;
    uint8_t  burst_n;                   // 0.63: licznik burstów potwierdzeń w bieżącym epizodzie przejścia
    float    last_ms;
};

static MonCfg g_cfg[MONITORS_MAX_SLOTS];
static MonRun g_run[MONITORS_MAX_SLOTS];

// q_lag: EMA (actual/target) po wszystkich slotach. 1.0 = sondy chodzą na czas;
// rośnie gdy kolejka/backpressure rozciąga kadencję. 0 = jeszcze brak pomiarów.
static float g_qlag = 0;
float monitors_qlag() { return g_qlag; }
int monitors_count() {
    int n = 0;
    for (int i = 0; i < MONITORS_MAX_SLOTS; i++) if (g_cfg[i].id != 0) n++;
    return n;
}

// Pomiar (icmp/tcp/dns/http) wykonuje net_worker — patrz nw_probe_* / cn_probe_*.

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
    LOGI("mon", "#%ld %s %s (%.0fms)", (long)c.id, c.host,
         r.state == 1 ? "UP" : "DOWN", r.last_ms);
}

static int cmp_u16(const void* a, const void* b) {
    return (int)*(const uint16_t*)a - (int)*(const uint16_t*)b;
}

static void mon_send_rollup(int i) {
    MonCfg& c = g_cfg[i]; MonRun& r = g_run[i];
    if (r.ok_cnt + r.fail_cnt == 0) return;      // pusty bucket — nic
    float p50 = 0, p95 = 0;
    if (r.ring_n > 0) {
        static uint16_t tmp[MONITORS_RING_MAX];
        memcpy(tmp, r.ring, r.ring_n * sizeof(uint16_t));
        qsort(tmp, r.ring_n, sizeof(uint16_t), cmp_u16);
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

// ── STATUS (0.62): migawka poziomów wszystkich slotów — warstwa UZGADNIANIA ──
// Event (mon_send_alert) niesie ZMIANĘ natychmiast; status co 60s niesie POZIOM (już po
// histerezie) + wiek ostatniej sondy. Bez tego zgubiony event (WS padło w złej ms,
// restart BE, idempotentny re-push monitor_set) = BE kłamie do następnej zmiany stanu.
// Wpis: [id, state(-1/0/1), age_s(-1 = jeszcze bez sondy)].
static unsigned long g_status_at = 0;    // 0 = nieaktywny (żadnego seta jeszcze nie było)
static void mon_send_status() {
    static char buf[576];
    int n = snprintf(buf, sizeof(buf), "{\"type\":\"monitor_status\",\"m\":[");
    bool any = false;
    for (int i = 0; i < MONITORS_MAX_SLOTS; i++) {
        if (g_cfg[i].id == 0) continue;
        MonRun& r = g_run[i];
        long age = r.last_done_ms ? (long)((millis() - r.last_done_ms) / 1000UL) : -1;
        n += snprintf(buf + n, sizeof(buf) - n, "%s[%ld,%d,%ld]",
                      any ? "," : "", (long)g_cfg[i].id, (int)r.state, age);
        any = true;
        if (n >= (int)sizeof(buf) - 24) break;   // nie urwij JSON-a przy pełnych slotach
    }
    snprintf(buf + n, sizeof(buf) - n, "]}");
    if (any) ws_client_send_raw(buf);
}

// ── Zakolejkuj pomiar na worker (hi-prio). false = kolejka pełna ──
static bool mon_enqueue_probe(int i) {
    MonCfg& c = g_cfg[i]; MonRun& r = g_run[i];
    NetJob nj; memset(&nj, 0, sizeof(nj));
    nj.src = NW_MONITOR; nj.ref_id = c.id; nj.ref_idx = (int16_t)i;
    strlcpy(nj.job.kind, c.kind, sizeof(nj.job.kind));
    strlcpy(nj.job.host, c.host, sizeof(nj.job.host));
    nj.job.port = c.port;
    nj.job.count = 3;                            // icmp: 3 pakiety (jak dawniej)
    strlcpy(nj.job.path, c.path, sizeof(nj.job.path));
    strlcpy(nj.job.expected, c.expected, sizeof(nj.job.expected));
    nj.job.https    = (c.port == 80) ? 0 : 1;    // http: domyślnie https, chyba że jawnie :80
    nj.job.http_get = c.http_get;                // uptime = GET (domyślnie); HEAD gdy BE tak każe
    if (!net_worker_enqueue(nj, true)) return false;
    r.awaiting = true;
    return true;
}

// ── Zastosuj wynik sondy z workera (dispatch w loop) ──────────
void monitors_on_net_result(const NetResult& nr) {
    int i = nr.ref_idx;
    if (i < 0 || i >= MONITORS_MAX_SLOTS) return;
    MonCfg& c = g_cfg[i]; MonRun& r = g_run[i];
    if (c.id == 0 || c.id != nr.ref_id) return;  // slot zwolniony/przeładowany → wynik nieaktualny
    r.awaiting = false;

    // q_lag: rzeczywisty odstęp wyników vs interval (liczony też dla DEFER — kadencja
    // to kadencja). Clamp [0.2, 5]: reboot/reassign nie może rozstrzelić EMA.
    if (r.last_done_ms > 0 && c.interval_s > 0) {
        float lag = (float)(millis() - r.last_done_ms) / (float)(c.interval_s * 1000UL);
        if (lag < 0.2f) lag = 0.2f;
        if (lag > 5.0f) lag = 5.0f;
        g_qlag = (g_qlag == 0) ? lag : g_qlag * 0.8f + lag * 0.2f;
    }
    r.last_done_ms = millis();

    // http odłożony (za mały ciągły blok na TLS): NIE licz jako fail — retry w kolejnym cyklu.
    if (nr.deferred) {
        LOGD("mon", "#%ld http deferred — blk %u < %u", (long)c.id,
             (unsigned)nr.heap_largest, (unsigned)MONITORS_HTTP_MIN_HEAP);
        return;
    }

    CnResult res = nr.res;
    if (strcmp(c.kind, "dns") == 0 && res.ok && !res.match) res.ok = false;  // hijack = fail
    bool ok = res.ok && (c.max_ms == 0 || res.rtt_ms <= (float)c.max_ms);
    r.last_ms = res.rtt_ms;

    LOGD("mon", "#%ld %s %s ok=%d code=%d %.0fms", (long)c.id, c.kind, c.host,
         ok, res.status_code, res.rtt_ms);

    // akumulacja rollupu
    if (ok) { r.ok_cnt++; if (r.ring_n < MONITORS_RING_MAX) {
        float ms = res.rtt_ms; if (ms < 0) ms = 0; if (ms > 65535.0f) ms = 65535.0f;
        r.ring[r.ring_n++] = (uint16_t)(ms + 0.5f); } }
    else    { r.fail_cnt++; }

    // histereza + alert TYLKO na zmianie stanu (unknown→up też — BE musi znać stan przydziału)
    if (ok) { r.cok++; r.cfail = 0; } else { r.cfail++; r.cok = 0; }
    if (r.state != 0 && r.cfail >= c.fail_n) { r.state = 0; mon_send_alert(i); }
    else if (r.state != 1 && r.cok >= c.ok_n) { r.state = 1; mon_send_alert(i); }

    // BURST potwierdzeń (0.63): pewność = N obserwacji, NIE N interwałów. W trakcie przejścia
    // (histereza nierozstrzygnięta: pierwszy fail przy up, pierwszy OK przy down, świeży slot)
    // kolejna sonda za ~8s zamiast pełnego interwału → wykrycie ~interwał+16s zamiast 3×interwał.
    // Stan ustalony = kadencja bez zmian. Cap 6/epizod: flapujący cel nie zamieni monitora
    // w wieczną pętlę 8s (po capie wraca interwał, licznik startuje od nowa).
    bool mid = (r.state != 0 && r.cfail > 0 && r.cfail < c.fail_n) ||
               (r.state != 1 && r.cok   > 0 && r.cok   < c.ok_n);
    if (mid && r.burst_n < 6) {
        r.burst_n++;
        r.next_run = millis() + 8000 + (esp_random() % 2000);
    } else {
        r.burst_n = 0;
    }
}

// ── API ───────────────────────────────────────────────────────
void monitors_init() {
    memset(g_cfg, 0, sizeof(g_cfg));
    memset(g_run, 0, sizeof(g_run));
    LOGI("mon", "init (RAM-only, awaiting monitor_set from BE)");
}

void monitors_on_set(JsonObject m) {
    int32_t id = m["id"] | 0;
    if (id <= 0) return;
    int slot = -1;
    for (int i = 0; i < MONITORS_MAX_SLOTS; i++) if (g_cfg[i].id == id) { slot = i; break; }
    if (slot < 0) for (int i = 0; i < MONITORS_MAX_SLOTS; i++) if (g_cfg[i].id == 0) { slot = i; break; }
    if (slot < 0) { LOGW("mon", "no free slot for #%ld", (long)id); return; }

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
        if (tmp.interval_s < 30) tmp.interval_s = 30;   // 0.62: min 30s (test szybkich interwałów)
        if (tmp.rollup_s < 300)  tmp.rollup_s   = 300;
        if (tmp.fail_n < 1)      tmp.fail_n     = 1;
        if (tmp.ok_n < 1)        tmp.ok_n       = 1;
        if (memcmp(&tmp, &c, sizeof(MonCfg)) == 0) {
            LOGD("mon", "set #%ld — unchanged, counters kept", (long)id);
            // ODPOWIEDŹ mimo idempotencji: BE mógł właśnie odtworzyć przydział (re-push) i czeka
            // na stan — status za ~2s (debounce zbija serię setów w jedną migawkę)
            g_status_at = millis() + 2000;
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
    if (c.interval_s < 30)   c.interval_s = 30;      // sanity (0.62: min 30s)
    if (c.rollup_s < 300)    c.rollup_s   = 300;
    if (c.fail_n < 1)        c.fail_n     = 1;
    if (c.ok_n < 1)          c.ok_n       = 1;
    if (strlen(c.host) == 0) { c.id = 0; return; }

    mon_reset_run(slot);
    g_status_at = millis() + 2000;   // świeży/zmieniony slot: status za ~2s (state=-1, age=-1 = „czekam na sondę")
    LOGD("mon", "set #%ld %s %s every %lus", (long)id, c.kind, c.host, (unsigned long)c.interval_s);
}

void monitors_on_clear(int32_t id) {
    for (int i = 0; i < MONITORS_MAX_SLOTS; i++) {
        if (g_cfg[i].id != id) continue;
        g_cfg[i].id = 0;
        g_status_at = millis() + 2000;
        LOGD("mon", "clear #%ld", (long)id);
        return;
    }
}

void monitors_update() {
    if (!g_wifi_connected) return;

    // puls statusu: co 60s od pierwszego seta (+ szybkie strzały ~2s po set/clear)
    if (g_status_at != 0 && (long)(millis() - g_status_at) >= 0) {
        if (ws_client_connected()) mon_send_status();
        g_status_at = millis() + 60000UL;
    }

    for (int i = 0; i < MONITORS_MAX_SLOTS; i++) {
        MonCfg& c = g_cfg[i];
        if (c.id == 0) continue;
        MonRun& r = g_run[i];

        // rollup (niezależnie od pomiaru — tani)
        if ((long)(millis() - r.rollup_at) >= 0) {
            if (ws_client_connected()) mon_send_rollup(i);
            r.rollup_at = millis() + c.rollup_s * 1000UL;
        }

        // pomiar → worker (nie blokuje loop; worker serializuje 1 TLS naraz). Jeśli poprzednia
        // sonda tego slotu jeszcze wisi (awaiting) — pomiń cykl. Kolejka pełna → NIE przeplanuj
        // (backpressure): retry w kolejnym przebiegu, gdy worker zdejmie job.
        if ((long)(millis() - r.next_run) >= 0) {
            if (!r.awaiting && !mon_enqueue_probe(i)) continue;
            long jitter = (long)(esp_random() % (c.interval_s * 100UL)) - (long)(c.interval_s * 50UL); // ±5%
            r.next_run = millis() + c.interval_s * 1000UL + jitter;
        }
    }
}
