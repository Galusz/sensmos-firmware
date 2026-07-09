/**
 * SENSMOS Firmware — checknet
 * Pomiary jakości internetu przydzielane dynamicznie przez BE (WS).
 * v0.39: cała praca sieciowa (icmp/tcp/dns/http/trace) idzie na net_worker ("wór") —
 *   checknet tylko kolejkuje joby (lo-prio) i zbiera wyniki (dispatch w loop). Zero
 *   blokowania loop(); worker serializuje sondy (max 1 TLS naraz). Autonomiczny trace
 *   (peer 100% loss) dokolejkowany po wyniku icmp — max 1/cykl, z cooldownem.
 */
#include "checknet.h"
#include "net_worker.h"
#include "config.h"
#include "data_sender.h"   // g_tx_scratch (współdzielony bufor TX)
#include "log.h"
#include "ws_client.h"
#include "wifi_manager.h"
#include "entity_store.h"
#include "http_internal.h"
#include <WiFi.h>
#include <HTTPClient.h>
#include <WiFiClientSecure.h>
#include <math.h>
#include <Preferences.h>
#include <esp_random.h>
#include "traceroute.h"

// CnJob/CnResult — definicje w checknet.h (współdzielone z net_worker.cpp/monitors.cpp)

static CnJob    g_jobs[CHECKNET_MAX_JOBS];
static CnResult g_res[CHECKNET_MAX_JOBS];
static int      g_jobCount = 0;
// trace: wynik w statycznych buforach (BE dostaje hopy), doklejany do joba źródłowego
static TrHop    g_tr_hops[TR_MAX_HOPS];
static int      g_tr_n = 0;
static bool     g_tr_reached = false;
static int      g_tr_job = -1;
static bool     g_tr_launched = false;   // max 1 autonomiczny trace / cykl
static char     g_tr_lh_host[80] = "";   // rDNS last-hopa (z workera) — do geo_ok + raportu
// Cooldown trace (rolling): swiezo trace'owany cel nie jest re-trace'owany przez
// TRACE_COOLDOWN_MS — martwy peer wracajacy w jobach co cykl nie mloci traceroutem.
static struct { char host[46]; unsigned long until; } g_tr_cd[TRACE_COOLDOWN_SLOTS];
static int g_tr_cd_idx = 0;
static bool tr_cd_ok(const char* host) {
    for (int i = 0; i < TRACE_COOLDOWN_SLOTS; i++)
        if (g_tr_cd[i].host[0] && !strcmp(g_tr_cd[i].host, host) && (long)(g_tr_cd[i].until - millis()) > 0)
            return false;
    return true;
}
static void tr_cd_add(const char* host) {
    strlcpy(g_tr_cd[g_tr_cd_idx].host, host, sizeof(g_tr_cd[0].host));
    g_tr_cd[g_tr_cd_idx].until = millis() + TRACE_COOLDOWN_MS;
    g_tr_cd_idx = (g_tr_cd_idx + 1) % TRACE_COOLDOWN_SLOTS;
}

enum CnState { CN_IDLE, CN_WAIT, CN_COLLECT };
static CnState  g_state = CN_IDLE;
static unsigned long g_waitStart = 0;
static unsigned long g_collectStart = 0;
static int      g_outstanding = 0;       // ile wyników cyklu jeszcze czekamy

// rolling EMA (alpha 0.3) — node sam liczy swoje encje pub.net_* (TYLKO z icmp)
// net_ping = do wszystkiego (anycast+peery); node_ping = tylko do innych nodów (P2P)
static float g_ema_ping = NAN, g_ema_jit = NAN, g_ema_loss = NAN, g_ema_node = NAN;

// ── Config samonapędu (rdzeń, nie skrypt) — nadpisywana przez BE (cn_config), persist NVS ──
// trace_cd_ms: globalny cooldown trace per NODE (nie per cel) — kilka głuchych peerów
// w cyklu nie młóci traceroutami; BE steruje (trace_cd_s), default 5 min.
struct CnConfig { bool enabled; uint32_t interval_ms; uint8_t max_jobs; uint8_t ping_count; uint32_t trace_cd_ms; };
static CnConfig g_cfg = {
    CHECKNET_ENABLED_DEFAULT, CHECKNET_INTERVAL_MS_DEFAULT, CHECKNET_MAX_JOBS, CHECKNET_PING_COUNT, 300000UL
};
static unsigned long g_nextRun = 0;
static unsigned long g_tr_next = 0;      // najbliższy dozwolony autonomiczny trace (globalny CD)

static void cn_load_config() {
    Preferences p; p.begin("sensmos_cn", true);
    g_cfg.enabled     = p.getBool ("en", CHECKNET_ENABLED_DEFAULT);
    g_cfg.interval_ms = p.getULong("iv", CHECKNET_INTERVAL_MS_DEFAULT);
    g_cfg.max_jobs    = p.getUChar("mj", CHECKNET_MAX_JOBS);
    g_cfg.ping_count  = p.getUChar("pc", CHECKNET_PING_COUNT);
    g_cfg.trace_cd_ms = p.getULong("tcd", 300000UL);
    p.end();
    if (g_cfg.trace_cd_ms < 60000UL) g_cfg.trace_cd_ms = 60000UL;   // sanity: min 1 min
    if (g_cfg.max_jobs > CHECKNET_MAX_JOBS) g_cfg.max_jobs = CHECKNET_MAX_JOBS;
    if (g_cfg.max_jobs < 1)                 g_cfg.max_jobs = 1;
    if (g_cfg.ping_count < 1)               g_cfg.ping_count = 1;
    if (g_cfg.interval_ms < 10000UL)        g_cfg.interval_ms = 10000UL;   // sanity: min 10s
}

static void cn_schedule_next() {
    long jitter = (long)(esp_random() % (2UL * CHECKNET_JITTER_MS)) - (long)CHECKNET_JITTER_MS;
    g_nextRun = millis() + g_cfg.interval_ms + jitter;
}

// ── Egzekutory blokujące (tcp/dns/http) — wołane z net_worker (i skryptów) ────
void cn_probe_tcp(CnJob& j, CnResult& r) {
    if (j.port <= 0) { r.ok = false; r.loss_pct = 100; return; }
    WiFiClient c;
    int to = j.timeout_ms > 0 ? j.timeout_ms : 3000;
    unsigned long t0 = millis();
    bool ok = c.connect(j.host, (uint16_t)j.port, to);
    float ms = (float)(millis() - t0);
    c.stop();
    r.ok = ok; r.rtt_ms = ok ? ms : 0; r.loss_pct = ok ? 0 : 100;
}

void cn_probe_dns(CnJob& j, CnResult& r) {
    IPAddress ip;
    unsigned long t0 = millis();
    bool ok = WiFi.hostByName(j.host, ip);
    float ms = (float)(millis() - t0);
    r.ok = ok; r.rtt_ms = ok ? ms : 0; r.loss_pct = ok ? 0 : 100;
    if (ok) {
        snprintf(r.resolved_ip, sizeof(r.resolved_ip), "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
        // MVP: match = prefix (CIDR pełne = przyszłość). Puste expected → match=true.
        r.match = (strlen(j.expected) == 0) ||
                  (strncmp(r.resolved_ip, j.expected, strlen(j.expected)) == 0);
    } else { r.resolved_ip[0] = 0; r.match = false; }
}

void cn_probe_http(CnJob& j, CnResult& r) {
    int port = j.port > 0 ? j.port : (j.https ? 443 : 80);
    char url[180];
    snprintf(url, sizeof(url), "%s://%s:%d%s",
             j.https ? "https" : "http", j.host, port, j.path[0] ? j.path : "/");
    HTTPClient http;
    WiFiClientSecure sec;
    if (!http_begin_url(http, sec, String(url))) { r.ok = false; r.loss_pct = 100; return; }
    http.setTimeout(j.timeout_ms > 0 ? j.timeout_ms : 5000);
    unsigned long t0 = millis();
    int code = j.http_get ? http.GET() : http.sendRequest("HEAD");
    float ms = (float)(millis() - t0);
    http.end();
    bool ok = j.expected_status > 0 ? (code == (int)j.expected_status)
                                    : (code >= 200 && code < 400);
    r.ok = ok; r.rtt_ms = ms; r.ttfb_ms = ms; r.status_code = code; r.loss_pct = ok ? 0 : 100;
}

// geo_ok z rDNS last-hopa: ostatnia etykieta hostnamu to ccTLD (2 znaki) → porównaj
// z krajem peera (ISO2, wyjątek uk→GB). gTLD (com/net) albo brak PTR → -1 (nie wiadomo).
static int cn_geo_ok(const char* host, const char* cc) {
    if (!host || !*host || !cc || strlen(cc) != 2) return -1;
    const char* dot = strrchr(host, '.');
    if (!dot || strlen(dot + 1) != 2) return -1;
    char t0 = tolower(dot[1]), t1 = tolower(dot[2]);
    if (t0 == 'u' && t1 == 'k') { t0 = 'g'; t1 = 'b'; }
    return (t0 == tolower(cc[0]) && t1 == tolower(cc[1])) ? 1 : 0;
}

// ── Wyślij wyniki ─────────────────────────────────────────────
static void cn_send_results() {
    // Współdzielony scratch TX (data_sender.h): batch i checknet budują JSON-y naprzemiennie
    // w loop(), nigdy równolegle — jeden bufor zamiast dwóch (RAM-AUDIT 0.49).
    // Referencja do tablicy: sizeof(buf) dalej = 3072 (18 użyć niżej bez zmian).
    char (&buf)[TX_SCRATCH_LEN] = g_tx_scratch;
    size_t n = 0;
    n += snprintf(buf + n, sizeof(buf) - n, "{\"type\":\"check_result\",\"results\":[");
    for (int i = 0; i < g_jobCount && n < sizeof(buf); i++) {
        CnJob&    j = g_jobs[i];
        CnResult& r = g_res[i];
        // wspólne
        n += snprintf(buf + n, sizeof(buf) - n,
            "%s{\"id\":%d,\"kind\":\"%s\",\"host\":\"%s\",\"target_kind\":\"%s\","
            "\"to_region\":\"%s\",\"to_lat\":\"%s\",\"to_lon\":\"%s\",\"ok\":%s",
            i ? "," : "", i, j.kind, j.host, j.target_kind,
            j.to_region, j.to_lat, j.to_lon, r.ok ? "true" : "false");
        // kind-specific
        if (strcmp(j.kind, "icmp") == 0) {
            n += snprintf(buf + n, sizeof(buf) - n, ",\"loss_pct\":%.1f,\"samples\":%d", r.loss_pct, r.samples);
            if (r.ok) n += snprintf(buf + n, sizeof(buf) - n, ",\"rtt_ms\":%.1f,\"jitter_ms\":%.1f", r.rtt_ms, r.jitter_ms);
        } else if (strcmp(j.kind, "tcp") == 0) {
            if (r.ok) n += snprintf(buf + n, sizeof(buf) - n, ",\"connect_ms\":%.1f", r.rtt_ms);
        } else if (strcmp(j.kind, "dns") == 0) {
            if (r.ok) n += snprintf(buf + n, sizeof(buf) - n,
                ",\"resolve_ms\":%.1f,\"resolved_ip\":\"%s\",\"match\":%s",
                r.rtt_ms, r.resolved_ip, r.match ? "true" : "false");
        } else if (strcmp(j.kind, "http") == 0) {
            n += snprintf(buf + n, sizeof(buf) - n, ",\"status_code\":%d", r.status_code);
            if (r.ok) n += snprintf(buf + n, sizeof(buf) - n, ",\"total_ms\":%.1f,\"ttfb_ms\":%.1f", r.rtt_ms, r.ttfb_ms);
        }
        if (g_tr_job == i) {
            if (g_tr_lh_host[0]) {
                int gok = cn_geo_ok(g_tr_lh_host, j.to_region);
                n += snprintf(buf + n, sizeof(buf) - n, ",\"lh_host\":\"%s\"", g_tr_lh_host);
                if (gok >= 0) n += snprintf(buf + n, sizeof(buf) - n, ",\"geo_ok\":%s", gok ? "true" : "false");
            }
            n += snprintf(buf + n, sizeof(buf) - n, ",\"reached\":%s,\"hops\":[", g_tr_reached ? "true" : "false");
            bool first = true;
            for (int h = 0; h < g_tr_n && n < sizeof(buf) - 48; h++) {
                if (g_tr_hops[h].ip == 0) continue;          // timeout — pomijamy (luka w ttl mówi sama)
                uint32_t a = g_tr_hops[h].ip;                // network order
                n += snprintf(buf + n, sizeof(buf) - n, "%s{\"ttl\":%d,\"ip\":\"%u.%u.%u.%u\",\"ms\":%.0f}",
                    first ? "" : ",", g_tr_hops[h].ttl,
                    (unsigned)(a & 0xFF), (unsigned)((a >> 8) & 0xFF),
                    (unsigned)((a >> 16) & 0xFF), (unsigned)((a >> 24) & 0xFF),
                    g_tr_hops[h].ms);
                first = false;
            }
            n += snprintf(buf + n, sizeof(buf) - n, "]");
        }
        n += snprintf(buf + n, sizeof(buf) - n, "}");
    }
    n += snprintf(buf + n, sizeof(buf) - n, "]}");
    if (n >= sizeof(buf)) { LOGW("cn", "result buffer overflow — skipped"); return; }
    ws_client_send_raw(buf);
    LOGD("cn", "cycle sent: %d jobs (%uB)", g_jobCount, (unsigned)n);

    // Agregacja per-cykl → encje pub.net_* — TYLKO icmp (net_ping = rtt ICMP, nie tcp/http)
    float sumRtt = 0, sumJit = 0, sumLoss = 0, sumRttPeer = 0; int okN = 0, peers = 0, icmpN = 0;
    for (int i = 0; i < g_jobCount; i++) {
        if (strcmp(g_jobs[i].kind, "icmp") != 0) continue;
        CnResult& r = g_res[i];
        icmpN++;
        sumLoss += r.loss_pct;
        if (r.ok) {
            sumRtt += r.rtt_ms; sumJit += r.jitter_ms; okN++;
            if (!strcmp(g_jobs[i].target_kind, "peer")) { peers++; sumRttPeer += r.rtt_ms; }
        }
    }
    if (icmpN == 0) return;   // cykl bez icmp → nie ruszaj net_*
    float avgLoss = sumLoss / icmpN;
    if (okN) {
        float ap = sumRtt / okN, aj = sumJit / okN;
        g_ema_ping = isnan(g_ema_ping) ? ap : g_ema_ping * 0.7f + ap * 0.3f;
        g_ema_jit  = isnan(g_ema_jit)  ? aj : g_ema_jit  * 0.7f + aj * 0.3f;
    }
    if (peers) { float anp = sumRttPeer / peers; g_ema_node = isnan(g_ema_node) ? anp : g_ema_node * 0.7f + anp * 0.3f; }
    g_ema_loss = isnan(g_ema_loss) ? avgLoss : g_ema_loss * 0.7f + avgLoss * 0.3f;

    char v[24];
    if (!isnan(g_ema_ping)) { snprintf(v, sizeof(v), "%.1f", g_ema_ping); entity_push("pub.net_ping", v, "ms"); }
    if (!isnan(g_ema_node)) { snprintf(v, sizeof(v), "%.1f", g_ema_node); entity_push("pub.node_ping", v, "ms"); }
    snprintf(v, sizeof(v), "%.1f", isnan(g_ema_jit) ? 0.0f : g_ema_jit); entity_push("pub.net_jitter", v, "ms");
    snprintf(v, sizeof(v), "%.0f", g_ema_loss); entity_push("pub.net_loss", v, "%");
    snprintf(v, sizeof(v), "%d", peers);        entity_push("pub.net_peers", v, "");
}

static void cn_finish_cycle() {
    cn_send_results();
    g_state = CN_IDLE;
}

// ── API ───────────────────────────────────────────────────────
void checknet_init() {
    g_state = CN_IDLE; g_jobCount = 0; g_outstanding = 0;
    cn_load_config();
    traceroute_init();   // statyczny raw_pcb (raz na zawsze — patrz traceroute.h)
    // Pierwszy cykl po starcie: delay (WS/NTP/batch) + losowy rozrzut (anty-stampede po restarcie BE)
    g_nextRun = millis() + CHECKNET_START_DELAY_MS + (esp_random() % CHECKNET_JITTER_MS);
    LOGI("cn", "init (enabled=%d interval=%lums)", g_cfg.enabled, (unsigned long)g_cfg.interval_ms);
}

// Config z BE (cn_config) — nadpisz + persist NVS + przeplanuj. interval_ms=0 → tylko toggle/limity.
void checknet_set_config(bool enabled, uint32_t interval_ms, int max_jobs, int ping_count, uint32_t trace_cd_s) {
    g_cfg.enabled = enabled;
    if (interval_ms >= 10000UL)                     g_cfg.interval_ms = interval_ms;
    if (max_jobs   >= 1 && max_jobs <= CHECKNET_MAX_JOBS) g_cfg.max_jobs   = (uint8_t)max_jobs;
    if (ping_count >= 1 && ping_count <= 20)        g_cfg.ping_count  = (uint8_t)ping_count;
    if (trace_cd_s >= 60 && trace_cd_s <= 86400)    g_cfg.trace_cd_ms = trace_cd_s * 1000UL;
    Preferences p; p.begin("sensmos_cn", false);
    p.putBool ("en", g_cfg.enabled);      p.putULong("iv", g_cfg.interval_ms);
    p.putUChar("mj", g_cfg.max_jobs);     p.putUChar("pc", g_cfg.ping_count);
    p.putULong("tcd", g_cfg.trace_cd_ms);
    p.end();
    cn_schedule_next();
    LOGD("cn", "config from BE (enabled=%d interval=%lums jobs=%d)",
         g_cfg.enabled, (unsigned long)g_cfg.interval_ms, g_cfg.max_jobs);
}

void checknet_run() {
    if (g_state != CN_IDLE) return;          // cykl już trwa
    if (!g_wifi_connected || !ws_client_connected()) return;
    ws_client_send_raw("{\"type\":\"check_assign\"}");
    g_state = CN_WAIT; g_waitStart = millis();
    LOGD("cn", "check_assign sent");
}

void checknet_on_jobs(JsonArray jobs) {
    if (g_state != CN_WAIT) return;          // nieoczekiwane → ignoruj
    g_jobCount = 0;
    g_tr_job = -1; g_tr_n = 0; g_tr_reached = false; g_tr_launched = false; g_tr_lh_host[0] = 0;
    for (JsonObject j : jobs) {
        if (g_jobCount >= g_cfg.max_jobs) break;
        CnJob& job = g_jobs[g_jobCount];
        memset(&job, 0, sizeof(job));
        strlcpy(job.kind,        j["kind"]        | "icmp",   sizeof(job.kind));
        strlcpy(job.host,        j["host"]        | "",       sizeof(job.host));
        strlcpy(job.target_kind, j["target_kind"] | "target", sizeof(job.target_kind));
        strlcpy(job.to_region,   j["to_region"]   | "ANY",    sizeof(job.to_region));
        if (j["to_lat"].is<const char*>()) strlcpy(job.to_lat, j["to_lat"] | "", sizeof(job.to_lat));
        else { float v = j["to_lat"] | 0.0f; snprintf(job.to_lat, sizeof(job.to_lat), "%.6f", v); }
        if (j["to_lon"].is<const char*>()) strlcpy(job.to_lon, j["to_lon"] | "", sizeof(job.to_lon));
        else { float v = j["to_lon"] | 0.0f; snprintf(job.to_lon, sizeof(job.to_lon), "%.6f", v); }
        job.count           = j["count"]           | g_cfg.ping_count;
        job.port            = j["port"]            | 0;
        job.timeout_ms      = j["timeout_ms"]      | 0;
        job.expected_status = j["expected_status"] | 0;
        job.https           = (j["https"] | true) ? 1 : 0;
        job.http_get        = (strcmp(j["method"] | "HEAD", "GET") == 0) ? 1 : 0;
        strlcpy(job.path,     j["path"]     | "/", sizeof(job.path));
        strlcpy(job.expected, j["expected"] | "",  sizeof(job.expected));
        if (strlen(job.host) == 0) continue;
        g_jobCount++;
    }
    if (g_jobCount == 0) { g_state = CN_IDLE; return; }

    // Wrzuć CAŁY cykl na worker (lo-prio) — worker serializuje (1 TLS naraz).
    g_outstanding = 0;
    for (int i = 0; i < g_jobCount; i++) {
        memset(&g_res[i], 0, sizeof(g_res[i])); g_res[i].loss_pct = 100;
        NetJob nj; memset(&nj, 0, sizeof(nj));
        nj.src = NW_CHECKNET; nj.ref_idx = (int16_t)i; nj.job = g_jobs[i];
        if (net_worker_enqueue(nj, false)) g_outstanding++;   // full → job zostaje jako fail
    }
    LOGD("cn", "%d jobs queued (outstanding=%d)", g_jobCount, g_outstanding);
    if (g_outstanding == 0) { cn_finish_cycle(); return; }    // nic nie weszło → wyślij fail-e
    g_state = CN_COLLECT; g_collectStart = millis();
}

void checknet_on_net_result(const NetResult& nr) {
    if (g_state != CN_COLLECT) return;                        // spóźniony wynik → ignoruj
    int i = nr.ref_idx;

    if (i >= 0 && i < g_jobCount) {
        if (nr.is_trace) {
            for (int h = 0; h < nr.hop_n && h < TR_MAX_HOPS; h++) g_tr_hops[h] = nr.hops[h];
            g_tr_n = nr.hop_n; g_tr_reached = nr.reached; g_tr_job = i;
            strlcpy(g_tr_lh_host, nr.lh_host, sizeof(g_tr_lh_host));
            LOGD("cn", "trace %s hops=%d reached=%d lh=%s", g_jobs[i].host, g_tr_n, g_tr_reached, g_tr_lh_host);
        } else {
            g_res[i] = nr.res;
            CnJob& j = g_jobs[i];
            LOGD("cn", "%s %s %s ok=%d %.0fms loss=%.0f%%", j.kind, j.target_kind, j.host,
                 g_res[i].ok, g_res[i].rtt_ms, g_res[i].loss_pct);
            // AUTONOMICZNY trace: peer całkiem głuchy → od razu szukamy WŁASNEGO last-hopa
            // (trasa node->cel; BE-trace widzi świat z serwerowni). Max 1/cykl + cooldown.
            if (!strcmp(j.kind, "icmp") && !strcmp(j.target_kind, "peer") &&
                g_res[i].loss_pct >= 100 && !g_tr_launched && g_tr_job < 0 && tr_cd_ok(j.host) &&
                (long)(millis() - g_tr_next) >= 0) {       // globalny CD: max 1 trace / trace_cd_ms
                NetJob tj; memset(&tj, 0, sizeof(tj));
                tj.src = NW_CHECKNET; tj.ref_idx = (int16_t)i;
                strlcpy(tj.job.kind, "trace", sizeof(tj.job.kind));
                strlcpy(tj.job.host, j.host, sizeof(tj.job.host));
                strlcpy(tj.job.to_region, j.to_region, sizeof(tj.job.to_region));   // kraj peera → geo_ok
                if (net_worker_enqueue(tj, false)) {
                    g_tr_launched = true; tr_cd_add(j.host); g_outstanding++;
                    g_tr_next = millis() + g_cfg.trace_cd_ms;
                }
            }
        }
    }

    if (g_outstanding > 0) g_outstanding--;
    if (g_outstanding == 0) cn_finish_cycle();
}

bool checknet_busy() { return g_state != CN_IDLE; }

void checknet_update() {
    // Samonapęd rdzenia: odpal cykl gdy czas i idle. checknet_run() sam sprawdza wifi/ws.
    if (g_state == CN_IDLE && g_cfg.enabled && (long)(millis() - g_nextRun) >= 0) {
        cn_schedule_next();
        checknet_run();
        return;
    }
    if (g_state == CN_WAIT) {
        if (millis() - g_waitStart > CHECKNET_ASSIGN_TIMEOUT_MS) g_state = CN_IDLE;
        return;
    }
    if (g_state == CN_COLLECT) {
        // Awaryjny limit: zgubiony wynik nie może zawiesić cyklu na wieki.
        if (millis() - g_collectStart > NET_COLLECT_TIMEOUT_MS) {
            LOGW("cn", "collect timeout (outstanding=%d) — sending partial", g_outstanding);
            cn_finish_cycle();
        }
    }
}
