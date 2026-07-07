/**
 * SENSMOS Firmware — checknet
 * Pomiary jakości internetu przydzielane dynamicznie przez BE (WS).
 * ICMP przez ESP-IDF ping_sock (async, w osobnym tasku IDF — nie blokuje loop()).
 * tcp/dns/http: blokujące (wzorem script_async), ale JEDEN probe per checknet_update()
 *   (g_needStart yield) — żeby nie łańcuchować blokad w jednym przebiegu loop().
 */
#include "checknet.h"
#include "config.h"
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
#include "ping/ping_sock.h"
#include "lwip/ip_addr.h"
#include "traceroute.h"

// CnJob/CnResult — definicje w checknet.h (współdzielone z monitors.cpp)

static CnJob    g_jobs[CHECKNET_MAX_JOBS];
static CnResult g_res[CHECKNET_MAX_JOBS];
static int      g_jobCount = 0;
// trace (v0.37): max 1 job/cykl, wynik w statycznych buforach (BE dostaje hopy)
static TrHop    g_tr_hops[16];
static int      g_tr_n = 0;
static bool     g_tr_reached = false;
static int      g_tr_job = -1;
static int      g_jobIdx   = 0;
static bool     g_needStart = false;
enum CnState { CN_IDLE, CN_WAIT, CN_RUN };
static CnState  g_state = CN_IDLE;
static unsigned long g_waitStart = 0;

static esp_ping_handle_t g_session = nullptr;
static volatile bool  g_pingDone = false;
// rolling EMA (alpha 0.3) — node sam liczy swoje encje pub.net_* (TYLKO z icmp)
// net_ping = do wszystkiego (anycast+peery); node_ping = tylko do innych nodów (P2P)
static float g_ema_ping = NAN, g_ema_jit = NAN, g_ema_loss = NAN, g_ema_node = NAN;
static volatile int   g_recv = 0;
static volatile float g_sum  = 0, g_sumsq = 0;

// ── Config samonapędu (rdzeń, nie skrypt) — nadpisywana przez BE (cn_config), persist NVS ──
struct CnConfig { bool enabled; uint32_t interval_ms; uint8_t max_jobs; uint8_t ping_count; };
static CnConfig g_cfg = {
    CHECKNET_ENABLED_DEFAULT, CHECKNET_INTERVAL_MS_DEFAULT, CHECKNET_MAX_JOBS, CHECKNET_PING_COUNT
};
static unsigned long g_nextRun = 0;

static void cn_load_config() {
    Preferences p; p.begin("sensmos_cn", true);
    g_cfg.enabled     = p.getBool ("en", CHECKNET_ENABLED_DEFAULT);
    g_cfg.interval_ms = p.getULong("iv", CHECKNET_INTERVAL_MS_DEFAULT);
    g_cfg.max_jobs    = p.getUChar("mj", CHECKNET_MAX_JOBS);
    g_cfg.ping_count  = p.getUChar("pc", CHECKNET_PING_COUNT);
    p.end();
    if (g_cfg.max_jobs > CHECKNET_MAX_JOBS) g_cfg.max_jobs = CHECKNET_MAX_JOBS;
    if (g_cfg.max_jobs < 1)                 g_cfg.max_jobs = 1;
    if (g_cfg.ping_count < 1)               g_cfg.ping_count = 1;
    if (g_cfg.interval_ms < 10000UL)        g_cfg.interval_ms = 10000UL;   // sanity: min 10s
}

static void cn_schedule_next() {
    long jitter = (long)(esp_random() % (2UL * CHECKNET_JITTER_MS)) - (long)CHECKNET_JITTER_MS;
    g_nextRun = millis() + g_cfg.interval_ms + jitter;
}

// ── Callbacki ping (task IDF) — tylko akumulacja ──────────────
static void cn_on_success(esp_ping_handle_t hdl, void* args) {
    uint32_t elapsed = 0;
    esp_ping_get_profile(hdl, ESP_PING_PROF_TIMEGAP, &elapsed, sizeof(elapsed));
    g_recv++;
    g_sum   += (float)elapsed;
    g_sumsq += (float)elapsed * (float)elapsed;
}
static void cn_on_timeout(esp_ping_handle_t hdl, void* args) { /* pakiet zgubiony */ }
static void cn_on_end(esp_ping_handle_t hdl, void* args)     { g_pingDone = true; }

// ── Egzekutory blokujące (tcp/dns/http) — jeden per update ────
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

// ── Start joba ────────────────────────────────────────────────
static void cn_start_job(int i) {
    CnJob&    j = g_jobs[i];
    CnResult& r = g_res[i];
    memset(&r, 0, sizeof(r)); r.loss_pct = 100; r.ok = false;
    g_recv = 0; g_sum = 0; g_sumsq = 0; g_pingDone = false;

    // Blokujące typy — wykonaj tu, oznacz done od razu (finalize w kolejnym update)
    if (strcmp(j.kind, "trace") == 0) {
        // max 1 trace/cykl (statyczny bufor hopow); kind[6] miesci "trace"
        if (g_tr_job >= 0) { g_pingDone = true; return; }
        g_tr_n = traceroute_run(j.host, g_tr_hops, 16, 1000, &g_tr_reached);
        g_tr_job = i;
        r.ok = g_tr_n > 0;
        g_pingDone = true; return;
    }
    if (strcmp(j.kind, "tcp")  == 0) { cn_probe_tcp(j, r);  g_pingDone = true; return; }
    if (strcmp(j.kind, "dns")  == 0) { cn_probe_dns(j, r);  g_pingDone = true; return; }
    if (strcmp(j.kind, "http") == 0) { cn_probe_http(j, r); g_pingDone = true; return; }
    if (strcmp(j.kind, "icmp") != 0) { g_pingDone = true; return; }  // nieznany kind → no-op

    // ── ICMP (async, esp_ping) ──
    ip_addr_t target; memset(&target, 0, sizeof(target));
    if (ipaddr_aton(j.host, &target) == 0) {                          // nie-IP → rozwiąż DNS
        IPAddress ip;
        if (WiFi.hostByName(j.host, ip)) {
            IP_ADDR4(&target, ip[0], ip[1], ip[2], ip[3]);
        } else { g_pingDone = true; return; }                        // brak → loss 100
    }

    esp_ping_config_t cfg = ESP_PING_DEFAULT_CONFIG();
    cfg.target_addr = target;
    cfg.count       = j.count > 0 ? j.count : CHECKNET_PING_COUNT;
    cfg.timeout_ms  = CHECKNET_PING_TIMEOUT_MS;
    cfg.interval_ms = CHECKNET_PING_INTERVAL_MS;
    cfg.task_stack_size = 2560;

    esp_ping_callbacks_t cbs = {};
    cbs.cb_args = nullptr;
    cbs.on_ping_success = cn_on_success;
    cbs.on_ping_timeout = cn_on_timeout;
    cbs.on_ping_end     = cn_on_end;

    if (esp_ping_new_session(&cfg, &cbs, &g_session) != ESP_OK || !g_session) {
        Serial.printf("[checknet] ping session FAIL — freeHeap=%u largestBlock=%u\n",
                      ESP.getFreeHeap(), ESP.getMaxAllocHeap());
        g_session = nullptr; g_pingDone = true; return;
    }
    esp_ping_start(g_session);
}

// ── Finalizacja joba (loop) ───────────────────────────────────
static void cn_finalize_job(int i) {
    CnJob&   j = g_jobs[i];
    CnResult& r = g_res[i];
    if (strcmp(j.kind, "icmp") == 0) {
        int sent = j.count > 0 ? j.count : CHECKNET_PING_COUNT;
        int recv = g_recv;
        r.samples = recv;
        if (recv > 0) {
            float avg = g_sum / recv;
            float var = g_sumsq / recv - avg * avg; if (var < 0) var = 0;
            r.rtt_ms    = avg;
            r.jitter_ms = sqrtf(var);
            r.loss_pct  = 100.0f * (sent - recv) / sent;
            r.ok = true;
        } else {
            r.rtt_ms = 0; r.jitter_ms = 0; r.loss_pct = 100; r.ok = false;
        }
        if (g_session) { esp_ping_stop(g_session); esp_ping_delete_session(g_session); g_session = nullptr; }

        // AUTONOMICZNY trace (v0.37): peer/proxy calkiem gluchy -> od razu szukamy
        // WLASNEGO last-hopa (trasa node->cel; BE-trace widzi swiat z serwerowni).
        // Max 1 trace/cykl; hopy doklejane do wyniku TEGO joba (zero roundtripu z BE).
        if (!strcmp(j.target_kind, "peer") && r.loss_pct >= 100 && g_tr_job < 0) {
            g_tr_n = traceroute_run(j.host, g_tr_hops, 16, 1000, &g_tr_reached);
            if (g_tr_n > 0) g_tr_job = i;
        }
    }
    Serial.printf("[checknet]  %-4s %-6s %-22s ok=%d ms=%.1f loss=%.0f%% free=%u\n",
                  j.kind, j.target_kind, j.host, r.ok, r.rtt_ms, r.loss_pct, ESP.getFreeHeap());
}

// ── Wyślij wyniki ─────────────────────────────────────────────
static void cn_send_results() {
    // Stały bufor (alloc raz w .bss) — zero JsonDocument/String churnu/fragmentacji.
    static char buf[2560];
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
    if (n >= sizeof(buf)) { Serial.println("[checknet] result buf overflow — pominięto"); return; }
    ws_client_send_raw(buf);
    Serial.printf("[checknet] wyniki wysłane: %d jobów (%uB)\n", g_jobCount, (unsigned)n);

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

// ── API ───────────────────────────────────────────────────────
void checknet_init() {
    g_state = CN_IDLE; g_session = nullptr; g_jobCount = 0; g_needStart = false;
    cn_load_config();
    traceroute_init();   // statyczny raw_pcb (raz na zawsze — patrz traceroute.h)
    // Pierwszy cykl po starcie: delay (WS/NTP/batch) + losowy rozrzut (anty-stampede po restarcie BE)
    g_nextRun = millis() + CHECKNET_START_DELAY_MS + (esp_random() % CHECKNET_JITTER_MS);
    Serial.printf("[checknet] core: en=%d interval=%lums maxJobs=%d ping=%d\n",
                  g_cfg.enabled, (unsigned long)g_cfg.interval_ms, g_cfg.max_jobs, g_cfg.ping_count);
}

// Config z BE (cn_config) — nadpisz + persist NVS + przeplanuj. interval_ms=0 → tylko toggle/limity.
void checknet_set_config(bool enabled, uint32_t interval_ms, int max_jobs, int ping_count) {
    g_cfg.enabled = enabled;
    if (interval_ms >= 10000UL)                     g_cfg.interval_ms = interval_ms;
    if (max_jobs   >= 1 && max_jobs <= CHECKNET_MAX_JOBS) g_cfg.max_jobs   = (uint8_t)max_jobs;
    if (ping_count >= 1 && ping_count <= 20)        g_cfg.ping_count  = (uint8_t)ping_count;
    Preferences p; p.begin("sensmos_cn", false);
    p.putBool ("en", g_cfg.enabled);      p.putULong("iv", g_cfg.interval_ms);
    p.putUChar("mj", g_cfg.max_jobs);     p.putUChar("pc", g_cfg.ping_count);
    p.end();
    cn_schedule_next();
    Serial.printf("[checknet] cn_config z BE: en=%d interval=%lums maxJobs=%d ping=%d\n",
                  g_cfg.enabled, (unsigned long)g_cfg.interval_ms, g_cfg.max_jobs, g_cfg.ping_count);
}

void checknet_run() {
    if (g_state != CN_IDLE) return;          // cykl już trwa
    if (!g_wifi_connected || !ws_client_connected()) return;
    ws_client_send_raw("{\"type\":\"check_assign\"}");
    g_state = CN_WAIT; g_waitStart = millis();
    Serial.println("[checknet] check_assign wysłane");
}

void checknet_on_jobs(JsonArray jobs) {
    if (g_state != CN_WAIT) return;          // nieoczekiwane → ignoruj
    g_jobCount = 0;
    g_tr_job = -1; g_tr_n = 0; g_tr_reached = false;
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
    Serial.printf("[checknet] %d jobów (freeHeap=%u largestBlock=%u)\n",
                  g_jobCount, ESP.getFreeHeap(), ESP.getMaxAllocHeap());
    g_jobIdx = 0; g_state = CN_RUN; g_needStart = true;   // start w update (yield — jeden probe/przebieg)
}

bool checknet_busy() { return g_state == CN_RUN; }   // monitors odracza swój probe gdy checknet mierzy

void checknet_update() {
    // Samonapęd rdzenia (zastępuje akcję skryptu "checknet"): odpal cykl gdy czas i idle.
    // checknet_run() sam sprawdza wifi/ws — jeśli nie gotowe, spróbuje w kolejnym interwale.
    if (g_state == CN_IDLE && g_cfg.enabled && (long)(millis() - g_nextRun) >= 0) {
        cn_schedule_next();
        checknet_run();
    }

    if (g_state == CN_WAIT) {
        if (millis() - g_waitStart > CHECKNET_ASSIGN_TIMEOUT_MS) { g_state = CN_IDLE; }
        return;
    }

    if (g_state != CN_RUN) return;

    // Jeden probe na przebieg: start (blokujące typy wykonują się tu), potem yield.
    if (g_needStart) { g_needStart = false; cn_start_job(g_jobIdx); return; }
    if (!g_pingDone) return;   // icmp async jeszcze w locie

    cn_finalize_job(g_jobIdx);
    g_jobIdx++;
    if (g_jobIdx < g_jobCount) { g_needStart = true; return; }
    cn_send_results();
    g_state = CN_IDLE;
}
