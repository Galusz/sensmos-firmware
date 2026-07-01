/**
 * SENSMOS Firmware — checknet
 * Pomiary jakości internetu przydzielane dynamicznie przez BE (WS).
 * ICMP przez ESP-IDF ping_sock (async, w osobnym tasku IDF — nie blokuje loop()).
 * Callbacki tylko akumulują; finalizacja/WS w loop() (thread-safe: sesja już zakończona).
 */
#include "checknet.h"
#include "config.h"
#include "ws_client.h"
#include "wifi_manager.h"
#include "entity_store.h"
#include <WiFi.h>
#include <math.h>
#include "ping/ping_sock.h"
#include "lwip/ip_addr.h"

struct CnJob {
    char kind[8];
    char host[40];
    char target_kind[8];
    char to_region[8];
    char to_lat[16];
    char to_lon[16];
    int  count;
};
struct CnResult {   // tylko pomiar — echo (host/kind/region…) czytamy z g_jobs (oszczędność RAM)
    bool  ok;
    float rtt_ms; float jitter_ms; float loss_pct; int samples;
};

static CnJob    g_jobs[CHECKNET_MAX_JOBS];
static CnResult g_res[CHECKNET_MAX_JOBS];
static int      g_jobCount = 0;
static int      g_jobIdx   = 0;
enum CnState { CN_IDLE, CN_WAIT, CN_RUN };
static CnState  g_state = CN_IDLE;
static unsigned long g_waitStart = 0;

static esp_ping_handle_t g_session = nullptr;
static volatile bool  g_pingDone = false;
// rolling EMA (alpha 0.3) — node sam liczy swoje encje pub.net_*
static float g_ema_ping = NAN, g_ema_jit = NAN, g_ema_loss = NAN;
static volatile int   g_recv = 0;
static volatile float g_sum  = 0, g_sumsq = 0;

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

// ── Start joba (ICMP) ─────────────────────────────────────────
static void cn_start_job(int i) {
    g_recv = 0; g_sum = 0; g_sumsq = 0; g_pingDone = false;
    CnJob&    j = g_jobs[i];
    CnResult& r = g_res[i];
    r.ok = false; r.rtt_ms = 0; r.jitter_ms = 0; r.loss_pct = 100; r.samples = 0;

    if (strcmp(j.kind, "icmp") != 0) { g_pingDone = true; return; }  // v1: tylko ICMP

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
        g_session = nullptr; g_pingDone = true; return;
    }
    esp_ping_start(g_session);
}

// ── Finalizacja joba (loop) ───────────────────────────────────
static void cn_finalize_job(int i) {
    CnJob&   j = g_jobs[i];
    CnResult& r = g_res[i];
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
    if (g_session) { esp_ping_delete_session(g_session); g_session = nullptr; }
    Serial.printf("[checknet]  %-6s %-15s rtt=%.1fms jit=%.1f loss=%.0f%% n=%d\n",
                  j.target_kind, j.host, r.rtt_ms, r.jitter_ms, r.loss_pct, r.samples);
}

// ── Wyślij wyniki ─────────────────────────────────────────────
static void cn_send_results() {
    JsonDocument doc;
    doc["type"] = "check_result";
    JsonArray arr = doc["results"].to<JsonArray>();
    for (int i = 0; i < g_jobCount; i++) {
        CnJob&    j = g_jobs[i];
        CnResult& r = g_res[i];
        JsonObject o = arr.add<JsonObject>();
        o["id"]          = i;
        o["kind"]        = j.kind;
        o["host"]        = j.host;
        o["target_kind"] = j.target_kind;
        o["to_region"]   = j.to_region;
        o["to_lat"]      = j.to_lat;
        o["to_lon"]      = j.to_lon;
        o["loss_pct"]    = r.loss_pct;
        o["samples"]     = r.samples;
        if (r.ok) { o["rtt_ms"] = r.rtt_ms; o["jitter_ms"] = r.jitter_ms; }
    }
    String out; serializeJson(doc, out);
    ws_client_send_raw(out.c_str());
    Serial.printf("[checknet] wyniki wysłane: %d jobów\n", g_jobCount);

    // Agregacja per-cykl → encje pub.net_* (node liczy sam, idą z batchem, robią heatmapę)
    float sumRtt = 0, sumJit = 0, sumLoss = 0; int okN = 0, peers = 0;
    for (int i = 0; i < g_jobCount; i++) {
        CnResult& r = g_res[i];
        sumLoss += r.loss_pct;
        if (r.ok) { sumRtt += r.rtt_ms; sumJit += r.jitter_ms; okN++; if (!strcmp(g_jobs[i].target_kind, "peer")) peers++; }
    }
    float avgLoss = g_jobCount ? sumLoss / g_jobCount : 0;
    if (okN) {
        float ap = sumRtt / okN, aj = sumJit / okN;
        g_ema_ping = isnan(g_ema_ping) ? ap : g_ema_ping * 0.7f + ap * 0.3f;
        g_ema_jit  = isnan(g_ema_jit)  ? aj : g_ema_jit  * 0.7f + aj * 0.3f;
    }
    g_ema_loss = isnan(g_ema_loss) ? avgLoss : g_ema_loss * 0.7f + avgLoss * 0.3f;

    char v[24];
    if (!isnan(g_ema_ping)) { snprintf(v, sizeof(v), "%.1f", g_ema_ping); entity_push("pub.net_ping", v, "ms"); }
    snprintf(v, sizeof(v), "%.1f", isnan(g_ema_jit) ? 0.0f : g_ema_jit); entity_push("pub.net_jitter", v, "ms");
    snprintf(v, sizeof(v), "%.0f", g_ema_loss); entity_push("pub.net_loss", v, "%");
    snprintf(v, sizeof(v), "%d", peers);        entity_push("pub.net_peers", v, "");
}

// ── API ───────────────────────────────────────────────────────
void checknet_init() { g_state = CN_IDLE; g_session = nullptr; g_jobCount = 0; }

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
    for (JsonObject j : jobs) {
        if (g_jobCount >= CHECKNET_MAX_JOBS) break;
        CnJob& job = g_jobs[g_jobCount];
        strlcpy(job.kind,        j["kind"]        | "icmp",   sizeof(job.kind));
        strlcpy(job.host,        j["host"]        | "",       sizeof(job.host));
        strlcpy(job.target_kind, j["target_kind"] | "target", sizeof(job.target_kind));
        strlcpy(job.to_region,   j["to_region"]   | "ANY",    sizeof(job.to_region));
        if (j["to_lat"].is<const char*>()) strlcpy(job.to_lat, j["to_lat"] | "", sizeof(job.to_lat));
        else { float v = j["to_lat"] | 0.0f; snprintf(job.to_lat, sizeof(job.to_lat), "%.6f", v); }
        if (j["to_lon"].is<const char*>()) strlcpy(job.to_lon, j["to_lon"] | "", sizeof(job.to_lon));
        else { float v = j["to_lon"] | 0.0f; snprintf(job.to_lon, sizeof(job.to_lon), "%.6f", v); }
        job.count = j["count"] | CHECKNET_PING_COUNT;
        if (strlen(job.host) == 0) continue;
        g_jobCount++;
    }
    if (g_jobCount == 0) { g_state = CN_IDLE; return; }
    Serial.printf("[checknet] %d jobów\n", g_jobCount);
    g_jobIdx = 0; g_state = CN_RUN;
    cn_start_job(0);
}

void checknet_update() {
    if (g_state == CN_WAIT) {
        if (millis() - g_waitStart > CHECKNET_ASSIGN_TIMEOUT_MS) { g_state = CN_IDLE; }
        return;
    }
    if (g_state != CN_RUN) return;
    if (!g_pingDone) return;

    cn_finalize_job(g_jobIdx);
    g_jobIdx++;
    if (g_jobIdx < g_jobCount) cn_start_job(g_jobIdx);
    else { cn_send_results(); g_state = CN_IDLE; }
}
