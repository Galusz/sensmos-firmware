/**
 * SENSMOS Firmware — Async net worker ("wór")
 * Jeden task (core 1) serializuje calą pracę sieciową: max 1 TLS naraz → heap-safe,
 * a loop() nie blokuje się na sondach. Priorytet: hi (monitory) przed lo (checknet).
 * Executory tcp/dns/http współdzielone z checknet (cn_probe_*); icmp blokujący własny;
 * trace przez traceroute_run. Zero WS/entity/store tutaj — worker tylko mierzy i odsyła.
 */
#include "net_worker.h"
#include "config.h"
#include "log.h"
#include "wifi_manager.h"
#include "http_internal.h"      // http_begin_url (fetch/webhook)
#include "http_client_util.h"   // http_post_json (webhook)
#include "rdns.h"               // PTR last-hopa (walidacja geo trace)
#include "punch.h"              // UDP hole punch (stun/punch executory + gate)
#include <WiFi.h>
#include <HTTPClient.h>
#include <WiFiClientSecure.h>
#include <ArduinoJson.h>
#include <math.h>
#include "ping/ping_sock.h"
#include "lwip/ip_addr.h"

static QueueHandle_t s_hiQ = nullptr, s_loQ = nullptr, s_resQ = nullptr;
static volatile bool s_busy = false;
// metryki (worker pisze, loop czyta 1/min — telemetria, wyścigi nieszkodliwe)
static volatile uint32_t s_busy_acc_ms = 0;   // suma czasu wykonywania w oknie
static volatile float    s_wait_ema    = 0;   // EMA czekania joba w kolejce (ms)
static uint32_t          s_win_start   = 0;   // początek okna busy% (reset przy odczycie)
static uint8_t           s_last_busy   = 0;   // ostatni policzony busy% (cache dla [health])

// ── ICMP blokujący (tylko worker — jeden task, więc statyki bezpieczne) ──
static volatile int   w_recv;
static volatile float w_sum, w_sumsq;
static volatile bool  w_done;
static void w_ok(esp_ping_handle_t h, void*) {
    uint32_t el = 0; esp_ping_get_profile(h, ESP_PING_PROF_TIMEGAP, &el, sizeof(el));
    w_recv++; w_sum += (float)el; w_sumsq += (float)el * (float)el;
}
static void w_to(esp_ping_handle_t, void*) {}
static void w_end(esp_ping_handle_t, void*) { w_done = true; }

static void nw_probe_icmp(CnJob& j, CnResult& r) {
    int cnt = j.count > 0 ? j.count : CHECKNET_PING_COUNT;
    ip_addr_t target; memset(&target, 0, sizeof(target));
    if (ipaddr_aton(j.host, &target) == 0) {
        IPAddress ip;
        if (!WiFi.hostByName(j.host, ip)) { r.ok = false; r.loss_pct = 100; return; }
        IP_ADDR4(&target, ip[0], ip[1], ip[2], ip[3]);
    }
    w_recv = 0; w_sum = 0; w_sumsq = 0; w_done = false;
    esp_ping_config_t cfg = ESP_PING_DEFAULT_CONFIG();
    cfg.target_addr = target;
    cfg.count       = cnt;
    cfg.timeout_ms  = CHECKNET_PING_TIMEOUT_MS;
    cfg.interval_ms = CHECKNET_PING_INTERVAL_MS;
    cfg.task_stack_size = 2560;
    esp_ping_callbacks_t cbs = {};
    cbs.on_ping_success = w_ok; cbs.on_ping_timeout = w_to; cbs.on_ping_end = w_end;
    esp_ping_handle_t s = nullptr;
    if (esp_ping_new_session(&cfg, &cbs, &s) != ESP_OK || !s) { r.ok = false; r.loss_pct = 100; return; }
    esp_ping_start(s);
    unsigned long t0 = millis();
    unsigned long budget = (unsigned long)cnt * (CHECKNET_PING_TIMEOUT_MS + CHECKNET_PING_INTERVAL_MS) + 500;
    while (!w_done && millis() - t0 < budget) vTaskDelay(pdMS_TO_TICKS(20));
    esp_ping_stop(s); esp_ping_delete_session(s);
    int recv = w_recv; r.samples = recv;
    if (recv > 0) {
        float avg = w_sum / recv;
        float var = w_sumsq / recv - avg * avg; if (var < 0) var = 0;
        r.rtt_ms = avg; r.jitter_ms = sqrtf(var);
        r.loss_pct = 100.0f * (cnt - recv) / cnt; r.ok = true;
    } else { r.rtt_ms = 0; r.jitter_ms = 0; r.loss_pct = 100; r.ok = false; }
}

// ── Fetch (skrypty): GET + JSON-path na workerze ──────────────
// (logika 1:1 z dawnego script_async — wartosc po sciezce "a.b.0.c")
static float nw_json_path(JsonDocument& doc, const char* path) {
    if (!path || strlen(path) == 0) {
        if (doc.is<JsonObject>()) {
            for (JsonPair kv : doc.as<JsonObject>()) {
                if (kv.value().is<float>() || kv.value().is<int>())
                    return kv.value().as<float>();
            }
        } else if (doc.is<float>() || doc.is<int>()) {
            return doc.as<float>();
        }
        return NAN;
    }
    char buf[64]; strncpy(buf, path, sizeof(buf)-1); buf[sizeof(buf)-1] = '\0';
    JsonVariant node = doc.as<JsonVariant>();
    char* tok = strtok(buf, ".");
    while (tok && !node.isNull()) {
        bool is_num = true;
        for (int i = 0; tok[i]; i++) if (!isdigit(tok[i])) { is_num = false; break; }
        if (is_num && node.is<JsonArray>()) node = node.as<JsonArray>()[atoi(tok)];
        else                                node = node[tok];
        tok = strtok(nullptr, ".");
    }
    if (node.is<float>() || node.is<int>()) return node.as<float>();
    if (node.is<const char*>()) {
        float v = atof(node.as<const char*>());
        return (v != 0.0f || strcmp(node.as<const char*>(), "0") == 0) ? v : NAN;
    }
    return NAN;
}

// Guard TLS: poczekaj az bedzie ciagly blok na sesje (~45KB). Dolki largest-block to
// glownie bursty buforow RX drivera WiFi (HA/WS/sondy naraz) — trwaja 3-8s i MIJAJA.
// Retry do 8s zamiast DEFER (ktory kosztuje caly cykl monitora). Worker jest szeregowy,
// wiec czekanie niczego nie blokuje poza samym worem; opoznienie widac w q_lag.
static bool nw_wait_tls_heap(uint32_t* out_blk) {
    uint32_t blk = ESP.getMaxAllocHeap();
    for (int t = 0; t < 80 && blk < MONITORS_HTTP_MIN_HEAP; t++) {
        vTaskDelay(pdMS_TO_TICKS(100));
        blk = ESP.getMaxAllocHeap();
    }
    if (out_blk) *out_blk = blk;
    return blk >= MONITORS_HTTP_MIN_HEAP;
}

// Guard TLS dla url https:// — plain http nie potrzebuje ciaglego bloku
static bool nw_tls_defer(const char* url, uint32_t* out_blk) {
    if (strncmp(url, "https://", 8) != 0) return false;
    return !nw_wait_tls_heap(out_blk);
}

static void nw_run_fetch(NetJob& nj, NetResult& out) {
    CnResult& r = out.res;
    if (nw_tls_defer(nj.url, &out.heap_largest)) { out.deferred = true; return; }
    HTTPClient http;
    WiFiClientSecure sec;
    if (!http_begin_url(http, sec, String(nj.url))) { r.ok = false; return; }
    http.setTimeout(HTTP_TIMEOUT_FETCH);
    int code = http.GET();
    r.status_code = code;
    if (code != 200) {
        http.end();
        r.ok = false;
        snprintf(out.payload, sizeof(out.payload), "{\"http_error\":%d,\"status\":%d}", code, code);
        return;
    }
    String body = http.getString().substring(0, FETCH_BODY_LIMIT);
    http.end();
    r.ok = true;
    // strip znakow kontrolnych (newline/tab/CR) ktore psuja JSON
    String clean = ""; clean.reserve(body.length());
    for (int i = 0; i < (int)body.length(); i++) {
        char ch = body[i];
        if (ch >= 0x20 || ch == '\0') clean += ch;
    }
    JsonDocument doc;
    DeserializationError err = deserializeJson(doc, clean);
    if (!err) {
        float val = nw_json_path(doc, nj.fetch_path[0] ? nj.fetch_path : nullptr);
        if (!isnan(val)) {
            out.has_value = true; out.store_val = val;
            snprintf(out.payload, sizeof(out.payload), "{\"value\":%.4f,\"path\":\"%s\"}", val, nj.fetch_path);
        } else {
            serializeJson(doc, out.payload, sizeof(out.payload));   // raw fallback do BE
        }
    } else {
        float plain = atof(clean.c_str());                          // nie-JSON → plain number
        if (plain != 0.0f) {
            out.has_value = true; out.store_val = plain;
            snprintf(out.payload, sizeof(out.payload), "{\"value\":%.4f}", plain);
        } else {
            r.ok = false;
            snprintf(out.payload, sizeof(out.payload), "{\"parse_error\":0,\"status\":0}");
        }
    }
}

static void nw_run_webhook(NetJob& nj, NetResult& out) {
    if (nw_tls_defer(nj.url, &out.heap_largest)) { out.deferred = true; return; }
    int code = http_post_json(nj.url, nj.body[0] ? nj.body : "{}", HTTP_TIMEOUT_WEBHOOK);
    out.res.status_code = code;
    out.res.ok = (code >= 200 && code < 400);
}

// ── Skan WiFi (NW_SYSTEM) — na worze, bo DRIVER trzyma ~34KB przez ~7s skanu ──
// Serializacja z TLS = zero kolizji z guardem heapu (DEFER-y monitorow przy skanie).
// Wynik (liczba sieci) w res.samples; scanDelete od razu — nie trzymac rekordow AP.
static void nw_run_scan(NetResult& out) {
    WiFi.scanDelete();
    WiFi.scanNetworks(true);                       // async start (task WiFi)
    int n = WIFI_SCAN_RUNNING;
    unsigned long t0 = millis();
    // Czekaj AŻ SKOŃCZY (hard cap 30s): wyjście z trwającym skanem = driver dalej trzyma
    // ~34KB i mierzy, a worker już odpala TLS → DEFER-y. Sens serializacji = skan MUSI
    // domknąć się zanim worker weźmie następny job.
    while ((n = WiFi.scanComplete()) == WIFI_SCAN_RUNNING && millis() - t0 < 30000UL)
        vTaskDelay(pdMS_TO_TICKS(200));
    out.res.ok = n >= 0;
    out.res.samples = n > 0 ? n : 0;
    WiFi.scanDelete();
    LOGD("net", "wifi scan: %d nets in %lums", n, millis() - t0);
}

// SSRF guard (operator-side): monitor/checknet od BE NIE może celować w prywatny/
// zarezerwowany zakres — chroni LAN operatora nawet przy rebindingu DNS (publiczna
// nazwa → prywatne A). Skrypty (własna integracja HA) i skan są zwolnione.
static bool nw_target_public(const char* host) {
    IPAddress r;
    if (!r.fromString(host)) {                         // nie literal IP → rozwiąż
        if (!WiFi.hostByName(host, r)) return true;    // brak DNS → i tak padnie normalnie
    }
    uint8_t a = r[0], b = r[1];
    if (a == 10 || a == 127 || a == 0)      return false;
    if (a == 169 && b == 254)               return false;   // link-local
    if (a == 172 && b >= 16 && b <= 31)     return false;   // 172.16/12
    if (a == 192 && b == 168)               return false;   // 192.168/16
    if (a == 100 && b >= 64 && b <= 127)    return false;   // CGNAT 100.64/10
    if (a >= 224)                            return false;   // multicast/reserved
    return true;
}

// ── Wykonanie jednego joba ────────────────────────────────────
static void nw_execute(NetJob& j, NetResult& out) {
    memset(&out, 0, sizeof(out));
    out.src = j.src; out.ref_id = j.ref_id; out.ref_idx = j.ref_idx;
    CnResult& r = out.res; r.loss_pct = 100;
    const char* k = j.job.kind;

    // SSRF: monitor/checknet nie tyka prywatnych zakresów (icmp/tcp/http łączą się z celem;
    // dns to test rozwiązywania — zostawiamy). deferred = nie licz jako fail/DOWN.
    if ((j.src == NW_MONITOR || j.src == NW_CHECKNET) &&
        (!strcmp(k, "icmp") || !strcmp(k, "tcp") || !strcmp(k, "http")) &&
        !nw_target_public(j.job.host)) {
        LOGW("net", "blocked private target %s (%s) — SSRF guard", j.job.host, k);
        out.deferred = true; r.ok = false;
        return;
    }

    if (!strcmp(k, "trace")) {
        out.is_trace = true;
        out.hop_n = (int16_t)traceroute_run(j.job.host, out.hops, TR_MAX_HOPS, 1000, &out.reached);
        r.ok = out.hop_n > 0;
        // rDNS najgłębszego PUBLICZNEGO hopa → checknet waliduje ccTLD vs kraj peera.
        // Prywatne/CGNAT pomijamy (10/8, 172.16/12, 192.168/16, 100.64/10, 169.254/16).
        for (int h = out.hop_n - 1; h >= 0; h--) {
            uint32_t ip = out.hops[h].ip;
            if (!ip) continue;
            uint8_t o1 = ip & 0xFF, o2 = (ip >> 8) & 0xFF;
            if (o1 == 10 || (o1 == 172 && o2 >= 16 && o2 <= 31) || (o1 == 192 && o2 == 168) ||
                (o1 == 100 && o2 >= 64 && o2 <= 127) || (o1 == 169 && o2 == 254)) continue;
            rdns_ptr(ip, out.lh_host, sizeof(out.lh_host), 2000);
            break;
        }
        return;
    }
    if (!strcmp(k, "stun"))  { punch_exec_stun(j, out);  return; }
    if (!strcmp(k, "punch")) { punch_exec_punch(j, out); return; }
    if (!strcmp(k, "fetch")) { nw_run_fetch(j, out);   return; }
    if (!strcmp(k, "whook")) { nw_run_webhook(j, out); return; }
    if (!strcmp(k, "scan"))  { nw_run_scan(out);       return; }
    if (!strcmp(k, "http")) {
        // http = TLS = ~45KB ciągłego bloku. Retry do 1s (dolki sa chwilowe); dalej za malo
        // → DEFER (nie fail), monitor sprobuje w kolejnym cyklu.
        if (!nw_wait_tls_heap(&out.heap_largest)) { out.deferred = true; r.ok = false; return; }
        cn_probe_http(j.job, r); return;
    }
    if (!strcmp(k, "tcp"))  { cn_probe_tcp(j.job, r); return; }
    if (!strcmp(k, "dns"))  { cn_probe_dns(j.job, r); return; }
    if (!strcmp(k, "icmp")) { nw_probe_icmp(j.job, r); return; }
    // nieznany kind → out.res.ok=false (loss 100)
}

// ── Task: hi przed lo, idle-poll gdy pusto ────────────────────
static void nw_task(void*) {
    NetJob j;
    for (;;) {
        // punch-gate: po STUN nie zaczynaj lo-jobów (trace = 30s) — okno punch by przepadło
        bool got = (xQueueReceive(s_hiQ, &j, 0) == pdTRUE) ||
                   (!punch_gate_active() && xQueueReceive(s_loQ, &j, 0) == pdTRUE);
        if (!got) { vTaskDelay(pdMS_TO_TICKS(20)); continue; }
        s_busy = true;
        uint32_t wait = millis() - j.enq_ms;
        s_wait_ema = (s_wait_ema == 0) ? (float)wait : s_wait_ema * 0.7f + (float)wait * 0.3f;
        uint32_t t0 = millis();
        NetResult out;
        nw_execute(j, out);
        s_busy_acc_ms += millis() - t0;
        xQueueSend(s_resQ, &out, portMAX_DELAY);
        s_busy = false;
    }
}

// ── API ───────────────────────────────────────────────────────
bool net_worker_init() {
    s_hiQ  = xQueueCreate(NET_JOBQ_DEPTH, sizeof(NetJob));
    s_loQ  = xQueueCreate(NET_JOBQ_DEPTH, sizeof(NetJob));
    s_resQ = xQueueCreate(NET_RESQ_DEPTH, sizeof(NetResult));
    if (!s_hiQ || !s_loQ || !s_resQ) { LOGE("net", "queue alloc failed"); return false; }
    // prio 5 (>loop=1): sondy głównie blokują na I/O i oddają CPU; spike potwierdził brak
    // głodzenia loop() przy tym prio. Ostatni rdzeń (dual: APP=1, C3 single-core: 0) —
    // nie kolidować z WiFi/lwIP na core 0 tam, gdzie są dwa rdzenie.
    const BaseType_t core = portNUM_PROCESSORS - 1;
    BaseType_t ok = xTaskCreatePinnedToCore(nw_task, "net_worker", NET_WORKER_STACK, nullptr, 5, nullptr, core);
    LOGI("net", "worker up (core %d, stack %d)", (int)core, NET_WORKER_STACK);
    return ok == pdPASS;
}

bool net_worker_enqueue(const NetJob& j, bool hi) {
    QueueHandle_t q = hi ? s_hiQ : s_loQ;
    if (!q) return false;
    NetJob stamped = j;
    stamped.enq_ms = millis();
    return xQueueSend(q, &stamped, 0) == pdTRUE;
}

bool net_worker_poll(NetResult& out) {
    if (!s_resQ) return false;
    return xQueueReceive(s_resQ, &out, 0) == pdTRUE;
}

uint16_t net_worker_pending() {
    if (!s_hiQ || !s_loQ) return 0;
    return (uint16_t)(uxQueueMessagesWaiting(s_hiQ) + uxQueueMessagesWaiting(s_loQ));
}

bool net_worker_busy() { return s_busy; }

void net_worker_stats(uint16_t* wait_ms, uint8_t* busy_pct, uint16_t* depth) {
    uint32_t now = millis();
    uint32_t win = now - s_win_start;
    if (wait_ms)  *wait_ms  = (uint16_t)(s_wait_ema > 65535 ? 65535 : s_wait_ema);
    uint32_t pct = win > 0 ? (100UL * s_busy_acc_ms) / win : 0;
    if (pct > 100) pct = 100;
    s_last_busy = (uint8_t)pct;
    if (busy_pct) *busy_pct = s_last_busy;
    if (depth) *depth = net_worker_pending() + (s_busy ? 1 : 0);
    s_busy_acc_ms = 0;            // nowe okno od tego odczytu
    s_win_start   = now;
}

uint8_t net_worker_last_busy() { return s_last_busy; }
