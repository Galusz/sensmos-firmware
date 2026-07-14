/**
 * SENSMOS Firmware — Check-now (UpFromWhere)
 * BE pcha podpisaną komendę {type:"check", id, url} — jednorazowa sonda HTTP URL-a
 * wpisanego przez usera na landingu. Trzeci klient net_workera (obok checknet/monitors):
 * bez schedulera i persystencji, jeden slot w locie (BE strzela max 1 check/node na cykl
 * globalnej kolejki ~20 s). Wynik: WS {type:"checknow_result", id, ok, rtt_ms, status}.
 *
 * Walidacja URL = defense-in-depth (BE waliduje pierwszy): tylko http/https, porty 80/443,
 * blok prywatnych IP / localhost / .local — flota z domowych łączy nie może być proxy do LAN.
 */
#include "checknow.h"
#include "config.h"
#include "log.h"
#include "net_worker.h"
#include "ws_client.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static char   g_id[24] = "";   // id joba BE w locie ("" = wolny slot)
static NetJob g_job;           // kopia joba — retry przy deferred (TLS pominięty przez heap)
static bool   g_retried = false;

static bool is_private_host(const char* h) {
    if (!strcmp(h, "localhost")) return true;
    size_t l = strlen(h);
    if (l > 6 && !strcmp(h + l - 6, ".local")) return true;
    int a = -1, b = -1, c = -1, d = -1;
    if (sscanf(h, "%d.%d.%d.%d", &a, &b, &c, &d) == 4) {   // literal IPv4
        if (a == 10 || a == 127 || a == 0) return true;
        if (a == 192 && b == 168) return true;
        if (a == 172 && b >= 16 && b <= 31) return true;
        if (a == 169 && b == 254) return true;
    }
    return false;
}

void checknow_on_cmd(JsonDocument& doc) {
    const char* id  = doc["id"]  | "";
    const char* url = doc["url"] | "";
    if (!*id || !*url) return;
    if (g_id[0]) { LOGW("cnow", "busy (job %s w locie) — drop %s", g_id, id); return; }

    bool https;
    const char* p = url;
    if      (!strncmp(p, "https://", 8)) { https = true;  p += 8; }
    else if (!strncmp(p, "http://",  7)) { https = false; p += 7; }
    else { LOGW("cnow", "bad scheme: %s", url); return; }

    char host[64] = "", path[64] = "/";
    const char* slash = strchr(p, '/');
    size_t hl = slash ? (size_t)(slash - p) : strlen(p);
    if (hl == 0 || hl >= sizeof(host)) { LOGW("cnow", "bad host len"); return; }
    memcpy(host, p, hl); host[hl] = 0;
    if (slash) strlcpy(path, slash, sizeof(path));

    int port = 0;                        // 0 → default wg https (cn_probe_http)
    char* colon = strchr(host, ':');
    if (colon) {                         // port w URL: tylko standardowe
        *colon = 0;
        port = atoi(colon + 1);
        if (port != 80 && port != 443) { LOGW("cnow", "port %d blocked", port); return; }
    }
    if (is_private_host(host)) { LOGW("cnow", "private host blocked: %s", host); return; }

    NetJob nj; memset(&nj, 0, sizeof(nj));
    nj.src = NW_CHECKNOW;
    strlcpy(nj.job.kind, "http", sizeof(nj.job.kind));
    strlcpy(nj.job.host, host,   sizeof(nj.job.host));
    strlcpy(nj.job.path, path,   sizeof(nj.job.path));
    nj.job.port       = port;
    nj.job.https      = https ? 1 : 0;
    nj.job.http_get   = 1;      // GET: HEAD bywa odrzucany (405) → fałszywy DOWN
    nj.job.timeout_ms = 6000;   // < okno pomiaru BE (8 s) — raport zdąży wrócić
    if (!net_worker_enqueue(nj, true)) { LOGW("cnow", "worker full — drop %s", id); return; }
    strlcpy(g_id, id, sizeof(g_id));
    g_job = nj; g_retried = false;
    LOGI("cnow", "check %s %s://%s%s", id, https ? "https" : "http", host, path);
}

void checknow_on_net_result(const NetResult& nr) {
    if (!g_id[0]) return;
    // deferred = sonda NIE wykonana (za mały ciągły blok na TLS) — jedna ponowka zamiast
    // raportowania fałszywego DOWN; druga wtopa → trudno, BE policzy timeout
    if (nr.deferred && !g_retried && net_worker_enqueue(g_job, true)) { g_retried = true; return; }
    char buf[160];
    snprintf(buf, sizeof(buf),
        "{\"type\":\"checknow_result\",\"id\":\"%s\",\"ok\":%s,\"rtt_ms\":%.0f,\"status\":%d}",
        g_id, nr.res.ok ? "true" : "false", nr.res.rtt_ms, nr.res.status_code);
    ws_client_send_raw(buf);
    LOGI("cnow", "%s ok=%d %.0fms status=%d", g_id, (int)nr.res.ok, nr.res.rtt_ms, nr.res.status_code);
    g_id[0] = 0;
}
