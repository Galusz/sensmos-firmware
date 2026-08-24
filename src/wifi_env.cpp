#include "wifi_env.h"
#include "config.h"
#include "net_worker.h"
#include "ws_client.h"
#include "log.h"
#include <WiFi.h>
#include <mbedtls/sha256.h>

// Ramka budowana NA WORZE (przed scanDelete — potem rekordy AP znikają), czytana z loop
// dopiero po odebraniu NetResult. Kolejka FreeRTOS daje barierę pamięci (wzorzec lora_pump),
// więc bez własnych volatile: worker pisze → post wyniku → loop czyta.
static char          s_frame[640];
static unsigned long s_next  = 0;
static bool          s_inflight = false;

// SHA256(data)[0..7] → 16 hex. Wspólne dla BSSID (6 B) i SSID (tekst).
static void hash16(const uint8_t* data, size_t len, char out[17]) {
    uint8_t h[32];
    mbedtls_sha256(data, len, h, 0);
    for (int i = 0; i < 8; i++) sprintf(out + i * 2, "%02x", h[i]);
    out[16] = 0;
}

void wifi_env_init() {
    s_next = millis() + WIFI_ENV_BOOT_DELAY_MS;   // pierwszy skan po okrzepnięciu (WS, batch)
}

void wifi_env_tick() {
    if (s_inflight) return;
    if (WiFi.status() != WL_CONNECTED || !ws_client_connected()) return;   // wynik i tak idzie po WS
    unsigned long now = millis();
    if ((long)(now - s_next) < 0) return;
    NetJob nj{};
    nj.src = NW_WIFIENV;
    strlcpy(nj.job.kind, "wenv", sizeof(nj.job.kind));
    if (net_worker_enqueue(nj, false)) s_inflight = true;
    else s_next = now + 60000UL;                  // wór pełny — za minutę
}

// NA WORZE: skan + top-8 + hashowanie + gotowa ramka WS do s_frame.
void wifi_env_run_scan(NetResult& out) {
    WiFi.scanDelete();
    WiFi.scanNetworks(true);
    int n = WIFI_SCAN_RUNNING;
    unsigned long t0 = millis();
    while ((n = WiFi.scanComplete()) == WIFI_SCAN_RUNNING && millis() - t0 < 30000UL)
        vTaskDelay(pdMS_TO_TICKS(200));
    if (n <= 0) { WiFi.scanDelete(); out.res.ok = false; return; }

    // Top-N po RSSI przez selekcję indeksów (n bywa 20+, ale WIFI_ENV_TOP małe — O(n*top)).
    int idx[WIFI_ENV_TOP]; int m = 0;
    for (int pick = 0; pick < WIFI_ENV_TOP; pick++) {
        int best = -1;
        for (int i = 0; i < n; i++) {
            bool used = false;
            for (int u = 0; u < m; u++) if (idx[u] == i) { used = true; break; }
            if (used) continue;
            if (best < 0 || WiFi.RSSI(i) > WiFi.RSSI(best)) best = i;
        }
        if (best < 0) break;
        idx[m++] = best;
    }

    int p = snprintf(s_frame, sizeof(s_frame), "{\"type\":\"wifi_env\",\"n\":[");
    for (int u = 0; u < m; u++) {
        int i = idx[u];
        char hb[17], hs[17];
        const uint8_t* bssid = WiFi.BSSID(i);
        if (!bssid) continue;
        hash16(bssid, 6, hb);
        // SSID: tylko trim spacji brzegowych — bez agresywnej normalizacji (sklejałaby różne sieci).
        String ss = WiFi.SSID(i); ss.trim();
        hash16((const uint8_t*)ss.c_str(), ss.length(), hs);
        p += snprintf(s_frame + p, sizeof(s_frame) - p, "%s{\"b\":\"%s\",\"s\":\"%s\",\"r\":%d}",
                      u ? "," : "", hb, hs, (int)WiFi.RSSI(i));
        if (p >= (int)sizeof(s_frame) - 48) break;   // margines na domknięcie
    }
    snprintf(s_frame + p, sizeof(s_frame) - p, "]}");
    WiFi.scanDelete();
    out.res.ok = true;
    out.res.samples = m;
    LOGD("wenv", "%d/%d sieci w %lums", m, n, millis() - t0);
}

// W LOOP: wynik z wora → wysyłka po WS. Porażka/pusto → ponów za godzinę, nie za 6h.
void wifi_env_on_net_result(const NetResult& nr) {
    s_inflight = false;
    if (nr.res.ok && nr.res.samples > 0 && ws_client_connected()) {
        ws_client_send_raw(s_frame);
        s_next = millis() + WIFI_ENV_EVERY_MS;
        LOGI("wenv", "fingerprint wyslany (%d sieci)", nr.res.samples);
    } else {
        s_next = millis() + 3600000UL;
    }
}
