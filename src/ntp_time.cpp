/**
 * SENSMOS Firmware — NTP Time Sync
 * Używa wbudowanej biblioteki ESP32 configTime()
 * Serwery NTP: pool.ntp.org, time.google.com, time.cloudflare.com
 */
#include "ntp_time.h"
#include "log.h"
#include <time.h>
#include <WiFi.h>

#define NTP_SERVER1    "pool.ntp.org"
#define NTP_SERVER2    "time.google.com"
#define NTP_SERVER3    "time.cloudflare.com"
#define NTP_TIMEZONE   "UTC0"  // UTC — identyczny dla wszystkich nodów na świecie
#define NTP_TIMEOUT_MS 10000  // max 10s na sync

static bool          _synced       = false;
static unsigned long _last_sync_ms = 0;

#define NTP_RESYNC_INTERVAL_MS (24UL * 60 * 60 * 1000)  // resync co 24h

void ntp_init() {
    if (WiFi.status() != WL_CONNECTED) {
        LOGD("ntp", "no WiFi — skipping sync");
        return;
    }

    configTzTime(NTP_TIMEZONE, NTP_SERVER1, NTP_SERVER2, NTP_SERVER3);
    // UTC — konwersja na lokalny czas po stronie apki/frontendu

    // Czekaj na sync (max NTP_TIMEOUT_MS)
    unsigned long start = millis();
    struct tm timeinfo;
    while (!getLocalTime(&timeinfo, 1000)) {
        if (millis() - start > NTP_TIMEOUT_MS) { LOGW("ntp", "sync timeout"); return; }  // NTP_TIMEOUT_MS
    }

    _synced       = true;
    _last_sync_ms = millis();
    LOGI("ntp", "synced %04d-%02d-%02d %02d:%02d:%02d UTC",
        timeinfo.tm_year + 1900, timeinfo.tm_mon + 1, timeinfo.tm_mday,
        timeinfo.tm_hour, timeinfo.tm_min, timeinfo.tm_sec);
}

bool ntp_synced() { return _synced; }

uint32_t ntp_unix_time() {
    if (!_synced) return 0;
    return (uint32_t)time(nullptr);
}

String ntp_time_str() {
    if (!_synced) return "not synced";
    struct tm timeinfo;
    if (!getLocalTime(&timeinfo)) return "error";
    char buf[32];
    snprintf(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d:%02d",
        timeinfo.tm_year + 1900, timeinfo.tm_mon + 1, timeinfo.tm_mday,
        timeinfo.tm_hour, timeinfo.tm_min, timeinfo.tm_sec);
    return String(buf);
}

// Wywołuj w loop() — resync co 24h
void ntp_tick() {
    if (WiFi.status() != WL_CONNECTED) return;
    unsigned long now = millis();
    // Pierwszy sync lub resync po 24h
    if (_last_sync_ms == 0 || (now - _last_sync_ms >= NTP_RESYNC_INTERVAL_MS)) {
        struct tm timeinfo;
        if (getLocalTime(&timeinfo, 5000)) {
            _synced      = true;
            _last_sync_ms = now;
            LOGD("ntp", "resynced %04d-%02d-%02d %02d:%02d:%02d UTC",
                timeinfo.tm_year + 1900, timeinfo.tm_mon + 1, timeinfo.tm_mday,
                timeinfo.tm_hour, timeinfo.tm_min, timeinfo.tm_sec);
        } else {
            LOGW("ntp", "resync failed");
        }
    }
}