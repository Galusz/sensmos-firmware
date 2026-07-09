#include "ota.h"
#include "config.h"
#include "identity.h"
#include "data_sender.h"   // FW_VERSION + nonce (valid/burn)
#include "ws_client.h"
#include "log.h"
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <Update.h>
#include <Preferences.h>
#include <mbedtls/sha256.h>

#if CONFIG_IDF_TARGET_ESP32
  #define OTA_CHIP "esp32"
#elif CONFIG_IDF_TARGET_ESP32S3
  #define OTA_CHIP "esp32s3"
#elif CONFIG_IDF_TARGET_ESP32C3
  #define OTA_CHIP "esp32c3"
#elif CONFIG_IDF_TARGET_ESP32S2
  #define OTA_CHIP "esp32s2"
#elif CONFIG_IDF_TARGET_ESP32C6
  #define OTA_CHIP "esp32c6"
#else
  #define OTA_CHIP "esp32"
#endif

#define NVS_NS_OTA "sensmos_ota"

static bool          s_confirm_armed = false;
static unsigned long s_boot_ms       = 0;

// ── Pobierz bin i zapisz do nieaktywnego slotu ────────────────
// sha256 liczony na streamie; commit slotu (Update.end) DOPIERO po zgodności hasha.
static bool ota_download_flash(const char* url, const char* sha_expect) {
    WiFiClientSecure sec;
    WiFiClient       plain;
    HTTPClient       http;
    bool https = !strncmp(url, "https://", 8);
    if (https) { sec.setInsecure(); if (!http.begin(sec, url)) return false; }
    else       {                    if (!http.begin(plain, url)) return false; }
    http.setTimeout(20000);

    int code = http.GET();
    if (code != 200) {
        LOGE("ota", "HTTP %d", code);
        http.end(); return false;
    }
    int len = http.getSize();
    if (len <= 0) { LOGE("ota", "no Content-Length"); http.end(); return false; }
    if (!Update.begin(len)) {
        LOGE("ota", "Update.begin: %s (bin %dB too big for slot?)", Update.errorString(), len);
        http.end(); return false;
    }

    mbedtls_sha256_context sha;
    mbedtls_sha256_init(&sha);
    mbedtls_sha256_starts(&sha, 0);

    WiFiClient* s = http.getStreamPtr();
    uint8_t buf[2048];
    size_t done = 0;
    unsigned long last_data = millis(), last_log = 0;
    while (done < (size_t)len) {
        size_t av = s->available();
        if (av) {
            int r = s->readBytes(buf, av > sizeof(buf) ? sizeof(buf) : av);
            if (r <= 0) break;
            mbedtls_sha256_update(&sha, buf, r);
            if (Update.write(buf, r) != (size_t)r) {
                LOGE("ota", "write: %s", Update.errorString());
                Update.abort(); http.end(); return false;
            }
            done += r; last_data = millis();
            if (millis() - last_log > 3000) {
                LOGI("ota", "downloading %u/%d KB", done / 1024, len / 1024);
                last_log = millis();
            }
        } else {
            if (!s->connected()) break;
            if (millis() - last_data > 20000) { LOGW("ota", "stall 20s"); break; }
            delay(1);
        }
        yield();
    }
    http.end();

    if (done != (size_t)len) {
        LOGE("ota", "incomplete download %u/%d", done, len);
        Update.abort(); return false;
    }
    uint8_t h[32]; char h_hex[65];
    mbedtls_sha256_finish(&sha, h);
    mbedtls_sha256_free(&sha);
    bytes_to_hex(h, 32, h_hex);
    if (strcasecmp(h_hex, sha_expect) != 0) {
        LOGE("ota", "sha256 mismatch (got %.16s want %.16s) — rejected", h_hex, sha_expect);
        Update.abort(); return false;
    }
    if (!Update.end(true)) {
        LOGE("ota", "Update.end: %s", Update.errorString());
        return false;
    }
    return true;
}

// ── Handler WS "ota" ──────────────────────────────────────────
void ota_handle(JsonDocument& doc) {
    const char* version = doc["version"] | "";
    const char* nonce   = doc["nonce"]   | "";
    JsonObject  t       = doc["targets"][OTA_CHIP];
    if (t.isNull()) { LOGD("ota", "no target for %s — ignored", OTA_CHIP); return; }
    const char* url     = t["url"]    | "";
    const char* sha     = t["sha256"] | "";
    const char* sig_hex = t["sig"]    | "";
    if (!*version || !*nonce || !*url || strlen(sha) != 64 || !*sig_hex) {
        LOGW("ota", "incomplete message — rejected"); return;
    }
    if (!strcmp(version, FW_VERSION)) { LOGD("ota", "already on %s — ignored", version); return; }
    if (!data_sender_nonce_valid(nonce)) { LOGW("ota", "stale nonce (replay?) — rejected"); return; }

    // Podpis BE nad parametrami: "ota:<nonce>:<sha256>:<version>"
    size_t sl = strlen(sig_hex) / 2;
    if (sl == 0 || sl > 80) return;
    uint8_t sig[80];
    for (size_t i = 0; i < sl; i++) { unsigned v; if (sscanf(sig_hex + i*2, "%2x", &v) != 1) return; sig[i] = (uint8_t)v; }
    char msg[160];
    snprintf(msg, sizeof(msg), "ota:%s:%s:%s", nonce, sha, version);
    if (!identity_verify_be(msg, sig, sl)) { LOGW("ota", "bad BE signature — rejected"); return; }
    data_sender_burn_nonce(nonce);

    LOGI("ota", "%s -> %s", FW_VERSION, version);
    if (!ota_download_flash(url, sha)) { LOGE("ota", "failed — staying on %s", FW_VERSION); return; }

    Preferences p; p.begin(NVS_NS_OTA, false);
    p.putString("pending", version);
    p.end();
    LOGI("ota", "ok — restarting into %s", version);
    delay(500);
    ESP.restart();
}

// ── Potwierdzenie po boocie / rollback ────────────────────────
void ota_init() {
    Preferences p; p.begin(NVS_NS_OTA, true);
    String pend = p.getString("pending", "");
    p.end();
    if (!pend.length()) return;
    if (pend == FW_VERSION) {
        s_confirm_armed = true;
        s_boot_ms = millis();
        LOGI("ota", "first boot %s — awaiting WS (%lus to rollback)",
             FW_VERSION, OTA_CONFIRM_TIMEOUT_MS / 1000UL);
    } else {
        // wersja inna niż pending → wcześniejszy rollback / stary slot; wyczyść flagę
        Preferences w; w.begin(NVS_NS_OTA, false); w.remove("pending"); w.end();
        LOGW("ota", "boot %s with pending=%s — flag cleared (rollback?)", FW_VERSION, pend.c_str());
    }
}

void ota_tick() {
    if (!s_confirm_armed) return;
    if (ws_client_connected()) {
        s_confirm_armed = false;
        Preferences p; p.begin(NVS_NS_OTA, false); p.remove("pending"); p.end();
        LOGI("ota", "%s confirmed (WS online)", FW_VERSION);
        return;
    }
    if (millis() - s_boot_ms > OTA_CONFIRM_TIMEOUT_MS) {
        s_confirm_armed = false;
        Preferences p; p.begin(NVS_NS_OTA, false); p.remove("pending"); p.end();
        LOGW("ota", "no WS after update — ROLLBACK to previous slot");
        if (Update.canRollBack()) { Update.rollBack(); delay(200); ESP.restart(); }
        else LOGE("ota", "rollback not possible — staying");
    }
}
