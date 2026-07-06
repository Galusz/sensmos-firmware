#include "ota.h"
#include "config.h"
#include "identity.h"
#include "data_sender.h"   // FW_VERSION + nonce (valid/burn)
#include "ws_client.h"
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
        Serial.printf("[OTA] HTTP %d\n", code);
        http.end(); return false;
    }
    int len = http.getSize();
    if (len <= 0) { Serial.println("[OTA] brak Content-Length"); http.end(); return false; }
    if (!Update.begin(len)) {
        Serial.printf("[OTA] Update.begin: %s (bin %d B nie mieści się w slocie?)\n",
                      Update.errorString(), len);
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
                Serial.printf("[OTA] write: %s\n", Update.errorString());
                Update.abort(); http.end(); return false;
            }
            done += r; last_data = millis();
            if (millis() - last_log > 3000) {
                Serial.printf("[OTA] %u/%d KB (free=%u)\n", done / 1024, len / 1024, ESP.getFreeHeap());
                last_log = millis();
            }
        } else {
            if (!s->connected()) break;
            if (millis() - last_data > 20000) { Serial.println("[OTA] stall 20s"); break; }
            delay(1);
        }
        yield();
    }
    http.end();

    if (done != (size_t)len) {
        Serial.printf("[OTA] niepełne pobranie %u/%d\n", done, len);
        Update.abort(); return false;
    }
    uint8_t h[32]; char h_hex[65];
    mbedtls_sha256_finish(&sha, h);
    mbedtls_sha256_free(&sha);
    bytes_to_hex(h, 32, h_hex);
    if (strcasecmp(h_hex, sha_expect) != 0) {
        Serial.printf("[OTA] sha256 MISMATCH (got %.16s… want %.16s…) — odrzucam\n", h_hex, sha_expect);
        Update.abort(); return false;
    }
    if (!Update.end(true)) {
        Serial.printf("[OTA] Update.end: %s\n", Update.errorString());
        return false;
    }
    return true;
}

// ── Handler WS "ota" ──────────────────────────────────────────
void ota_handle(JsonDocument& doc) {
    const char* version = doc["version"] | "";
    const char* nonce   = doc["nonce"]   | "";
    JsonObject  t       = doc["targets"][OTA_CHIP];
    if (t.isNull()) { Serial.printf("[OTA] brak targetu %s — pomijam\n", OTA_CHIP); return; }
    const char* url     = t["url"]    | "";
    const char* sha     = t["sha256"] | "";
    const char* sig_hex = t["sig"]    | "";
    if (!*version || !*nonce || !*url || strlen(sha) != 64 || !*sig_hex) {
        Serial.println("[OTA] niekompletna wiadomość — odrzucam"); return;
    }
    if (!strcmp(version, FW_VERSION)) { Serial.printf("[OTA] już na %s — pomijam\n", version); return; }
    if (!data_sender_nonce_valid(nonce)) { Serial.println("[OTA] nieświeży nonce (replay?) — odrzucam"); return; }

    // Podpis BE nad parametrami: "ota:<nonce>:<sha256>:<version>"
    size_t sl = strlen(sig_hex) / 2;
    if (sl == 0 || sl > 80) return;
    uint8_t sig[80];
    for (size_t i = 0; i < sl; i++) { unsigned v; if (sscanf(sig_hex + i*2, "%2x", &v) != 1) return; sig[i] = (uint8_t)v; }
    char msg[160];
    snprintf(msg, sizeof(msg), "ota:%s:%s:%s", nonce, sha, version);
    if (!identity_verify_be(msg, sig, sl)) { Serial.println("[OTA] zły podpis BE — odrzucam"); return; }
    data_sender_burn_nonce(nonce);

    Serial.printf("[OTA] %s → %s  %s  (free=%u largest=%u)\n", FW_VERSION, version, url,
                  (unsigned)ESP.getFreeHeap(), (unsigned)ESP.getMaxAllocHeap());
    if (!ota_download_flash(url, sha)) { Serial.println("[OTA] FAIL — zostaję na bieżącej"); return; }

    Preferences p; p.begin(NVS_NS_OTA, false);
    p.putString("pending", version);
    p.end();
    Serial.printf("[OTA] OK — restart do %s\n", version);
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
        Serial.printf("[OTA] Pierwszy boot %s — czekam na WS (%lus na rollback)\n",
                      FW_VERSION, OTA_CONFIRM_TIMEOUT_MS / 1000UL);
    } else {
        // wersja inna niż pending → wcześniejszy rollback / stary slot; wyczyść flagę
        Preferences w; w.begin(NVS_NS_OTA, false); w.remove("pending"); w.end();
        Serial.printf("[OTA] Boot %s przy pending=%s — flaga wyczyszczona (rollback?)\n",
                      FW_VERSION, pend.c_str());
    }
}

void ota_tick() {
    if (!s_confirm_armed) return;
    if (ws_client_connected()) {
        s_confirm_armed = false;
        Preferences p; p.begin(NVS_NS_OTA, false); p.remove("pending"); p.end();
        Serial.printf("[OTA] %s potwierdzone (WS online)\n", FW_VERSION);
        return;
    }
    if (millis() - s_boot_ms > OTA_CONFIRM_TIMEOUT_MS) {
        s_confirm_armed = false;
        Preferences p; p.begin(NVS_NS_OTA, false); p.remove("pending"); p.end();
        Serial.println("[OTA] Brak WS po aktualizacji — ROLLBACK na poprzedni slot");
        if (Update.canRollBack()) { Update.rollBack(); delay(200); ESP.restart(); }
        else Serial.println("[OTA] rollback niemożliwy — zostaję");
    }
}
