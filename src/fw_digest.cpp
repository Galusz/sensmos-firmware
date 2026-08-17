#include "fw_digest.h"
#include "identity.h"
#include "ws_client.h"
#include "ws_enc.h"
#include "http_internal.h"
#include "data_sender.h"   // FW_VERSION
#include "log.h"
#include <esp_ota_ops.h>
#include <esp_partition.h>
#include <mbedtls/sha256.h>

// ── (1) Odcisk STAŁY — do porównania przez usera z release'em, po LAN-ie ────────
bool fw_digest_app_sha(char out_hex[65]) {
    const esp_partition_t* p = esp_ota_get_running_partition();
    if (!p) return false;
    uint8_t sha[32];
    // Nasze obrazy mają hash_appended=1 → to zwraca doklejone 32 B z końca .bin,
    // NIE sha256 całego pliku. IDF weryfikuje spójność przed zwrotem (ESP_ERR_IMAGE_INVALID
    // przy uszkodzonym obrazie), więc to jest zarówno odcisk, jak i check integralności za darmo.
    if (esp_partition_get_sha256(p, sha) != ESP_OK) return false;
    bytes_to_hex(sha, 32, out_hex);
    return true;
}

// ── (2) Odcisk WYZWANIOWY — BE wskazuje okna, node czyta WŁASNY flash ──────────
// device_id wchodzi z tożsamości noda, NIGDY z parametru — inaczej jeden prawdziwy
// node mógłby liczyć „na kogoś innego" i służyć za wyrocznię dla dowolnej liczby fejków.
bool fw_digest_windows(const char* nonce, const FwdWin* win, int nwin,
                       char out_hex[65], uint32_t* took_us) {
    if (!nonce || !win || nwin <= 0 || nwin > FWD_MAX_WIN) return false;

    const esp_partition_t* p = esp_ota_get_running_partition();
    if (!p) return false;

    uint32_t total = 0;
    for (int i = 0; i < nwin; i++) {
        // Okno musi mieścić się w partycji — czytamy TYLKO flash aplikacji, nigdy poza nią.
        if (win[i].len == 0 || (uint64_t)win[i].off + win[i].len > p->size) return false;
        total += win[i].len;
    }
    if (total > FWD_MAX_BYTES) return false;

    uint32_t t0 = micros();
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);

    mbedtls_sha256_update(&ctx, (const uint8_t*)"sensmos-fwd1", 12);
    mbedtls_sha256_update(&ctx, (const uint8_t*)g_device_id, strlen(g_device_id));
    mbedtls_sha256_update(&ctx, (const uint8_t*)nonce, strlen(nonce));

    uint8_t buf[512];
    bool ok = true;
    for (int i = 0; i < nwin && ok; i++) {
        // Okno wchodzi do hasza RAZEM z zawartością — inaczej ktoś podstawiłby inne
        // offsety pod tę samą odpowiedź.
        uint32_t off_be = __builtin_bswap32(win[i].off), len_be = __builtin_bswap32(win[i].len);
        mbedtls_sha256_update(&ctx, (const uint8_t*)&off_be, 4);
        mbedtls_sha256_update(&ctx, (const uint8_t*)&len_be, 4);

        uint32_t off = win[i].off, left = win[i].len;
        while (left && ok) {
            uint32_t n = left > sizeof(buf) ? sizeof(buf) : left;
            if (esp_partition_read(p, off, buf, n) != ESP_OK) { ok = false; break; }
            mbedtls_sha256_update(&ctx, buf, n);
            off += n; left -= n;
        }
    }

    uint8_t h[32];
    mbedtls_sha256_finish(&ctx, h);
    mbedtls_sha256_free(&ctx);
    if (took_us) *took_us = micros() - t0;
    if (!ok) return false;

    bytes_to_hex(h, 32, out_hex);
    return true;
}

// ── Handler WS: {"type":"fw_digest","nonce":"<hex>","win":[[off,len],...]} ─────
// Ramka jest już uwierzytelniona tagiem GCM sesji ws_enc — dokładanie tu podpisu
// ECDSA nie dodałoby ani bitu bezpieczeństwa, tylko koszt czasu i stosu.
void fw_digest_on_ws(JsonDocument& doc) {
    // Ten sam wzorzec co OTA (ota.cpp): poza szyfrowaną sesją komenda jest ignorowana.
    if (!ws_enc_active()) { LOGW("fwd", "cmd outside encryption — rejected"); return; }
    const char* nonce = doc["nonce"] | "";
    JsonArray   wins   = doc["win"].as<JsonArray>();
    if (!*nonce || wins.isNull() || wins.size() == 0 || wins.size() > FWD_MAX_WIN) {
        LOGW("fwd", "bad request — ignored");
        return;
    }

    FwdWin win[FWD_MAX_WIN];
    int n = 0;
    for (JsonVariant v : wins) {
        if (n >= FWD_MAX_WIN) break;
        JsonArray pair = v.as<JsonArray>();
        if (pair.size() != 2) continue;
        win[n].off = pair[0].as<uint32_t>();
        win[n].len = pair[1].as<uint32_t>();
        n++;
    }

    char hash_hex[65] = {0};
    uint32_t took_us = 0;
    bool ok = fw_digest_windows(nonce, win, n, hash_hex, &took_us);

    char resp[256];
    int len = snprintf(resp, sizeof(resp),
        "{\"type\":\"fwd_resp\",\"nonce\":\"%s\",\"fw\":\"%s\",\"chip\":\"%s\",\"ok\":%s",
        nonce, FW_VERSION, FWD_CHIP, ok ? "true" : "false");
    if (ok) len += snprintf(resp + len, sizeof(resp) - len,
        ",\"d\":\"%s\",\"us\":%lu", hash_hex, (unsigned long)took_us);
    snprintf(resp + len, sizeof(resp) - len, "}");

    ws_client_send_raw(resp);
    LOGI("fwd", "digest nonce=%.8s… ok=%d us=%lu", nonce, ok, (unsigned long)took_us);
}

// ── GET /fw/verify — lokalnie, BEZ PIN-u ───────────────────────────────────────
// Odpowiedź nie ujawnia niczego prywatnego (hash publicznego obrazu aplikacji),
// a wymóg PIN-u zabiłby cały sens „user sprawdza sam z przeglądarki, bez pytania
// naszego serwera o cokolwiek".
static void handle_fw_verify() {
    char app_sha[65];
    bool ok = fw_digest_app_sha(app_sha);

    JsonDocument d;
    d["device_id"] = g_device_id;
    d["firmware"]  = FW_VERSION;
    d["chip"]      = FWD_CHIP;
    d["ok"]        = ok;
    if (ok) d["app_sha"] = app_sha;
    // Jawna instrukcja w samej odpowiedzi — user nie musi znać żadnego innego dokumentu,
    // żeby wiedzieć, z czym porównać.
    d["compare_with"] = "sha256 of the appended-hash field in the published .bin: "
        "head -c $(($(stat -c%s FILE.bin)-32)) FILE.bin | sha256sum";

    String out; serializeJson(d, out);
    server.send(ok ? 200 : 500, "application/json", out);
}

void register_fw_digest_routes() {
    server.on("/fw/verify", HTTP_GET, handle_fw_verify);
}
