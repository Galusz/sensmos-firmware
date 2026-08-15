#pragma once
#include <Arduino.h>
#include <ArduinoJson.h>

// ── Odcisk działającego firmware ─────────────────────────────────────────────
//
// Dwa różne skróty, dwa różne cele — NIE mylić:
//
//  1. fw_digest_app_sha()  — STAŁY odcisk obrazu aplikacji. Do porównania przez
//     UŻYTKOWNIKA z tym, co opublikowane przy release. Nie ma nonce, bo user
//     sprawdza własny node po LAN-ie i powtórzenie nie jest tu zagrożeniem.
//     UWAGA: to NIE jest sha256 pliku .bin. Nasze obrazy mają flagę hash_appended,
//     więc IDF zwraca doklejone na końcu 32 bajty = sha256(plik bez tych 32 bajtów).
//     Zweryfikowane na realnych binarkach 2026-08-14.
//
//  2. fw_digest_windows() — odcisk WYZWANIOWY dla BE. Wiąże losowy nonce, WŁASNE
//     device_id i wskazane okna flasha. device_id bierzemy z tożsamości noda, NIGDY
//     z payloadu — inaczej jedna prawdziwa płytka mogłaby posłużyć za wyrocznię
//     odpowiadającą za dowolną liczbę fejków.
//
// Okna wybiera BE ze SWOJEJ kopii binarki, więc firmware nie musi wiedzieć, gdzie
// kończy się obraz — czyta dokładnie to, co mu wskazano. Dlatego nie ma tu parsowania
// nagłówka ESP ani liczenia długości segmentów.

// Wariant płytki — ta sama logika co przy OTA, bo BE musi wiedzieć, KTÓRY obraz
// porównać (esp32s3 i esp32s3-n16r8 to dwa różne pliki).
#if CONFIG_IDF_TARGET_ESP32
  #define FWD_CHIP "esp32"
#elif CONFIG_IDF_TARGET_ESP32S3
  #ifdef CONFIG_SPIRAM_MODE_OCT
    #define FWD_CHIP "esp32s3-n16r8"
  #else
    #define FWD_CHIP "esp32s3"
  #endif
#elif CONFIG_IDF_TARGET_ESP32C3
  #define FWD_CHIP "esp32c3"
#elif CONFIG_IDF_TARGET_ESP32S2
  #define FWD_CHIP "esp32s2"
#elif CONFIG_IDF_TARGET_ESP32C6
  #define FWD_CHIP "esp32c6"
#else
  #define FWD_CHIP "esp32"
#endif

struct FwdWin { uint32_t off; uint32_t len; };

#define FWD_MAX_WIN    24          // okien na wyzwanie
#define FWD_MAX_BYTES  (256*1024)  // sufit sumy długości — żeby wyzwanie nie było DoS-em

// Zwraca false przy złych parametrach albo błędzie odczytu flasha.
bool fw_digest_windows(const char* nonce, const FwdWin* win, int nwin,
                       char out_hex[65], uint32_t* took_us);

bool fw_digest_app_sha(char out_hex[65]);

// Handler ramki WS {"type":"fw_digest", nonce, win:[[off,len],…]} — odsyła fwd_resp.
void fw_digest_on_ws(JsonDocument& doc);

// Rejestruje GET /fw/verify na lokalnym serwerze (bez PIN-u — zwraca publiczny hash).
void register_fw_digest_routes();
