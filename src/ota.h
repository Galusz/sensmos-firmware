#pragma once
#include <ArduinoJson.h>

// OTA po WS: BE wysyła {type:"ota", version, nonce, targets:{<chip>:{url,sha256,sig}}}.
// sig = BE_priv nad "ota:<nonce>:<sha256>:<version>" — parametry są częścią podpisu.
// Pobranie https (integralność przez podpisany sha256), zapis do nieaktywnego slotu,
// restart; po boocie bez WS w OTA_CONFIRM_TIMEOUT_MS → rollback na stary slot.
void ota_init();                       // boot: sprawdź czy to pierwszy start po OTA
void ota_tick();                       // potwierdzenie (WS online) albo rollback po timeoucie
void ota_handle(JsonDocument& doc);    // handler wiadomości WS "ota"
