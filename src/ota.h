#pragma once
#include <ArduinoJson.h>

// OTA po WS: BE wysyła {type:"ota", version, targets:{<chip>:{url,sha256}}}.
// AUTENTYCZNOŚĆ komendy = szyfrowana sesja WS (tag GCM) — bez enc handler odrzuca.
// INTEGRALNOŚĆ binarki = sha256 liczony na streamie, commit slotu dopiero po zgodności.
// NIE ma podpisu BE nad obrazem ani przypiętego klucza: sha256 pochodzi od BE, więc
// dowodzi tylko, że pobranie się nie uszkodziło, nie że firmware jest nasz. Weryfikacja
// podpisu (Ed25519/ECDSA, klucz w firmwarze) to osobny, jeszcze niezbudowany krok.
// Pobranie https, zapis do nieaktywnego slotu, restart; po boocie bez WS
// w OTA_CONFIRM_TIMEOUT_MS → rollback na stary slot.
void ota_init();                       // boot: sprawdź czy to pierwszy start po OTA
void ota_tick();                       // potwierdzenie (WS online) albo rollback po timeoucie
void ota_handle(JsonDocument& doc);    // handler wiadomości WS "ota"
