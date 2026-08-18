#pragma once
#include <Arduino.h>

// ── Autoryzator przystawek: node jako pośrednik zaufania ─────────────────────
//
// Po co: chcemy podpiąć obok noda sprzęt, który nodem nie jest i nie będzie —
// koncentrator LoRaWAN, odbiornik GNSS, cokolwiek dalej. Taki sprzęt nie ma
// atestacji BLE ani portfela, więc BE nie ma podstaw, żeby mu cokolwiek wierzyć.
// Ma za to jedną rzecz, której nie podrobi zdalny napastnik: STOI W LAN-IE
// WŁAŚCICIELA. To jest dokładnie ten sam argument, na którym opiera się parowanie
// telefonu (patrz pairing.h) — tylko druga strona jest inna.
//
// Node nie wydaje uprawnień sam. Przekazuje prośbę do BE po już uwierzytelnionym,
// szyfrowanym WS i oddaje przystawce to, co BE odeśle. PIN mówi „jesteś u mnie
// w domu", zgoda BE mówi „ten node istnieje i nie ma jeszcze kompletu przystawek".
// Żadne z tego osobno nie wystarcza.
//
// CELOWO BEZ NVS. Node jest kurierem, nie rejestrem — token przechowuje przystawka,
// a listę wydanych uprawnień trzyma BE (tam też się je odbiera). Restart płytki w
// trakcie ceremonii nic nie psuje: przystawka po prostu pyta jeszcze raz.
//
// Jedno zgłoszenie naraz. Parowanie jest czynnością człowieka przy sprzęcie, więc
// kolejka byłaby rozwiązaniem problemu, którego nie ma — a kosztowałaby RAM i stan.

enum ExtAuthState : uint8_t {
    EXT_AUTH_IDLE = 0,
    EXT_AUTH_PENDING,
    EXT_AUTH_GRANTED,
    EXT_AUTH_DENIED,
};

// Startuje ceremonię: wysyła ext_auth_req do BE i zapisuje `req` w buforze wywołującego.
// false = odmowa lokalna (brak WS, zgłoszenie w toku, za częste próby); powód w `err`.
bool ext_auth_begin(const char* kind, const char* name, const char* scopes_csv,
                    char* req_out, size_t req_len, const char** err);

// Stan zgłoszenia o podanym `req`. Nieznany identyfikator = EXT_AUTH_IDLE.
ExtAuthState ext_auth_state(const char* req);

const char* ext_auth_token();     // ważne tylko przy EXT_AUTH_GRANTED
const char* ext_auth_id();
uint32_t    ext_auth_exp();
const char* ext_auth_reason();    // powód przy EXT_AUTH_DENIED

// Z ws_client — odpowiedzi BE.
void ext_auth_on_grant(const char* req, const char* id, const char* token, uint32_t exp);
void ext_auth_on_deny (const char* req, const char* reason);

// Z loop() — pilnuje timeoutu i sprząta wydany token po odbiorze.
void ext_auth_tick();
