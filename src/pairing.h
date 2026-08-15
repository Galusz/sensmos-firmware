#pragma once
#include <Arduino.h>

// ── Parowanie telefon↔node: klucz, którego BE NIGDY nie widzi ────────────────
//
// Po co: kanał WS BE↔node jest szyfrowany (ws_enc), ale klucz sesji to
// ECDH(node_priv, BE_pub) — BE potrafi go odtworzyć dla KAŻDEGO noda z samego
// pubkeya w bazie. Uwierzytelnia więc „rozmawiam z naszym BE", a nie „ten
// konkretny właściciel się zgodził". Skompromitowany serwer mógł otworzyć tunel
// do LAN-u dowolnego użytkownika i nic w firmwarze by go nie zatrzymało.
//
// Klucz parowania rozwiązuje to inaczej niż kolejne ECDH: telefon i node SPOTYKAJĄ
// SIĘ FIZYCZNIE w tej samej sieci, więc wystarczy kanał, którego BE nie widzi —
// lokalne HTTP po LAN (POST /node/pair za PIN-em). Sekret symetryczny wystarcza,
// bo obie strony wychodzą z parowania z tą samą wartością; HMAC jest przy tym
// tańszy na ESP32 niż operacje asymetryczne.
//
// POSIADANIE KLUCZA JEST UPRAWNIENIEM. Nie ma osobnej flagi „remote on/off" —
// sparowany = zdalny dostęp możliwy, brak klucza = nie da się zbudować ważnego
// dowodu, więc tunel jest nieotwieralny. Jedna prawda zamiast dwóch, które mogłyby
// się rozjechać. (Poprzednia flaga `remote_ok` udawała lokalny bezpiecznik, ale
// przestawiał ją wyłącznie BE ramką tun_cfg — czyli dokładnie ten, przed kim miała
// chronić.)

#define PAIR_KEY_LEN  32
#define PAIR_MAX_KEYS 4     // kilka telefonów w domu; najstarszy wypada przy przepełnieniu

void pairing_init();                                   // z setup(); wczytuje NVS
bool pairing_add(const uint8_t key[PAIR_KEY_LEN]);     // nowy klucz (duplikat = no-op)
void pairing_clear();                                  // koniec zdalnego dostępu
bool pairing_has_key();
int  pairing_count();

// Czy `proof` to HMAC-SHA256(którykolwiek_klucz, msg)? Porównanie stałoczasowe.
bool pairing_verify(const char* msg, const uint8_t proof[32]);
