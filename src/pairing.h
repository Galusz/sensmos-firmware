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

// Który klucz podpisał `proof` = HMAC-SHA256(klucz, msg)? Zwraca indeks 0..n-1 albo -1.
// Porównanie stałoczasowe, bez wcześniejszego wyjścia — czas odpowiedzi nie zdradza, ile
// kluczy ma node ani który pasuje. Indeks jest potrzebny, bo tunel v2 szyfruje sesję
// kluczem TEGO telefonu, który ją otworzył (node trzyma do PAIR_MAX_KEYS kluczy).
int pairing_verify_idx(const char* msg, const uint8_t proof[32]);

// Klucz sesji tunelu v2: SHA256(klucz_parowania[idx] ‖ "sensmos-tun-v2").
// Osobny od HMAC-a dowodu (ten sam sekret, dwa różne zastosowania) i wyprowadzany lokalnie
// po obu stronach — nic się nie wymienia, BE nie ma jak go poznać. To JEDYNA droga, którą
// materiał klucza opuszcza ten moduł, i wychodzi już przemielony przez hash.
bool pairing_tun_key(int idx, uint8_t out[32]);
