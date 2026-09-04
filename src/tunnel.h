#pragma once
#include <Arduino.h>
#include <ArduinoJson.h>

/**
 * SENSMOS — RemoteTerminal: głupia rura TCP z LAN-u noda do właściciela (przez BE relay).
 *
 * Node NIE rozumie SSH — tylko przepycha bajty między lokalnym socketem (np. 192.168.1.1:22)
 * a kanałem WS(enc) do BE, który relayuje do apki właściciela. Cała krypto SSH jest w apce (E2E).
 *
 * Tunel v2 (1.01+): bajty są szyfrowane AES-256-GCM kluczem wyprowadzonym z KLUCZA PAROWANIA
 * (pairing_tun_key), którego BE nie zna i mieć nie może. Serwer widzi wyłącznie szyfrogram —
 * także dla paneli HTTP (HA, router), gdzie wcześniej przechodziły przez niego token i treść
 * stron. Ramka leci w binarnej kopercie WS_ENC_VER_TUN, więc znika JSON i base64: koniec
 * z +33% narzutu i budowaniem/parsowaniem dokumentu przy KAŻDEJ porcji 1 KB.
 *
 * Bezpieczeństwo:
 *   - opt-in per node: KLUCZ PAROWANIA (pairing.h), ustawiany wyłącznie po LAN za PIN-em.
 *     Brak klucza = node odmawia otwarcia, choćby BE kazał. To jedyny lokalny bezpiecznik,
 *     którego BE nie potrafi przestawić — poprzednia flaga `remote_ok` udawała taki bezpiecznik,
 *     ale przełączał ją sam BE ramką tun_cfg, czyli dokładnie ten, przed kim miała chronić.
 *   - tylko zakresy PRYWATNE (RFC1918/CGNAT) — nigdy publiczny internet (żeby flota nie była proxy).
 *
 * Wątkowość: osobny task dotyka WYŁĄCZNIE socketu LAN. Bajty do/z WS lecą przez kolejki, a całe
 * ws.send() zostaje w loop() (tunnel_tick) — `ws` i bufor enc są loop-only.
 *
 * Zero footprintu (0.72, on-demand): przełącznik remote to czysta polityka. Podsystem (~27KB)
 * wstaje dopiero przy tun_open i oddaje RAM po sesji (linger 2 min) lub przy disable.
 */

// Wołane z setup(). Zero alokacji — RAM wstaje dopiero przy tun_open. Idempotentne.
void tunnel_init();

// Wołane co pętlę z loop() — drenuje bajty LAN→BE i wysyła jako tun_data (kontekst loop = WS-safe).
// No-op gdy podsystem nie wystartował.
void tunnel_tick();

// Dispatch z ws_client (kontekst loop): komendy od BE po kanale enc.
// `key` = klucz sesji z pairing_tun_key (telefon, który otworzył tunel), `ts` = znacznik
// z tun_open — wchodzi do AAD, więc ramka jednej sesji nie przejdzie w innej.
void tunnel_on_open (int tid, const char* ip, int port, const uint8_t key[32], uint32_t ts);
void tunnel_on_data (int tid, const uint8_t* frame, size_t len);   // ramka v2 (BE→LAN)
void tunnel_on_close(int tid);                                     // tun_close

// Czy TERAZ jest aktywna sesja tunelu (socket LAN otwarty). Scheduler checknet usypia się na
// czas sesji, a monitory/sondy odraczają cykl przy niskim heapie (0.68: A/B — ochrona terminala).
bool tunnel_active();
