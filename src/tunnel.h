#pragma once
#include <Arduino.h>
#include <ArduinoJson.h>

/**
 * SENSMOS — RemoteTerminal: głupia rura TCP z LAN-u noda do właściciela (przez BE relay).
 *
 * Node NIE rozumie SSH — tylko przepycha bajty między lokalnym socketem (np. 192.168.1.1:22)
 * a kanałem WS(enc) do BE, który relayuje do apki właściciela. Cała krypto SSH jest w apce (E2E).
 *
 * Bezpieczeństwo:
 *   - opt-in per node: NVS `remote_ok` (domyślnie FALSE) — bez niej node ODMAWIA otwarcia tunelu,
 *     nawet gdyby BE kazał. To lokalny bezpiecznik niezależny od BE.
 *   - owner-only egzekwuje BE (apka uwierzytelniona jako właściciel); node ufa BE przez enc.
 *   - tylko zakresy PRYWATNE (RFC1918/CGNAT) — nigdy publiczny internet (żeby flota nie była proxy).
 *
 * Wątkowość: osobny task dotyka WYŁĄCZNIE socketu LAN. Bajty do/z WS lecą przez kolejki, a całe
 * ws.send() zostaje w loop() (tunnel_tick) — `ws` i bufor enc są loop-only.
 *
 * Zero footprintu (0.72, on-demand): przełącznik remote to czysta polityka. Podsystem (~27KB)
 * wstaje dopiero przy tun_open i oddaje RAM po sesji (linger 2 min) lub przy disable.
 */

// Wołane z setup() — czyta tylko flagę NVS (zero alokacji). Idempotentne.
void tunnel_init();

// Wołane co pętlę z loop() — drenuje bajty LAN→BE i wysyła jako tun_data (kontekst loop = WS-safe).
// No-op gdy podsystem nie wystartował.
void tunnel_tick();

// Dispatch z ws_client (kontekst loop): komendy od BE po kanale enc.
void tunnel_on_open (int tid, const char* ip, int port);   // tun_open
void tunnel_on_data (int tid, const char* b64);            // tun_data (BE→LAN)
void tunnel_on_close(int tid);                             // tun_close
void tunnel_set_enabled(bool on);                          // tun_cfg {enable} — zapis NVS (polityka); OFF ubija sesję+RAM

// Czy remote access włączony (raportowane do BE w identify → dobór nodów do monitorów go omija).
bool tunnel_enabled();

// Czy TERAZ jest aktywna sesja tunelu (socket LAN otwarty). Scheduler checknet usypia się na
// czas sesji, a monitory/sondy odraczają cykl przy niskim heapie (0.68: A/B — ochrona terminala).
bool tunnel_active();
