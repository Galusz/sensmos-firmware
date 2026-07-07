#pragma once
#include <Arduino.h>

// Traceroute v2 (v0.37) — ICMP echo z rosnącym TTL na LWIP **raw API**.
// Poprzednia wersja (v0.8, BSD-sockets, socket+close per trace) ciekła ~3.8KB/trace:
// pbufy zakolejkowane w recvmbox socketa ginęły przy close(). Teraz: JEDEN statyczny
// raw_pcb tworzony raz przy init i NIGDY nie zamykany (cała klasa leak-on-close
// wyeliminowana projektem), pbufy zwalniane jawnie w recv-callbacku, operacje na pcb
// przez tcpip_callback (wątek tcpip — poprawne niezależnie od core-lockingu),
// zero malloc w pętli. Callback zjada WYŁĄCZNIE nasze pakiety (id=TR_ID) —
// echo/time-exceeded esp_pinga przechodzą dalej nietknięte.

struct TrHop {
    uint8_t  ttl;
    uint32_t ip;      // 0 = timeout na tym TTL (router nie odpowiedział)
    float    ms;      // -1 przy timeoucie
};

void traceroute_init();                     // twórz statyczny pcb (wołaj raz, po WiFi)
// Blokujące (max_hops × per_hop_ms; early-exit gdy cel osiągnięty). Zwraca liczbę
// wpisów w hops[]; *reached=true gdy doszło echo-reply od celu.
int  traceroute_run(const char* host, TrHop* hops, int max_hops,
                    uint32_t per_hop_ms, bool* reached);
