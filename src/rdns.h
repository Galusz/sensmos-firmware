#pragma once
#include <Arduino.h>

// Reverse DNS (PTR) — ręczne zapytanie UDP do resolvera z DHCP (lwIP nie umie PTR).
// Użycie: hostname ostatniego hopa trace → walidacja ccTLD vs kraj peera (checknet).
// Blokujące (max timeout_ms) — wołać TYLKO z net_workera. Zero malloc, zero TLS.
// ip_netorder: adres w network order (jak TrHop.ip). Zwraca true + hostname w out.
bool rdns_ptr(uint32_t ip_netorder, char* out, size_t outlen, uint32_t timeout_ms);
