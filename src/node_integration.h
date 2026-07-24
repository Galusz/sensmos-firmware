#pragma once
#include <Arduino.h>

// ── Node Integration Webhook ──────────────────────────────────
// Webhook telemetryczny: zdarzenia noda (message/batch/sub) zbierane w kolejce, a 0.73 wysyłane
// ZBIORCZO co 60s jako JEDEN POST — i to NA WORZE (net_worker), więc pod bramką heapu i
// serializowane z resztą TLS (koniec autonomicznego drugiego TLS w kontekście loop).
// Konfiguracja: POST /config {"integration_url": "http://..."}

struct NetResult;   // net_worker.h (fwd)

void node_integration_init();
void node_integration_update();  // wywołaj z loop() — co 60s kolejkuje batch-job na worze

// Wypchnij zdarzenie do kolejki
void node_integration_push(const char* action, const char* payload_json);

// Wór: ciało batcha do POST (statyczny bufor, jeden job w locie) + zwrot wyniku
const char* node_integration_wor_body();
void        node_integration_on_result(const NetResult& nr);

// Konfiguracja
void   node_integration_set_url(const char* url);
String node_integration_get_url();
