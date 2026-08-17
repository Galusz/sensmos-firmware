/**
 * SENSMOS Firmware — Data Sender
 * Wysyła batch przez WS co 1-3 min.
 * WiFi scan jest asynchroniczny (nie blokuje pętli).
 */
#include "data_sender.h"
#include "config.h"
#include "entity_store.h"
#include "identity.h"
#include "ble_config.h"
#include "wifi_manager.h"
#include "ntp_time.h"
#include "ws_client.h"
#include "net_worker.h"
#include "monitors.h"
#include "log.h"
#include <ArduinoJson.h>
#include <WiFi.h>
#include <esp_random.h>

#define MIN_SEND_INTERVAL   BATCH_MIN_INTERVAL_MS
#define FORCE_SEND_INTERVAL BATCH_FORCE_INTERVAL_MS

char g_tx_scratch[TX_SCRATCH_LEN];   // współdzielony bufor TX (batch + checknet results, loop-only)

// Znacznik wersji CZYTELNY Z SAMEGO .bin. Panel OTA kazał człowiekowi wpisywać wersję
// z pamięci, choć siedzi ona w binarce — dwa źródła prawdy o jednym fakcie, i to człowiek
// był tym zawodnym. Teraz BE wyciąga ją z pliku, a pole w panelu tylko pokazuje.
// Samo `used` NIE wystarcza: dziala na kompilator, a rdzen ESP32 linkuje z --gc-sections,
// ktory i tak wycina nieuzywana sekcje. Zywe odwolanie przez volatile w data_sender_init()
// (nizej) jest jedynym wariantem dzialajacym niezaleznie od wersji GCC — `retain` wymaga 11+.
__attribute__((used)) const char FW_VERSION_TAG[] = "SENSMOS_FW_VERSION=" FW_VERSION "=END";

static unsigned long g_last_send    = 0;
static unsigned long g_last_mon     = 0;         // ramka telemetrii mon.* (osobny cykl od batcha)
static unsigned long g_last_ping    = 0;         // periodyczny heartbeat (heap + metryki wora)
static bool          g_pending_send = false;
static int           g_last_nets    = 0;         // cache wifi scan (nie blokuje)
static unsigned long g_last_scan    = 0;
// Skan WiFi: karmi TYLKO mon.wifi_nets (liczba sieci w okolicy — zmienia sie rzadko).
// Wykonywany NA WORZE (NW_SYSTEM): driver trzyma ~34KB przez ~7s skanu i skacze po
// kanalach — serializacja z TLS eliminuje kolizje (DEFER-y) niezaleznie od cadence.
#define SCAN_INTERVAL   (10UL * 60 * 1000)       // skan co 10 min
#define BASICS_INTERVAL (30UL * 1000)            // encje rssi/nets/uptime co 30s

// Heartbeat: heap + metryki saturacji wora (q_lag/q_busy/q_depth/q_wait) → admission w BE
// (ASYNC-QUEUE §10). Integralność/autentyczność ramki zapewnia enc (tag GCM) — bez podpisów/nonce.
void data_sender_send_ping() {
    if (!ws_client_connected()) return;
    uint16_t qw = 0, qd = 0; uint8_t qb = 0;
    net_worker_stats(&qw, &qb, &qd);
    char buf[256];
    snprintf(buf, sizeof(buf),
             "{\"type\":\"ping\",\"device_id\":\"%s\",\"free\":%u,\"largest\":%u,"
             "\"q_lag\":%.2f,\"q_busy\":%u,\"q_depth\":%u,\"q_wait\":%u}",
             g_device_id,
             (unsigned)ESP.getFreeHeap(), (unsigned)ESP.getMaxAllocHeap(),
             monitors_qlag(), (unsigned)qb, (unsigned)qd, (unsigned)qw);
    ws_client_send_raw(buf);
}

// ── Podstawowe metryki noda → mon.* (telemetria, osobna ramka) ─
static void push_basics() {
    char val[32];
    snprintf(val, sizeof(val), "%d",  WiFi.RSSI());
    entity_push("mon.wifi_rssi", val, "dBm");
    snprintf(val, sizeof(val), "%d",  g_last_nets);
    entity_push("mon.wifi_nets", val, "");
    snprintf(val, sizeof(val), "%lu", millis() / 1000);
    entity_push("mon.uptime_s",  val, "s");
}

// ── WiFi scan (job na worze) + odświeżanie encji bazowych ─────
static unsigned long g_last_basics = 0;
static void update_wifi_scan() {
    unsigned long now = millis();
    // encje rssi/nets/uptime niezależnie od skanu (batch co 1-3 min musi mieć świeże)
    if (now - g_last_basics >= BASICS_INTERVAL) { g_last_basics = now; push_basics(); }

    if (g_last_scan != 0 && now - g_last_scan < SCAN_INTERVAL) return;   // 0 = 1. skan zaraz po boot
    g_last_scan = now;
    NetJob nj; memset(&nj, 0, sizeof(nj));
    nj.src = NW_SYSTEM;
    strlcpy(nj.job.kind, "scan", sizeof(nj.job.kind));
    net_worker_enqueue(nj, false);   // lo-prio; pełna kolejka → trudno, za 10 min
}

// Wynik skanu z wora (dispatch w loop)
void data_sender_on_net_result(const NetResult& nr) {
    if (nr.res.ok) {
        g_last_nets = nr.res.samples;
        char val[16];
        snprintf(val, sizeof(val), "%d", g_last_nets);
        entity_push("mon.wifi_nets", val, "");
    }
}

// ── Budowa entities[]/user_data{} z buforów ───────────────────
static void build_entity_payload(JsonDocument& doc, int& pub_count, int& user_count) {
    entity_own_prune(OWN_TTL_S);   // zdejmij wiszące own.* zanim zbudujemy batch
    pub_count = user_count = 0;
    int count = entity_count();
    if (count == 0) return;

    JsonArray  pub_arr  = doc["entities"].to<JsonArray>();
    JsonObject user_obj = doc["user_data"].to<JsonObject>();
    char eid[36], ev[64], eu[16];   // eid >=36: entity_get kopiuje do 35 znakow (DataEntry.entity_id[36])
    unsigned long ets;

    for (int i = 0; i < count; i++) {
        entity_get(i, eid, ev, eu, &ets);

        // Natywne encje — sprawdź listę z BE (entity_is_native) zamiast hardcode
        // Strip ewentualnych pub. prefixów przed sprawdzeniem
        char base_eid[32] = {0};
        const char* src = eid;
        while (strncmp(src, "pub.", 4) == 0) src += 4;
        strncpy(base_eid, src, sizeof(base_eid)-1);

        const bool is_native_eid = entity_is_native(base_eid);
        const bool has_pub_prefix = (strncmp(eid, "pub.", 4) == 0);

        // Odrzuć pub.coś jeśli nie jest natywną — ktoś próbuje podszyć się pod natywną
        if (has_pub_prefix && !is_native_eid) continue;

        char pub_eid[36] = {0};
        if (is_native_eid && !has_pub_prefix)
            snprintf(pub_eid, sizeof(pub_eid), "pub.%s", base_eid);
        const char* send_eid = (is_native_eid && !has_pub_prefix) ? pub_eid : eid;

        if (strncmp(eid, "pub.", 4) == 0 || is_native_eid) {
            JsonObject e   = pub_arr.add<JsonObject>();
            e["entity_id"] = send_eid;
            e["value"]     = ev;
            e["unit"]      = eu;
            if (ntp_synced()) {
                uint32_t now_s = millis() / 1000;
                e["last_updated"] = (now_s >= ets)
                    ? ntp_unix_time() - (now_s - ets)
                    : ntp_unix_time();
            } else {
                e["last_updated"] = ets;
            }
            pub_count++;
        } else if (strncmp(eid, "own.", 4) == 0) {
            // own.* → user_data w batchu
            const char* key = eid + 4;  // strip "own."
            user_obj[key] = ev;
            user_count++;
        }
        // sub.*/tmp.* (pool) — NIE relayujemy do BE. Dane subskrybowane/lokalne (HA, skrypty).
        // Inaczej eid+4 obcina "sub." → gole native w soft_data (prefix ginie + kolizja z wlasnymi
        // wifi/uptime), a przy wzajemnych subach nodow robi sie petla relayowania.
    }
}

// ── Batch ─────────────────────────────────────────────────────
static void send_batch() {
    if (!g_wifi_connected) return;
    if (!ws_client_connected()) {
        LOGD("net", "batch skipped — WS down");
        g_last_send = millis();  // cooldown — nie spamuj prób co tick
        return;
    }

    push_basics();

    // Buduj JSON (doc = jedna alokacja/batch, zwalniana czysto; serializacja do STAŁEGO
    // bufora zamiast String → koniec realloc-churnu, który najbardziej fragmentował stertę)
    JsonDocument doc;
    // Zawsze "batch" — telemetria wyprowadziła się do mon[], więc goły node ma entity_count()==0.
    // "ping" NIE woła record_ping w BE → ping_count < MIN_PINGS_PER_EPOCH = 0 GALU i offline na mapie.
    doc["type"] = "batch";
    doc["device_id"]     = g_device_id;
    doc["owner_address"] = g_owner_address;
    doc["timestamp"]     = ntp_synced() ? ntp_unix_time() : (uint32_t)(millis() / 1000);
    doc["firmware"]      = FW_VERSION;
    // Batch NIE jest już podpisywany ECDSA — autentyczność/integralność daje enc (tag GCM na ramce).
    // Lokalizacja: NIE wysyłamy w batchu — źródłem prawdy jest BE (setAppLocation),
    // apka podaje GPS przez POST /config -> WS node_config.

    int pub_count  = 0;
    int user_count = 0;
    build_entity_payload(doc, pub_count, user_count);

    // Jedna serializacja do współdzielonego scratcha (loop-only, patrz data_sender.h); enc owija w ws_client.
    char* final_payload = g_tx_scratch;
    size_t flen = serializeJson(doc, final_payload, TX_SCRATCH_LEN);

    g_last_send = millis();  // PRZED overflow-checkiem: inaczej przepełniony batch jest
                             // przebudowywany ~100x/s w nieskończoność (bez cooldownu)
    if (flen == 0 || flen >= TX_SCRATCH_LEN) { LOGW("net", "batch payload overflow — skipped"); return; }

    if (ws_client_send_raw(final_payload)) {
        LOGD("net", "batch sent %uB (pub:%d user:%d)", (unsigned)flen, pub_count, user_count);
        g_pending_send = false;
    } else {
        LOGW("net", "batch send failed — retry after cooldown");
    }
}

// ── Ramka telemetrii NET (mon.*) ──────────────────────────────
// WŁASNY typ "mon_batch": handleBatch w BE robi saveSoftData(replace:true), więc wysłanie
// telemetrii jako zwykły "batch" kasowałoby own.* usera co cykl.
// Nie używa build_entity_payload — tamto strippuje tylko "pub." i iteruje po entity_get().
static void send_mon_batch() {
    if (!g_wifi_connected) return;
    if (!ws_client_connected()) {
        LOGD("net", "mon skipped — WS down");
        g_last_mon = millis();  // cooldown — nie spamuj prób co tick
        return;
    }

    int n = entity_mon_count();
    if (n == 0) return;

    JsonDocument doc;
    doc["type"]          = "mon_batch";
    doc["device_id"]     = g_device_id;
    doc["owner_address"] = g_owner_address;
    doc["timestamp"]     = ntp_synced() ? ntp_unix_time() : (uint32_t)(millis() / 1000);
    doc["firmware"]      = FW_VERSION;

    JsonArray arr = doc["entities"].to<JsonArray>();
    char eid[36] = {0}, ev[64] = {0}, eu[16] = {0};
    unsigned long ets;
    for (int i = 0; i < n; i++) {
        if (!entity_get_mon(i, eid, ev, eu, &ets)) continue;
        JsonObject e = arr.add<JsonObject>();
        e["entity_id"] = eid;   // Z prefiksem "mon." — BE go zdejmuje przed zapisem
        e["value"]     = ev;
        e["unit"]      = eu;
        if (ntp_synced()) {
            uint32_t now_s = millis() / 1000;
            e["last_updated"] = (now_s >= ets)
                ? ntp_unix_time() - (now_s - ets)
                : ntp_unix_time();
        } else {
            e["last_updated"] = ets;
        }
    }

    size_t flen = serializeJson(doc, g_tx_scratch, TX_SCRATCH_LEN);

    g_last_mon = millis();  // PRZED overflow-checkiem (patrz send_batch)
    if (flen == 0 || flen >= TX_SCRATCH_LEN) { LOGW("net", "mon payload overflow — skipped"); return; }

    if (ws_client_send_raw(g_tx_scratch)) {
        LOGD("net", "mon sent %uB (%d)", (unsigned)flen, n);
    } else {
        LOGW("net", "mon send failed — retry after cooldown");
    }
}

// ── API ───────────────────────────────────────────────────────
void data_sender_init() {
    // Trzyma znacznik wersji w binarce (patrz FW_VERSION_TAG). Volatile, wiec linker nie
    // moze uznac odwolania za martwe i wyciac napisu — BE czyta go wprost z pliku .bin,
    // zeby panel OTA nie musial pytac czlowieka o wersje.
    static const char* volatile fwtag = FW_VERSION_TAG;
    (void)fwtag;

    g_last_send    = 0;
    // Pierwsza ramka mon ~90s po boot: w przeciwfazie do batcha i już po 1. checknecie (45-65s)
    g_last_mon     = millis() - (MON_INTERVAL_MS / 2);
    g_pending_send = false;
    // Skan startowy pojedzie przez wór przy 1. ticku (g_last_scan=0 → od razu enqueue).
    // Wypełnij bufor od razu żeby skrypty miały dane przy pierwszym ticku
    push_basics();
}

void data_sender_trigger() { g_pending_send = true; }

void data_sender_fetch_entities() {
    // Entities są ładowane przez WS w ws_client.cpp — stub
}

void data_sender_update_basics() {
    // Aktualizowane przy każdym send_batch() — nie potrzeba osobno
}

void data_sender_tick() {
    update_wifi_scan();
    unsigned long now = millis();
    // K3: periodyczny ping z nonce (heartbeat) — rotuje nonce u BE, ogranicza okno replay.
    // Po pingu (świeży busy% z net_worker_stats) jedna linia [health].
    // Jedna ramka na iterację loop (wczesne return) — nie zalewaj WS trzema naraz.
    if (now - g_last_ping >= 60000UL) { g_last_ping = now; data_sender_send_ping(); log_health(); return; }
    bool cooldown = (now - g_last_send >= MIN_SEND_INTERVAL) || (g_last_send == 0);
    bool force    = (now - g_last_send >= FORCE_SEND_INTERVAL) || (g_last_send == 0);
    if ((g_pending_send && cooldown) || force) { send_batch(); return; }
    if (now - g_last_mon >= MON_INTERVAL_MS) send_mon_batch();
}
