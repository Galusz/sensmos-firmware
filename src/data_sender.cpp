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
#include <ArduinoJson.h>
#include <WiFi.h>
#include <esp_random.h>

#define MIN_SEND_INTERVAL   BATCH_MIN_INTERVAL_MS
#define FORCE_SEND_INTERVAL BATCH_FORCE_INTERVAL_MS

static unsigned long g_last_send    = 0;
static unsigned long g_last_ping    = 0;         // K3: periodyczny ping z nonce (heartbeat)
static bool          g_pending_send = false;
static int           g_last_nets    = 0;         // cache wifi scan (nie blokuje)
static unsigned long g_last_scan    = 0;
#define SCAN_INTERVAL (30UL * 1000)              // skanuj sieci co 30s

// K3: heartbeat-nonce (anti-replay, stateless). Node publikuje świeży nonce w identify + periodycznym
// pingu. BE zapamiętuje ostatni i podpisuje nim komendy BE→node (reboot). Node akceptuje komendę tylko
// gdy nonce jest w historii ostatnich NONCE_HISTORY (okno wyścigu) i podpis BE OK. Po użyciu: nonce
// SPALONY (usunięty z historii → single-use) + wymuszony ping z nowym (BE od razu dostaje świeży).
#define NONCE_HISTORY 3
static char g_nonce_hist[NONCE_HISTORY][33] = {{0}};
static int  g_nonce_idx = 0;
static char g_cur_nonce[33] = {0};

const char* data_sender_new_nonce() {
    for (int i = 0; i < 16; i++) snprintf(g_cur_nonce + i * 2, 3, "%02x", (uint8_t)(esp_random() & 0xFF));
    g_cur_nonce[32] = 0;
    strncpy(g_nonce_hist[g_nonce_idx], g_cur_nonce, 33);
    g_nonce_idx = (g_nonce_idx + 1) % NONCE_HISTORY;
    return g_cur_nonce;
}
bool data_sender_nonce_valid(const char* nonce) {
    if (!nonce || !*nonce) return false;
    for (int i = 0; i < NONCE_HISTORY; i++)
        if (g_nonce_hist[i][0] && strcmp(g_nonce_hist[i], nonce) == 0) return true;
    return false;
}
void data_sender_burn_nonce(const char* nonce) {   // single-use: zużyty nonce znika z puli
    if (!nonce) return;
    for (int i = 0; i < NONCE_HISTORY; i++)
        if (strcmp(g_nonce_hist[i], nonce) == 0) g_nonce_hist[i][0] = 0;
}
// Ping z nowym nonce (heartbeat-nonce). Wołane: periodycznie (data_sender_tick) + wymuszane po użyciu komendy.
void data_sender_send_ping() {
    if (!ws_client_connected()) return;
    char buf[224];
    snprintf(buf, sizeof(buf),
             "{\"type\":\"ping\",\"device_id\":\"%s\",\"nonce\":\"%s\",\"free\":%u,\"largest\":%u}",
             g_device_id, data_sender_new_nonce(),
             (unsigned)ESP.getFreeHeap(), (unsigned)ESP.getMaxAllocHeap());
    ws_client_send_raw(buf);
}

// ── Podstawowe metryki noda → pub.* ───────────────────────────
static void push_basics() {
    char val[32];
    snprintf(val, sizeof(val), "%d",  WiFi.RSSI());
    entity_push("pub.wifi_rssi", val, "dBm");
    snprintf(val, sizeof(val), "%d",  g_last_nets);
    entity_push("pub.wifi_nets", val, "");
    snprintf(val, sizeof(val), "%lu", millis() / 1000);
    entity_push("pub.uptime_s",  val, "s");
}

// ── WiFi scan (asynchroniczny) ─────────────────────────────────
static void update_wifi_scan() {
    unsigned long now = millis();
    if (now - g_last_scan < SCAN_INTERVAL) return;
    g_last_scan = now;

    int n = WiFi.scanComplete();
    if (n == WIFI_SCAN_FAILED || n == WIFI_SCAN_RUNNING) {
        WiFi.scanNetworks(true);  // async
    } else {
        g_last_nets = (n > 0) ? n : 0;
        WiFi.scanDelete();
        WiFi.scanNetworks(true);  // zacznij kolejny async
    }

    // Aktualizuj encje w buforze na bieżąco (dostępne przez /data/status i skrypty)
    push_basics();
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
        Serial.println("[Sender] WS niedostępny — batch pominięty");
        g_last_send = millis();  // cooldown — nie spamuj prób co tick
        return;
    }

    push_basics();

    // Buduj JSON (doc = jedna alokacja/batch, zwalniana czysto; serializacja do STAŁEGO
    // bufora zamiast String → koniec realloc-churnu, który najbardziej fragmentował stertę)
    JsonDocument doc;
    doc["type"] = (entity_count() > 0) ? "batch" : "ping";
    doc["device_id"]     = g_device_id;
    doc["owner_address"] = g_owner_address;
    doc["timestamp"]     = ntp_synced() ? ntp_unix_time() : (uint32_t)(millis() / 1000);
    doc["firmware"]      = FW_VERSION;
    // Dane plytki (raz zbudowane): model/rev/MHz/flash — BE zapisuje do devices.chip;
    // pozwala korelowac czasy TLS/probe z konkretnym sprzetem we flocie
    static char s_chip[48] = {0};
    if (!s_chip[0])
        snprintf(s_chip, sizeof(s_chip), "%s r%d @%luMHz %luMB",
                 ESP.getChipModel(), (int)ESP.getChipRevision(),
                 (unsigned long)ESP.getCpuFreqMHz(),
                 (unsigned long)(ESP.getFlashChipSize() / (1024UL*1024UL)));
    doc["chip"] = s_chip;
    // K3: nonce NIE w batchu — jest w identify + periodycznym pingu (data_sender_send_ping)
    // Lokalizacja: NIE wysyłamy w batchu — źródłem prawdy jest BE (setAppLocation),
    // apka podaje GPS przez POST /config -> WS node_config.

    int pub_count  = 0;
    int user_count = 0;
    build_entity_payload(doc, pub_count, user_count);

    // Podpisz batch — serializacja do stałego bufora (alloc raz w .bss)
    static char payload[2600];
    size_t plen = serializeJson(doc, payload, sizeof(payload));
    if (plen == 0 || plen >= sizeof(payload)) { Serial.println("[Sender] payload overflow — pominięto"); return; }
    uint8_t hash[32];
    sha256_string(payload, hash);
    uint8_t sig[72];
    size_t  sig_len = 0;
    if (!identity_sign(hash, sig, &sig_len)) {
        Serial.println("[Sender] Błąd podpisywania!");
        return;
    }
    char sig_hex[145];
    bytes_to_hex(sig, sig_len, sig_hex);
    doc["signature"] = sig_hex;

    static char final_payload[2800];
    size_t flen = serializeJson(doc, final_payload, sizeof(final_payload));
    if (flen == 0 || flen >= sizeof(final_payload)) { Serial.println("[Sender] final overflow — pominięto"); return; }

    Serial.printf("[Sender] Batch: %u B | pub:%d user:%d\n",
        (unsigned)flen, pub_count, user_count);

    g_last_send = millis();  // zawsze — cooldown licz od próby, nie od sukcesu
    if (ws_client_send_raw(final_payload)) {
        Serial.println("[Sender] Batch → WS ✓");
        g_pending_send = false;
    } else {
        Serial.println("[Sender] Batch → WS ✗ (retry za cooldown)");
    }
}

// ── API ───────────────────────────────────────────────────────
void data_sender_init() {
    g_last_send    = 0;
    g_pending_send = false;
    WiFi.scanNetworks(true);  // start async scan
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
    // K3: periodyczny ping z nonce (heartbeat) — rotuje nonce u BE, ogranicza okno replay
    if (now - g_last_ping >= 60000UL) { g_last_ping = now; data_sender_send_ping(); }
    bool cooldown = (now - g_last_send >= MIN_SEND_INTERVAL) || (g_last_send == 0);
    bool force    = (now - g_last_send >= FORCE_SEND_INTERVAL) || (g_last_send == 0);
    if ((g_pending_send && cooldown) || force) {
        send_batch();
    }
}
