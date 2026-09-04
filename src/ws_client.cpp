#include "node_integration.h"
/**
 * SENSMOS Firmware — WebSocket Client
 * Połączenie z backendem, routing wiadomości.
 */
#include "ws_client.h"
#include "ota.h"
#include "entity_store.h"
#include "identity.h"
#include "ble_config.h"
#include "wifi_manager.h"
#include "subscription_map.h"
#include "http_server.h"
#include "node_log.h"
#include "message_router.h"
#include "checknet.h"
#include "checknow.h"
#include "punch.h"
#include "monitors.h"
#include "tunnel.h"
#include "lora_scan.h"
#include "pairing.h"
#include "ext_auth.h"
#include "ntp_time.h"   // okno świeżości dowodu przy tun_open
#include "fw_digest.h"
#include "data_sender.h"
#include "ws_enc.h"
#include "net_worker.h"   // WS-watchdog: sonda TCP jedzie na worze (istniejący cn_probe_tcp)
#include "mqtt_pub.h"     // most wiadomości Sensmos→MQTT/HA + stan WAN dla topiku net/wan
#include "log.h"
#include <ArduinoJson.h>
#include <WebSocketsClient.h>
#include <Preferences.h>   // WD: epizod awarii przezywa restart (dowod dla ISP-down)
#include <esp_random.h>

static WebSocketsClient ws;
static bool             g_ws_connected = false;
static unsigned long    g_last_reconnect = 0;
#define RECONNECT_INTERVAL 5000

// Nonce sesji wygenerowany w send_identify — pół soli klucza (druga połowa: be_nonce z identified).
static uint8_t s_fw_nonce[16] = {0};
// JEDEN bufor enc (loop-only) dla TX i RX — oszczędza ~3KB .bss. Bezpieczne bo half-duplex w loop:
// RX plaintext jest w CAŁOŚCI skopiowany do JsonDocument przez deserializeJson (handle_message bierze
// `const char*` → ArduinoJson w trybie KOPIUJĄCYM) ZANIM ruszy dispatch; handlery które synchronicznie
// wysyłają (push/script) czytają z własnych buforów i pieczętują tutaj, nadpisując już-martwe bajty RX.
// ⚠️ INWARIANT: handle_message MUSI zostać na `const char*`. Gdyby przyjął zapisywalny `char*` (zero-copy),
// doc aliasowałby ten bufor i TX z handlera by go zepsuł w trakcie dispatchu. Rozmiar = max tasks_update.
static uint8_t s_enc[TX_SCRATCH_LEN + 32];

// ── WS-watchdog (KNOWN-ISSUES #7; progi w config.h) ───────────────────────────
// Zawieszka do wyleczenia: WiFi żywe, klient WS martwy i nie próbuje (stan po blipie
// serwera — 1 node z 263; restart czyści lwIP/DNS/sockety/stan biblioteki). Sonda TCP
// na endpoint WS rusza OD RAZU po padzie (kadencja: karencja→20 s, potem 60 s).
// Restart „zawieszka" = sonda przechodzi, a WS leży nieprzerwanie >= WS_WD_GRACE_MS
// (karencja chroni flotę przed zbiorowym restartem przy każdym deployu BE — deploy
// zrywa WS na 10-30 s przy żywym nginx). Restart profilaktyczny = WS i TCP martwe
// nieprzerwanie WS_WD_PROPH_MS. Checknet tu nie pomoże — jego cykl zaczyna się od
// check_assign PO WS, więc po padzie WS milknie razem z nim; sonda WD jest niezależna.
static char          s_wd_host[64]    = {0};   // cel sondy = dokładnie endpoint WS (z init)
static int           s_wd_port        = 0;
static unsigned long s_wd_down_since  = 0;     // start ciągłego stanu „WS martwy + WiFi żywe"; 0 = nie liczę
static unsigned long s_wd_next_probe  = 0;
static bool          s_wd_inflight    = false;
static int8_t        s_wd_probe_ok    = -1;    // ostatnia sonda: -1 brak, 0 padła (net down), 1 przeszła

// Epizod awarii — surowiec pod „ISP down detect" (historia zaników per gospodarstwo,
// podstawa do reklamacji u operatora). Stemple ABSOLUTNE (epoch): w chwili padu WS zegar
// jest wiarygodny (zsynchronizowany w sesji, która właśnie padła, tyka dalej na millis),
// więc start epizodu i 1. nieudaną sondę zapisujemy jako epoch — restarty WD ani nawet
// zanik zasilania go nie psują (NVS; jeden zapis na restart, kasowany po raporcie).
// Okno net-down wyznaczają NIEUDANE sondy TCP.
struct WdEp { uint32_t start_epoch; uint32_t ff_epoch; uint16_t fails; uint16_t oks; uint8_t restarts; };
static WdEp          s_wd_prev        = {0,0,0,0,0};  // stan sprzed restartów (z NVS)
static unsigned long s_wd_first_fail  = 0;            // millis 1. nieudanej sondy w TYM bootcie
static uint16_t      s_wd_fail_cnt    = 0;
static uint16_t      s_wd_ok_cnt      = 0;

// Konwersja chwili millis → epoch. 0 gdy zegar nieznany (zimny boot bez syncu) —
// wtedy stempel zostaje pusty, a prev z NVS (jeśli jest) i tak niesie prawdziwy start.
static uint32_t ws_wd_epoch_at(unsigned long t_ms) {
    uint32_t e = ws_epoch_now();
    if (!e || !t_ms) return 0;
    return e - (uint32_t)((millis() - t_ms) / 1000UL);
}

static void ws_wd_persist_episode() {
    WdEp ep = s_wd_prev;
    if (!ep.start_epoch) ep.start_epoch = ws_wd_epoch_at(s_wd_down_since);
    if (!ep.ff_epoch)    ep.ff_epoch    = ws_wd_epoch_at(s_wd_first_fail);
    ep.fails    += s_wd_fail_cnt;
    ep.oks      += s_wd_ok_cnt;
    ep.restarts += 1;
    Preferences p; p.begin("sensmos", false);
    p.putBytes("wd_ep", &ep, sizeof(ep));
    p.end();
}

static void ws_wd_restart(const char* why) {
    LOGW("ws", "watchdog: %s -> restart", why);
    node_log_push("error", why, false);   // ślad w GET /node/log widoczny po powrocie
    ws_wd_persist_episode();              // epizod nie może zginąć z restartem — to dowód
    delay(200);
    ESP.restart();
}

// ── Parsowanie URL ─────────────────────────────────────────────
static bool parseUrl(const char* url, char* host, int* port, char* path_out, bool* secure) {
    const char* p = url;
    *secure = false;
    int defPort = 80;
    if      (strncmp(p, "https://", 8) == 0) { p += 8; *secure = true; defPort = 443; }
    else if (strncmp(p, "http://",  7) == 0) { p += 7; }

    const char* colon = strchr(p, ':');
    const char* slash = strchr(p, '/');

    // host = bufor char[64] u wywolujacego → clamp do 63, inaczej dlugi host = stack overflow
    const size_t HOST_MAX = 63;
    if (colon && (!slash || colon < slash)) {
        size_t n = (size_t)(colon - p); if (n > HOST_MAX) n = HOST_MAX;
        strncpy(host, p, n); host[n] = '\0';
        *port = atoi(colon + 1);
    } else if (slash) {
        size_t n = (size_t)(slash - p); if (n > HOST_MAX) n = HOST_MAX;
        strncpy(host, p, n); host[n] = '\0';
        *port = defPort;
    } else {
        strncpy(host, p, HOST_MAX); host[HOST_MAX] = '\0';
        *port = defPort;
    }

    if (slash) snprintf(path_out, 64, "%s/ws", slash);
    else       strcpy(path_out, "/v1/ws");
    return true;
}

// ── Identify ──────────────────────────────────────────────────
static void send_identify() {
    unsigned long ts = millis() / 1000;

    // Nonce sesji (16B) — wchodzi do PODPISYWANEGO stringa razem z flagą e1: MITM nie zdejmie
    // szyfrowania ani nie podmieni nonce bez złamania podpisu (downgrade → rozłączenie, nie plaintext).
    esp_fill_random(s_fw_nonce, 16);
    char enonce_hex[33];
    bytes_to_hex(s_fw_nonce, 16, enonce_hex);

    char msg_to_sign[160];
    snprintf(msg_to_sign, sizeof(msg_to_sign),
        "identify:%s:%lu:e1:%s", g_device_id, ts, enonce_hex);

    uint8_t hash[32];
    sha256_string(msg_to_sign, hash);
    uint8_t sig[72]; size_t sig_len = 0;
    identity_sign(hash, sig, &sig_len);
    char sig_hex[145];
    bytes_to_hex(sig, sig_len, sig_hex);

    JsonDocument doc;
    doc["type"]      = "identify";
    doc["device_id"] = g_device_id;
    doc["timestamp"] = (uint32_t)ts;
    doc["msg"]       = msg_to_sign;
    doc["signature"] = sig_hex;
    doc["enc"]       = 1;             // wymagam szyfrowania kanału (ws_enc)
    doc["enonce"]    = enonce_hex;    // pół soli klucza sesji
    doc["firmware"]  = FW_VERSION;
    if (pairing_has_key()) doc["remote"] = 1;   // sparowany → BE wie, że node może otworzyć tunel
#if LORA_ENABLED
    // Zdolność radiowa wykryta przy starcie (SX1262 faktycznie odpowiedział) — BE wysyła
    // lora_cfg wyłącznie takim nodom, więc reszta floty nie dostaje ramek, których nie zrozumie.
    if (lora_available()) {
        doc["lora"] = 1;
        // Nazwa WYKRYTEJ plytki, nie zbudowanej — chip (ESP32-S3 r2 @240MHz 8MB) wyglada
        // identycznie dla XIAO i Helteca, wiec BE nie mial jak ich rozroznic i zgadywal
        // target po rozmiarze flasha.
        doc["board"] = lora_board_name();
    }
#endif
    // Dane plytki RAZ na polaczenie (nie w kazdym batchu): model/rev/MHz/flash ->
    // devices.chip; korelacja czasow TLS/probe ze sprzetem
    static char s_chip[48] = {0};
    if (!s_chip[0])
        snprintf(s_chip, sizeof(s_chip), "%s r%d @%luMHz %luMB",
                 ESP.getChipModel(), (int)ESP.getChipRevision(),
                 (unsigned long)ESP.getCpuFreqMHz(),
                 (unsigned long)(ESP.getFlashChipSize() / (1024UL*1024UL)));
    doc["chip"] = s_chip;

    String packet;
    serializeJson(doc, packet);
    ws.sendTXT(packet);
    LOGD("ws", "identify sent (%dB)", packet.length());
}

// ── Zapis danych subskrypcji do entity_store ──────────────────
// Prefix z lokalnej mapy subskrypcji po device_id nadawcy (from); default "sub".
static void push_remote_entities(JsonObject user_obj, JsonArray pub_arr,
                                 const char* from) {
    char prefix[16];
    if (!from || !sub_map_get(from, prefix, sizeof(prefix)))
        strcpy(prefix, "sub");

    if (!user_obj.isNull()) {
        for (JsonPair kv : user_obj) {
            const char* k = kv.key().c_str();
            if (strncmp(k, "pub.", 4) == 0) k += 4;
            char eid[64], val[64];
            snprintf(eid, sizeof(eid), "%s.%s", prefix, k);
            if (kv.value().is<const char*>()) {
                strncpy(val, kv.value().as<const char*>(), 63);
            } else {
                float fv = kv.value().as<float>();
                (fv == (int)fv)
                    ? snprintf(val, sizeof(val), "%d",   (int)fv)
                    : snprintf(val, sizeof(val), "%.2f", fv);
            }
            entity_push(eid, val, "");
        }
    }

    if (!pub_arr.isNull()) {
        for (JsonObject e : pub_arr) {
            const char* eid  = e["entity_id"] | "";
            const char* val  = e["value"]     | "";
            const char* unit = e["unit"]      | "";
            const char* base = (strncmp(eid, "pub.", 4) == 0) ? eid + 4 : eid;
            char full_eid[64];
            snprintf(full_eid, sizeof(full_eid), "%s.%s", prefix, base);
            entity_push(full_eid, val, unit);
        }
    }
}

// ── Handlery per typ wiadomości ───────────────────────────────
// Baza zegara UTC: epoch z identified + millis() w tej chwili. Odświeżane przy każdym
// (re)connect — dryf ESP32 rzędu sekund/dobę nie ma szans narosnąć między reconnectami.
static uint32_t s_epoch_base = 0, s_epoch_ms = 0;
uint32_t ws_epoch_now() {
    if (!s_epoch_base) return 0;
    return s_epoch_base + (millis() - s_epoch_ms) / 1000UL;
}

static void on_identified(JsonDocument& doc) {
    uint32_t st = doc["server_time"] | 0;   // czas serwera (informacyjnie)
    if (st > 1700000000UL) { s_epoch_base = st; s_epoch_ms = millis(); }

    // Ustanów klucz sesji: be_nonce (hex) z identified + s_fw_nonce z identify → ECDH+HKDF.
    // Dopiero po sukcesie oznaczamy WS jako gotowy — od tej chwili wszystko idzie szyfrowane (BIN).
    const char* be_hex = doc["enonce"] | "";
    if (strlen(be_hex) != 32) { LOGE("ws", "identified without enonce - BE lacks enc support; disconnecting"); ws.disconnect(); return; }
    uint8_t be_nonce[16];
    for (int i = 0; i < 16; i++) { unsigned v; if (sscanf(be_hex + i*2, "%2x", &v) != 1) { ws.disconnect(); return; } be_nonce[i] = (uint8_t)v; }
    if (!ws_enc_derive(s_fw_nonce, be_nonce)) { LOGE("ws", "key derive failed - disconnecting"); ws.disconnect(); return; }

    g_ws_connected = true;
    node_integration_push("ws_connected", "{}");

    // Raport epizodu awarii (WD): stemple ABSOLUTNE. Zegar właśnie zsynchronizowany
    // (server_time wyżej), więc nawet epizod bez restartów dostaje dokładny start_epoch
    // z konwersji millis. Po restartach/zaniku zasilania prawdziwy start niesie NVS.
    // Blipy <60 s (deploy BE) pomijamy. Wysyłka po identify = kanał już żywy.
    {
        uint32_t start_e = s_wd_prev.start_epoch ? s_wd_prev.start_epoch
                                                 : ws_wd_epoch_at(s_wd_down_since);
        uint32_t ff_e    = s_wd_prev.ff_epoch    ? s_wd_prev.ff_epoch
                                                 : ws_wd_epoch_at(s_wd_first_fail);
        uint32_t now_e   = ws_epoch_now();
        if (start_e && now_e > start_e && now_e - start_e >= 60) {
            char rep[192];
            snprintf(rep, sizeof(rep),
                "{\"type\":\"ws_outage\",\"start_epoch\":%lu,\"ff_epoch\":%lu,"
                "\"probes_fail\":%u,\"probes_ok\":%u,\"restarts\":%u}",
                (unsigned long)start_e, (unsigned long)ff_e,
                (unsigned)(s_wd_prev.fails + s_wd_fail_cnt),
                (unsigned)(s_wd_prev.oks + s_wd_ok_cnt),
                (unsigned)s_wd_prev.restarts);
            ws_client_send_raw(rep);
            LOGI("ws", "wd: outage reported (start=%lu, %lus, restarts=%u)",
                 (unsigned long)start_e, (unsigned long)(now_e - start_e),
                 (unsigned)s_wd_prev.restarts);
        }
        // Epizod zamknięty — czyścimy stan i NVS (jeśli był zapis sprzed restartu).
        if (s_wd_prev.start_epoch || s_wd_prev.restarts) {
            Preferences p; p.begin("sensmos", false); p.remove("wd_ep"); p.end();
        }
        s_wd_prev = {0,0,0,0,0};
        s_wd_first_fail = 0;
        s_wd_fail_cnt = s_wd_ok_cnt = 0;
    }

    // 0.64: udany identify = BE zna device i wpuścił → onboarding potwierdzony.
    // Rozbraja watchdog factory-resetu, gdy apka nie mogła strzelić lokalnego
    // /node/confirm (telefon w innej podsieci niż node — mDNS nie przechodzi).
    watchdog_confirm();

    // Załaduj native_entities
    int loaded = 0;
    for (JsonObject e : doc["entities"].as<JsonArray>()) {
        const char* eid = e["entity_id"] | "";
        if (strlen(eid) > 0) { entity_load_native(eid); loaded++; }
    }

    LOGI("ws", "identified+enc (%d native entities, server_time=%u)", loaded, st);
}

static void on_message_recv(JsonDocument& doc) {
    const char* from       = doc["from"]    | "unknown";
    const char* message_id = doc["eid"]     | "unknown";
    const char* pl         = doc["payload"] | "";

    http_inbox_push(from, message_id, pl);
    LOGD("ws", "message %s from %.8s", message_id, from);
    mqtt_pub_message(from, message_id, pl);   // most do HA: wiadomość → lokalny broker (no-op gdy MQTT off)
    message_router_dispatch(from, message_id, pl);
}

static void on_message_sent(JsonDocument& doc) {
    bool delivered = doc["delivered"] | false;
    if (!delivered) LOGD("ws", "message: recipient offline");
}

static void on_batch_ack(JsonDocument& doc) {
    int saved = doc["entities_saved"] | 0;
    LOGD("ws", "batch ack: %d entities", saved);
    char detail[32], sse[64];
    snprintf(detail, sizeof(detail), "%d entities saved", saved);
    snprintf(sse,    sizeof(sse),    "{\"entities_saved\":%d}", saved);
    node_log_push("batch", detail, true);
    node_integration_push("batch_sent", sse);
}

static void on_batch_error(JsonDocument& doc) {
    LOGW("ws", "batch error: %s", doc["error"] | "?");
}

static void on_tasks_update(JsonDocument& doc) {
    extern int script_engine_load(const JsonArray&);
    extern int script_engine_load_user();
    int n = script_engine_load(doc["scripts"].as<JsonArray>());
    script_engine_load_user();
    LOGD("ws", "tasks: %d BE scripts", n);
}

static void on_tasks_clear(JsonDocument& doc) {
    extern void script_engine_clear();
    script_engine_clear();
    LOGD("ws", "scripts cleared");
}

// Komendy zmieniające stan przychodzą WYŁĄCZNIE przez zaszyfrowany kanał (ramka BIN, tag GCM =
// autentyczność). Plaintext (WStype_TEXT) po aktywacji enc jest DROPOWANY w wsEvent, więc MITM na
// ws://:80 nie wstrzyknie fałszywej komendy. Ten guard = pas bezpieczeństwa (dispatch komend i tak
// leci tylko z ramek BIN). Zastąpił K3 (podpisy per-komenda + pula nonce).
static bool cmd_enc_guard(const char* type) {
    if (!ws_enc_active()) { LOGW("ws", "%s outside encryption — rejected", type); return false; }
    return true;
}

// Zdalny restart (BE admin) — czyści wyciekłą pamięć bez fizycznego dostępu.
static void on_reboot(JsonDocument& doc) {
    if (!cmd_enc_guard("reboot")) return;
    LOGW("ws", "remote reboot — restarting");
    delay(300);
    ESP.restart();
}

// Owner skasował noda z apki (BE→WS). TRZYMAMY tożsamość/klucze, ale przechodzimy w BLE onboarding
// (flaga NVS + reboot) — czekamy na ponowne dodanie. Bez factory resetu.
static void on_deleted(JsonDocument& doc) {
    if (!cmd_enc_guard("deleted")) return;
    LOGW("ws", "owner deleted node — entering BLE onboarding (identity kept)");
    node_deleted_set(true);
    delay(300);
    ESP.restart();
}

static void on_subscription_push(JsonDocument& doc) {
    const char* from = doc["from"] | "?";
    char detail[48], sse[96];
    snprintf(detail, sizeof(detail), "from:%.8s", from);
    snprintf(sse,    sizeof(sse),    "{\"from\":\"%.8s...\"}",  from);
    node_log_push("sub_push", detail, true);
    node_integration_push("sub_received", sse);
    LOGD("ws", "sub push from %.8s", from);
    push_remote_entities(
        doc["user"].as<JsonObject>(),
        doc["pub"].as<JsonArray>(),
        from
    );
}

static void on_error(JsonDocument& doc) {
    LOGW("ws", "backend error: %s", doc["msg"] | "?");
}

static void on_check_jobs(JsonDocument& doc) {
    checknet_on_jobs(doc["jobs"].as<JsonArray>());
}

// Check-now (UpFromWhere, 0.56+): zmierz URL wskazany przez usera na landingu. Tylko przez enc —
// bez tego rogue-WS mógłby kazać nodowi strzelać w dowolny adres.
static void on_check(JsonDocument& doc) {
    if (!cmd_enc_guard("check")) return;
    checknow_on_cmd(doc);
}

// Config checknetu z BE (interwał adaptacyjny wg floty + limity). Stary FW ignoruje ten typ.
static void on_cn_config(JsonDocument& doc) {
    bool     en  = doc["enabled"]    | true;
    uint32_t iv  = (uint32_t)(doc["interval_s"] | 600) * 1000UL;
    int      mj  = doc["max_jobs"]   | 6;
    int      pc  = doc["ping_count"] | 5;
    uint32_t tcd = doc["trace_cd_s"] | 300;
    checknet_set_config(en, iv, mj, pc, tcd);
}

// UDP hole punch (v0.43): BE koordynuje pary — patrz punch.h
static void on_cn_stun(JsonDocument& doc)  { punch_on_stun(doc); }
static void on_cn_punch(JsonDocument& doc) { punch_on_punch(doc); }

// R3 monitory kierowane (v0.30+): deskryptor/odwolanie z BE. Stary FW ignoruje te typy.
static void on_monitor_set(JsonDocument& doc) {
    monitors_on_set(doc["monitor"].as<JsonObject>());
}
static void on_monitor_clear(JsonDocument& doc) {
    monitors_on_clear((int32_t)(doc["id"] | 0));
}

// OTA (v0.35+): podpis BE nad parametrami weryfikuje ota_handle. Stary FW ignoruje typ.
static void on_ota(JsonDocument& doc) {
    ota_handle(doc);
}

// RemoteTerminal (v0.65+): tunel TCP do LAN-u. Lokalna bramka = klucz parowania (pairing.h),
// ustawiany wyłącznie po LAN — BE nie ma jak go podłożyć. Plus tylko prywatne cele.
//
// Otwarcie wymaga DOWODU od właściciela: HMAC-SHA256(klucz_parowania, msg), gdzie
//   msg = "sensmos-tun-open|<device_id>|<ip>|<port>|<ts>"
// BE tylko PRZEPYCHA `ts` i `proof` z apki — nie ma klucza, więc nie potrafi ich wytworzyć
// ani podmienić celu (ip i port siedzą W ŚRODKU podpisywanego ciągu). To jest rdzeń całej
// zmiany: bez tego skompromitowany serwer otwierał tunel do cudzego LAN-u sam z siebie.
//
// `ts` + okno czasowe są konieczne OBOK dowodu: sam HMAC byłby ważny w nieskończoność,
// więc raz podejrzany `proof` dałoby się odtworzyć choćby za tydzień. Zmiana `ts` zmienia
// wymagany HMAC, a tego bez klucza nie da się przeliczyć.
#define TUN_OPEN_WINDOW_S 60

// ── Anti-replay: jednorazowość proof w oknie ─────────────────────────────────
// Sam HMAC + okno 60 s wciąż pozwalają POWTÓRZYĆ ważny proof w tym oknie. Istotne wobec
// jedynego przeciwnika, przed którym proof w ogóle chroni — skompromitowanego BE: klucza
// parowania nie zna, ale JEST końcem szyfrowanego kanału (seq go nie zatrzyma, sam tworzy
// ramki) i widzi proof, bo go przepycha telefon→node. Domykamy to jednorazowością: node
// pamięta proofy przyjęte w oknie i odrzuca powtórki. Ten sam wzorzec co claimCode() w BE.
#define TUN_PROOF_SLOTS 16
static struct { uint8_t p[32]; uint32_t at; } s_tun_seen[TUN_PROOF_SLOTS];

// true = proof już przyjęty w oknie (replay); false = świeży (zajmuje slot).
static bool tun_proof_replay(const uint8_t proof[32], uint32_t now) {
    int slot = 0; uint32_t oldest = 0xFFFFFFFF;
    for (int i = 0; i < TUN_PROOF_SLOTS; i++) {
        bool live = s_tun_seen[i].at && (now - s_tun_seen[i].at <= TUN_OPEN_WINDOW_S);
        if (live && memcmp(s_tun_seen[i].p, proof, 32) == 0) return true;
        uint32_t age = live ? s_tun_seen[i].at : 0;   // puste/wygasłe = do nadpisania pierwsze
        if (age < oldest) { oldest = age; slot = i; }
    }
    memcpy(s_tun_seen[slot].p, proof, 32);
    s_tun_seen[slot].at = now;
    return false;
}

static void on_tun_open(JsonDocument& doc) {
    const int   tid  = (int)(doc["tid"] | 0);
    const char* ip   = doc["ip"] | "";
    const int   port = (int)(doc["port"] | 0);
    const char* proof_hex = doc["proof"] | "";
    const uint32_t ts = (uint32_t)(doc["ts"] | 0);
    const int   ver  = (int)(doc["v"] | 0);

    auto deny = [&](const char* why) {
        char buf[160];
        snprintf(buf, sizeof(buf), "{\"type\":\"tun_state\",\"tid\":%d,\"st\":\"error\",\"msg\":\"%s\"}", tid, why);
        ws_client_send_raw(buf);
        LOGW("tun", "tun_open ODRZUCONY: %s", why);
    };

    if (!pairing_has_key())      { deny("node not paired"); return; }
    // Tunel jest v2-only: bajty lecą zaszyfrowane kluczem parowania, w binarnej kopercie.
    // Apka sprzed 1.5.53 nie umie tego formatu — odmawiamy z komunikatem zamiast otwierać
    // sesję, z której nie popłynie ani jeden bajt (wiszący terminal bez wyjaśnienia).
    if (ver != 2)                { deny("update the app");  return; }
    if (strlen(proof_hex) != 64) { deny("missing proof");   return; }

    // Bez NTP nie umiemy ocenić świeżości, więc nie wolno przepuścić — inaczej okno czasowe
    // przestaje cokolwiek znaczyć i dowód staje się wieczny.
    if (!ntp_synced()) { deny("node clock not synced"); return; }
    uint32_t now = ntp_unix_time();
    uint32_t age = now > ts ? now - ts : ts - now;
    if (age > TUN_OPEN_WINDOW_S) { deny("stale timestamp"); return; }

    uint8_t proof[32];
    for (int i = 0; i < 32; i++) {
        unsigned v;
        if (sscanf(proof_hex + i * 2, "%2x", &v) != 1) { deny("proof not hex"); return; }
        proof[i] = (uint8_t)v;
    }

    char msg[192];
    snprintf(msg, sizeof(msg), "sensmos-tun-open|%s|%s|%d|%lu",
             g_device_id, ip, port, (unsigned long)ts);
    // Który telefon otworzył sesję — jego kluczem ją szyfrujemy (node trzyma do 4 kluczy).
    const int kidx = pairing_verify_idx(msg, proof);
    if (kidx < 0) { deny("bad proof"); return; }
    if (tun_proof_replay(proof, now)) { deny("proof replayed"); return; }

    uint8_t tunkey[32];
    if (!pairing_tun_key(kidx, tunkey)) { deny("key derive failed"); return; }
    tunnel_on_open(tid, ip, port, tunkey, ts);
    memset(tunkey, 0, sizeof(tunkey));   // kopia lokalna nie zostaje na stosie
}
// Przystawki: odpowiedź BE na ext_auth_req. Guard jest tu obowiązkowy — ramka niesie
// TOKEN, więc plaintext oznaczałby, że rogue-AP wydaje uprawnienia w naszym imieniu.
static void on_ext_auth_grant(JsonDocument& doc) {
    if (!cmd_enc_guard("ext_auth_grant")) return;
    ext_auth_on_grant(doc["req"] | "", doc["id"] | "", doc["token"] | "",
                      (uint32_t)(doc["exp"] | 0));
}
static void on_ext_auth_deny(JsonDocument& doc) {
    if (!cmd_enc_guard("ext_auth_deny")) return;
    ext_auth_on_deny(doc["req"] | "", doc["reason"] | "denied");
}

static void on_tun_close(JsonDocument& doc) {
    tunnel_on_close((int)(doc["tid"] | 0));
}

#if LORA_ENABLED
// hex(64) -> 32 B (owner-seed). false = zła długość / nie-hex.
static bool hex32(const char* hex, uint8_t out[32]) {
    if (!hex || strlen(hex) != 64) return false;
    for (int i = 0; i < 32; i++) {
        unsigned v;
        if (sscanf(hex + i * 2, "%2x", &v) != 1) return false;
        out[i] = (uint8_t)v;
    }
    return true;
}

// BE dyktuje plan pasma i slot nadawania (rola jak check_jobs dla sieci). Sam harmonogram
// liczy się z zegara UTC, więc ta ramka nie musi przychodzić punktualnie — tylko raz.
static void on_lora_cfg(JsonDocument& doc) {
    if (!cmd_enc_guard("lora_cfg")) return;
    LoraLinkCh ch[LORA_LINK_MAX_CH];
    uint8_t n = 0;
    for (JsonObject c : doc["scan"].as<JsonArray>()) {
        if (n >= LORA_LINK_MAX_CH) break;
        memset(&ch[n], 0, sizeof(LoraLinkCh));
        ch[n].freq = c["freq"] | 868.3f;
        ch[n].bw   = c["bw"]   | 125.0f;
        ch[n].sf   = c["sf"]   | 9;
        ch[n].cr   = c["cr"]   | 5;
        ch[n].sync = (uint8_t)(c["sync"] | 0x34);
        ch[n].mode = (uint8_t)(c["mode"] | 0);
        if (ch[n].mode == 1) {
            ch[n].br  = c["br"]  | 4.8f;
            ch[n].dev = c["dev"] | 5.0f;
            ch[n].len = (uint8_t)(c["len"] | 0);
            ch[n].flags = (uint8_t)((c["crc"] | 0 ? 0x01 : 0) |
                                    (c["white"] | 0 ? 0x02 : 0) |
                                    (c["fixed"] | 0 ? 0x04 : 0));
            // sync jako ciąg hex ("543d") — bajty, nie jedna liczba jak w LoRa
            const char* sh = c["syncb"] | "";
            uint8_t k = 0;
            for (const char* p = sh; p[0] && p[1] && k < 8; p += 2) {
                char b[3] = { p[0], p[1], 0 };
                ch[n].syncb[k++] = (uint8_t)strtoul(b, nullptr, 16);
            }
            ch[n].syncn = k;
        }
        n++;
    }
    // 0.92: seed kodu beaconu NIE przychodzi już z BE — node liczy go sam z ECDH
    // (ws_enc_beacon_seed przy starcie), BE liczy to samo z devices.pubkey.
    JsonObject b = doc["beacon"];
    lora_link_set((bool)(doc["on"] | false), (bool)(b["on"] | false),
                  (uint8_t)(b["slot"] | 0), (uint16_t)(b["every_s"] | 60),
                  (uint8_t)(doc["min_per_ch"] | 0), n ? ch : nullptr, n,
                  (uint8_t)(doc["role"] | 0));   // model v2: 0 skaner | 1 PUNKT
    // owner-seed (klucz SMOM) idzie OSOBNĄ komendą lora_msg_seed (kontrakt BE 0.95), nie tutaj.
}

// Skan całego pasma na żądanie BE. Przerywa nasłuch na kilka sekund, po czym tryb link
// wraca sam (zlecenie zeruje bieżący kanał, więc następny tick przestraja radio).
static void on_lora_scan(JsonDocument& doc) {
    if (!cmd_enc_guard("lora_scan")) return;
    lora_sweep(doc["from"] | 863.0f, doc["to"] | 870.0f, doc["step"] | 0.2f);
}

// Nasłuch energii na JEDNEJ częstotliwości przez N sekund — odpowiada na pytanie
// „czy tu w ogóle coś nadaje", niezależnie od modulacji. Skan pasma tego nie powie,
// bo stoi na każdym punkcie ułamek sekundy.
static void on_lora_camp(JsonDocument& doc) {
    if (!cmd_enc_guard("lora_camp")) return;
    lora_camp(doc["freq"] | 869.525f, doc["secs"] | 120);
}
// listen/cad/hunt/bg istnialy od poczatku, ale WYLACZNIE spod seriala — czyli dla noda
// bez kabla nie istnialy wcale. Ten sam brak naprawiono wczesniej dla sweepa i campa.
static void on_lora_listen(JsonDocument& doc) {
    if (!cmd_enc_guard("lora_listen")) return;
    lora_listen(doc["freq"] | 868.1f, doc["bw"] | 125.0f, doc["sf"] | 7,
                doc["cr"] | 5, doc["sync"] | 0x34, doc["secs"] | 30);
}
static void on_lora_cad(JsonDocument& doc) {
    if (!cmd_enc_guard("lora_cad")) return;
    lora_cad(doc["freq"] | 869.525f, doc["bw"] | 62.5f, doc["sf"] | 8, doc["secs"] | 30);
}
static void on_lora_hunt(JsonDocument& doc) {
    if (!cmd_enc_guard("lora_hunt")) return;
    lora_hunt(doc["freq"] | 869.525f, doc["bw"] | 62.5f, doc["sf"] | 8,
              doc["cr"] | 5, doc["dwell_ms"] | 3000);
}
static void on_lora_bg(JsonDocument& doc) {
    if (!cmd_enc_guard("lora_bg")) return;
    lora_bg_set(doc["on"] | true);
}

// Owner-seed per-owner (klucz kodeka SMOM; model v2: uwierzytelnia ramkę CMD) — komenda BE
// `lora_msg_seed`. Guard obowiązkowy: seed steruje aktuacją, plaintext = rogue-AP wydający
// klucz grupie. Pole `seed` = 32-B seed w hex (64 znaki).
static void on_lora_msg_seed(JsonDocument& doc) {
    if (!cmd_enc_guard("lora_msg_seed")) return;
    uint8_t seed[32];
    if (hex32(doc["seed"] | "", seed)) lora_owner_seed_set(seed);
    else LOGW("ws", "lora_msg_seed: zły format (oczekiwano 64 hex)");
}

// Downlink LoRa — BE każe przekaźnikowi nadać gotową ramkę binarną (model v2: CMD 0x03,
// uwierzytelnioną seedem ODBIORCY) do noda offline. Ten sam podpisany kanał co OTA.
static void on_lora_tx(JsonDocument& doc) {
    if (!cmd_enc_guard("lora_tx")) return;
    if (!lora_tx_raw_hex(doc["frame"] | "")) LOGW("ws", "lora_tx: ramka odrzucona");
}

// Ramka DATA (0x02) usłyszana przez INNY node — BE routuje po dst do adresata (nas).
// NIE nadajemy jej: dekod lokalny (zero-knowledge), jakby przyszła z własnego radia.
static void on_lora_frame(JsonDocument& doc) {
    if (!cmd_enc_guard("lora_frame")) return;
    lora_data_rx_ws(doc["hex"] | "");
}
// Zlecenie nadania do MOJEGO czujnika (lora10, model §6a): inny node zrobił lorasend z moim
// dst — BE dowiózł ramkę po WS, ja jestem jedynym nadajnikiem radiowym dla moich czujników.
static void on_lora_frame_tx(JsonDocument& doc) {
    if (!cmd_enc_guard("lora_frame_tx")) return;
    lora_data_tx_ws(doc["hex"] | "");
}
#endif

// ── Tablica dispatchu ─────────────────────────────────────────
typedef void (*ws_handler_t)(JsonDocument&);
struct WsEntry { const char* type; ws_handler_t fn; };

static const WsEntry WS_TABLE[] = {
    { "identified",        on_identified },
    { "message",           on_message_recv },
    { "message_sent",      on_message_sent },
    { "batch_ack",         on_batch_ack },
    { "batch_error",       on_batch_error },
    { "tasks_update",      on_tasks_update },
    { "tasks_clear",       on_tasks_clear },
    { "reboot",            on_reboot },
    { "deleted",           on_deleted },
    { "subscription_push", on_subscription_push },
    { "check_jobs",        on_check_jobs },
    { "check",             on_check },
    { "cn_config",         on_cn_config },
    { "cn_stun",           on_cn_stun },
    { "cn_punch",          on_cn_punch },
    { "monitor_set",       on_monitor_set },
    { "monitor_clear",     on_monitor_clear },
    { "ota",               on_ota },
    { "tun_open",          on_tun_open },
    { "tun_close",         on_tun_close },
    { "fw_digest",         fw_digest_on_ws },
    { "ext_auth_grant",    on_ext_auth_grant },
    { "ext_auth_deny",     on_ext_auth_deny },
#if LORA_ENABLED
    { "lora_cfg",          on_lora_cfg },
    { "lora_scan",         on_lora_scan },
    { "lora_camp",         on_lora_camp },
    { "lora_listen",       on_lora_listen },
    { "lora_cad",          on_lora_cad },
    { "lora_hunt",         on_lora_hunt },
    { "lora_bg",           on_lora_bg },
    { "lora_msg_seed",     on_lora_msg_seed },
    { "lora_tx",           on_lora_tx },
    { "lora_frame",        on_lora_frame },
    { "lora_frame_tx",     on_lora_frame_tx },
#endif
    { "error",             on_error },
};

// ── Obsługa wiadomości ────────────────────────────────────────
static void handle_message(const char* payload) {
    JsonDocument doc;
    if (deserializeJson(doc, payload)) {
        LOGW("ws", "JSON parse error");
        return;
    }
    const char* type = doc["type"] | "";

    if (strcmp(type, "pong") == 0) return;

    // Pre-enc (handshake) akceptujemy TYLKO identified/error. Reszta (tasks_update/check_jobs/
    // monitor_set/cn_*) MUSI przyjść szyfrowana (BIN) — inaczej rogue-AP wstrzyknąłby skrypty/config
    // w plaintext, trzymając noda przed identified. Po aktywacji enc plaintext TEXT i tak jest dropowany.
    if (!ws_enc_active() && strcmp(type, "identified") != 0 && strcmp(type, "error") != 0) {
        LOGW("ws", "%s before enc — dropped", type);
        return;
    }

    for (const WsEntry& e : WS_TABLE) {
        if (strcmp(type, e.type) == 0) { e.fn(doc); return; }
    }
    LOGD("ws", "unknown type: %s", type);
}

// ── WS Events ─────────────────────────────────────────────────
static void wsEvent(WStype_t event, uint8_t* payload, size_t length) {
    switch (event) {
        case WStype_CONNECTED:
            LOGI("ws", "connected (heap %uk)", ESP.getFreeHeap() / 1024);
            send_identify();
            break;
        case WStype_DISCONNECTED:
            g_ws_connected = false;
            ws_enc_reset();   // świeży klucz przy następnym handshake
            if (payload && length) LOGW("ws", "disconnected: %.*s", (int)length, (char*)payload);
            else                   LOGW("ws", "disconnected");
            break;
        case WStype_TEXT:
            // Po ustaleniu klucza cały ruch to BIN — plaintext TEXT = próba wstrzyknięcia (MITM), drop.
            if (ws_enc_active()) { LOGW("ws", "plaintext after enc — dropped"); break; }
            handle_message((char*)payload);
            break;
        case WStype_BIN: {
            if (!ws_enc_active()) { LOGW("ws", "BIN before enc — dropped"); break; }
            uint8_t ver = 0;
            int n = ws_enc_open_ver(payload, length, s_enc, sizeof(s_enc) - 1, &ver);
            if (n < 0) { LOGW("ws", "enc open failed — reconnect"); ws.disconnect(); break; }
            if (ver == WS_ENC_VER_TUN) {
                // Tunel v2: [tid u16 BE][ramka]. Bez JSON-a i bez ArduinoJson — to jest cała
                // różnica w koszcie na porcję 1 KB (było: parse 1,4 KB dokumentu + base64).
                if (n < 2) { LOGW("ws", "tun frame too short"); break; }
                int tid = ((int)s_enc[0] << 8) | s_enc[1];
                tunnel_on_data(tid, s_enc + 2, (size_t)n - 2);
                break;
            }
            s_enc[n] = 0;
            handle_message((char*)s_enc);
            break;
        }
        case WStype_ERROR:
            if (payload && length) LOGE("ws", "error: %.*s", (int)length, (char*)payload);
            else                   LOGE("ws", "error");
            break;
        case WStype_PING: LOGD("ws", "ping"); break;
        case WStype_PONG: LOGD("ws", "pong"); break;
        default: break;
    }
}

// ── API ───────────────────────────────────────────────────────
void ws_client_init() {
    if (!g_wifi_connected || strlen(g_backend_url) == 0) return;

    char host[64] = {0}, path[64] = {0};
    int  port = 80; bool secure = false;
    if (!parseUrl(g_backend_url, host, &port, path, &secure)) {
        LOGE("ws", "URL parse error");
        return;
    }

#if WS_PLAINTEXT
    secure = false;               // WS bez TLS → ~70KB heapu więcej (dane i tak podpisane)
    port   = WS_PLAINTEXT_PORT;   // ws://host:80/v1/ws (nginx → :3000). Fetch/HTTP zostają https.
#endif

    // WS-watchdog: sonda celuje w DOKŁADNIE ten sam endpoint co klient WS.
    strlcpy(s_wd_host, host, sizeof(s_wd_host));
    s_wd_port = port;
    // Epizod sprzed restartu (jeśli WD restartował) — doliczymy go do raportu po identify.
    { Preferences p; p.begin("sensmos", true);
      if (p.getBytes("wd_ep", &s_wd_prev, sizeof(s_wd_prev)) != sizeof(s_wd_prev))
          s_wd_prev = {0,0,0,0,0};
      p.end(); }

    LOGI("ws", "connecting %s://%s:%d%s", secure ? "wss" : "ws", host, port, path);
    if (secure) ws.beginSSL(host, port, path);
    else        ws.begin(host, port, path);
    ws.onEvent(wsEvent);
    ws.setReconnectInterval(RECONNECT_INTERVAL);
    ws.enableHeartbeat(30000, 10000, 2);  // ping co 30s, timeout 10s
}

void ws_client_send_push(const char* title, const char* body) {
    // Adresata rozwiązuje BE po owner_address (rejestr push_tokens — token FCM rejestruje
    // sama apka). Node tokenu nie zna i nie przechowuje: ta ścieżka odpadła razem z
    // push_notify, bo apka przestała rozsyłać token po nodach w 1.5.39.
    char buf[384];
    snprintf(buf, sizeof(buf),
        "{\"type\":\"push\",\"push_title\":\"%s\",\"push_body\":\"%s\"}", title, body);
    ws_client_send_raw(buf);
    LOGD("push", "sent: %s", title);
}

// Ramka tunelu v2 → koperta WS_ENC_VER_TUN. `pt` przychodzi GOTOWY jako [tid u16 BE][ramka] —
// tunnel.cpp buduje to w swoim buforze sesyjnym, więc tu nie ma ani kopii, ani własnego
// bufora: żaden node bez sesji tunelu nie płaci za to bajtem RAM-u (zasada z 0.71).
bool ws_client_send_tun(const uint8_t* pt, size_t len) {
    if (!g_ws_connected || !ws_enc_active() || !pt) return false;
    int n = ws_enc_seal_ver(WS_ENC_VER_TUN, pt, len, s_enc, sizeof(s_enc));
    if (n < 0) { LOGW("ws", "tun seal failed"); return false; }
    return ws.sendBIN(s_enc, n);
}

bool ws_client_send_raw(const char* json_msg) {
    if (!g_ws_connected) return false;
    if (ws_enc_active()) {
        int n = ws_enc_seal((const uint8_t*)json_msg, strlen(json_msg), s_enc, sizeof(s_enc));
        if (n < 0) { LOGW("ws", "enc seal failed (payload too big?)"); return false; }
        return ws.sendBIN(s_enc, n);
    }
    return ws.sendTXT(json_msg);   // tylko faza pre-handshake (identify idzie plaintextem)
}

bool ws_client_connected() { return g_ws_connected; }

// Stan WAN dla MQTT (topik net/wan): 1=up, 2=down, 0=nieznany.
// WS żyje → net na pewno działa. WS martwy → wierzymy ostatniej sondzie TCP watchdoga
// (przechodzi = internet jest, a wisi tylko WS; pada = internet leży).
uint8_t ws_client_wan_state() {
    if (g_ws_connected)      return 1;
    if (s_wd_probe_ok == 1)  return 1;
    if (s_wd_probe_ok == 0)  return 2;
    return 0;
}

// Kadencja sondy: w oknie karencji gęsto (szybka diagnoza), potem oszczędnie.
static unsigned long ws_wd_cadence(unsigned long now) {
    return (now - s_wd_down_since < WS_WD_GRACE_MS) ? WS_WD_PROBE_FAST_MS : WS_WD_PROBE_MS;
}

// Wynik sondy TCP z wora (dispatch w .ino po nr.src == NW_WSWD).
void ws_client_wd_on_net_result(const NetResult& nr) {
    s_wd_inflight = false;
    if (!s_wd_down_since || g_ws_connected) return;              // WS wrócił zanim sonda doszła
    unsigned long now = millis();
    if (!nr.deferred) {
        s_wd_probe_ok = nr.res.ok ? 1 : 0;
        if (nr.res.ok) s_wd_ok_cnt++;
        else {   // nieudane sondy wyznaczają okno „internet leżał" (dowód pod ISP-down)
            s_wd_fail_cnt++;
            if (!s_wd_first_fail) s_wd_first_fail = now ? now : 1;
        }
    }
    // TCP przechodzi + WS martwy nieprzerwanie >= karencja → zawieszka klienta, restart.
    // W oknie karencji udana sonda NIE restartuje (normalny reconnect po deployu BE).
    if (!nr.deferred && nr.res.ok && now - s_wd_down_since >= WS_WD_GRACE_MS)
        ws_wd_restart("ws-wd: net OK, WS dead");
    s_wd_next_probe = now + ws_wd_cadence(now);
}

void ws_client_tick() {
    ws.loop();

    if (g_ws_connected || WiFi.status() != WL_CONNECTED) {
        s_wd_down_since = 0;   // WiFi-down leczy wifi_maintain (własny reboot) — tu nie liczymy
        s_wd_probe_ok   = -1;  // stan sondy z poprzedniego epizodu nie mówi nic o teraz
        return;
    }
    unsigned long now = millis();
    if (!s_wd_down_since) {
        s_wd_down_since = now ? now : 1;   // 0 to sentinel „nie liczę"
        s_wd_next_probe = now;             // sonda od razu, bez czekania
        return;
    }
    // Restart profilaktyczny: WS i TCP martwe nieprzerwanie 2h (gdyby TCP w międzyczasie
    // przeszło, restart „zawieszka" zapadłby już po karencji — tu trafiamy tylko przy
    // ciągłym braku internetu albo zawieszce, która kładzie też sondę).
    // WYJĄTEK (model v2, 2026-08-31): tryb EMERGENCY. Node z uzbrojonym E żyje z zegarem
    // sprzed padu i nadaje przez LoRa; restart = boot offline BEZ epoki (brak NTP/WS)
    // → link_tick milczy → node ZNIKA z eteru (tak umarł 00d0668d po 2 h testu).
    if (now - s_wd_down_since >= WS_WD_PROPH_MS
#if LORA_ENABLED
        && !lora_emerg_active()
#endif
    )
        ws_wd_restart("ws-wd: prophylactic (ws+net down)");
    if (s_wd_inflight || (long)(now - s_wd_next_probe) < 0) return;

    NetJob nj{};
    nj.src = NW_WSWD;
    strlcpy(nj.job.kind, "tcp", sizeof(nj.job.kind));
    strlcpy(nj.job.host, s_wd_host, sizeof(nj.job.host));
    nj.job.port       = s_wd_port;
    nj.job.timeout_ms = 4000;
    if (net_worker_enqueue(nj, false)) s_wd_inflight = true;
    else s_wd_next_probe = now + ws_wd_cadence(now);   // wór pełny — spróbuj wg kadencji
}
