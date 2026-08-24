#include "mqtt_pub.h"
#include "config.h"
#include "net_worker.h"
#include "identity.h"
#include "data_sender.h"   // FW_VERSION
#include "ws_client.h"     // ws_client_connected + ws_client_wan_state (net/wan)
#include "entity_store.h"  // publish encji pub+own do HA
#include "log.h"
#include <WiFi.h>
#include <Preferences.h>
#include <ArduinoJson.h>

// ── Config (NVS namespace "sensmos", klucze mqtt_*) ───────────────────────────
static bool  s_on       = false;
static char  s_host[64] = {0};
static int   s_port     = MQTT_PORT_DEF;
static char  s_user[48] = {0};
static char  s_pass[48] = {0};

// ── Stan klienta ──────────────────────────────────────────────────────────────
// OFF → PREFLIGHT (sonda TCP na worze, nieblokująca) → CONNECTING (blokujący connect,
// krótki timeout) → UP. Rozłączenie/błąd → backoff → OFF. Wzorzec jak WS-watchdog:
// nigdy nie blokujemy loop na martwym brokerze — najpierw sonda, potem dopiero socket.
enum MqttState : uint8_t { M_OFF, M_PREFLIGHT, M_UP };
static MqttState     s_state       = M_OFF;
static WiFiClient    s_sock;
static bool          s_probe_busy  = false;
static unsigned long s_pref_at     = 0;   // wejście w PREFLIGHT (timeout na zgubiony wynik sondy)
static unsigned long s_next_try    = 0;
static unsigned long s_backoff_ms  = MQTT_RECONNECT_MS;
static unsigned long s_last_state  = 0;   // ostatni publish state
static unsigned long s_last_ent    = 0;   // ostatni publish encji
static unsigned long s_last_ping   = 0;
static uint32_t      s_tx_count    = 0;
static char          s_err[24]     = "idle";
static uint8_t       s_wan_last    = 0xFF; // ostatni opublikowany stan net/wan (0xFF = nic)

// Cache eid-ów, dla których poszło już HA-discovery (per połączenie — FNV-1a 32-bit).
// Discovery jest retained, więc wystarczy raz; po reconnect wysyłamy ponownie (tanio, pewnie).
static uint32_t      s_disc[MQTT_DISC_MAX];
static uint8_t       s_disc_n      = 0;

static char          s_buf[MQTT_BUF_SIZE];   // wspólny bufor pakietu (single-writer: loop)
static char          s_id8[9]      = {0};    // pierwsze 8 hex device_id (topik, jak beacon)

// ── Kodowanie MQTT 3.1.1 (tylko to, co publikujemy) ───────────────────────────
// Remaining Length: varint 7-bit z bitem kontynuacji. Zwraca liczbę zapisanych bajtów.
static int enc_len(uint8_t* p, uint32_t len) {
    int n = 0;
    do { uint8_t b = len % 128; len /= 128; if (len) b |= 0x80; p[n++] = b; } while (len);
    return n;
}
// String z 2-bajtowym prefiksem długości (MQTT UTF-8 string). Zwraca nową pozycję.
static int put_str(uint8_t* p, int pos, const char* s) {
    uint16_t l = strlen(s);
    p[pos++] = l >> 8; p[pos++] = l & 0xFF;
    memcpy(p + pos, s, l); return pos + l;
}

static void mqtt_disconnect(const char* why) {
    if (s_sock.connected()) s_sock.stop();
    if (s_state != M_OFF) LOGW("mqtt", "rozłączony: %s", why);
    s_state = M_OFF;
    strlcpy(s_err, why, sizeof(s_err));
}

// PUBLISH QoS0. topic/payload; retain opcjonalnie. false = błąd zapisu (rozłącza).
static bool mqtt_publish(const char* topic, const char* payload, bool retain) {
    if (!s_sock.connected()) return false;
    uint16_t tl = strlen(topic), pl = strlen(payload);
    uint32_t rem = 2 + tl + pl;                 // var-header(topic) + payload (QoS0: bez packet id)
    uint8_t* b = (uint8_t*)s_buf;
    int pos = 0;
    b[pos++] = 0x30 | (retain ? 0x01 : 0x00);   // PUBLISH, QoS0
    pos += enc_len(b + pos, rem);
    if (pos + (int)rem > MQTT_BUF_SIZE) {        // za duże na bufor → drop (jak lora_out_drop)
        LOGW("mqtt", "publish %s: %u B > bufor, drop", topic, (unsigned)rem);
        return true;                             // nie rozłączaj — to nasz limit, nie błąd łącza
    }
    pos = put_str(b, pos, topic);
    memcpy(b + pos, payload, pl); pos += pl;
    if (s_sock.write((uint8_t*)b, pos) != (size_t)pos) { mqtt_disconnect("write"); return false; }
    s_tx_count++;
    return true;
}

static const char* topic(const char* leaf) {
    static char t[64];
    snprintf(t, sizeof(t), "sensmos/%s/%s", s_id8, leaf);
    return t;
}

// Blokujący CONNECT (po pozytywnej sondzie). LWT status=offline retained → HA rozróżni
// „node padł" (broker publikuje LWT) od zwykłej ciszy. Krótki timeout, żeby nie wisieć w loop.
static bool mqtt_connect() {
    s_sock.setTimeout(MQTT_SOCK_TIMEOUT_MS / 1000);   // WiFiClient: sekundy
    if (!s_sock.connect(s_host, s_port, MQTT_SOCK_TIMEOUT_MS)) { strlcpy(s_err, "connect", sizeof(s_err)); return false; }

    char cid[32]; snprintf(cid, sizeof(cid), "sensmos-%s", s_id8);
    char wtopic[64]; strlcpy(wtopic, topic("status"), sizeof(wtopic));
    const char* wmsg = "offline";
    bool auth = s_user[0] != 0;

    uint8_t* b = (uint8_t*)s_buf;
    // Variable header: "MQTT" + level 4 + flags + keepalive
    uint8_t flags = 0x02;                        // clean session
    flags |= 0x04;                               // will flag
    flags |= (0x01 << 3);                        // will QoS0 (jawnie 0)
    flags |= 0x20;                               // will retain
    if (auth) flags |= 0x80 | 0x40;              // username + password
    // Payload: clientId, willTopic, willMsg, [user], [pass]
    int vh = 0; uint8_t vhbuf[10];
    vh = put_str(vhbuf, 0, "MQTT");
    vhbuf[vh++] = 0x04;                           // protocol level 3.1.1
    vhbuf[vh++] = flags;
    vhbuf[vh++] = MQTT_KEEPALIVE_S >> 8; vhbuf[vh++] = MQTT_KEEPALIVE_S & 0xFF;

    // Zbuduj payload w s_buf od pozycji po fixed+var header (policzymy remaining najpierw)
    // Prościej: payload do tymczasowego offsetu, potem złożymy.
    uint8_t pl[256]; int pp = 0;
    pp = put_str(pl, pp, cid);
    pp = put_str(pl, pp, wtopic);
    pp = put_str(pl, pp, wmsg);
    if (auth) { pp = put_str(pl, pp, s_user); pp = put_str(pl, pp, s_pass); }

    uint32_t rem = vh + pp;
    int pos = 0;
    b[pos++] = 0x10;                              // CONNECT
    pos += enc_len(b + pos, rem);
    memcpy(b + pos, vhbuf, vh); pos += vh;
    memcpy(b + pos, pl, pp);    pos += pp;
    if (s_sock.write((uint8_t*)b, pos) != (size_t)pos) { s_sock.stop(); strlcpy(s_err, "conn_write", sizeof(s_err)); return false; }

    // CONNACK: 0x20 0x02 <flags> <rc>
    unsigned long t0 = millis();
    while (s_sock.available() < 4) {
        if (millis() - t0 > MQTT_SOCK_TIMEOUT_MS) { s_sock.stop(); strlcpy(s_err, "no_connack", sizeof(s_err)); return false; }
        delay(5);
    }
    uint8_t ack[4]; s_sock.read(ack, 4);
    if (ack[0] != 0x20 || ack[3] != 0x00) {       // rc!=0 → odrzucony (auth/proto)
        s_sock.stop();
        snprintf(s_err, sizeof(s_err), "connack_rc%u", ack[3]);
        return false;
    }
    return true;
}

// ── Encje + HA Discovery ──────────────────────────────────────────────────────
static uint32_t fnv1a(const char* s) {
    uint32_t h = 2166136261u;
    while (*s) { h ^= (uint8_t)*s++; h *= 16777619u; }
    return h;
}

// HA MQTT Discovery dla encji (retained, raz per połączenie). Klucze skrócone (stat_t itd.)
// są oficjalnymi aliasami HA — mieścimy się w buforze bez ściskania.
static void publish_discovery(const char* eid, const char* unit) {
    if (s_disc_n >= MQTT_DISC_MAX) return;
    uint32_t h = fnv1a(eid);
    for (int i = 0; i < s_disc_n; i++) if (s_disc[i] == h) return;   // już poszło

    char objid[40];
    strlcpy(objid, eid, sizeof(objid));
    for (char* p = objid; *p; p++) if (*p == '.') *p = '_';          // HA nie znosi kropek w object_id

    char t[96], cfg[512];
    snprintf(t, sizeof(t), "homeassistant/sensor/sensmos_%s/%s/config", s_id8, objid);
    JsonDocument d;
    d["name"]    = eid;
    { char st[64]; snprintf(st, sizeof(st), "sensmos/%s/ent/%s", s_id8, eid); d["stat_t"] = st; }
    d["val_tpl"] = "{{ value_json.v }}";
    { char uq[56]; snprintf(uq, sizeof(uq), "sensmos_%s_%s", s_id8, objid); d["uniq_id"] = uq; }
    { char av[40]; snprintf(av, sizeof(av), "sensmos/%s/status", s_id8); d["avty_t"] = av; }
    if (unit && unit[0]) d["unit_of_meas"] = unit;
    JsonObject dev = d["dev"].to<JsonObject>();
    { char di[24]; snprintf(di, sizeof(di), "sensmos_%s", s_id8); dev["ids"][0] = di;
      char dn[24]; snprintf(dn, sizeof(dn), "Sensmos %s", s_id8);  dev["name"] = dn; }
    dev["mf"]  = "Sensmos";
    dev["mdl"] = FW_VERSION;
    serializeJson(d, cfg, sizeof(cfg));
    if (mqtt_publish(t, cfg, true)) s_disc[s_disc_n++] = h;
}

// Publish wszystkich encji pub+own (retained). Pełny zrzut co MQTT_ENT_EVERY_MS — prostota
// zamiast śledzenia zmian: 32 małe pakiety/min na brokera w LAN to nic, a HA ma zawsze świeże.
static void publish_entities() {
    char eid[36], val[40], unit[12]; unsigned long ts;
    char t[80], pl[96];
    for (int pass = 0; pass < 2; pass++) {
        int n = pass == 0 ? entity_pub_count() : entity_own_count();
        for (int i = 0; i < n; i++) {
            bool ok = pass == 0 ? entity_get_pub(i, eid, val, unit, &ts)
                                : entity_get_own(i, eid, val, unit, &ts);
            if (!ok || !eid[0]) continue;
            publish_discovery(eid, unit);
            snprintf(t, sizeof(t), "sensmos/%s/ent/%s", s_id8, eid);
            JsonDocument d;
            d["v"] = val;
            if (unit[0]) d["u"] = unit;
            d["ts"] = ts;
            serializeJson(d, pl, sizeof(pl));
            if (!mqtt_publish(t, pl, true)) return;   // padło łącze — reszta przy powrocie
        }
    }
}

// net/wan (retained, tylko przy zmianie): rozróżnia „internet padł" od „node padł" (LWT).
static void publish_wan() {
    uint8_t w = ws_client_wan_state();
    if (w == s_wan_last) return;
    const char* v = w == 1 ? "up" : w == 2 ? "down" : "unknown";
    if (mqtt_publish(topic("net/wan"), v, true)) s_wan_last = w;
}

// ── Snapshot state (diagnostyka noda) ─────────────────────────────────────────
static void publish_state() {
    JsonDocument d;
    d["fw"]   = FW_VERSION;
    d["ip"]   = WiFi.localIP().toString();
    d["rssi"] = WiFi.RSSI();
    d["heap"] = ESP.getFreeHeap();
    d["up"]   = (uint32_t)(millis() / 1000);
    d["ws"]   = ws_client_connected();
    char out[192]; serializeJson(d, out, sizeof(out));
    mqtt_publish(topic("state"), out, true);
}

// ── API ───────────────────────────────────────────────────────────────────────
void mqtt_pub_init() {
    strncpy(s_id8, g_device_id, 8); s_id8[8] = 0;
    Preferences p; p.begin("sensmos", true);
    s_on   = p.getBool("mqtt_on", false);
    p.getString("mqtt_host", s_host, sizeof(s_host));
    s_port = p.getInt("mqtt_port", MQTT_PORT_DEF);
    p.getString("mqtt_user", s_user, sizeof(s_user));
    p.getString("mqtt_pass", s_pass, sizeof(s_pass));
    p.end();
    if (s_on && s_host[0]) LOGI("mqtt", "config: %s:%d (user=%s)", s_host, s_port, s_user[0] ? s_user : "-");
}

bool mqtt_pub_set_config(bool on, const char* host, int port, const char* user, const char* pass) {
    Preferences p; p.begin("sensmos", false);
    p.putBool("mqtt_on", on);
    p.putString("mqtt_host", host ? host : "");
    p.putInt("mqtt_port", port > 0 ? port : MQTT_PORT_DEF);
    p.putString("mqtt_user", user ? user : "");
    p.putString("mqtt_pass", pass ? pass : "");
    p.end();
    // Reload + rozłącz, żeby wejść na nowy config przy najbliższym ticku.
    mqtt_disconnect("reconfig");
    mqtt_pub_init();
    s_next_try = 0; s_backoff_ms = MQTT_RECONNECT_MS;
    return true;
}

void mqtt_pub_status_json(char* out, size_t cap) {
    JsonDocument d;
    d["on"]        = s_on;
    d["connected"] = (s_state == M_UP);
    d["host"]      = s_host;
    d["err"]       = s_err;
    d["tx"]        = s_tx_count;
    serializeJson(d, out, cap);
}

// Most wiadomości Sensmos→HA (wołane z ws_client przy 'message'). Nie retained —
// wiadomość to zdarzenie, nie stan; HA łapie triggerem MQTT.
void mqtt_pub_message(const char* from, const char* eid, const char* payload) {
    if (s_state != M_UP) return;
    JsonDocument d;
    d["from"] = from ? from : "";
    d["eid"]  = eid ? eid : "";
    d["p"]    = payload ? payload : "";
    // ≤512 B payloadu + koperta + zapas na escapowanie JSON-w-stringu (\" podwaja cudzysłowy).
    // Statycznie jak s_enc w ws_client: to leci głęboko w łańcuchu ws.loop() → stack loopTask
    // jest cenny, a kontekst loop = single-writer.
    static char out[1100];
    serializeJson(d, out, sizeof(out));
    mqtt_publish(topic("msg"), out, false);
}

// Wynik preflight-sondy TCP (NW_MQTT). ok → broker osiągalny, próbujemy connect.
void mqtt_pub_on_net_result(const NetResult& nr) {
    s_probe_busy = false;
    if (!s_on || s_state != M_PREFLIGHT) return;
    if (nr.deferred) { s_next_try = millis() + 60000UL; s_state = M_OFF; return; }
    if (!nr.res.ok) {                             // broker nieosiągalny → backoff
        strlcpy(s_err, "unreachable", sizeof(s_err));
        s_state = M_OFF;
        s_next_try = millis() + s_backoff_ms;
        s_backoff_ms = min(s_backoff_ms * 2, (unsigned long)MQTT_RECONNECT_MAX_MS);
        return;
    }
    // Osiągalny → connect (blokujący, krótki).
    if (mqtt_connect()) {
        s_state = M_UP;
        s_backoff_ms = MQTT_RECONNECT_MS;
        strlcpy(s_err, "ok", sizeof(s_err));
        s_disc_n   = 0;      // discovery ponownie (retained, ale po reconnect wysyłamy dla pewności)
        s_wan_last = 0xFF;
        mqtt_publish(topic("status"), "online", true);   // birth (przeciwieństwo LWT)
        publish_state();
        publish_wan();
        publish_entities();
        s_last_state = s_last_ent = s_last_ping = millis();
        LOGI("mqtt", "połączony z %s:%d", s_host, s_port);
    } else {
        s_state = M_OFF;
        s_next_try = millis() + s_backoff_ms;
        s_backoff_ms = min(s_backoff_ms * 2, (unsigned long)MQTT_RECONNECT_MAX_MS);
    }
}

void mqtt_pub_tick() {
    if (!s_on || !s_host[0] || WiFi.status() != WL_CONNECTED) {
        if (s_state != M_OFF) mqtt_disconnect("wifi/off");
        return;
    }
    unsigned long now = millis();

    if (s_state == M_UP) {
        // Drenuj RX (CONNACK już zjedliśmy; broker może słać PINGRESP — ignorujemy treść).
        while (s_sock.available()) s_sock.read();
        if (!s_sock.connected()) { mqtt_disconnect("dropped"); s_next_try = now + s_backoff_ms; return; }
        if (now - s_last_ping >= (unsigned long)MQTT_KEEPALIVE_S * 1000 / 2) {
            uint8_t ping[2] = { 0xC0, 0x00 };
            if (s_sock.write(ping, 2) != 2) { mqtt_disconnect("ping"); s_next_try = now + s_backoff_ms; return; }
            s_last_ping = now;
        }
        if (now - s_last_state >= (unsigned long)MQTT_STATE_EVERY_MS) {
            publish_state();
            publish_wan();       // tanio: publikuje tylko przy zmianie stanu
            s_last_state = now;
        }
        if (now - s_last_ent >= (unsigned long)MQTT_ENT_EVERY_MS) {
            publish_entities();
            s_last_ent = now;
        }
        return;
    }

    // PREFLIGHT bez wyniku (teoretycznie zgubiony job) → nie wisimy wiecznie: wróć do OFF.
    // Spóźniony wynik jest niegroźny — on_net_result czyści probe_busy i wychodzi na guardzie stanu.
    if (s_state == M_PREFLIGHT && now - s_pref_at > 30000UL) {
        s_probe_busy = false;
        s_state = M_OFF;
        s_next_try = now + s_backoff_ms;
        strlcpy(s_err, "probe_lost", sizeof(s_err));
    }

    // OFF → gdy nadszedł czas: odpal preflight sondę TCP na worze (nieblokujące).
    if (s_state == M_OFF && !s_probe_busy && (long)(now - s_next_try) >= 0) {
        NetJob nj{};
        nj.src = NW_MQTT;
        strlcpy(nj.job.kind, "tcp", sizeof(nj.job.kind));
        strlcpy(nj.job.host, s_host, sizeof(nj.job.host));
        nj.job.port       = s_port;
        nj.job.timeout_ms = MQTT_SOCK_TIMEOUT_MS;
        if (net_worker_enqueue(nj, false)) { s_probe_busy = true; s_state = M_PREFLIGHT; s_pref_at = now; }
        else s_next_try = now + 5000UL;           // wór pełny — spróbuj za 5 s
    }
}
