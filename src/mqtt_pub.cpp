#include "mqtt_pub.h"
#include "config.h"
#include "net_worker.h"
#include "identity.h"
#include "data_sender.h"   // FW_VERSION
#include "ws_client.h"     // ws_client_connected (pole "ws" w state)
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
static unsigned long s_next_try    = 0;
static unsigned long s_backoff_ms  = MQTT_RECONNECT_MS;
static unsigned long s_last_state  = 0;   // ostatni publish state
static unsigned long s_last_ping   = 0;
static uint32_t      s_tx_count    = 0;
static char          s_err[24]     = "idle";

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
        mqtt_publish(topic("status"), "online", true);   // birth (przeciwieństwo LWT)
        publish_state();
        s_last_state = s_last_ping = millis();
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
            s_last_state = now;
        }
        return;
    }

    // OFF → gdy nadszedł czas: odpal preflight sondę TCP na worze (nieblokujące).
    if (s_state == M_OFF && !s_probe_busy && (long)(now - s_next_try) >= 0) {
        NetJob nj{};
        nj.src = NW_MQTT;
        strlcpy(nj.job.kind, "tcp", sizeof(nj.job.kind));
        strlcpy(nj.job.host, s_host, sizeof(nj.job.host));
        nj.job.port       = s_port;
        nj.job.timeout_ms = MQTT_SOCK_TIMEOUT_MS;
        if (net_worker_enqueue(nj, false)) { s_probe_busy = true; s_state = M_PREFLIGHT; }
        else s_next_try = now + 5000UL;           // wór pełny — spróbuj za 5 s
    }
}
