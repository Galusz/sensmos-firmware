/**
 * SENSMOS — RemoteTerminal (tunnel.cpp). Patrz tunnel.h.
 *
 * Model wątkowy:
 *   - tun_task (osobny task): JEDYNY właściciel socketu LAN (WiFiClient). Czyta/pisze socket.
 *   - loop() (tunnel_tick): JEDYNY, który dotyka WS. Bajty przechodzą przez kolejki.
 *
 * Kolejki:
 *   s_cmdQ  loop→task : {OPEN ip:port | CLOSE}
 *   s_toLan loop→task : bajty BE→LAN (tun_data od BE, zdekodowane) → task pisze do socketu
 *   s_toBe  task→loop : bajty LAN→BE (odczyt z socketu) → tick koduje base64 i wysyła tun_data
 *   s_stQ   task→loop : zmiany stanu (open/closed/error) → tick wysyła tun_state
 */
#include "tunnel.h"
#include "log.h"
#include "ws_client.h"
#include "data_sender.h"   // g_tx_scratch / TX_SCRATCH_LEN (bufor TX loop-only)
#include <WiFi.h>
#include <Preferences.h>
#include <mbedtls/base64.h>

// ── Parametry ──────────────────────────────────────────────────
#define TUN_CHUNK        1024          // bajtów na porcję (base64 → ~1420B JSON, mieści się w enc seal 3072)
#define TUN_QDEPTH       6             // głębokość kolejek danych
#define TUN_STACK        4096
#define TUN_CONNECT_MS   8000          // timeout connect do celu LAN
#define TUN_IDLE_MS      (5UL*60*1000) // brak bajtów → auto-close (chroni socket)
#define TUN_SESSION_MS   (2UL*60*60*1000UL) // twardy limit sesji
#define TUN_TICK_MAX     4             // ile porcji LAN→BE max na jeden tick (nie zajeżdżaj loop)

enum { CMD_OPEN = 1, CMD_CLOSE = 2 };
enum { ST_OPEN = 1, ST_CLOSED = 2, ST_ERROR = 3 };
enum { S_IDLE = 0, S_OPEN = 1 };

struct TunCmd   { uint8_t op; int tid; char ip[40]; uint16_t port; };
struct TunChunk { uint16_t len; uint8_t d[TUN_CHUNK]; };
struct TunState { int tid; uint8_t st; char msg[48]; };

// ── Stan podsystemu ────────────────────────────────────────────
static bool          s_up      = false;   // task+kolejki utworzone
static volatile bool s_enabled = false;   // NVS remote_ok
static QueueHandle_t s_cmdQ = nullptr, s_toLan = nullptr, s_toBe = nullptr, s_stQ = nullptr;
static WiFiClient    s_cli;
static volatile int  s_state = S_IDLE;
static volatile int  s_tid   = 0;

// ── Helpers ────────────────────────────────────────────────────
static bool nvs_get_remote_ok() {
    Preferences p; p.begin("sensmos", true);
    bool v = p.getBool("remote_ok", false); p.end();
    return v;
}
static void nvs_set_remote_ok(bool v) {
    Preferences p; p.begin("sensmos", false);
    p.putBool("remote_ok", v); p.end();
}

// RFC1918 / CGNAT / loopback / link-local — tylko prywatne cele (nigdy publiczny internet)
static bool is_private(const IPAddress& ip) {
    uint8_t a = ip[0], b = ip[1];
    if (a == 10 || a == 127)                 return true;
    if (a == 192 && b == 168)                return true;
    if (a == 172 && b >= 16 && b <= 31)      return true;
    if (a == 169 && b == 254)                return true;   // link-local
    if (a == 100 && b >= 64 && b <= 127)     return true;   // CGNAT 100.64/10
    return false;
}

static void push_state(int tid, uint8_t st, const char* msg) {
    if (!s_stQ) return;
    TunState s; s.tid = tid; s.st = st;
    strncpy(s.msg, msg ? msg : "", sizeof(s.msg) - 1); s.msg[sizeof(s.msg) - 1] = '\0';
    xQueueSend(s_stQ, &s, 0);
}

// ── Task: właściciel socketu LAN ───────────────────────────────
static unsigned long s_lastAct = 0, s_openedAt = 0;

static void do_close(const char* reason) {
    if (s_state == S_IDLE) return;
    s_cli.stop();
    // wyrzuć zaległe bajty do-LAN (nieaktualne po zamknięciu)
    TunChunk drop; while (s_toLan && xQueueReceive(s_toLan, &drop, 0) == pdTRUE) {}
    int tid = s_tid;
    s_state = S_IDLE; s_tid = 0;
    push_state(tid, ST_CLOSED, reason);
    LOGI("tun", "closed tid=%d (%s)", tid, reason ? reason : "");
}

static void do_open(const TunCmd& c) {
    if (!s_enabled)          { push_state(c.tid, ST_ERROR, "remote access disabled"); return; }
    if (s_state != S_IDLE)   { push_state(c.tid, ST_ERROR, "busy (one tunnel at a time)"); return; }
    IPAddress ip;
    if (!ip.fromString(c.ip)) { push_state(c.tid, ST_ERROR, "target must be a literal IP"); return; }
    if (!is_private(ip))      { push_state(c.tid, ST_ERROR, "only private LAN addresses allowed"); return; }

    s_cli.setTimeout(TUN_CONNECT_MS / 1000);
    LOGI("tun", "open tid=%d → %s:%u", c.tid, c.ip, c.port);
    if (!s_cli.connect(ip, c.port, TUN_CONNECT_MS)) {
        push_state(c.tid, ST_ERROR, "connect failed");
        return;
    }
    s_cli.setNoDelay(true);
    s_tid = c.tid; s_state = S_OPEN;
    s_lastAct = s_openedAt = millis();
    push_state(c.tid, ST_OPEN, "connected");
}

static void pump_io() {
    // LAN → BE
    while (s_cli.available() > 0) {
        TunChunk ch;
        int n = s_cli.read(ch.d, TUN_CHUNK);
        if (n <= 0) break;
        ch.len = (uint16_t)n;
        if (xQueueSend(s_toBe, &ch, 0) != pdTRUE) break;   // kolejka pełna → backpressure, spróbuj za tick
        s_lastAct = millis();
    }
    // BE → LAN
    TunChunk ch;
    while (xQueueReceive(s_toLan, &ch, 0) == pdTRUE) {
        s_cli.write(ch.d, ch.len);
        s_lastAct = millis();
    }
    // peer zamknął?
    if (!s_cli.connected() && s_cli.available() == 0) { do_close("peer closed"); return; }
    // timeouty
    if (millis() - s_lastAct  > TUN_IDLE_MS)    { do_close("idle timeout"); return; }
    if (millis() - s_openedAt > TUN_SESSION_MS) { do_close("session limit"); return; }
}

static void tun_task(void*) {
    for (;;) {
        TunCmd c;
        if (xQueueReceive(s_cmdQ, &c, s_state == S_OPEN ? 0 : portMAX_DELAY) == pdTRUE) {
            if      (c.op == CMD_OPEN)  do_open(c);
            else if (c.op == CMD_CLOSE) do_close("closed by user");
        }
        if (s_state == S_OPEN) pump_io();
        else                   vTaskDelay(pdMS_TO_TICKS(10));
    }
}

// ── Init / spin-up ─────────────────────────────────────────────
void tunnel_init() {
    s_enabled = nvs_get_remote_ok();
    if (!s_enabled || s_up) return;          // wyłączone (cała flota) → zero footprint
    s_cmdQ  = xQueueCreate(4, sizeof(TunCmd));
    s_toLan = xQueueCreate(TUN_QDEPTH, sizeof(TunChunk));
    s_toBe  = xQueueCreate(TUN_QDEPTH, sizeof(TunChunk));
    s_stQ   = xQueueCreate(8, sizeof(TunState));
    if (!s_cmdQ || !s_toLan || !s_toBe || !s_stQ) { LOGE("tun", "queue alloc failed"); return; }
    const BaseType_t core = portNUM_PROCESSORS - 1;
    xTaskCreatePinnedToCore(tun_task, "tunnel", TUN_STACK, nullptr, 3, nullptr, core);  // prio<net_worker(5)
    s_up = true;
    LOGI("tun", "remote access ENABLED — subsystem up (~12KB)");
}

bool tunnel_enabled() { return s_enabled; }

// ── Dispatch z ws_client (kontekst loop) ───────────────────────
static void reply_state_direct(int tid, const char* st, const char* msg) {
    // gdy podsystem nie działa (remote off) — odpowiedz od razu w loopie (WS-safe)
    char buf[128];
    snprintf(buf, sizeof(buf), "{\"type\":\"tun_state\",\"tid\":%d,\"st\":\"%s\",\"msg\":\"%s\"}", tid, st, msg);
    ws_client_send_raw(buf);
}

void tunnel_on_open(int tid, const char* ip, int port) {
    if (!s_enabled) { reply_state_direct(tid, "error", "remote access disabled"); return; }
    if (!s_up) tunnel_init();
    if (!s_cmdQ) { reply_state_direct(tid, "error", "subsystem not ready"); return; }
    TunCmd c; c.op = CMD_OPEN; c.tid = tid; c.port = (uint16_t)port;
    strncpy(c.ip, ip ? ip : "", sizeof(c.ip) - 1); c.ip[sizeof(c.ip) - 1] = '\0';
    xQueueSend(s_cmdQ, &c, 0);
}

void tunnel_on_data(int tid, const char* b64) {
    if (!s_up || !s_toLan || !b64) return;
    if (s_state != S_OPEN || tid != s_tid) return;   // brak aktywnego tunelu o tym id → drop
    size_t inlen = strlen(b64), olen = 0;
    TunChunk ch;
    if (mbedtls_base64_decode(ch.d, TUN_CHUNK, &olen, (const uint8_t*)b64, inlen) != 0 || olen == 0) return;
    ch.len = (uint16_t)olen;
    xQueueSend(s_toLan, &ch, pdMS_TO_TICKS(50));      // krótki backpressure zamiast gubienia bajtów
}

void tunnel_on_close(int tid) {
    if (!s_up || !s_cmdQ) return;
    TunCmd c; c.op = CMD_CLOSE; c.tid = tid; c.ip[0] = 0; c.port = 0;
    xQueueSend(s_cmdQ, &c, 0);
}

void tunnel_set_enabled(bool on) {
    nvs_set_remote_ok(on);
    s_enabled = on;
    if (on)  tunnel_init();            // spin up (idempotentne)
    else if (s_up) tunnel_on_close(s_tid);   // wyłączenie → zamknij aktywny; nowe openy odrzuci gate
    LOGI("tun", "remote access %s", on ? "ENABLED" : "DISABLED");
}

// ── Tick (kontekst loop — WS-safe) ─────────────────────────────
void tunnel_tick() {
    if (!s_up) return;
    // stany → tun_state
    TunState st;
    while (xQueueReceive(s_stQ, &st, 0) == pdTRUE) {
        const char* s = st.st == ST_OPEN ? "open" : st.st == ST_CLOSED ? "closed" : "error";
        char buf[128];
        snprintf(buf, sizeof(buf), "{\"type\":\"tun_state\",\"tid\":%d,\"st\":\"%s\",\"msg\":\"%s\"}", st.tid, s, st.msg);
        ws_client_send_raw(buf);
    }
    // bajty LAN→BE → tun_data (base64), max TUN_TICK_MAX porcji na tick
    static uint8_t b64[TUN_CHUNK * 2];      // base64 z 1024B = ~1368B, z zapasem
    TunChunk ch;
    for (int i = 0; i < TUN_TICK_MAX && xQueueReceive(s_toBe, &ch, 0) == pdTRUE; i++) {
        size_t olen = 0;
        if (mbedtls_base64_encode(b64, sizeof(b64), &olen, ch.d, ch.len) != 0) continue;
        b64[olen] = '\0';
        // JSON ręcznie (base64 nie ma znaków wymagających escapowania)
        char* out = g_tx_scratch;   // współdzielony bufor TX (loop-only, jak reszta wysyłek)
        int n = snprintf(out, TX_SCRATCH_LEN, "{\"type\":\"tun_data\",\"tid\":%d,\"d\":\"%s\"}", s_tid, (char*)b64);
        if (n > 0 && n < TX_SCRATCH_LEN) ws_client_send_raw(out);
    }
}
