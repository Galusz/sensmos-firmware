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
#define TUN_QDEPTH       6             // głębokość kolejki s_toBe (LAN→BE)
#define TUN_LAN_QDEPTH   6             // s_toLan (BE→LAN). 0.71: 12→6 (bump 0.69 był pod złą diagnozę —
                                       // app→LAN łagodzi pace apki + fix dartssh2 2.14) → odzysk ~6KB heapu
// 0.69 — throttle „rury TCP" (pomysł usera): czytaj z socketu LAN max TUN_READ_PER_WIN / TUN_WIN_MS.
// Nadmiar zostaje w buforze TCP → okno się zamyka → serwer (htop) zwalnia = flow control ZA DARMO,
// zero dropu. Robi z tunelu „wolny serial": pod zalewem degraduje TEMPO, nie zrywa sesji.
#define TUN_WIN_MS       100
#define TUN_READ_PER_WIN 3072          // 3KB/100ms ≈ 30KB/s — wolno, ale komplet i stabilnie
#define TUN_STACK        8192          // TunChunk (1KB) na stosie + WiFiClient.connect → 4096 przepełniał (canary crash)
#define TUN_CONNECT_MS   8000          // timeout connect do celu LAN
#define TUN_IDLE_MS      (5UL*60*1000) // brak bajtów → auto-close (chroni socket)
#define TUN_SESSION_MS   (2UL*60*60*1000UL) // twardy limit sesji
#define TUN_TICK_MAX     4             // ile porcji LAN→BE max na jeden tick (nie zajeżdżaj loop)
#define TUN_TEARDOWN_MS  (2UL*60*1000) // linger po sesji zanim podsystem odda RAM (reconnect nie churnuje heapu)

enum { CMD_OPEN = 1, CMD_CLOSE = 2, CMD_SHUTDOWN = 3 };
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
// Bufory robocze — 0.71: na HEAP (alokowane w tun_spin_up), NIE function-static/BSS. Skutek:
// nody z remote_ok=false NIGDY nie alokują → 0 bajtów (wcześniej ~6KB BSS na CAŁEJ flocie).
static TunChunk *s_chPump = nullptr, *s_chDrop = nullptr, *s_chData = nullptr, *s_chTick = nullptr;
static uint8_t  *s_b64 = nullptr;   // base64 scratch (TUN_CHUNK*2), loop-only
// 0.72 — teardown on-demand: loop prosi taska o zejście (CMD_SHUTDOWN), task potwierdza flagą
// jako OSTATNIĄ instrukcją przed vTaskDelete, dopiero wtedy loop zwalnia kolejki/bufory (bez wyścigu).
static volatile bool s_task_dead    = false;
static bool          s_shutdown_req = false;
static unsigned long s_idle_since   = 0;

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
    // wyrzuć zaległe bajty do-LAN (nieaktualne po zamknięciu). bufor na heapie (task-ctx).
    while (s_toLan && s_chDrop && xQueueReceive(s_toLan, s_chDrop, 0) == pdTRUE) {}
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
    TunChunk* ch = s_chPump;   // bufor roboczy na heapie (task-ctx, jednowątkowy → bez reentrancji)
    // LAN → BE (throttle rury TCP): czytaj max TUN_READ_PER_WIN bajtów / okno TUN_WIN_MS.
    // Nie czytamy nadmiaru → zostaje w buforze socketu → okno TCP się zamyka → serwer zwalnia.
    static unsigned long s_win = 0;
    static uint32_t s_read = 0;
    unsigned long now = millis();
    if (now - s_win >= TUN_WIN_MS) { s_win = now; s_read = 0; }
    while (s_cli.available() > 0 && s_read < TUN_READ_PER_WIN) {
        uint32_t room = TUN_READ_PER_WIN - s_read;
        int n = s_cli.read(ch->d, room < TUN_CHUNK ? (int)room : TUN_CHUNK);
        if (n <= 0) break;
        ch->len = (uint16_t)n;
        if (xQueueSend(s_toBe, ch, 0) != pdTRUE) break;   // s_toBe pełne → backpressure, spróbuj za tick
        s_read += (uint32_t)n;
        s_lastAct = millis();
    }
    // BE → LAN
    while (xQueueReceive(s_toLan, ch, 0) == pdTRUE) {
        s_cli.write(ch->d, ch->len);
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
            else if (c.op == CMD_SHUTDOWN) {
                do_close("shutdown");
                s_task_dead = true;          // od tej linii task NIE dotyka kolejek/buforów
                vTaskDelete(nullptr);
            }
        }
        // KRYTYCZNE: oddaj CPU nawet przy otwartym tunelu. Bez tego task (prio 3 > loop 1) kręcił
        // się w pętli pump_io bez przerwy → zagłodził główną pętlę → serial i WS stawały (starvation).
        // 2ms = ~500 przebiegów/s, w zupełności starcza dla interaktywnego SSH.
        if (s_state == S_OPEN) { pump_io(); vTaskDelay(pdMS_TO_TICKS(2)); }
        else                   vTaskDelay(pdMS_TO_TICKS(10));
    }
}

// ── Init / spin-up / teardown ──────────────────────────────────
// 0.72 — ON-DEMAND: przełącznik remote to CZYSTA POLITYKA (flaga NVS + gate w do_open).
// Podsystem (~27KB: kolejki ~13KB + stack 8KB + bufory ~6KB) wstaje dopiero przy tun_open
// i schodzi po sesji (linger TUN_TEARDOWN_MS) lub od razu przy disable. Bez sesji: 0 bajtów.
void tunnel_init() {
    s_enabled = nvs_get_remote_ok();         // boot: tylko polityka, zero alokacji
}

static void tun_free_all() {
    if (s_cmdQ)  { vQueueDelete(s_cmdQ);  s_cmdQ  = nullptr; }
    if (s_toLan) { vQueueDelete(s_toLan); s_toLan = nullptr; }
    if (s_toBe)  { vQueueDelete(s_toBe);  s_toBe  = nullptr; }
    if (s_stQ)   { vQueueDelete(s_stQ);   s_stQ   = nullptr; }
    free(s_chPump); free(s_chDrop); free(s_chData); free(s_chTick); free(s_b64);
    s_chPump = s_chDrop = s_chData = s_chTick = nullptr; s_b64 = nullptr;
    s_up = false; s_shutdown_req = false; s_task_dead = false; s_idle_since = 0;
}

static bool tun_spin_up() {
    if (s_up) return true;
    s_cmdQ  = xQueueCreate(4, sizeof(TunCmd));
    s_toLan = xQueueCreate(TUN_LAN_QDEPTH, sizeof(TunChunk));
    s_toBe  = xQueueCreate(TUN_QDEPTH, sizeof(TunChunk));
    s_stQ   = xQueueCreate(8, sizeof(TunState));
    s_chPump = (TunChunk*)malloc(sizeof(TunChunk)); s_chDrop = (TunChunk*)malloc(sizeof(TunChunk));
    s_chData = (TunChunk*)malloc(sizeof(TunChunk)); s_chTick = (TunChunk*)malloc(sizeof(TunChunk));
    s_b64    = (uint8_t*)malloc(TUN_CHUNK * 2);
    if (!s_cmdQ || !s_toLan || !s_toBe || !s_stQ ||
        !s_chPump || !s_chDrop || !s_chData || !s_chTick || !s_b64) {
        LOGE("tun", "spin-up alloc failed — rollback");
        tun_free_all();
        return false;
    }
    s_task_dead = false;
    const BaseType_t core = portNUM_PROCESSORS - 1;
    if (xTaskCreatePinnedToCore(tun_task, "tunnel", TUN_STACK, nullptr, 3, nullptr, core) != pdPASS) {  // prio<net_worker(5)
        LOGE("tun", "spin-up task failed — rollback");
        tun_free_all();
        return false;
    }
    s_up = true; s_idle_since = 0;
    LOGI("tun", "spin-up (~27KB heap - session only)");
    return true;
}

bool tunnel_enabled() { return s_enabled; }
bool tunnel_active()  { return s_state == S_OPEN; }

// ── Dispatch z ws_client (kontekst loop) ───────────────────────
static void reply_state_direct(int tid, const char* st, const char* msg) {
    // gdy podsystem nie działa (remote off) — odpowiedz od razu w loopie (WS-safe)
    char buf[128];
    snprintf(buf, sizeof(buf), "{\"type\":\"tun_state\",\"tid\":%d,\"st\":\"%s\",\"msg\":\"%s\"}", tid, st, msg);
    ws_client_send_raw(buf);
}

void tunnel_on_open(int tid, const char* ip, int port) {
    if (!s_enabled) { reply_state_direct(tid, "error", "remote access disabled"); return; }
    if (s_shutdown_req) { reply_state_direct(tid, "error", "restarting, retry"); return; }   // okno ms-sek., APP ponowi
    if (!s_up && !tun_spin_up()) { reply_state_direct(tid, "error", "low memory, retry"); return; }
    if (!s_cmdQ) { reply_state_direct(tid, "error", "subsystem not ready"); return; }
    TunCmd c; c.op = CMD_OPEN; c.tid = tid; c.port = (uint16_t)port;
    strncpy(c.ip, ip ? ip : "", sizeof(c.ip) - 1); c.ip[sizeof(c.ip) - 1] = '\0';
    xQueueSend(s_cmdQ, &c, 0);
}

void tunnel_on_data(int tid, const char* b64) {
    if (!s_up || !s_toLan || !b64) return;
    if (s_state != S_OPEN || tid != s_tid) return;   // brak aktywnego tunelu o tym id → drop
    size_t inlen = strlen(b64), olen = 0;
    TunChunk* ch = s_chData;   // bufor na heapie (loop-ctx)
    if (!ch || mbedtls_base64_decode(ch->d, TUN_CHUNK, &olen, (const uint8_t*)b64, inlen) != 0 || olen == 0) return;
    ch->len = (uint16_t)olen;
    xQueueSend(s_toLan, ch, pdMS_TO_TICKS(50));      // krótki backpressure zamiast gubienia bajtów
}

void tunnel_on_close(int tid) {
    if (!s_up || !s_cmdQ) return;
    TunCmd c; c.op = CMD_CLOSE; c.tid = tid; c.ip[0] = 0; c.port = 0;
    xQueueSend(s_cmdQ, &c, 0);
}

void tunnel_set_enabled(bool on) {
    nvs_set_remote_ok(on);
    s_enabled = on;
    // ON = tylko polityka (spin-up dopiero przy tun_open). OFF: zamknij sesję; teardown zrobi
    // tick (stan→IDLE + !enabled = natychmiastowy shutdown → ~27KB wraca do heapu).
    if (!on && s_up) tunnel_on_close(s_tid);
    LOGI("tun", "remote access %s", on ? "ENABLED (policy)" : "DISABLED");
}

// ── Tick (kontekst loop — WS-safe) ─────────────────────────────
void tunnel_tick() {
    if (!s_up) return;
    // teardown w toku: dopchnij CMD_SHUTDOWN (idempotentne — retry gdyby kolejka była pełna),
    // a po potwierdzeniu zejścia taska zwolnij wszystko (loop-ctx, bez wyścigu z ws_client).
    if (s_shutdown_req) {
        if (!s_task_dead) {
            TunCmd c; c.op = CMD_SHUTDOWN; c.tid = 0; c.ip[0] = 0; c.port = 0;
            xQueueSend(s_cmdQ, &c, 0);
            return;
        }
        tun_free_all();
        LOGI("tun", "teardown — ~27KB wrocilo do heapu");
        return;
    }
    // stany → tun_state
    TunState st;
    while (xQueueReceive(s_stQ, &st, 0) == pdTRUE) {
        const char* s = st.st == ST_OPEN ? "open" : st.st == ST_CLOSED ? "closed" : "error";
        char buf[128];
        snprintf(buf, sizeof(buf), "{\"type\":\"tun_state\",\"tid\":%d,\"st\":\"%s\",\"msg\":\"%s\"}", st.tid, s, st.msg);
        ws_client_send_raw(buf);
    }
    // bajty LAN→BE → tun_data (base64), max TUN_TICK_MAX porcji na tick
    uint8_t*  b64 = s_b64;      // base64 scratch na heapie (TUN_CHUNK*2)
    TunChunk* ch  = s_chTick;   // bufor na heapie (loop-ctx)
    for (int i = 0; i < TUN_TICK_MAX && xQueueReceive(s_toBe, ch, 0) == pdTRUE; i++) {
        size_t olen = 0;
        if (mbedtls_base64_encode(b64, TUN_CHUNK * 2, &olen, ch->d, ch->len) != 0) continue;  // enc fail — pomiń
        b64[olen] = '\0';
        // JSON ręcznie (base64 nie ma znaków wymagających escapowania)
        char* out = g_tx_scratch;   // współdzielony bufor TX (loop-only, jak reszta wysyłek)
        int n = snprintf(out, TX_SCRATCH_LEN, "{\"type\":\"tun_data\",\"tid\":%d,\"d\":\"%s\"}", s_tid, (char*)b64);
        if (n <= 0 || n >= TX_SCRATCH_LEN) continue;
        // C (backpressure): gdy WS nie wyśle (seal fail / TX full / niski heap) — NIE gub bajtu
        // SSH (drop = MAC fail = zerwana sesja). Wróć chunk na PRZÓD kolejki i przerwij tick;
        // s_toBe zostaje pełne → pump_io przestaje czytać socket LAN → TCP backpressure do hosta
        // (htop zwalnia zamiast nas zabić). Retry w następnym ticku, gdy heap/TX wróci.
        if (!ws_client_send_raw(out)) { xQueueSendToFront(s_toBe, ch, 0); break; }
    }
    // on-demand (0.72): sesja zamknięta → linger TUN_TEARDOWN_MS i oddaj RAM; disable → od razu
    if (s_state == S_IDLE) {
        if (!s_enabled)              s_shutdown_req = true;
        else if (!s_idle_since)      s_idle_since = millis();
        else if (millis() - s_idle_since > TUN_TEARDOWN_MS) s_shutdown_req = true;
    } else s_idle_since = 0;
}
