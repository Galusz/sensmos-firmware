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
#include "pairing.h"
#include "log.h"
#include "ws_client.h"
#include <WiFi.h>
#include <Preferences.h>
#include <mbedtls/gcm.h>
#include <esp_random.h>

// ── Parametry ──────────────────────────────────────────────────
#define TUN_CHUNK        1024          // bajtów na porcję (+36B szyfru → 1060B w kopercie enc 3072)
#define TUN_QDEPTH       6             // głębokość kolejki s_toBe (LAN→BE)
#define TUN_LAN_QDEPTH   6             // s_toLan (BE→LAN). 0.71: 12→6 (bump 0.69 był pod złą diagnozę —
                                       // app→LAN łagodzi pace apki + fix dartssh2 2.14) → odzysk ~6KB heapu
// 0.69 — throttle „rury TCP" (pomysł usera): czytaj z socketu LAN max TUN_READ_PER_WIN / TUN_WIN_MS.
// Nadmiar zostaje w buforze TCP → okno się zamyka → serwer (htop) zwalnia = flow control ZA DARMO,
// zero dropu. Robi z tunelu „wolny serial": pod zalewem degraduje TEMPO, nie zrywa sesji.
#define TUN_WIN_MS       100
#define TUN_READ_PER_WIN 10240         // 10KB/100ms ≈ 100KB/s (0.93: 3072→10240 pod Panel LAN);
                                       // realne tempo i tak ogranicza WS+szyfrowanie, a backpressure
                                       // (s_toBe pełne / WS fail → wstrzymaj odczyt socketu) zostaje
#define TUN_STACK        8192          // TunChunk (1KB) na stosie + WiFiClient.connect → 4096 przepełniał (canary crash)
#define TUN_CONNECT_MS   8000          // timeout connect do celu LAN
#define TUN_IDLE_MS      (5UL*60*1000) // brak bajtów → auto-close (chroni socket)
#define TUN_SESSION_MS   (2UL*60*60*1000UL) // twardy limit sesji
#define TUN_TICK_MAX     4             // ile porcji LAN→BE max na jeden tick (nie zajeżdżaj loop)
#define TUN_TEARDOWN_MS  (2UL*60*1000) // linger po sesji zanim podsystem odda RAM (reconnect nie churnuje heapu)

enum { CMD_OPEN = 1, CMD_CLOSE = 2, CMD_SHUTDOWN = 3 };
enum { ST_OPEN = 1, ST_CLOSED = 2, ST_ERROR = 3 };
enum { S_IDLE = 0, S_OPEN = 1 };

// ── Szyfrowanie sesji (v2) ─────────────────────────────────────
// Ramka: [seq u64 BE][nonce 12][ciphertext][tag 16]  — narzut 36 B na porcję (+3,5%).
//
// Nonce jest LOSOWY, nie licznikowy, bo klucz sesji wyprowadza się z klucza parowania i jest
// TEN SAM przez wszystkie sesje i restarty noda. Licznik od zera powtórzyłby parę (klucz,
// nonce) po każdym restarcie, a w GCM powtórka to nie „słabsze szyfrowanie", tylko wyciek:
// XOR dwóch szyfrogramów daje XOR tekstów jawnych i kompromituje klucz uwierzytelniania.
// 96 bitów losowości → granica urodzinowa ~2^48 porcji; przy 100 porcjach/s nieosiągalne.
//
// seq jest jawny (nie jest sekretem) i wchodzi do AAD: chroni przed powtórzeniem i
// przestawieniem porcji przez BE. Przy SSH skończyłoby się to zerwaniem sesji, ale przy
// panelu HA powtórzony POST to powtórzone „włącz". Odbiorca wymaga ściśle rosnącego seq;
// dziury są dozwolone (porcja mogła zginąć przy backpressure i zostać zaszyfrowana od nowa).
//
// AAD = "tun2" ‖ ts(u32 BE, z tun_open) ‖ dir(u8) ‖ seq(u64 BE). `ts` wiąże ramkę z KONKRETNĄ
// sesją (ramka z wczoraj nie przejdzie dziś), `dir` odcina odbicie ramki z powrotem do nadawcy.
#define TUN_SEQ_LEN    8
#define TUN_NONCE_LEN  12
#define TUN_TAG_LEN    16
#define TUN_OVERHEAD   (TUN_SEQ_LEN + TUN_NONCE_LEN + TUN_TAG_LEN)   // 36
#define TUN_DIR_TO_BE  0    // node → apka
#define TUN_DIR_TO_LAN 1    // apka → node

struct TunCmd   { uint8_t op; int tid; char ip[40]; uint16_t port; };
struct TunChunk { uint16_t len; uint8_t d[TUN_CHUNK]; };
struct TunState { int tid; uint8_t st; char msg[48]; };

// ── Stan podsystemu ────────────────────────────────────────────
static bool          s_up      = false;   // task+kolejki utworzone
static QueueHandle_t s_cmdQ = nullptr, s_toLan = nullptr, s_toBe = nullptr, s_stQ = nullptr;
static WiFiClient    s_cli;
static volatile int  s_state = S_IDLE;
static volatile int  s_tid   = 0;
// Bufory robocze — 0.71: na HEAP (alokowane w tun_spin_up), NIE function-static/BSS. Skutek:
// nody bez klucza parowania NIGDY nie alokują → 0 bajtów (wcześniej ~6KB BSS na CAŁEJ flocie).
static TunChunk *s_chPump = nullptr, *s_chDrop = nullptr, *s_chData = nullptr, *s_chTick = nullptr;
static uint8_t  *s_crypt = nullptr;   // scratch ramki v2 (TUN_CHUNK+TUN_OVERHEAD), loop-only

// Sekrety sesji — ustawiane przy open, zerowane przy close (klucz nie leży w RAM po sesji).
static uint8_t  s_key[32] = {0};
static int      s_key_tid = 0;        // do KTÓREJ sesji należy klucz (patrz wymazywanie w tick)
static uint32_t s_ts  = 0;            // znacznik z tun_open → AAD
static uint64_t s_seq_tx = 0;         // nasz licznik (node → apka)
static uint64_t s_seq_rx = 0;         // ostatni przyjęty od apki
static bool     s_rx_init = false;
// 0.72 — teardown on-demand: loop prosi taska o zejście (CMD_SHUTDOWN), task potwierdza flagą
// jako OSTATNIĄ instrukcją przed vTaskDelete, dopiero wtedy loop zwalnia kolejki/bufory (bez wyścigu).
static volatile bool s_task_dead    = false;
static bool          s_shutdown_req = false;
static unsigned long s_idle_since   = 0;

// ── Helpers ────────────────────────────────────────────────────
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

// ── Krypto sesji (WYŁĄCZNIE kontekst loop: tick i tunnel_on_data) ──────────────
static void put_u64(uint8_t* p, uint64_t v) { for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8 * (7 - i))); }
static uint64_t get_u64(const uint8_t* p) { uint64_t v = 0; for (int i = 0; i < 8; i++) v = (v << 8) | p[i]; return v; }

#define TUN_AAD_LEN 17
static void tun_aad(uint8_t aad[TUN_AAD_LEN], uint8_t dir, uint64_t seq) {
    memcpy(aad, "tun2", 4);
    aad[4] = (uint8_t)(s_ts >> 24); aad[5] = (uint8_t)(s_ts >> 16);
    aad[6] = (uint8_t)(s_ts >> 8);  aad[7] = (uint8_t)s_ts;
    aad[8] = dir;
    put_u64(aad + 9, seq);
}

// pt → [seq][nonce][ct][tag]. Zwraca długość ramki albo -1.
static int tun_seal(const uint8_t* pt, size_t len, uint8_t* out, size_t cap) {
    if (!len || cap < len + TUN_OVERHEAD) return -1;
    const uint64_t seq = s_seq_tx;
    put_u64(out, seq);
    esp_fill_random(out + TUN_SEQ_LEN, TUN_NONCE_LEN);   // sprzętowy RNG (WiFi włączone)
    uint8_t aad[TUN_AAD_LEN]; tun_aad(aad, TUN_DIR_TO_BE, seq);
    uint8_t* ct  = out + TUN_SEQ_LEN + TUN_NONCE_LEN;
    uint8_t* tag = ct + len;
    mbedtls_gcm_context g; mbedtls_gcm_init(&g);
    int r = mbedtls_gcm_setkey(&g, MBEDTLS_CIPHER_ID_AES, s_key, 256);
    if (r == 0) r = mbedtls_gcm_crypt_and_tag(&g, MBEDTLS_GCM_ENCRYPT, len,
                        out + TUN_SEQ_LEN, TUN_NONCE_LEN, aad, TUN_AAD_LEN, pt, ct, TUN_TAG_LEN, tag);
    mbedtls_gcm_free(&g);
    if (r) return -1;
    // Licznik rośnie DOPIERO po udanym zapieczętowaniu. Gdy wysyłka padnie i porcja wróci do
    // kolejki, następna próba dostanie kolejny seq i NOWY losowy nonce — nigdy nie szyfrujemy
    // dwa razy tą samą parą (klucz, nonce), a dziura w seq jest po drugiej stronie dozwolona.
    s_seq_tx++;
    return (int)(len + TUN_OVERHEAD);
}

// [seq][nonce][ct][tag] → pt. Zwraca długość plaintextu albo -1 (zły tag / powtórka).
static int tun_unseal(const uint8_t* fr, size_t len, uint8_t* out, size_t cap) {
    if (len <= TUN_OVERHEAD) return -1;
    const size_t ct_len = len - TUN_OVERHEAD;
    if (ct_len > cap) return -1;
    const uint64_t seq = get_u64(fr);
    if (s_rx_init && seq <= s_seq_rx) return -1;             // powtórka / przestawienie
    uint8_t aad[TUN_AAD_LEN]; tun_aad(aad, TUN_DIR_TO_LAN, seq);
    const uint8_t* ct  = fr + TUN_SEQ_LEN + TUN_NONCE_LEN;
    const uint8_t* tag = ct + ct_len;
    mbedtls_gcm_context g; mbedtls_gcm_init(&g);
    int r = mbedtls_gcm_setkey(&g, MBEDTLS_CIPHER_ID_AES, s_key, 256);
    if (r == 0) r = mbedtls_gcm_auth_decrypt(&g, ct_len, fr + TUN_SEQ_LEN, TUN_NONCE_LEN,
                        aad, TUN_AAD_LEN, tag, TUN_TAG_LEN, ct, out);
    mbedtls_gcm_free(&g);
    if (r) return -1;
    s_seq_rx = seq; s_rx_init = true;
    return (int)ct_len;
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
    if (!pairing_has_key())  { push_state(c.tid, ST_ERROR, "node not paired"); return; }
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
        // 0.94 — NAJPIERW miejsce w kolejce, POTEM odczyt. Stary porządek (czytaj → wkładaj →
        // break przy pełnej) GUBIŁ właśnie przeczytany chunk: przy 30 KB/s kolejka nigdy nie
        // była pełna i mina spała, przy 100 KB/s zryw (strona WWW) zapychał ją i środek
        // odpowiedzi HTTP znikał — proxy czekało na bajty, których nie było (czarny panel).
        // Nieczytane bajty zostają w buforze TCP → okno się przymyka → uczciwy backpressure.
        // Jedyny producent to ten task, więc spaces-check przed send jest bez wyścigu.
        if (uxQueueSpacesAvailable(s_toBe) == 0) break;
        uint32_t room = TUN_READ_PER_WIN - s_read;
        int n = s_cli.read(ch->d, room < TUN_CHUNK ? (int)room : TUN_CHUNK);
        if (n <= 0) break;
        ch->len = (uint16_t)n;
        xQueueSend(s_toBe, ch, 0);
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
    // Nic do zrobienia: uprawnieniem jest klucz parowania (pairing_init z setup()),
    // a RAM i tak wstaje dopiero przy tun_open. Zostaje dla symetrii cyklu życia modułów.
}

static void tun_free_all() {
    if (s_cmdQ)  { vQueueDelete(s_cmdQ);  s_cmdQ  = nullptr; }
    if (s_toLan) { vQueueDelete(s_toLan); s_toLan = nullptr; }
    if (s_toBe)  { vQueueDelete(s_toBe);  s_toBe  = nullptr; }
    if (s_stQ)   { vQueueDelete(s_stQ);   s_stQ   = nullptr; }
    free(s_chPump); free(s_chDrop); free(s_chData); free(s_chTick); free(s_crypt);
    s_chPump = s_chDrop = s_chData = s_chTick = nullptr; s_crypt = nullptr;
    s_up = false; s_shutdown_req = false; s_task_dead = false; s_idle_since = 0;
    memset(s_key, 0, sizeof(s_key)); s_key_tid = 0; s_ts = 0; s_seq_tx = s_seq_rx = 0; s_rx_init = false;
}

static bool tun_spin_up() {
    if (s_up) return true;
    s_cmdQ  = xQueueCreate(4, sizeof(TunCmd));
    s_toLan = xQueueCreate(TUN_LAN_QDEPTH, sizeof(TunChunk));
    s_toBe  = xQueueCreate(TUN_QDEPTH, sizeof(TunChunk));
    s_stQ   = xQueueCreate(8, sizeof(TunState));
    s_chPump = (TunChunk*)malloc(sizeof(TunChunk)); s_chDrop = (TunChunk*)malloc(sizeof(TunChunk));
    s_chData = (TunChunk*)malloc(sizeof(TunChunk)); s_chTick = (TunChunk*)malloc(sizeof(TunChunk));
    s_crypt  = (uint8_t*)malloc(2 + TUN_CHUNK + TUN_OVERHEAD);   // [tid][ramka]; było TUN_CHUNK*2 pod base64
    if (!s_cmdQ || !s_toLan || !s_toBe || !s_stQ ||
        !s_chPump || !s_chDrop || !s_chData || !s_chTick || !s_crypt) {
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

bool tunnel_active()  { return s_state == S_OPEN; }

// ── Dispatch z ws_client (kontekst loop) ───────────────────────
static void reply_state_direct(int tid, const char* st, const char* msg) {
    // gdy podsystem nie działa (remote off) — odpowiedz od razu w loopie (WS-safe)
    char buf[128];
    snprintf(buf, sizeof(buf), "{\"type\":\"tun_state\",\"tid\":%d,\"st\":\"%s\",\"msg\":\"%s\"}", tid, st, msg);
    ws_client_send_raw(buf);
}

void tunnel_on_open(int tid, const char* ip, int port, const uint8_t key[32], uint32_t ts) {
    if (!pairing_has_key()) { reply_state_direct(tid, "error", "node not paired"); return; }
    if (s_shutdown_req) { reply_state_direct(tid, "error", "restarting, retry"); return; }   // okno ms-sek., APP ponowi
    if (!s_up && !tun_spin_up()) { reply_state_direct(tid, "error", "low memory, retry"); return; }
    if (!s_cmdQ) { reply_state_direct(tid, "error", "subsystem not ready"); return; }
    // Sekrety sesji ustawiamy w kontekście loop, PRZED zleceniem otwarcia — task ich nie dotyka,
    // szyfrowanie i deszyfrowanie dzieje się wyłącznie tutaj (tick / tunnel_on_data).
    memcpy(s_key, key, 32);
    s_key_tid = tid;
    s_ts = ts; s_seq_tx = 0; s_seq_rx = 0; s_rx_init = false;
    TunCmd c; c.op = CMD_OPEN; c.tid = tid; c.port = (uint16_t)port;
    strncpy(c.ip, ip ? ip : "", sizeof(c.ip) - 1); c.ip[sizeof(c.ip) - 1] = '\0';
    xQueueSend(s_cmdQ, &c, 0);
}

void tunnel_on_data(int tid, const uint8_t* frame, size_t len) {
    if (!s_up || !s_toLan || !frame) return;
    if (s_state != S_OPEN || tid != s_tid) return;   // brak aktywnego tunelu o tym id → drop
    TunChunk* ch = s_chData;                          // bufor na heapie (loop-ctx)
    if (!ch) return;
    int n = tun_unseal(frame, len, ch->d, TUN_CHUNK);
    if (n <= 0) {
        // Zły tag albo powtórzony seq. Do LAN-u nie idzie NIC — cichy drop byłby gorszy niż
        // zerwanie, bo SSH i tak padnie na MAC, a panel HTTP dostałby dziurę w odpowiedzi.
        LOGW("tun", "ramka odrzucona (tag/seq) — zamykam sesję");
        tunnel_on_close(tid);
        return;
    }
    ch->len = (uint16_t)n;
    xQueueSend(s_toLan, ch, pdMS_TO_TICKS(50));      // krótki backpressure zamiast gubienia bajtów
}

void tunnel_on_close(int tid) {
    if (!s_up || !s_cmdQ) return;
    TunCmd c; c.op = CMD_CLOSE; c.tid = tid; c.ip[0] = 0; c.port = 0;
    xQueueSend(s_cmdQ, &c, 0);
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
        LOGI("tun", "teardown — ~27KB returned to heap");
        return;
    }
    // stany → tun_state
    TunState st;
    while (xQueueReceive(s_stQ, &st, 0) == pdTRUE) {
        const char* s = st.st == ST_OPEN ? "open" : st.st == ST_CLOSED ? "closed" : "error";
        char buf[128];
        snprintf(buf, sizeof(buf), "{\"type\":\"tun_state\",\"tid\":%d,\"st\":\"%s\",\"msg\":\"%s\"}", st.tid, s, st.msg);
        ws_client_send_raw(buf);
        // Koniec sesji → wymaż klucz z RAM-u. Robimy to TUTAJ (loop), nie w do_close (task),
        // żeby nie kasować klucza pod ręką szyfrowania, które biegnie w tym samym momencie.
        // Warunek na tid jest KONIECZNY: zamknięcie i otwarcie mogą przyjść w jednej pętli
        // (dispatch WS biegnie przed tickiem), a wtedy bez niego wymazalibyśmy klucz świeżo
        // ustawionej sesji i wszystkie jej ramki poleciałyby z zerami.
        if (st.st != ST_OPEN && st.tid == s_key_tid) {
            memset(s_key, 0, sizeof(s_key)); s_key_tid = 0; s_ts = 0; s_rx_init = false;
        }
    }
    // bajty LAN→BE → ramka v2 w binarnej kopercie, max TUN_TICK_MAX porcji na tick.
    // Bufor ma z przodu 2 bajty na `tid`, więc pieczętujemy w miejscu i ws_client wysyła
    // gotowy plaintext — bez drugiego bufora i bez kopii.
    uint8_t*  buf = s_crypt;    // [tid u16][ramka]; heap, loop-ctx
    TunChunk* ch  = s_chTick;
    for (int i = 0; i < TUN_TICK_MAX && xQueueReceive(s_toBe, ch, 0) == pdTRUE; i++) {
        buf[0] = (uint8_t)((s_tid >> 8) & 0xFF); buf[1] = (uint8_t)(s_tid & 0xFF);
        int n = tun_seal(ch->d, ch->len, buf + 2, TUN_CHUNK + TUN_OVERHEAD);
        if (n <= 0) { xQueueSendToFront(s_toBe, ch, 0); break; }   // brak klucza/RNG — nie gub bajtu
        // C (backpressure): gdy WS nie wyśle (seal fail / TX full / niski heap) — NIE gub bajtu
        // SSH (drop = MAC fail = zerwana sesja). Wróć chunk na PRZÓD kolejki i przerwij tick;
        // s_toBe zostaje pełne → pump_io przestaje czytać socket LAN → TCP backpressure do hosta
        // (htop zwalnia zamiast nas zabić). Retry w następnym ticku, gdy heap/TX wróci —
        // porcja zostaje zaszyfrowana od nowa, z kolejnym seq i nowym nonce.
        if (!ws_client_send_tun(buf, (size_t)n + 2)) { xQueueSendToFront(s_toBe, ch, 0); break; }
    }
    // on-demand (0.72): sesja zamknięta → linger TUN_TEARDOWN_MS i oddaj RAM; disable → od razu
    if (s_state == S_IDLE) {
        if (!pairing_has_key())      s_shutdown_req = true;   // klucze skasowane = natychmiast oddaj RAM
        else if (!s_idle_since)      s_idle_since = millis();
        else if (millis() - s_idle_since > TUN_TEARDOWN_MS) s_shutdown_req = true;
    } else s_idle_since = 0;
}
