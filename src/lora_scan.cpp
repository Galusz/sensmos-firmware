#include "lora_scan.h"
#if LORA_ENABLED

#include <RadioLib.h>
#include <SPI.h>
#include "entity_store.h"
#include "log.h"
#include "ws_client.h"
#include "ws_enc.h"        // ws_enc_beacon_seed — seed kodu beaconu z ECDH (0.92)
#include "identity.h"
#include "smom.h"          // kodek SMOM — ramka CMD 0x03 (model v2)
#include "mqtt_pub.h"        // CMD → lokalny broker (most HA; no-op gdy MQTT off)
#include "http_client_util.h"// CMD → opcjonalny webhook z konfigu LoRa (np. UniFi)
#include <Preferences.h>   // plan LoRa w NVS (offline-ready beacon, decyzja 2026-08-23)
#include <mbedtls/md.h>
#include <mbedtls/aes.h>   // DATA 0x02: AES-CTR payloadu (klucz z frazy operatora)
#include <mbedtls/sha256.h>
#include <WiFi.h>          // detekcja padu uplinku dla trybu awaryjnego (0.91)
#include <ctype.h>         // isxdigit — parser hex ramek/seedów

static_assert(LORA_RX_HEX_MAX >= SMOM_FRAME_MAX,
              "LORA_RX_HEX_MAX musi zmiescic pelna ramke SMOM (przekaznik forwarduje ja do BE)");

static const LoraPinout PINOUTS[] = LORA_PINOUTS;
static const int        N_PINOUTS  = sizeof(PINOUTS) / sizeof(PINOUTS[0]);

// Radio wskazuje na pinout, ktory FAKTYCZNIE odpowiedzial przy starcie. Wskaznik nigdy nie
// jest null (startuje na pierwszym kandydacie), bo s_radio jest uzywane w 38 miejscach i nie
// chce, zeby jedno wywolanie przed inicjalizacja konczylo sie crashem zamiast "brak radia".
static Module           s_mod0(PINOUTS[0].nss, PINOUTS[0].dio1, PINOUTS[0].rst, PINOUTS[0].busy);
static SX1262           s_radio0(&s_mod0);
static SX1262*          g_radio = &s_radio0;
static const LoraPinout* g_pin  = &PINOUTS[0];
#define s_radio (*g_radio)
static bool         s_ok    = false;
static TaskHandle_t s_task  = nullptr;
static QueueHandle_t s_q    = nullptr;
static volatile bool s_busy = false;
static volatile bool s_bg   = LORA_BG_DEFAULT;

enum LJob : uint8_t { LJ_SWEEP, LJ_CAMP, LJ_LISTEN, LJ_HUNT, LJ_CAD };
struct LReq {
    LJob     job;
    float    f0, f1, step, bw;
    uint8_t  sf, cr, sync;
    uint16_t secs, dwell_ms;
};

static volatile bool s_irq = false;
ICACHE_RAM_ATTR static void on_dio1() { s_irq = true; }

// Ostatnie wyniki — do podejrzenia przez GET /lora/last. Zapisywane jednym ciągiem
// na końcu joba; czytelnik może trafić na wynik w trakcie zapisu, co przy diagnostyce
// jest akceptowalne (najwyżej jedna liczba ze starego przebiegu).
#define LORA_SWEEP_MAX 48
struct LoraLast {
    uint8_t  sweep_n;
    float    sweep_f[LORA_SWEEP_MAX], sweep_noise[LORA_SWEEP_MAX], sweep_peak[LORA_SWEEP_MAX];
    float    camp_freq, camp_noise, camp_peak;
    uint16_t camp_events, camp_short, camp_secs;
    uint32_t camp_air_ms;
    float    cad_freq, cad_bw;
    uint8_t  cad_sf;
    uint16_t cad_hits, cad_probes;
    float    bg_noise, bg_peak;
    int16_t  bg_busy, bg_cad, bg_cad_total, bg_frames;
};
static LoraLast s_last = {};

// ── Pomocnicze ────────────────────────────────────────────────

// Przestrojenie + rozgrzewka. Pierwsze odczyty RSSI po zmianie częstotliwości są śmieciowe
// (PLL i AGC się ustawiają) — bez tego pierwszy kanał przemiatania zawsze wychodził „aktywny".
// getRSSI(false) czyta CHWILOWY poziom, który istnieje wyłącznie gdy odbiornik pracuje —
// w standby zwraca podłogę skali (−128). Każdy pomiar szumu musi więc iść po startReceive()
// i po rozgrzewce AGC.
static void rx_warmup() {
    s_radio.startReceive();
    delay(8);
    // Po begin() układ dokańcza kalibrację. Odczyt RSSI trafia wtedy na zajęte SPI i wraca
    // 0xFF, które RadioLib przelicza na równe −128 dBm — stąd „martwe" pomiary przy każdej
    // rotacji kanału (sweep tego nie miał, bo tune() nie woła begin()). Czekamy na pierwszą
    // sensowną wartość, zamiast zgadywać stałym opóźnieniem.
    for (int i = 0; i < 40 && s_radio.getRSSI(false) <= -127.0f; i++) delay(5);
    for (int i = 0; i < 8; i++) { s_radio.getRSSI(false); delayMicroseconds(500); }
}

static bool tune(float freq) {
    if (s_radio.setFrequency(freq) != RADIOLIB_ERR_NONE) return false;
    rx_warmup();
    return true;
}

// begin() resetuje konfigurację modułu, więc przełącznik anteny i handler IRQ trzeba
// ustawiać PO każdym begin(), a nie raz w init.
static void after_begin() {
    if (g_pin->rxen >= 0) s_radio.setRfSwitchPins(g_pin->rxen, RADIOLIB_NC);
    s_radio.setDio1Action(on_dio1);
}

static bool cfg(float freq, float bw, uint8_t sf, uint8_t cr, uint8_t sync) {
    int st = s_radio.begin(freq, bw, sf, cr, sync, 10, 8, g_pin->tcxo, false);
    if (st != RADIOLIB_ERR_NONE) { LOGW("lora", "begin() = %d", st); return false; }
    after_begin();
    return true;
}

// Konfiguracja kanału wg jego trybu. FSK to osobne wejście w RadioLib (beginFSK) —
// inny modem, więc parametry LoRa (SF/CR) nie mają tam znaczenia i odwrotnie.
static bool cfg_ch(const LoraLinkCh& c) {
    if (c.mode != 1) return cfg(c.freq, c.bw, c.sf, c.cr, c.sync);

    int st = s_radio.beginFSK(c.freq, c.br, c.dev, c.bw, 10, 16, g_pin->tcxo, false);
    if (st != RADIOLIB_ERR_NONE) { LOGW("lora", "beginFSK() = %d", st); return false; }
    after_begin();
    // Sync word FSK to ciąg bajtów (nie jedna wartość jak w LoRa) — bez niego odbiornik
    // nie wie, gdzie zaczyna się ramka, więc dla podsłuchu konkretnego protokołu jest kluczowy.
    if (c.syncn) {
        uint8_t sw[8];
        memcpy(sw, c.syncb, c.syncn > 8 ? 8 : c.syncn);
        s_radio.setSyncWord(sw, c.syncn > 8 ? 8 : c.syncn);
    }
    // Obce protokoły liczą CRC i whitening po swojemu — domyślne ustawienia RadioLib
    // odrzuciłyby ich ramki jako uszkodzone, dlatego jedno i drugie jest wyłączalne.
    s_radio.setCRC((c.flags & 0x01) ? 2 : 0);
    s_radio.setWhitening((c.flags & 0x02) != 0);
    if ((c.flags & 0x04) && c.len) s_radio.fixedPacketLengthMode(c.len);
    else                           s_radio.variablePacketLengthMode(255);
    LOGI("lora", "FSK %.3f MHz br %.1fk dev %.1fk rxbw %.1fk sync %uB crc %d white %d",
         c.freq, c.br, c.dev, c.bw, c.syncn, (c.flags & 1) ? 2 : 0, (c.flags & 2) ? 1 : 0);
    return true;
}

// min = szum tła kanału, max = szczyt. Płaski RSSI to cisza; nadajnik w pobliżu daje skok.
static void channel_rssi(float* out_min, float* out_max) {
    float mn = 999, mx = -999;
    for (int i = 0; i < LORA_SWEEP_SAMPLES; i++) {
        float r = s_radio.getRSSI(false);
        if (r < mn) mn = r;
        if (r > mx) mx = r;
        delayMicroseconds(700);
    }
    *out_min = mn; *out_max = mx;
}

static void push_num(const char* eid, float v, const char* unit, int dec = 0) {
    char b[24];
    snprintf(b, sizeof(b), "%.*f", dec, v);
    entity_push(eid, b, unit);
}

// ── LoRa awaryjne (0.91) ─────────────────────────────────────────────────────
// Zestaw ≤4 encji właściciela. Zapis z HTTP (kontekst loop), odczyt z taska radiowego —
// bez locka: zmiana zestawu jest rzadka, a najgorszy skutek wyścigu to jedna przekłamana
// wartość w jednym beaconie (ta sama tolerancja co przy LoraLast).
static struct {
    uint8_t n;
    char    eids[LORA_EMERG_MAX][36];
} s_emerg = {};
static uint32_t      s_emerg_bad_since = 0;     // millis() początku ciągłej awarii uplinku
static volatile bool s_emerg_on        = false; // tryb E uzbrojony (czyta też loop dla statusu)
static volatile bool s_emerg_report    = false; // zestaw czeka na zgłoszenie do BE
static char          s_cmd_hook[120]   = "";    // webhook dla CMD (NVS "cmdhook"; pisze/czyta loop)
static bool          s_cmd_hook_get    = false; // true = GET ?cmd=... (UniFi itp.), false = POST JSON

// ── Skrzynka nadawcza ────────────────────────────────────────────────────────
// Task radiowy NIE MOZE wysylac po WS sam. ws_client trzyma JEDEN bufor `s_enc`
// wspoldzielony przez TX i RX oraz licznik sekwencji `s_seq_tx`, a jego wlasny komentarz
// mowi wprost: "loop-only ... bezpieczne bo half-duplex w loop". Ten task chodzi na rdzeniu 0,
// petla Arduino na rdzeniu 1 — czyli naprawde rownolegle. Skutki wyscigu, ktore realnie
// widzielismy w analizie:
//   · seal ramki radiowej w trakcie parsowania komendy z BE tnie JSON w polowie — przepada
//     lora_cfg razem z seedem, a node dalej nadaje beacon bez kodu, nieodroznialnie od
//     starego firmware'u;
//   · dwie sciezki czytaja ten sam s_seq_tx i buduja z niego IV — powtorzone IV pod tym
//     samym kluczem AES-GCM to zlamanie uwierzytelnienia szyfru, a BE i tak zrywa polaczenie
//     po duplikacie numeru sekwencji.
// Rozwiazanie jest tym samym wzorcem, ktory repo juz stosuje: net_worker oddaje wyniki
// kolejka do loop(), tunnel wysyla wylacznie z tunnel_tick ("kontekst loop, bez wyscigu").
// LoRa byla jedynym wyjatkiem.
//
// Sloty statyczne (.bss), nie sterta: przy 2,6 kB na wiadomosc alokacja z taska fragmentowalaby
// heap, ktory ten projekt swiadomie trzyma ciagly dla TLS i monitorow. Dwa sloty wystarcza,
// bo ruch jest rzadki (lora_ch przy rotacji kanalu, lora_rx najwyzej raz na minute).
#define LORA_OUT_MAX   2600
#define LORA_OUT_SLOTS 2
static char          s_out[LORA_OUT_SLOTS][LORA_OUT_MAX];
static QueueHandle_t s_outQ  = nullptr;    // sloty czekajace na wyslanie
static QueueHandle_t s_freeQ = nullptr;    // sloty wolne
static uint32_t      s_out_drop = 0;       // ile wiadomosci przepadlo (loop nie nadazyl)

// Z TASKA: zajmij wolny slot. nullptr = brak — wtedy wiadomosc przepada, i tak ma byc.
// Telemetria jest odtwarzalna, a czekanie w tasku radiowym gubiloby ramki z eteru.
static char* out_claim() {
    char* slot = nullptr;
    if (!s_freeQ || xQueueReceive(s_freeQ, &slot, 0) != pdTRUE) { s_out_drop++; return nullptr; }
    return slot;
}
static void out_post(char* slot) {
    if (!slot) return;
    if (!s_outQ || xQueueSend(s_outQ, &slot, 0) != pdTRUE) {   // nie powinno sie zdarzyc
        s_out_drop++;
        if (s_freeQ) xQueueSend(s_freeQ, &slot, 0);
    }
}

// ══ Radio na zlecenie BE (model v2 — baza pod ramkę CMD 0x03, Krok 3) ═════════
// Zostały tylko klocki wspólne: owner-seed (klucz kodeka SMOM z BE, cache NVS) i kolejka
// surowych ramek do nadania (loop -> task radiowy; transmit respektuje budżet DC).
// Ciężka warstwa wiadomości 0.95 (outbox/dispatch/ACK/dedupe) wycięta — model v2.
static uint8_t       s_self_id3[SMOM_ID_LEN]  = {0};    // pierwsze 3 B własnego device_id (CMD: „czy do mnie")
static uint8_t       s_owner_seed[SMOM_KEY_LEN] = {0};  // klucz SMOM (per-owner, z BE po szyfr. WS)
static volatile bool s_owner_seed_ok = false;

// Ramki gotowe do NADANIA (loop -> task). Task tylko wysyła (respektuje budżet DC).
struct SmomTx { uint8_t frame[SMOM_FRAME_MAX]; uint8_t len; };
static QueueHandle_t s_txQ = nullptr;

// Diagnostyka drenażu TX (lora7; test DATA 2026-09-01: ramki nie wychodziły w eter,
// serial niedostępny — USB=JTAG). Widoczna w GET /lora/last pole "link".
static uint32_t s_dr_seen = 0, s_dr_nobud = 0, s_dr_cad = 0, s_dr_ok = 0, s_dr_fail = 0;
static int      s_tx_last_st = 999;    // ostatni status s_radio.transmit (999 = nigdy)

// Komenda emergency (CMD 0x03) odebrana-dla-mnie: task radiowy (core 0) -> loop (core 1).
// Dispatch (inbox/MQTT/akcje) MUSI iść z loop — router czyta NVS i robi HTTP/skrypty.
struct CmdRx { char cmd[SMOM_CMD_MAX + 1]; };
static QueueHandle_t s_cmdQ = nullptr;

// ── DATA 0x02 — stan (Faza 2, zero-knowledge; decyzje 2026-09-01). Kryptografia i we/wy
// niżej (za hex_to_bytes); tu tylko to, czego potrzebuje inbox.
#define LORA_DATA_HDR          8
#define LORA_DATA_NONCE_LEN    4
#define LORA_DATA_PAYLOAD_MAX  128
#define LORA_DATA_FLAG_AES     0x01
#define LORA_DATA_INBOX_SIZE   6

static uint8_t s_self_id4[4] = {0};       // pierwsze 4 B własnego device_id (dst „czy do mnie")
static uint8_t s_rx_key[32];              // SHA256(fraza operatora) — wspólny z czujnikami
static bool    s_rx_key_ok = false;

struct DataRx { uint32_t ts; uint8_t sub; uint8_t enc; uint8_t via_ws; uint8_t len;
                uint8_t payload[LORA_DATA_PAYLOAD_MAX]; };
static QueueHandle_t s_dataQ = nullptr;   // task radiowy / loop(WS) -> loop (inbox+MQTT)
static DataRx  s_data_inbox[LORA_DATA_INBOX_SIZE];
static uint8_t s_data_inbox_n = 0;
static uint32_t s_data_last_crc = 0;      // dedupe: radio i zwrotka WS niosą tę samą ramkę
static uint32_t s_data_last_ts  = 0;

// CRC32 zlib (poly odbite) bit po bicie — ramki ≤144 B, tablica byłaby zbędnym 1 KB;
// zgodność ze standardem, żeby BE/ESPHome liczyły bibliotecznym crc32.
static uint32_t crc32_calc(const uint8_t* d, size_t n) {
    uint32_t c = 0xFFFFFFFFu;
    for (size_t i = 0; i < n; i++) {
        c ^= d[i];
        for (int b = 0; b < 8; b++) c = (c >> 1) ^ (0xEDB88320u & (0u - (c & 1)));
    }
    return c ^ 0xFFFFFFFFu;
}

static bool data_is_text(const DataRx& r) {
    for (uint8_t i = 0; i < r.len; i++) {
        const uint8_t c = r.payload[i];
        if (c < 0x20 || c > 0x7e || c == '"' || c == '\\') return false;
    }
    return true;
}

static void data_inbox_push(const DataRx& rx) {
    if (s_data_inbox_n >= LORA_DATA_INBOX_SIZE) {
        for (int i = 0; i < LORA_DATA_INBOX_SIZE - 1; i++) s_data_inbox[i] = s_data_inbox[i + 1];
        s_data_inbox_n = LORA_DATA_INBOX_SIZE - 1;
    }
    s_data_inbox[s_data_inbox_n++] = rx;
}

// Inbox LoRa — OSOBNY od inboxu wiadomości WS (wspólny ring wypychałby komendy ruchem WS)
// i z ROZDZIELONYMI kubełkami: komendy ≠ ramki (decyzja 2026-08-31). GET /lora/inbox (PIN).
struct CmdInboxItem { uint32_t ts; char payload[SMOM_CMD_MAX + 1]; };
#define LORA_CMD_INBOX_SIZE 8
static CmdInboxItem s_cmd_inbox[LORA_CMD_INBOX_SIZE];
static uint8_t      s_cmd_inbox_n = 0;

static void cmd_inbox_push(const char* payload) {
    if (s_cmd_inbox_n >= LORA_CMD_INBOX_SIZE) {
        for (int i = 0; i < LORA_CMD_INBOX_SIZE - 1; i++) s_cmd_inbox[i] = s_cmd_inbox[i + 1];
        s_cmd_inbox_n = LORA_CMD_INBOX_SIZE - 1;
    }
    CmdInboxItem& it = s_cmd_inbox[s_cmd_inbox_n++];
    it.ts = ws_epoch_now();
    strlcpy(it.payload, payload, sizeof(it.payload));
}

void lora_inbox_json(String& out) {
    out = "{\"cmds\":{\"count\":";
    out += s_cmd_inbox_n;
    out += ",\"items\":[";
    for (int i = 0; i < s_cmd_inbox_n; i++) {
        if (i) out += ',';
        out += "{\"ts\":";  out += s_cmd_inbox[i].ts;
        out += ",\"payload\":\""; out += s_cmd_inbox[i].payload;   // ASCII bez " i \ (walidacja RX)
        out += "\"}";
    }
    out += "]},\"frames\":{\"count\":";
    out += s_data_inbox_n;
    out += ",\"items\":[";
    for (int i = 0; i < s_data_inbox_n; i++) {
        const DataRx& r = s_data_inbox[i];
        if (i) out += ',';
        out += "{\"ts\":";   out += r.ts;
        out += ",\"sub\":";  out += r.sub;
        out += ",\"enc\":";  out += r.enc ? "true" : "false";
        out += ",\"via\":\""; out += r.via_ws ? "ws" : "rf"; out += "\",";
        if (data_is_text(r)) {                    // ASCII bez " i \ — bezpieczne 1:1 w JSON
            out += "\"text\":\"";
            for (uint8_t b = 0; b < r.len; b++) out += (char)r.payload[b];
        } else {
            out += "\"hex\":\"";
            char h[3];
            for (uint8_t b = 0; b < r.len; b++) { snprintf(h, sizeof(h), "%02x", r.payload[b]); out += h; }
        }
        out += "\"}";
    }
    out += "]}}";
}

// cmd-ack do ogona najbliższego beaconu (" C <s1>,<s2>,...", advisory — poza HMAC jak
// dawny ACK). DO 4 SLOTÓW: salwa komend rozlicza się jednym beaconem, nie po jednej na
// cykl (test 2026-08-31: 3 komendy = ~15 min zbierania acków przy 1 slocie).
// RX i TX beaconu żyją w tym samym tasku radiowym — sekwencyjnie, bez wyścigu.
#define LORA_CMDACK_SLOTS 4
static uint8_t s_cmdacks[LORA_CMDACK_SLOTS];
static uint8_t s_cmdack_n = 0;

static void cmdack_arm(uint8_t seq) {
    for (uint8_t i = 0; i < s_cmdack_n; i++)
        if (s_cmdacks[i] == seq) return;                     // już czeka
    if (s_cmdack_n >= LORA_CMDACK_SLOTS) {                   // pełne → wypchnij najstarszy
        for (uint8_t i = 0; i < LORA_CMDACK_SLOTS - 1; i++) s_cmdacks[i] = s_cmdacks[i + 1];
        s_cmdack_n = LORA_CMDACK_SLOTS - 1;
    }
    s_cmdacks[s_cmdack_n++] = seq;
}

// Dedupe wykonania: BE retryuje tę samą komendę przez kolejne przekaźniki, a echo z eteru
// wraca wielokrotnie — ta sama (seq, okno minut) wykonuje się RAZ, ale ack re-armujemy
// (pierwszy beacon z ackiem mógł nie zostać usłyszany).
static uint8_t  s_cmd_last_seq = 0;
static uint32_t s_cmd_last_min = 0;
static bool     s_cmd_seen     = false;

// hex(nhex znaków) -> nhex/2 bajtów. false = nieparzyste / nie-hex.
static bool hex_to_bytes(const char* hex, size_t nhex, uint8_t* out) {
    if (nhex & 1) return false;
    for (size_t i = 0; i < nhex; i += 2) {
        if (!isxdigit((int)(unsigned char)hex[i]) || !isxdigit((int)(unsigned char)hex[i + 1])) return false;
        char b[3] = { hex[i], hex[i + 1], 0 };
        out[i / 2] = (uint8_t)strtoul(b, nullptr, 16);
    }
    return true;
}

static void smom_state_load() {
    Preferences pr; pr.begin("sensmos_lora", true);
    size_t got = pr.getBytes("oseed", s_owner_seed, sizeof(s_owner_seed));
    bool   okf = pr.getBool("oseed_ok", false);
    pr.end();
    s_owner_seed_ok = (got == sizeof(s_owner_seed)) && okf;
    if (s_owner_seed_ok) LOGI("lora", "owner-seed odtworzony z NVS");
}

// ══ DATA 0x02 — ramki publiczne LoRa (Faza 2, zero-knowledge; decyzje 2026-09-01) ══
// Format: [0xE0][0x02][flags][dst 4B][sub 1B][payload][CRC32 LE]           (jawna)
//         [0xE0][0x02][flags][dst 4B][sub 1B][nonce 4B][AES-CTR(payload+CRC32)]  (flags bit0)
// dst = pierwsze 4 B device_id noda-bazy (id8 z apki), sub = pod-adres czujnika za bazą
// (0 = baza; plugin ESPHome filtruje po własnym sub). Klucz = SHA256(frazy operatora),
// żyje WYŁĄCZNIE w NVS nodów/czujników — BE routuje hex po dst NA ŚLEPO (WS lora_frame),
// dekoduje dopiero odbiorca (FW publiczne: każdy zweryfikuje, że nie podsłuchujemy).
// Stan/struktury wyżej (przy inboxie); tu kryptografia i we/wy.

// AES-256-CTR in-place nad payload+CRC. Blok licznika: [nonce4][dst4][sub][zera] — losowy
// nonce daje unikalność, dst/sub wiążą szyfr z adresem (ta sama treść do dwóch odbiorców
// = różne szyfrogramy). CTR: szyfrowanie == deszyfrowanie.
static void data_crypt(const uint8_t key[32], const uint8_t nonce[LORA_DATA_NONCE_LEN],
                       const uint8_t dst[4], uint8_t sub, uint8_t* buf, size_t n) {
    uint8_t ctr[16] = {0}, sb[16];
    size_t off = 0;
    memcpy(ctr, nonce, LORA_DATA_NONCE_LEN);
    memcpy(ctr + 4, dst, 4);
    ctr[8] = sub;
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_enc(&aes, key, 256);
    mbedtls_aes_crypt_ctr(&aes, n, &off, ctr, sb, buf, buf);
    mbedtls_aes_free(&aes);
}

void lora_rx_key_set(const char* phrase) {
    Preferences pr; pr.begin("sensmos_lora", false);
    if (!phrase || !phrase[0]) {
        s_rx_key_ok = false;
        memset(s_rx_key, 0, sizeof(s_rx_key));
        pr.remove("rxkey");
    } else {
        mbedtls_sha256((const unsigned char*)phrase, strlen(phrase), s_rx_key, 0);
        pr.putBytes("rxkey", s_rx_key, sizeof(s_rx_key));
        s_rx_key_ok = true;
    }
    pr.end();
    LOGI("lora", "klucz RX ramek DATA %s", s_rx_key_ok ? "ustawiony" : "skasowany");
}
bool lora_rx_key_present() { return s_rx_key_ok; }

// Wspólny dekod (radio: task core 0; zwrotka WS: loop). true = DATA zaadresowana do mnie,
// SKONSUMOWANA (także przy złym CRC/braku klucza — nie forwardować dalej do BE).
static bool data_rx_process(const uint8_t* d, int len, bool via_ws, uint32_t now) {
    if (len < LORA_DATA_HDR + 1 + 4 || d[0] != SMOM_MAGIC0 || d[1] != SMOM_TYPE_DATA) return false;
    if (memcmp(d + 3, s_self_id4, 4) != 0) return false;     // dst != ja → do batcha uplinku
    const uint8_t sub = d[7];
    const bool    aes = d[2] & LORA_DATA_FLAG_AES;
    uint8_t buf[LORA_DATA_PAYLOAD_MAX + 4];
    int n;                                                    // payload+CRC w buf
    if (aes) {
        if (!s_rx_key_ok) { LOGW("lora", "DATA szyfrowana, brak klucza RX — drop"); return true; }
        n = len - LORA_DATA_HDR - LORA_DATA_NONCE_LEN;
        if (n < 1 + 4 || n > (int)sizeof(buf)) return true;
        memcpy(buf, d + LORA_DATA_HDR + LORA_DATA_NONCE_LEN, n);
        data_crypt(s_rx_key, d + LORA_DATA_HDR, d + 3, sub, buf, n);
    } else {
        n = len - LORA_DATA_HDR;
        if (n < 1 + 4 || n > (int)sizeof(buf)) return true;
        memcpy(buf, d + LORA_DATA_HDR, n);
    }
    const int plen = n - 4;
    const uint32_t crc = (uint32_t)buf[plen] | ((uint32_t)buf[plen + 1] << 8) |
                         ((uint32_t)buf[plen + 2] << 16) | ((uint32_t)buf[plen + 3] << 24);
    if (crc32_calc(buf, plen) != crc) {
        LOGW("lora", "DATA dla mnie: CRC nie pasuje (%s)", aes ? "zly klucz?" : "eter");
        return true;
    }
    if (crc == s_data_last_crc && now - s_data_last_ts < 120) return true;   // duplikat
    s_data_last_crc = crc; s_data_last_ts = now;
    if (s_dataQ) {
        DataRx rx; memset(&rx, 0, sizeof(rx));
        rx.ts = now; rx.sub = sub; rx.enc = aes; rx.via_ws = via_ws;
        rx.len = (uint8_t)plen;
        memcpy(rx.payload, buf, plen);
        xQueueSend(s_dataQ, &rx, 0);
    }
    LOGI("lora", "DATA sub %u, %d B (%s%s) — przyjeta", sub, plen,
         aes ? "AES" : "plain", via_ws ? ", via WS" : "");
    return true;
}

// Zwrotka z BE (WS lora_frame): ramka DATA usłyszana przez INNY node/bramę — dekod jak
// z radia. Dzięki temu odbiorca nie musi sam słyszeć nadawcy (wystarczy ktokolwiek).
void lora_data_rx_ws(const char* hex) {
    if (!hex) return;
    const size_t nh = strlen(hex);
    if ((nh & 1) || nh < 2 * (LORA_DATA_HDR + 5) || nh / 2 > SMOM_FRAME_MAX) return;
    uint8_t d[SMOM_FRAME_MAX];
    if (!hex_to_bytes(hex, nh, d)) return;
    data_rx_process(d, (int)(nh / 2), true, ws_epoch_now());
}

// Nadanie ramki DATA (POST /node/lorasend — stała funkcja, nie tylko test). Kolejka s_txQ:
// nadanie na kanale domowym z CAD i budżetem DC jak każdy TX. 0=OK (zakolejkowane),
// -1 brak radia, -2 zły payload, -3 zły dst, -4 AES bez klucza, -5 kolejka pełna.
int lora_data_send(const char* dst8, uint8_t sub, const uint8_t* payload, size_t plen, bool aes) {
    if (!s_ok || !s_txQ) return -1;
    if (!payload || !plen || plen > LORA_DATA_PAYLOAD_MAX) return -2;
    uint8_t dst[4];
    if (!dst8 || strlen(dst8) < 8 || !hex_to_bytes(dst8, 8, dst)) return -3;
    if (aes && !s_rx_key_ok) return -4;
    SmomTx tx;
    uint8_t* f = tx.frame;
    f[0] = SMOM_MAGIC0; f[1] = SMOM_TYPE_DATA; f[2] = aes ? LORA_DATA_FLAG_AES : 0;
    memcpy(f + 3, dst, 4); f[7] = sub;
    int p = LORA_DATA_HDR;
    uint8_t body[LORA_DATA_PAYLOAD_MAX + 4];
    memcpy(body, payload, plen);
    const uint32_t crc = crc32_calc(body, plen);
    body[plen]     = crc & 0xff;          body[plen + 1] = (crc >> 8) & 0xff;
    body[plen + 2] = (crc >> 16) & 0xff;  body[plen + 3] = (crc >> 24) & 0xff;
    if (aes) {
        const uint32_t r = esp_random();
        memcpy(f + p, &r, LORA_DATA_NONCE_LEN);
        data_crypt(s_rx_key, f + p, dst, sub, body, plen + 4);
        p += LORA_DATA_NONCE_LEN;
    }
    memcpy(f + p, body, plen + 4);
    tx.len = (uint8_t)(p + plen + 4);
    return xQueueSend(s_txQ, &tx, 0) == pdTRUE ? 0 : -5;
}

// Z LOOP(): wyslij wszystko, co czeka. Kolejki FreeRTOS daja bariery pamieci, wiec slot
// zapisany w tasku jest tu widoczny w calosci — bez wlasnych volatile i barier.
void lora_pump() {
    if (!s_outQ) return;
    char* slot;
    while (xQueueReceive(s_outQ, &slot, 0) == pdTRUE) {
        if (ws_client_connected()) ws_client_send_raw(slot);
        xQueueSend(s_freeQ, &slot, 0);
    }
    // Zgloszenie zestawu awaryjnego do BE — po kazdym (re)connect i po zmianie zestawu.
    // BE mapuje pozycyjne wartosci z ramki E1 na eidy, wiec musi znac aktualny wybor
    // (takze pusty — kasuje poprzedni). Kontekst loop, wiec wolno slac wprost.
    static bool was_conn = false;
    const bool conn = ws_client_connected();
    if (conn && (!was_conn || s_emerg_report)) {
        char b[224];
        int p = snprintf(b, sizeof(b), "{\"type\":\"lora_emerg_cfg\",\"eids\":[");
        for (uint8_t i = 0; i < s_emerg.n; i++)
            p += snprintf(b + p, sizeof(b) - p, "%s\"%s\"", i ? "," : "", s_emerg.eids[i]);
        snprintf(b + p, sizeof(b) - p, "]}");
        if (ws_client_send_raw(b)) s_emerg_report = false;
    }
    was_conn = conn;

    // ── Komendy emergency (CMD 0x03): dispatch z loop — CELOWO POZA akcjami wiadomości ──
    // (decyzja 2026-08-31: sloty akcji = ukryta wiedza, nikt by nie odkrył konwencji).
    // Wszystko w module LoRa: OSOBNY inbox LoRa (GET /lora/inbox — nie miesza się z ringiem
    // wiadomości WS), most MQTT→HA (topic message/lora_cmd; działa, gdy padł tylko WAN
    // a LAN żyje) i OPCJONALNY webhook z konfigu LoRa (NVS, razem z zestawem emergency
    // w /node/lora_emerg) — np. UniFi Protect bez HA.
    if (s_cmdQ) {
        CmdRx rx;
        while (xQueueReceive(s_cmdQ, &rx, 0) == pdTRUE) {
            cmd_inbox_push(rx.cmd);
            mqtt_pub_message("owner", "lora_cmd", rx.cmd);
            if (s_cmd_hook[0]) {
                int code;
                if (s_cmd_hook_get) {
                    // GET ?cmd=<url-encoded> — proste webhooki (UniFi Protect itp.) nie mają POST.
                    char enc[3 * SMOM_CMD_MAX + 1]; size_t p = 0;
                    for (const char* c = rx.cmd; *c && p + 4 < sizeof(enc); c++) {
                        if (isalnum((int)(unsigned char)*c) || *c=='-' || *c=='_' || *c=='.' || *c=='~')
                            enc[p++] = *c;
                        else p += snprintf(enc + p, 4, "%%%02X", (unsigned char)*c);
                    }
                    enc[p] = 0;
                    char url[168];
                    snprintf(url, sizeof(url), "%s%scmd=%s",
                             s_cmd_hook, strchr(s_cmd_hook, '?') ? "&" : "?", enc);
                    code = http_get_simple(url, HTTP_TIMEOUT_WEBHOOK);
                } else {
                    char body[80];
                    snprintf(body, sizeof(body), "{\"source\":\"lora_cmd\",\"cmd\":\"%s\"}", rx.cmd);
                    code = http_post_json(s_cmd_hook, body, HTTP_TIMEOUT_WEBHOOK);
                }
                LOGI("lora", "CMD webhook (%s) HTTP %d", s_cmd_hook_get ? "GET" : "POST", code);
            }
        }
    }

    // ── Ramki DATA (0x02) przyjęte dla mnie: inbox LoRa (kubełek frames) + MQTT ──
    // eid "lora_frame" (sub 0) albo "lora_frame.N" — HA rozróżnia czujniki za bazą.
    if (s_dataQ) {
        DataRx drx;
        while (xQueueReceive(s_dataQ, &drx, 0) == pdTRUE) {
            data_inbox_push(drx);
            char eid[16];
            if (drx.sub) snprintf(eid, sizeof(eid), "lora_frame.%u", drx.sub);
            else         strlcpy(eid, "lora_frame", sizeof(eid));
            char txt[2 * LORA_DATA_PAYLOAD_MAX + 1];
            if (data_is_text(drx)) {
                memcpy(txt, drx.payload, drx.len); txt[drx.len] = 0;
            } else {
                size_t o = 0;
                for (uint8_t b = 0; b < drx.len; b++)
                    o += snprintf(txt + o, sizeof(txt) - o, "%02x", drx.payload[b]);
            }
            mqtt_pub_message("lora", eid, txt);
            // Kwit dostarczenia do BE (lora8): SAME metadane, ZERO treści — zero-knowledge
            // zostaje, a właściciel/staty widzą „doszło". Best-effort (offline = trudno,
            // dane i tak są lokalnie w inboxie/MQTT).
            if (ws_client_connected()) {
                char rcpt[96];
                snprintf(rcpt, sizeof(rcpt),
                         "{\"type\":\"lora_data_rcpt\",\"sub\":%u,\"via\":\"%s\",\"len\":%u,\"enc\":%s}",
                         drx.sub, drx.via_ws ? "ws" : "rf", drx.len, drx.enc ? "true" : "false");
                ws_client_send_raw(rcpt);
            }
        }
    }

    static uint32_t last_warn = 0;
    if (s_out_drop && millis() - last_warn > 60000) {
        last_warn = millis();
        LOGW("lora", "skrzynka pelna — przepadlo %lu wiadomosci", (unsigned long)s_out_drop);
        s_out_drop = 0;
    }
}

// ── Zlecenia ──────────────────────────────────────────────────

static void do_sweep(const LReq& r) {
    LOGI("lora", "sweep %.3f-%.3f MHz step %.3f", r.f0, r.f1, r.step);
    // Konfiguracja ODNIESIENIA. Bez tego skan mierzył tym modemem, który zostawił tryb
    // link: w LoRa/125 kHz rozrzut RSSI to 1-2 dB, a w FSK/100 kHz naturalnie 15-30 dB,
    // przez co próg „6 dB ponad szum" zapalał WSZYSTKIE punkty. Wynik musi być
    // porównywalny między skanami, więc zawsze mierzymy tak samo.
    if (!cfg(r.f0, 125.0f, 9, 5, 0x34)) { LOGW("lora", "sweep: cfg odniesienia nieudana"); return; }
    float worst = 999, peak = -999, peak_f = 0;
    int busy = 0, total = 0;
    s_last.sweep_n = 0;
    for (float f = r.f0; f <= r.f1 + 0.001f; f += r.step) {
        if (!tune(f)) continue;
        float mn, mx; channel_rssi(&mn, &mx);
        total++;
        if (mx - mn >= LORA_BUSY_MARGIN_DB) busy++;
        if (mn < worst) worst = mn;
        if (mx > peak) { peak = mx; peak_f = f; }
        if (s_last.sweep_n < LORA_SWEEP_MAX) {
            int i = s_last.sweep_n++;
            s_last.sweep_f[i] = f; s_last.sweep_noise[i] = mn; s_last.sweep_peak[i] = mx;
        }
        LOGI("lora", "  %7.3f  noise %4.0f  peak %4.0f %s", f, mn, mx,
             (mx - mn >= LORA_BUSY_MARGIN_DB) ? "<-- ACTIVE" : "");
    }
    LOGI("lora", "sweep done: noise %.0f dBm | peak %.0f dBm @ %.3f | active %d/%d",
         worst, peak, peak_f, busy, total);

    // Wynik → BE. Bez tego skan całego pasma był widoczny wyłącznie na serialu, więc
    // dla nodów w terenie (bez kabla) nie istniał.
    if (ws_client_connected()) {
        char* b = out_claim();                      // wlasny static b[1800] zastapiony slotem
        if (b) {
            int p = snprintf(b, LORA_OUT_MAX,
                "{\"type\":\"lora_sweep\",\"ts\":%lu,\"busy\":%d,\"total\":%d,\"points\":[",
                (unsigned long)ws_epoch_now(), busy, total);
            for (int i = 0; i < s_last.sweep_n && p < LORA_OUT_MAX - 48; i++)
                p += snprintf(b + p, LORA_OUT_MAX - p, "%s{\"f\":%.3f,\"n\":%.0f,\"p\":%.0f}",
                              i ? "," : "", s_last.sweep_f[i], s_last.sweep_noise[i], s_last.sweep_peak[i]);
            snprintf(b + p, LORA_OUT_MAX - p, "]}");
            out_post(b);
        }
    }
}

// Detektor energii — nie obchodzi go BW, SF, CR ani sync word. Mierzy samą moc w kanale,
// więc łapie cokolwiek: LoRa, FSK, zakłócenie. Jeśli TO nic nie widzi przy nadajniku obok,
// problem jest w sprzęcie/antenie/paśmie płytki, a nie w parametrach demodulatora.
static void do_camp(const LReq& r) {
    LOGI("lora", "energy detector %.3f MHz for %us", r.f0, r.secs);
    if (!tune(r.f0)) { LOGW("lora", "setFrequency failed"); return; }

    float noise = 0; int n = 0;
    uint32_t t0 = millis();
    while (millis() - t0 < 1000) { noise += s_radio.getRSSI(false); n++; delay(2); }
    noise /= (n ? n : 1);
    LOGI("lora", "  noise floor %.0f dBm - reporting above %.0f", noise, noise + LORA_BUSY_MARGIN_DB);

    // Histereza + minimalny czas trwania. Bez tego sygnał wiszący na progu przełącza się
    // w kółko i produkuje setki „zdarzeń" po 1-2 ms — czego nie da się odróżnić od ruchu.
    // Najkrótsza realna ramka LoRa to i tak dziesiątki ms (przy SF8/BW62.5 było 314 ms),
    // więc wszystko poniżej progu czasu to przejście przez szum, nie transmisja.
    const float TH_ON  = noise + LORA_BUSY_MARGIN_DB;
    const float TH_OFF = noise + LORA_BUSY_MARGIN_DB - 3.0f;
    const uint32_t MIN_EV_MS = 10;

    int events = 0, shorts = 0, logged = 0;
    float pk = -999, best = -999;
    uint32_t air = 0, ev0 = 0;
    bool in_ev = false;
    t0 = millis();
    while (millis() - t0 < (uint32_t)r.secs * 1000UL) {
        float v = s_radio.getRSSI(false);
        if (!in_ev && v > TH_ON) { in_ev = true; ev0 = millis(); pk = v; }
        else if (in_ev) {
            if (v > pk) pk = v;
            if (v < TH_OFF) {
                in_ev = false;
                uint32_t dur = millis() - ev0;
                if (dur < MIN_EV_MS) { shorts++; }
                else {
                    events++; air += dur;
                    if (pk > best) best = pk;
                    if (logged < 20) {
                        logged++;
                        LOGI("lora", "  [%2d] t=%4lus peak %.0f dBm (+%.0f) for %lums",
                             events, (millis() - t0) / 1000, pk, pk - noise, dur);
                    }
                }
                pk = -999;
            }
        }
        delay(1);
    }
    if (logged >= 20) LOGI("lora", "  ...(dalsze zdarzenia pominiete w logu)");

    s_last.camp_freq = r.f0; s_last.camp_noise = noise; s_last.camp_peak = best;
    s_last.camp_events = events; s_last.camp_short = shorts;
    s_last.camp_secs = r.secs; s_last.camp_air_ms = air;

    LOGI("lora", "camp done: %d events, %lums airtime (%.1f%%), %d short rejected%s",
         events, (unsigned long)air, 100.0f * air / (r.secs * 1000.0f), shorts,
         events ? "  *** SOMETHING IS TRANSMITTING ***" : "  (silence)");

    if (ws_client_connected()) {
        char* b = out_claim();
        if (b) {
            snprintf(b, LORA_OUT_MAX,
                "{\"type\":\"lora_camp\",\"ts\":%lu,\"freq\":%.3f,\"secs\":%u,\"noise\":%.0f,"
                "\"peak\":%.0f,\"events\":%d,\"short\":%d,\"air_ms\":%lu}",
                (unsigned long)ws_epoch_now(), r.f0, r.secs, noise,
                events ? best : noise, events, shorts, (unsigned long)air);
            out_post(b);
        }
    }
}

// Zwraca liczbę ramek. CRC error też liczymy — to nadal dowód, że ktoś nadaje
// na tych parametrach; odrzucenie go zamieniłoby trafienie w fałszywą ciszę.
static int listen_window(float freq, float bw, uint8_t sf, uint8_t cr, uint8_t sync,
                         uint16_t secs, float* best_rssi, bool verbose) {
    if (!cfg(freq, bw, sf, cr, sync)) return -1;
    s_irq = false;
    s_radio.startReceive();

    int frames = 0; float best = -999;
    uint32_t t0 = millis();
    while (millis() - t0 < (uint32_t)secs * 1000UL) {
        if (s_irq) {
            s_irq = false;
            uint8_t buf[256];
            int len = s_radio.getPacketLength();
            int st  = s_radio.readData(buf, len > 255 ? 255 : len);
            if (st == RADIOLIB_ERR_NONE || st == RADIOLIB_ERR_CRC_MISMATCH) {
                frames++;
                float rssi = s_radio.getRSSI();
                if (rssi > best) best = rssi;
                if (verbose)
                    LOGI("lora", "  [%2d] len=%3d RSSI=%.0f SNR=%.1f%s", frames, len, rssi,
                         s_radio.getSNR(), st == RADIOLIB_ERR_CRC_MISMATCH ? "  (CRC err)" : "");
            }
            s_radio.startReceive();
        }
        delay(2);
    }
    if (best_rssi) *best_rssi = best;
    return frames;
}

// CAD nie dotyka sync worda — modem szuka samych symboli preambuły, więc odpowiada
// na pytanie „czy ktoś nadaje LoRa na tych parametrach" bez wiedzy, czyj to protokół.
// To czyni łowcę sync worda zbędnym do samego wykrycia ruchu.
static void do_cad(const LReq& r) {
    LOGI("lora", "CAD %.3f MHz BW%.1f SF%u for %us (sync word irrelevant)",
         r.f0, r.bw, r.sf, r.secs);
    if (!cfg(r.f0, r.bw, r.sf, r.cr, 0x12)) return;

    int hits = 0, probes = 0;
    uint32_t t0 = millis(), last = 0;
    while (millis() - t0 < (uint32_t)r.secs * 1000UL) {
        probes++;
        if (s_radio.scanChannel() == RADIOLIB_LORA_DETECTED) {
            hits++;
            uint32_t now = millis();
            // Jedna transmisja daje serię trafień — loguj tylko początek epizodu,
            // inaczej dłuższa ramka zalewa konsolę setką linii.
            if (now - last > 500) LOGI("lora", "  [%3d] preamble @ t=%lus", hits, (now - t0) / 1000);
            last = now;
        }
        delay(5);
    }
    s_last.cad_freq = r.f0; s_last.cad_bw = r.bw; s_last.cad_sf = r.sf;
    s_last.cad_hits = hits; s_last.cad_probes = probes;
    LOGI("lora", "CAD done: %d/%d probes detected (%.1f%%)%s", hits, probes,
         probes ? 100.0f * hits / probes : 0.0f,
         hits ? "  *** LORA TRAFFIC ON THESE PARAMS ***" : "  (nothing on these params)");
}

static void do_listen(const LReq& r) {
    LOGI("lora", "listen %.3f MHz BW%.1f SF%u CR4:%u sync 0x%02X for %us",
         r.f0, r.bw, r.sf, r.cr, r.sync, r.secs);
    float best = -999;
    int n = listen_window(r.f0, r.bw, r.sf, r.cr, r.sync, r.secs, &best, true);
    if (n < 0) return;
    LOGI("lora", "listen done: %d frames%s", n, n ? "  *** TRAFFIC HERE ***" : "  (silence)");
}

// MeshCore nie publikuje sync worda. Zamiast zgadywać — przemiatamy wszystkie 256 wartości
// na znanych freq/BW/SF/CR. Przy nadajniku pracującym bez przerwy któraś MUSI zadziałać,
// co zamienia zgadywanie w pomiar. Wymaga ciągłego nadawania po drugiej stronie.
static void do_hunt(const LReq& r) {
    LOGI("lora", "sync word hunt %.3f MHz BW%.1f SF%u CR4:%u - TRANSMIT CONTINUOUSLY NOW",
         r.f0, r.bw, r.sf, r.cr);
    LOGI("lora", "  %ums per value, 256 values = ~%lus total",
         r.dwell_ms, (unsigned long)r.dwell_ms * 256 / 1000);

    for (int sw = 0; sw <= 0xFF; sw++) {
        if (!cfg(r.f0, r.bw, r.sf, r.cr, (uint8_t)sw)) continue;
        s_irq = false;
        s_radio.startReceive();
        uint32_t t0 = millis();
        while (millis() - t0 < r.dwell_ms) {
            if (s_irq) {
                s_irq = false;
                uint8_t buf[256];
                int len = s_radio.getPacketLength();
                int st  = s_radio.readData(buf, len > 255 ? 255 : len);
                if (st == RADIOLIB_ERR_NONE || st == RADIOLIB_ERR_CRC_MISMATCH) {
                    LOGI("lora", "*** HIT: sync=0x%02X len=%d RSSI=%.0f SNR=%.1f%s",
                         sw, len, s_radio.getRSSI(), s_radio.getSNR(),
                         st == RADIOLIB_ERR_CRC_MISMATCH ? "  (CRC err - still the right sync)" : "");
                    return;
                }
                s_radio.startReceive();
            }
            delay(1);
        }
        if ((sw & 0x1F) == 0x1F) LOGI("lora", "  ...checked up to 0x%02X", sw);
    }
    LOGI("lora", "hunt done: no sync matched - wrong freq/BW/SF/CR or signal too weak");
}

// ── Cykl tła ──────────────────────────────────────────────────
// Trzy pomiary o rosnącej selektywności: energia (łapie wszystko, nie odróżnia nic),
// CAD (jest preambuła LoRa czy nie — odróżnia ruch od zakłócenia), nasłuch (zdekodowane ramki).
static void bg_cycle() {
    static const float CH[] = LORA_BG_CHANNELS;
    static const uint8_t SFS[] = LORA_BG_SFS;
    const int NCH = sizeof(CH) / sizeof(CH[0]);
    const int NSF = sizeof(SFS) / sizeof(SFS[0]);

    if (!cfg(CH[0], LORA_BG_BW, LORA_BG_SF, LORA_BG_CR, LORA_BG_SYNC)) return;

    float noise = 999;
    int   busy  = 0;
    for (int i = 0; i < NCH; i++) {
        if (!tune(CH[i])) continue;
        float mn, mx; channel_rssi(&mn, &mx);
        if (mn < noise) noise = mn;
        if (mx - mn >= LORA_BUSY_MARGIN_DB) busy++;
    }

    int cad = 0, cad_total = 0;
    for (int s = 0; s < NSF; s++) {
        for (int i = 0; i < NCH; i++) {
            if (!cfg(CH[i], LORA_BG_BW, SFS[s], LORA_BG_CR, LORA_BG_SYNC)) continue;
            cad_total++;
            if (s_radio.scanChannel() == RADIOLIB_LORA_DETECTED) cad++;
        }
    }

    float best = -999;
    int frames = listen_window(LORA_BG_FREQ, LORA_BG_BW, LORA_BG_SF, LORA_BG_CR,
                               LORA_BG_SYNC, LORA_BG_LISTEN_S, &best, false);

    // mon.* — BE zna juz te encje jako natywne (kategoria RF, migrate_lora_category.sql).
    // own.* NIE dzialalo: stripPrefix po stronie BE zdejmuje wylacznie pub. i mon., wiec
    // "own.lora_noise" nie redukowalo sie do "lora_noise" i ladowalo w soft_data zamiast
    // w data_points — czyli nie liczylo sie ani do kategorii, ani do aktywnosci.
    // mon, nie pub: to pomiar srodowiska, ale na razie nie towar (poza katalogiem).
    push_num("mon.lora_noise", noise, "dBm");
    push_num("mon.lora_busy",  busy,  "");
    // lora_cad USUNIETY z encji. Mierzy go tylko bg_cycle, a ten nie biegnie w trybie link
    // (link_tick przejmuje petle wczesniej), wiec w praktyce wartosc pochodzila z jednego
    // przebiegu tuz po restarcie i zostawala ZAMROZONA na zawsze — bufor mon nie ma czyszczenia
    // po TTL. Zamrozone 0% wyglada jak martwa siec i jest gorsze niz brak metryki.
    // Pomiar zostaje w s_last.bg_cad (widoczny w /lora/last i w panelu skanow), tylko nie
    // udaje juz encji. Wroci, jesli kiedys zrobimy sonde CAD w oknie guard.
    push_num("mon.lora_pkt",   frames > 0 ? frames : 0, "");
    if (frames > 0) push_num("mon.lora_rssi", best, "dBm");

    s_last.bg_noise = noise; s_last.bg_busy = busy;
    s_last.bg_cad = cad; s_last.bg_cad_total = cad_total;
    s_last.bg_frames = frames > 0 ? frames : 0;

    LOGI("lora", "bg: noise %.0f dBm | busy %d/%d ch | CAD %d/%d | frames %d",
         noise, busy, NCH, cad, cad_total, frames > 0 ? frames : 0);
}

// GET /lora/last — cały stan pomiarowy w jednym JSON-ie, żeby dało się to obejrzeć
// wykresem zamiast czytać log.
void lora_json(String& out) {
    char b[192];
    out = "{\"radio\":";
    out += s_ok ? "\"up\"" : "\"down\"";
    snprintf(b, sizeof(b), ",\"busy\":%s,\"bg\":{\"noise\":%.0f,\"busy_ch\":%d,"
             "\"cad\":%d,\"cad_total\":%d,\"frames\":%d}",
             s_busy ? "true" : "false", s_last.bg_noise, s_last.bg_busy,
             s_last.bg_cad, s_last.bg_cad_total, s_last.bg_frames);
    out += b;

    snprintf(b, sizeof(b), ",\"camp\":{\"freq\":%.3f,\"noise\":%.0f,\"peak\":%.0f,"
             "\"events\":%u,\"short\":%u,\"air_ms\":%lu,\"secs\":%u}",
             s_last.camp_freq, s_last.camp_noise, s_last.camp_peak,
             s_last.camp_events, s_last.camp_short,
             (unsigned long)s_last.camp_air_ms, s_last.camp_secs);
    out += b;

    snprintf(b, sizeof(b), ",\"cad\":{\"freq\":%.3f,\"bw\":%.1f,\"sf\":%u,"
             "\"hits\":%u,\"probes\":%u}",
             s_last.cad_freq, s_last.cad_bw, s_last.cad_sf,
             s_last.cad_hits, s_last.cad_probes);
    out += b;

    out += ",\"sweep\":[";
    for (int i = 0; i < s_last.sweep_n; i++) {
        snprintf(b, sizeof(b), "%s{\"f\":%.3f,\"noise\":%.0f,\"peak\":%.0f}",
                 i ? "," : "", s_last.sweep_f[i], s_last.sweep_noise[i], s_last.sweep_peak[i]);
        out += b;
    }
    out += "],\"link\":";
    String ls; lora_link_status_json(ls);   // diagnoza drenażu TX widoczna bez seriala
    out += ls;
    out += "}";
}

// ══ TRYB LINK ═════════════════════════════════════════════════
// Zasada: nasłuch jest stanem spoczynkowym. Radio wychodzi z RX tylko na własne ~200 ms
// nadania i na przestrojenie kanału. Kanał liczy się z zegara UTC, więc wszystkie nody
// są na tej samej częstotliwości bez wymiany jakiejkolwiek wiadomości.
static struct {
    volatile bool on, beacon;
    uint8_t  slot, min_per_ch, n_ch;
    uint8_t  role;                       // 0 = skaner (rotacja planu), 1 = PUNKT (camp ch[0], CAD)
    uint16_t beacon_s;
    bool     has_seed;                   // sekret kodu w beaconie — tylko RAM, patrz lora_link_set
    uint8_t  seed[16];
    LoraLinkCh ch[LORA_LINK_MAX_CH];
} s_link = {};

static int      s_cur_ch   = -1;         // indeks kanału, na którym stoi radio
static uint32_t s_duty_ms  = 0;          // airtime w bieżącym oknie godzinowym
static uint32_t s_duty_h   = 0;          // numer okna (epoch/3600)
static uint32_t s_tx_seq   = 0;
static uint32_t s_rx_total = 0, s_rx_dropped = 0;
static uint32_t s_rx_min   = 0, s_rx_in_min = 0;   // licznik cap/min

// ── Telemetria RF w trybie link ──────────────────────────────────────────────
// Encje mon.lora_* produkowal WYLACZNIE bg_cycle(), a ten nigdy nie biegnie przy s_link.on
// — link przejmuje petle wczesniej (link_tick + continue). Od chwili, gdy BE zaczal rozdawac
// plany regionalne z on:true, cala flota radiowa przestala raportowac kategorie RF. Skutki
// byly trzy i dlugo wygladaly na osobne usterki: znikla sekcja RF w panelu, przestal rosnac
// licznik typow danych, a mnoznik kategorii utknal na 1.30 zamiast 1.40 (RF jest czwarta
// kategoria we wzorze — patrz CATEGORY_BONUS_MAX w BE/src/config.js).
//
// Pomiary i tak sa robione przy KAZDEJ rotacji kanalu (channel_rssi ponizej) — brakowalo
// tylko wypchniecia ich jako encji. Nie przerywamy nasluchu i nie gubimy ramek.
// lora_cad zostaje poza tym zestawem: CAD wymaga scanChannel() na wylacznosc radia, czego
// w trybie ciaglego RX zrobic nie mozna. Lepiej nie raportowac niz raportowac zmyslone.
static float    s_ent_noise[LORA_LINK_MAX_CH];
static float    s_ent_peak [LORA_LINK_MAX_CH];
static bool     s_ent_seen [LORA_LINK_MAX_CH];
static uint32_t s_ent_pkt  = 0;
static float    s_ent_best = -999;
static uint32_t s_ent_last = 0;                    // epoch ostatniego wypchniecia

// Bufor ramek do wysłania w batchu. Statyczny — żadnych String w ścieżce RX.
struct RxFrame {
    uint32_t ts;
    float    freq, rssi, snr;
    uint8_t  sf, len, hexlen, mode;
    bool     crc_err;
    char     smos[9];                     // id8 nadawcy, gdy to nasza ramka; "" gdy obca
    uint8_t  raw[LORA_RX_HEX_MAX];
};
static RxFrame s_rx[LORA_RX_BATCH_MAX];
static uint8_t s_rx_n = 0;

// Batch ramek → BE. Format lustrzany do check_result: metadane zawsze, payload przycięty.
static void link_flush_rx() {
    if (!s_rx_n) return;
    if (!ws_client_connected()) { s_rx_n = 0; return; }   // offline: nie kolejkujemy, radio ma iść dalej

    // Brak wolnego slotu = paczka przepada, ale bufor ramek MUSI sie zwolnic — inaczej
    // zapchana skrzynka zatrzymalaby odbior z eteru, czyli to, po co ten node istnieje.
    char* buf = out_claim();
    if (!buf) { s_rx_n = 0; return; }

    int p = snprintf(buf, LORA_OUT_MAX, "{\"type\":\"lora_rx\",\"frames\":[");
    for (uint8_t i = 0; i < s_rx_n && p < LORA_OUT_MAX - 420; i++) {
        const RxFrame& f = s_rx[i];
        // mode leci razem z ramką — bez tego BE i panel pokazywały „SF9" także przy FSK,
        // gdzie spreading factor nie istnieje (podobnie SNR, który ma sens tylko w LoRa).
        p += snprintf(buf + p, LORA_OUT_MAX - p,
            "%s{\"ts\":%lu,\"freq\":%.3f,\"mode\":%u,\"sf\":%u,\"rssi\":%.0f,\"snr\":%.1f,\"len\":%u,\"crc\":%s",
            i ? "," : "", (unsigned long)f.ts, f.freq, f.mode, f.sf, f.rssi, f.snr, f.len,
            f.crc_err ? "false" : "true");
        if (f.smos[0]) p += snprintf(buf + p, LORA_OUT_MAX - p, ",\"smos\":\"%s\"", f.smos);
        p += snprintf(buf + p, LORA_OUT_MAX - p, ",\"hex\":\"");
        for (uint8_t b = 0; b < f.hexlen && p < (int)LORA_OUT_MAX - 8; b++)
            p += snprintf(buf + p, LORA_OUT_MAX - p, "%02x", f.raw[b]);
        p += snprintf(buf + p, LORA_OUT_MAX - p, "\"}");
    }
    snprintf(buf + p, LORA_OUT_MAX - p, "]}");
    out_post(buf);
    s_rx_n = 0;
}

// CMD 0x03 (model v2, core 0): komenda emergency ≤8 zn od ownera (app→BE→przekaźnik→eter).
// true = obsłużona (dla mnie: wykonana albo echo) → NIE forwardować do BE.
// false = nie dla mnie / brak seeda / zły tag → do batcha uplinku jak każda ramka.
static bool cmd_rx_handle(const uint8_t* data, int len, uint32_t now) {
    if (memcmp(data + 2, s_self_id3, SMOM_ID_LEN) != 0) return false;   // dst != ja
    if (!s_owner_seed_ok) return false;                                 // brak seeda → nie zweryfikuję
    SmomMsg m; bool forme = false;
    if (!smom_decode(data, (size_t)len, s_owner_seed, now / 60, s_self_id3, &m, &forme)) return false;
    if (!forme || m.type != SMOM_TYPE_CMD) return false;
    if (m.payload_len == 0 || m.payload_len > SMOM_CMD_MAX) return true; // nasza, ale zepsuta → drop
    // Tylko drukowalne ASCII bez " i \ — payload idzie 1:1 w JSON-y (inbox/webhook/MQTT).
    for (uint8_t i = 0; i < m.payload_len; i++) {
        const uint8_t c = m.payload[i];
        if (c < 0x21 || c > 0x7e || c == '"' || c == '\\') return true;  // zepsuta → drop
    }

    const uint32_t minute = now / 60;
    const bool dupe = s_cmd_seen && m.seq == s_cmd_last_seq &&
                      (minute - s_cmd_last_min) <= (uint32_t)(2 * SMOM_MINUTE_SKEW + 1);
    cmdack_arm(m.seq);                                       // ack ZAWSZE (także dla echa)
    if (dupe) return true;                                   // wykonanie tylko raz
    s_cmd_seen = true; s_cmd_last_seq = m.seq; s_cmd_last_min = minute;

    if (s_cmdQ) {
        CmdRx rx; memset(&rx, 0, sizeof(rx));
        memcpy(rx.cmd, m.payload, m.payload_len);
        xQueueSend(s_cmdQ, &rx, 0);
    }
    LOGI("lora", "CMD emergency '%.*s' seq %u — przyjęta", m.payload_len, m.payload, m.seq);
    return true;
}

// Odebrana ramka → bufor. Nasze beacony rozpoznajemy TU (BE nie ma zgadywać):
// 0xE0 + "SMOS <id8> <seq>".
static void link_on_frame(const uint8_t* data, int len, bool crc_err, float freq, uint8_t sf, uint8_t mode) {
    uint32_t now = ws_epoch_now();
    uint32_t min = now / 60;
    if (min != s_rx_min) { s_rx_min = min; s_rx_in_min = 0; }
    s_rx_total++;
    if (++s_rx_in_min > LORA_RX_CAP_PER_MIN) { s_rx_dropped++; return; }

    // Komenda emergency (0xE0 0x03) dla mnie → wykonaj lokalnie, nie zajmuje slotu batcha.
    if (!crc_err && len >= SMOM_HDR_LEN && data[0] == SMOM_MAGIC0 &&
        data[1] == SMOM_TYPE_CMD && cmd_rx_handle(data, len, now)) return;

    // Ramka publiczna DATA (0xE0 0x02) dla mnie → dekod lokalny (zero-knowledge), też poza
    // batchem. Nie-dla-mnie spada niżej i leci hexem do BE, który routuje po dst.
    if (!crc_err && data[0] == SMOM_MAGIC0 && data[1] == SMOM_TYPE_DATA &&
        data_rx_process(data, len, false, now)) return;

    if (s_rx_n >= LORA_RX_BATCH_MAX) link_flush_rx();
    if (s_rx_n >= LORA_RX_BATCH_MAX) return;

    RxFrame& f = s_rx[s_rx_n++];
    f.ts = now; f.freq = freq; f.sf = sf; f.mode = mode; f.crc_err = crc_err;
    f.rssi = s_radio.getRSSI(); f.snr = s_radio.getSNR();
    // Licznik do encji RF. Tylko ramki z poprawnym CRC — zlamana ramka jest dowodem
    // transmisji, ale jej RSSI bywa smieciowe i psuloby "najmocniejszy odbior".
    if (!crc_err) { s_ent_pkt++; if (f.rssi > s_ent_best) s_ent_best = f.rssi; }
    f.len = len > 255 ? 255 : len;
    f.hexlen = len > LORA_RX_HEX_MAX ? LORA_RX_HEX_MAX : (uint8_t)len;
    memcpy(f.raw, data, f.hexlen);
    f.smos[0] = 0;
    const int PFX = 1 + 5;                                  // 0xE0 + "SMOS "
    if (!crc_err && len >= PFX + 8 && data[0] == LORA_BEACON_MAGIC &&
        memcmp(data + 1, LORA_BEACON_PREFIX, 5) == 0) {
        memcpy(f.smos, data + PFX, 8); f.smos[8] = 0;
        // Te 8 bajtow przyszlo Z ETERU — nadaje je ktokolwiek, nie nasz kod. Bez sprawdzenia
        // dowolny ciag (cudzyslow, backslash, bajt zerowy) szedl wprost do JSON-a paczki RX:
        // psul cala ramke lora_rx, przez co ginely takze wszystkie poprawne odczyty obok,
        // a po stronie BE ladowal jako klucz krawedzi i w innerHTML panelu admina.
        // Prawdziwy identyfikator to zawsze 8 znakow [0-9a-f]; cokolwiek innego = ramka obca.
        for (int k = 0; k < 8; k++) {
            const char c = f.smos[k];
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) { f.smos[0] = 0; break; }
        }
        // Własny beacon nigdy nie jest krawędzią „kto kogo słyszy" (echo z bufora TX,
        // w przyszłości repeater) — zostaje w ramce jako ślad, ale bez identyfikacji nadawcy.
        if (f.smos[0] && memcmp(f.smos, g_device_id, 8) == 0) f.smos[0] = 0;
    }
    if (f.smos[0])
        LOGI("lora", "BEACON from %s  RSSI %.0f  SNR %.1f  @%.3f SF%u",
             f.smos, f.rssi, f.snr, freq, sf);
}

// Airtime ramki LoRa wg datasheetu SX126x — potrzebny PRZED nadaniem, żeby licznik duty
// cycle mógł odmówić. Poprzednia wersja szacowała to przesunięciem bitowym i przy SF<9
// robiła `1 << -1` (UB): budżet „wyczerpywał się" natychmiast i beacon nigdy nie leciał.
static uint32_t lora_airtime_ms(uint8_t sf, float bw_khz, uint8_t cr, uint8_t len) {
    if (sf < 6)  sf = 6;
    if (sf > 12) sf = 12;
    if (cr < 5)  cr = 5;
    if (cr > 8)  cr = 8;
    if (bw_khz <= 0) bw_khz = 125.0f;
    const float ts = (float)(1UL << sf) / bw_khz;            // czas symbolu [ms]
    const int   de = (ts > 16.0f) ? 1 : 0;                    // low data rate optimize
    const int   num = 8 * (int)len - 4 * (int)sf + 28 + 16;
    const int   den = 4 * ((int)sf - 2 * de);
    const int   n   = 8 + (num > 0 ? ((num + den - 1) / den) * (int)cr : 0);
    return (uint32_t)((12.25f + n) * ts) + 1;                 // preambuła 8 + 4.25 symbola
}

// Kod beaconu: HMAC-SHA256(seed, "<id8>:<minuta_epoch>") -> pierwsze 4 bajty jako 8 hex.
// Sekret znamy tylko my i BE, wiec „uslyszalem noda X" przestaje byc czyms, co da sie
// wpisac z palca — a poniewaz argumentem jest MINUTA z zegara, nikt nie musi niczego
// dosylac i wczorajszy kod jest dzis bezwartosciowy.
// Ramka awaryjna (vals != null): HMAC z "<id8>:<minuta>:<vals>" — kod obejmuje TRESC,
// wiec podsluchany swiezy kod nie nadaje sie do nadania ramki z podmienionymi wartosciami.
// Param acks (0.95) ZAREZERWOWANY na Faze 3 (authenticated ACK) — OBECNIE NIE uzywany: link_tx_beacon
// wola beacon_code BEZ acks, wiec ACK jest advisory i kod HMAC zostaje BAJT-W-BAJT jak 0.94 (kompat z verifyBeacon BE).
static void beacon_code(char out[9], uint32_t minute, const char* vals = nullptr,
                        const char* acks = nullptr) {
    out[0] = 0;
    const mbedtls_md_info_t* mi = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!mi) return;
    char msg[192];
    if (acks && acks[0])
        snprintf(msg, sizeof(msg), "%.8s:%lu:%s:A:%s", g_device_id, (unsigned long)minute,
                 (vals && vals[0]) ? vals : "", acks);
    else if (vals && vals[0])
        snprintf(msg, sizeof(msg), "%.8s:%lu:%s", g_device_id, (unsigned long)minute, vals);
    else
        snprintf(msg, sizeof(msg), "%.8s:%lu", g_device_id, (unsigned long)minute);
    uint8_t mac[32];
    if (mbedtls_md_hmac(mi, s_link.seed, sizeof(s_link.seed),
                        (const uint8_t*)msg, strlen(msg), mac) != 0) return;
    bytes_to_hex(mac, 4, out);                               // 8 znakow + NUL
}

// Wartosci zestawu awaryjnego: "v1,v2,v3,v4" pozycyjnie wg s_emerg (brak encji = puste
// pole, BE mapuje po indeksie). Przecinek/spacja/nie-ASCII w wartosci -> '_' (separatory).
static void emerg_vals(char* out, size_t cap) {
    size_t p = 0;
    for (uint8_t i = 0; i < s_emerg.n && p + 2 < cap; i++) {
        if (i) out[p++] = ',';
        char v[40];
        if (!entity_get_string(s_emerg.eids[i], v, sizeof(v))) continue;
        for (uint8_t k = 0; v[k] && k < LORA_EMERG_VAL_MAX && p + 1 < cap; k++) {
            const char c = v[k];
            out[p++] = (c == ',' || c < 0x21 || c > 0x7e) ? '_' : c;
        }
    }
    out[p] = 0;
}

// Budżet airtime na godzinę zależnie od podpasma: EU-slot 869.4-869.65 = 10%, reszta 1%.
// Konserwatywnie po częstotliwości — poza EU (US 906.x) zostaje 1%, choć FCC nie liczy DC.
static uint32_t duty_budget(float freq) {
    return (freq >= 869.4f && freq <= 869.65f) ? LORA_DUTY_MS_H_10PCT : LORA_LINK_DUTY_MS_H;
}

// CAD (Channel Activity Detection) przed nadaniem — ALOHA trybu PUNKT. Zwraca true, gdy
// kanał wolny. scanChannel() jest blokujące (kilka symboli; SF11@125 ≈ 130 ms) i też strzela
// DIO1, więc po sondzie wracamy w nasłuch z wyzerowanym IRQ (jak po transmit()).
static bool cad_clear(const LoraLinkCh& c) {
    if (c.mode == 1) return true;                            // FSK: brak CAD — nadawaj
    int st = s_radio.scanChannel();
    s_irq = false;
    s_radio.startReceive();
    return st != RADIOLIB_LORA_DETECTED && st != RADIOLIB_PREAMBLE_DETECTED;
}

// Nadanie beaconu. Zwraca airtime w ms (0 = nie nadano).
static uint32_t link_tx_beacon(const LoraLinkCh& c) {
    uint32_t now = ws_epoch_now();
    uint32_t h = now / 3600;
    if (h != s_duty_h) { s_duty_h = h; s_duty_ms = 0; }
    // Ramka niesie to, czego ODBIORNIK nie ma jak zmierzyc: moc nadawania (bez niej nie
    // policzysz tlumienia trasy, bo tlumienie = txp - rssi) oraz podloge i szczyt szumu
    // u nadawcy (bez nich nie odroznisz "slabo go slysze bo daleko" od "slabo bo u niego
    // halas"). RSSI i SNR odbiornik zmierzy sam, wiec ich nie wysylamy.
    //
    // Pola DOKLADANE NA KONCU i rozdzielone spacjami — stary parser czyta trzy pierwsze
    // tokeny i ignoruje reszte, wiec nody na starym firmware pozostaja zrozumiale. Kod
    // (ostatni token) trzyma sie tej samej zasady i znika, gdy BE nie przyslal seeda.
    // Tryb awaryjny: ogon " E1 <vals>" za kodem. Wartosci wchodza do HMAC (anty-podmiana),
    // wiec ogon istnieje tylko razem z kodem — bez seeda nie ma czego uwierzytelnic.
    // Model v2: ogon " C <s1>,<s2>,..." = cmd-acki (≤4 potwierdzenia komend CMD 0x03) —
    // ADVISORY, poza HMAC (jak dawny ACK); BE przyjmuje go tylko z beaconu zweryfikowanego.
    char pl[160], code[9] = {0}, vals[40] = {0}, ctok[24] = {0};
    const bool emerg = s_emerg_on;                      // snapshot: spojny kod i ogon
    if (emerg) emerg_vals(vals, sizeof(vals));
    if (s_link.has_seed)
        beacon_code(code, now / 60, (emerg && vals[0]) ? vals : nullptr);
    const bool etail = emerg && vals[0] && code[0];
    const bool ctail = s_cmdack_n > 0 && code[0];
    if (ctail) {
        size_t p = snprintf(ctok, sizeof(ctok), " C ");
        for (uint8_t i = 0; i < s_cmdack_n && p + 5 < sizeof(ctok); i++)
            p += snprintf(ctok + p, sizeof(ctok) - p, "%s%u", i ? "," : "", s_cmdacks[i]);
    }
    int n = snprintf(pl + 1, sizeof(pl) - 1, "%s%.8s %lu %d %d %d%s%s%s%s%s",
                     LORA_BEACON_PREFIX, g_device_id, (unsigned long)s_tx_seq,
                     (int)s_last.bg_noise, (int)s_last.bg_peak, LORA_LINK_TX_POWER,
                     code[0] ? " " : "", code,
                     etail ? " E1 " : "", etail ? vals : "",
                     ctok);
    if (n < 0) return 0;
    if (n > (int)sizeof(pl) - 1) n = (int)sizeof(pl) - 1;   // snprintf zwraca dlugosc SPRZED obciecia
    pl[0] = (char)LORA_BEACON_MAGIC;

    // Airtime z RZECZYWISTEJ dlugosci ramki. Stale 44 B przestaly byc prawda, gdy doszedl
    // kod (do 47 B), a zanizony szacunek okrada licznik duty cycle z tego, po co istnieje.
    uint32_t est = lora_airtime_ms(c.sf, c.bw, c.cr, (uint8_t)(n + 1));
    if (s_duty_ms + est > duty_budget(c.freq)) {
        LOGW("lora", "beacon skipped — duty cycle budget spent (%lums/h)", (unsigned long)s_duty_ms);
        return 0;
    }
    uint32_t t0 = millis();
    s_radio.setOutputPower(LORA_LINK_TX_POWER);
    int st = s_radio.transmit((uint8_t*)pl, n + 1);
    uint32_t air = millis() - t0;
    // KRYTYCZNE: transmit() też generuje przerwanie DIO1 (TxDone), a nasz ISR nie odróżnia
    // go od RxDone. Bez tego pętla RX odczytałaby bufor z WŁASNYM beaconem i node
    // zaraportowałby, że słyszy sam siebie.
    s_irq = false;
    s_radio.startReceive();                                  // NATYCHMIAST z powrotem w nasłuch
    if (st != RADIOLIB_ERR_NONE) { LOGW("lora", "beacon TX failed (%d)", st); return 0; }
    s_duty_ms += air; s_tx_seq++;
    if (ctail) s_cmdack_n = 0;                               // acki poleciały — dopiero teraz kasuj
    LOGI("lora", "beacon #%lu sent @%.3f SF%u (%lums air, duty %lums/h)",
         (unsigned long)s_tx_seq - 1, c.freq, c.sf, (unsigned long)air, (unsigned long)s_duty_ms);
    return air;
}

// Nadanie SUROWEJ ramki binarnej (downlink lora_tx). Wspólny budżet DC z beaconem;
// ramka ma PRIORYTET — drenowana w link_tick PRZED slotem beaconu.
// Zakłada odświeżone s_duty_ms (link_tick resetuje okno godzinowe). Zwraca air ms (0 = nie nadano).
static uint32_t link_tx_raw(const LoraLinkCh& c, const uint8_t* frame, uint8_t len) {
    uint32_t est = lora_airtime_ms(c.sf, c.bw, c.cr, len);
    if (s_duty_ms + est > duty_budget(c.freq)) return 0;    // brak budżetu — zostaw w kolejce
    uint32_t t0 = millis();
    s_radio.setOutputPower(LORA_LINK_TX_POWER);
    int st = s_radio.transmit((uint8_t*)frame, len);
    uint32_t air = millis() - t0;
    s_irq = false;                                          // TxDone tez podnosi DIO1 — nie licz jak RX
    s_radio.startReceive();                                 // natychmiast z powrotem w nasłuch
    s_tx_last_st = st;
    if (st != RADIOLIB_ERR_NONE) { LOGW("lora", "SMOM TX failed (%d)", st); return 0; }
    s_duty_ms += air;
    LOGI("lora", "SMOM frame TX @%.3f SF%u (%u B, %lums air, duty %lums/h)",
         c.freq, c.sf, len, (unsigned long)air, (unsigned long)s_duty_ms);
    return air;
}

// Drenaż kolejki TX na kanale `ch` (Punkt/emergency: kanał domowy, na którym stoi;
// skaner: wycieczka — patrz link_tick). Liczniki dr_* = diagnoza w GET /lora/last.
static void drain_txq(const LoraLinkCh& ch) {
    SmomTx tx;
    while (xQueuePeek(s_txQ, &tx, 0) == pdTRUE) {
        s_dr_seen++;
        uint32_t est = lora_airtime_ms(ch.sf, ch.bw, ch.cr, tx.len);
        if (s_duty_ms + est > duty_budget(ch.freq)) { s_dr_nobud++; break; }   // brak budżetu
        if (!cad_clear(ch)) { s_dr_cad++; break; }                             // kanał zajęty
        xQueueReceive(s_txQ, &tx, 0);
        if (link_tx_raw(ch, tx.frame, tx.len)) s_dr_ok++; else s_dr_fail++;
    }
}

// Jeden przebieg pętli link (~200 ms). Wszystko sterowane zegarem UTC — bez stanu między iteracjami.
static void link_tick() {
    uint32_t now = ws_epoch_now();
    if (!now || !s_link.n_ch) { delay(200); return; }

    // Tryb awaryjny: uplink pada, gdy WiFi lezy ALBO sonda WD orzekla "internet w dol"
    // (wan_state 2). Uzbrojenie po LORA_EMERG_AFTER_MS ciaglej awarii — blip deployu BE
    // konczy sie stanem 1 (sonda przechodzi) i licznik startuje od zera.
    const bool bad = (WiFi.status() != WL_CONNECTED) || (ws_client_wan_state() == 2);
    if (bad) { if (!s_emerg_bad_since) s_emerg_bad_since = millis(); }
    else s_emerg_bad_since = 0;
    s_emerg_on = s_emerg_bad_since && (millis() - s_emerg_bad_since >= LORA_EMERG_AFTER_MS)
                 && s_emerg.n && s_link.has_seed;

    // Tryb DOMOWY: rola PUNKT campuje na kanale domowym (= scan[0] planu, region-aware z BE),
    // a EMERGENCY parkuje tam KAŻDĄ rolę — tam nasłuchują Punkty, tam ma być słyszany.
    // Skaner bez emergency: rotacja planu z zegara UTC jak dotąd (ch[0] w rotacji = „próbka"
    // kanału domowego — skaner przy okazji łapie tam ramki i staty beaconów).
    const bool home_mode = (s_link.role == 1) || s_emerg_on;
    const uint8_t idx = home_mode ? 0
                      : (uint8_t)((now / 60 / s_link.min_per_ch) % s_link.n_ch);
    const LoraLinkCh& c = s_link.ch[idx];
    const uint32_t sec_in_min = now % 60;

    // Encje RF co LORA_ENT_PERIOD_S. Poza blokiem zmiany kanalu, zeby leciec niezaleznie
    // od tego, jak dlugo trwa slot — przy min_per_ch=10 rotacja jest rzadsza niz ten okres.
    if (!s_ent_last) s_ent_last = now;
    else if (now - s_ent_last >= LORA_ENT_PERIOD_S) {
        s_ent_last = now;
        float noise = 999; int busy = 0, seen = 0;
        for (int i = 0; i < LORA_LINK_MAX_CH; i++) {
            if (!s_ent_seen[i]) continue;
            seen++;
            if (s_ent_noise[i] < noise) noise = s_ent_noise[i];
            if (s_ent_peak[i] - s_ent_noise[i] >= LORA_BUSY_MARGIN_DB) busy++;
        }
        if (seen) {
            push_num("mon.lora_noise", noise, "dBm");
            push_num("mon.lora_busy",  (float)busy, "");
            push_num("mon.lora_pkt",   (float)s_ent_pkt, "");
            if (s_ent_best > -900) push_num("mon.lora_rssi", s_ent_best, "dBm");
            LOGI("lora", "encje RF: szum %.0f dBm, zajete %d/%d kanalow, ramek %lu, najlepszy %.0f",
                 noise, busy, seen, (unsigned long)s_ent_pkt,
                 s_ent_best > -900 ? s_ent_best : 0);
        }
        s_ent_pkt = 0; s_ent_best = -999;
    }

    // Zmiana kanału: skaner TYLKO w oknie guard (nikt wtedy nie nadaje), przy okazji sweep.
    // Tryb domowy przestraja się OD RAZU (nie ma harmonogramu, na który trzeba czekać).
    if ((int)idx != s_cur_ch) {
        if (!home_mode &&
            sec_in_min > LORA_LINK_GUARD_S && sec_in_min < 60 - LORA_LINK_GUARD_S && s_cur_ch >= 0) {
            delay(200); return;                              // czekamy na guard — nie gubimy ramek w środku minuty
        }
        link_flush_rx();
        if (c.mode == 1)
            LOGI("lora", "link: channel -> %.3f MHz FSK br%.1f dev%.1f (slot %u)",
                 c.freq, c.br, c.dev, s_link.slot);
        else
            LOGI("lora", "link: channel -> %.3f MHz SF%u BW%.0f sync 0x%02X (slot %u)",
                 c.freq, c.sf, c.bw, c.sync, s_link.slot);
        if (!cfg_ch(c)) { delay(1000); return; }
        // begin() zostawia radio w standby — bez tego pomiar leciał na wyłączonym
        // odbiorniku i KAŻDY kanał raportował −128 dBm (podłoga skali, nie cisza w eterze).
        s_irq = false;
        rx_warmup();
        float mn, mx; channel_rssi(&mn, &mx);                // szybki sweep = puls kanału
        s_last.bg_noise = mn; s_last.bg_peak = mx;
        // Ten sam pomiar zasila encje RF — patrz komentarz przy s_ent_*.
        if (idx < LORA_LINK_MAX_CH) {
            s_ent_noise[idx] = mn; s_ent_peak[idx] = mx; s_ent_seen[idx] = true;
        }
        // Puls kanału → BE. Bez tego pomiar szumu ginął w RAM płytki (czytelny tylko po
        // kablu), a przy rotacji to jest gotowy obraz zajętości pasma: szum i szczyt
        // na każdej częstotliwości planu, z każdego noda floty.
        if (ws_client_connected()) {
            char* b = out_claim();
            if (b) {
                snprintf(b, LORA_OUT_MAX,
                    "{\"type\":\"lora_ch\",\"ts\":%lu,\"freq\":%.3f,\"bw\":%.1f,\"sf\":%u,"
                    "\"sync\":%u,\"mode\":%u,\"noise\":%.0f,\"peak\":%.0f}",
                    (unsigned long)now, c.freq, c.bw, c.sf, c.sync, c.mode, mn, mx);
                out_post(b);
            }
        }
        // Radio odbiera już od rx_warmup() — ponowne startReceive() z zerowaniem s_irq
        // wyrzuciłoby ramkę, która wpadła w trakcie 28 ms pomiaru.
        s_cur_ch = idx;
        return;
    }

    // Tryb domowy nie rotuje, więc puls kanału (lora_ch → BE) nie ma okazji z retune —
    // robimy go okresowo. Punkt siedzący 24/7 daje NAJLEPSZY obraz zajętości kanału domowego.
    static uint32_t s_pulse_last = 0;
    if (home_mode && now - s_pulse_last >= LORA_POINT_PULSE_S) {
        s_pulse_last = now;
        s_irq = false;
        rx_warmup();
        float mn, mx; channel_rssi(&mn, &mx);
        s_last.bg_noise = mn; s_last.bg_peak = mx;
        s_ent_noise[0] = mn; s_ent_peak[0] = mx; s_ent_seen[0] = true;
        if (ws_client_connected()) {
            char* b = out_claim();
            if (b) {
                snprintf(b, LORA_OUT_MAX,
                    "{\"type\":\"lora_ch\",\"ts\":%lu,\"freq\":%.3f,\"bw\":%.1f,\"sf\":%u,"
                    "\"sync\":%u,\"mode\":%u,\"noise\":%.0f,\"peak\":%.0f}",
                    (unsigned long)now, c.freq, c.bw, c.sf, c.sync, c.mode, mn, mx);
                out_post(b);
            }
        }
    }

    // ── Ramki na zlecenie BE (lora_tx): nadaj ASAP, PRIORYTET nad beaconem (wspólny budżet DC) ──
    // Reset okna godzinowego tu, by budżet był świeży dla drenażu (link_tx_beacon resetuje sam).
    // Jeśli ramki zjedzą budżet — link_tx_beacon i tak sam odmówi (ten sam s_duty_ms).
    { uint32_t hh = now / 3600; if (hh != s_duty_h) { s_duty_h = hh; s_duty_ms = 0; } }
    // Adresat DATA/CMD parkuje (albo bywa) na ch[0] — nadanie na innym kanale by go minęło.
    // Punkt/emergency stoi na ch[0] → drenaż w miejscu. Skaner (lora8): WYCIECZKA TX —
    // skok na kanał domowy, nadanie, powrót do slotu rotacji. Bez tego ramka czekała na
    // rotację do ~40 min (lekcja z testu 2026-09-01). Throttle 30 s, żeby zablokowana
    // kolejka (budżet/CAD) nie telepała radiem co tick.
    if (s_txQ && uxQueueMessagesWaiting(s_txQ) > 0) {
        if (home_mode || idx == 0) {
            drain_txq(c);
        } else {
            static uint32_t s_next_exc = 0;
            if (now >= s_next_exc) {
                const LoraLinkCh& h = s_link.ch[0];
                if (cfg_ch(h)) {
                    s_irq = false;
                    rx_warmup();
                    drain_txq(h);
                }
                if (cfg_ch(c)) { s_irq = false; rx_warmup(); }   // powrót na kanał slotu
                s_next_exc = uxQueueMessagesWaiting(s_txQ) ? now + 30 : 0;
            }
        }
    }

    if (home_mode) {
        // ── Beacon ALOHA (tryb domowy): bez slotów/zegara — kadencja + CAD + jitter ──
        // Jitter rozstrzela nody, które wystartowałyby równo; CAD nie wchodzi nikomu w słowo.
        // Emergency: kanał MUSI mówić — po LORA_CAD_TRIES zajętych sondach nadaje mimo wszystko.
        static uint32_t s_next_beacon = 0;
        static uint8_t  s_cad_busy = 0;
        if (s_link.beacon && now >= s_next_beacon) {
            if (cad_clear(c) || (s_emerg_on && s_cad_busy >= LORA_CAD_TRIES)) {
                s_cad_busy = 0;
                link_tx_beacon(c);
                const uint32_t period = s_emerg_on ? (uint32_t)LORA_EMERG_EVERY_MIN * 60
                                                   : (s_link.beacon_s ? s_link.beacon_s : 60);
                s_next_beacon = now + period + (esp_random() % 11);        // +0..10 s jitteru
            } else {
                s_cad_busy++;
                s_next_beacon = now + 2 + (esp_random() % 4);              // krótki backoff
            }
        }
    } else {
        // Slot nadawania: sekunda 10 + k*7 w każdej minucie. Trafiamy w nią raz — seq rośnie,
        // więc podwójne wejście w tę samą sekundę wykluczamy znacznikiem ostatniej minuty.
        static uint32_t last_tx_min = 0;
        const uint32_t my_sec = LORA_LINK_SLOT0_S + (uint32_t)s_link.slot * LORA_LINK_SLOT_GAP_S;
        if (s_link.beacon && sec_in_min == my_sec && (now / 60) != last_tx_min &&
            (s_link.beacon_s == 0 || (now % s_link.beacon_s) < 60)) {
            last_tx_min = now / 60;
            link_tx_beacon(c);
        }
    }

    // Ciągły RX — 200 ms pollingu IRQ.
    uint32_t t0 = millis();
    while (millis() - t0 < 200) {
        if (s_irq) {
            s_irq = false;
            uint8_t b[256];
            int len = s_radio.getPacketLength();
            int st  = s_radio.readData(b, len > 255 ? 255 : len);
            if (st == RADIOLIB_ERR_NONE || st == RADIOLIB_ERR_CRC_MISMATCH)
                link_on_frame(b, len, st == RADIOLIB_ERR_CRC_MISMATCH, c.freq, c.sf, c.mode);
            s_radio.startReceive();
        }
        delay(2);
    }
    // Flush co pełną sekundę zerową minuty albo gdy bufor się zapełnia — batch, nie strumień.
    if (s_rx_n >= LORA_RX_BATCH_MAX / 2 || (sec_in_min == 0 && s_rx_n)) link_flush_rx();
}

// Plan w NVS (bez seeda) — zmiana decyzji RAM-only 2026-08-23: node bez internetu MUSI
// beaconować (wizja LoRa awaryjne), a plan żyjący tylko w RAM ginął z każdym resetem —
// node budził się głuchy i niemy na wkompilowanych kanałach EU (Rochester to obnażył).
// Seed ZOSTAJE tylko w RAM (stara decyzja bezpieczeństwa) — po restarcie beacon leci bez
// kodu (niepotwierdzalny, ale ŻYWY), kod wraca z planem przy pierwszym identify.
struct LoraPlanNvs {
    uint8_t    ver;                        // format (2 — od modelu v2 z polem role)
    uint8_t    on, beacon, slot;
    uint16_t   beacon_s;
    uint8_t    min_per_ch, n_ch, role;
    LoraLinkCh ch[LORA_LINK_MAX_CH];
};
static bool s_restoring = false;   // restore woła lora_link_set — nie zapisuj wtedy z powrotem

static void lora_plan_save() {
    LoraPlanNvs p{};
    p.ver = 2; p.on = s_link.on; p.beacon = s_link.beacon; p.slot = s_link.slot;
    p.beacon_s = s_link.beacon_s; p.min_per_ch = s_link.min_per_ch; p.n_ch = s_link.n_ch;
    p.role = s_link.role;
    for (uint8_t i = 0; i < s_link.n_ch; i++) p.ch[i] = s_link.ch[i];
    Preferences pr; pr.begin("sensmos_lora", false);
    pr.putBytes("plan", &p, sizeof(p));
    pr.end();
}

void lora_link_restore() {
    LoraPlanNvs p{};
    Preferences pr; pr.begin("sensmos_lora", true);
    size_t got = pr.getBytes("plan", &p, sizeof(p));
    pr.end();
    // Stary blob v1 ma inny rozmiar → got != sizeof(p) i odpada; świeży plan przyjdzie z BE.
    if (got != sizeof(p) || p.ver != 2 || !p.n_ch || p.n_ch > LORA_LINK_MAX_CH) return;
    s_restoring = true;
    lora_link_set(p.on, p.beacon, p.slot, p.beacon_s, p.min_per_ch, p.ch, p.n_ch, p.role);
    s_restoring = false;
    LOGI("lora", "plan przywrocony z NVS (offline-ready): beacon=%d, %u kanalow, rola=%u",
         p.beacon, p.n_ch, p.role);
}

// ── Zestaw awaryjny: NVS + API ───────────────────────────────────────────────
struct EmergNvs { uint8_t ver, n; char eids[LORA_EMERG_MAX][36]; };

static void emerg_save() {
    EmergNvs e{};
    e.ver = 1; e.n = s_emerg.n;
    memcpy(e.eids, s_emerg.eids, sizeof(e.eids));
    Preferences pr; pr.begin("sensmos_lora", false);
    pr.putBytes("emerg", &e, sizeof(e));
    pr.end();
}

static void emerg_load() {
    EmergNvs e{};
    Preferences pr; pr.begin("sensmos_lora", true);
    size_t got = pr.getBytes("emerg", &e, sizeof(e));
    String hook = pr.getString("cmdhook", "");
    bool   hget = pr.getBool("cmdhookg", false);
    size_t kg   = pr.getBytes("rxkey", s_rx_key, sizeof(s_rx_key));   // klucz ramek DATA
    pr.end();
    s_rx_key_ok = (kg == sizeof(s_rx_key));
    strlcpy(s_cmd_hook, hook.c_str(), sizeof(s_cmd_hook));
    s_cmd_hook_get = hget;
    if (got != sizeof(e) || e.ver != 1 || e.n > LORA_EMERG_MAX) return;
    s_emerg.n = e.n;
    memcpy(s_emerg.eids, e.eids, sizeof(s_emerg.eids));
    for (uint8_t i = 0; i < LORA_EMERG_MAX; i++) s_emerg.eids[i][35] = 0;
}

// Webhook dla komend CMD (model v2) — puste = wyłączony. use_get: GET ?cmd= zamiast
// POST JSON (proste systemy). Konfig razem z zestawem emergency (/node/lora_emerg), NVS.
void lora_cmd_hook_set(const char* url, bool use_get) {
    strlcpy(s_cmd_hook, url ? url : "", sizeof(s_cmd_hook));
    s_cmd_hook_get = use_get;
    Preferences pr; pr.begin("sensmos_lora", false);
    pr.putString("cmdhook", s_cmd_hook);
    pr.putBool("cmdhookg", s_cmd_hook_get);
    pr.end();
}

void lora_emerg_set(const char (*eids)[36], uint8_t n) {
    if (n > LORA_EMERG_MAX) n = LORA_EMERG_MAX;
    memset(s_emerg.eids, 0, sizeof(s_emerg.eids));
    for (uint8_t i = 0; i < n; i++) strlcpy(s_emerg.eids[i], eids[i], sizeof(s_emerg.eids[i]));
    s_emerg.n = n;
    emerg_save();
    s_emerg_report = true;                 // lora_pump zglosi przy zywym WS
    LOGI("lora", "zestaw awaryjny: %u encji", n);
}

bool lora_emerg_active() { return s_emerg_on; }

void lora_emerg_json(String& out) {
    out = "{\"eids\":[";
    for (uint8_t i = 0; i < s_emerg.n; i++) {
        if (i) out += ',';
        out += '"'; out += s_emerg.eids[i]; out += '"';
    }
    out += "],\"active\":";
    out += s_emerg_on ? "true" : "false";
    out += ",\"webhook\":\"";
    out += s_cmd_hook;                       // URL bez cudzysłowów/backslashy (walidacja w set)
    out += "\",\"webhook_get\":";
    out += s_cmd_hook_get ? "true}" : "false}";
}

// Downlink z BE (WS lora_tx): nadaj gotową surową ramkę binarną (model v2: CMD 0x03).
// Ramka już uwierzytelniona seedem ODBIORCY — tylko ją transmitujemy. Kolejka loop -> task;
// nadanie w link_tick (budżet DC). Bezpiecznik: magic 0xE0 + typ binarny (nie beacon "S").
bool lora_tx_raw_hex(const char* frame_hex) {
    if (!s_ok || !s_txQ || !frame_hex) return false;
    size_t nh = strlen(frame_hex);
    if ((nh & 1) || nh < 2 * SMOM_HDR_LEN || nh / 2 > SMOM_FRAME_MAX) return false;
    SmomTx tx; tx.len = (uint8_t)(nh / 2);
    if (!hex_to_bytes(frame_hex, nh, tx.frame)) return false;
    if (tx.frame[0] != SMOM_MAGIC0 || tx.frame[1] == 'S') return false;
    return xQueueSend(s_txQ, &tx, 0) == pdTRUE;
}

// Owner-seed per-owner z BE (klucz kodeka SMOM). Kolejność zapisu ustawia flagę na końcu,
// żeby czytelnik z core 0 nie trafił na pół-zaktualizowany seed jako „gotowy".
void lora_owner_seed_set(const uint8_t seed[32]) {
    s_owner_seed_ok = false;
    memcpy(s_owner_seed, seed, SMOM_KEY_LEN);
    Preferences pr; pr.begin("sensmos_lora", false);
    pr.putBytes("oseed", s_owner_seed, SMOM_KEY_LEN);
    pr.putBool("oseed_ok", true);
    pr.end();
    s_owner_seed_ok = true;
    LOGI("lora", "owner-seed przyjęty z BE");
}

void lora_link_set(bool on, bool beacon, uint8_t slot, uint16_t beacon_s,
                   uint8_t min_per_ch, const LoraLinkCh* chans, uint8_t n, uint8_t role) {
    s_link.beacon = beacon;
    s_link.slot = slot;
    s_link.beacon_s = beacon_s;
    s_link.role = role ? 1 : 0;
    s_link.min_per_ch = min_per_ch ? min_per_ch : LORA_LINK_MIN_PER_CH;
    if (chans && n) {
        s_link.n_ch = n > LORA_LINK_MAX_CH ? LORA_LINK_MAX_CH : n;
        for (uint8_t i = 0; i < s_link.n_ch; i++) s_link.ch[i] = chans[i];
    }
    // Seed kodu beaconu NIE jest ustawiany tutaj (0.92): liczy go lora_scan_init z ECDH
    // (ws_enc_beacon_seed) — deterministyczny z klucza tożsamości, przeżywa restart.
    s_link.on = on;
    s_cur_ch = -1;                                            // wymuś retune przy najbliższym tick
    if (!s_restoring) lora_plan_save();                       // plan z BE → NVS (przeżywa reset)
    LOGI("lora", "link %s: rola=%s beacon=%d slot=%u every=%us, %u channels, %u min/ch, seed=%d",
         on ? "ON" : "off", s_link.role ? "PUNKT" : "skaner", beacon ? 1 : 0, slot, beacon_s,
         s_link.n_ch, s_link.min_per_ch, s_link.has_seed ? 1 : 0);
}

bool lora_link_on() { return s_link.on; }

void lora_link_status_json(String& out) {
    char b[360];
    uint32_t now = ws_epoch_now();
    snprintf(b, sizeof(b),
        "{\"on\":%s,\"beacon\":%s,\"role\":%u,\"slot\":%u,\"ch\":%d,\"n_ch\":%u,\"tx_seq\":%lu,"
        "\"rx_total\":%lu,\"rx_dropped\":%lu,\"duty_ms_h\":%lu,\"epoch\":%lu,"
        "\"txq\":%u,\"dr_seen\":%lu,\"dr_nobud\":%lu,\"dr_cad\":%lu,\"dr_ok\":%lu,"
        "\"dr_fail\":%lu,\"tx_st\":%d,\"rxkey\":%s}",
        s_link.on ? "true" : "false", s_link.beacon ? "true" : "false", s_link.role, s_link.slot,
        s_cur_ch, s_link.n_ch, (unsigned long)s_tx_seq, (unsigned long)s_rx_total,
        (unsigned long)s_rx_dropped, (unsigned long)s_duty_ms, (unsigned long)now,
        s_txQ ? (unsigned)uxQueueMessagesWaiting(s_txQ) : 0,
        (unsigned long)s_dr_seen, (unsigned long)s_dr_nobud, (unsigned long)s_dr_cad,
        (unsigned long)s_dr_ok, (unsigned long)s_dr_fail, s_tx_last_st,
        s_rx_key_ok ? "true" : "false");
    out = b;
}

// ── Task ──────────────────────────────────────────────────────
static void lora_task(void*) {
    uint32_t next_bg = millis() + 10000;   // pierwszy cykl po 10s, żeby nie wchodzić w boot
    for (;;) {
        LReq r;
        if (xQueueReceive(s_q, &r, pdMS_TO_TICKS(s_link.on ? 0 : 200)) == pdTRUE) {
            s_busy = true;
            // Oproznij bufor PRZED zleceniem. Skan pasma potrafi trwac minuty, a BE liczy
            // okno kodu beaconu od SWOJEGO zegara — ramka, ktora przeczeka tu caly skan,
            // dociera z kodem sprzed kilku minut i zostaje uznana za probe podszycia.
            // Uczciwy odczyt nie moze wygladac na atak tylko dlatego, ze akurat trwal sweep.
            link_flush_rx();
            switch (r.job) {
                case LJ_SWEEP:  do_sweep(r);  break;
                case LJ_CAMP:   do_camp(r);   break;
                case LJ_LISTEN: do_listen(r); break;
                case LJ_HUNT:   do_hunt(r);   break;
                case LJ_CAD:    do_cad(r);    break;
            }
            s_busy = false;
            s_cur_ch = -1;                                    // ręczny skan rozstroił radio
            next_bg = millis() + LORA_BG_PERIOD_S * 1000UL;   // nie wchodź w tło zaraz po ręcznym skanie
            continue;
        }
        // Tryb link ma pierwszeństwo nad cyklem tła — to on trzyma radio w ciągłym RX.
        if (s_link.on) { link_tick(); continue; }
        if (s_bg && (int32_t)(millis() - next_bg) >= 0) {
            s_busy = true;
            bg_cycle();
            s_busy = false;
            next_bg = millis() + LORA_BG_PERIOD_S * 1000UL;
        }
    }
}

static bool enqueue(const LReq& r) {
    if (!s_ok || !s_q) return false;
    if (s_busy) return false;
    return xQueueSend(s_q, &r, 0) == pdTRUE;
}

// ── API ───────────────────────────────────────────────────────
// Próba JEDNEGO pinoutu. Zwraca true, gdy SX1262 odpowiedział — RadioLib daje
// RADIOLIB_ERR_CHIP_NOT_FOUND, gdy odczyt rejestru nie wraca, więc to pytanie do krzemu,
// a nie wnioskowanie z czasu. Nic nie nadajemy, sonda jest wyłącznie odczytem.
static bool try_pinout(const LoraPinout& p) {
    SPI.end();
    SPI.begin(p.sck, p.miso, p.mosi, p.nss);

    // Instancje na stercie, bo pinów w Module nie da się zmienić po konstrukcji.
    // Przegrane kandydatury zwalniamy od razu — zostaje tylko zwycięzca.
    Module* mod = new Module(p.nss, p.dio1, p.rst, p.busy);
    SX1262* rad = new SX1262(mod);
    if (p.rxen >= 0) rad->setRfSwitchPins(p.rxen, RADIOLIB_NC);

    int st = rad->begin(LORA_BG_FREQ, LORA_BG_BW, LORA_BG_SF, LORA_BG_CR,
                        LORA_BG_SYNC, 10, 8, p.tcxo, false);
    if (st != RADIOLIB_ERR_NONE) {
        LOGD("lora", "  %-14s nie odpowiada (begin = %d)", p.name, st);
        delete rad; delete mod;
        return false;
    }
    g_radio = rad; g_pin = &p;
    return true;
}

void lora_scan_init() {
    // Sondowanie: jeden bin obsługuje każdą płytkę z tablicy. LORA_PIN_FORCE pomija próby
    // i wymusza konkretny wpis — furtka na wypadek płytki, która źle znosi cudze piny.
    bool found = false;
    if (LORA_PIN_FORCE >= 0 && LORA_PIN_FORCE < N_PINOUTS) {
        found = try_pinout(PINOUTS[LORA_PIN_FORCE]);
        LOGI("lora", "pinout wymuszony: %s -> %s", PINOUTS[LORA_PIN_FORCE].name,
             found ? "OK" : "BRAK ODPOWIEDZI");
    } else {
        LOGI("lora", "szukam SX1262 (%d pinoutow)...", N_PINOUTS);
        for (int i = 0; i < N_PINOUTS && !found; i++) found = try_pinout(PINOUTS[i]);
    }

    if (!found) {
        // Brak radia to normalny przypadek — ten sam bin chodzi na sprzęcie bez SX1262.
        // Node ma działać dalej jak zwykle, tylko bez LoRa.
        LOGW("lora", "nie znaleziono SX1262 na zadnym ze znanych pinoutow - plytka bez radia?");
        return;
    }
    LOGI("lora", "SX1262 znaleziony: plytka %s (nss%d dio%d rst%d busy%d, tcxo %.1fV)",
         g_pin->name, g_pin->nss, g_pin->dio1, g_pin->rst, g_pin->busy, g_pin->tcxo);

    after_begin();
    s_ok = true;

    s_q     = xQueueCreate(2, sizeof(LReq));
    s_outQ  = xQueueCreate(LORA_OUT_SLOTS, sizeof(char*));
    s_freeQ = xQueueCreate(LORA_OUT_SLOTS, sizeof(char*));
    for (int i = 0; i < LORA_OUT_SLOTS; i++) {          // na starcie wszystkie sloty wolne
        char* p = s_out[i];
        xQueueSend(s_freeQ, &p, 0);
    }
    // TX na zlecenie BE (lora_tx): kolejka surowych ramek loop -> task radiowy.
    s_txQ  = xQueueCreate(LORA_MSG_TXQ_DEPTH, sizeof(SmomTx));
    // CMD 0x03: odebrane-dla-mnie komendy task -> loop (dispatch inbox/MQTT/akcje).
    s_cmdQ = xQueueCreate(2, sizeof(CmdRx));
    // DATA 0x02: przyjęte-dla-mnie ramki task/loop -> loop (inbox frames + MQTT).
    s_dataQ = xQueueCreate(2, sizeof(DataRx));
    xTaskCreatePinnedToCore(lora_task, "lora", 6144, nullptr, 1, &s_task, 0);
    LOGI("lora", "radio up (RX only) - bg scan %s, period %ds",
         s_bg ? "on" : "off", LORA_BG_PERIOD_S);

    // Seed kodu beaconu z ECDH (0.92): liczony lokalnie z klucza tożsamości — przeżywa
    // restart (scenariusz "burza wywala prąd i internet naraz"), niczego nie przesyłamy.
    if (ws_enc_beacon_seed(s_link.seed)) s_link.has_seed = true;
    else LOGW("lora", "beacon seed derive failed — beacony bez kodu");

    // Ostatni plan z BE (NVS) — node beaconuje/słucha regionalnie OD RAZU, także bez
    // internetu. Node fabrycznie świeży (zero kontaktu z BE) zostaje w RX-only: nadawanie
    // na wkompilowanych kanałach EU byłoby nielegalne poza Europą — region musi nadać BE.
    lora_link_restore();
    emerg_load();

    // Skrót własnego id (dst = 3 B; CMD „czy do mnie" — Krok 3) + odtworzenie seeda z NVS.
    // Brak owner-seeda (świeży node) = graceful: czeka na lora_msg_seed z BE.
    if (!hex_to_bytes(g_device_id, 2 * SMOM_ID_LEN, s_self_id3))
        LOGW("lora", "device_id nie-hex? — SMOM dst moze byc zly");
    hex_to_bytes(g_device_id, 8, s_self_id4);   // dst ramek DATA (id8 — pełny skrót z apki)
    smom_state_load();
}

bool lora_available() { return s_ok; }
// Nazwa WYKRYTEJ plytki (nie zbudowanej) — idzie w identify jako devices.board.
const char* lora_board_name() { return s_ok ? g_pin->name : nullptr; }
bool lora_busy()      { return s_busy; }

bool lora_sweep(float from, float to, float step) {
    LReq r = {}; r.job = LJ_SWEEP; r.f0 = from; r.f1 = to; r.step = step;
    return enqueue(r);
}
bool lora_camp(float freq, uint16_t secs) {
    LReq r = {}; r.job = LJ_CAMP; r.f0 = freq; r.secs = secs;
    return enqueue(r);
}
bool lora_listen(float freq, float bw, uint8_t sf, uint8_t cr, uint8_t sync, uint16_t secs) {
    LReq r = {}; r.job = LJ_LISTEN; r.f0 = freq; r.bw = bw; r.sf = sf; r.cr = cr;
    r.sync = sync; r.secs = secs;
    return enqueue(r);
}
bool lora_cad(float freq, float bw, uint8_t sf, uint16_t secs) {
    LReq r = {}; r.job = LJ_CAD; r.f0 = freq; r.bw = bw; r.sf = sf; r.cr = 5; r.secs = secs;
    return enqueue(r);
}
bool lora_hunt(float freq, float bw, uint8_t sf, uint8_t cr, uint16_t dwell_ms) {
    LReq r = {}; r.job = LJ_HUNT; r.f0 = freq; r.bw = bw; r.sf = sf; r.cr = cr;
    r.dwell_ms = dwell_ms;
    return enqueue(r);
}

void lora_bg_set(bool on) { s_bg = on; LOGI("lora", "bg scan %s", on ? "on" : "off"); }
bool lora_bg_get()        { return s_bg; }

void lora_status() {
    LOGI("lora", "radio=%s busy=%d bg=%d board=%s pins nss%d dio%d rst%d busy%d tcxo%.1f",
         s_ok ? "up" : "down", s_busy ? 1 : 0, s_bg ? 1 : 0, s_ok ? g_pin->name : "?",
         g_pin->nss, g_pin->dio1, g_pin->rst, g_pin->busy, g_pin->tcxo);
}
#endif
