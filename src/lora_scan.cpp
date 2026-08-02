#include "lora_scan.h"
#if LORA_ENABLED

#include <RadioLib.h>
#include <SPI.h>
#include "entity_store.h"
#include "log.h"
#include "ws_client.h"
#include "identity.h"

static SX1262       s_radio = new Module(LORA_NSS, LORA_DIO1, LORA_RST, LORA_BUSY);
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
    float    bg_noise;
    int16_t  bg_busy, bg_cad, bg_cad_total, bg_frames;
};
static LoraLast s_last = {};

// ── Pomocnicze ────────────────────────────────────────────────

// Przestrojenie + rozgrzewka. Pierwsze odczyty RSSI po zmianie częstotliwości są śmieciowe
// (PLL i AGC się ustawiają) — bez tego pierwszy kanał przemiatania zawsze wychodził „aktywny".
static bool tune(float freq) {
    if (s_radio.setFrequency(freq) != RADIOLIB_ERR_NONE) return false;
    s_radio.startReceive();
    delay(8);
    for (int i = 0; i < 8; i++) { s_radio.getRSSI(false); delayMicroseconds(500); }
    return true;
}

// begin() resetuje konfigurację modułu, więc przełącznik anteny i handler IRQ trzeba
// ustawiać PO każdym begin(), a nie raz w init.
static void after_begin() {
#ifdef LORA_RXEN
    s_radio.setRfSwitchPins(LORA_RXEN, RADIOLIB_NC);
#endif
    s_radio.setDio1Action(on_dio1);
}

static bool cfg(float freq, float bw, uint8_t sf, uint8_t cr, uint8_t sync) {
    int st = s_radio.begin(freq, bw, sf, cr, sync, 10, 8, LORA_TCXO, false);
    if (st != RADIOLIB_ERR_NONE) { LOGW("lora", "begin() = %d", st); return false; }
    after_begin();
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

// ── Zlecenia ──────────────────────────────────────────────────

static void do_sweep(const LReq& r) {
    LOGI("lora", "sweep %.3f-%.3f MHz step %.3f", r.f0, r.f1, r.step);
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

    // own.* a nie mon.* — mon jest zamknięte listą natywnych z BE, a tych encji BE
    // jeszcze nie zna. Przy przejściu na produkcję: dopisać natywne i zmienić prefix.
    push_num("own.lora_noise", noise, "dBm");
    push_num("own.lora_busy",  busy,  "");
    push_num("own.lora_cad",   cad_total ? (100.0f * cad / cad_total) : 0, "%");
    push_num("own.lora_pkt",   frames > 0 ? frames : 0, "");
    if (frames > 0) push_num("own.lora_rssi", best, "dBm");

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
    out += "]}";
}

// ══ TRYB LINK ═════════════════════════════════════════════════
// Zasada: nasłuch jest stanem spoczynkowym. Radio wychodzi z RX tylko na własne ~200 ms
// nadania i na przestrojenie kanału. Kanał liczy się z zegara UTC, więc wszystkie nody
// są na tej samej częstotliwości bez wymiany jakiejkolwiek wiadomości.
static struct {
    volatile bool on, beacon;
    uint8_t  slot, min_per_ch, n_ch;
    uint16_t beacon_s;
    LoraLinkCh ch[LORA_LINK_MAX_CH];
} s_link = {};

static int      s_cur_ch   = -1;         // indeks kanału, na którym stoi radio
static uint32_t s_duty_ms  = 0;          // airtime w bieżącym oknie godzinowym
static uint32_t s_duty_h   = 0;          // numer okna (epoch/3600)
static uint32_t s_tx_seq   = 0;
static uint32_t s_rx_total = 0, s_rx_dropped = 0;
static uint32_t s_rx_min   = 0, s_rx_in_min = 0;   // licznik cap/min

// Bufor ramek do wysłania w batchu. Statyczny — żadnych String w ścieżce RX.
struct RxFrame {
    uint32_t ts;
    float    freq, rssi, snr;
    uint8_t  sf, len, hexlen;
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

    static char buf[1600];
    int p = snprintf(buf, sizeof(buf), "{\"type\":\"lora_rx\",\"frames\":[");
    for (uint8_t i = 0; i < s_rx_n && p < (int)sizeof(buf) - 220; i++) {
        const RxFrame& f = s_rx[i];
        p += snprintf(buf + p, sizeof(buf) - p,
            "%s{\"ts\":%lu,\"freq\":%.3f,\"sf\":%u,\"rssi\":%.0f,\"snr\":%.1f,\"len\":%u,\"crc\":%s",
            i ? "," : "", (unsigned long)f.ts, f.freq, f.sf, f.rssi, f.snr, f.len,
            f.crc_err ? "false" : "true");
        if (f.smos[0]) p += snprintf(buf + p, sizeof(buf) - p, ",\"smos\":\"%s\"", f.smos);
        p += snprintf(buf + p, sizeof(buf) - p, ",\"hex\":\"");
        for (uint8_t b = 0; b < f.hexlen && p < (int)sizeof(buf) - 8; b++)
            p += snprintf(buf + p, sizeof(buf) - p, "%02x", f.raw[b]);
        p += snprintf(buf + p, sizeof(buf) - p, "\"}");
    }
    snprintf(buf + p, sizeof(buf) - p, "]}");
    ws_client_send_raw(buf);
    s_rx_n = 0;
}

// Odebrana ramka → bufor. Nasze beacony rozpoznajemy TU (BE nie ma zgadywać):
// 0xE0 + "SMOS <id8> <seq>".
static void link_on_frame(const uint8_t* data, int len, bool crc_err, float freq, uint8_t sf) {
    uint32_t now = ws_epoch_now();
    uint32_t min = now / 60;
    if (min != s_rx_min) { s_rx_min = min; s_rx_in_min = 0; }
    s_rx_total++;
    if (++s_rx_in_min > LORA_RX_CAP_PER_MIN) { s_rx_dropped++; return; }
    if (s_rx_n >= LORA_RX_BATCH_MAX) link_flush_rx();
    if (s_rx_n >= LORA_RX_BATCH_MAX) return;

    RxFrame& f = s_rx[s_rx_n++];
    f.ts = now; f.freq = freq; f.sf = sf; f.crc_err = crc_err;
    f.rssi = s_radio.getRSSI(); f.snr = s_radio.getSNR();
    f.len = len > 255 ? 255 : len;
    f.hexlen = len > LORA_RX_HEX_MAX ? LORA_RX_HEX_MAX : (uint8_t)len;
    memcpy(f.raw, data, f.hexlen);
    f.smos[0] = 0;
    const int PFX = 1 + 5;                                  // 0xE0 + "SMOS "
    if (!crc_err && len >= PFX + 8 && data[0] == LORA_BEACON_MAGIC &&
        memcmp(data + 1, LORA_BEACON_PREFIX, 5) == 0) {
        memcpy(f.smos, data + PFX, 8); f.smos[8] = 0;
        // Własny beacon nigdy nie jest krawędzią „kto kogo słyszy" (echo z bufora TX,
        // w przyszłości repeater) — zostaje w ramce jako ślad, ale bez identyfikacji nadawcy.
        if (memcmp(f.smos, g_device_id, 8) == 0) f.smos[0] = 0;
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

// Nadanie beaconu. Zwraca airtime w ms (0 = nie nadano).
static uint32_t link_tx_beacon(const LoraLinkCh& c) {
    uint32_t h = ws_epoch_now() / 3600;
    if (h != s_duty_h) { s_duty_h = h; s_duty_ms = 0; }
    uint32_t est = lora_airtime_ms(c.sf, c.bw, c.cr, 24);
    if (s_duty_ms + est > LORA_LINK_DUTY_MS_H) {
        LOGW("lora", "beacon skipped — duty cycle budget spent (%lums/h)", (unsigned long)s_duty_ms);
        return 0;
    }
    char pl[40];
    int n = snprintf(pl + 1, sizeof(pl) - 1, "%s%.8s %lu",
                     LORA_BEACON_PREFIX, g_device_id, (unsigned long)s_tx_seq);
    pl[0] = (char)LORA_BEACON_MAGIC;
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
    LOGI("lora", "beacon #%lu sent @%.3f SF%u (%lums air, duty %lums/h)",
         (unsigned long)s_tx_seq - 1, c.freq, c.sf, (unsigned long)air, (unsigned long)s_duty_ms);
    return air;
}

// Jeden przebieg pętli link (~200 ms). Wszystko sterowane zegarem UTC — bez stanu między iteracjami.
static void link_tick() {
    uint32_t now = ws_epoch_now();
    if (!now || !s_link.n_ch) { delay(200); return; }

    const uint8_t idx = (uint8_t)((now / 60 / s_link.min_per_ch) % s_link.n_ch);
    const LoraLinkCh& c = s_link.ch[idx];
    const uint32_t sec_in_min = now % 60;

    // Zmiana kanału: TYLKO w oknie guard (nikt wtedy nie nadaje), przy okazji sweep otoczenia.
    if ((int)idx != s_cur_ch) {
        if (sec_in_min > LORA_LINK_GUARD_S && sec_in_min < 60 - LORA_LINK_GUARD_S && s_cur_ch >= 0) {
            delay(200); return;                              // czekamy na guard — nie gubimy ramek w środku minuty
        }
        link_flush_rx();
        LOGI("lora", "link: channel -> %.3f MHz SF%u BW%.0f sync 0x%02X (slot %u)",
             c.freq, c.sf, c.bw, c.sync, s_link.slot);
        if (!cfg(c.freq, c.bw, c.sf, c.cr, c.sync)) { delay(1000); return; }
        float mn, mx; channel_rssi(&mn, &mx);                // szybki sweep = puls kanału
        s_last.bg_noise = mn;
        s_irq = false;
        s_radio.startReceive();
        s_cur_ch = idx;
        return;
    }

    // Slot nadawania: sekunda 10 + k*7 w każdej minucie. Trafiamy w nią raz — seq rośnie,
    // więc podwójne wejście w tę samą sekundę wykluczamy znacznikiem ostatniej minuty.
    static uint32_t last_tx_min = 0;
    const uint32_t my_sec = LORA_LINK_SLOT0_S + (uint32_t)s_link.slot * LORA_LINK_SLOT_GAP_S;
    if (s_link.beacon && sec_in_min == my_sec && (now / 60) != last_tx_min &&
        (s_link.beacon_s == 0 || (now % s_link.beacon_s) < 60)) {
        last_tx_min = now / 60;
        link_tx_beacon(c);
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
                link_on_frame(b, len, st == RADIOLIB_ERR_CRC_MISMATCH, c.freq, c.sf);
            s_radio.startReceive();
        }
        delay(2);
    }
    // Flush co pełną sekundę zerową minuty albo gdy bufor się zapełnia — batch, nie strumień.
    if (s_rx_n >= LORA_RX_BATCH_MAX / 2 || (sec_in_min == 0 && s_rx_n)) link_flush_rx();
}

void lora_link_set(bool on, bool beacon, uint8_t slot, uint16_t beacon_s,
                   uint8_t min_per_ch, const LoraLinkCh* chans, uint8_t n) {
    s_link.beacon = beacon;
    s_link.slot = slot;
    s_link.beacon_s = beacon_s;
    s_link.min_per_ch = min_per_ch ? min_per_ch : LORA_LINK_MIN_PER_CH;
    if (chans && n) {
        s_link.n_ch = n > LORA_LINK_MAX_CH ? LORA_LINK_MAX_CH : n;
        for (uint8_t i = 0; i < s_link.n_ch; i++) s_link.ch[i] = chans[i];
    }
    s_link.on = on;
    s_cur_ch = -1;                                            // wymuś retune przy najbliższym tick
    LOGI("lora", "link %s: beacon=%d slot=%u every=%us, %u channels, %u min/ch",
         on ? "ON" : "off", beacon ? 1 : 0, slot, beacon_s, s_link.n_ch, s_link.min_per_ch);
}

bool lora_link_on() { return s_link.on; }

void lora_link_status_json(String& out) {
    char b[220];
    uint32_t now = ws_epoch_now();
    snprintf(b, sizeof(b),
        "{\"on\":%s,\"beacon\":%s,\"slot\":%u,\"ch\":%d,\"n_ch\":%u,\"tx_seq\":%lu,"
        "\"rx_total\":%lu,\"rx_dropped\":%lu,\"duty_ms_h\":%lu,\"epoch\":%lu}",
        s_link.on ? "true" : "false", s_link.beacon ? "true" : "false", s_link.slot,
        s_cur_ch, s_link.n_ch, (unsigned long)s_tx_seq, (unsigned long)s_rx_total,
        (unsigned long)s_rx_dropped, (unsigned long)s_duty_ms, (unsigned long)now);
    out = b;
}

// ── Task ──────────────────────────────────────────────────────
static void lora_task(void*) {
    uint32_t next_bg = millis() + 10000;   // pierwszy cykl po 10s, żeby nie wchodzić w boot
    for (;;) {
        LReq r;
        if (xQueueReceive(s_q, &r, pdMS_TO_TICKS(s_link.on ? 0 : 200)) == pdTRUE) {
            s_busy = true;
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
void lora_scan_init() {
    SPI.begin(LORA_SCK, LORA_MISO, LORA_MOSI, LORA_NSS);
    int st = s_radio.begin(LORA_BG_FREQ, LORA_BG_BW, LORA_BG_SF, LORA_BG_CR,
                           LORA_BG_SYNC, 10, 8, LORA_TCXO, false);
    if (st != RADIOLIB_ERR_NONE) {
        // Brak radia na płytce to normalny przypadek (ten sam bin na sprzęcie bez SX1262) —
        // node ma działać dalej jak zwykle, bez LoRa.
        LOGW("lora", "radio not available (begin = %d) - check pins/TCXO or board has no SX1262", st);
        return;
    }
    after_begin();
    s_ok = true;

    s_q = xQueueCreate(2, sizeof(LReq));
    xTaskCreatePinnedToCore(lora_task, "lora", 6144, nullptr, 1, &s_task, 0);
    LOGI("lora", "radio up (RX only) - bg scan %s, period %ds",
         s_bg ? "on" : "off", LORA_BG_PERIOD_S);
}

bool lora_available() { return s_ok; }
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
    LOGI("lora", "radio=%s busy=%d bg=%d board=%d pins nss%d dio%d rst%d busy%d",
         s_ok ? "up" : "down", s_busy ? 1 : 0, s_bg ? 1 : 0, LORA_BOARD,
         LORA_NSS, LORA_DIO1, LORA_RST, LORA_BUSY);
}
#endif
