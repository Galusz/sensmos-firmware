#include "lora_scan.h"
#if LORA_ENABLED

#include <RadioLib.h>
#include <SPI.h>
#include "entity_store.h"
#include "log.h"
#include "ws_client.h"
#include "ws_enc.h"        // ws_enc_beacon_seed — seed kodu beaconu z ECDH (0.92)
#include "identity.h"
#include <Preferences.h>   // plan LoRa w NVS (offline-ready beacon, decyzja 2026-08-23)
#include <mbedtls/md.h>
#include <WiFi.h>          // detekcja padu uplinku dla trybu awaryjnego (0.91)

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

// Odebrana ramka → bufor. Nasze beacony rozpoznajemy TU (BE nie ma zgadywać):
// 0xE0 + "SMOS <id8> <seq>".
static void link_on_frame(const uint8_t* data, int len, bool crc_err, float freq, uint8_t sf, uint8_t mode) {
    uint32_t now = ws_epoch_now();
    uint32_t min = now / 60;
    if (min != s_rx_min) { s_rx_min = min; s_rx_in_min = 0; }
    s_rx_total++;
    if (++s_rx_in_min > LORA_RX_CAP_PER_MIN) { s_rx_dropped++; return; }
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
static void beacon_code(char out[9], uint32_t minute, const char* vals = nullptr) {
    out[0] = 0;
    const mbedtls_md_info_t* mi = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!mi) return;
    char msg[64];
    if (vals && vals[0])
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
    // 96 B miesci najdluzsza ramke (~86 B); stare FW sasiadow przekazuje do 128 B payloadu.
    char pl[96], code[9] = {0}, vals[40] = {0};
    const bool emerg = s_emerg_on;                      // snapshot: spojny kod i ogon
    if (emerg) emerg_vals(vals, sizeof(vals));
    if (s_link.has_seed) beacon_code(code, now / 60, (emerg && vals[0]) ? vals : nullptr);
    const bool tail = emerg && vals[0] && code[0];
    int n = snprintf(pl + 1, sizeof(pl) - 1, "%s%.8s %lu %d %d %d%s%s%s%s",
                     LORA_BEACON_PREFIX, g_device_id, (unsigned long)s_tx_seq,
                     (int)s_last.bg_noise, (int)s_last.bg_peak, LORA_LINK_TX_POWER,
                     code[0] ? " " : "", code,
                     tail ? " E1 " : "", tail ? vals : "");
    if (n < 0) return 0;
    if (n > (int)sizeof(pl) - 1) n = (int)sizeof(pl) - 1;   // snprintf zwraca dlugosc SPRZED obciecia
    pl[0] = (char)LORA_BEACON_MAGIC;

    // Airtime z RZECZYWISTEJ dlugosci ramki. Stale 44 B przestaly byc prawda, gdy doszedl
    // kod (do 47 B), a zanizony szacunek okrada licznik duty cycle z tego, po co istnieje.
    uint32_t est = lora_airtime_ms(c.sf, c.bw, c.cr, (uint8_t)(n + 1));
    if (s_duty_ms + est > LORA_LINK_DUTY_MS_H) {
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
    LOGI("lora", "beacon #%lu sent @%.3f SF%u (%lums air, duty %lums/h)",
         (unsigned long)s_tx_seq - 1, c.freq, c.sf, (unsigned long)air, (unsigned long)s_duty_ms);
    return air;
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

    const uint8_t idx = (uint8_t)((now / 60 / s_link.min_per_ch) % s_link.n_ch);
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

    // Zmiana kanału: TYLKO w oknie guard (nikt wtedy nie nadaje), przy okazji sweep otoczenia.
    if ((int)idx != s_cur_ch) {
        if (sec_in_min > LORA_LINK_GUARD_S && sec_in_min < 60 - LORA_LINK_GUARD_S && s_cur_ch >= 0) {
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

    // Slot nadawania: sekunda 10 + k*7 w każdej minucie. Trafiamy w nią raz — seq rośnie,
    // więc podwójne wejście w tę samą sekundę wykluczamy znacznikiem ostatniej minuty.
    static uint32_t last_tx_min = 0;
    const uint32_t my_sec = LORA_LINK_SLOT0_S + (uint32_t)s_link.slot * LORA_LINK_SLOT_GAP_S;
    if (s_link.beacon && sec_in_min == my_sec && (now / 60) != last_tx_min &&
        (s_link.beacon_s == 0 || (now % s_link.beacon_s) < 60) &&
        // Tryb E: ramka jest ~2x dluzsza, wiec nadajemy co N minut — duty cycle zostaje
        // z duzym zapasem, a przy awarii i tak liczy sie "uslyszany", nie kadencja.
        (!s_emerg_on || ((now / 60) % LORA_EMERG_EVERY_MIN) == 0)) {
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
    uint8_t    ver;                        // format (1)
    uint8_t    on, beacon, slot;
    uint16_t   beacon_s;
    uint8_t    min_per_ch, n_ch;
    LoraLinkCh ch[LORA_LINK_MAX_CH];
};
static bool s_restoring = false;   // restore woła lora_link_set — nie zapisuj wtedy z powrotem

static void lora_plan_save() {
    LoraPlanNvs p{};
    p.ver = 1; p.on = s_link.on; p.beacon = s_link.beacon; p.slot = s_link.slot;
    p.beacon_s = s_link.beacon_s; p.min_per_ch = s_link.min_per_ch; p.n_ch = s_link.n_ch;
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
    if (got != sizeof(p) || p.ver != 1 || !p.n_ch || p.n_ch > LORA_LINK_MAX_CH) return;
    s_restoring = true;
    lora_link_set(p.on, p.beacon, p.slot, p.beacon_s, p.min_per_ch, p.ch, p.n_ch);
    s_restoring = false;
    LOGI("lora", "plan przywrocony z NVS (offline-ready): beacon=%d, %u kanalow", p.beacon, p.n_ch);
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
    pr.end();
    if (got != sizeof(e) || e.ver != 1 || e.n > LORA_EMERG_MAX) return;
    s_emerg.n = e.n;
    memcpy(s_emerg.eids, e.eids, sizeof(s_emerg.eids));
    for (uint8_t i = 0; i < LORA_EMERG_MAX; i++) s_emerg.eids[i][35] = 0;
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
    out += s_emerg_on ? "true}" : "false}";
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
    // Seed kodu beaconu NIE jest ustawiany tutaj (0.92): liczy go lora_scan_init z ECDH
    // (ws_enc_beacon_seed) — deterministyczny z klucza tożsamości, przeżywa restart.
    s_link.on = on;
    s_cur_ch = -1;                                            // wymuś retune przy najbliższym tick
    if (!s_restoring) lora_plan_save();                       // plan z BE → NVS (przeżywa reset)
    LOGI("lora", "link %s: beacon=%d slot=%u every=%us, %u channels, %u min/ch, seed=%d",
         on ? "ON" : "off", beacon ? 1 : 0, slot, beacon_s, s_link.n_ch, s_link.min_per_ch,
         s_link.has_seed ? 1 : 0);
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
