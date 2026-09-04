#include "pairing.h"
#include "log.h"
#include <Preferences.h>
#include <mbedtls/md.h>
#include <mbedtls/sha256.h>
#include <string.h>

// Cały zestaw kluczy w JEDNYM wpisie NVS — prościej niż pair0..pair3 osobno i nie da się
// zostawić sieroty po częściowym zapisie.
#define NVS_BLOB "pairv1"

struct PairStore {
    uint8_t n;                                   // ile kluczy zajętych (0..PAIR_MAX_KEYS)
    uint8_t key[PAIR_MAX_KEYS][PAIR_KEY_LEN];
};

static PairStore s_st = {0, {{0}}};

static void store_save() {
    Preferences p; p.begin("sensmos", false);
    p.putBytes(NVS_BLOB, &s_st, sizeof(s_st));
    p.end();
}

void pairing_init() {
    Preferences p; p.begin("sensmos", true);
    size_t got = p.getBytesLength(NVS_BLOB);
    if (got == sizeof(s_st)) p.getBytes(NVS_BLOB, &s_st, sizeof(s_st));
    p.end();
    if (s_st.n > PAIR_MAX_KEYS) s_st.n = 0;      // NVS z innej wersji / śmieci — traktuj jak brak
    LOGI("pair", "%u klucz(y) parowania", (unsigned)s_st.n);
}

int  pairing_count()   { return s_st.n; }
bool pairing_has_key() { return s_st.n > 0; }

// Stałoczasowe porównanie — bez wczesnego wyjścia, żeby czas odpowiedzi nie zdradzał,
// ile bajtów dowodu się zgadza.
static bool ct_eq(const uint8_t* a, const uint8_t* b, size_t n) {
    uint8_t diff = 0;
    for (size_t i = 0; i < n; i++) diff |= (uint8_t)(a[i] ^ b[i]);
    return diff == 0;
}

bool pairing_add(const uint8_t key[PAIR_KEY_LEN]) {
    if (!key) return false;
    // Klucz z samych zer = prawie na pewno błąd po stronie apki, nie losowy sekret.
    bool all_zero = true;
    for (int i = 0; i < PAIR_KEY_LEN; i++) if (key[i]) { all_zero = false; break; }
    if (all_zero) { LOGW("pair", "odrzucony klucz z samych zer"); return false; }

    for (int i = 0; i < s_st.n; i++)
        if (ct_eq(s_st.key[i], key, PAIR_KEY_LEN)) return true;   // już mamy — idempotentne

    if (s_st.n >= PAIR_MAX_KEYS) {
        // FIFO: najstarszy wypada. Bez tego trzeci/czwarty telefon w domu wymagałby
        // ręcznego czyszczenia, a użytkownik nie ma jak zgadnąć, że o to chodzi.
        memmove(s_st.key[0], s_st.key[1], (PAIR_MAX_KEYS - 1) * PAIR_KEY_LEN);
        s_st.n = PAIR_MAX_KEYS - 1;
        LOGI("pair", "limit %d — najstarszy klucz usunięty", PAIR_MAX_KEYS);
    }
    memcpy(s_st.key[s_st.n], key, PAIR_KEY_LEN);
    s_st.n++;
    store_save();
    LOGI("pair", "klucz dodany (%u/%d)", (unsigned)s_st.n, PAIR_MAX_KEYS);
    return true;
}

void pairing_clear() {
    memset(&s_st, 0, sizeof(s_st));
    store_save();
    LOGI("pair", "klucze skasowane — zdalny dostęp wyłączony");
}

int pairing_verify_idx(const char* msg, const uint8_t proof[32]) {
    if (!msg || !proof || s_st.n == 0) return -1;
    const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!info) return -1;

    // Sprawdzamy WSZYSTKIE klucze bez przerywania po trafieniu — inaczej czas odpowiedzi
    // mówiłby, ILE kluczy ma node i który z nich pasuje. Indeks zapisujemy bez gałęzi
    // (maska), żeby nie wprowadzić z powrotem różnicy czasowej, którą właśnie wycinamy.
    int found = -1;
    for (int i = 0; i < s_st.n; i++) {
        uint8_t mac[32];
        if (mbedtls_md_hmac(info, s_st.key[i], PAIR_KEY_LEN,
                            (const uint8_t*)msg, strlen(msg), mac) != 0) continue;
        int hit = ct_eq(mac, proof, 32) ? 1 : 0;
        found = (found & ~(-hit)) | (i & (-hit));
    }
    return found;
}

bool pairing_tun_key(int idx, uint8_t out[32]) {
    if (!out || idx < 0 || idx >= s_st.n) return false;
    // SHA256(klucz ‖ etykieta) — deterministycznie, bez wymiany. Etykieta oddziela ten klucz
    // od HMAC-a dowodu: ten sam sekret, dwa zastosowania, zero wspólnych stanów.
    static const char LBL[] = "sensmos-tun-v2";
    mbedtls_sha256_context c;
    mbedtls_sha256_init(&c);
    bool ok = mbedtls_sha256_starts(&c, 0) == 0
           && mbedtls_sha256_update(&c, s_st.key[idx], PAIR_KEY_LEN) == 0
           && mbedtls_sha256_update(&c, (const uint8_t*)LBL, sizeof(LBL) - 1) == 0
           && mbedtls_sha256_finish(&c, out) == 0;
    mbedtls_sha256_free(&c);
    if (!ok) memset(out, 0, 32);
    return ok;
}
