#include "ext_auth.h"
#include "ws_client.h"
#include "log.h"
#include <esp_random.h>

// Jedno zgłoszenie naraz — uzasadnienie w ext_auth.h. Cały stan w RAM, celowo bez NVS.
static ExtAuthState s_state = EXT_AUTH_IDLE;
static char     s_req[17]   = {0};
static char     s_id[17]    = {0};
static char     s_token[80] = {0};
static char     s_reason[32]= {0};
static uint32_t s_exp       = 0;
static uint32_t s_started   = 0;   // millis() startu ceremonii
static uint32_t s_settled   = 0;   // millis() nadejścia odpowiedzi

#define EXT_TIMEOUT_MS   30000UL   // BE nie odpowiedział — przystawka ma dostać powód, nie ciszę
#define EXT_KEEP_MS     300000UL   // jak długo trzymamy wynik do odczytania (retry po zgubionym HTTP)
#define EXT_MIN_GAP_MS    3000UL   // dławik: PIN w LAN-ie nie ma zamieniać się w młot na BE

// CSV → tablica JSON. Zakresy przychodzą z HTTP jako "radio.frames,radio.spectrum",
// bo tak najprościej wpisać je w konfiguracji przystawki; BE chce tablicy.
static int scopes_json(const char* csv, char* out, size_t n) {
    int p = snprintf(out, n, "[");
    bool first = true;
    const char* s = csv;
    while (s && *s && p < (int)n - 4) {
        while (*s == ' ' || *s == ',') s++;
        const char* e = s;
        while (*e && *e != ',') e++;
        int len = (int)(e - s);
        while (len > 0 && s[len - 1] == ' ') len--;
        // Whitelist znaków: zakresy to [a-z0-9.-], więc nie ma czego escapować, a wszystko
        // inne po prostu nie wejdzie do JSON-a — to jedyna walidacja, jakiej tu trzeba.
        if (len > 0 && len < 40) {
            bool ok = true;
            for (int i = 0; i < len; i++) {
                char c = s[i];
                if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '-'))
                    { ok = false; break; }
            }
            if (ok) { p += snprintf(out + p, n - p, "%s\"%.*s\"", first ? "" : ",", len, s);
                      first = false; }
        }
        s = (*e) ? e + 1 : e;
    }
    p += snprintf(out + p, n - p, "]");
    return first ? 0 : p;            // 0 = nie został ani jeden poprawny zakres
}

bool ext_auth_begin(const char* kind, const char* name, const char* scopes_csv,
                    char* req_out, size_t req_len, const char** err) {
    uint32_t now = millis();
    if (s_state == EXT_AUTH_PENDING)                    { *err = "pending";     return false; }
    if (s_started && now - s_started < EXT_MIN_GAP_MS)  { *err = "too_soon";    return false; }
    if (!ws_client_connected())                         { *err = "ws_offline";  return false; }

    char sc[128];
    if (!scopes_json(scopes_csv, sc, sizeof(sc)))       { *err = "bad_scopes";  return false; }

    snprintf(s_req, sizeof(s_req), "%08lx", (unsigned long)esp_random());
    s_id[0] = s_token[0] = s_reason[0] = 0;
    s_exp = 0;
    s_state = EXT_AUTH_PENDING;
    s_started = now;
    s_settled = 0;

    // Nazwa idzie od człowieka, więc cudzysłów i backslash trzeba wyciąć — inaczej rozjedzie
    // się JSON. Obcinamy do 48 znaków; BE i tak tnie do 64.
    char nm[52]; size_t k = 0;
    for (const char* c = name; c && *c && k < sizeof(nm) - 1; c++)
        if (*c != '"' && *c != '\\' && (uint8_t)*c >= 0x20) nm[k++] = *c;
    nm[k] = 0;

    char buf[320];
    snprintf(buf, sizeof(buf),
             "{\"type\":\"ext_auth_req\",\"req\":\"%s\",\"kind\":\"%s\",\"name\":\"%s\",\"scopes\":%s}",
             s_req, kind, nm, sc);
    if (!ws_client_send_raw(buf)) { s_state = EXT_AUTH_IDLE; *err = "send_failed"; return false; }

    LOGI("ext", "prośba o autoryzację: %s \"%s\" %s (req %s)", kind, nm, sc, s_req);
    snprintf(req_out, req_len, "%s", s_req);
    return true;
}

ExtAuthState ext_auth_state(const char* req) {
    if (!req || !*req || strcmp(req, s_req) != 0) return EXT_AUTH_IDLE;
    return s_state;
}

const char* ext_auth_token()  { return s_token; }
const char* ext_auth_id()     { return s_id; }
uint32_t    ext_auth_exp()    { return s_exp; }
const char* ext_auth_reason() { return s_reason; }

void ext_auth_on_grant(const char* req, const char* id, const char* token, uint32_t exp) {
    if (s_state != EXT_AUTH_PENDING || !req || strcmp(req, s_req) != 0) {
        LOGW("ext", "grant na nieznane zgłoszenie — ignoruję");
        return;
    }
    snprintf(s_id,    sizeof(s_id),    "%s", id    ? id    : "");
    snprintf(s_token, sizeof(s_token), "%s", token ? token : "");
    s_exp = exp;
    s_state = EXT_AUTH_GRANTED;
    s_settled = millis();
    LOGI("ext", "autoryzacja przyznana (id %s)", s_id);
}

void ext_auth_on_deny(const char* req, const char* reason) {
    if (s_state != EXT_AUTH_PENDING || !req || strcmp(req, s_req) != 0) return;
    snprintf(s_reason, sizeof(s_reason), "%s", reason ? reason : "denied");
    s_state = EXT_AUTH_DENIED;
    s_settled = millis();
    LOGW("ext", "autoryzacja odmówiona: %s", s_reason);
}

void ext_auth_tick() {
    uint32_t now = millis();
    if (s_state == EXT_AUTH_PENDING && now - s_started > EXT_TIMEOUT_MS) {
        snprintf(s_reason, sizeof(s_reason), "timeout");
        s_state = EXT_AUTH_DENIED;
        s_settled = now;
        LOGW("ext", "BE nie odpowiedział w %lus", (unsigned long)(EXT_TIMEOUT_MS / 1000));
    }
    // Token nie ma leżeć w RAM-ie dłużej, niż trwa jego odbiór. Okno jest hojne, bo
    // przystawka może zgubić odpowiedź HTTP i ponowić odczyt — ale nie jest wieczne.
    if (s_settled && now - s_settled > EXT_KEEP_MS) {
        memset(s_token, 0, sizeof(s_token));
        s_state = EXT_AUTH_IDLE;
        s_settled = 0;
    }
}
