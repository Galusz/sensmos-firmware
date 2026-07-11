#include "entity_store.h"
#include "log.h"
#include <string.h>
#include <stdlib.h>
#include <math.h>

// ── Bufory ────────────────────────────────────────────────────

// Bufory encji STATYCZNIE (.bss) — liczność stała, więc nie ma po co zjadać heapu:
// w .bss nie fragmentują sterty, heap zostaje ciągły dla TLS/monitorów/checknet.
// (~6.5KB: pub16 + own16 + tmp8 + pool16 × 116B)
static DataEntry g_pub_buf [ENTITY_PUB_MAX];
static DataEntry g_own_buf [ENTITY_OWN_MAX];
static DataEntry g_tmp_buf [ENTITY_TMP_MAX];
static DataEntry g_pool_buf[ENTITY_POOL_MAX];
static DataEntry* g_pub  = g_pub_buf;
static DataEntry* g_own  = g_own_buf;
static DataEntry* g_tmp  = g_tmp_buf;
static DataEntry* g_pool = g_pool_buf;

static int g_pub_count  = 0;
static int g_own_count  = 0;
static int g_tmp_head   = 0;  // ring buffer head
static int g_tmp_count  = 0;
static int g_pool_head  = 0;  // ring buffer head
static int g_pool_count = 0;

// ── Native whitelist ──────────────────────────────────────────

#define NATIVE_MAX 40   // katalog BE ma 37 encji! 32 (RAM-AUDIT 0.49) UCINAŁO końcówkę PWR
                        // (grid_v/pv_power/load_power znikały z nodów i HA). 40 = 37 + zapas.
static char g_native[NATIVE_MAX][28];
static int  g_native_count = 0;

// ── Helpers ───────────────────────────────────────────────────

static void fill_entry(DataEntry& e, const char* eid, const char* val, const char* unit) {
    strncpy(e.entity_id,   eid,  sizeof(e.entity_id)-1);  e.entity_id[sizeof(e.entity_id)-1]='\0';
    strncpy(e.value,       val,  sizeof(e.value)-1);       e.value[sizeof(e.value)-1]='\0';
    strncpy(e.unit,        unit, sizeof(e.unit)-1);        e.unit[sizeof(e.unit)-1]='\0';
    e.last_updated = millis()/1000;
}

// Znajdź istniejącą encję w buforze (update)
static int find_in(DataEntry* buf, int count, const char* eid) {
    for (int i = 0; i < count; i++)
        if (strcmp(buf[i].entity_id, eid) == 0) return i;
    return -1;
}

// Indeks w ring bufferze dla i-tego najstarszego wpisu
static inline int ring_index(int head, int count, int i, int max) {
    return (head - count + i + max*2) % max;
}

// Szukaj encji we wszystkich 4 buforach (pub→own→tmp→pool)
static DataEntry* find_entry(const char* eid) {
    for (int i = 0; i < g_pub_count; i++)
        if (strcmp(g_pub[i].entity_id, eid) == 0) return &g_pub[i];
    for (int i = 0; i < g_own_count; i++)
        if (strcmp(g_own[i].entity_id, eid) == 0) return &g_own[i];
    for (int i = 0; i < g_tmp_count; i++) {
        int idx = ring_index(g_tmp_head, g_tmp_count, i, ENTITY_TMP_MAX);
        if (strcmp(g_tmp[idx].entity_id, eid) == 0) return &g_tmp[idx];
    }
    for (int i = 0; i < g_pool_count; i++) {
        int idx = ring_index(g_pool_head, g_pool_count, i, ENTITY_POOL_MAX);
        if (strcmp(g_pool[idx].entity_id, eid) == 0) return &g_pool[idx];
    }
    return nullptr;
}

// ── Init ──────────────────────────────────────────────────────

void entity_store_init() {
    memset(g_pub,  0, ENTITY_PUB_MAX  * sizeof(DataEntry));
    memset(g_own,  0, ENTITY_OWN_MAX  * sizeof(DataEntry));
    memset(g_tmp,  0, ENTITY_TMP_MAX  * sizeof(DataEntry));
    memset(g_pool, 0, ENTITY_POOL_MAX * sizeof(DataEntry));
    g_pub_count = g_own_count = 0;
    g_tmp_head = g_tmp_count = 0;
    g_pool_head = g_pool_count = 0;
}

void entity_tmp_clear() {
    if (g_tmp) memset(g_tmp, 0, ENTITY_TMP_MAX * sizeof(DataEntry));
    g_tmp_head = g_tmp_count = 0;
}

// Usuń own.* nieodświeżone przez ttl_s (kompaktuje tablicę). Wołane przed budową batcha,
// żeby zdjęty mapping / porzucona encja sama wypadła zamiast „wisieć" w blobie BE.
void entity_own_prune(unsigned long ttl_s) {
    if (ttl_s == 0) return;
    unsigned long now_s = millis() / 1000;
    int w = 0;
    for (int r = 0; r < g_own_count; r++) {
        unsigned long age = (now_s >= g_own[r].last_updated) ? (now_s - g_own[r].last_updated) : 0;
        if (age <= ttl_s) {
            if (w != r) g_own[w] = g_own[r];
            w++;
        }
    }
    if (w != g_own_count) {
        LOGD("store", "own prune: %d -> %d (TTL %lus)", g_own_count, w, ttl_s);
        g_own_count = w;
    }
}

// ── Push ──────────────────────────────────────────────────────

void entity_push(const char* entity_id, const char* value, const char* unit) {
    if (!entity_id || !value) return;
    const char* u = unit ? unit : "";

    // pub.* → pub buffer
    if (strncmp(entity_id, "pub.", 4) == 0) {
        const char* key = entity_id + 4;
        // Tylko natywne (jeśli lista załadowana)
        if (g_native_count > 0 && !entity_is_native(key)) {
            LOGW("store", "blocked non-native pub.%s", key);
            return;
        }
        int idx = find_in(g_pub, g_pub_count, entity_id);
        if (idx >= 0) { fill_entry(g_pub[idx], entity_id, value, u); return; }
        if (g_pub_count < ENTITY_PUB_MAX) {
            fill_entry(g_pub[g_pub_count++], entity_id, value, u);
        } else {
            // Nadpisz najstarszy
            int oldest = 0;
            for (int i = 1; i < ENTITY_PUB_MAX; i++)
                if (g_pub[i].last_updated < g_pub[oldest].last_updated) oldest = i;
            fill_entry(g_pub[oldest], entity_id, value, u);
        }
        return;
    }

    // own.* → own buffer
    if (strncmp(entity_id, "own.", 4) == 0) {
        int idx = find_in(g_own, g_own_count, entity_id);
        if (idx >= 0) { fill_entry(g_own[idx], entity_id, value, u); return; }
        if (g_own_count < ENTITY_OWN_MAX) {
            fill_entry(g_own[g_own_count++], entity_id, value, u);
        } else {
            int oldest = 0;
            for (int i = 1; i < ENTITY_OWN_MAX; i++)
                if (g_own[i].last_updated < g_own[oldest].last_updated) oldest = i;
            fill_entry(g_own[oldest], entity_id, value, u);
        }
        return;
    }

    // tmp.* → tmp ring buffer (niewidoczne)
    if (strncmp(entity_id, "tmp.", 4) == 0) {
        // Szukaj istniejącej
        for (int i = 0; i < g_tmp_count; i++) {
            int idx = ring_index(g_tmp_head, g_tmp_count, i, ENTITY_TMP_MAX);
            if (strcmp(g_tmp[idx].entity_id, entity_id) == 0) {
                fill_entry(g_tmp[idx], entity_id, value, u); return;
            }
        }
        // Nowy wpis
        int slot = g_tmp_head % ENTITY_TMP_MAX;
        fill_entry(g_tmp[slot], entity_id, value, u);
        g_tmp_head = (g_tmp_head + 1) % ENTITY_TMP_MAX;
        if (g_tmp_count < ENTITY_TMP_MAX) g_tmp_count++;
        return;
    }

    // Blokada zarezerwowanych prefixów przez pool
    // pub.* i own.* obsługiwane wyżej, tmp.* też
    // Jeśli ktoś próbuje wpisać przez pool z zarezerwowanym prefixem → odrzuć
    if (strncmp(entity_id,"pub.",4)==0 || strncmp(entity_id,"own.",4)==0 ||
        strncmp(entity_id,"tmp.",4)==0) {
        // Już obsłużone wyżej — tu nie powinniśmy dojść
        LOGW("store", "routing error: %s", entity_id);
        return;
    }

    // Wszystko inne → pool ring buffer (sub.*/get.*/msg.* z prefixem)
    // Szukaj istniejącej
    for (int i = 0; i < g_pool_count; i++) {
        int idx = ring_index(g_pool_head, g_pool_count, i, ENTITY_POOL_MAX);
        if (strcmp(g_pool[idx].entity_id, entity_id) == 0) {
            fill_entry(g_pool[idx], entity_id, value, u); return;
        }
    }
    // Nowy wpis — ring buffer
    int slot = g_pool_head % ENTITY_POOL_MAX;
    fill_entry(g_pool[slot], entity_id, value, u);
    g_pool_head = (g_pool_head + 1) % ENTITY_POOL_MAX;
    if (g_pool_count < ENTITY_POOL_MAX) g_pool_count++;
}

// ── Odczyt ────────────────────────────────────────────────────

float entity_get_float(const char* entity_id) {
    DataEntry* e = find_entry(entity_id);
    return e ? atof(e->value) : NAN;
}

// entity_get — iteracja po pub+own+pool (bez tmp)
bool entity_get(int index, char* eid, char* val, char* unit, unsigned long* ts) {
    // pub
    if (index < g_pub_count) {
        DataEntry& e = g_pub[index];
        strncpy(eid, e.entity_id, 35); eid[35]='\0'; strncpy(val, e.value, 63); val[63]='\0';
        strncpy(unit, e.unit, 11); if(ts) *ts = e.last_updated;
        return true;
    }
    index -= g_pub_count;
    // own
    if (index < g_own_count) {
        DataEntry& e = g_own[index];
        strncpy(eid, e.entity_id, 35); eid[35]='\0'; strncpy(val, e.value, 63); val[63]='\0';
        strncpy(unit, e.unit, 11); if(ts) *ts = e.last_updated;
        return true;
    }
    index -= g_own_count;
    // pool
    if (index < g_pool_count) {
        int idx = ring_index(g_pool_head, g_pool_count, index, ENTITY_POOL_MAX);
        DataEntry& e = g_pool[idx];
        strncpy(eid, e.entity_id, 35); eid[35]='\0'; strncpy(val, e.value, 63); val[63]='\0';
        strncpy(unit, e.unit, 11); if(ts) *ts = e.last_updated;
        return true;
    }
    return false;
}

int entity_count()     { return g_pub_count + g_own_count + g_pool_count; }

bool entity_get_string(const char* entity_id, char* out, size_t out_len) {
    DataEntry* e = find_entry(entity_id);
    if (!e) return false;
    strncpy(out, e->value, out_len-1); out[out_len-1]='\0';
    return true;
}
int entity_count_all() { return g_pub_count + g_own_count + g_pool_count + g_tmp_count; }

int  entity_pub_count()  { return g_pub_count; }
int  entity_own_count()  { return g_own_count; }
int  entity_pool_count() { return g_pool_count; }
int  entity_tmp_count()  { return g_tmp_count; }

bool entity_get_pub(int i, char* eid, char* val, char* unit, unsigned long* ts) {
    if (i < 0 || i >= g_pub_count) return false;
    DataEntry& e = g_pub[i];
    strncpy(eid,e.entity_id,35); strncpy(val,e.value,63);
    strncpy(unit,e.unit,11); if(ts)*ts=e.last_updated; return true;
}
bool entity_get_own(int i, char* eid, char* val, char* unit, unsigned long* ts) {
    if (i < 0 || i >= g_own_count) return false;
    DataEntry& e = g_own[i];
    strncpy(eid,e.entity_id,35); strncpy(val,e.value,63);
    strncpy(unit,e.unit,11); if(ts)*ts=e.last_updated; return true;
}
bool entity_get_pool(int i, char* eid, char* val, char* unit, unsigned long* ts) {
    if (i < 0 || i >= g_pool_count) return false;
    int idx = ring_index(g_pool_head, g_pool_count, i, ENTITY_POOL_MAX);
    DataEntry& e = g_pool[idx];
    strncpy(eid,e.entity_id,35); strncpy(val,e.value,63);
    strncpy(unit,e.unit,11); if(ts)*ts=e.last_updated; return true;
}
bool entity_get_tmp(int i, char* eid, char* val, char* unit, unsigned long* ts) {
    if (i < 0 || i >= g_tmp_count) return false;
    int idx = ring_index(g_tmp_head, g_tmp_count, i, ENTITY_TMP_MAX);
    DataEntry& e = g_tmp[idx];
    strncpy(eid,e.entity_id,35); strncpy(val,e.value,63);
    strncpy(unit,e.unit,11); if(ts)*ts=e.last_updated; return true;
}

bool entity_goes_to_batch(const char* entity_id) {
    return strncmp(entity_id,"pub.",4)==0 || strncmp(entity_id,"own.",4)==0;
}

bool entity_classify(const char* entity_id, char* out, size_t out_len) {
    if (strncmp(entity_id,"pub.",4)==0 || strncmp(entity_id,"own.",4)==0 ||
        strncmp(entity_id,"tmp.",4)==0) {
        strncpy(out, entity_id, out_len-1); out[out_len-1]='\0';
        return strncmp(entity_id,"pub.",4)==0;
    }
    if (entity_is_native(entity_id)) {
        snprintf(out, out_len, "pub.%s", entity_id);
        return true;
    }
    snprintf(out, out_len, "own.%s", entity_id);
    return false;
}

// ── Native ────────────────────────────────────────────────────

void entity_load_native(const char* entity_id) {
    if (g_native_count >= NATIVE_MAX) return;
    for (int i = 0; i < g_native_count; i++)
        if (strcmp(g_native[i], entity_id) == 0) return;
    strncpy(g_native[g_native_count++], entity_id, 27);
}

bool entity_is_native(const char* entity_id) {
    const char* key = (strncmp(entity_id,"pub.",4)==0) ? entity_id+4 : entity_id;
    for (int i = 0; i < g_native_count; i++)
        if (strcmp(g_native[i], key) == 0) return true;
    return false;
}

int         entity_native_count()      { return g_native_count; }
const char* entity_get_native(int i)   { return (i>=0&&i<g_native_count) ? g_native[i] : nullptr; }
