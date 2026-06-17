#pragma once
#include <Arduino.h>

// ══════════════════════════════════════════════════════════════
// Entity Store — 4 osobne bufory
//
// pub[16]   — natywne pomiary ESP (pub.*)
// own[16]   — dane od użytkownika/integracji (own.*)
// tmp[8]    — wewnętrzny bufor skryptów (tmp.*)
// pool[64]  — ring buffer dla sub.*/get.*/msg.* z prefixem
//
// Zasady zapisu:
//   pub.*  → pub[] (tylko natywne, blokada na fałszywe)
//   own.*  → own[]
//   tmp.*  → tmp[] (ring buffer, reset przy restarcie)
//   *.*    → pool[] ring buffer (sub/get/msg z konfig prefixem)
//
// Zasady widoczności:
//   pub, own, sub.*, get.*, msg.*  → /data/status ✓
//   tmp.*                          → niewidoczne ✗
//   pub, own                       → batch do BE ✓
//   reszta                         → mark_local ✗
// ══════════════════════════════════════════════════════════════

#include "config.h"

struct DataEntry {
    char          entity_id[36];   // prefix.key, max 35 znaków
    char          value[64];
    char          unit[12];
    unsigned long last_updated;    // millis()/1000
};

// ── Zapis ─────────────────────────────────────────────────────
// Prefix decyduje o buforze docelowym
void entity_push(const char* entity_id, const char* value, const char* unit = "");
bool entity_get_string(const char* entity_id, char* out, size_t out_len);  // true jeśli znaleziono

// ── Odczyt ────────────────────────────────────────────────────
bool        entity_get(int index, char* eid, char* val, char* unit, unsigned long* ts);
float       entity_get_float(const char* entity_id);
int         entity_count();          // pub + own + pool (bez tmp)
int         entity_count_all();      // wszystkie włącznie z tmp

// ── Iteracja po buforach ─────────────────────────────────────
int         entity_pub_count();
int         entity_own_count();
int         entity_pool_count();
int         entity_tmp_count();
bool        entity_get_pub(int i, char* eid, char* val, char* unit, unsigned long* ts);
bool        entity_get_own(int i, char* eid, char* val, char* unit, unsigned long* ts);
bool        entity_get_pool(int i, char* eid, char* val, char* unit, unsigned long* ts);
bool        entity_get_tmp(int i, char* eid, char* val, char* unit, unsigned long* ts);

// ── Batch helpers ─────────────────────────────────────────────
// Zwraca true jeśli encja powinna iść do batcha (pub + own)
bool        entity_goes_to_batch(const char* entity_id);

// ── Klasyfikacja wejścia (HA/user bez prefiksu) ───────────────
// Surowa nazwa → pełny eid z prefiksem (out). Natywne → pub., reszta → own.
// Nazwa już z prefiksem zostaje bez zmian. Zwraca true jeśli wynik to pub.*
bool        entity_classify(const char* entity_id, char* out, size_t out_len);

// ── Native entities (pub.* whitelist z BE) ────────────────────
void        entity_load_native(const char* entity_id);
bool        entity_is_native(const char* entity_id);
int         entity_native_count();
const char* entity_get_native(int index);

// ── Tmp helpers ───────────────────────────────────────────────
void        entity_tmp_clear();   // reset tmp przy restarcie
void        entity_own_prune(unsigned long ttl_s);  // usuń own.* starsze niż ttl_s (anty „wiszące")

// ── Init ──────────────────────────────────────────────────────
void        entity_store_init();
