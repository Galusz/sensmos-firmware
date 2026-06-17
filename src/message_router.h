#pragma once
#include <Arduino.h>

#include "config.h"

// ── Message Router ────────────────────────────────────────────
// Obsługuje przychodzące wiadomości node↔node
// Konfiguracja przez /config/messages
//
// POST /config/messages:
// {
//   "slot": 0,
//   "message_id": "hello",
//   "prefix": "dom",           ← zapisz payload do dom.* w pool (pusty = nie zapisuj)
//   "webhook": "https://...",
//   "push": {
//     "title": "Od {from}: {dom.temp}°C",
//     "body":  "{message}"
//   },
//   "script": "moj_skrypt"
// }

struct MessageAction {
    char message_id[32];
    char prefix[16];           // prefix zapisu np. "dom" → "dom.key"
                               // pusty = brak zapisu
    char webhook[128];
    char push_title[64];
    char push_body[128];
    char script_id[32];
};

void   message_router_init();
void   message_router_dispatch(const char* from, const char* message_id, const char* payload);

// Sloty 0-2 (wewnętrzne)
void   message_router_set(int slot, const MessageAction& action);
MessageAction message_router_get(int slot);

// API po message_id (publiczne)
bool   message_router_set_by_id(const MessageAction& action);  // true=OK, false=brak miejsca
bool   message_router_delete_by_id(const char* message_id);    // true=OK, false=nie znaleziono

// JSON dump dla GET /config
String message_router_get_config_json();

// Helper
bool   message_router_id_matches(const char* slot_id, const char* message_id);
