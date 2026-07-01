#include "serial_cmd.h"
#include "data_sender.h"
#include "identity.h"
#include "ble_config.h"
#include "message_router.h"
#include "push_notify.h"
#include "wifi_manager.h"
#include "http_server.h"
#include <ArduinoJson.h>
#include <HTTPClient.h>
#include "http_internal.h"
#include <Preferences.h>

static String serial_buffer = "";

// ── Wyślij odpowiedź przez Serial (odpowiednik BLE notify) ────
static void serial_respond(const char* status, const char* cmd,
                           const char* msg = nullptr) {
    char resp[256];
    if (msg) {
        snprintf(resp, sizeof(resp),
            "{\"status\":\"%s\",\"cmd\":\"%s\",\"msg\":\"%s\"}",
            status, cmd, msg);
    } else {
        snprintf(resp, sizeof(resp),
            "{\"status\":\"%s\",\"cmd\":\"%s\"}", status, cmd);
    }
    Serial.printf("[BLE→Serial] %s\n", resp);
}

// ── Obsługa register — wysyła do backendu ────────────────────
static void do_register(const char* owner, const char* sig_wallet,
                        uint32_t timestamp) {
    if (strlen(g_backend_url) == 0) {
        serial_respond("error", "register", "no_backend_url"); return;
    }

    char message[256];
    snprintf(message, sizeof(message),
        "{\"device_id\":\"%s\",\"owner\":\"%s\",\"ts\":%u}",
        g_device_id, owner, timestamp);

    uint8_t hash[32];
    sha256_string(message, hash);
    uint8_t sig[72];
    size_t  sig_len = 0;
    if (!identity_sign(hash, sig, &sig_len)) {
        serial_respond("error", "register", "sign_failed"); return;
    }
    char sig_esp_hex[145];
    bytes_to_hex(sig, sig_len, sig_esp_hex);

    char pubkey_hex[131];
    identity_get_pubkey_hex(pubkey_hex, sizeof(pubkey_hex));

    // Zbuduj payload dla backendu
    JsonDocument doc;
    doc["message"]    = message;
    doc["pubkey"]     = pubkey_hex;
    doc["sig_esp"]    = sig_esp_hex;
    if (sig_wallet && strlen(sig_wallet) > 10) {
        doc["sig_wallet"] = sig_wallet; // opcjonalny — gdy jest portfel
    }

    String payload;
    serializeJson(doc, payload);

    String url = String(g_backend_url) + "/register";
    HTTPClient http;
    WiFiClientSecure sec;
    http_begin_url(http, sec, url);
    http.addHeader("Content-Type", "application/json");
    http.setTimeout(10000);
    int code = http.POST(payload);

    if (code == 200) {
        strncpy(g_owner_address, owner, sizeof(g_owner_address) - 1);
        Preferences prefs;
        prefs.begin("sensmos", false);
        prefs.putString("owner_addr", owner);
        prefs.end();

        char resp[512];
        snprintf(resp, sizeof(resp),
            "{\"status\":\"ok\",\"cmd\":\"register\","
            "\"message\":%s,\"sig_esp\":\"%s\"}",
            message, sig_esp_hex);
        Serial.printf("[BLE→Serial] %s\n", resp);
        Serial.println("[Serial] ✓ Node zarejestrowany! Restart za 3s...");
        delay(3000);
        ESP.restart();
    } else {
        String body = http.getString();
        Serial.printf("[Serial] ✗ Błąd %d: %s\n", code, body.c_str());
    }
    http.end();
}

// ── Handlery komend (każdy dostaje doc + nazwę cmd) ──────────
static void cmd_set_wifi(JsonDocument& doc, const char* cmd) {
    const char* ssid = doc["ssid"];
    const char* pass = doc["password"];
    if (!ssid || strlen(ssid) == 0) {
        serial_respond("error", cmd, "no_ssid"); return;
    }
    wifi_save_config(ssid, pass ? pass : "");
    if (wifi_connect(ssid, pass ? pass : "")) {
        char resp[128];
        snprintf(resp, sizeof(resp),
            "{\"status\":\"ok\",\"cmd\":\"set_wifi\",\"ip\":\"%s\"}",
            g_local_ip);
        Serial.printf("[BLE→Serial] %s\n", resp);
    } else {
        serial_respond("error", cmd, "wifi_failed");
    }
}

static void cmd_set_backend(JsonDocument& doc, const char* cmd) {
    const char* url = doc["url"];
    if (!url || strlen(url) < 7) {
        serial_respond("error", cmd, "invalid_url"); return;
    }
    strncpy(g_backend_url, url, sizeof(g_backend_url) - 1);
    Preferences prefs;
    prefs.begin("sensmos", false);
    prefs.putString("backend_url", url);
    prefs.end();
    Serial.printf("[BLE→Serial] Backend: %s\n", g_backend_url);
    serial_respond("ok", cmd);
}

static void cmd_set_pin(JsonDocument& doc, const char* cmd) {
    const char* pin = doc["pin"];
    if (!pin || strlen(pin) < 4 || strlen(pin) > 15) {
        serial_respond("error", cmd, "pin_invalid_length"); return;
    }
    if (strcmp(pin, "123456") == 0 || strcmp(pin, "000000") == 0) {
        serial_respond("error", cmd, "pin_too_simple"); return;
    }
    { Preferences p; p.begin("sensmos", false);
      p.putString("ble_pin", pin); p.end(); }
    serial_respond("ok", cmd);
}

static void cmd_register(JsonDocument& doc, const char* cmd) {
    const char* owner      = doc["owner"];
    const char* sig_wallet = doc["sig_wallet"] | "";
    uint32_t    timestamp  = doc["timestamp"]  | 0;
    if (!owner || strlen(owner) != 42) {
        serial_respond("error", cmd, "invalid_owner"); return;
    }
    do_register(owner, sig_wallet, timestamp);
}

static void cmd_unregister(JsonDocument& doc, const char* cmd) {
    const char* owner = doc["owner"];
    if (!owner || strcmp(owner, g_owner_address) != 0) {
        serial_respond("error", cmd, "owner_mismatch"); return;
    }
    memset(g_owner_address, 0, sizeof(g_owner_address));
    Preferences prefs;
    prefs.begin("sensmos", false);
    prefs.remove("owner_addr");
    prefs.end();
    serial_respond("ok", cmd);
    Serial.println("[Serial] Node odrejestrowany");
}

static void cmd_get_info(JsonDocument& doc, const char* cmd) {
    char pubkey_hex[131];
    identity_get_pubkey_hex(pubkey_hex, sizeof(pubkey_hex));
    char resp[600];
    snprintf(resp, sizeof(resp),
        "{\"status\":\"ok\",\"cmd\":\"get_info\","
        "\"device_id\":\"%s\","
        "\"eth_address\":\"%s\","
        "\"owner_address\":\"%s\","
        "\"ip\":\"%s\","
        "\"backend\":\"%s\","
        "\"pubkey\":\"%.32s...\","
        "\"registered\":%s,"
        "\"firmware\":\"" FW_VERSION "\"}",
        g_device_id, g_eth_address, g_owner_address,
        g_local_ip,
        g_backend_url, pubkey_hex,
        strlen(g_owner_address) > 0 ? "true" : "false");
    Serial.printf("[BLE→Serial] %s\n", resp);
}

static void cmd_get_token(JsonDocument& doc, const char* cmd) {
    char resp[128];
    snprintf(resp, sizeof(resp),
        "{\"status\":\"ok\",\"cmd\":\"get_token\",\"token\":\"%s\"}",
        g_api_token);
    Serial.printf("[BLE→Serial] %s\n", resp);
}

static void cmd_done(JsonDocument& doc, const char* cmd) {
    serial_respond("ok", cmd);
    Serial.println("[Serial] Sesja zakończona — restart za 1s...");
    delay(1000);
    ESP.restart();
}

static void cmd_factory_reset(JsonDocument& doc, const char* cmd) {
    Serial.println("[Serial] ⚠ FACTORY RESET...");
    Preferences prefs;
    prefs.begin("sensmos",      false); prefs.clear(); prefs.end();
    prefs.begin("sensmos_wifi", false); prefs.clear(); prefs.end();
    prefs.begin("sensmos_api",  false); prefs.clear(); prefs.end();
    Serial.println("[Serial] ✓ NVS wyczyszczony. Restart za 3s...");
    delay(3000);
    ESP.restart();
}

static void cmd_help(JsonDocument& doc, const char* cmd) {
    Serial.println("\n[Serial] Komendy JSON (identyczne z BLE):");
    Serial.println("  {\"cmd\":\"set_wifi\",\"ssid\":\"...\",\"password\":\"...\"}");
    Serial.println("  {\"cmd\":\"set_backend\",\"url\":\"http://IP:3000/v1\"}");
    Serial.println("  {\"cmd\":\"set_pin\",\"pin\":\"TwojPin\"}");
    Serial.println("  {\"cmd\":\"register\",\"owner\":\"0x...\",\"sig_wallet\":\"0x...\",\"timestamp\":123}");
    Serial.println("  {\"cmd\":\"unregister\",\"owner\":\"0x...\"}");
    Serial.println("  {\"cmd\":\"get_info\"}");
    Serial.println("  {\"cmd\":\"get_token\"}");
    Serial.println("  {\"cmd\":\"factory_reset\"}  ← tylko Serial");
    Serial.println("  {\"cmd\":\"help\"}            ← tylko Serial\n");
}

static void cmd_get_message_config(JsonDocument& doc, const char* cmd) {
    String cfg = message_router_get_config_json();
    Serial.printf("[BLE->Serial] {\"status\":\"ok\",\"cmd\":\"%s\",%s}\n",
        cmd, cfg.c_str());
}

static void cmd_set_push_token(JsonDocument& doc, const char* cmd) {
    const char* token = doc["token"] | "";
    if (strlen(token) < 10) {
        serial_respond("error", cmd, "invalid_token"); return;
    }
    push_set_token(token);
    serial_respond("ok", cmd);
}

static void cmd_get_push_token(JsonDocument& doc, const char* cmd) {
    char resp[256];
    snprintf(resp, sizeof(resp),
        "{\"status\":\"ok\",\"cmd\":\"get_push_token\","
        "\"available\":%s}",
        push_available() ? "true" : "false");
    Serial.printf("[BLE→Serial] %s\n", resp);
}

// ── Tablica dispatchu ─────────────────────────────────────────
typedef void (*cmd_handler_t)(JsonDocument&, const char*);
struct CmdEntry { const char* cmd; cmd_handler_t fn; };

static const CmdEntry CMD_TABLE[] = {
    { "set_wifi",        cmd_set_wifi },
    { "set_backend",     cmd_set_backend },
    { "set_pin",         cmd_set_pin },
    { "register",        cmd_register },
    { "unregister",      cmd_unregister },
    { "get_info",        cmd_get_info },
    { "get_token",       cmd_get_token },
    { "done",            cmd_done },
    { "factory_reset",   cmd_factory_reset },
    { "help",            cmd_help },
    { "get_webhook",     cmd_get_message_config },
    { "get_message_config", cmd_get_message_config },
    { "set_push_token",  cmd_set_push_token },
    { "get_push_token",  cmd_get_push_token },
};

// ── Główna funkcja — przetwarza JSON identyczny z BLE ────────
static void process_json(String json) {
    JsonDocument doc;
    if (deserializeJson(doc, json)) {
        Serial.println("[Serial] Błąd parsowania JSON");
        return;
    }

    const char* cmd = doc["cmd"];
    if (!cmd) { Serial.println("[Serial] Brak pola cmd"); return; }

    for (const CmdEntry& e : CMD_TABLE) {
        if (strcmp(cmd, e.cmd) == 0) { e.fn(doc, cmd); return; }
    }
    serial_respond("error", cmd, "unknown_cmd");
}

void serial_cmd_init() {
    Serial.println("[Serial] Ready. Wpisz {\"cmd\":\"help\"} aby zobaczyć komendy.");
}

void serial_cmd_tick() {
    while (Serial.available()) {
        char c = Serial.read();
        if (c == '\n' || c == '\r') {
            if (serial_buffer.length() > 0) {
                process_json(serial_buffer);
                serial_buffer = "";
            }
        } else {
            serial_buffer += c;
            if (serial_buffer.length() > 512) serial_buffer = "";
        }
    }
}