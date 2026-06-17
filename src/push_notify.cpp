/**
 * SENSMOS Firmware — Push Token Storage
 * Token FCM zapisany w NVS — wysyłany do backendu przy user_script_event
 * Backend (nie ESP32) odpowiada za wysyłkę FCM
 */
#include "push_notify.h"
#include <Preferences.h>

static String _pushToken = "";

void push_init() {
    Preferences prefs;
    prefs.begin("push", true);
    _pushToken = prefs.getString("token", "");
    prefs.end();
    if (_pushToken.length() > 0) {
        Serial.printf("[Push] Token wczytany (%.16s...)\n", _pushToken.c_str());
    } else {
        Serial.println("[Push] Brak tokenu");
    }
}

void push_set_token(const char* token) {
    _pushToken = String(token);
    Preferences prefs;
    prefs.begin("push", false);
    prefs.putString("token", _pushToken);
    prefs.end();
    Serial.printf("[Push] Token zapisany (%.16s...)\n", token);
}

String push_get_token() { return _pushToken; }
bool   push_available() { return _pushToken.length() > 10; }
