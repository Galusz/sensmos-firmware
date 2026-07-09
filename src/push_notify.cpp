/**
 * SENSMOS Firmware — Push Token Storage
 * Token FCM zapisany w NVS — wysyłany do backendu przy user_script_event
 * Backend (nie ESP32) odpowiada za wysyłkę FCM
 */
#include "push_notify.h"
#include "log.h"
#include <Preferences.h>

static String _pushToken = "";

void push_init() {
    Preferences prefs;
    prefs.begin("push", true);
    _pushToken = prefs.getString("token", "");
    prefs.end();
    LOGD("push", _pushToken.length() > 0 ? "token loaded" : "no token");
}

void push_set_token(const char* token) {
    _pushToken = String(token);
    Preferences prefs;
    prefs.begin("push", false);
    prefs.putString("token", _pushToken);
    prefs.end();
    LOGD("push", "token saved");
}

String push_get_token() { return _pushToken; }
bool   push_available() { return _pushToken.length() > 10; }
