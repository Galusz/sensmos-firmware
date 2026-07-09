#include "wifi_manager.h"
#include "identity.h"
#include "log.h"
#include <WiFi.h>
#include <ESPmDNS.h>
#include <Preferences.h>
#include "data_sender.h"  // FW_VERSION

bool g_wifi_connected = false;
char g_wifi_ssid[64]  = {0};
char g_local_ip[16]   = {0};

bool wifi_has_config() {
    Preferences prefs;
    prefs.begin("sensmos_wifi", true);
    bool has = prefs.isKey("ssid");
    prefs.end();
    return has;
}

void wifi_save_config(const char* ssid, const char* password) {
    Preferences prefs;
    prefs.begin("sensmos_wifi", false);
    prefs.putString("ssid",     ssid);
    prefs.putString("password", password);
    prefs.end();
    LOGI("wifi", "config saved: %s", ssid);
}

void wifi_clear_config() {
    Preferences prefs;
    prefs.begin("sensmos_wifi", false);
    prefs.clear();
    prefs.end();
    LOGI("wifi", "config cleared");
}

// Zwraca kod: 0=OK, 1=zle haslo, 2=brak sieci(SSID), 3=timeout
int wifi_connect_result(const char* ssid, const char* password) {
    LOGI("wifi", "connecting to %s", ssid);
    // Reset WiFi stack przed próbą — usuwa stary stan
    WiFi.disconnect(true);   // rozłącz i wyczyść creds
    WiFi.mode(WIFI_OFF);
    delay(500);              // daj stackowi czas na reset
    WiFi.mode(WIFI_STA);
    WiFi.setSleep(false);
    delay(100);
    WiFi.begin(ssid, password);

    int attempts = 0;
    while (attempts < 24) {  // max ~12s
        wl_status_t st = WiFi.status();
        if (st == WL_CONNECTED) {
            g_wifi_connected = true;
            strncpy(g_wifi_ssid, ssid, sizeof(g_wifi_ssid));
            strncpy(g_local_ip, WiFi.localIP().toString().c_str(), sizeof(g_local_ip));
            LOGI("wifi", "connected, ip %s", g_local_ip);
            return 0;  // mDNS uruchomimy PO wysłaniu notify (mniej obciążenia naraz)
        }
        if (st == WL_CONNECT_FAILED) { LOGW("wifi", "wrong password"); return 1; }
        if (st == WL_NO_SSID_AVAIL)  { LOGW("wifi", "SSID not found"); return 2; }
        delay(500);
        attempts++;
    }
    LOGW("wifi", "connect timeout");
    return 3;
}

bool wifi_connect(const char* ssid, const char* password) {
    LOGI("wifi", "connecting to %s", ssid);
    if (WiFi.getMode() != WIFI_STA) WiFi.mode(WIFI_STA);
    WiFi.setSleep(false);
    WiFi.begin(ssid, password);
    int attempts = 0;
    while (WiFi.status() != WL_CONNECTED && attempts < 60) {
        delay(500);
        attempts++;
    }

    if (WiFi.status() == WL_CONNECTED) {
        g_wifi_connected = true;
        strncpy(g_wifi_ssid, ssid, sizeof(g_wifi_ssid));
        strncpy(g_local_ip, WiFi.localIP().toString().c_str(), sizeof(g_local_ip));
        LOGI("wifi", "connected, ip %s", g_local_ip);
        wifi_setup_mdns();
        return true;
    }

    LOGW("wifi", "connect failed");
    g_wifi_connected = false;
    return false;
}

bool wifi_init() {
    if (!wifi_has_config()) {
        LOGW("wifi", "no config — needs BLE provisioning");
        return false;
    }

    Preferences prefs;
    prefs.begin("sensmos_wifi", true);
    char ssid[64]     = {0};
    char password[64] = {0};
    prefs.getString("ssid",     ssid,     sizeof(ssid));
    prefs.getString("password", password, sizeof(password));
    prefs.end();

    return wifi_connect(ssid, password);
}

// ── mDNS — wykrywalność w sieci lokalnej (dla apki) ───────────
void wifi_setup_mdns() {
    // Nazwa hosta: sensmos-XXXXXX (6 znaków device_id)
    char hostname[32];
    snprintf(hostname, sizeof(hostname), "sensmos-%.6s", g_device_id);

    if (MDNS.begin(hostname)) {
        // Ogłoś usługę sensmos przez mDNS
        MDNS.addService("sensmos", "tcp", 80);
        MDNS.addServiceTxt("sensmos", "tcp", "device_id", (const char*)g_device_id);
        MDNS.addServiceTxt("sensmos", "tcp", "version", (const char*)FW_VERSION);
        // Standardowy HTTP też
        MDNS.addService("http", "tcp", 80);
        LOGI("wifi", "mDNS: %s.local", hostname);
    } else {
        LOGW("wifi", "mDNS start failed");
    }
}