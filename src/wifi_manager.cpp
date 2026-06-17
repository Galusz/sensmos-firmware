#include "wifi_manager.h"
#include "identity.h"
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
    Serial.printf("[WiFi] Config zapisany: %s\n", ssid);
}

void wifi_clear_config() {
    Preferences prefs;
    prefs.begin("sensmos_wifi", false);
    prefs.clear();
    prefs.end();
    Serial.println("[WiFi] Config wyczyszczony");
}

// Zwraca kod: 0=OK, 1=zle haslo, 2=brak sieci(SSID), 3=timeout
int wifi_connect_result(const char* ssid, const char* password) {
    Serial.printf("[WiFi] Łączę z: %s\n", ssid);
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
            Serial.printf("\n[WiFi] Połączono! IP: %s\n", g_local_ip);
            return 0;  // mDNS uruchomimy PO wysłaniu notify (mniej obciążenia naraz)
        }
        // Błędne hasło — ESP zgłasza szybko (zwykle 2-4s)
        if (st == WL_CONNECT_FAILED) {
            Serial.println("\n[WiFi] Błędne hasło!");
            return 1;
        }
        // Brak takiej sieci
        if (st == WL_NO_SSID_AVAIL) {
            Serial.println("\n[WiFi] Sieć nie znaleziona!");
            return 2;
        }
        delay(500);
        Serial.print(".");
        attempts++;
    }
    Serial.println("\n[WiFi] Timeout");
    return 3;
}

bool wifi_connect(const char* ssid, const char* password) {
    Serial.printf("[WiFi] Łączę z: %s\n", ssid);
    if (WiFi.getMode() != WIFI_STA) WiFi.mode(WIFI_STA);
    WiFi.setSleep(false);
    WiFi.begin(ssid, password);
    int attempts = 0;
    while (WiFi.status() != WL_CONNECTED && attempts < 60) {
        delay(500);
        Serial.print(".");
        attempts++;
        if (attempts % 10 == 0) Serial.printf(" [status=%d] ", WiFi.status());
    }
    Serial.println();

    if (WiFi.status() == WL_CONNECTED) {
        g_wifi_connected = true;
        strncpy(g_wifi_ssid, ssid, sizeof(g_wifi_ssid));
        strncpy(g_local_ip, WiFi.localIP().toString().c_str(), sizeof(g_local_ip));
        Serial.printf("[WiFi] Połączono! IP: %s\n", g_local_ip);
        wifi_setup_mdns();
        return true;
    }

    Serial.println("[WiFi] Błąd połączenia!");
    g_wifi_connected = false;
    return false;
}

bool wifi_init() {
    if (!wifi_has_config()) {
        Serial.println("[WiFi] Brak konfiguracji — potrzebna konfiguracja BLE");
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
        Serial.printf("[mDNS] Dostępny jako: %s.local\n", hostname);
    } else {
        Serial.println("[mDNS] Błąd uruchomienia");
    }
}