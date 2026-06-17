#ifndef WIFI_MANAGER_H
#define WIFI_MANAGER_H

#include <Arduino.h>
#include <WiFi.h>
#include <Preferences.h>

// Status WiFi
extern bool g_wifi_connected;
extern char g_wifi_ssid[64];
extern char g_local_ip[16];

bool wifi_init();
bool wifi_connect(const char* ssid, const char* password);
int wifi_connect_result(const char* ssid, const char* password);
bool wifi_has_config();
void wifi_clear_config();
void wifi_save_config(const char* ssid, const char* password);
void wifi_setup_mdns();

#endif