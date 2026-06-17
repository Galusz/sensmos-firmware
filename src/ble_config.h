#ifndef BLE_CONFIG_H
#define BLE_CONFIG_H
#include <Arduino.h>

#define BLE_SERVICE_UUID    "a7f3bc52-4e1d-4e7a-9c2f-8b5d6e3a1f0c"
#define BLE_CHAR_WRITE_UUID "a7f3bc52-4e1d-4e7a-9c2f-8b5d6e3a1f0d"
#define BLE_CHAR_READ_UUID  "a7f3bc52-4e1d-4e7a-9c2f-8b5d6e3a1f0e"

extern bool g_ble_active;
extern char g_owner_address[43];
extern char g_backend_url[128];
extern char g_location_lat[16];
extern char g_location_lon[16];

void ble_load_config();  // wczytaj config z NVS
void ble_start();
void ble_set_wifi_ready_cb(void (*cb)());
void ble_stop();
void ble_tick();
void watchdog_start();
void watchdog_confirm();
void watchdog_tick();  // wywołuj z loop()
#endif
