#ifndef SERIAL_CMD_H
#define SERIAL_CMD_H

#include <Arduino.h>

// Serial Monitor emuluje dokładnie to samo co apka Flutter przez BLE
// Te same komendy JSON — ta sama logika
//
// Użycie:
//   Wpisz JSON w Serial Monitor i naciśnij Enter
//
// Komendy (identyczne z BLE):
//   {"cmd":"set_wifi","ssid":"...","password":"..."}
//   {"cmd":"set_backend","url":"http://IP:3000/v1"}
//   {"cmd":"set_location","lat":52.23,"lon":21.01}
//   {"cmd":"set_pin","pin":"TwojPin"}
//   {"cmd":"register","owner":"0x...","sig_wallet":"0x...","timestamp":123}
//   {"cmd":"unregister","owner":"0x..."}
//   {"cmd":"get_info"}
//   {"cmd":"get_token"}
//   {"cmd":"done"}
//
// Dodatkowe komendy tylko przez Serial (nie przez BLE):
//   {"cmd":"factory_reset"}
//   {"cmd":"help"}

void serial_cmd_init();
void serial_cmd_tick();

#endif