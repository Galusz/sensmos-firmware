#ifndef IDENTITY_H
#define IDENTITY_H

#include <Preferences.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/sha256.h>
#include <Arduino.h>
#include <esp_mac.h>

extern uint8_t g_privkey[32];
extern uint8_t g_pubkey[65];
extern char    g_device_id[67];
extern char    g_eth_address[43];
extern char    g_api_token[65];

bool identity_init();
bool identity_sign(const uint8_t* hash, uint8_t* sig_out, size_t* sig_len);
bool identity_verify_be(const char* message, const uint8_t* sig_der, size_t sig_len);  // K3: weryfikacja komend BE→node
void identity_get_pubkey_hex(char* out, size_t len);
bool identity_regenerate_token();
// Odtworzenie ID noda po reflashu (apka, BLE set_device_id): stały device_id z poprzedniego
// życia, klucze zostają świeże. Persist NVS; factory reset przywraca ID liczony z pubkey+MAC.
bool identity_set_override(const char* device_id_hex64);
void bytes_to_hex(const uint8_t* bytes, size_t len, char* out);
void sha256_string(const char* input, uint8_t* output);

#endif
