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
void identity_get_pubkey_hex(char* out, size_t len);
bool identity_regenerate_token();
void bytes_to_hex(const uint8_t* bytes, size_t len, char* out);
void sha256_string(const char* input, uint8_t* output);

#endif
