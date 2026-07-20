#pragma once
#include <Arduino.h>

// SENSMOS — szyfrowanie+integralność kanału WS BE↔FW (0.61+).
// Klucz sesji = HKDF-SHA256( ECDH(node_priv, BE_pub), salt = fw_nonce||be_nonce ).
// Osobne podklucze kierunkowe; ramka [ver(1)|seq(8 BE)|tag(16)|ciphertext] = AES-128-GCM.
// seq jest jednocześnie IV (unikalny per ramka) i licznikiem anty-replay w sesji.
// Zastępuje K3/podpisy-batch — tag GCM uwierzytelnia KAŻDĄ ramkę w obu kierunkach.

bool ws_enc_derive(const uint8_t fw_nonce[16], const uint8_t be_nonce[16]);
int  ws_enc_seal(const uint8_t* pt, size_t pt_len, uint8_t* out, size_t out_cap);   // >0 = długość ramki, <0 błąd
int  ws_enc_open(const uint8_t* frame, size_t len, uint8_t* out, size_t out_cap);   // >=0 = długość plaintextu, <0 błąd
bool ws_enc_active();
void ws_enc_reset();
