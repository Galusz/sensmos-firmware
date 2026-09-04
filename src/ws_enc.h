#pragma once
#include <Arduino.h>

// SENSMOS — szyfrowanie+integralność kanału WS BE↔FW (0.61+).
// Klucz sesji = HKDF-SHA256( ECDH(node_priv, BE_pub), salt = fw_nonce||be_nonce ).
// Osobne podklucze kierunkowe; ramka [ver(1)|seq(8 BE)|tag(16)|ciphertext] = AES-128-GCM.
// seq jest jednocześnie IV (unikalny per ramka) i licznikiem anty-replay w sesji.
// Zastępuje K3/podpisy-batch — tag GCM uwierzytelnia KAŻDĄ ramkę w obu kierunkach.

// Wersje ramki (bajt 0, objęty AAD — nikt jej nie przemianuje bez unieważnienia tagu):
//   0x01 — plaintext to JSON, trafia do handle_message (sterowanie, telemetria, wszystko)
//   0x02 — plaintext to [tid u16 BE][ramka tunelu], omija JSON i ArduinoJson (v2, 1.01+)
#define WS_ENC_VER_JSON 0x01
#define WS_ENC_VER_TUN  0x02

bool ws_enc_derive(const uint8_t fw_nonce[16], const uint8_t be_nonce[16]);
int  ws_enc_seal(const uint8_t* pt, size_t pt_len, uint8_t* out, size_t out_cap);   // >0 = długość ramki, <0 błąd

// Warianty z jawną wersją — ta sama sesja, ten sam licznik seq i ta sama ochrona przed
// powtórką. `ver_out` (może być nullptr) mówi, co przyszło.
int  ws_enc_seal_ver(uint8_t ver, const uint8_t* pt, size_t pt_len, uint8_t* out, size_t out_cap);
int  ws_enc_open_ver(const uint8_t* frame, size_t len, uint8_t* out, size_t out_cap, uint8_t* ver_out);
bool ws_enc_active();
void ws_enc_reset();

// Seed kodu beaconu LoRa (0.92): HKDF( ECDH(node_priv, BE_pub), salt=0^32,
// info="sensmos-lora-beacon-v1" )[0:16]. Liczony lokalnie z klucza tożsamości (NVS),
// BE liczy to samo z devices.pubkey — nic nie jest przesyłane, przeżywa restart.
bool ws_enc_beacon_seed(uint8_t out[16]);
