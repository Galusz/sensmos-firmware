#pragma once
// ══════════════════════════════════════════════════════════════
// SENSMOS SMOM — kodek ramki wiadomości node↔node po LoRa.
// Design (pełny): DOCS/dev/LORA-MESSAGING.md  (§0 pigułka, §5 ramka, §5c wnętrze).
//
// Semantyka wiadomości = TA SAMA co przez WiFi: { to, message_id, payload }.
// Ramka LoRa różni się tylko PAKOWANIEM (binarnie zamiast JSON).
//
// Ramka (RAW binary, bez Base64, bez fragmentacji — jedna wiadomość = jedna ramka):
//   nagłówek 13 B:  [0xE0][0x01] [dst3] [src3] [seq1] [vf1] [code3]
//   wnętrze (SZYFROWANE AES-256-CTR + HMAC = encrypt-then-MAC, klucze z owner-seeda):
//                   [mid_len:1B] [message_id: N B (string)] [payload: bajty usera 1:1]
//
//   0xE0        = LoRaWAN "Proprietary" (obce bramki ignorują; odróżnia od świata LoRaWAN)
//   0x01        = typ MESSAGE (bajt[1]≠'S' → nie koliduje z beaconem 0xE0 "SMOS ")
//   dst3/src3   = pierwsze 3 B device_id (24-bit); reszta kolizji odsiewa tag
//   seq         = licznik rolling per-src → DEDUPE + korelacja ACK (TRANSPORTOWY, ≠ message_id)
//   vf          = bity7-6 wersja, bity5-0 flagi (SMOM_FLAG_*)
//   code        = HMAC-SHA256(k_mac, hdr10|minuta|ciphertext)[:3]; IV CTR z dst|src|seq|minuta (minuta NIE leci w ramce)
//
// message_id  = semantyczny „eid" — to samo, po czym message_router dopasowuje slot (jak WiFi).
//               (W docu bywało nazywane „topic" — to synonim, porzucony.)
// „minuta" (ws_epoch/60) wchodzi do nonce+AAD — anty-replay w oknie ±SMOM_MINUTE_SKEW.
// Kodek jest CZYSTĄ funkcją (klucz podawany parametrem) — testowalny wektorami bez radia.
// ══════════════════════════════════════════════════════════════

#include <stdint.h>
#include <stddef.h>

#define SMOM_MAGIC0        0xE0      // LoRaWAN Proprietary MHDR
#define SMOM_TYPE_MSG      0x01      // typ ramki: message (0.95, nieużywany po modelu v2)
#define SMOM_TYPE_CMD      0x03      // typ ramki: komenda emergency (model v2) — payload ≤8 zn
#define SMOM_CMD_MAX       8         // twardy cap payloadu CMD (znaki ASCII)

#define SMOM_ID_LEN        3         // skrót device_id (pierwsze 3 B)
#define SMOM_SEQ_LEN       1
#define SMOM_VF_LEN        1
#define SMOM_CODE_LEN      3         // tag AES-GCM obcięty do 3 B
#define SMOM_HDR_LEN       (2 + SMOM_ID_LEN + SMOM_ID_LEN + SMOM_SEQ_LEN + SMOM_VF_LEN + SMOM_CODE_LEN)  // = 13

#define SMOM_MSGID_MAX     20        // == MAX_ID_LEN (config.h) — spójnie z WiFi
#define SMOM_PAYLOAD_MAX   170       // cap payloadu (>SMS 160, cichy zapas); frame ≤204 B < 255 PHY. Krótkie w praktyce; pełne 170 B @SF11 ≈ ~4 s
#define SMOM_INNER_MAX     (1 + SMOM_MSGID_MAX + SMOM_PAYLOAD_MAX)   // [mid_len][message_id][payload]
#define SMOM_FRAME_MAX     (SMOM_HDR_LEN + SMOM_INNER_MAX)

#define SMOM_KEY_LEN       32        // owner-seed (wejście do HKDF: k_enc + k_mac)
#define SMOM_MINUTE_SKEW   2         // ± ile minut akceptujemy (rozjazd zegarów, jak beacon)

// vf: wersja + flagi
#define SMOM_VER           0         // bieżąca wersja formatu (0..3)
#define SMOM_VF_VER_SHIFT  6
#define SMOM_FLAG_ACKREQ   0x01      // nadawca prosi o ACK
#define SMOM_FLAG_DOWNLINK 0x02      // ramka nadana przez przekaźnika na zlecenie BE (do adresata offline)
#define SMOM_FLAG_ENC      0x04      // payload zaszyfrowany (domyślnie 1 dla MESSAGE)

struct SmomMsg {
    uint8_t type;                               // SMOM_TYPE_* (0 = MSG dla zgodności)
    uint8_t dst[SMOM_ID_LEN];
    uint8_t src[SMOM_ID_LEN];
    uint8_t seq;
    uint8_t flags;                              // SMOM_FLAG_*  (wersja doklejana przy enkodowaniu)
    char    message_id[SMOM_MSGID_MAX + 1];     // NUL-terminated (semantyczny eid — jak przez WiFi)
    uint8_t payload[SMOM_PAYLOAD_MAX];
    uint8_t payload_len;
};

// Enkoduje `m` do bufora `out` (pojemność out_cap ≥ SMOM_FRAME_MAX).
//   key    = owner-seed 32 B (HKDF → k_enc/k_mac wewnątrz)
//   minute = ws_epoch_now()/60 (nonce + AAD)
// Zwraca długość ramki w bajtach, albo 0 przy błędzie (za mały bufor / za długi message_id|payload).
size_t smom_encode(const SmomMsg* m, const uint8_t key[SMOM_KEY_LEN],
                   uint32_t minute, uint8_t* out, size_t out_cap);

// Dekoduje + WERYFIKUJE ramkę `buf`(`len`) kluczem `key`.
//   minute_now = bieżąca minuta (okno ±SMOM_MINUTE_SKEW dla anty-replay)
//   self_id3   = pierwsze 3 B WŁASNEGO device_id (do ustalenia „czy do mnie")
//   is_for_me  = out: dst == self_id3 (odbiór bezpośredni vs kandydat na przekaźnik)
// Zwraca true gdy: magic/typ OK, rozmiar OK, tag AES-GCM się zgadza w oknie czasu.
// false = nie nasza ramka / zły tag / poza oknem. Przy true `out` wypełnione (odszyfrowane).
bool smom_decode(const uint8_t* buf, size_t len, const uint8_t key[SMOM_KEY_LEN],
                 uint32_t minute_now, const uint8_t self_id3[SMOM_ID_LEN],
                 SmomMsg* out, bool* is_for_me);

// Pomocnik: „czy to w ogóle nasza binarna ramka SMOM" (tani pre-filtr przed pełnym decode).
static inline bool smom_is_frame(const uint8_t* buf, size_t len) {
    return len >= SMOM_HDR_LEN && buf[0] == SMOM_MAGIC0 &&
           (buf[1] == SMOM_TYPE_MSG || buf[1] == SMOM_TYPE_CMD);
}
