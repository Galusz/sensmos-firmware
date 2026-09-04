#include "smom.h"
#include <string.h>
#include "mbedtls/hkdf.h"
#include "mbedtls/md.h"
#include "mbedtls/aes.h"

// Klucze z owner-seeda: HKDF-SHA256 → k_enc(32) || k_mac(32).
static void smom_keys(const uint8_t seed[SMOM_KEY_LEN], uint8_t k_enc[32], uint8_t k_mac[32]) {
    const mbedtls_md_info_t* md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    static const uint8_t info[] = "sensmos-smom-v1";
    uint8_t okm[64];
    mbedtls_hkdf(md, nullptr, 0, seed, SMOM_KEY_LEN, info, sizeof(info) - 1, okm, sizeof(okm));
    memcpy(k_enc, okm, 32);
    memcpy(k_mac, okm + 32, 32);
}

// IV dla CTR (16 B) — odtwarzalny po obu stronach: dst|src|seq|minuta(LE)|pad0.
static void smom_iv(const uint8_t dst[3], const uint8_t src[3], uint8_t seq, uint32_t minute, uint8_t iv[16]) {
    memset(iv, 0, 16);
    memcpy(iv, dst, 3);
    memcpy(iv + 3, src, 3);
    iv[6] = seq;
    iv[7]  = (uint8_t)(minute & 0xff);
    iv[8]  = (uint8_t)((minute >> 8) & 0xff);
    iv[9]  = (uint8_t)((minute >> 16) & 0xff);
    iv[10] = (uint8_t)((minute >> 24) & 0xff);
}

static void smom_ctr(const uint8_t k_enc[32], const uint8_t iv[16],
                     const uint8_t* in, size_t len, uint8_t* out) {
    mbedtls_aes_context a;
    mbedtls_aes_init(&a);
    mbedtls_aes_setkey_enc(&a, k_enc, 256);
    uint8_t nc[16]; memcpy(nc, iv, 16);
    uint8_t sb[16]; size_t off = 0;
    mbedtls_aes_crypt_ctr(&a, len, &off, nc, sb, in, out);
    mbedtls_aes_free(&a);
}

// code = HMAC-SHA256(k_mac, hdr10 | minuta(LE,4) | ciphertext)[:3]
// hdr10 = magic(2)|dst(3)|src(3)|seq(1)|vf(1) = pierwsze 10 B ramki (BEZ pola code).
static void smom_code(const uint8_t k_mac[32], const uint8_t hdr10[10], uint32_t minute,
                      const uint8_t* ct, size_t ct_len, uint8_t out3[3]) {
    const mbedtls_md_info_t* md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_md_context_t c;
    mbedtls_md_init(&c);
    mbedtls_md_setup(&c, md, 1);
    mbedtls_md_hmac_starts(&c, k_mac, 32);
    mbedtls_md_hmac_update(&c, hdr10, 10);
    uint8_t mb[4] = { (uint8_t)(minute & 0xff), (uint8_t)((minute >> 8) & 0xff),
                      (uint8_t)((minute >> 16) & 0xff), (uint8_t)((minute >> 24) & 0xff) };
    mbedtls_md_hmac_update(&c, mb, 4);
    mbedtls_md_hmac_update(&c, ct, ct_len);
    uint8_t full[32];
    mbedtls_md_hmac_finish(&c, full);
    mbedtls_md_free(&c);
    memcpy(out3, full, 3);
}


bool smom_decode(const uint8_t* buf, size_t len, const uint8_t key[SMOM_KEY_LEN],
                 uint32_t minute_now, const uint8_t self_id3[SMOM_ID_LEN],
                 SmomMsg* out, bool* is_for_me) {
    if (!smom_is_frame(buf, len) || len < SMOM_HDR_LEN + 1) return false;
    size_t inner = len - SMOM_HDR_LEN;
    if (inner > SMOM_INNER_MAX) return false;

    uint8_t dst[3], src[3];
    memcpy(dst, buf + 2, 3);
    memcpy(src, buf + 5, 3);
    uint8_t seq = buf[8];
    uint8_t vf  = buf[9];
    const uint8_t* code = buf + 10;
    const uint8_t* ct   = buf + SMOM_HDR_LEN;

    uint8_t k_enc[32], k_mac[32];
    smom_keys(key, k_enc, k_mac);

    for (int32_t d = -SMOM_MINUTE_SKEW; d <= SMOM_MINUTE_SKEW; d++) {
        uint32_t m = minute_now + (uint32_t)d;
        uint8_t expect[3];
        smom_code(k_mac, buf, m, ct, inner, expect);
        if (memcmp(expect, code, 3) != 0) continue;

        // zweryfikowane → odszyfruj
        uint8_t iv[16];
        smom_iv(dst, src, seq, m, iv);
        uint8_t pt[SMOM_INNER_MAX];
        smom_ctr(k_enc, iv, ct, inner, pt);

        uint8_t mid = pt[0];
        if ((size_t)(1 + mid) > inner || mid > SMOM_MSGID_MAX) return false;
        size_t pl = inner - 1 - mid;
        if (pl > SMOM_PAYLOAD_MAX) return false;

        memset(out, 0, sizeof(*out));
        out->type = buf[1];
        memcpy(out->dst, dst, 3);
        memcpy(out->src, src, 3);
        out->seq   = seq;
        out->flags = vf & 0x3f;
        memcpy(out->message_id, pt + 1, mid);
        out->message_id[mid] = 0;
        memcpy(out->payload, pt + 1 + mid, pl);
        out->payload_len = (uint8_t)pl;
        if (is_for_me) *is_for_me = (memcmp(dst, self_id3, SMOM_ID_LEN) == 0);
        return true;
    }
    return false;
}
