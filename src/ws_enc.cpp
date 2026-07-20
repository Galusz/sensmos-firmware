#include "ws_enc.h"
#include "identity.h"
#include "log.h"
#include <string.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/ecp.h>
#include <mbedtls/bignum.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/md.h>
#include <mbedtls/gcm.h>

static bool     s_ready   = false;
static uint8_t  s_key_tx[16] = {0};   // FW→BE
static uint8_t  s_key_rx[16] = {0};   // BE→FW
static uint64_t s_seq_tx  = 0;
static uint64_t s_seq_rx  = 0;
static bool     s_rx_init = false;

void ws_enc_reset() {
    s_ready = false; s_seq_tx = 0; s_seq_rx = 0; s_rx_init = false;
    memset(s_key_tx, 0, 16); memset(s_key_rx, 0, 16);
}
bool ws_enc_active() { return s_ready; }

static void hmac_sha256(const uint8_t* key, size_t klen,
                        const uint8_t* d, size_t dlen, uint8_t out[32]) {
    mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), key, klen, d, dlen, out);
}

// ECDH(node_priv, BE_pub) → shared.X, potem HKDF-SHA256 → dwa podklucze 16B.
// FW: tx = okm[0:16] (FW→BE), rx = okm[16:32] (BE→FW). BE bierze odwrotnie.
bool ws_enc_derive(const uint8_t fw_nonce[16], const uint8_t be_nonce[16]) {
    ws_enc_reset();
    uint8_t be_pub[65];
    if (!identity_be_pubkey(be_pub)) { LOGE("wsenc", "no BE pubkey"); return false; }

    mbedtls_ecp_group grp;  mbedtls_ecp_point Qp;
    mbedtls_mpi d, z;       mbedtls_entropy_context ent; mbedtls_ctr_drbg_context drbg;
    mbedtls_ecp_group_init(&grp); mbedtls_ecp_point_init(&Qp);
    mbedtls_mpi_init(&d); mbedtls_mpi_init(&z);
    mbedtls_entropy_init(&ent); mbedtls_ctr_drbg_init(&drbg);
    const char* pers = "sensmos_ecdh";
    bool ok = false;
    do {
        if (mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &ent, (const uint8_t*)pers, strlen(pers))) break;
        if (mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256K1)) break;
        if (mbedtls_ecp_point_read_binary(&grp, &Qp, be_pub, 65)) break;
        if (mbedtls_mpi_read_binary(&d, g_privkey, 32)) break;
        if (mbedtls_ecdh_compute_shared(&grp, &z, &Qp, &d, mbedtls_ctr_drbg_random, &drbg)) break;
        uint8_t shared[32];
        if (mbedtls_mpi_write_binary(&z, shared, 32)) break;

        // HKDF-SHA256 (extract + jedno expand — L=32 = hashlen)
        uint8_t salt[32]; memcpy(salt, fw_nonce, 16); memcpy(salt + 16, be_nonce, 16);
        uint8_t prk[32];  hmac_sha256(salt, 32, shared, 32, prk);
        const char* istr = "sensmos-ws-v1"; size_t il = strlen(istr);
        uint8_t info[16]; memcpy(info, istr, il); info[il] = 0x01;
        uint8_t okm[32];  hmac_sha256(prk, 32, info, il + 1, okm);
        memcpy(s_key_tx, okm, 16);
        memcpy(s_key_rx, okm + 16, 16);
        ok = true;
    } while (0);
    mbedtls_ecp_group_free(&grp); mbedtls_ecp_point_free(&Qp);
    mbedtls_mpi_free(&d); mbedtls_mpi_free(&z);
    mbedtls_entropy_free(&ent); mbedtls_ctr_drbg_free(&drbg);

    if (ok) { s_ready = true; LOGI("wsenc", "session key derived"); }
    else      LOGE("wsenc", "derive failed");
    return ok;
}

static void put_seq(uint8_t* p, uint64_t seq) { for (int i = 0; i < 8; i++) p[i] = (uint8_t)(seq >> (8 * (7 - i))); }
static uint64_t get_seq(const uint8_t* p) { uint64_t s = 0; for (int i = 0; i < 8; i++) s = (s << 8) | p[i]; return s; }

int ws_enc_seal(const uint8_t* pt, size_t pt_len, uint8_t* out, size_t out_cap) {
    if (!s_ready) return -1;
    size_t need = 25 + pt_len;
    if (need > out_cap) return -1;
    out[0] = 0x01; put_seq(out + 1, s_seq_tx);
    uint8_t iv[12] = {0}; memcpy(iv + 4, out + 1, 8);   // IV = 0x00000000 || seq(8)
    uint8_t* tag = out + 9;
    uint8_t* ct  = out + 25;
    mbedtls_gcm_context g; mbedtls_gcm_init(&g);
    int r = mbedtls_gcm_setkey(&g, MBEDTLS_CIPHER_ID_AES, s_key_tx, 128);
    if (r == 0) r = mbedtls_gcm_crypt_and_tag(&g, MBEDTLS_GCM_ENCRYPT, pt_len, iv, 12, out, 9, pt, ct, 16, tag);
    mbedtls_gcm_free(&g);
    if (r) return -1;
    s_seq_tx++;
    return (int)need;
}

int ws_enc_open(const uint8_t* frame, size_t len, uint8_t* out, size_t out_cap) {
    if (!s_ready) return -1;
    if (len < 25 || frame[0] != 0x01) return -1;
    uint64_t seq = get_seq(frame + 1);
    if (s_rx_init && seq <= s_seq_rx) return -1;         // replay / reorder
    size_t ct_len = len - 25;
    if (ct_len > out_cap) return -1;
    uint8_t iv[12] = {0}; memcpy(iv + 4, frame + 1, 8);
    const uint8_t* tag = frame + 9;
    const uint8_t* ct  = frame + 25;
    mbedtls_gcm_context g; mbedtls_gcm_init(&g);
    int r = mbedtls_gcm_setkey(&g, MBEDTLS_CIPHER_ID_AES, s_key_rx, 128);
    if (r == 0) r = mbedtls_gcm_auth_decrypt(&g, ct_len, iv, 12, frame, 9, tag, 16, ct, out);
    mbedtls_gcm_free(&g);
    if (r) return -1;
    s_seq_rx = seq; s_rx_init = true;
    return (int)ct_len;
}
