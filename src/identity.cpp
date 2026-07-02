#include "identity.h"

uint8_t g_privkey[32]    = {0};
uint8_t g_pubkey[65]     = {0};
char    g_device_id[67]  = {0};
char    g_eth_address[43]= {0};
char    g_api_token[65]  = {0};

void bytes_to_hex(const uint8_t* bytes, size_t len, char* out) {
    for (size_t i = 0; i < len; i++) {
        sprintf(out + i * 2, "%02x", bytes[i]);
    }
    out[len * 2] = '\0';
}

void sha256_string(const char* input, uint8_t* output) {
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, (const uint8_t*)input, strlen(input));
    mbedtls_sha256_finish(&ctx, output);
    mbedtls_sha256_free(&ctx);
}

static void compute_eth_address(const uint8_t* pubkey65) {
    uint8_t hash[32];
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, pubkey65 + 1, 64);
    mbedtls_sha256_finish(&ctx, hash);
    mbedtls_sha256_free(&ctx);
    g_eth_address[0] = '0';
    g_eth_address[1] = 'x';
    bytes_to_hex(hash + 12, 20, g_eth_address + 2);
}

static void compute_device_id() {
    char input[200];
    char pubkey_hex[131];
    bytes_to_hex(g_pubkey, 65, pubkey_hex);
    uint8_t mac[6];
    esp_read_mac(mac, ESP_MAC_WIFI_STA);
    char mac_hex[13];
    bytes_to_hex(mac, 6, mac_hex);
    snprintf(input, sizeof(input), "%s%s", pubkey_hex, mac_hex);
    uint8_t hash[32];
    sha256_string(input, hash);
    bytes_to_hex(hash, 32, g_device_id);
}

bool identity_regenerate_token() {
    uint8_t token_bytes[32];
    esp_fill_random(token_bytes, 32);
    bytes_to_hex(token_bytes, 32, g_api_token);
    Preferences prefs;
    prefs.begin("sensmos", false);
    prefs.putBytes("api_token", token_bytes, 32);
    prefs.end();
    Serial.println("[Identity] Nowy API token wygenerowany");
    return true;
}

bool identity_init() {
    Preferences prefs;
    prefs.begin("sensmos", false);
    bool has_key = prefs.isKey("privkey");

    if (!has_key) {
        Serial.println("[Identity] Generuję nowy keypair...");

        mbedtls_entropy_context  entropy;
        mbedtls_ctr_drbg_context ctr_drbg;
        mbedtls_entropy_init(&entropy);
        mbedtls_ctr_drbg_init(&ctr_drbg);

        const char* pers = "sensmos_esp32";
        mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
            (const uint8_t*)pers, strlen(pers));

        mbedtls_ecdsa_context ecdsa;
        mbedtls_ecdsa_init(&ecdsa);
        mbedtls_ecdsa_genkey(&ecdsa, MBEDTLS_ECP_DP_SECP256K1,
            mbedtls_ctr_drbg_random, &ctr_drbg);

        mbedtls_mpi_write_binary(&ecdsa.MBEDTLS_PRIVATE(d), g_privkey, 32);
        g_pubkey[0] = 0x04;
        mbedtls_mpi_write_binary(&ecdsa.MBEDTLS_PRIVATE(Q).MBEDTLS_PRIVATE(X), g_pubkey + 1,  32);
        mbedtls_mpi_write_binary(&ecdsa.MBEDTLS_PRIVATE(Q).MBEDTLS_PRIVATE(Y), g_pubkey + 33, 32);

        prefs.putBytes("privkey", g_privkey, 32);
        prefs.putBytes("pubkey",  g_pubkey,  65);

        mbedtls_ecdsa_free(&ecdsa);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);

        Serial.println("[Identity] Keypair zapisany w NVS");
    } else {
        prefs.getBytes("privkey", g_privkey, 32);
        prefs.getBytes("pubkey",  g_pubkey,  65);
        Serial.println("[Identity] Keypair wczytany z NVS");
    }

    if (!prefs.isKey("api_token")) {
        uint8_t token_bytes[32];
        esp_fill_random(token_bytes, 32);
        bytes_to_hex(token_bytes, 32, g_api_token);
        prefs.putBytes("api_token", token_bytes, 32);
    } else {
        uint8_t token_bytes[32];
        prefs.getBytes("api_token", token_bytes, 32);
        bytes_to_hex(token_bytes, 32, g_api_token);
    }

    prefs.end();
    compute_device_id();
    compute_eth_address(g_pubkey);

    char pubkey_hex[131];
    identity_get_pubkey_hex(pubkey_hex, sizeof(pubkey_hex));
    Serial.printf("[Identity] PubKey: %s\n", pubkey_hex);
    Serial.printf("[Identity] Device ID:   %s\n", g_device_id);
    Serial.printf("[Identity] ETH Address: %s\n", g_eth_address);
    return true;
}

bool identity_sign(const uint8_t* hash, uint8_t* sig_out, size_t* sig_len) {
    mbedtls_entropy_context  entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ecdsa_context    ecdsa;

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_ecdsa_init(&ecdsa);

    const char* pers = "sensmos_sign";
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
        (const uint8_t*)pers, strlen(pers));

    mbedtls_ecp_group_load(&ecdsa.MBEDTLS_PRIVATE(grp), MBEDTLS_ECP_DP_SECP256K1);
    mbedtls_mpi_read_binary(&ecdsa.MBEDTLS_PRIVATE(d), g_privkey, 32);

    int ret = mbedtls_ecdsa_write_signature(
        &ecdsa, MBEDTLS_MD_SHA256,
        hash, 32, sig_out, 72, sig_len,
        mbedtls_ctr_drbg_random, &ctr_drbg
    );

    mbedtls_ecdsa_free(&ecdsa);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    return ret == 0;
}

// K3: klucz publiczny BE (secp256k1 uncompressed) — wbudowany, do weryfikacji komend BE→node.
// Publiczny → bezpieczny w firmware. Priv trzyma tylko serwer (.env BE_SIGN_PRIV).
static const char* BE_PUBKEY_HEX =
    "042e5d120dcd4324edb14b7a694b0868f1df9ef0f3b8ecd7580702482413f58183b6f10b55ea2b643cfcf01880ef120db3cfadbda87f62c487b458d0a3000d5117";

bool identity_verify_be(const char* message, const uint8_t* sig_der, size_t sig_len) {
    uint8_t be_pub[65];
    for (int i = 0; i < 65; i++) { unsigned v; if (sscanf(BE_PUBKEY_HEX + i*2, "%2x", &v) != 1) return false; be_pub[i] = (uint8_t)v; }

    uint8_t hash[32];
    sha256_string(message, hash);   // ten sam SHA256 co BE (crypto.createSign('SHA256'))

    mbedtls_ecdsa_context ecdsa;
    mbedtls_ecdsa_init(&ecdsa);
    int ret = mbedtls_ecp_group_load(&ecdsa.MBEDTLS_PRIVATE(grp), MBEDTLS_ECP_DP_SECP256K1);
    if (ret == 0) ret = mbedtls_ecp_point_read_binary(&ecdsa.MBEDTLS_PRIVATE(grp), &ecdsa.MBEDTLS_PRIVATE(Q), be_pub, 65);
    if (ret == 0) ret = mbedtls_ecdsa_read_signature(&ecdsa, hash, 32, sig_der, sig_len);
    mbedtls_ecdsa_free(&ecdsa);
    return ret == 0;
}

void identity_get_pubkey_hex(char* out, size_t len) {
    bytes_to_hex(g_pubkey, 65, out);
}
