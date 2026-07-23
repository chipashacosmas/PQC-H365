#include "hybrid_kdf.h"

#include <openssl/evp.h>
#include <openssl/kdf.h>

#include <string.h>

int pqc_hkdf_sha256(const uint8_t *input, size_t input_len,
                    const uint8_t *salt, size_t salt_len,
                    const uint8_t *info, size_t info_len,
                    uint8_t *out, size_t out_len) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (ctx == NULL) {
        return -1;
    }

    int ok = EVP_PKEY_derive_init(ctx) > 0 &&
             EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) > 0 &&
             EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt, (int)salt_len) > 0 &&
             EVP_PKEY_CTX_set1_hkdf_key(ctx, input, (int)input_len) > 0 &&
             EVP_PKEY_CTX_add1_hkdf_info(ctx, info, (int)info_len) > 0 &&
             EVP_PKEY_derive(ctx, out, &out_len) > 0;

    EVP_PKEY_CTX_free(ctx);
    return ok ? 0 : -1;
}

int pqc_hybrid_session_key(const uint8_t *x25519_secret, size_t x25519_len,
                           const uint8_t *ml_kem_secret, size_t ml_kem_len,
                           uint8_t out_key[PQC_SESSION_KEY_LEN]) {
    static const uint8_t salt[] = "pqc-hybrid-vpn-demo-salt";
    static const uint8_t info[] = "PQC_H365 hybrid session key v1";

    if (x25519_secret == NULL || ml_kem_secret == NULL || out_key == NULL ||
        x25519_len == 0 || ml_kem_len == 0) {
        return -1;
    }

    uint8_t input[64];
    if (x25519_len + ml_kem_len != sizeof(input)) {
        return -1;
    }

    memcpy(input, x25519_secret, x25519_len);
    memcpy(input + x25519_len, ml_kem_secret, ml_kem_len);

    int rc = pqc_hkdf_sha256(input, sizeof(input),
                             salt, sizeof(salt) - 1,
                             info, sizeof(info) - 1,
                             out_key, PQC_SESSION_KEY_LEN);

    OPENSSL_cleanse(input, sizeof(input));
    return rc;
}

