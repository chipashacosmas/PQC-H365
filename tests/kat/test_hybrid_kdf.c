#include "secret_print.h"
#include "timing.h"

#include <oqs/oqs.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SHARED_SECRET_LEN 32U
#define HYBRID_INPUT_LEN 64U
#define SESSION_KEY_LEN 32U

static EVP_PKEY *generate_x25519_key(void) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (ctx == NULL) {
        return NULL;
    }

    EVP_PKEY *key = NULL;
    if (EVP_PKEY_keygen_init(ctx) <= 0 || EVP_PKEY_keygen(ctx, &key) <= 0) {
        EVP_PKEY_free(key);
        key = NULL;
    }

    EVP_PKEY_CTX_free(ctx);
    return key;
}

static int derive_x25519_secret(EVP_PKEY *private_key, EVP_PKEY *peer_public_key,
                                uint8_t *secret, size_t *secret_len) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(private_key, NULL);
    if (ctx == NULL) {
        return -1;
    }

    int ok = EVP_PKEY_derive_init(ctx) > 0 &&
             EVP_PKEY_derive_set_peer(ctx, peer_public_key) > 0 &&
             EVP_PKEY_derive(ctx, secret, secret_len) > 0;

    EVP_PKEY_CTX_free(ctx);
    return ok ? 0 : -1;
}

static int hkdf_sha256(const uint8_t *input, size_t input_len,
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

static int run_x25519(uint8_t *out_secret) {
    EVP_PKEY *alice_key = generate_x25519_key();
    EVP_PKEY *bob_key = generate_x25519_key();
    if (alice_key == NULL || bob_key == NULL) {
        EVP_PKEY_free(alice_key);
        EVP_PKEY_free(bob_key);
        return -1;
    }

    size_t secret_len = SHARED_SECRET_LEN;
    int rc = derive_x25519_secret(alice_key, bob_key, out_secret, &secret_len);
    EVP_PKEY_free(alice_key);
    EVP_PKEY_free(bob_key);

    return rc == 0 && secret_len == SHARED_SECRET_LEN ? 0 : -1;
}

static int run_ml_kem(uint8_t *out_secret) {
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (kem == NULL) {
        return -1;
    }

    uint8_t *public_key = malloc(kem->length_public_key);
    uint8_t *secret_key = malloc(kem->length_secret_key);
    uint8_t *ciphertext = malloc(kem->length_ciphertext);
    uint8_t *enc_secret = malloc(kem->length_shared_secret);

    if (public_key == NULL || secret_key == NULL || ciphertext == NULL || enc_secret == NULL) {
        free(public_key);
        OQS_MEM_secure_free(secret_key, kem->length_secret_key);
        free(ciphertext);
        OQS_MEM_secure_free(enc_secret, kem->length_shared_secret);
        OQS_KEM_free(kem);
        return -1;
    }

    int ok = OQS_KEM_keypair(kem, public_key, secret_key) == OQS_SUCCESS &&
             OQS_KEM_encaps(kem, ciphertext, enc_secret, public_key) == OQS_SUCCESS &&
             OQS_KEM_decaps(kem, out_secret, ciphertext, secret_key) == OQS_SUCCESS &&
             memcmp(enc_secret, out_secret, kem->length_shared_secret) == 0;

    free(public_key);
    OQS_MEM_secure_free(secret_key, kem->length_secret_key);
    free(ciphertext);
    OQS_MEM_secure_free(enc_secret, kem->length_shared_secret);
    OQS_KEM_free(kem);

    return ok ? 0 : -1;
}

int main(void) {
    static const uint8_t salt[] = "pqc-hybrid-vpn-demo-salt";
    static const uint8_t info[] = "PQC_H365 hybrid session key v1";

    uint8_t x25519_secret[SHARED_SECRET_LEN];
    uint8_t ml_kem_secret[SHARED_SECRET_LEN];
    uint8_t hybrid_input[HYBRID_INPUT_LEN];
    uint8_t session_key[SESSION_KEY_LEN];

    OQS_init();

    uint64_t x_start = pqc_now_ns();
    int x_status = run_x25519(x25519_secret);
    uint64_t x_end = pqc_now_ns();

    uint64_t kem_start = pqc_now_ns();
    int kem_status = run_ml_kem(ml_kem_secret);
    uint64_t kem_end = pqc_now_ns();

    memcpy(hybrid_input, x25519_secret, SHARED_SECRET_LEN);
    memcpy(hybrid_input + SHARED_SECRET_LEN, ml_kem_secret, SHARED_SECRET_LEN);

    uint64_t hkdf_start = pqc_now_ns();
    int hkdf_status = hkdf_sha256(hybrid_input, sizeof(hybrid_input),
                                  salt, sizeof(salt) - 1,
                                  info, sizeof(info) - 1,
                                  session_key, sizeof(session_key));
    uint64_t hkdf_end = pqc_now_ns();

    int ok = x_status == 0 && kem_status == 0 && hkdf_status == 0;

    printf("Hybrid KDF standalone test\n");
    printf("  X25519 secret: %u bytes\n", SHARED_SECRET_LEN);
    printf("  ML-KEM secret: %u bytes\n", SHARED_SECRET_LEN);
    printf("  HKDF input: %u bytes\n", HYBRID_INPUT_LEN);
    printf("  session key: %u bytes\n", SESSION_KEY_LEN);
    printf("  X25519 generation+derive time: %.3f ms\n", pqc_elapsed_ms(x_start, x_end));
    printf("  ML-KEM full cycle time: %.3f ms\n", pqc_elapsed_ms(kem_start, kem_end));
    printf("  HKDF-SHA256 time: %.3f ms\n", pqc_elapsed_ms(hkdf_start, hkdf_end));
    pqc_print_secret_sha256_prefix("session key", session_key, sizeof(session_key));
    printf("  result: %s\n", ok ? "PASS" : "FAIL");

    OPENSSL_cleanse(x25519_secret, sizeof(x25519_secret));
    OQS_MEM_cleanse(ml_kem_secret, sizeof(ml_kem_secret));
    OPENSSL_cleanse(hybrid_input, sizeof(hybrid_input));
    OPENSSL_cleanse(session_key, sizeof(session_key));
    OQS_destroy();

    return ok ? 0 : 1;
}
