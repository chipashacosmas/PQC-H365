#include "timing.h"

#include <openssl/evp.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

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

int main(void) {
    uint8_t alice_secret[32];
    uint8_t bob_secret[32];
    size_t alice_secret_len = sizeof(alice_secret);
    size_t bob_secret_len = sizeof(bob_secret);

    uint64_t alice_key_start = pqc_now_ns();
    EVP_PKEY *alice_key = generate_x25519_key();
    uint64_t alice_key_end = pqc_now_ns();

    uint64_t bob_key_start = pqc_now_ns();
    EVP_PKEY *bob_key = generate_x25519_key();
    uint64_t bob_key_end = pqc_now_ns();

    if (alice_key == NULL || bob_key == NULL) {
        fprintf(stderr, "X25519 key generation failed\n");
        EVP_PKEY_free(alice_key);
        EVP_PKEY_free(bob_key);
        return 1;
    }

    uint64_t alice_derive_start = pqc_now_ns();
    int alice_status = derive_x25519_secret(alice_key, bob_key, alice_secret, &alice_secret_len);
    uint64_t alice_derive_end = pqc_now_ns();

    uint64_t bob_derive_start = pqc_now_ns();
    int bob_status = derive_x25519_secret(bob_key, alice_key, bob_secret, &bob_secret_len);
    uint64_t bob_derive_end = pqc_now_ns();

    int secrets_match = alice_secret_len == bob_secret_len &&
                        memcmp(alice_secret, bob_secret, alice_secret_len) == 0;

    printf("X25519 standalone test\n");
    printf("  shared secret: %zu bytes\n", alice_secret_len);
    printf("  alice keypair time: %.3f ms\n", pqc_elapsed_ms(alice_key_start, alice_key_end));
    printf("  bob keypair time: %.3f ms\n", pqc_elapsed_ms(bob_key_start, bob_key_end));
    printf("  alice derive time: %.3f ms\n", pqc_elapsed_ms(alice_derive_start, alice_derive_end));
    printf("  bob derive time: %.3f ms\n", pqc_elapsed_ms(bob_derive_start, bob_derive_end));

    int ok = alice_status == 0 && bob_status == 0 && secrets_match;
    printf("  result: %s\n", ok ? "PASS" : "FAIL");

    OPENSSL_cleanse(alice_secret, sizeof(alice_secret));
    OPENSSL_cleanse(bob_secret, sizeof(bob_secret));
    EVP_PKEY_free(alice_key);
    EVP_PKEY_free(bob_key);

    return ok ? 0 : 1;
}
