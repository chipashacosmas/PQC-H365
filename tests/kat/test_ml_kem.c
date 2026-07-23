#include "timing.h"

#include <oqs/oqs.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void secure_free(uint8_t *ptr, size_t len) {
    if (ptr != NULL) {
        OQS_MEM_secure_free(ptr, len);
    }
}

int main(void) {
    OQS_init();

    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (kem == NULL) {
        fprintf(stderr, "failed to initialize ML-KEM-768\n");
        OQS_destroy();
        return 1;
    }

    uint8_t *public_key = malloc(kem->length_public_key);
    uint8_t *secret_key = malloc(kem->length_secret_key);
    uint8_t *ciphertext = malloc(kem->length_ciphertext);
    uint8_t *shared_secret_enc = malloc(kem->length_shared_secret);
    uint8_t *shared_secret_dec = malloc(kem->length_shared_secret);

    if (public_key == NULL || secret_key == NULL || ciphertext == NULL ||
        shared_secret_enc == NULL || shared_secret_dec == NULL) {
        fprintf(stderr, "allocation failed\n");
        free(public_key);
        secure_free(secret_key, kem->length_secret_key);
        free(ciphertext);
        secure_free(shared_secret_enc, kem->length_shared_secret);
        secure_free(shared_secret_dec, kem->length_shared_secret);
        OQS_KEM_free(kem);
        OQS_destroy();
        return 1;
    }

    uint64_t keypair_start = pqc_now_ns();
    OQS_STATUS keypair_status = OQS_KEM_keypair(kem, public_key, secret_key);
    uint64_t keypair_end = pqc_now_ns();

    uint64_t enc_start = pqc_now_ns();
    OQS_STATUS enc_status = OQS_KEM_encaps(kem, ciphertext, shared_secret_enc, public_key);
    uint64_t enc_end = pqc_now_ns();

    uint64_t dec_start = pqc_now_ns();
    OQS_STATUS dec_status = OQS_KEM_decaps(kem, shared_secret_dec, ciphertext, secret_key);
    uint64_t dec_end = pqc_now_ns();

    int secrets_match = memcmp(shared_secret_enc, shared_secret_dec, kem->length_shared_secret) == 0;

    printf("ML-KEM-768 standalone test\n");
    printf("  public key: %zu bytes\n", kem->length_public_key);
    printf("  secret key: %zu bytes\n", kem->length_secret_key);
    printf("  ciphertext: %zu bytes\n", kem->length_ciphertext);
    printf("  shared secret: %zu bytes\n", kem->length_shared_secret);
    printf("  keypair time: %.3f ms\n", pqc_elapsed_ms(keypair_start, keypair_end));
    printf("  encaps time: %.3f ms\n", pqc_elapsed_ms(enc_start, enc_end));
    printf("  decaps time: %.3f ms\n", pqc_elapsed_ms(dec_start, dec_end));

    int ok = keypair_status == OQS_SUCCESS &&
             enc_status == OQS_SUCCESS &&
             dec_status == OQS_SUCCESS &&
             secrets_match;

    printf("  result: %s\n", ok ? "PASS" : "FAIL");

    free(public_key);
    secure_free(secret_key, kem->length_secret_key);
    free(ciphertext);
    secure_free(shared_secret_enc, kem->length_shared_secret);
    secure_free(shared_secret_dec, kem->length_shared_secret);
    OQS_KEM_free(kem);
    OQS_destroy();

    return ok ? 0 : 1;
}
