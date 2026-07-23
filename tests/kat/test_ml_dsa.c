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
    static const uint8_t message[] = "PQC hybrid VPN ML-DSA-65 signature test message";
    const size_t message_len = sizeof(message) - 1;

    OQS_init();

    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    if (sig == NULL) {
        fprintf(stderr, "failed to initialize ML-DSA-65\n");
        OQS_destroy();
        return 1;
    }

    uint8_t *public_key = malloc(sig->length_public_key);
    uint8_t *secret_key = malloc(sig->length_secret_key);
    uint8_t *signature = malloc(sig->length_signature);

    if (public_key == NULL || secret_key == NULL || signature == NULL) {
        fprintf(stderr, "allocation failed\n");
        free(public_key);
        secure_free(secret_key, sig->length_secret_key);
        free(signature);
        OQS_SIG_free(sig);
        OQS_destroy();
        return 1;
    }

    size_t signature_len = 0;

    uint64_t keypair_start = pqc_now_ns();
    OQS_STATUS keypair_status = OQS_SIG_keypair(sig, public_key, secret_key);
    uint64_t keypair_end = pqc_now_ns();

    uint64_t sign_start = pqc_now_ns();
    OQS_STATUS sign_status = OQS_SIG_sign(sig, signature, &signature_len, message, message_len, secret_key);
    uint64_t sign_end = pqc_now_ns();

    uint64_t verify_start = pqc_now_ns();
    OQS_STATUS verify_status = OQS_SIG_verify(sig, message, message_len, signature, signature_len, public_key);
    uint64_t verify_end = pqc_now_ns();

    printf("ML-DSA-65 standalone test\n");
    printf("  public key: %zu bytes\n", sig->length_public_key);
    printf("  secret key: %zu bytes\n", sig->length_secret_key);
    printf("  max signature: %zu bytes\n", sig->length_signature);
    printf("  actual signature: %zu bytes\n", signature_len);
    printf("  keypair time: %.3f ms\n", pqc_elapsed_ms(keypair_start, keypair_end));
    printf("  sign time: %.3f ms\n", pqc_elapsed_ms(sign_start, sign_end));
    printf("  verify time: %.3f ms\n", pqc_elapsed_ms(verify_start, verify_end));

    int ok = keypair_status == OQS_SUCCESS &&
             sign_status == OQS_SUCCESS &&
             verify_status == OQS_SUCCESS;

    printf("  result: %s\n", ok ? "PASS" : "FAIL");

    free(public_key);
    secure_free(secret_key, sig->length_secret_key);
    free(signature);
    OQS_SIG_free(sig);
    OQS_destroy();

    return ok ? 0 : 1;
}
