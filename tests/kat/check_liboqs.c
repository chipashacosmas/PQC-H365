#include <oqs/oqs.h>

#include <stdio.h>

static int check_kem(const char *name) {
    if (OQS_KEM_alg_is_enabled(name) != 1) {
        fprintf(stderr, "KEM not enabled: %s\n", name);
        return -1;
    }

    OQS_KEM *kem = OQS_KEM_new(name);
    if (kem == NULL) {
        fprintf(stderr, "KEM allocation failed: %s\n", name);
        return -1;
    }

    printf("KEM OK: %s\n", kem->method_name);
    printf("  public key: %zu bytes\n", kem->length_public_key);
    printf("  secret key: %zu bytes\n", kem->length_secret_key);
    printf("  ciphertext: %zu bytes\n", kem->length_ciphertext);
    printf("  shared secret: %zu bytes\n", kem->length_shared_secret);

    OQS_KEM_free(kem);
    return 0;
}

static int check_sig(const char *name) {
    if (OQS_SIG_alg_is_enabled(name) != 1) {
        fprintf(stderr, "SIG not enabled: %s\n", name);
        return -1;
    }

    OQS_SIG *sig = OQS_SIG_new(name);
    if (sig == NULL) {
        fprintf(stderr, "SIG allocation failed: %s\n", name);
        return -1;
    }

    printf("SIG OK: %s\n", sig->method_name);
    printf("  public key: %zu bytes\n", sig->length_public_key);
    printf("  secret key: %zu bytes\n", sig->length_secret_key);
    printf("  signature: %zu bytes\n", sig->length_signature);

    OQS_SIG_free(sig);
    return 0;
}

int main(void) {
    OQS_init();

    int rc = 0;
    rc |= check_kem(OQS_KEM_alg_ml_kem_768);
    rc |= check_sig(OQS_SIG_alg_ml_dsa_65);

    OQS_destroy();
    return rc == 0 ? 0 : 1;
}
