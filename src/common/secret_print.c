#include "secret_print.h"

#include <openssl/sha.h>

#include <stdio.h>

void pqc_print_secret_sha256_prefix(const char *label, const uint8_t *secret, size_t secret_len) {
    uint8_t digest[SHA256_DIGEST_LENGTH];
    SHA256(secret, secret_len, digest);

    printf("%s SHA256 prefix: ", label);
    for (size_t i = 0; i < 8; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");
}

