#ifndef PQC_SECRET_PRINT_H
#define PQC_SECRET_PRINT_H

#include <stddef.h>
#include <stdint.h>

void pqc_print_secret_sha256_prefix(const char *label, const uint8_t *secret, size_t secret_len);

#endif

