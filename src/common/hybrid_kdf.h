#ifndef PQC_HYBRID_KDF_H
#define PQC_HYBRID_KDF_H

#include <stddef.h>
#include <stdint.h>

#define PQC_SESSION_KEY_LEN 32U

int pqc_hkdf_sha256(const uint8_t *input, size_t input_len,
                    const uint8_t *salt, size_t salt_len,
                    const uint8_t *info, size_t info_len,
                    uint8_t *out, size_t out_len);

int pqc_hybrid_session_key(const uint8_t *x25519_secret, size_t x25519_len,
                           const uint8_t *ml_kem_secret, size_t ml_kem_len,
                           uint8_t out_key[PQC_SESSION_KEY_LEN]);

#endif

