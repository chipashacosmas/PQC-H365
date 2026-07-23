#ifndef PQC_AEAD_H
#define PQC_AEAD_H

#include <stddef.h>
#include <stdint.h>

#define PQC_AES_GCM_NONCE_LEN 12U
#define PQC_AES_GCM_TAG_LEN 16U

int pqc_aes256_gcm_encrypt(const uint8_t key[32],
                           const uint8_t nonce[PQC_AES_GCM_NONCE_LEN],
                           const uint8_t *plaintext, size_t plaintext_len,
                           const uint8_t *aad, size_t aad_len,
                           uint8_t *ciphertext,
                           uint8_t tag[PQC_AES_GCM_TAG_LEN]);

int pqc_aes256_gcm_decrypt(const uint8_t key[32],
                           const uint8_t nonce[PQC_AES_GCM_NONCE_LEN],
                           const uint8_t *ciphertext, size_t ciphertext_len,
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t tag[PQC_AES_GCM_TAG_LEN],
                           uint8_t *plaintext);

#endif

