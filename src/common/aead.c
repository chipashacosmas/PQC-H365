#include "aead.h"

#include <openssl/evp.h>

int pqc_aes256_gcm_encrypt(const uint8_t key[32],
                           const uint8_t nonce[PQC_AES_GCM_NONCE_LEN],
                           const uint8_t *plaintext, size_t plaintext_len,
                           const uint8_t *aad, size_t aad_len,
                           uint8_t *ciphertext,
                           uint8_t tag[PQC_AES_GCM_TAG_LEN]) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return -1;
    }

    int len = 0;
    int ciphertext_len = 0;
    int ok = EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) == 1 &&
             EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, PQC_AES_GCM_NONCE_LEN, NULL) == 1 &&
             EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) == 1;

    if (ok && aad != NULL && aad_len > 0) {
        ok = EVP_EncryptUpdate(ctx, NULL, &len, aad, (int)aad_len) == 1;
    }
    if (ok) {
        ok = EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, (int)plaintext_len) == 1;
        ciphertext_len = len;
    }
    if (ok) {
        ok = EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, &len) == 1;
        ciphertext_len += len;
    }
    if (ok) {
        ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, PQC_AES_GCM_TAG_LEN, tag) == 1;
    }

    EVP_CIPHER_CTX_free(ctx);
    return ok ? ciphertext_len : -1;
}

int pqc_aes256_gcm_decrypt(const uint8_t key[32],
                           const uint8_t nonce[PQC_AES_GCM_NONCE_LEN],
                           const uint8_t *ciphertext, size_t ciphertext_len,
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t tag[PQC_AES_GCM_TAG_LEN],
                           uint8_t *plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return -1;
    }

    int len = 0;
    int plaintext_len = 0;
    int ok = EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) == 1 &&
             EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, PQC_AES_GCM_NONCE_LEN, NULL) == 1 &&
             EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) == 1;

    if (ok && aad != NULL && aad_len > 0) {
        ok = EVP_DecryptUpdate(ctx, NULL, &len, aad, (int)aad_len) == 1;
    }
    if (ok) {
        ok = EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, (int)ciphertext_len) == 1;
        plaintext_len = len;
    }
    if (ok) {
        ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, PQC_AES_GCM_TAG_LEN, (void *)tag) == 1;
    }
    if (ok) {
        ok = EVP_DecryptFinal_ex(ctx, plaintext + plaintext_len, &len) == 1;
        plaintext_len += len;
    }

    EVP_CIPHER_CTX_free(ctx);
    return ok ? plaintext_len : -1;
}

