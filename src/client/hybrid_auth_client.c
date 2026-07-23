#include "framing.h"
#include "hybrid_kdf.h"
#include "secret_print.h"
#include "timing.h"

#include <oqs/oqs.h>
#include <openssl/evp.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define DEFAULT_PORT 4450
#define X25519_LEN 32U

static int connect_server(const char *host, uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1 ||
        connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("connect");
        close(fd);
        return -1;
    }
    return fd;
}

static EVP_PKEY *generate_x25519(void) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    EVP_PKEY *key = NULL;
    if (ctx != NULL && EVP_PKEY_keygen_init(ctx) > 0) {
        EVP_PKEY_keygen(ctx, &key);
    }
    EVP_PKEY_CTX_free(ctx);
    return key;
}

static int derive_x25519(EVP_PKEY *private_key, const uint8_t peer_public[X25519_LEN],
                         uint8_t secret[X25519_LEN]) {
    EVP_PKEY *peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer_public, X25519_LEN);
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(private_key, NULL);
    size_t secret_len = X25519_LEN;
    int ok = peer != NULL && ctx != NULL &&
             EVP_PKEY_derive_init(ctx) > 0 &&
             EVP_PKEY_derive_set_peer(ctx, peer) > 0 &&
             EVP_PKEY_derive(ctx, secret, &secret_len) > 0 &&
             secret_len == X25519_LEN;
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peer);
    return ok ? 0 : -1;
}

static size_t build_transcript(uint8_t *out,
                               const uint8_t *server_x, const uint8_t *server_kem, size_t server_kem_len,
                               const uint8_t *server_sig_pk, size_t server_sig_pk_len,
                               const uint8_t *client_x,
                               const uint8_t *client_ct, size_t client_ct_len) {
    uint8_t *p = out;
    memcpy(p, server_x, X25519_LEN);
    p += X25519_LEN;
    memcpy(p, server_kem, server_kem_len);
    p += server_kem_len;
    memcpy(p, server_sig_pk, server_sig_pk_len);
    p += server_sig_pk_len;
    memcpy(p, client_x, X25519_LEN);
    p += X25519_LEN;
    memcpy(p, client_ct, client_ct_len);
    p += client_ct_len;
    return (size_t)(p - out);
}

int main(int argc, char **argv) {
    if (argc < 2 || argc > 3) {
        fprintf(stderr, "usage: %s <server-ip> [port]\n", argv[0]);
        return 1;
    }
    uint16_t port = argc == 3 ? (uint16_t)atoi(argv[2]) : DEFAULT_PORT;

    OQS_init();
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    EVP_PKEY *x_key = generate_x25519();
    if (kem == NULL || sig == NULL || x_key == NULL) {
        fprintf(stderr, "crypto initialization failed\n");
        return 1;
    }

    uint8_t client_x_public[X25519_LEN];
    size_t client_x_public_len = sizeof(client_x_public);
    EVP_PKEY_get_raw_public_key(x_key, client_x_public, &client_x_public_len);

    uint8_t server_x_public[X25519_LEN];
    uint8_t *kem_public = malloc(kem->length_public_key);
    uint8_t *kem_ciphertext = malloc(kem->length_ciphertext);
    uint8_t *sig_public = malloc(sig->length_public_key);
    uint8_t *signature = malloc(sig->length_signature);
    uint8_t *transcript = malloc(X25519_LEN + kem->length_public_key + sig->length_public_key +
                                 X25519_LEN + kem->length_ciphertext);
    uint8_t x_secret[X25519_LEN];
    uint8_t kem_secret[32];
    uint8_t session_key[PQC_SESSION_KEY_LEN];

    if (kem_public == NULL || kem_ciphertext == NULL || sig_public == NULL ||
        signature == NULL || transcript == NULL) {
        fprintf(stderr, "allocation failed\n");
        return 1;
    }

    uint64_t start = pqc_now_ns();
    int fd = connect_server(argv[1], port);
    if (fd < 0) {
        return 1;
    }

    uint32_t server_x_len = 0;
    uint32_t kem_public_len = 0;
    uint32_t sig_public_len = 0;
    pqc_recv_frame(fd, server_x_public, sizeof(server_x_public), &server_x_len);
    pqc_recv_frame(fd, kem_public, (uint32_t)kem->length_public_key, &kem_public_len);
    pqc_recv_frame(fd, sig_public, (uint32_t)sig->length_public_key, &sig_public_len);

    uint64_t crypto_start = pqc_now_ns();
    int x_ok = derive_x25519(x_key, server_x_public, x_secret) == 0;
    int kem_ok = OQS_KEM_encaps(kem, kem_ciphertext, kem_secret, kem_public) == OQS_SUCCESS;
    int kdf_ok = pqc_hybrid_session_key(x_secret, sizeof(x_secret), kem_secret, sizeof(kem_secret), session_key) == 0;
    uint64_t crypto_end = pqc_now_ns();

    pqc_send_frame(fd, client_x_public, X25519_LEN);
    pqc_send_frame(fd, kem_ciphertext, (uint32_t)kem->length_ciphertext);

    uint32_t signature_len = 0;
    pqc_recv_frame(fd, signature, (uint32_t)sig->length_signature, &signature_len);

    size_t transcript_len = build_transcript(transcript, server_x_public, kem_public, kem->length_public_key,
                                             sig_public, sig->length_public_key,
                                             client_x_public, kem_ciphertext, kem->length_ciphertext);
    uint64_t verify_start = pqc_now_ns();
    int verify_ok = OQS_SIG_verify(sig, transcript, transcript_len, signature, signature_len, sig_public) == OQS_SUCCESS;
    uint64_t verify_end = pqc_now_ns();
    uint64_t end = pqc_now_ns();

    printf("received server X25519 public key: %u bytes\n", server_x_len);
    printf("received ML-KEM public key: %u bytes\n", kem_public_len);
    printf("received ML-DSA public key: %u bytes\n", sig_public_len);
    printf("sent client X25519 public key: %u bytes\n", X25519_LEN);
    printf("sent ML-KEM ciphertext: %zu bytes\n", kem->length_ciphertext);
    printf("received ML-DSA signature: %u bytes\n", signature_len);
    printf("verified transcript: %zu bytes\n", transcript_len);
    pqc_print_secret_sha256_prefix("client authenticated session key", session_key, sizeof(session_key));
    printf("derive+encaps+HKDF time: %.3f ms\n", pqc_elapsed_ms(crypto_start, crypto_end));
    printf("ML-DSA verify time: %.3f ms\n", pqc_elapsed_ms(verify_start, verify_end));
    printf("authenticated hybrid handshake time: %.3f ms\n", pqc_elapsed_ms(start, end));
    printf("result: %s\n", (x_ok && kem_ok && kdf_ok && verify_ok) ? "PASS" : "FAIL");

    OPENSSL_cleanse(x_secret, sizeof(x_secret));
    OQS_MEM_cleanse(kem_secret, sizeof(kem_secret));
    OPENSSL_cleanse(session_key, sizeof(session_key));
    free(kem_public);
    free(kem_ciphertext);
    free(sig_public);
    free(signature);
    free(transcript);
    EVP_PKEY_free(x_key);
    OQS_KEM_free(kem);
    OQS_SIG_free(sig);
    close(fd);
    OQS_destroy();
    return 0;
}

