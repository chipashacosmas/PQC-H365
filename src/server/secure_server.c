#include "aead.h"
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

#define DEFAULT_PORT 4451
#define BACKLOG 8
#define X25519_LEN 32U
#define AAD "PQC_H365_SECURE_PAYLOAD_V1"

static int listen_socket(uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }
    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0 || listen(fd, BACKLOG) != 0) {
        perror("bind/listen");
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

static int derive_x25519(EVP_PKEY *private_key, const uint8_t peer_public[X25519_LEN], uint8_t secret[X25519_LEN]) {
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

static size_t build_transcript(uint8_t *out, const uint8_t *server_x,
                               const uint8_t *server_kem, size_t server_kem_len,
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
    uint16_t port = argc == 2 ? (uint16_t)atoi(argv[1]) : DEFAULT_PORT;
    OQS_init();

    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    EVP_PKEY *x_key = generate_x25519();
    uint8_t x_public[X25519_LEN];
    size_t x_public_len = sizeof(x_public);
    EVP_PKEY_get_raw_public_key(x_key, x_public, &x_public_len);

    uint8_t *kem_public = malloc(kem->length_public_key);
    uint8_t *kem_secret_key = malloc(kem->length_secret_key);
    uint8_t *kem_ciphertext = malloc(kem->length_ciphertext);
    uint8_t *sig_public = malloc(sig->length_public_key);
    uint8_t *sig_secret = malloc(sig->length_secret_key);
    uint8_t *signature = malloc(sig->length_signature);
    uint8_t *transcript = malloc(X25519_LEN + kem->length_public_key + sig->length_public_key + X25519_LEN + kem->length_ciphertext);
    uint8_t x_secret[X25519_LEN];
    uint8_t kem_secret[32];
    uint8_t session_key[PQC_SESSION_KEY_LEN];

    OQS_KEM_keypair(kem, kem_public, kem_secret_key);
    OQS_SIG_keypair(sig, sig_public, sig_secret);

    int lfd = listen_socket(port);
    if (lfd < 0) {
        return 1;
    }

    printf("pqc_secure_server listening on port %u\n", port);
    int cfd = accept(lfd, NULL, NULL);
    if (cfd < 0) {
        perror("accept");
        return 1;
    }

    uint64_t start = pqc_now_ns();
    pqc_send_frame(cfd, x_public, X25519_LEN);
    pqc_send_frame(cfd, kem_public, (uint32_t)kem->length_public_key);
    pqc_send_frame(cfd, sig_public, (uint32_t)sig->length_public_key);

    uint8_t client_x_public[X25519_LEN];
    uint32_t client_x_len = 0;
    uint32_t kem_ciphertext_len = 0;
    pqc_recv_frame(cfd, client_x_public, sizeof(client_x_public), &client_x_len);
    pqc_recv_frame(cfd, kem_ciphertext, (uint32_t)kem->length_ciphertext, &kem_ciphertext_len);

    int x_ok = derive_x25519(x_key, client_x_public, x_secret) == 0;
    int kem_ok = OQS_KEM_decaps(kem, kem_secret, kem_ciphertext, kem_secret_key) == OQS_SUCCESS;
    int kdf_ok = pqc_hybrid_session_key(x_secret, sizeof(x_secret), kem_secret, sizeof(kem_secret), session_key) == 0;

    size_t transcript_len = build_transcript(transcript, x_public, kem_public, kem->length_public_key,
                                             sig_public, sig->length_public_key,
                                             client_x_public, kem_ciphertext, kem->length_ciphertext);
    size_t signature_len = 0;
    OQS_SIG_sign(sig, signature, &signature_len, transcript, transcript_len, sig_secret);
    pqc_send_frame(cfd, signature, (uint32_t)signature_len);

    uint8_t packet[PQC_MAX_FRAME_SIZE];
    uint32_t packet_len = 0;
    pqc_recv_frame(cfd, packet, sizeof(packet), &packet_len);

    uint8_t *nonce = packet;
    uint8_t *tag = packet + PQC_AES_GCM_NONCE_LEN;
    uint8_t *ciphertext = packet + PQC_AES_GCM_NONCE_LEN + PQC_AES_GCM_TAG_LEN;
    uint32_t ciphertext_len = packet_len - PQC_AES_GCM_NONCE_LEN - PQC_AES_GCM_TAG_LEN;
    uint8_t plaintext[PQC_MAX_FRAME_SIZE];

    uint64_t dec_start = pqc_now_ns();
    int plaintext_len = pqc_aes256_gcm_decrypt(session_key, nonce,
                                               ciphertext, ciphertext_len,
                                               (const uint8_t *)AAD, strlen(AAD),
                                               tag, plaintext);
    uint64_t dec_end = pqc_now_ns();
    uint64_t end = pqc_now_ns();

    pqc_print_secret_sha256_prefix("server secure session key", session_key, sizeof(session_key));
    printf("received encrypted packet: %u bytes\n", packet_len);
    printf("ciphertext bytes: %u\n", ciphertext_len);
    printf("AES-256-GCM decrypt time: %.3f ms\n", pqc_elapsed_ms(dec_start, dec_end));
    if (plaintext_len > 0) {
        printf("decrypted plaintext: %.*s\n", plaintext_len, plaintext);
    }
    printf("secure payload total time: %.3f ms\n", pqc_elapsed_ms(start, end));
    printf("result: %s\n", (x_ok && kem_ok && kdf_ok && plaintext_len > 0) ? "PASS" : "FAIL");

    close(cfd);
    close(lfd);
    EVP_PKEY_free(x_key);
    OQS_KEM_free(kem);
    OQS_SIG_free(sig);
    OQS_destroy();
    return 0;
}

