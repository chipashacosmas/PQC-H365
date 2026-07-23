#include "framing.h"
#include "hybrid_kdf.h"
#include "secret_print.h"
#include "timing.h"
#include "tun.h"
#include "aead.h"

#include <oqs/oqs.h>
#include <openssl/evp.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <unistd.h>

#define DEFAULT_PORT 4447
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

static int derive_x25519(EVP_PKEY *private_key, EVP_PKEY *peer_key, uint8_t *secret, size_t *secret_len) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(private_key, NULL);
    if (ctx == NULL) return -1;
    int ok = EVP_PKEY_derive_init(ctx) > 0 &&
             EVP_PKEY_derive_set_peer(ctx, peer_key) > 0 &&
             EVP_PKEY_derive(ctx, secret, secret_len) > 0;
    EVP_PKEY_CTX_free(ctx);
    return ok ? 0 : -1;
}

int main(int argc, char **argv) {
    if (argc < 2 || argc > 3) {
        fprintf(stderr, "usage: %s <server-ip> [port]\n", argv[0]);
        return 1;
    }
    uint16_t port = argc == 3 ? (uint16_t)atoi(argv[2]) : DEFAULT_PORT;

    OQS_init();
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    OQS_SIG *dsa = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    EVP_PKEY *x_key = generate_x25519();
    
    if (!kem || !dsa || !x_key) {
        fprintf(stderr, "crypto initialization failed\n");
        return 1;
    }

    uint8_t x_public[X25519_LEN];
    size_t x_public_len = sizeof(x_public);
    EVP_PKEY_get_raw_public_key(x_key, x_public, &x_public_len);

    uint8_t server_x_public[X25519_LEN];
    uint8_t *kem_public = malloc(kem->length_public_key);
    uint8_t *kem_ciphertext = malloc(kem->length_ciphertext);
    uint8_t kem_secret[32];
    uint8_t x_secret[32];
    uint8_t session_key[PQC_SESSION_KEY_LEN];

    if (!kem_public || !kem_ciphertext) {
        fprintf(stderr, "allocation failed\n");
        return 1;
    }

    uint64_t start = pqc_now_ns();
    int fd = connect_server(argv[1], port);
    if (fd < 0) return 1;

    // --- PHASE 1: Classical X25519 Handshake ---
    uint32_t server_x_len = 0;
    if (pqc_recv_frame(fd, server_x_public, sizeof(server_x_public), &server_x_len) != 0 || server_x_len != X25519_LEN) {
        fprintf(stderr, "failed to receive X25519 key\n");
        close(fd); return 1;
    }
    EVP_PKEY *server_x_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, server_x_public, server_x_len);
    size_t x_secret_len = sizeof(x_secret);
    derive_x25519(x_key, server_x_key, x_secret, &x_secret_len);
    pqc_send_frame(fd, x_public, X25519_LEN);

    // --- PHASE 2: Post-Quantum ML-KEM Handshake ---
    uint32_t kem_public_len = 0;
    if (pqc_recv_frame(fd, kem_public, (uint32_t)kem->length_public_key, &kem_public_len) != 0) {
        fprintf(stderr, "failed to receive ML-KEM key\n");
        close(fd); return 1;
    }
    if (OQS_KEM_encaps(kem, kem_ciphertext, kem_secret, kem_public) != OQS_SUCCESS) {
        fprintf(stderr, "ML-KEM encaps failed\n");
        close(fd); return 1;
    }
    pqc_send_frame(fd, kem_ciphertext, (uint32_t)kem->length_ciphertext);

    // --- PHASE 3: Hybrid Key Derivation ---
    if (pqc_hybrid_session_key(x_secret, sizeof(x_secret), kem_secret, sizeof(kem_secret), session_key) != 0) {
        fprintf(stderr, "HKDF failed\n");
        close(fd); return 1;
    }

    // --- PHASE 4: ML-DSA Authentication Verification ---
    uint32_t payload_len = 0;
    uint8_t *payload = malloc(PQC_MAX_FRAME_SIZE);
    if (pqc_recv_frame(fd, payload, PQC_MAX_FRAME_SIZE, &payload_len) != 0) {
        fprintf(stderr, "failed to receive ML-DSA signature\n");
        close(fd); return 1;
    }

    if (payload_len < dsa->length_public_key) {
        fprintf(stderr, "invalid ML-DSA payload size\n");
        close(fd); return 1;
    }

    uint8_t *server_dsa_public = payload;
    uint8_t *server_sig = payload + dsa->length_public_key;
    size_t sig_len = payload_len - dsa->length_public_key;

    if (OQS_SIG_verify(dsa, session_key, sizeof(session_key), server_sig, sig_len, server_dsa_public) != OQS_SUCCESS) {
        fprintf(stderr, "ML-DSA authentication failed! Server signature is invalid.\n");
        close(fd); return 1;
    }
    printf("[PASS] Server ML-DSA signature verified (TOFU).\n");
    free(payload);

    uint64_t end = pqc_now_ns();
    pqc_print_secret_sha256_prefix("client session key", session_key, sizeof(session_key));
    printf("hybrid handshake time: %.3f ms\n", pqc_elapsed_ms(start, end));

    // Clean up secrets
    OPENSSL_cleanse(x_secret, sizeof(x_secret));
    OQS_MEM_cleanse(kem_secret, sizeof(kem_secret));
    EVP_PKEY_free(server_x_key);
    EVP_PKEY_free(x_key);
    free(kem_public);
    free(kem_ciphertext);
    OQS_KEM_free(kem);
    OQS_SIG_free(dsa);

    // --- PHASE 5: Data Plane ---
    char tun_name[16] = "tun1";
    int tun_fd = pqc_tun_alloc(tun_name);
    if (tun_fd < 0) {
        fprintf(stderr, "Failed to create TUN interface. Exiting.\n");
        close(fd); return 1;
    }
    printf("Created virtual interface: %s\n", tun_name);
    printf("Entering Data Plane. Routing packets...\n");

    pqc_make_nonblocking(fd);
    pqc_make_nonblocking(tun_fd);

    uint8_t tun_buf[PQC_MAX_FRAME_SIZE];
    uint8_t sock_buf[PQC_MAX_FRAME_SIZE];
    
    while (1) {
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(fd, &read_fds);
        FD_SET(tun_fd, &read_fds);
        int max_fd = fd > tun_fd ? fd : tun_fd;

        if (select(max_fd + 1, &read_fds, NULL, NULL, NULL) < 0) {
            break;
        }

        // Read from TUN, encrypt, send to socket
        if (FD_ISSET(tun_fd, &read_fds)) {
            int n = read(tun_fd, tun_buf, sizeof(tun_buf));
            if (n > 0) {
                uint8_t nonce[PQC_AES_GCM_NONCE_LEN] = {0};
                uint8_t ciphertext[PQC_MAX_FRAME_SIZE + PQC_AES_GCM_TAG_LEN];
                uint8_t tag[PQC_AES_GCM_TAG_LEN];
                pqc_aes256_gcm_encrypt(session_key, nonce, tun_buf, n, NULL, 0, ciphertext, tag);
                memcpy(ciphertext + n, tag, PQC_AES_GCM_TAG_LEN);
                pqc_send_frame(fd, ciphertext, n + PQC_AES_GCM_TAG_LEN);
            }
        }

        // Read from socket, decrypt, send to TUN
        if (FD_ISSET(fd, &read_fds)) {
            uint32_t len = 0;
            int ret = pqc_recv_frame(fd, sock_buf, sizeof(sock_buf), &len);
            if (ret == 0 && len > PQC_AES_GCM_TAG_LEN) {
                uint8_t nonce[PQC_AES_GCM_NONCE_LEN] = {0};
                uint8_t plaintext[PQC_MAX_FRAME_SIZE];
                uint8_t tag[PQC_AES_GCM_TAG_LEN];
                memcpy(tag, sock_buf + len - PQC_AES_GCM_TAG_LEN, PQC_AES_GCM_TAG_LEN);
                
                if (pqc_aes256_gcm_decrypt(session_key, nonce, sock_buf, len - PQC_AES_GCM_TAG_LEN, NULL, 0, tag, plaintext) == 0) {
                    write(tun_fd, plaintext, len - PQC_AES_GCM_TAG_LEN);
                }
            } else if (ret != 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                printf("Server disconnected.\n");
                break;
            }
        }
    }

    close(tun_fd);
    close(fd);
    OQS_destroy();
    return 0;
}
