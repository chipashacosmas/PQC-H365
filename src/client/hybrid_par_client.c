#include "framing.h"
#include "hybrid_kdf.h"
#include "secret_print.h"
#include "timing.h"

#include <oqs/oqs.h>
#include <openssl/evp.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define DEFAULT_PORT 4448
#define X25519_LEN 32U

typedef struct {
    EVP_PKEY *key;
    const uint8_t *peer_public;
    uint8_t public_key[X25519_LEN];
    uint8_t secret[X25519_LEN];
    int ok;
} x25519_task_t;

typedef struct {
    OQS_KEM *kem;
    const uint8_t *public_key;
    uint8_t *ciphertext;
    uint8_t secret[32];
    int ok;
} kem_task_t;

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

static void *x25519_thread(void *arg) {
    x25519_task_t *task = arg;
    EVP_PKEY_CTX *keygen_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    size_t public_len = sizeof(task->public_key);
    EVP_PKEY *peer = NULL;
    EVP_PKEY_CTX *derive_ctx = NULL;
    size_t secret_len = sizeof(task->secret);

    task->ok = keygen_ctx != NULL &&
               EVP_PKEY_keygen_init(keygen_ctx) > 0 &&
               EVP_PKEY_keygen(keygen_ctx, &task->key) > 0 &&
               EVP_PKEY_get_raw_public_key(task->key, task->public_key, &public_len) > 0 &&
               public_len == X25519_LEN;

    if (task->ok) {
        peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, task->peer_public, X25519_LEN);
        derive_ctx = EVP_PKEY_CTX_new(task->key, NULL);
        task->ok = peer != NULL && derive_ctx != NULL &&
                   EVP_PKEY_derive_init(derive_ctx) > 0 &&
                   EVP_PKEY_derive_set_peer(derive_ctx, peer) > 0 &&
                   EVP_PKEY_derive(derive_ctx, task->secret, &secret_len) > 0 &&
                   secret_len == X25519_LEN;
    }

    EVP_PKEY_CTX_free(derive_ctx);
    EVP_PKEY_free(peer);
    EVP_PKEY_CTX_free(keygen_ctx);
    return NULL;
}

static void *kem_thread(void *arg) {
    kem_task_t *task = arg;
    task->ok = OQS_KEM_encaps(task->kem, task->ciphertext, task->secret, task->public_key) == OQS_SUCCESS;
    return NULL;
}

int main(int argc, char **argv) {
    if (argc < 2 || argc > 3) {
        fprintf(stderr, "usage: %s <server-ip> [port]\n", argv[0]);
        return 1;
    }
    uint16_t port = argc == 3 ? (uint16_t)atoi(argv[2]) : DEFAULT_PORT;

    OQS_init();
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (kem == NULL) {
        fprintf(stderr, "failed to initialize ML-KEM-768\n");
        OQS_destroy();
        return 1;
    }

    uint8_t server_x_public[X25519_LEN];
    uint8_t *kem_public = malloc(kem->length_public_key);
    uint8_t *kem_ciphertext = malloc(kem->length_ciphertext);
    uint8_t session_key[PQC_SESSION_KEY_LEN];
    if (kem_public == NULL || kem_ciphertext == NULL) {
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
    pqc_recv_frame(fd, server_x_public, sizeof(server_x_public), &server_x_len);
    pqc_recv_frame(fd, kem_public, (uint32_t)kem->length_public_key, &kem_public_len);

    x25519_task_t x_task = {0};
    x_task.peer_public = server_x_public;
    kem_task_t kem_task = {kem, kem_public, kem_ciphertext, {0}, 0};

    pthread_t x_thread_id;
    pthread_t kem_thread_id;
    uint64_t crypto_start = pqc_now_ns();
    pthread_create(&x_thread_id, NULL, x25519_thread, &x_task);
    pthread_create(&kem_thread_id, NULL, kem_thread, &kem_task);
    pthread_join(x_thread_id, NULL);
    pthread_join(kem_thread_id, NULL);
    uint64_t crypto_end = pqc_now_ns();

    pqc_send_frame(fd, x_task.public_key, X25519_LEN);
    pqc_send_frame(fd, kem_ciphertext, (uint32_t)kem->length_ciphertext);

    uint64_t kdf_start = pqc_now_ns();
    int kdf_ok = pqc_hybrid_session_key(x_task.secret, sizeof(x_task.secret),
                                         kem_task.secret, sizeof(kem_task.secret),
                                         session_key) == 0;
    uint64_t kdf_end = pqc_now_ns();
    uint64_t end = pqc_now_ns();

    printf("received X25519 public key: %u bytes\n", server_x_len);
    printf("received ML-KEM public key: %u bytes\n", kem_public_len);
    printf("sent ML-KEM ciphertext: %zu bytes\n", kem->length_ciphertext);
    pqc_print_secret_sha256_prefix("client session key", session_key, sizeof(session_key));
    printf("parallel derive+encaps time: %.3f ms\n", pqc_elapsed_ms(crypto_start, crypto_end));
    printf("HKDF phase time: %.3f ms\n", pqc_elapsed_ms(kdf_start, kdf_end));
    printf("parallel hybrid handshake time: %.3f ms\n", pqc_elapsed_ms(start, end));
    printf("result: %s\n", (x_task.ok && kem_task.ok && kdf_ok) ? "PASS" : "FAIL");

    OPENSSL_cleanse(x_task.secret, sizeof(x_task.secret));
    OQS_MEM_cleanse(kem_task.secret, sizeof(kem_task.secret));
    OPENSSL_cleanse(session_key, sizeof(session_key));
    EVP_PKEY_free(x_task.key);
    free(kem_public);
    free(kem_ciphertext);
    OQS_KEM_free(kem);
    close(fd);
    OQS_destroy();
    return 0;
}

