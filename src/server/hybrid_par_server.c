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
#define BACKLOG 8
#define X25519_LEN 32U

typedef struct {
    EVP_PKEY *key;
    uint8_t public_key[X25519_LEN];
    int ok;
} x25519_keygen_task_t;

typedef struct {
    OQS_KEM *kem;
    uint8_t *public_key;
    uint8_t *secret_key;
    int ok;
} kem_keygen_task_t;

typedef struct {
    EVP_PKEY *private_key;
    uint8_t peer_public[X25519_LEN];
    uint8_t secret[X25519_LEN];
    int ok;
} x25519_derive_task_t;

typedef struct {
    OQS_KEM *kem;
    const uint8_t *ciphertext;
    const uint8_t *secret_key;
    uint8_t secret[32];
    int ok;
} kem_decaps_task_t;

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

static void *x25519_keygen_thread(void *arg) {
    x25519_keygen_task_t *task = arg;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    size_t public_len = sizeof(task->public_key);
    task->ok = ctx != NULL &&
               EVP_PKEY_keygen_init(ctx) > 0 &&
               EVP_PKEY_keygen(ctx, &task->key) > 0 &&
               EVP_PKEY_get_raw_public_key(task->key, task->public_key, &public_len) > 0 &&
               public_len == X25519_LEN;
    EVP_PKEY_CTX_free(ctx);
    return NULL;
}

static void *kem_keygen_thread(void *arg) {
    kem_keygen_task_t *task = arg;
    task->ok = OQS_KEM_keypair(task->kem, task->public_key, task->secret_key) == OQS_SUCCESS;
    return NULL;
}

static void *x25519_derive_thread(void *arg) {
    x25519_derive_task_t *task = arg;
    EVP_PKEY *peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, task->peer_public, X25519_LEN);
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(task->private_key, NULL);
    size_t secret_len = sizeof(task->secret);
    task->ok = peer != NULL && ctx != NULL &&
               EVP_PKEY_derive_init(ctx) > 0 &&
               EVP_PKEY_derive_set_peer(ctx, peer) > 0 &&
               EVP_PKEY_derive(ctx, task->secret, &secret_len) > 0 &&
               secret_len == X25519_LEN;
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peer);
    return NULL;
}

static void *kem_decaps_thread(void *arg) {
    kem_decaps_task_t *task = arg;
    task->ok = OQS_KEM_decaps(task->kem, task->secret, task->ciphertext, task->secret_key) == OQS_SUCCESS;
    return NULL;
}

int main(int argc, char **argv) {
    uint16_t port = argc == 2 ? (uint16_t)atoi(argv[1]) : DEFAULT_PORT;
    OQS_init();

    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (kem == NULL) {
        fprintf(stderr, "failed to initialize ML-KEM-768\n");
        OQS_destroy();
        return 1;
    }

    uint8_t *kem_public = malloc(kem->length_public_key);
    uint8_t *kem_secret_key = malloc(kem->length_secret_key);
    uint8_t *kem_ciphertext = malloc(kem->length_ciphertext);
    uint8_t session_key[PQC_SESSION_KEY_LEN];
    if (kem_public == NULL || kem_secret_key == NULL || kem_ciphertext == NULL) {
        fprintf(stderr, "allocation failed\n");
        return 1;
    }

    x25519_keygen_task_t x_key_task = {0};
    kem_keygen_task_t kem_key_task = {kem, kem_public, kem_secret_key, 0};
    pthread_t x_key_thread;
    pthread_t kem_key_thread;

    uint64_t prep_start = pqc_now_ns();
    pthread_create(&x_key_thread, NULL, x25519_keygen_thread, &x_key_task);
    pthread_create(&kem_key_thread, NULL, kem_keygen_thread, &kem_key_task);
    pthread_join(x_key_thread, NULL);
    pthread_join(kem_key_thread, NULL);
    uint64_t prep_end = pqc_now_ns();

    if (!x_key_task.ok || !kem_key_task.ok) {
        fprintf(stderr, "parallel key preparation failed\n");
        return 1;
    }

    int lfd = listen_socket(port);
    if (lfd < 0) {
        return 1;
    }

    printf("pqc_hybrid_par_server listening on port %u\n", port);
    int cfd = accept(lfd, NULL, NULL);
    if (cfd < 0) {
        perror("accept");
        return 1;
    }

    uint64_t start = pqc_now_ns();
    pqc_send_frame(cfd, x_key_task.public_key, X25519_LEN);
    pqc_send_frame(cfd, kem_public, (uint32_t)kem->length_public_key);

    uint8_t client_x_public[X25519_LEN];
    uint32_t client_x_len = 0;
    uint32_t kem_ciphertext_len = 0;
    pqc_recv_frame(cfd, client_x_public, sizeof(client_x_public), &client_x_len);
    pqc_recv_frame(cfd, kem_ciphertext, (uint32_t)kem->length_ciphertext, &kem_ciphertext_len);

    x25519_derive_task_t x_task = {0};
    x_task.private_key = x_key_task.key;
    memcpy(x_task.peer_public, client_x_public, X25519_LEN);
    kem_decaps_task_t kem_task = {kem, kem_ciphertext, kem_secret_key, {0}, 0};

    pthread_t x_thread;
    pthread_t kem_thread;
    uint64_t crypto_start = pqc_now_ns();
    pthread_create(&x_thread, NULL, x25519_derive_thread, &x_task);
    pthread_create(&kem_thread, NULL, kem_decaps_thread, &kem_task);
    pthread_join(x_thread, NULL);
    pthread_join(kem_thread, NULL);
    uint64_t crypto_end = pqc_now_ns();

    uint64_t kdf_start = pqc_now_ns();
    int kdf_ok = pqc_hybrid_session_key(x_task.secret, sizeof(x_task.secret),
                                         kem_task.secret, sizeof(kem_task.secret),
                                         session_key) == 0;
    uint64_t kdf_end = pqc_now_ns();
    uint64_t end = pqc_now_ns();

    printf("received X25519 public key: %u bytes\n", client_x_len);
    printf("received ML-KEM ciphertext: %u bytes\n", kem_ciphertext_len);
    pqc_print_secret_sha256_prefix("server session key", session_key, sizeof(session_key));
    printf("parallel prep keygen time: %.3f ms\n", pqc_elapsed_ms(prep_start, prep_end));
    printf("parallel derive+decaps time: %.3f ms\n", pqc_elapsed_ms(crypto_start, crypto_end));
    printf("HKDF phase time: %.3f ms\n", pqc_elapsed_ms(kdf_start, kdf_end));
    printf("parallel hybrid handshake time: %.3f ms\n", pqc_elapsed_ms(start, end));
    printf("result: %s\n", (x_task.ok && kem_task.ok && kdf_ok) ? "PASS" : "FAIL");

    OPENSSL_cleanse(x_task.secret, sizeof(x_task.secret));
    OQS_MEM_cleanse(kem_task.secret, sizeof(kem_task.secret));
    OPENSSL_cleanse(session_key, sizeof(session_key));
    EVP_PKEY_free(x_key_task.key);
    free(kem_public);
    OQS_MEM_secure_free(kem_secret_key, kem->length_secret_key);
    free(kem_ciphertext);
    OQS_KEM_free(kem);
    close(cfd);
    close(lfd);
    OQS_destroy();
    return 0;
}

