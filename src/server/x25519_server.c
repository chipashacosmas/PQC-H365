#include "framing.h"
#include "secret_print.h"
#include "timing.h"

#include <openssl/evp.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define DEFAULT_PORT 4446
#define BACKLOG 8
#define X25519_KEY_LEN 32U

static int create_listen_socket(uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }

    int enabled = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled)) != 0) {
        perror("setsockopt");
        close(fd);
        return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("bind");
        close(fd);
        return -1;
    }

    if (listen(fd, BACKLOG) != 0) {
        perror("listen");
        close(fd);
        return -1;
    }

    return fd;
}

static EVP_PKEY *generate_x25519_key(void) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (ctx == NULL) {
        return NULL;
    }

    EVP_PKEY *key = NULL;
    if (EVP_PKEY_keygen_init(ctx) <= 0 || EVP_PKEY_keygen(ctx, &key) <= 0) {
        EVP_PKEY_free(key);
        key = NULL;
    }

    EVP_PKEY_CTX_free(ctx);
    return key;
}

static int derive_x25519_secret(EVP_PKEY *private_key, EVP_PKEY *peer_public_key,
                                uint8_t *secret, size_t *secret_len) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(private_key, NULL);
    if (ctx == NULL) {
        return -1;
    }

    int ok = EVP_PKEY_derive_init(ctx) > 0 &&
             EVP_PKEY_derive_set_peer(ctx, peer_public_key) > 0 &&
             EVP_PKEY_derive(ctx, secret, secret_len) > 0;

    EVP_PKEY_CTX_free(ctx);
    return ok ? 0 : -1;
}

int main(int argc, char **argv) {
    uint16_t port = DEFAULT_PORT;
    if (argc == 2) {
        port = (uint16_t)atoi(argv[1]);
    }

    uint64_t key_start = pqc_now_ns();
    EVP_PKEY *server_key = generate_x25519_key();
    uint64_t key_end = pqc_now_ns();
    if (server_key == NULL) {
        fprintf(stderr, "X25519 server key generation failed\n");
        return 1;
    }

    uint8_t server_public[X25519_KEY_LEN];
    size_t server_public_len = sizeof(server_public);
    if (EVP_PKEY_get_raw_public_key(server_key, server_public, &server_public_len) <= 0 ||
        server_public_len != X25519_KEY_LEN) {
        fprintf(stderr, "failed to export server public key\n");
        EVP_PKEY_free(server_key);
        return 1;
    }

    int listen_fd = create_listen_socket(port);
    if (listen_fd < 0) {
        EVP_PKEY_free(server_key);
        return 1;
    }

    printf("pqc_x25519_server listening on port %u\n", port);
    printf("X25519 public key ready: %u bytes\n", X25519_KEY_LEN);

    int client_fd = accept(listen_fd, NULL, NULL);
    if (client_fd < 0) {
        perror("accept");
        close(listen_fd);
        EVP_PKEY_free(server_key);
        return 1;
    }

    uint64_t handshake_start = pqc_now_ns();

    if (pqc_send_frame(client_fd, server_public, X25519_KEY_LEN) != 0) {
        fprintf(stderr, "failed to send server public key\n");
        close(client_fd);
        close(listen_fd);
        EVP_PKEY_free(server_key);
        return 1;
    }

    uint8_t client_public[X25519_KEY_LEN];
    uint32_t client_public_len = 0;
    if (pqc_recv_frame(client_fd, client_public, sizeof(client_public), &client_public_len) != 0 ||
        client_public_len != X25519_KEY_LEN) {
        fprintf(stderr, "failed to receive valid client public key\n");
        close(client_fd);
        close(listen_fd);
        EVP_PKEY_free(server_key);
        return 1;
    }

    EVP_PKEY *client_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, client_public, client_public_len);
    if (client_key == NULL) {
        fprintf(stderr, "failed to import client public key\n");
        close(client_fd);
        close(listen_fd);
        EVP_PKEY_free(server_key);
        return 1;
    }

    uint8_t shared_secret[X25519_KEY_LEN];
    size_t shared_secret_len = sizeof(shared_secret);

    uint64_t derive_start = pqc_now_ns();
    int derive_status = derive_x25519_secret(server_key, client_key, shared_secret, &shared_secret_len);
    uint64_t derive_end = pqc_now_ns();
    uint64_t handshake_end = pqc_now_ns();

    if (derive_status != 0 || shared_secret_len != X25519_KEY_LEN) {
        fprintf(stderr, "X25519 derive failed\n");
        EVP_PKEY_free(client_key);
        close(client_fd);
        close(listen_fd);
        EVP_PKEY_free(server_key);
        return 1;
    }

    printf("received client public key: %u bytes\n", client_public_len);
    pqc_print_secret_sha256_prefix("server X25519 shared secret", shared_secret, shared_secret_len);
    printf("keypair time: %.3f ms\n", pqc_elapsed_ms(key_start, key_end));
    printf("derive time: %.3f ms\n", pqc_elapsed_ms(derive_start, derive_end));
    printf("network X25519 handshake time: %.3f ms\n", pqc_elapsed_ms(handshake_start, handshake_end));

    OPENSSL_cleanse(shared_secret, sizeof(shared_secret));
    EVP_PKEY_free(client_key);
    close(client_fd);
    close(listen_fd);
    EVP_PKEY_free(server_key);
    return 0;
}

