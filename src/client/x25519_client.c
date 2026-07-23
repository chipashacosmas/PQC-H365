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
#define X25519_KEY_LEN 32U

static int connect_to_server(const char *host, uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        fprintf(stderr, "invalid IPv4 address: %s\n", host);
        close(fd);
        return -1;
    }

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("connect");
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
    if (argc < 2 || argc > 3) {
        fprintf(stderr, "usage: %s <server-ip> [port]\n", argv[0]);
        return 1;
    }

    const char *host = argv[1];
    uint16_t port = DEFAULT_PORT;
    if (argc == 3) {
        port = (uint16_t)atoi(argv[2]);
    }

    uint64_t key_start = pqc_now_ns();
    EVP_PKEY *client_key = generate_x25519_key();
    uint64_t key_end = pqc_now_ns();
    if (client_key == NULL) {
        fprintf(stderr, "X25519 client key generation failed\n");
        return 1;
    }

    uint8_t client_public[X25519_KEY_LEN];
    size_t client_public_len = sizeof(client_public);
    if (EVP_PKEY_get_raw_public_key(client_key, client_public, &client_public_len) <= 0 ||
        client_public_len != X25519_KEY_LEN) {
        fprintf(stderr, "failed to export client public key\n");
        EVP_PKEY_free(client_key);
        return 1;
    }

    uint64_t handshake_start = pqc_now_ns();
    int fd = connect_to_server(host, port);
    if (fd < 0) {
        EVP_PKEY_free(client_key);
        return 1;
    }

    uint8_t server_public[X25519_KEY_LEN];
    uint32_t server_public_len = 0;
    if (pqc_recv_frame(fd, server_public, sizeof(server_public), &server_public_len) != 0 ||
        server_public_len != X25519_KEY_LEN) {
        fprintf(stderr, "failed to receive valid server public key\n");
        close(fd);
        EVP_PKEY_free(client_key);
        return 1;
    }

    EVP_PKEY *server_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, server_public, server_public_len);
    if (server_key == NULL) {
        fprintf(stderr, "failed to import server public key\n");
        close(fd);
        EVP_PKEY_free(client_key);
        return 1;
    }

    uint8_t shared_secret[X25519_KEY_LEN];
    size_t shared_secret_len = sizeof(shared_secret);

    uint64_t derive_start = pqc_now_ns();
    int derive_status = derive_x25519_secret(client_key, server_key, shared_secret, &shared_secret_len);
    uint64_t derive_end = pqc_now_ns();

    if (derive_status != 0 || shared_secret_len != X25519_KEY_LEN) {
        fprintf(stderr, "X25519 derive failed\n");
        EVP_PKEY_free(server_key);
        close(fd);
        EVP_PKEY_free(client_key);
        return 1;
    }

    if (pqc_send_frame(fd, client_public, X25519_KEY_LEN) != 0) {
        fprintf(stderr, "failed to send client public key\n");
        EVP_PKEY_free(server_key);
        close(fd);
        EVP_PKEY_free(client_key);
        return 1;
    }

    uint64_t handshake_end = pqc_now_ns();

    printf("received server public key: %u bytes\n", server_public_len);
    printf("sent client public key: %u bytes\n", X25519_KEY_LEN);
    pqc_print_secret_sha256_prefix("client X25519 shared secret", shared_secret, shared_secret_len);
    printf("keypair time: %.3f ms\n", pqc_elapsed_ms(key_start, key_end));
    printf("derive time: %.3f ms\n", pqc_elapsed_ms(derive_start, derive_end));
    printf("network X25519 handshake time: %.3f ms\n", pqc_elapsed_ms(handshake_start, handshake_end));

    OPENSSL_cleanse(shared_secret, sizeof(shared_secret));
    EVP_PKEY_free(server_key);
    close(fd);
    EVP_PKEY_free(client_key);
    return 0;
}

