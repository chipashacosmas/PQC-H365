#include "framing.h"
#include "timing.h"

#include <oqs/oqs.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define DEFAULT_PORT 4449
#define BACKLOG 8

static const uint8_t AUTH_MESSAGE[] = "PQC_H365_SERVER_HANDSHAKE_AUTH_V1";

static int create_listen_socket(uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }

    int enabled = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled));

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

int main(int argc, char **argv) {
    uint16_t port = argc == 2 ? (uint16_t)atoi(argv[1]) : DEFAULT_PORT;

    OQS_init();
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    if (sig == NULL) {
        fprintf(stderr, "failed to initialize ML-DSA-65\n");
        OQS_destroy();
        return 1;
    }

    uint8_t *public_key = malloc(sig->length_public_key);
    uint8_t *secret_key = malloc(sig->length_secret_key);
    uint8_t *signature = malloc(sig->length_signature);
    if (public_key == NULL || secret_key == NULL || signature == NULL) {
        fprintf(stderr, "allocation failed\n");
        free(public_key);
        OQS_MEM_secure_free(secret_key, sig->length_secret_key);
        free(signature);
        OQS_SIG_free(sig);
        OQS_destroy();
        return 1;
    }

    uint64_t keypair_start = pqc_now_ns();
    int keypair_ok = OQS_SIG_keypair(sig, public_key, secret_key) == OQS_SUCCESS;
    uint64_t keypair_end = pqc_now_ns();

    size_t signature_len = 0;
    uint64_t sign_start = pqc_now_ns();
    int sign_ok = OQS_SIG_sign(sig, signature, &signature_len,
                               AUTH_MESSAGE, sizeof(AUTH_MESSAGE) - 1,
                               secret_key) == OQS_SUCCESS;
    uint64_t sign_end = pqc_now_ns();

    if (!keypair_ok || !sign_ok) {
        fprintf(stderr, "ML-DSA keypair/sign failed\n");
        OQS_MEM_secure_free(secret_key, sig->length_secret_key);
        free(public_key);
        free(signature);
        OQS_SIG_free(sig);
        OQS_destroy();
        return 1;
    }

    int listen_fd = create_listen_socket(port);
    if (listen_fd < 0) {
        OQS_MEM_secure_free(secret_key, sig->length_secret_key);
        free(public_key);
        free(signature);
        OQS_SIG_free(sig);
        OQS_destroy();
        return 1;
    }

    printf("pqc_dsa_auth_server listening on port %u\n", port);
    printf("ML-DSA public key ready: %zu bytes\n", sig->length_public_key);
    printf("ML-DSA signature ready: %zu bytes\n", signature_len);

    int client_fd = accept(listen_fd, NULL, NULL);
    if (client_fd < 0) {
        perror("accept");
        close(listen_fd);
        OQS_MEM_secure_free(secret_key, sig->length_secret_key);
        free(public_key);
        free(signature);
        OQS_SIG_free(sig);
        OQS_destroy();
        return 1;
    }

    uint64_t send_start = pqc_now_ns();
    int send_ok = pqc_send_frame(client_fd, public_key, (uint32_t)sig->length_public_key) == 0 &&
                  pqc_send_frame(client_fd, AUTH_MESSAGE, (uint32_t)(sizeof(AUTH_MESSAGE) - 1)) == 0 &&
                  pqc_send_frame(client_fd, signature, (uint32_t)signature_len) == 0;
    uint64_t send_end = pqc_now_ns();

    printf("sent public key: %zu bytes\n", sig->length_public_key);
    printf("sent auth message: %zu bytes\n", sizeof(AUTH_MESSAGE) - 1);
    printf("sent signature: %zu bytes\n", signature_len);
    printf("keypair time: %.3f ms\n", pqc_elapsed_ms(keypair_start, keypair_end));
    printf("sign time: %.3f ms\n", pqc_elapsed_ms(sign_start, sign_end));
    printf("network auth send time: %.3f ms\n", pqc_elapsed_ms(send_start, send_end));
    printf("result: %s\n", send_ok ? "PASS" : "FAIL");

    close(client_fd);
    close(listen_fd);
    OQS_MEM_secure_free(secret_key, sig->length_secret_key);
    free(public_key);
    free(signature);
    OQS_SIG_free(sig);
    OQS_destroy();
    return send_ok ? 0 : 1;
}

