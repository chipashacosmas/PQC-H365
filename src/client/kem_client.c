#include "framing.h"
#include "secret_print.h"
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

#define DEFAULT_PORT 4445

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

static void cleanup(OQS_KEM *kem, uint8_t *public_key, uint8_t *ciphertext, uint8_t *shared_secret) {
    free(public_key);
    free(ciphertext);
    if (shared_secret != NULL && kem != NULL) {
        OQS_MEM_secure_free(shared_secret, kem->length_shared_secret);
    }
    OQS_KEM_free(kem);
    OQS_destroy();
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

    OQS_init();
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (kem == NULL) {
        fprintf(stderr, "failed to initialize ML-KEM-768\n");
        OQS_destroy();
        return 1;
    }

    uint8_t *public_key = malloc(kem->length_public_key);
    uint8_t *ciphertext = malloc(kem->length_ciphertext);
    uint8_t *shared_secret = malloc(kem->length_shared_secret);
    if (public_key == NULL || ciphertext == NULL || shared_secret == NULL) {
        fprintf(stderr, "allocation failed\n");
        cleanup(kem, public_key, ciphertext, shared_secret);
        return 1;
    }

    uint64_t handshake_start = pqc_now_ns();
    int fd = connect_to_server(host, port);
    if (fd < 0) {
        cleanup(kem, public_key, ciphertext, shared_secret);
        return 1;
    }

    uint32_t public_key_len = 0;
    if (pqc_recv_frame(fd, public_key, (uint32_t)kem->length_public_key, &public_key_len) != 0 ||
        public_key_len != kem->length_public_key) {
        fprintf(stderr, "failed to receive valid ML-KEM public key\n");
        close(fd);
        cleanup(kem, public_key, ciphertext, shared_secret);
        return 1;
    }

    uint64_t encaps_start = pqc_now_ns();
    if (OQS_KEM_encaps(kem, ciphertext, shared_secret, public_key) != OQS_SUCCESS) {
        fprintf(stderr, "ML-KEM encapsulation failed\n");
        close(fd);
        cleanup(kem, public_key, ciphertext, shared_secret);
        return 1;
    }
    uint64_t encaps_end = pqc_now_ns();

    if (pqc_send_frame(fd, ciphertext, (uint32_t)kem->length_ciphertext) != 0) {
        fprintf(stderr, "failed to send ML-KEM ciphertext\n");
        close(fd);
        cleanup(kem, public_key, ciphertext, shared_secret);
        return 1;
    }

    uint64_t handshake_end = pqc_now_ns();

    printf("received public key: %u bytes\n", public_key_len);
    printf("sent ciphertext: %zu bytes\n", kem->length_ciphertext);
    pqc_print_secret_sha256_prefix("client shared secret", shared_secret, kem->length_shared_secret);
    printf("encaps time: %.3f ms\n", pqc_elapsed_ms(encaps_start, encaps_end));
    printf("network ML-KEM handshake time: %.3f ms\n", pqc_elapsed_ms(handshake_start, handshake_end));

    close(fd);
    cleanup(kem, public_key, ciphertext, shared_secret);
    return 0;
}

