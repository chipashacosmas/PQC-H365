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

    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1 ||
        connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("connect");
        close(fd);
        return -1;
    }

    return fd;
}

int main(int argc, char **argv) {
    if (argc < 2 || argc > 3) {
        fprintf(stderr, "usage: %s <server-ip> [port]\n", argv[0]);
        return 1;
    }

    uint16_t port = argc == 3 ? (uint16_t)atoi(argv[2]) : DEFAULT_PORT;

    OQS_init();
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    if (sig == NULL) {
        fprintf(stderr, "failed to initialize ML-DSA-65\n");
        OQS_destroy();
        return 1;
    }

    uint8_t *public_key = malloc(sig->length_public_key);
    uint8_t *message = malloc(PQC_MAX_FRAME_SIZE);
    uint8_t *signature = malloc(sig->length_signature);
    if (public_key == NULL || message == NULL || signature == NULL) {
        fprintf(stderr, "allocation failed\n");
        free(public_key);
        free(message);
        free(signature);
        OQS_SIG_free(sig);
        OQS_destroy();
        return 1;
    }

    uint64_t start = pqc_now_ns();
    int fd = connect_to_server(argv[1], port);
    if (fd < 0) {
        free(public_key);
        free(message);
        free(signature);
        OQS_SIG_free(sig);
        OQS_destroy();
        return 1;
    }

    uint32_t public_key_len = 0;
    uint32_t message_len = 0;
    uint32_t signature_len = 0;

    int recv_ok = pqc_recv_frame(fd, public_key, (uint32_t)sig->length_public_key, &public_key_len) == 0 &&
                  pqc_recv_frame(fd, message, PQC_MAX_FRAME_SIZE, &message_len) == 0 &&
                  pqc_recv_frame(fd, signature, (uint32_t)sig->length_signature, &signature_len) == 0;

    uint64_t verify_start = pqc_now_ns();
    int verify_ok = recv_ok &&
                    public_key_len == sig->length_public_key &&
                    signature_len <= sig->length_signature &&
                    OQS_SIG_verify(sig, message, message_len,
                                   signature, signature_len,
                                   public_key) == OQS_SUCCESS;
    uint64_t verify_end = pqc_now_ns();
    uint64_t end = pqc_now_ns();

    printf("received public key: %u bytes\n", public_key_len);
    printf("received auth message: %u bytes\n", message_len);
    printf("received signature: %u bytes\n", signature_len);
    printf("verify time: %.3f ms\n", pqc_elapsed_ms(verify_start, verify_end));
    printf("network auth verification time: %.3f ms\n", pqc_elapsed_ms(start, end));
    printf("result: %s\n", verify_ok ? "PASS" : "FAIL");

    close(fd);
    free(public_key);
    free(message);
    free(signature);
    OQS_SIG_free(sig);
    OQS_destroy();
    return verify_ok ? 0 : 1;
}

