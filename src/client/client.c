#include "framing.h"
#include "timing.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define DEFAULT_PORT 4444

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

    uint64_t start = pqc_now_ns();
    int fd = connect_to_server(host, port);
    if (fd < 0) {
        return 1;
    }

    const char hello[] = "CLIENT_HELLO_FRAME_OK";
    if (pqc_send_frame(fd, (const uint8_t *)hello, (uint32_t)strlen(hello)) != 0) {
        fprintf(stderr, "failed to send client frame\n");
        close(fd);
        return 1;
    }

    uint8_t buffer[PQC_MAX_FRAME_SIZE];
    uint32_t len = 0;
    if (pqc_recv_frame(fd, buffer, sizeof(buffer), &len) != 0) {
        fprintf(stderr, "failed to receive server frame\n");
        close(fd);
        return 1;
    }

    uint64_t end = pqc_now_ns();
    printf("received %u bytes: %.*s\n", len, (int)len, buffer);
    printf("basic round-trip handshake time: %.3f ms\n", pqc_elapsed_ms(start, end));

    close(fd);
    return 0;
}

