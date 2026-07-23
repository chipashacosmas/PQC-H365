#include "framing.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int send_all(int fd, const uint8_t *data, size_t len) {
    size_t sent = 0;

    while (sent < len) {
        ssize_t n = send(fd, data + sent, len - sent, 0);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (n == 0) {
            return -1;
        }
        sent += (size_t)n;
    }

    return 0;
}

static int recv_all(int fd, uint8_t *buffer, size_t len) {
    size_t received = 0;

    while (received < len) {
        ssize_t n = recv(fd, buffer + received, len - received, 0);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (n == 0) {
            return -1;
        }
        received += (size_t)n;
    }

    return 0;
}

int pqc_send_frame(int fd, const uint8_t *data, uint32_t len) {
    if (data == NULL || len > PQC_MAX_FRAME_SIZE) {
        return -1;
    }

    uint32_t network_len = htonl(len);
    if (send_all(fd, (const uint8_t *)&network_len, sizeof(network_len)) != 0) {
        return -1;
    }

    return send_all(fd, data, len);
}

int pqc_recv_frame(int fd, uint8_t *buffer, uint32_t capacity, uint32_t *out_len) {
    if (buffer == NULL || out_len == NULL || capacity == 0) {
        return -1;
    }

    uint32_t network_len = 0;
    if (recv_all(fd, (uint8_t *)&network_len, sizeof(network_len)) != 0) {
        return -1;
    }

    uint32_t len = ntohl(network_len);
    if (len > capacity || len > PQC_MAX_FRAME_SIZE) {
        return -1;
    }

    if (recv_all(fd, buffer, len) != 0) {
        return -1;
    }

    *out_len = len;
    return 0;
}

#include <fcntl.h>

int pqc_make_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return -1;
    flags |= O_NONBLOCK;
    return fcntl(fd, F_SETFL, flags);
}

