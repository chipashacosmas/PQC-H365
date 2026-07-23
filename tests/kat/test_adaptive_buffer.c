#include "framing.h"
#include "timing.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define ML_KEM_PUBLIC_KEY_SIZE 1184U
#define ML_DSA_SIGNATURE_SIZE 3309U
#define OVERSIZED_PAYLOAD_SIZE 4097U

static void fill_pattern(uint8_t *buffer, uint32_t len, uint8_t seed) {
    for (uint32_t i = 0; i < len; i++) {
        buffer[i] = (uint8_t)(seed + i);
    }
}

static int roundtrip_frame(uint32_t payload_len) {
    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) {
        perror("socketpair");
        return -1;
    }

    uint8_t send_buffer[PQC_MAX_FRAME_SIZE];
    uint8_t recv_buffer[PQC_MAX_FRAME_SIZE];
    uint32_t recv_len = 0;

    fill_pattern(send_buffer, payload_len, 0x35);

    uint64_t start = pqc_now_ns();
    int send_status = pqc_send_frame(fds[0], send_buffer, payload_len);
    int recv_status = pqc_recv_frame(fds[1], recv_buffer, sizeof(recv_buffer), &recv_len);
    uint64_t end = pqc_now_ns();

    close(fds[0]);
    close(fds[1]);

    int ok = send_status == 0 &&
             recv_status == 0 &&
             recv_len == payload_len &&
             memcmp(send_buffer, recv_buffer, payload_len) == 0;

    printf("  %u-byte frame: %s (%.3f ms)\n",
           payload_len,
           ok ? "PASS" : "FAIL",
           pqc_elapsed_ms(start, end));

    return ok ? 0 : -1;
}

static int oversized_frame_rejected(void) {
    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) {
        perror("socketpair");
        return -1;
    }

    uint8_t dummy[1] = {0};
    int status = pqc_send_frame(fds[0], dummy, OVERSIZED_PAYLOAD_SIZE);

    close(fds[0]);
    close(fds[1]);

    int ok = status != 0;
    printf("  %u-byte oversized frame rejection: %s\n",
           OVERSIZED_PAYLOAD_SIZE,
           ok ? "PASS" : "FAIL");

    return ok ? 0 : -1;
}

int main(void) {
    printf("Adaptive buffer/framing test\n");
    printf("  configured max frame: %u bytes\n", PQC_MAX_FRAME_SIZE);
    printf("  ML-KEM-768 public key target: %u bytes\n", ML_KEM_PUBLIC_KEY_SIZE);
    printf("  ML-DSA-65 signature target: %u bytes\n", ML_DSA_SIGNATURE_SIZE);

    int ok = 1;
    ok &= roundtrip_frame(ML_KEM_PUBLIC_KEY_SIZE) == 0;
    ok &= roundtrip_frame(ML_DSA_SIGNATURE_SIZE) == 0;
    ok &= roundtrip_frame(PQC_MAX_FRAME_SIZE) == 0;
    ok &= oversized_frame_rejected() == 0;

    printf("  result: %s\n", ok ? "PASS" : "FAIL");
    return ok ? 0 : 1;
}
