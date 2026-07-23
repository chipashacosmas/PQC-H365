#ifndef PQC_FRAMING_H
#define PQC_FRAMING_H

#include <stdint.h>
#include <stddef.h>

#define PQC_MAX_FRAME_SIZE 4096U

int pqc_send_frame(int fd, const uint8_t *data, uint32_t len);
int pqc_recv_frame(int fd, uint8_t *buffer, uint32_t capacity, uint32_t *out_len);

int pqc_make_nonblocking(int fd);

#endif

