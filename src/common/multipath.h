#ifndef PQC_MULTIPATH_H
#define PQC_MULTIPATH_H

#include <stdint.h>
#include <stddef.h>

#define PQC_MP_MAX_INTERFACES 2

typedef struct {
    int fds[PQC_MP_MAX_INTERFACES];
    size_t active_if_count;
    size_t round_robin_idx;
} pqc_multipath_t;

// Initializes Multi-Path bonding manager
void pqc_multipath_init(pqc_multipath_t *mp);

// Adds a secondary physical network socket interface to the multi-path bonding pool
int pqc_multipath_add_interface(pqc_multipath_t *mp, int socket_fd);

// Sends an AEAD frame by multiplexing across active physical interfaces round-robin
int pqc_multipath_send_frame(pqc_multipath_t *mp, const uint8_t *data, uint32_t len);

#endif // PQC_MULTIPATH_H
