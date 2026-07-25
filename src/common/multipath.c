#include "multipath.h"
#include "framing.h"
#include <string.h>

void pqc_multipath_init(pqc_multipath_t *mp) {
    if (!mp) return;
    memset(mp, 0, sizeof(pqc_multipath_t));
    for (int i = 0; i < PQC_MP_MAX_INTERFACES; i++) {
        mp->fds[i] = -1;
    }
}

int pqc_multipath_add_interface(pqc_multipath_t *mp, int socket_fd) {
    if (!mp || socket_fd < 0) return -1;
    if (mp->active_if_count >= PQC_MP_MAX_INTERFACES) return -1;
    
    mp->fds[mp->active_if_count++] = socket_fd;
    return 0;
}

int pqc_multipath_send_frame(pqc_multipath_t *mp, const uint8_t *data, uint32_t len) {
    if (!mp || mp->active_if_count == 0) return -1;

    int target_fd = mp->fds[mp->round_robin_idx];
    mp->round_robin_idx = (mp->round_robin_idx + 1) % mp->active_if_count;

    return pqc_send_padded_frame(target_fd, data, len);
}
