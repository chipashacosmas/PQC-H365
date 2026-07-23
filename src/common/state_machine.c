#include "state_machine.h"
#include <string.h>

void pqc_conn_init(pqc_connection_t *conn, int fd) {
    if (!conn) return;
    
    memset(conn, 0, sizeof(pqc_connection_t));
    conn->fd = fd;
    conn->state = STATE_INIT;
    conn->mode = MODE_HYBRID; // Default to Hybrid Quantum-Resistant
    conn->tx_seq = 1;
    conn->anti_replay.last_seq = 0;
    conn->anti_replay.window_mask = 0;
    gettimeofday(&conn->last_activity, NULL);
}

// RFC 6479 / IPsec style 64-packet Sliding Window Anti-Replay Verification
int pqc_anti_replay_check_and_update(pqc_anti_replay_t *ar, uint64_t seq_num) {
    if (!ar || seq_num == 0) return -1;

    if (seq_num > ar->last_seq) {
        uint64_t diff = seq_num - ar->last_seq;
        if (diff < 64) {
            ar->window_mask = (ar->window_mask << diff) | 1ULL;
        } else {
            ar->window_mask = 1ULL;
        }
        ar->last_seq = seq_num;
        return 0; // Valid new packet
    } else {
        uint64_t diff = ar->last_seq - seq_num;
        if (diff >= 64) {
            return -1; // Replay / packet too old
        }
        if (ar->window_mask & (1ULL << diff)) {
            return -1; // Replay / already received
        }
        ar->window_mask |= (1ULL << diff);
        return 0; // Valid out-of-order packet within window
    }
}
