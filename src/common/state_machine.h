#ifndef PQC_STATE_MACHINE_H
#define PQC_STATE_MACHINE_H

#include "framing.h"
#include <stdint.h>
#include <sys/time.h>

// Connection states for the protocol handshake
typedef enum {
    STATE_INIT = 0,
    STATE_WAIT_CLIENT_HELLO,
    STATE_SEND_SERVER_HELLO,
    STATE_SEND_KEM_PUBLIC_KEY,
    STATE_WAIT_KEM_ENCAPSULATION,
    STATE_SEND_KEM_CIPHERTEXT,
    STATE_SEND_X25519_PUBLIC_KEY,
    STATE_WAIT_X25519_PUBLIC_KEY,
    STATE_SEND_HYBRID_KEM_PUBLIC_KEY,
    STATE_WAIT_HYBRID_KEM_ENCAPSULATION,
    STATE_SEND_DSA_SIGNATURE,
    STATE_WAIT_DSA_SIGNATURE,
    STATE_ESTABLISHED,
    STATE_DATA_PLANE,
    STATE_ERROR,
    STATE_CLOSED
} pqc_conn_state_t;

// Crypto-Agility Modes
typedef enum {
    MODE_CLASSICAL = 0,
    MODE_PURE_PQC,
    MODE_HYBRID
} pqc_crypto_mode_t;

// Sliding Window Anti-Replay Structure (64-packet window)
typedef struct {
    uint64_t last_seq;
    uint64_t window_mask;
} pqc_anti_replay_t;

// Connection structure
typedef struct {
    int fd;
    pqc_conn_state_t state;
    pqc_crypto_mode_t mode;
    pqc_anti_replay_t anti_replay;
    uint64_t tx_seq;
    
    // Partial read/write buffers for non-blocking I/O
    uint8_t read_buffer[PQC_MAX_FRAME_SIZE];
    uint32_t read_bytes_expected;
    uint32_t read_bytes_received;
    
    uint8_t write_buffer[PQC_MAX_FRAME_SIZE];
    uint32_t write_bytes_total;
    uint32_t write_bytes_sent;

    // Last activity timestamp for timeouts
    struct timeval last_activity;
} pqc_connection_t;

// Helper functions for state machine & anti-replay
void pqc_conn_init(pqc_connection_t *conn, int fd);
int pqc_anti_replay_check_and_update(pqc_anti_replay_t *ar, uint64_t seq_num);

#endif // PQC_STATE_MACHINE_H
