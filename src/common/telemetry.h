#ifndef PQC_TELEMETRY_H
#define PQC_TELEMETRY_H

#include <stdint.h>

// Initializes non-blocking UDP telemetry socket targeting 127.0.0.1:target_port
int pqc_telemetry_init(uint16_t target_port);

// Sends a JSON telemetry frame for a completed handshake event
int pqc_telemetry_send_handshake(const char *mode, double latency_ms, int active_clients);

// Sends a JSON telemetry frame for packet/throughput metrics
int pqc_telemetry_send_metrics(uint64_t bytes_sent, uint64_t bytes_recv, int active_clients);

// Closes telemetry socket
void pqc_telemetry_cleanup(void);

#endif // PQC_TELEMETRY_H
