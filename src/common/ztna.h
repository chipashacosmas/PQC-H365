#ifndef PQC_ZTNA_H
#define PQC_ZTNA_H

#include <stdint.h>
#include <stddef.h>

#define PQC_ZTNA_MAX_RULES 16

typedef struct {
    uint32_t dest_ip;       // Allowed destination IP (0 = wildcard)
    uint16_t dest_port;     // Allowed destination port (0 = wildcard)
    uint8_t allow;          // 1 = Allow, 0 = Deny
} pqc_ztna_rule_t;

typedef struct {
    uint8_t client_identity[64]; // Hashed ML-DSA-65 client ID
    pqc_ztna_rule_t rules[PQC_ZTNA_MAX_RULES];
    size_t rule_count;
} pqc_ztna_policy_t;

// Initializes default Zero-Trust Micro-Segmentation policy
void pqc_ztna_init_policy(pqc_ztna_policy_t *policy, const uint8_t *client_id_hash);

// Evaluates an IP packet payload against ZTNA policy rules
// Returns 1 if permitted by Micro-Segmentation policy, 0 if dropped
int pqc_ztna_evaluate_packet(const pqc_ztna_policy_t *policy, const uint8_t *packet, size_t len);

#endif // PQC_ZTNA_H
