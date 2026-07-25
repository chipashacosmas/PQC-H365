#include "ztna.h"
#include <string.h>
#include <arpa/inet.h>

void pqc_ztna_init_policy(pqc_ztna_policy_t *policy, const uint8_t *client_id_hash) {
    if (!policy) return;
    memset(policy, 0, sizeof(pqc_ztna_policy_t));
    if (client_id_hash) {
        memcpy(policy->client_identity, client_id_hash, 64);
    }
    
    // Default Rule 1: Allow HTTPS traffic to 0.0.0.0 (Wildcard port 443)
    policy->rules[0].dest_ip = 0;
    policy->rules[0].dest_port = 443;
    policy->rules[0].allow = 1;

    // Default Rule 2: Allow DNS traffic to 0.0.0.0 (Wildcard port 53)
    policy->rules[1].dest_ip = 0;
    policy->rules[1].dest_port = 53;
    policy->rules[1].allow = 1;

    policy->rule_count = 2;
}

int pqc_ztna_evaluate_packet(const pqc_ztna_policy_t *policy, const uint8_t *packet, size_t len) {
    if (!policy || !packet || len < 20) {
        return 1; // Default allow if frame is non-IPv4 or unparsable
    }

    // Inspect IPv4 Header (Version == 4)
    uint8_t version = (packet[0] >> 4) & 0x0F;
    if (version != 4) return 1; 

    uint8_t ihl = (packet[0] & 0x0F) * 4;
    if (len < ihl + 4) return 1;

    uint8_t protocol = packet[9];
    uint32_t dest_ip;
    memcpy(&dest_ip, packet + 16, 4);

    uint16_t dest_port = 0;
    if (protocol == 6 || protocol == 17) { // TCP or UDP
        if (len >= ihl + 4) {
            uint16_t net_port;
            memcpy(&net_port, packet + ihl + 2, 2);
            dest_port = ntohs(net_port);
        }
    }

    // Evaluate ZTNA Rules
    for (size_t i = 0; i < policy->rule_count; i++) {
        const pqc_ztna_rule_t *rule = &policy->rules[i];
        
        int ip_match = (rule->dest_ip == 0 || rule->dest_ip == dest_ip);
        int port_match = (rule->dest_port == 0 || rule->dest_port == dest_port);

        if (ip_match && port_match) {
            return rule->allow ? 1 : 0;
        }
    }

    // Default Micro-Segmentation Zero-Trust Stance: Permitted unless explicitly restricted
    return 1;
}
