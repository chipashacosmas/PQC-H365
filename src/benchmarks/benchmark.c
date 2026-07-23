#include "aead.h"
#include "framing.h"
#include "hybrid_kdf.h"
#include "secret_print.h"
#include "timing.h"

#include <oqs/oqs.h>
#include <openssl/evp.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ITERATIONS 100
#define X25519_LEN 32U

static EVP_PKEY *generate_x25519(void) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    EVP_PKEY *key = NULL;
    if (ctx && EVP_PKEY_keygen_init(ctx) > 0) EVP_PKEY_keygen(ctx, &key);
    EVP_PKEY_CTX_free(ctx);
    return key;
}

static int derive_x25519(EVP_PKEY *priv, EVP_PKEY *peer, uint8_t *sec, size_t *slen) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(priv, NULL);
    if (!ctx) return -1;
    int ok = EVP_PKEY_derive_init(ctx) > 0 &&
             EVP_PKEY_derive_set_peer(ctx, peer) > 0 &&
             EVP_PKEY_derive(ctx, sec, slen) > 0;
    EVP_PKEY_CTX_free(ctx);
    return ok ? 0 : -1;
}

int main(void) {
    printf("========================================================================\n");
    printf("     POST-QUANTUM HYBRID VPN (PQC-H365) EMPIRICAL BENCHMARK SUITE       \n");
    printf("========================================================================\n");
    printf("Running %d iterations per crypto suite...\n\n", ITERATIONS);

    OQS_init();

    // -------------------------------------------------------------------------
    // 1. CLASSICAL BENCHMARK (X25519)
    // -------------------------------------------------------------------------
    uint64_t x_keygen_time = 0, x_derive_time = 0;
    for (int i = 0; i < ITERATIONS; i++) {
        uint64_t t0 = pqc_now_ns();
        EVP_PKEY *s_key = generate_x25519();
        EVP_PKEY *c_key = generate_x25519();
        uint64_t t1 = pqc_now_ns();
        x_keygen_time += (t1 - t0);

        uint8_t sec[32]; size_t slen = sizeof(sec);
        uint64_t t2 = pqc_now_ns();
        derive_x25519(s_key, c_key, sec, &slen);
        uint64_t t3 = pqc_now_ns();
        x_derive_time += (t3 - t2);

        EVP_PKEY_free(s_key);
        EVP_PKEY_free(c_key);
    }
    double avg_x_keygen = (double)x_keygen_time / (ITERATIONS * 1e6);
    double avg_x_derive = (double)x_derive_time / (ITERATIONS * 1e6);

    // -------------------------------------------------------------------------
    // 2. PURE POST-QUANTUM BENCHMARK (ML-KEM-768 + ML-DSA-65)
    // -------------------------------------------------------------------------
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    OQS_SIG *dsa = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);

    uint64_t kem_keypair_time = 0, kem_encaps_time = 0, kem_decaps_time = 0;
    uint64_t dsa_sign_time = 0, dsa_verify_time = 0;

    for (int i = 0; i < ITERATIONS; i++) {
        uint8_t *k_pub = malloc(kem->length_public_key);
        uint8_t *k_sec = malloc(kem->length_secret_key);
        uint8_t *k_ct  = malloc(kem->length_ciphertext);
        uint8_t k_ss1[32], k_ss2[32];

        uint64_t t0 = pqc_now_ns();
        OQS_KEM_keypair(kem, k_pub, k_sec);
        uint64_t t1 = pqc_now_ns();
        kem_keypair_time += (t1 - t0);

        uint64_t t2 = pqc_now_ns();
        OQS_KEM_encaps(kem, k_ct, k_ss1, k_pub);
        uint64_t t3 = pqc_now_ns();
        kem_encaps_time += (t3 - t2);

        uint64_t t4 = pqc_now_ns();
        OQS_KEM_decaps(kem, k_ss2, k_ct, k_sec);
        uint64_t t5 = pqc_now_ns();
        kem_decaps_time += (t5 - t4);

        // ML-DSA
        uint8_t *d_pub = malloc(dsa->length_public_key);
        uint8_t *d_sec = malloc(dsa->length_secret_key);
        uint8_t *sig   = malloc(dsa->length_signature);
        size_t sig_len = 0;

        OQS_SIG_keypair(dsa, d_pub, d_sec);

        uint64_t t6 = pqc_now_ns();
        OQS_SIG_sign(dsa, sig, &sig_len, k_ss1, 32, d_sec);
        uint64_t t7 = pqc_now_ns();
        dsa_sign_time += (t7 - t6);

        uint64_t t8 = pqc_now_ns();
        OQS_SIG_verify(dsa, k_ss1, 32, sig, sig_len, d_pub);
        uint64_t t9 = pqc_now_ns();
        dsa_verify_time += (t9 - t8);

        free(k_pub); free(k_sec); free(k_ct);
        free(d_pub); free(d_sec); free(sig);
    }

    double avg_kem_keypair = (double)kem_keypair_time / (ITERATIONS * 1e6);
    double avg_kem_encaps  = (double)kem_encaps_time / (ITERATIONS * 1e6);
    double avg_kem_decaps  = (double)kem_decaps_time / (ITERATIONS * 1e6);
    double avg_dsa_sign    = (double)dsa_sign_time / (ITERATIONS * 1e6);
    double avg_dsa_verify  = (double)dsa_verify_time / (ITERATIONS * 1e6);

    // -------------------------------------------------------------------------
    // 3. AEAD THROUGHPUT (AES-256-GCM)
    // -------------------------------------------------------------------------
    size_t chunk_size = 64 * 1024; // 64 KB packets
    int aead_count = 1000;
    uint8_t key[32] = {0x42};
    uint8_t nonce[12] = {0};
    uint8_t *plain = malloc(chunk_size);
    uint8_t *cipher = malloc(chunk_size);
    uint8_t tag[16];
    memset(plain, 'A', chunk_size);

    uint64_t aead_start = pqc_now_ns();
    for (int i = 0; i < aead_count; i++) {
        pqc_aes256_gcm_encrypt(key, nonce, plain, chunk_size, NULL, 0, cipher, tag);
    }
    uint64_t aead_end = pqc_now_ns();
    double aead_time_sec = (double)(aead_end - aead_start) / 1e9;
    double total_mb = (double)(chunk_size * aead_count) / (1024.0 * 1024.0);
    double throughput_mbps = total_mb / aead_time_sec;

    free(plain); free(cipher);

    // -------------------------------------------------------------------------
    // SUMMARY REPORT GENERATION
    // -------------------------------------------------------------------------
    size_t classical_wire_tax = X25519_LEN * 2; // Server PK + Client PK
    size_t pqc_wire_tax = kem->length_public_key + kem->length_ciphertext + dsa->length_public_key + dsa->length_signature;
    size_t hybrid_wire_tax = classical_wire_tax + pqc_wire_tax;

    printf("+---------------------------------------------------------------------------------+\n");
    printf("|                              EMPIRICAL RESULTS TABLE                            |\n");
    printf("+------------------------------+--------------------+-----------------------------+\n");
    printf("| Metric                       | Classical (X25519) | Hybrid Quantum-Resistant    |\n");
    printf("+------------------------------+--------------------+-----------------------------+\n");
    printf("| Handshake Compute Latency    | %8.3f ms        | %8.3f ms                 |\n", 
           avg_x_keygen + avg_x_derive, 
           avg_x_keygen + avg_x_derive + avg_kem_keypair + avg_kem_encaps + avg_kem_decaps + avg_dsa_sign + avg_dsa_verify);
    printf("| Wire Overhead (Payload Tax)  | %8zu Bytes      | %8zu Bytes               |\n", classical_wire_tax, hybrid_wire_tax);
    printf("| Wire Tax Inflation Ratio     |        1.0x        | %8.1fx                     |\n", (double)hybrid_wire_tax / classical_wire_tax);
    printf("| AEAD Encryption Throughput   | %8.1f MB/s      | %8.1f MB/s               |\n", throughput_mbps, throughput_mbps);
    printf("+------------------------------+--------------------+-----------------------------+\n\n");

    printf("Detailed Breakdown for NIST FIPS Algorithms:\n");
    printf("  * ML-KEM-768  (FIPS 203) Keypair: %.3f ms | Encaps: %.3f ms | Decaps: %.3f ms\n", avg_kem_keypair, avg_kem_encaps, avg_kem_decaps);
    printf("  * ML-DSA-65   (FIPS 204) Sign:    %.3f ms | Verify: %.3f ms\n", avg_dsa_sign, avg_dsa_verify);
    printf("  * Public Key Size Tax: ML-KEM (%zu B) + ML-DSA (%zu B) vs X25519 (%u B)\n", kem->length_public_key, dsa->length_public_key, X25519_LEN);

    // Save Markdown summary file for thesis / presentation use
    FILE *f = fopen("benchmark_results.md", "w");
    if (f) {
        fprintf(f, "# PQC-H365 Empirical Benchmarking Report\n\n");
        fprintf(f, "## Handshake & Cryptographic Overhead\n\n");
        fprintf(f, "| Metric | Classical (X25519) | Pure PQC (ML-KEM/DSA) | Hybrid (X25519 + ML-KEM/DSA) |\n");
        fprintf(f, "|---|---|---|---|\n");
        fprintf(f, "| Key Exchange Latency | %.3f ms | %.3f ms | %.3f ms |\n", 
                avg_x_keygen + avg_x_derive,
                avg_kem_keypair + avg_kem_encaps + avg_kem_decaps,
                avg_x_keygen + avg_x_derive + avg_kem_keypair + avg_kem_encaps + avg_kem_decaps);
        fprintf(f, "| Authentication Latency | N/A | %.3f ms | %.3f ms |\n", avg_dsa_sign + avg_dsa_verify, avg_dsa_sign + avg_dsa_verify);
        fprintf(f, "| Wire Payload Tax | %zu Bytes | %zu Bytes | %zu Bytes |\n", classical_wire_tax, pqc_wire_tax, hybrid_wire_tax);
        fprintf(f, "| AEAD Throughput | %.1f MB/s | %.1f MB/s | %.1f MB/s |\n\n", throughput_mbps, throughput_mbps, throughput_mbps);
        fprintf(f, "### Key Findings\n");
        fprintf(f, "- **Payload Inflation**: Hybrid mode incurs a **%.1fx wire overhead** due to ML-DSA signatures and ML-KEM public keys.\n", (double)hybrid_wire_tax / classical_wire_tax);
        fprintf(f, "- **NIST Standards**: Implements **FIPS 203** (ML-KEM) and **FIPS 204** (ML-DSA).\n");
        fclose(f);
        printf("\nSaved clean thesis report to `benchmark_results.md`!\n");
    }

    OQS_KEM_free(kem);
    OQS_SIG_free(dsa);
    OQS_destroy();
    return 0;
}
