# Project Status

## Current Build Stage

The prototype has reached the first working hybrid handshake milestone. The system now includes standalone cryptographic tests, TCP framing tests, sequential hybrid network handshake, parallel hybrid network handshake, and repeatable benchmark reporting.

## Environment

- Platform: Ubuntu Server VM running in VirtualBox
- Host access: Windows PowerShell SSH through VirtualBox NAT port forwarding
- SSH forwarding: host `127.0.0.1:2222` to guest `10.0.2.15:22`
- Project path in Ubuntu: `/media/sf_PQC_H-365_V0`
- Project path in Windows: `C:\Users\365\Documents\PQC_H-365 V0`
- PQC library: `liboqs` installed at `/home/h-365/opt/liboqs`
- Python environment: `/home/h-365/pqc-venv`

## Implemented Binaries

| Binary | Purpose |
|---|---|
| `pqc_server` | Basic TCP framed-message server |
| `pqc_client` | Basic TCP framed-message client |
| `pqc_kem_server` | ML-KEM-768 network handshake server |
| `pqc_kem_client` | ML-KEM-768 network handshake client |
| `pqc_x25519_server` | X25519 network handshake server |
| `pqc_x25519_client` | X25519 network handshake client |
| `pqc_hybrid_seq_server` | Sequential hybrid X25519 + ML-KEM + HKDF server |
| `pqc_hybrid_seq_client` | Sequential hybrid X25519 + ML-KEM + HKDF client |
| `pqc_hybrid_par_server` | Parallel hybrid X25519 + ML-KEM + HKDF server |
| `pqc_hybrid_par_client` | Parallel hybrid X25519 + ML-KEM + HKDF client |
| `pqc_dsa_auth_server` | ML-DSA-65 network authentication server |
| `pqc_dsa_auth_client` | ML-DSA-65 network authentication client |
| `pqc_hybrid_auth_server` | Authenticated hybrid handshake server |
| `pqc_hybrid_auth_client` | Authenticated hybrid handshake client |
| `pqc_secure_server` | Authenticated hybrid handshake plus AES-256-GCM payload decryption server |
| `pqc_secure_client` | Authenticated hybrid handshake plus AES-256-GCM payload encryption client |
| `check_liboqs` | Verifies ML-KEM-768 and ML-DSA-65 availability |
| `test_ml_kem` | Standalone ML-KEM-768 correctness/timing test |
| `test_ml_dsa` | Standalone ML-DSA-65 correctness/timing test |
| `test_x25519` | Standalone X25519 correctness/timing test |
| `test_hybrid_kdf` | Standalone X25519 + ML-KEM HKDF test |
| `test_adaptive_buffer` | Application framing/buffer boundary test |

## Verified Results

### Cryptographic Correctness

- ML-KEM-768 keypair, encapsulation, and decapsulation: PASS
- ML-DSA-65 keypair, signing, and verification: PASS
- X25519 shared secret derivation: PASS
- Hybrid HKDF session-key derivation: PASS
- liboqs algorithm detection for ML-KEM-768 and ML-DSA-65: PASS

### Network Handshakes

- Basic framed TCP client/server: PASS
- ML-KEM-768 over TCP: PASS
- X25519 over TCP: PASS
- Sequential hybrid network handshake: PASS
- Parallel hybrid network handshake: PASS
- ML-DSA-65 authentication over TCP: PASS
- Authenticated hybrid handshake transcript: PASS
- Encrypted AES-256-GCM payload after authenticated hybrid handshake: PASS

### Adaptive Buffer/Framing

- 1184-byte ML-KEM public-key-sized frame: PASS
- 3309-byte ML-DSA signature-sized frame: PASS
- 4096-byte maximum frame: PASS
- 4097-byte oversized frame rejection: PASS

## Benchmark Evidence

Current 20-run benchmark summary:

| Mode | Client Avg ms | Server Avg ms |
|---|---:|---:|
| Classical X25519 | 1.558 | 0.547 |
| ML-KEM-768 | 8.432 | 7.225 |
| Sequential Hybrid | 55.559 | 56.314 |
| Parallel Hybrid | 10.268 | 11.789 |

The benchmark runner now also supports:

- Authenticated Hybrid
- Secure Transport

Sequential-to-parallel reduction:

| Side | Sequential Avg ms | Parallel Avg ms | Reduction |
|---|---:|---:|---:|
| Client | 55.559 | 10.268 | 81.5% |
| Server | 56.314 | 11.789 | 79.1% |

Evidence files:

- `benchmarks/handshake_results.csv`
- `benchmarks/handshake_summary.md`
- `benchmarks/adaptive_buffer_summary.md`
- `benchmarks/authentication_summary.md`
- `benchmarks/secure_transport_summary.md`

## Verification Command

Run all local and network correctness tests:

```bash
cd /media/sf_PQC_H-365_V0
./scripts/run_all_tests.sh
```

Expected final output:

```text
All local and network correctness tests passed.
```

## Current Technical Boundary

The prototype currently proves application-layer TCP framing, post-quantum key exchange, classical key exchange, hybrid key derivation, parallel handshake scheduling, and application-level buffer handling.
It also proves ML-DSA transcript authentication and encrypted application payload transport using AES-256-GCM with the derived hybrid session key.

It does not yet implement:

- TUN/TAP OS-level VPN routing
- public-network deployment
- IP-layer MTU fragmentation measurement
- Kali/Scapy adversarial fuzzing

## Next Recommended Step

Step 27 should add encrypted application payload transport after the authenticated hybrid handshake. The derived 32-byte HKDF session key can be used with an AEAD mode such as AES-256-GCM or ChaCha20-Poly1305.
