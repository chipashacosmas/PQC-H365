# Secure Transport Summary

## Test Context

- Environment: Ubuntu Server VM under VirtualBox
- Transport: TCP over localhost (`127.0.0.1`)
- Hybrid key exchange: X25519 + ML-KEM-768
- Session key derivation: HKDF-SHA256
- Authentication: ML-DSA-65 transcript signature
- Payload encryption: AES-256-GCM

## Secure Payload Flow

The secure transport test performs an authenticated hybrid handshake, verifies the ML-DSA-65 transcript signature, then uses the derived 32-byte session key to encrypt and decrypt an application payload.

```text
X25519 shared secret ||
ML-KEM-768 shared secret
        |
        v
HKDF-SHA256 session key
        |
        v
AES-256-GCM encrypted payload
```

## Observed Result

| Item | Value |
|---|---:|
| Plaintext size | 55 bytes |
| Ciphertext size | 55 bytes |
| AES-GCM nonce | 12 bytes |
| AES-GCM tag | 16 bytes |
| Total encrypted packet | 83 bytes |

Packet size calculation:

```text
12-byte nonce + 16-byte GCM tag + 55-byte ciphertext = 83 bytes
```

## Timing

| Side | Operation | Time ms |
|---|---|---:|
| Client | AES-256-GCM encrypt | 0.028 |
| Client | secure payload total | 54.585 |
| Server | AES-256-GCM decrypt | 0.015 |
| Server | secure payload total | 54.766 |

## Verification

The client and server derived the same secure session key fingerprint:

```text
d82210f6675432b4
```

The server decrypted the payload successfully:

```text
PQC secure payload after authenticated hybrid handshake
```

Result:

```text
PASS
```

## Interpretation

The prototype now demonstrates secure application data transport after authenticated hybrid key establishment. The derived hybrid session key is not only produced and matched across endpoints; it is used for AEAD encryption and authentication through AES-256-GCM.

Current limitation: this is still a single-message secure transport proof. A production-style tunnel would need message counters, nonce management across many packets, replay protection, session rekeying, and integration with a TUN/TAP interface or another packet-forwarding mechanism.

## Benchmarking

Secure transport can be included in the repeated benchmark runner:

```bash
cd /media/sf_PQC_H-365_V0
python3 benchmarks/run_handshake_bench.py --runs 20
python3 benchmarks/summarize_handshake_results.py
```

The benchmark runner includes both:

- `hybrid_auth`: authenticated hybrid handshake with ML-DSA transcript verification
- `secure_transport`: authenticated hybrid handshake plus AES-256-GCM encrypted payload transport

