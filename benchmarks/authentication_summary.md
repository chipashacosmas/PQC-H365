# Authentication Summary

## Test Context

- Environment: Ubuntu Server VM under VirtualBox
- Transport: TCP over localhost (`127.0.0.1`)
- Authentication algorithm: ML-DSA-65 through `liboqs`
- Hybrid key exchange: X25519 + ML-KEM-768
- Session key derivation: HKDF-SHA256

## ML-DSA-65 Network Authentication Test

The standalone authentication exchange verified that ML-DSA-65 signatures can be generated, transmitted, and verified over the project framing layer.

| Item | Size bytes | Result |
|---|---:|---|
| ML-DSA-65 public key | 1952 | PASS |
| Authentication message | 33 | PASS |
| ML-DSA-65 signature | 3309 | PASS |
| Client signature verification | N/A | PASS |

Observed timing:

| Side | Operation | Time ms |
|---|---|---:|
| Server | ML-DSA keypair | 9.666 |
| Server | ML-DSA sign | 0.501 |
| Client | ML-DSA verify | 6.889 |
| Client | Network auth verification | 7.737 |

## Authenticated Hybrid Handshake Test

The authenticated hybrid handshake signs the real handshake transcript:

```text
server_x25519_public ||
server_ml_kem_public ||
server_ml_dsa_public ||
client_x25519_public ||
client_ml_kem_ciphertext
```

The client verifies this ML-DSA-65 signature before accepting the derived hybrid session key.

| Item | Size bytes | Result |
|---|---:|---|
| Server X25519 public key | 32 | PASS |
| Server ML-KEM-768 public key | 1184 | PASS |
| Server ML-DSA-65 public key | 1952 | PASS |
| Client X25519 public key | 32 | PASS |
| Client ML-KEM-768 ciphertext | 1088 | PASS |
| Signed transcript | 4288 | PASS |
| ML-DSA-65 signature | 3309 | PASS |
| Client transcript verification | N/A | PASS |
| Client/server session key match | N/A | PASS |

Observed timing:

| Side | Operation | Time ms |
|---|---|---:|
| Client | derive + encaps + HKDF | 4.308 |
| Client | ML-DSA verify | 3.284 |
| Client | authenticated hybrid handshake | 13.864 |
| Server | derive + decaps + HKDF | 0.747 |
| Server | ML-DSA sign | 0.591 |
| Server | authenticated hybrid handshake | 5.846 |

## Interpretation

The prototype now authenticates the hybrid handshake transcript using ML-DSA-65. This prevents the client from accepting unauthenticated key-exchange material and moves the design closer to a VPN-style authenticated key establishment protocol.

Current limitation: the server currently signs using an ephemeral ML-DSA key generated at runtime and sends the public key during the same exchange. For a production-like trust model, the server ML-DSA public key should be pinned, pre-distributed, or validated through a certificate-like trust mechanism.

