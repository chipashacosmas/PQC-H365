# Handshake Benchmark Summary

## Test Context

- Environment: Ubuntu Server VM under VirtualBox
- Transport: TCP over localhost (`127.0.0.1`)
- Algorithms: X25519, ML-KEM-768, HKDF-SHA256
- Measurement: application-level handshake timing in milliseconds
- Note: localhost VM timing is suitable for comparative prototype evaluation, not public-network latency claims

## Results

| Mode | Runs | Client Avg ms | Client Min ms | Client Max ms | Server Avg ms | Server Min ms | Server Max ms | Fingerprints Match |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| Classical X25519 | 20 | 1.558 | 0.450 | 2.880 | 0.547 | 0.313 | 0.799 | Yes |
| ML-KEM-768 | 20 | 8.432 | 3.636 | 11.821 | 7.225 | 3.606 | 9.726 | Yes |
| Sequential Hybrid | 20 | 55.559 | 42.393 | 127.366 | 56.314 | 42.892 | 129.821 | Yes |
| Parallel Hybrid | 20 | 10.268 | 5.013 | 18.410 | 11.789 | 6.253 | 18.648 | Yes |

## Sequential vs Parallel Hybrid

| Side | Sequential Avg ms | Parallel Avg ms | Reduction |
|---|---:|---:|---:|
| Client | 55.559 | 10.268 | 81.5% |
| Server | 56.314 | 11.789 | 79.1% |

## Interpretation

The parallel hybrid handshake reduced average handshake time compared with the sequential hybrid baseline. This supports the project objective that independent classical and post-quantum operations can be scheduled concurrently to reduce cumulative handshake latency while still deriving the same hybrid session key on both endpoints.
