# Adaptive Buffer/Framing Test Summary

## Test Context

- Environment: Ubuntu Server VM under VirtualBox
- Test method: local UNIX `socketpair` using the project framing layer
- Framing format: 4-byte network-order length prefix followed by payload bytes
- Configured maximum frame size: `4096` bytes
- Purpose: verify that post-quantum-sized payloads can be transmitted through the application framing layer without truncation, and that oversized frames are rejected

## Payload Sizes Tested

| Payload Type | Size bytes | Expected Result | Actual Result |
|---|---:|---|---|
| ML-KEM-768 public key equivalent | 1184 | Accepted | PASS |
| ML-DSA-65 signature equivalent | 3309 | Accepted | PASS |
| Maximum allowed application frame | 4096 | Accepted | PASS |
| Oversized payload | 4097 | Rejected | PASS |

## Interpretation

The framing layer successfully transmitted and verified payloads matching the expected ML-KEM-768 public key size and ML-DSA-65 signature size. It also accepted the configured maximum frame size of `4096` bytes and rejected a `4097` byte oversized payload.

This supports the adaptive buffer objective at the application layer: the prototype can safely handle large post-quantum handshake payloads without relying on small legacy buffers. This result should not be overstated as full IP MTU fragmentation prevention; MTU behavior must be tested separately with packet capture tools such as `tcpdump` or `tshark`.

