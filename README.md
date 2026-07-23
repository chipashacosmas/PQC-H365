# PQC Hybrid VPN Research Prototype

This repository is for building a Linux-based research prototype of a hybrid post-quantum VPN-style encrypted tunnel.

The first implementation target is a TCP client/server prototype that performs a measurable handshake, then incrementally adds:

- X25519 classical key exchange
- ML-KEM-768 post-quantum key exchange through liboqs
- ML-DSA-65 authentication through liboqs
- HKDF-SHA256 hybrid session key derivation
- Parallel handshake execution with pthreads
- Adaptive message framing and receive buffers
- Benchmarking and isolated fuzz testing

## Recommended Lab Shape

Use Linux virtual machines on a host-only network:

- `pqc-client`: client endpoint
- `pqc-gateway`: server/gateway endpoint
- `pqc-adversary`: Kali Linux node for Scapy, tcpdump, malformed packets, and downgrade tests

Start with the client and gateway only. Add the adversary VM after the basic handshake works.

## Repository Layout

```text
docs/
  environment-setup.md
scripts/
  setup_ubuntu.sh
src/
  client/
  server/
  common/
tests/
  kat/
  fuzz/
benchmarks/
```

## First Setup Step

On Ubuntu/Debian inside the Linux VM:

```bash
chmod +x scripts/setup_ubuntu.sh
./scripts/setup_ubuntu.sh
```

Then verify:

```bash
gcc --version
cmake --version
openssl version
python3 --version
```

