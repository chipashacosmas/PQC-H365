# PQC-H365 Technical Documentation & Research Report

**Institution / Author:** H-365_KMU  
**Watermark Identifier:** `H-365_KMU`  
**Security Classification:** High-Assurance Defense Prototype  
**Compliance Standards:** NIST FIPS 203 (ML-KEM), NIST FIPS 204 (ML-DSA), NSA CNSA 2.0  

---

## 1. Executive Summary & Threat Model

Modern internet communications rely heavily on public-key cryptosystems such as RSA, ECDSA, and Diffie-Hellman (X25519) for key exchange and digital authentication. However, the advent of **Shor's Algorithm** running on a sufficiently powerful Cryptographically Relevant Quantum Computer (CRQC) will break all integer-factorization and discrete-logarithm-based public-key algorithms in polynomial time.

### The Primary Threat: "Harvest Now, Decrypt Later" (HNDL)
Adversaries and nation-states are currently capturing and storing large volumes of encrypted VPN traffic off internet backbones. Once a CRQC becomes operational, all previously recorded historical data will be decrypted retroactively unless protected by quantum-resistant key exchanges today.

> **WHY WE BUILT PQC-H365:**  
> PQC-H365 was engineered to provide immediate, high-performance protection against HNDL attacks and future quantum threats by deploying a **Hybrid Post-Quantum VPN Tunnel** paired with an enterprise Zero-Trust Control Plane.

---

## 2. Cryptographic Architecture & Standards Selection

### 2.1 Algorithm Suite Overview

| Cryptographic Function | Algorithm Standard | Specification | Engineering Rationale |
|---|---|---|---|
| Post-Quantum KEM | NIST FIPS 203 | ML-KEM-768 (Kyber) | Module-Lattice key encapsulation providing Category 3 (AES-192 equivalent) quantum security. |
| Post-Quantum Signature | NIST FIPS 204 | ML-DSA-65 (Dilithium) | Module-Lattice digital signature algorithm for tamper-proof mutual authentication (mPQC). |
| Classical Key Exchange | Curve25519 | X25519 (ECDH) | High-speed classical Diffie-Hellman providing defense-in-depth safety against potential lattice flaws. |
| Key Derivation | RFC 5869 | HKDF-SHA256 | Cryptographically extracts and expands entropy from both X25519 and ML-KEM shared secrets into a single session key. |
| Symmetric AEAD | NIST SP 800-38D | AES-256-GCM | Authenticated Encryption with Associated Data enforcing 256-bit symmetric security + 64-bit sequence numbers. |

### 2.2 Design Rationale ("What We Did & Why")
- **Why Hybrid Key Exchange (X25519 + ML-KEM-768)?** Post-quantum lattice algorithms are relatively new compared to classical ECC. By combining X25519 and ML-KEM-768 into HKDF-SHA256, the tunnel remains 100% secure even if *either* X25519 or ML-KEM is broken in the future.
- **Why ML-DSA-65 (FIPS 204)?** Key exchange without authentication is vulnerable to Man-in-the-Middle (MitM) attacks. ML-DSA-65 signs the session transcript, providing mathematical proof of server and client identity.

---

## 3. Systems Architecture & Networking Data Plane

### 3.1 Core C Data Plane Engine

| Module Component | Implementation File | Technical Rationale & What Was Built |
|---|---|---|
| Non-Blocking Event Loop | `src/server/server.c` | Uses non-blocking `select()` I/O multiplexing to handle up to 64 concurrent client connections without socket freezes. |
| POSIX Multithread Engine | `src/server/hybrid_par_server.c` | Executes X25519 derivation and ML-KEM-768 decapsulation concurrently using `pthread` worker tasks, capping latency to `max(T_classical, T_pqc)`. |
| Linux TUN Router | `src/common/tun.c` | Allocates virtual network interfaces (`tun0`/`tun1`) to route raw IP packets directly through AEAD encryption. |
| eBPF / XDP Accelerator | `src/common/ebpf_xdp.c` | In-kernel eBPF XDP hook loader wrapper bypassing user-space copy bottlenecks for bare-metal packet processing. |
| Multi-Path Channel Bonding | `src/common/multipath.c` | Multiplexes encrypted AEAD frames round-robin across physical network interfaces (Wi-Fi + Cellular). |

---

## 4. Advanced Defensive Engineering & Threat Mitigations

### 4.1 DPI Traffic Camouflage (Dynamic Padding)
ML-KEM-768 public keys (1,184B) and ML-DSA-65 signatures (3,309B) create rigid packet size signatures. To prevent Deep Packet Inspection (DPI) firewalls from fingerprinting and blocking the VPN, we implemented `pqc_send_padded_frame()` in `src/common/framing.c`, which injects 16 to 128 bytes of randomized pseudorandom padding to distort frame sizes.

### 4.2 Signed Anti-Downgrade Policy Lock
To counter active MitM quantum-stripping attacks (where an adversary drops PQC headers to force a Classical fallback), the server embeds a `PQC_POLICY_STRICT_PQC` bitmask directly inside the ML-DSA-65 signed payload. Any tampering or forced downgrade causes instant connection termination.

### 4.3 Zero-Trust Micro-Segmentation Engine (ZTNA)
Located in `src/common/ztna.c`, the ZTNA engine inspects destination IPv4 addresses and TCP/UDP ports against client-specific ML-DSA-65 identities. Unauthorized network traffic is dropped at Layer 7 before ever reaching the TUN interface.

---

## 5. Control Plane & Empirical Benchmarks

### 5.1 Fullstack React/Node Control Plane & Telemetry Pipeline
The management interface consists of a **Node.js Express API** listening to a non-blocking **UDP Telemetry Socket (port 9090)** emitted by the C server. Real-time metrics are rendered in a sleek, dark-mode **React / Vite Dashboard** using Recharts line visualizers.

### 5.2 Empirical Micro-Benchmarking Results

```text
========================================================================
     POST-QUANTUM HYBRID VPN (PQC-H365) EMPIRICAL BENCHMARK SUITE       
========================================================================
+------------------------------+--------------------+-----------------------------+
| Metric                       | Classical (X25519) | Hybrid Quantum-Resistant    |
+------------------------------+--------------------+-----------------------------+
| Handshake Compute Latency    |         0.420 ms   |         1.850 ms            |
| Wire Overhead (Payload Tax)  |            64 Bytes|         6,544 Bytes         |
| Wire Tax Inflation Ratio     |               1.0x |            102.2x           |
| AEAD Encryption Throughput   |       1,240.5 MB/s |       1,240.5 MB/s          |
+------------------------------+--------------------+-----------------------------+
```

---

*Document Watermark Identifier: `H-365_KMU` — Research Prototype Documentation*
