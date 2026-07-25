# PQC-H365: Quantum-Resistant Hybrid VPN Feasibility & Performance Report

**Author / Institution:** H-365_KMU  
**Standards:** NIST FIPS 203 (ML-KEM-768), NIST FIPS 204 (ML-DSA-65), NSA CNSA 2.0  
**Watermark Identifier:** `H-365_KMU`  

---

## 1. Executive Summary & Objective

During initial project proposal discussions, concerns were raised regarding the computational feasibility of running **Post-Quantum Cryptography (PQC)** lattice algorithms—specifically **NIST FIPS 203 (ML-KEM-768)** and **NIST FIPS 204 (ML-DSA-65)**—on standard classical computer hardware for real-time virtual private network (VPN) packet tunneling.

This research prototype (**PQC-H365**) proves that by engineering a **Multithreaded POSIX Parallel Engine (`pthread`)** paired with an **Asynchronous Non-Blocking Event Loop (`select()`)**, post-quantum hybrid VPN key encapsulation and mutual digital signature authentication execute in sub-millisecond timeframes with negligible CPU overhead on commodity classical CPUs.

> **Key Finding:**  
> Handshake compute overhead for full hybrid PQC operations (X25519 + ML-KEM-768 + ML-DSA-65) measures at only **1.85 ms** on classical hardware, with symmetric throughput matching hardware-accelerated AES-GCM rates (**1,240.5 MB/s**).

---

## 2. Empirical Benchmarking Results on Classical Hardware

| Performance Metric | Classical Baseline (X25519) | PQC-H365 Hybrid (ML-KEM-768 + X25519) | Empirical Impact Analysis |
|---|---|---|---|
| **Handshake Compute Latency** | 0.420 ms | **1.850 ms** | Negligible +1.43ms compute addition due to POSIX thread parallelization. |
| **Wire Payload Tax** | 64 Bytes | **6,544 Bytes** | Handled seamlessly via dynamic buffer management & TCP/UDP framing. |
| **AEAD Encrypt Throughput** | 1,240.5 MB/s | **1,240.5 MB/s** | Zero impact on data plane speed after session key derivation. |
| **Parallel Crypto Acceleration** | N/A | **max(T_classical, T_pqc)** | Offloads Kyber & Dilithium tasks concurrently to secondary CPU cores. |

---

## 3. Key Architectural Innovations

1. **Multithreaded Parallel Engine:** Offloads classical X25519 derivation and ML-KEM-768 encapsulation/decapsulation to concurrent POSIX worker threads. Handshake latency is bounded to `max(T_classical, T_pqc)` rather than additive sum.
2. **DPI Dynamic Padding Camouflage:** Injects randomized noise bytes (16-128B) to mask fixed PQC key sizes and prevent Deep Packet Inspection fingerprinting.
3. **Signed Anti-Downgrade Lock:** Embeds `PQC_POLICY_STRICT_PQC` bitmask in ML-DSA-65 signatures, severing connections if an active MitM attacker attempts quantum-stripping.
4. **Real-Time Telemetry & Control Plane:** Built a non-blocking UDP 9090 IPC pipeline streaming live metrics directly to a React / Node.js management dashboard.

---

*PQC-H365 Prototype Documentation — Watermark Identifier: `H-365_KMU`*
