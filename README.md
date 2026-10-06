# PQC-H365: Quantum-Resistant Hybrid VPN & Multi-Message Secure Transport

[![Q-Hack India 2026](https://img.shields.io/badge/Q--Hack%20India%202026-Quantum%20Security%20%26%20Cryptography-blueviolet?style=for-the-badge)](https://github.com/chipashacosmas/PQC-H365)
[![Demo Video](https://img.shields.io/badge/YouTube-Live%20Demo%20Video-red?style=for-the-badge&logo=youtube)](https://youtube.com/watch?v=KZSbHbDPfOk)
[![Presentation Deck](https://img.shields.io/badge/Slide%20Deck-PPTX%20%2F%20PDF-orange?style=for-the-badge&logo=microsoftpowerpoint)](docs/Q-Hack_India26_PQC_H365_FINAL.pptx)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue?style=for-the-badge)](LICENSE)

> **Official Q-Hack India 2026 Submission**  
> **Team:** PQC H-365 | **Lead:** Cosmas Chipasha  
> **Track:** Quantum Security & Cryptography  
> **Live Video Demo:** [Watch on YouTube (2 min)](https://youtube.com/watch?v=KZSbHbDPfOk)  
> **Slide Deck:** [Q-Hack_India26_PQC_H365_FINAL.pptx](docs/Q-Hack_India26_PQC_H365_FINAL.pptx) | [PDF View](docs/Q-Hack_India26_PQC_H365.pdf)

---

## 🌟 Key Architecture & Features

### 🔐 1. Cryptography & Standards Compliance
* **NIST FIPS 203**: ML-KEM-768 Post-Quantum Key Encapsulation Mechanism.
* **NIST FIPS 204**: ML-DSA-65 Post-Quantum Digital Signature Algorithm for Mutual Authentication (mPQC).
* **Classical Hybrid DH**: X25519 Ephemeral Key Exchange.
* **HKDF-SHA256**: RFC 5869 Hybrid Key Derivation Function.
* **AEAD Cipher**: AES-256-GCM (NIST SP 800-38D) with 64-bit sequence numbers.
* **Crypto-Agility Engine**: Dynamic runtime switching (`-m classical | pqc | hybrid`).

### ⚡ 2. High-Performance C Data Plane
* **Multithreaded Parallel Engine (`pthread`)**: Executes classical X25519 and ML-KEM-768 concurrently to cap crypto latency to $\max(T_{\text{classical}}, T_{\text{pqc}})$.
* **Non-Blocking I/O**: Event-driven `select()` event loop multiplexing up to 64 active client connections.
* **Kernel Network Router**: Linux `/dev/net/tun` virtual interface data plane (`tun0` / `tun1`).
* **eBPF / XDP Fast-Path**: In-kernel XDP packet hook loader (`ebpf_xdp.c`) for bare-metal line-rate packet routing.
* **Multi-Path Channel Bonding**: AEAD frame multiplexing (`multipath.c`) round-robin across physical network interfaces.

### 🛡️ 3. Advanced Defensive Engineering
* **DPI Traffic Camouflage**: Dynamic pseudorandom frame padding (16-128 bytes) masking payload size signatures against Deep Packet Inspection state firewalls.
* **Signed Anti-Downgrade Lock**: `PQC_POLICY_STRICT_PQC` signed payload binding to prevent active MitM quantum-stripping attacks.
* **Zero-Trust Micro-Segmentation (ZTNA)**: Layer 7 identity-based IP/Port access control policy engine (`ztna.c`).
* **Anti-Replay Window**: IPsec RFC 6479 standard 64-packet sliding window bitmask.
* **Quantum-Safe 0-RTT Session Resumption**: Instant resumption tickets (`pqc_session_ticket_t`) for seamless mobile handoffs.
* **Anti-DDoS Mitigations**: Automatic 5-second handshake inactivity cleanup.

### 📊 4. Fullstack Control Plane & Live Telemetry
* **Real-Time IPC Telemetry Pipeline**: Non-blocking UDP datagram socket (`127.0.0.1:9090`) emitting JSON metrics from the C server.
* **Node.js Management API**: Express API + native UDP `dgram` socket receiver listening to C server metrics.
* **React / Vite Dashboard**: Dark-mode dual-pane interface with animated **Recharts** rendering live production latency ($\text{ms}$), active client count, and daemon logs.
* **Empirical Benchmarking Suite**: `pqc_benchmark` tool outputting timing, memory, and wire tax comparisons to `benchmark_results.md`.

---

## 📁 Repository Structure

```text
pqc_hybrid_vpn/
├── CMakeLists.txt                 # CMake build manifest for C binaries & benchmarks
├── README.md                      # Project architecture & user guide
├── benchmark_results.md           # Automated empirical benchmarking report
├── dashboard/                     # React/Vite Dual-Pane Telemetry UI
│   ├── src/App.jsx                # Main Dashboard UI component
│   ├── src/MetricsChart.jsx       # Recharts live latency visualizer
│   └── package.json
├── management-api/                # Node.js Control Plane API
│   ├── server.js                  # Express API & UDP 9090 Telemetry Receiver
│   └── package.json
└── src/
    ├── benchmarks/
    │   └── benchmark.c            # Automated Empirical Micro-benchmarking Suite
    ├── client/
    │   └── hybrid_par_client.c    # Multithreaded mPQC Parallel Client
    ├── server/
    │   └── hybrid_par_server.c    # Multithreaded mPQC Parallel Server
    └── common/
        ├── aead.c / aead.h        # AES-256-GCM AEAD encryption
        ├── framing.c / framing.h  # Framing & Dynamic Camouflage Padding
        ├── hybrid_kdf.c           # HKDF-SHA256 session key derivation
        ├── state_machine.c        # Protocol State Machine & Anti-Replay Bitmask
        ├── telemetry.c            # UDP IPC Telemetry datagram sender
        ├── tun.c / tun.h          # Linux TUN/TAP virtual network driver
        ├── ztna.c / ztna.h        # Zero-Trust L7 Micro-Segmentation engine
        ├── multipath.c            # Multi-Path AEAD Channel Bonding pool
        └── ebpf_xdp.c             # eBPF / XDP kernel packet accelerator
```

---

## 🚀 Quick Start Guide

### 1. Compile the C Engine & Benchmarks
```bash
# Prepare build directory
mkdir -p build && cd build
cmake ..
make -j$(nproc)
```

### 2. Run Empirical Benchmarks
```bash
./pqc_benchmark
```
*Outputs a clean thesis report to `benchmark_results.md`!*

### 3. Launch Control Plane & Web Dashboard
```bash
# Terminal 1: Node.js Control API
cd management-api
npm install
node server.js

# Terminal 2: React Dashboard
cd dashboard
npm install
npm run dev
```
*Open `http://localhost:5173` to view the live dashboard!*

### 4. Run the Quantum-Resistant VPN Server & Client (Linux/WSL)
```bash
# Terminal 1: Launch Server (Root required for TUN interface allocation)
sudo ./build/pqc_hybrid_par_server

# Terminal 2: Connect Client
sudo ./build/pqc_hybrid_par_client 127.0.0.1
```

---

## 📜 License & Compliance
Designed in accordance with **NIST Post-Quantum Cryptography Standardization (FIPS 203 / FIPS 204)** and **NSA CNSA 2.0** deployment guidelines.
