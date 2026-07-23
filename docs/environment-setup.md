# Environment Setup

## 1. Host Machine

The development host can be Windows, but the actual prototype should run inside Linux VMs because the project depends on POSIX sockets, pthreads, Linux timing APIs, packet capture tools, and optional TUN/TAP networking later.

Recommended VM resources:

- CPU: 2 cores minimum, 4 cores preferred
- RAM: 4 GB minimum, 8 GB preferred
- Disk: 25 GB minimum
- Network: host-only adapter for isolated testing

## 2. Virtual Machines

Create these VMs in phases:

### Phase 1 VMs

- `pqc-client`: Ubuntu Server or Desktop
- `pqc-gateway`: Ubuntu Server or Desktop

### Phase 2 VM

- `pqc-adversary`: Kali Linux

Keep all VMs on a host-only network so test traffic cannot leave the lab.

## 3. Base Packages

Install the base toolchain:

```bash
sudo apt update
sudo apt install -y \
  build-essential \
  cmake \
  ninja-build \
  git \
  pkg-config \
  gdb \
  valgrind \
  clang-format \
  libssl-dev \
  tcpdump \
  tshark \
  iproute2 \
  net-tools \
  iperf3 \
  python3 \
  python3-pip \
  python3-venv
```

Install Python tools for later fuzzing and analysis:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install scapy pandas matplotlib
```

## 4. liboqs

The prototype needs liboqs for ML-KEM-768 and ML-DSA-65.

Recommended install location:

```bash
$HOME/opt/liboqs
```

Build from source:

```bash
git clone https://github.com/open-quantum-safe/liboqs.git ~/src/liboqs
cd ~/src/liboqs
mkdir -p build
cd build
cmake -GNinja \
  -DCMAKE_INSTALL_PREFIX=$HOME/opt/liboqs \
  -DOQS_BUILD_ONLY_LIB=ON \
  -DOQS_USE_OPENSSL=ON \
  ..
ninja
ninja install
```

Export paths:

```bash
export LIBOQS_ROOT=$HOME/opt/liboqs
export CMAKE_PREFIX_PATH=$LIBOQS_ROOT:$CMAKE_PREFIX_PATH
export LD_LIBRARY_PATH=$LIBOQS_ROOT/lib:$LD_LIBRARY_PATH
export PKG_CONFIG_PATH=$LIBOQS_ROOT/lib/pkgconfig:$PKG_CONFIG_PATH
```

Add those exports to `~/.bashrc` after confirming the build works.

## 5. OpenSSL

OpenSSL will be used for classical crypto and HKDF unless the implementation later chooses libsodium.

Check version:

```bash
openssl version
```

The first prototype should use the distribution-provided OpenSSL package through `libssl-dev`.

## 6. Network Verification

On each VM, check IP addresses:

```bash
ip addr
```

From `pqc-client`, test connectivity to `pqc-gateway`:

```bash
ping <gateway-host-only-ip>
```

Capture packets on the gateway:

```bash
sudo tcpdump -i <host-only-interface> -nn
```

## 7. Benchmark Tools

Use these tools during development:

- `clock_gettime`: handshake timing inside C code
- `tcpdump`/`tshark`: packet capture and fragmentation checks
- `iperf3`: baseline network throughput
- `valgrind`: memory safety checks
- `gdb`: debugging crashes
- `Scapy`: malformed packet and fuzz testing

## 8. Success Criteria For Environment

The environment is ready when:

- Both Linux VMs can ping each other on the host-only network.
- `gcc`, `cmake`, `ninja`, `openssl`, and `tcpdump` run successfully.
- liboqs builds and installs under `$HOME/opt/liboqs`.
- A simple TCP client/server can be compiled and run.

