#!/usr/bin/env bash
set -euo pipefail

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

python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install scapy pandas matplotlib

mkdir -p "$HOME/src" "$HOME/opt"

cat <<'MSG'

Base environment installed.

Next manual step: build liboqs.

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

Then export:

  export LIBOQS_ROOT=$HOME/opt/liboqs
  export CMAKE_PREFIX_PATH=$LIBOQS_ROOT:$CMAKE_PREFIX_PATH
  export LD_LIBRARY_PATH=$LIBOQS_ROOT/lib:$LD_LIBRARY_PATH
  export PKG_CONFIG_PATH=$LIBOQS_ROOT/lib/pkgconfig:$PKG_CONFIG_PATH

MSG

