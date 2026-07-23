#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="$ROOT_DIR/build"

cmake -S "$ROOT_DIR" -B "$BUILD_DIR" -GNinja
ninja -C "$BUILD_DIR"

tests=(
  check_liboqs
  test_ml_kem
  test_ml_dsa
  test_x25519
  test_hybrid_kdf
  test_adaptive_buffer
)

for test_name in "${tests[@]}"; do
  echo
  echo "== Running $test_name =="
  "$BUILD_DIR/$test_name"
done

echo
echo "== Running network correctness tests =="
python3 "$ROOT_DIR/scripts/run_network_tests.py"

echo
echo "All local and network correctness tests passed."
