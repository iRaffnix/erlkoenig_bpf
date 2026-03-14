#!/usr/bin/env bash
#
# Build uBPF and the ubpf_port binary from scratch.
#
# Prerequisites: gcc, cmake, libelf-dev
#   sudo apt install build-essential cmake libelf-dev
#
# Usage:
#   ./scripts/build_ubpf.sh
#

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
THIRD_PARTY="$ROOT/third-party"
UBPF_SRC="$THIRD_PARTY/src/ubpf"
UBPF_BLD="$THIRD_PARTY/bld"
UBPF_LIB="$THIRD_PARTY/lib"

echo "=== erlkoenig_bpf: uBPF build script ==="
echo ""

# --- Step 1: Clone uBPF ---
if [ -d "$UBPF_SRC" ]; then
    echo "[1/4] uBPF source already exists at $UBPF_SRC, skipping clone."
else
    echo "[1/4] Cloning uBPF..."
    git clone https://github.com/iovisor/ubpf.git "$UBPF_SRC"
    cd "$UBPF_SRC"
    git submodule update --init --recursive
    cd "$ROOT"
fi

# --- Step 2: Build uBPF ---
echo "[2/4] Building uBPF..."
rm -rf "$UBPF_BLD"
cmake -B "$UBPF_BLD" \
      -S "$UBPF_SRC" \
      -DCMAKE_INSTALL_PREFIX="$UBPF_LIB" \
      -DUBPF_ENABLE_TESTS=OFF \
      -DUBPF_ENABLE_INSTALL=ON \
      -DCMAKE_BUILD_TYPE=Release
make -C "$UBPF_BLD" -j"$(nproc)"

# --- Step 3: Install uBPF ---
echo "[3/4] Installing uBPF to $UBPF_LIB..."
make -C "$UBPF_BLD" install

# --- Step 4: Build ubpf_port ---
echo "[4/4] Building ubpf_port..."
make -C "$ROOT/c_src"

# --- Done ---
echo ""
echo "Done. ubpf_port built at: $ROOT/priv/ubpf_port"
echo ""
echo "Run tests with: rebar3 eunit"
