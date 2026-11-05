#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd -- "$SCRIPT_DIR/.." && pwd)
CARGO_BIN=${CARGO:-cargo}
TARGET_TRIPLE=riscv64imac-unknown-none-elf
OUTPUT_DIR="$REPO_ROOT/target/$TARGET_TRIPLE/release"

if [[ -n "${CARGO_HOME:-}" ]]; then
  CARGO_HOME_DIR=$(cd -- "$CARGO_HOME" && pwd -P)
else
  CARGO_HOME_DIR=$(cd -- "${HOME:?HOME is required}/.cargo" && pwd -P)
fi

mkdir -p "$REPO_ROOT/target"
BUILD_DIR=$(mktemp -d "$REPO_ROOT/target/contract-build.XXXXXXXX")
cleanup_build_dir() {
  case "$BUILD_DIR" in
    "$REPO_ROOT"/target/contract-build.*)
      rm -rf -- "$BUILD_DIR"
      ;;
    *)
      echo "refusing to clean unexpected contract build directory: $BUILD_DIR" >&2
      ;;
  esac
}
trap cleanup_build_dir EXIT

scripts=(
  morph-state-lock
  morph-state-type
  morph-factory-type
  morph-factory-vault-lock
  morph-vault-lock
  morph-batch-lock
  morph-sponsor-lock
  morph-devnet-xudt
)

# Rust 1.95 no longer supports ckb-std dummy atomics with target-feature=-a.
# Match .cargo/config.toml and lower atomics for the single-threaded CKB-VM.
contract_rustflags="-C passes=lower-atomic"
contract_rustflags+=" --remap-path-prefix=$REPO_ROOT=/morph"
contract_rustflags+=" --remap-path-prefix=$CARGO_HOME_DIR=/cargo"

env -u CARGO_ENCODED_RUSTFLAGS \
  CARGO_TARGET_DIR="$BUILD_DIR" \
  RUSTFLAGS="$contract_rustflags" \
  "$CARGO_BIN" build --locked --release --target "$TARGET_TRIPLE" \
  -p morph-state-lock \
  -p morph-state-type \
  -p morph-factory-type \
  -p morph-factory-vault-lock \
  -p morph-vault-lock \
  -p morph-batch-lock \
  -p morph-sponsor-lock \
  -p morph-devnet-xudt

mkdir -p "$OUTPUT_DIR"
for script_name in "${scripts[@]}"; do
  install -m 0755 \
    "$BUILD_DIR/$TARGET_TRIPLE/release/$script_name" \
    "$OUTPUT_DIR/$script_name"
done

echo "built deterministic CKB contract ELFs in $OUTPUT_DIR"
