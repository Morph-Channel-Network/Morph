#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd -- "$SCRIPT_DIR/.." && pwd)
CONTRACT_DIR="$REPO_ROOT/target/riscv64imac-unknown-none-elf/release"
OUTPUT_PARENT="$REPO_ROOT/target"

mkdir -p "$OUTPUT_PARENT"
STAGING_DIR=$(mktemp -d "$OUTPUT_PARENT/contract-release.XXXXXXXX")
cleanup_staging_dir() {
  case "$STAGING_DIR" in
    "$OUTPUT_PARENT"/contract-release.*)
      rm -rf -- "$STAGING_DIR"
      ;;
    *)
      echo "refusing to clean unexpected staging directory: $STAGING_DIR" >&2
      ;;
  esac
}
trap cleanup_staging_dir EXIT
ARTIFACT_DIR="$STAGING_DIR/morph-current-custody"
mkdir -p "$ARTIFACT_DIR/contracts"

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

for script_name in "${scripts[@]}"; do
  install -m 0755 "$CONTRACT_DIR/$script_name" "$ARTIFACT_DIR/contracts/$script_name"
done
install -m 0644 \
  "$REPO_ROOT/release/factory-preproduction/contracts.json" \
  "$ARTIFACT_DIR/contracts.json"
install -m 0644 \
  "$REPO_ROOT/release/factory-preproduction/envelope.json" \
  "$ARTIFACT_DIR/envelope.json"
install -m 0644 \
  "$REPO_ROOT/release/factory-preproduction/README.md" \
  "$ARTIFACT_DIR/README.md"
install -m 0644 \
  "$REPO_ROOT/release/factory-preproduction/watch-policy.json" \
  "$ARTIFACT_DIR/watch-policy.json"
install -m 0644 \
  "$REPO_ROOT/release/factory-preproduction/publication-profile.json" \
  "$ARTIFACT_DIR/publication-profile.json"
install -m 0644 \
  "$REPO_ROOT/release/factory-preproduction/watch-config.example.json" \
  "$ARTIFACT_DIR/watch-config.example.json"

(
  cd "$ARTIFACT_DIR"
  sha256sum contracts/* contracts.json envelope.json README.md \
    watch-policy.json publication-profile.json watch-config.example.json > SHA256SUMS
)

STAGED_ARCHIVE="$STAGING_DIR/morph-current-custody.tar.gz"
tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner \
  -C "$STAGING_DIR" -cf - morph-current-custody \
  | gzip -n > "$STAGED_ARCHIVE"
ARCHIVE_PATH="$OUTPUT_PARENT/morph-current-custody.tar.gz"
install -m 0644 "$STAGED_ARCHIVE" "$ARCHIVE_PATH"

echo "temporary release staging verified and scheduled for cleanup: $ARTIFACT_DIR"
echo "contract release archive: $ARCHIVE_PATH"
