#!/usr/bin/env bash
# Local packaging only. No release, upload, deployment or tag.
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
mkdir -p target
stage="$(mktemp -d "$ROOT_DIR/target/native-desktop.XXXXXXXX")"
trap 'rm -rf -- "$stage"' EXIT
bundle="morph-desktop-linux-$(uname -m)"
cargo run --locked -q -p morph-xtask -- desktop-bundle \
  --binary "$ROOT_DIR/target/desktop/morph-desktop" --output-dir "$stage/$bundle"
(
  cd "$stage/$bundle"
  find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS
  sha256sum -c SHA256SUMS >/dev/null
)
tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner -C "$stage" -cf - "$bundle" | gzip -n > "$stage/$bundle.tar.gz"
install -m 0644 "$stage/$bundle.tar.gz" "$ROOT_DIR/target/$bundle.tar.gz"
printf 'Local native desktop bundle: %s/target/%s.tar.gz\n' "$ROOT_DIR" "$bundle"
