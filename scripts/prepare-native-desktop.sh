#!/usr/bin/env bash
# Check native build inputs. Never installs system packages or changes system paths.
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[ "$(uname -s)" = Linux ] || { printf 'Morph native desktop currently qualifies Linux only\n' >&2; exit 1; }
for tool in pkg-config ldconfig; do
  command -v "$tool" >/dev/null || { printf 'missing native build tool: %s\n' "$tool" >&2; exit 1; }
done
for package in fontconfig freetype2 xkbcommon wayland-client; do
  pkg-config --exists "$package" || { printf 'missing native development package: %s\n' "$package" >&2; exit 1; }
done
mkdir -p "$ROOT_DIR/target/native-libs"
if pkg-config --exists xkbcommon-x11; then
  exit 0
fi
# Some workstations have the compatible runtime and headers through the system
# GPUI package, but no unversioned linker name. Keep this opt-in build shim local.
runtime="$(ldconfig -p | awk '$1 == "libxkbcommon-x11.so.0" {value=$NF} END {print value}')"
[ -n "$runtime" ] && [ -f "$runtime" ] || { printf 'install libxkbcommon-x11 development/runtime libraries\n' >&2; exit 1; }
ln -sfn -- "$runtime" "$ROOT_DIR/target/native-libs/libxkbcommon-x11.so"
