#!/usr/bin/env bash
set -euo pipefail

# All acceptance entry points execute the sole current protocol pipeline.
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec bash "$ROOT_DIR/scripts/devnet-current-e2e.sh" "$@"
