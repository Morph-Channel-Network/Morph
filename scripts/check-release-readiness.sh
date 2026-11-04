#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd -- "$SCRIPT_DIR/.." && pwd)

required_files=(
  "release/factory-preproduction/contracts.json"
  "release/factory-preproduction/envelope.json"
  "release/factory-preproduction/README.md"
  "release/factory-preproduction/watch-policy.json"
  "release/factory-preproduction/publication-profile.json"
  "release/factory-preproduction/watch-config.example.json"
  "docs/preproduction-envelope.md"
  "docs/runbooks/README.md"
  "docs/runbooks/operations.md"
  "docs/runbooks/incident-response.md"
  "docs/runbooks/upgrade-and-migration.md"
  "docs/runbooks/rehearsal-2026-08-15.md"
)

for relative_path in "${required_files[@]}"; do
  if [[ ! -s "$REPO_ROOT/$relative_path" ]]; then
    echo "missing or empty release-readiness file: $relative_path" >&2
    exit 1
  fi
done

cd "$REPO_ROOT"
grep -q "chain_reorg_detected" docs/runbooks/incident-response.md
grep -q "Historical formats and in-place migrations are rejected" docs/runbooks/upgrade-and-migration.md
grep -q "Real assets | Prohibited" docs/preproduction-envelope.md
cargo run -q -p morph-cli -- validate-watch-policy \
  release/factory-preproduction/watch-policy.json
cargo run -q -p morph-cli -- validate-watch-config \
  release/factory-preproduction/watch-config.example.json

echo "Morph current custody release-readiness documents verified"
