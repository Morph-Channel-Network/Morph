#!/usr/bin/env bash
# Produces local evidence/archive only. No release, tag, push or main merge.
set -euo pipefail
umask 077
export CARGO_TERM_COLOR=never
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
OUT_DIR="${OUT_DIR:-.local-evidence/$(date -u +%Y%m%dT%H%M%S)-$$}"
[ ! -e "$OUT_DIR" ] || { echo 'use a fresh OUT_DIR' >&2; exit 1; }
[ -z "$(git status --porcelain --untracked-files=no)" ] || { echo 'commit tracked changes before qualification' >&2; exit 1; }
mkdir -p "$OUT_DIR/logs"
OUT_DIR="$(cd "$OUT_DIR" && pwd)"
# A new cache prefix prevents pre-existing bytecode from being imported; source
# provenance still includes every untracked implementation source file.
export PYTHONPYCACHEPREFIX="$OUT_DIR/python-cache"
export PYTHONDONTWRITEBYTECODE=1
python3 -B scripts/current-stateful-ledger.py --run-dir "$OUT_DIR" --capture-provenance
python3 -B - "$OUT_DIR/source-provenance.json" <<'PY_SOURCE'
import json, sys
with open(sys.argv[1]) as file:
    source = json.load(file)
if source["git_dirty"]:
    raise SystemExit("pre-build source includes tracked changes or untracked implementation files")
PY_SOURCE
# Prepare exact ELFs before capturing integration identity. Preparation itself
# must preserve the pre-build source inventory above.
make build-contracts >"$OUT_DIR/logs/prepare-contracts.log" 2>&1
python3 -B scripts/local-integration-evidence.py prepare --output "$OUT_DIR"
run_gate() {
  python3 -B scripts/verify-integration-evidence.py --plan "$OUT_DIR/integration-plan.json" \
    run --candidate "$OUT_DIR/integration-candidate.json" --gate "$1" \
    --output "$OUT_DIR/gates/$1" --timeout 21600
}
run_gate ci
python3 -B scripts/local-integration-evidence.py ci-receipt --output "$OUT_DIR"
run_gate native
run_gate signer-lifecycle
run_gate cooperative-close
run_gate typed-conditions
run_gate fuzz
run_gate shadow-service
run_gate contracts-package
cp target/morph-current-custody.tar.gz "$OUT_DIR/morph-current-custody.tar.gz"
run_gate desktop-package
cp target/morph-desktop-linux-x86_64.tar.gz "$OUT_DIR/morph-desktop-linux-x86_64.tar.gz"
python3 -B scripts/export-current-public-evidence.py \
  --run-dir "$OUT_DIR/native" --source-commit "$(git rev-parse HEAD)" \
  --ci-log "$OUT_DIR/gates/ci/output.private.log" --output-dir "$OUT_DIR/public-evidence"
run_gate qualification
python3 -B scripts/local-integration-evidence.py finish --output "$OUT_DIR"
printf 'Local qualification passed: %s/qualification.json\n' "$OUT_DIR"
printf 'Public integration index: %s/integration-public\n' "$OUT_DIR"
