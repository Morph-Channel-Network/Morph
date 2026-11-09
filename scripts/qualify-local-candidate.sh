#!/usr/bin/env bash
# Produces local evidence/archive only. No release, tag, push or main merge.
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
OUT_DIR="${OUT_DIR:-target/local-candidate/$(date -u +%Y%m%dT%H%M%S)-$$}"
[ ! -e "$OUT_DIR" ] || { echo 'use a fresh OUT_DIR' >&2; exit 1; }
[ -z "$(git status --porcelain --untracked-files=no)" ] || { echo 'commit tracked changes before qualification' >&2; exit 1; }
mkdir -p "$OUT_DIR/logs"
OUT_DIR="$(cd "$OUT_DIR" && pwd)"
python3 -B scripts/current-stateful-ledger.py --run-dir "$OUT_DIR" --capture-provenance
make ci >"$OUT_DIR/logs/make-ci.log" 2>&1
python3 -B - "$OUT_DIR" <<'PY'
import hashlib, importlib.util, json, subprocess, sys
from pathlib import Path
root=Path.cwd()
run=Path(sys.argv[1])
spec=importlib.util.spec_from_file_location('candidate_ledger',root/'scripts/current-stateful-ledger.py')
ledger=importlib.util.module_from_spec(spec)
spec.loader.exec_module(ledger)
before=json.loads((run/'source-provenance.json').read_text())
unchanged=before['git_commit_full']==subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip() and before['source_tree_sha256']==ledger.source_digest()
if before['git_dirty'] or not unchanged:
    raise SystemExit('source changed during full CI')
receipt={'schema':'morph.local_ci_receipt.v1','command':['make','ci'],'exit_code':0,
         'source_commit':before['git_commit_full'],'source_tree_sha256':before['source_tree_sha256'],
         'tracked_clean_before':True,'source_unchanged':True,
         'log_sha256':hashlib.sha256((run/'logs/make-ci.log').read_bytes()).hexdigest()}
(run/'ci-receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
PY
OUT_DIR="$OUT_DIR/native" scripts/devnet-current-e2e.sh
make package-contract-release >"$OUT_DIR/logs/package-contracts.log" 2>&1
cp target/morph-current-custody.tar.gz "$OUT_DIR/morph-current-custody.tar.gz"
make package-desktop >"$OUT_DIR/logs/package-desktop.log" 2>&1
cp target/morph-desktop-linux-x86_64.tar.gz "$OUT_DIR/morph-desktop-linux-x86_64.tar.gz"
python3 -B scripts/export-current-public-evidence.py \
  --run-dir "$OUT_DIR/native" --source-commit "$(git rev-parse HEAD)" \
  --ci-log "$OUT_DIR/logs/make-ci.log" --output-dir "$OUT_DIR/public-evidence"
python3 -B scripts/verify-local-candidate.py \
  --public-evidence "$OUT_DIR/public-evidence" --bundle "$OUT_DIR/morph-current-custody.tar.gz" \
  --desktop-bundle "$OUT_DIR/morph-desktop-linux-x86_64.tar.gz" \
  --ci-receipt "$OUT_DIR/ci-receipt.json" >"$OUT_DIR/qualification.json"
printf 'Local qualification passed: %s/qualification.json\n' "$OUT_DIR"
