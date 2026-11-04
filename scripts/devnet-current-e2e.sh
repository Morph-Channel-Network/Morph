#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
CKB_BIN="${CKB_BIN:-$(command -v ckb || true)}"
RPC_PORT="${RPC_PORT:-19124}"
P2P_PORT="${P2P_PORT:-19125}"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%S)-$$}"
OUT_DIR="${OUT_DIR:-target/current-protocol-e2e/$RUN_ID}"
FIBER_DIR="${FIBER_DIR:-$ROOT_DIR/../fiber}"
NODE_PID=""
RPC_URL="${EXTERNAL_RPC_URL:-http://127.0.0.1:$RPC_PORT}"

fail() { printf '[current-e2e] %s\n' "$*" >&2; exit 1; }
stop_node() {
  if [ -n "$NODE_PID" ] && kill -0 "$NODE_PID" 2>/dev/null; then
    kill "$NODE_PID"
    wait "$NODE_PID" || true
  fi
}
trap stop_node EXIT
for tool in cargo make jq curl python3; do command -v "$tool" >/dev/null || fail "missing $tool"; done
[ -n "$CKB_BIN" ] && [ -x "$CKB_BIN" ] || fail "set CKB_BIN to a devnet CKB executable"
[ ! -e "$OUT_DIR" ] || fail "OUT_DIR already exists; use a fresh run directory"
mkdir -p "$OUT_DIR/logs"
OUT_DIR="$(cd "$OUT_DIR" && pwd)"
MATRIX_DIR="$OUT_DIR/scenarios/smoke"
CLI_BIN="$OUT_DIR/morph-cli"
mkdir -p "$MATRIX_DIR/contracts"
python3 scripts/current-stateful-ledger.py --run-dir "$OUT_DIR" --capture-provenance

read_key() {
  local variable="$1" path="$2" value="${!1:-}"
  if [ -z "$value" ]; then
    [ -f "$path" ] || fail "missing fixture key file for $variable"
    value="$(tr -d '\r\n' <"$path")"
  fi
  [[ "$value" =~ ^(0x)?[0-9a-fA-F]{64}$ ]] || fail "invalid fixture key for $variable"
  printf -v "$variable" '%s' "$value"
  export "$variable"
}
read_key MORPH_DEVNET_PRIVATE_KEY "${MORPH_E2E_DEPLOYER_KEY_FILE:-$FIBER_DIR/tests/nodes/deployer/ckb/plain_key}"
read_key MORPH_ALICE_PRIVATE_KEY "${MORPH_E2E_ALICE_KEY_FILE:-$FIBER_DIR/tests/nodes/1/ckb/plain_key}"
read_key MORPH_BOB_PRIVATE_KEY "${MORPH_E2E_BOB_KEY_FILE:-$FIBER_DIR/tests/nodes/2/ckb/plain_key}"
printf '[current-e2e] building current contracts and CLI\n'
make build-contracts >"$OUT_DIR/logs/build-contracts.log" 2>&1
cargo build -p morph-cli --features devnet >"$OUT_DIR/logs/build-cli.log" 2>&1
cp target/debug/morph-cli "$CLI_BIN"
"$CLI_BIN" devnet --help >"$OUT_DIR/logs/cli-capability.txt"
for contract in morph-state-type morph-state-lock morph-vault-lock morph-batch-lock morph-sponsor-lock morph-factory-type morph-factory-vault-lock morph-devnet-xudt; do
  cp "target/riscv64imac-unknown-none-elf/release/$contract" "$MATRIX_DIR/contracts/$contract"
done

if [ -n "${EXTERNAL_RPC_URL:-}" ]; then
  curl --fail --silent -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"get_tip_header","params":[]}' "$RPC_URL" >"$OUT_DIR/initial-tip.json"
else
  # The node assembler must pay the independently selected funding wallet.
  # Only its public key is passed to this hash operation.
  PUBLIC_KEY="$("$CLI_BIN" devnet --devnet-only derive-operator-pubkey --json | jq -er '.pubkey_sec1')"
  BLOCK_ASSEMBLER_ARG="$(python3 - "$PUBLIC_KEY" <<'PY'
import hashlib,sys
print('0x'+hashlib.blake2b(bytes.fromhex(sys.argv[1].removeprefix('0x')),digest_size=32,person=b'ckb-default-hash').digest()[:20].hex())
PY
  )"
  CKB_BIN="$CKB_BIN" CKB_DIR="$OUT_DIR/node" RPC_PORT="$RPC_PORT" P2P_PORT="$P2P_PORT" BLOCK_ASSEMBLER_ARG="$BLOCK_ASSEMBLER_ARG" \
    bash scripts/devnet-node.sh >"$OUT_DIR/logs/node.log" 2>&1 &
  NODE_PID="$!"
  for _ in $(seq 1 60); do
    if curl --fail --silent -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"get_tip_header","params":[]}' "$RPC_URL" >"$OUT_DIR/initial-tip.json"; then break; fi
    kill -0 "$NODE_PID" 2>/dev/null || fail "node exited; see node.log"
    sleep 1
  done
  jq -e '.result.hash' "$OUT_DIR/initial-tip.json" >/dev/null || fail "node RPC did not become ready"
fi
curl --fail --silent -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"get_blockchain_info","params":[]}' "$RPC_URL" >"$OUT_DIR/chain-info.json"
python3 - "$OUT_DIR/chain-info.json" <<'PYCHAIN'
import json,sys
info=json.load(open(sys.argv[1]))
if 'dev' not in str(info.get('result',{}).get('chain','')).lower():
    raise SystemExit('current acceptance requires a no-value development chain')
PYCHAIN
curl --fail --silent -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"get_block_hash","params":["0x0"]}' "$RPC_URL" >"$OUT_DIR/genesis.json"
curl --fail --silent -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"get_local_node_info","params":[]}' "$RPC_URL" >"$OUT_DIR/node-info.json"
"$CLI_BIN" devnet --devnet-only --rpc-url "$RPC_URL" mine --blocks 6 --json >"$OUT_DIR/mine.json"
"$CLI_BIN" devnet --devnet-only --rpc-url "$RPC_URL" deploy-contracts --contracts-dir "$MATRIX_DIR/contracts" --json >"$MATRIX_DIR/deployment.json"
"$CLI_BIN" print-contract-manifest --contracts-dir "$MATRIX_DIR/contracts" >"$MATRIX_DIR/contracts.json"
printf '[current-e2e] running independent shared-wallet bilateral lifecycle\n'
"$CLI_BIN" devnet --devnet-only --rpc-url "$RPC_URL" multi-asset-smoke --shared-funding --fee 100000 \
  --contracts-dir "$MATRIX_DIR/contracts" --store-dir "$MATRIX_DIR/shared-packages" --json >"$MATRIX_DIR/shared-acceptance.json" 2>"$OUT_DIR/logs/shared-acceptance.log"
printf '[current-e2e] running independent funding, asset removal/admission and unilateral settlement\n'
"$CLI_BIN" devnet --devnet-only --rpc-url "$RPC_URL" multi-asset-smoke --splice-transitions --fee 100000 \
  --contracts-dir "$MATRIX_DIR/contracts" --store-dir "$MATRIX_DIR/splice-packages" --json >"$MATRIX_DIR/acceptance.json" 2>"$OUT_DIR/logs/acceptance.log"
printf '[current-e2e] running native Factory funding, independent journals and same-path activation handoff\n'
"$CLI_BIN" devnet --devnet-only --rpc-url "$RPC_URL" factory smoke \
  --contracts-dir "$MATRIX_DIR/contracts" --store-dir "$MATRIX_DIR/factory-packages" >"$MATRIX_DIR/factory-acceptance.json" 2>"$OUT_DIR/logs/factory-acceptance.log"
printf '[current-e2e] running continuous watch service, sponsor and canonical reorg recovery\n'
"$CLI_BIN" devnet --devnet-only --rpc-url "$RPC_URL" publication-profile-fixture --json >"$MATRIX_DIR/publication-profile.json"
# The ceremony deliberately mines stale-state checks and automatic Sponsor
# funding before correction. Keep all reserved safety blocks and give that
# development rehearsal its own 64-block challenge window.
python3 - "$MATRIX_DIR/publication-profile.json" <<'PROFILE'
from pathlib import Path
import json,sys
path=Path(sys.argv[1]); profile=json.loads(path.read_text())
profile['window']['configured_challenge_blocks']=64
path.write_text(json.dumps(profile,indent=2)+'\n')
PROFILE
"$CLI_BIN" devnet --devnet-only --rpc-url "$RPC_URL" multi-asset-smoke \
  --shared-funding --sponsor-publication --watch-publication --watch-reorg --fee 100000 \
  --finalise-since "$(jq -er '.window.configured_challenge_blocks' "$MATRIX_DIR/publication-profile.json")" \
  --publication-profile "$MATRIX_DIR/publication-profile.json" --contracts-dir "$MATRIX_DIR/contracts" \
  --store-dir "$MATRIX_DIR/watch-service-packages" --json >"$MATRIX_DIR/watch-service-acceptance.json" 2>"$OUT_DIR/logs/watch-service-acceptance.log"
printf '[current-e2e] running eight-asset complete-set lifecycle\n'
"$CLI_BIN" devnet --devnet-only --rpc-url "$RPC_URL" multi-asset-smoke --shared-funding --asset-count 8 --fee 100000 \
  --contracts-dir "$MATRIX_DIR/contracts" --store-dir "$MATRIX_DIR/eight-asset-packages" --json >"$MATRIX_DIR/eight-asset-acceptance.json" 2>"$OUT_DIR/logs/eight-asset-acceptance.log"
python3 - "$OUT_DIR" "$MATRIX_DIR" "$CKB_BIN" "$RPC_URL" <<'PY'
from pathlib import Path
import datetime,hashlib,json,os,subprocess,sys
run=Path(sys.argv[1]);out=Path(sys.argv[2]); report=json.loads((out/'acceptance.json').read_text())
factory=json.loads((out/'factory-acceptance.json').read_text())
shared=json.loads((out/'shared-acceptance.json').read_text())
watched=json.loads((out/'watch-service-acceptance.json').read_text())
maximum=json.loads((out/'eight-asset-acceptance.json').read_text())
trace=Path(report['transitions']['trace_file']); records=json.loads(trace.read_text())
assert len(records)==2
assert all(x['withheld_bridge_receipt_reconciled'] for x in report['transitions']['operations'])
assert all(x['status']=='Committed' for x in report['transitions']['terminal'])
assert factory['root']['report']['status']=='Committed'
assert factory['activation']['report']['status']=='Committed'
assert factory['canonical_replay']['canonical_replay']
assert factory['wrong_key_preserves_journal'] and factory['partial_export_cannot_poison_path'] and factory['same_path_handoff']
assert factory['transitions']['withheld_full_consent_escaped'] and factory['transitions']['peer_refreshed_from_public_changes']
assert factory['transitions']['child']['reduced']['finalise']['status']=='Committed'
assert factory['transitions']['child']['terminal']['finalise']['status']=='Committed'
assert factory['transitions']['child']['terminal']['retained_factory']['retired']
assert shared['shared_funding'] and shared['finalise']['status']=='Committed'
assert watched['finalise']['status']=='Committed' and any(p.get('reorg_recovery') for p in watched['watch_passes'])
assert any(p.get('service',{}).get('published_count')==1 for p in watched['watch_passes'])
assert maximum['asset_count']==8 and maximum['shared_funding'] and maximum['finalise']['status']=='Committed'
cases=[{'name':name,'kind':kind,'report_path':report} for name,kind,report in [
 ('bilateral_shared','bilateral_shared','shared-acceptance.json'),
 ('bilateral_splice','splice','acceptance.json'),
 ('factory_custody_and_children','factory','factory-acceptance.json'),
 ('watch_service_reorg','watch_service','watch-service-acceptance.json'),
 ('maximum_asset_lifecycle','bilateral_max_assets','eight-asset-acceptance.json')]]
(out/'matrix.json').write_text(json.dumps({'schema':'morph.current_acceptance_matrix.v1','cases':cases},indent=2)+'\n')
genesis=json.loads((run/'genesis.json').read_text()).get('result')
assert isinstance(genesis,str) and genesis.startswith('0x') and len(genesis)==66
node_info=json.loads((run/'node-info.json').read_text()).get('result') or {}
evidence={'schema':'morph.current_splice_fixture_evidence.v1','scope':'development node acceptance; maximum-dimension cases do not approve pilot admission or real assets',
 'rpc_url':sys.argv[4],'genesis_hash':genesis,
 'contracts_manifest':'scenarios/smoke/contracts.json','deployment':'scenarios/smoke/deployment.json',
 'recorded_at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
 'node_version':node_info.get('version'),
 'runner_binary_version':subprocess.check_output([str(run/'morph-cli'),'--version'],text=True).strip(),
 'descriptor_version':5,'trace_sha256':hashlib.sha256(trace.read_bytes()).hexdigest(),
 'cli_sha256':hashlib.sha256((run/'morph-cli').read_bytes()).hexdigest(),
 'contract_sha256':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted((out/'contracts').iterdir())},
 'command':'scripts/devnet-current-e2e.sh','root_funding':report['fund'],'root_activation':report['activation'],
 'transitions':report['transitions']['operations'],'terminal':report['transitions']['terminal'],
 'factory':factory}
(run/'evidence.json').write_text(json.dumps(evidence,indent=2)+'\n')
if os.environ.get('MORPH_UPDATE_FIXTURES')=='1':
 dest=Path('sdk/typescript/test/fixtures/multi-asset-splice-transitions.json')
 dest.write_bytes(trace.read_bytes());dest.with_suffix('.evidence.json').write_text(json.dumps(evidence,indent=2)+'\n')
print('[current-e2e] native cases completed; artifacts: '+str(run))
PY
python3 scripts/current-stateful-ledger.py --run-dir "$OUT_DIR" --cli "$CLI_BIN"
"$CLI_BIN" devnet-smoke-report --dir "$MATRIX_DIR" --json >"$MATRIX_DIR/summary.json"
"$CLI_BIN" devnet-stateful-report --dir "$OUT_DIR/scenarios" \
  --audit-profile "${AUDIT_PROFILE:-docs/devnet-audit-profile.example.json}" --json >"$OUT_DIR/scenarios/summary.json"
"$CLI_BIN" devnet-smoke-assert --dir "$MATRIX_DIR" --contracts-dir "$MATRIX_DIR/contracts" \
  --budget-profile "${BUDGET_PROFILE:-docs/devnet-stateful-budget.example.json}" --json >"$MATRIX_DIR/summary-check.json"
"$CLI_BIN" devnet-stateful-assert --dir "$OUT_DIR/scenarios" --contracts-dir "$MATRIX_DIR/contracts" \
  --budget-profile "${BUDGET_PROFILE:-docs/devnet-stateful-budget.example.json}" \
  --audit-profile "${AUDIT_PROFILE:-docs/devnet-audit-profile.example.json}" --json >"$OUT_DIR/scenarios/summary-check.json"
LATEST_LINK="target/current-protocol-e2e/latest"
if [ -e "$LATEST_LINK" ] && [ ! -L "$LATEST_LINK" ]; then
  fail "refusing to replace non-symlink $LATEST_LINK"
fi
mkdir -p "$(dirname "$LATEST_LINK")"
ln -s "$OUT_DIR" "$LATEST_LINK.next-$$"
mv -Tf "$LATEST_LINK.next-$$" "$LATEST_LINK"
printf '[current-e2e] strict budget, audit, and source freshness gates passed: %s\n' "$OUT_DIR"
