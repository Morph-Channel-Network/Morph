#!/usr/bin/env bash
# Focused no-value native participant-key service qualification. This reuses the
# current builders, ceremonies, same-path handoffs and settlement runner.
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
source scripts/private-key-files.sh
morph_reject_raw_private_keys
CKB_BIN="${CKB_BIN:-$(command -v ckb || true)}"
RPC_PORT="${RPC_PORT:-19964}"
P2P_PORT="${P2P_PORT:-19965}"
OUT_DIR="${OUT_DIR:-target/participant-signer-e2e/$(date -u +%Y%m%dT%H%M%S)-$$}"
FIBER_DIR="${FIBER_DIR:-$ROOT_DIR/../fiber}"
CONTRACTS_DIR="${CONTRACTS_DIR:-target/riscv64imac-unknown-none-elf/release}"
SCENARIO="${SCENARIO:-lifecycle}"
case "$SCENARIO" in lifecycle|close|factory-close) ;; *) printf 'SCENARIO must be lifecycle, close or factory-close\n' >&2; exit 1 ;; esac
export SCENARIO
NODE_PID=""
cleanup() {
  if [ -n "$NODE_PID" ] && kill -0 "$NODE_PID" 2>/dev/null; then kill "$NODE_PID"; wait "$NODE_PID" || true; fi
  morph_fixture_keys_cleanup
}
trap cleanup EXIT
[ -n "$CKB_BIN" ] && [ -x "$CKB_BIN" ] || { printf 'set CKB_BIN to a CKB devnet executable\n' >&2; exit 1; }
[ ! -e "$OUT_DIR" ] || { printf 'use a fresh OUT_DIR\n' >&2; exit 1; }
mkdir -m 700 -p "$OUT_DIR"
OUT_DIR="$(cd "$OUT_DIR" && pwd)"
mkdir -m 700 "$OUT_DIR/logs" "$OUT_DIR/contracts"
export OUT_DIR
fingerprint() {
  python3 - "$ROOT_DIR" <<'PY'
import hashlib,json,pathlib,subprocess,sys
root=pathlib.Path(sys.argv[1])
names=subprocess.check_output(['git','ls-files','--cached','--others','--exclude-standard','-z'],cwd=root).decode().split('\0')
files={name:hashlib.sha256((root/name).read_bytes()).hexdigest() for name in sorted(set(names)) if name and (root/name).is_file()}
print(json.dumps({'head':subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip(),'dirty':bool(subprocess.check_output(['git','status','--porcelain'],cwd=root)), 'files':files},sort_keys=True,indent=2))
PY
}
fingerprint >"$OUT_DIR/source-before.json"
cargo build --locked -p morph-cli --features devnet >"$OUT_DIR/logs/build.log" 2>&1
cp target/debug/morph-cli "$OUT_DIR/morph-cli"
CLI_BIN="$OUT_DIR/morph-cli"
for name in morph-state-type morph-state-lock morph-vault-lock morph-batch-lock morph-sponsor-lock morph-factory-type morph-factory-vault-lock morph-devnet-xudt; do
  cp "$CONTRACTS_DIR/$name" "$OUT_DIR/contracts/$name"
done
"$CLI_BIN" print-contract-manifest --contracts-dir "$OUT_DIR/contracts" >"$OUT_DIR/contracts.json"
cmp release/factory-preproduction/contracts.json "$OUT_DIR/contracts.json"
morph_fixture_keys_init
morph_fixture_key_file MORPH_DEVNET_PRIVATE_KEY_FILE "$FIBER_DIR/tests/nodes/deployer/ckb/plain_key" deployer.key
morph_fixture_key_file MORPH_ALICE_PRIVATE_KEY_FILE "$FIBER_DIR/tests/nodes/1/ckb/plain_key" alice.key
morph_fixture_key_file MORPH_BOB_PRIVATE_KEY_FILE "$FIBER_DIR/tests/nodes/2/ckb/plain_key" bob.key
PUBLIC_KEY="$("$CLI_BIN" devnet --devnet-only derive-operator-pubkey --json | jq -er '.pubkey_sec1')"
BLOCK_ASSEMBLER_ARG="$(python3 - "$PUBLIC_KEY" <<'PY'
import hashlib,sys
print('0x'+hashlib.blake2b(bytes.fromhex(sys.argv[1].removeprefix('0x')),digest_size=32,person=b'ckb-default-hash').digest()[:20].hex())
PY
)"
CKB_BIN="$CKB_BIN" CKB_DIR="$OUT_DIR/node" RPC_PORT="$RPC_PORT" P2P_PORT="$P2P_PORT" BLOCK_ASSEMBLER_ARG="$BLOCK_ASSEMBLER_ARG" \
  bash scripts/devnet-node.sh >"$OUT_DIR/logs/node.log" 2>&1 &
NODE_PID="$!"
RPC_URL="http://127.0.0.1:$RPC_PORT"
for _ in $(seq 1 60); do
  if curl -sf --max-time 1 -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"get_tip_header","params":[]}' "$RPC_URL" >"$OUT_DIR/initial-tip.json"; then break; fi
  kill -0 "$NODE_PID" || { printf 'node exited during startup\n' >&2; exit 1; }
  sleep 0.5
done
jq -e '.result.hash' "$OUT_DIR/initial-tip.json" >/dev/null
"$CLI_BIN" devnet --devnet-only --rpc-url "$RPC_URL" mine --blocks 6 --json >"$OUT_DIR/mine.json"
"$CLI_BIN" devnet --devnet-only --rpc-url "$RPC_URL" deploy-contracts --contracts-dir "$OUT_DIR/contracts" --json >"$OUT_DIR/deployment.json" 2>"$OUT_DIR/logs/deployment.log"
if [ "$SCENARIO" = close ]; then
  for assets in 2 8; do
    "$CLI_BIN" devnet --devnet-only --rpc-url "$RPC_URL" multi-asset-smoke --signer-faults --cooperative-close --asset-count "$assets" --finalise-since 64 --fee 100000 \
      --contracts-dir "$OUT_DIR/contracts" --store-dir "$OUT_DIR/close-$assets-packages" --json >"$OUT_DIR/close-$assets.json" 2>"$OUT_DIR/logs/close-$assets.log"
  done
elif [ "$SCENARIO" = factory-close ]; then
  "$CLI_BIN" devnet --devnet-only --rpc-url "$RPC_URL" factory smoke --reorg \
    --contracts-dir "$OUT_DIR/contracts" --store-dir "$OUT_DIR/factory-packages" >"$OUT_DIR/factory-close.json" 2>"$OUT_DIR/logs/factory-close.log"
else
"$CLI_BIN" devnet --devnet-only --rpc-url "$RPC_URL" multi-asset-smoke --signer-faults --shared-funding --funding-reorg --fee 100000 \
  --contracts-dir "$OUT_DIR/contracts" --store-dir "$OUT_DIR/shared-packages" --json >"$OUT_DIR/shared.json" 2>"$OUT_DIR/logs/shared.log"
"$CLI_BIN" devnet --devnet-only --rpc-url "$RPC_URL" multi-asset-smoke --signer-faults --splice-transitions --fee 100000 \
  --contracts-dir "$OUT_DIR/contracts" --store-dir "$OUT_DIR/splice-packages" --json >"$OUT_DIR/splice.json" 2>"$OUT_DIR/logs/splice.log"
fi
fingerprint >"$OUT_DIR/source-after.json"
cmp "$OUT_DIR/source-before.json" "$OUT_DIR/source-after.json"
python3 - "$OUT_DIR" <<'PY'
import collections,hashlib,json,pathlib,sys,os
root=pathlib.Path(sys.argv[1]);rows=[]
for path in sorted(root.glob('*-packages/**/external-signing.jsonl')):
    rows.extend(json.loads(line) for line in path.read_text().splitlines())
scenario=os.environ['SCENARIO']
expected={'root_exit':4,'root_creation':4,'update':2,'splice_creation':4,'splice_recovery':4,'splice_bridge':4}
if scenario=='close':
    expected={'root_exit':4,'root_creation':4,'cooperative_close':8}
if scenario=='factory-close':
    expected={'cooperative_close':6}
actual=dict(collections.Counter(row['target'] for row in rows))
assert actual==expected,(actual,expected)
assert all(row['schema']=='morph.external_signer_observation.v1' and row['verified_and_recorded'] and row['service_exit_code']==0 and row['signer_pid']!=row['caller_pid'] for row in rows)
assert len({(r['target'],r['pubkey'],r['signing_digest']) for r in rows})==len(rows)
processes=[]
for row in rows:
    faults=row['faults']
    for check in ['service_unavailable_reserved','expired_request_rejected','after_key_disconnect','reservation_unchanged','exact_retry_recorded','cached_retry_without_service']:
        assert faults[check] is True,(row['target'],check)
    processes.extend([row['signer_pid'],faults['expired_process'],faults['lost_response_process']])
    assert all(pid!=row['caller_pid'] for pid in processes[-3:])
assert len(set(processes))==3*len(rows)
callers=[pid for row in rows for pid in [row['caller_pid'],row['cached_caller_pid']]]
assert len(set(callers))==2*len(rows)
assert not set(callers)&set(processes)
assert all(row['caller_pid']!=row['harness_pid'] and row['cached_caller_pid']!=row['harness_pid'] for row in rows)
assert len({r['genesis'] for r in rows})==1
assert len({r['channel_id'] for r in rows})==(3 if scenario=='factory-close' else 2)
files=['morph-cli','contracts.json','source-before.json','source-after.json','deployment.json']
files += ['close-2.json','close-8.json'] if scenario=='close' else ['factory-close.json'] if scenario=='factory-close' else ['shared.json','splice.json']
if scenario=='close':
    for assets in [2,8]:
        report=json.loads((root/f'close-{assets}.json').read_text())
        assert report['asset_count']==assets
        close=report['close']
        for check in ['all_custody_consumed','old_approval_exportable','missing_fee_preflight_rejected','wrong_fee_owner_rejected','unilateral_package_retained','source_race_rejected','journals_unchanged_after_reorg_and_fallback','confirmed_retry_no_broadcast','required_depth_enforced']:
            assert close[check] is True
        assert len(set(close['replacement_hashes']))==2
        assert close['submitted']['canonical_confirmations']>=4
        assert close['submitted']['status']['state']=='finalised'
        assert close['lost_race_operation']['status']['state']=='operator_action'
        assert close['reorg_replay']['transaction_hash']==close['submitted']['transaction_hash']
        assert close['reorg_replay']['canonical_confirmations']>=4
        assert close['replacement_winners_reconciled'] is True
        predecessor=close['predecessor_preview']['operation']['operation_id']
        assert close['submitted']['operation']['replaces']==predecessor
        assert close['predecessor_lost']['operation']['status']['by_operation_id']==close['submitted']['operation']['operation_id']
        assert close['predecessor_lost']['operation']['canonical_confirmations']==0
        assert close['predecessor_won']['canonical_confirmations']>=4
        assert close['descendant_lost']['operation']['status']['by_operation_id']==predecessor
        assert close['descendant_lost']['operation']['canonical_confirmations']==0
        assert close['final_branch']=='ordinary_unilateral_fallback_after_three_controlled_rollbacks'
        assert close['fallback_finalise']['canonical_confirmed'] is True
        assert close['preview']['dry_run'] is True and close['submitted']['dry_run'] is False
if scenario=='factory-close':
    report=json.loads((root/'factory-close.json').read_text())
    children=report['transitions']['child']
    assert set(children)=={'reduced','retained','terminal'}
    for name,child in children.items():
        close=child['cooperative_close']
        assert close['submitted']['status']['state']=='finalised'
        assert close['submitted']['canonical_confirmations']>=4
        for check in ['zero_since','all_payouts_verified','parent_journals_unchanged','child_journals_unchanged_after_rollback']:
            assert close[check] is True,(name,check)
        assert child['finalise']['status']=='Committed'
        assert close['branch']=='cooperative_branch_orphaned_before_existing_unilateral_acceptance'
        if name=='terminal':
            assert child['terminal_factory'] is True
            assert close['batch']['fulfilled']['status']=='Committed'
            assert close['batch']['refunded']['status']=='Committed'
            assert close['batch']['canonical_payouts_verified'] is True
        else:
            assert close['batch'] is None
evidence={'schema':'morph.external_signer_native_evidence.v1','passed':True,'scenario':scenario,'roles':actual,'isolated_service_processes':len(processes),'key_using_processes':2*len(rows),'completed_role_attempts':len(rows),'verified_fresh_caller_processes':len(callers),'source_unchanged':True,'source_dirty':json.loads((root/'source-before.json').read_text())['dirty'],'sha256':{name:hashlib.sha256((root/name).read_bytes()).hexdigest() for name in files},'boundaries':['controlled devnet; no real assets','existing manifest-matched ELFs, not a clean contract rebuild','full CI and remaining W1 qualification not run by this script','hostile same-UID and whole-store rollback remain excluded','selected roles: unavailable service, expired request, lost signed response, restart and cached retry; malformed/deadline IPC tests are separate']}
(root/'verification.json').write_text(json.dumps(evidence,indent=2)+'\n')
print(json.dumps({'passed':True,'isolated_service_processes':len(processes),'key_using_processes':2*len(rows),'completed_role_attempts':len(rows),'verified_fresh_caller_processes':len(callers),'roles':actual}))
PY
