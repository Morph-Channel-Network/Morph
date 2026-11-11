#!/usr/bin/env bash
# Canonical shadow observation using actual Factory children and splice contexts.
# No provider mutation, forwarding, or release qualification.
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
source scripts/private-key-files.sh
morph_reject_raw_private_keys
CKB_BIN="${CKB_BIN:-$(command -v ckb || true)}"
RPC_PORT="${RPC_PORT:-19974}"
P2P_PORT="${P2P_PORT:-19975}"

# Runtime databases require a trusted, non-shared-writable ancestor chain.
OUT_DIR="${OUT_DIR:-/tmp/morph-shadow-observer-e2e-$(date -u +%Y%m%dT%H%M%S)-$$}"
FIBER_DIR="${FIBER_DIR:-$ROOT_DIR/../fiber}"
CONTRACTS_DIR="${CONTRACTS_DIR:-target/riscv64imac-unknown-none-elf/release}"
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
"$CLI_BIN" devnet --devnet-only --rpc-url "$RPC_URL" factory smoke --reorg --contracts-dir "$OUT_DIR/contracts" --store-dir "$OUT_DIR/factory-packages" >"$OUT_DIR/factory.json" 2>"$OUT_DIR/logs/factory.log"
"$CLI_BIN" devnet --devnet-only --rpc-url "$RPC_URL" multi-asset-smoke --splice-transitions --asset-count 2 --fee 100000 --contracts-dir "$OUT_DIR/contracts" --store-dir "$OUT_DIR/splice-packages" --json >"$OUT_DIR/splice.json" 2>"$OUT_DIR/logs/splice.log"
fingerprint >"$OUT_DIR/source-after.json"
cmp "$OUT_DIR/source-before.json" "$OUT_DIR/source-after.json"
python3 - "$OUT_DIR" <<'CHECK'
import hashlib,json,pathlib,sys
r=pathlib.Path(sys.argv[1]);f=json.loads((r/'factory.json').read_text());s=json.loads((r/'splice.json').read_text())
rows=[]
for name in ('reduced','retained','terminal'):
 c=f['transitions']['child'][name];o=c['shadow_observer']
 assert o['forwarding'] is False and int(o['confirmations'])>=4
 assert o['edge']['factory_id'] is not None and o['edge']['factory_reservation_id'] is not None
 assert c['shadow_spent_child_rejected'] is True
 assert c['journal_source_verified'] is True and c['changed_journal_rejected'] is True and c['pending_update_drains'] is True
 if name!='reduced': assert c['cross_child_history_rejected'] is True
 rows.append({'kind':'factory_'+name,'observation':o,'spent_child_rejected':True,'journal_source_verified':True,'changed_journal_rejected':True,'pending_update_drains':True})
trace=s['transitions']
assert trace['shadow_finalised_contexts_rejected'] is True and trace['initial_journal_source_verified'] is True
root=trace['initial_shadow_observer'];assert root['forwarding'] is False
assert int(root['confirmations'])>=4
rows.append({'kind':'splice_initial_root','observation':root,'journal_source_verified':True})
for index,c in enumerate(trace['operations']):
 o=c['shadow_observer'];assert o['forwarding'] is False and int(o['confirmations'])>=4
 assert o['edge']['factory_id'] is None
 assert c['journal_source_verified'] is True
 assert c['previous_shadow_context_rejected'] is True and c['prior_contexts_checked']==index+1
 rows.append({'kind':'splice_'+c['operation'],'observation':o,'previous_context_rejected':True,'journal_source_verified':True,'prior_contexts_checked':c['prior_contexts_checked']})
assert len({row['observation']['edge']['morph_edge_id'] for row in rows})==6
(r/'public-observations.json').write_text(json.dumps(rows,indent=2)+'\n')
files=['morph-cli','contracts.json','source-before.json','source-after.json','deployment.json','factory.json','splice.json','public-observations.json']
evidence={'schema':'morph.shadow_native_evidence.v1','passed':True,'observations':6,'source_unchanged':True,'sha256':{name:hashlib.sha256((r/name).read_bytes()).hexdigest() for name in files},'boundaries':['controlled no-value chain; prebuilt manifest-matched ELFs','observer only; no provider hook or durable Morph service exercised','Factory child splice and external-child provider admission not exercised','not full CI or release qualification']}
(r/'verification.json').write_text(json.dumps(evidence,indent=2)+'\n');print(json.dumps({'passed':True,'observations':6}))
CHECK
