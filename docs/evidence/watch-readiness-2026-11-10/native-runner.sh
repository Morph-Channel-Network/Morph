#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="/home/arthur/RustRoverProjects/Morph"
cd "$ROOT_DIR"
source scripts/private-key-files.sh
morph_reject_raw_private_keys || exit 1
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
  morph_fixture_keys_cleanup
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

# Stage only the public development fixtures outside the evidence directory.
# Explicit *_PRIVATE_KEY_FILE paths go unchanged to the protected Rust loader.
morph_fixture_keys_init || fail "cannot prepare private fixture key files"
morph_fixture_key_file MORPH_DEVNET_PRIVATE_KEY_FILE "${MORPH_E2E_DEPLOYER_KEY_FILE:-$FIBER_DIR/tests/nodes/deployer/ckb/plain_key}" deployer.key
morph_fixture_key_file MORPH_ALICE_PRIVATE_KEY_FILE "${MORPH_E2E_ALICE_KEY_FILE:-$FIBER_DIR/tests/nodes/1/ckb/plain_key}" alice.key
morph_fixture_key_file MORPH_BOB_PRIVATE_KEY_FILE "${MORPH_E2E_BOB_KEY_FILE:-$FIBER_DIR/tests/nodes/2/ckb/plain_key}" bob.key
printf '[current-e2e] building current contracts and CLI\n'
# Contracts unchanged in this host-only checkpoint; stage the existing manifest-checked artifacts.
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

"$CLI_BIN" devnet --devnet-only --rpc-url "$RPC_URL" publication-profile-fixture --json >"$MATRIX_DIR/publication-profile.json"
python3 - "$MATRIX_DIR/publication-profile.json" <<'PROFILE'
from pathlib import Path
import json,sys
p=Path(sys.argv[1]);v=json.loads(p.read_text());v['window']['configured_challenge_blocks']=64;p.write_text(json.dumps(v)+'\n')
PROFILE
"$CLI_BIN" devnet --devnet-only --rpc-url "$RPC_URL" multi-asset-smoke --shared-funding --sponsor-publication --watch-publication --watch-reorg --fee 100000 --finalise-since 64 --publication-profile "$MATRIX_DIR/publication-profile.json" --contracts-dir "$MATRIX_DIR/contracts" --store-dir "$MATRIX_DIR/watch-service-packages" --json >"$MATRIX_DIR/watch-service-acceptance.json" 2>"$OUT_DIR/logs/watch.log"
python3 - "$MATRIX_DIR" <<'VERIFY'
import json,sys,pathlib
p=pathlib.Path(sys.argv[1]);v=json.loads((p/'watch-service-acceptance.json').read_text())
services=[r['service'] for r in v['watch_passes'] if 'service' in r]
assert services
for s in services:
 assert s['published_count']==1 and s['stopped_reason']=='publication'
 assert s['last_pass']['failed_count']==1 and s['last_pass']['channel_count']==2
 assert s['last_pass']['channels'][0]['observation']['completed'] is False
 assert s['last_pass']['channels'][1]['observation']['publication_confirmed'] is True
assert json.loads((p/'contracts.json').read_text())==json.loads(pathlib.Path('release/factory-preproduction/contracts.json').read_text())
print('PASS: failed first resource, real peer correction, current health, manifest unchanged')
VERIFY
