#!/usr/bin/env bash
# Real CKB + pinned patched Fiber + separate Morph worker. No routed payments.
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
source scripts/private-key-files.sh
morph_reject_raw_private_keys
CKB_BIN="${CKB_BIN:-$ROOT_DIR/../ckb/target/debug/ckb}"
FIBER_SOURCE="${FIBER_SOURCE:-$ROOT_DIR/../fiber}"
FIBER_CHECKOUT="${FIBER_CHECKOUT:?set FIBER_CHECKOUT to the pinned patched checkout}"
FIBER_BUILD_TARGET="$ROOT_DIR/target/fiber-shadow-build"
FIBER_BIN="$FIBER_BUILD_TARGET/debug/fnn"
OUT_DIR="${OUT_DIR:-/tmp/morph-shadow-service-$(date -u +%Y%m%dT%H%M%S)-$$}"
RPC_PORT="${RPC_PORT:-19984}"
P2P_PORT="${P2P_PORT:-19985}"
FIBER_RPC_PORT="${FIBER_RPC_PORT:-19986}"
NODE_PID=""; FIBER_PID=""; CLI_PID=""
cleanup() {
  for owned in "$CLI_PID" "$FIBER_PID" "$NODE_PID"; do
    if [ -n "$owned" ] && kill -0 "$owned" 2>/dev/null; then kill "$owned"; wait "$owned" || true; fi
  done
  morph_fixture_keys_cleanup
}
trap cleanup EXIT
[ ! -e "$OUT_DIR" ] || { echo 'use a fresh OUT_DIR' >&2; exit 1; }
[ "$(git -C "$FIBER_CHECKOUT" rev-parse HEAD)" = "$(jq -r .fiber_revision integrations/fiber-shadow/manifest.json)" ]
[ -x "$CKB_BIN" ]
mkdir -m 700 -p "$OUT_DIR"
OUT_DIR="$(cd "$OUT_DIR" && pwd)"
mkdir -m 700 "$OUT_DIR/logs" "$OUT_DIR/contracts" "$OUT_DIR/fiber" "$OUT_DIR/fiber/ckb"
fingerprint() {
  python3 - "$ROOT_DIR" "$FIBER_CHECKOUT" <<'PY'
import hashlib,json,pathlib,subprocess,sys
result={}
for label,directory in [('morph',sys.argv[1]),('fiber',sys.argv[2])]:
 r=pathlib.Path(directory);names=subprocess.check_output(['git','ls-files','--cached','--others','--exclude-standard','-z'],cwd=r).decode().split('\0')
 result[label]={'head':subprocess.check_output(['git','rev-parse','HEAD'],cwd=r,text=True).strip(),'files':{n:hashlib.sha256((r/n).read_bytes()).hexdigest() for n in sorted(set(names)) if n and (r/n).is_file()}}
print(json.dumps(result,sort_keys=True,indent=2))
PY
}
fingerprint >"$OUT_DIR/source-before.json"
cargo build --locked -p morph-cli --features devnet >"$OUT_DIR/logs/build.log" 2>&1
(cd "$FIBER_CHECKOUT" && CARGO_TARGET_DIR="$FIBER_BUILD_TARGET" cargo +1.95.0 build --locked -p fiber-bin --no-default-features --features sqlite,morph-shadow) >"$OUT_DIR/logs/fiber-build.log" 2>&1
cp target/debug/morph-cli "$OUT_DIR/morph-cli"
cp "$FIBER_BIN" "$OUT_DIR/fnn"
CLI_BIN="$OUT_DIR/morph-cli"
for name in morph-state-type morph-state-lock morph-vault-lock morph-batch-lock morph-sponsor-lock morph-factory-type morph-factory-vault-lock morph-devnet-xudt; do cp "target/riscv64imac-unknown-none-elf/release/$name" "$OUT_DIR/contracts/$name"; done
"$CLI_BIN" print-contract-manifest --contracts-dir "$OUT_DIR/contracts" >"$OUT_DIR/contracts.json"
cmp release/factory-preproduction/contracts.json "$OUT_DIR/contracts.json"
morph_fixture_keys_init
morph_fixture_key_file MORPH_DEVNET_PRIVATE_KEY_FILE "$FIBER_SOURCE/tests/nodes/deployer/ckb/plain_key" deployer.key
morph_fixture_key_file MORPH_ALICE_PRIVATE_KEY_FILE "$FIBER_SOURCE/tests/nodes/1/ckb/plain_key" alice.key
morph_fixture_key_file MORPH_BOB_PRIVATE_KEY_FILE "$FIBER_SOURCE/tests/nodes/2/ckb/plain_key" bob.key
install -m 600 "$MORPH_ALICE_PRIVATE_KEY_FILE" "$OUT_DIR/fiber/ckb/key"
PUBLIC_KEY="$("$CLI_BIN" devnet --devnet-only derive-operator-pubkey --json | jq -er '.pubkey_sec1')"
BLOCK_ASSEMBLER_ARG="$(python3 - "$PUBLIC_KEY" <<'PY'
import hashlib,sys
print('0x'+hashlib.blake2b(bytes.fromhex(sys.argv[1].removeprefix('0x')),digest_size=32,person=b'ckb-default-hash').digest()[:20].hex())
PY
)"
"$CKB_BIN" init -C "$OUT_DIR/node" --chain dev --force --rpc-port "$RPC_PORT" --p2p-port "$P2P_PORT" --ba-code-hash 0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8 --ba-arg "$BLOCK_ASSEMBLER_ARG" --ba-hash-type type --log-to stdout >"$OUT_DIR/logs/init.log" 2>&1
# Fiber's actual dev chain requires its native system contracts. No fake graph,
# code hash or compatibility fallback is used.
python3 - "$FIBER_SOURCE" "$OUT_DIR" <<'PY'
from pathlib import Path
import sys
f=Path(sys.argv[1]);o=Path(sys.argv[2]);s=(f/'tests/nodes/1/dev.toml').read_text();s=s.replace('../../deploy/contracts/',str((f/'tests/deploy/contracts').resolve())+'/');(o/'node/specs/dev.toml').write_text(s)
PY
CKB_BIN="$CKB_BIN" CKB_DIR="$OUT_DIR/node" RPC_PORT="$RPC_PORT" P2P_PORT="$P2P_PORT" bash scripts/devnet-node.sh >"$OUT_DIR/logs/node.log" 2>&1 &
NODE_PID="$!"
RPC_URL="http://127.0.0.1:$RPC_PORT"
for _ in $(seq 1 80); do
  if curl -sf --max-time 1 -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"get_block_hash","params":["0x0"]}' "$RPC_URL" >"$OUT_DIR/genesis.json"; then break; fi
  kill -0 "$NODE_PID"; sleep 0.2
done
GENESIS="$(jq -er .result "$OUT_DIR/genesis.json")"
jq --arg genesis "$GENESIS" '{fiber_commit:.fiber_revision,patch_hash:("0x"+.patch_sha256),ckb_genesis_hash:$genesis}' integrations/fiber-shadow/manifest.json >"$OUT_DIR/fiber/policy.json"
cat >"$OUT_DIR/fiber/config.yml" <<CONFIG
fiber:
  chain: $OUT_DIR/node/specs/dev.toml
  auto_announce_node: false
  listening_addr: /ip4/127.0.0.1/tcp/0
rpc:
  listening_addr: 127.0.0.1:$FIBER_RPC_PORT
  enabled_modules: [info, morph_shadow]
  morph_shadow_policy: $OUT_DIR/fiber/policy.json
  morph_shadow_database: $OUT_DIR/fiber/shadow.db
ckb:
  rpc_url: $RPC_URL
services: [fiber, rpc, ckb]
CONFIG
FIBER_RPC="http://127.0.0.1:$FIBER_RPC_PORT"
start_fiber() {
  FIBER_SECRET_KEY_PASSWORD=morph-isolated-no-value-fixture "$OUT_DIR/fnn" -d "$OUT_DIR/fiber" -c "$OUT_DIR/fiber/config.yml" >"$OUT_DIR/logs/fiber-$1.log" 2>&1 &
  FIBER_PID="$!"
  for _ in $(seq 1 480); do
    if curl -sf --max-time 1 -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"morph_external_edge_capabilities","params":[{}]}' "$FIBER_RPC" >"$OUT_DIR/fiber/capabilities-$1.json" && jq -e '.result.forwarding==false' "$OUT_DIR/fiber/capabilities-$1.json" >/dev/null; then return; fi
    kill -0 "$FIBER_PID"; sleep 0.25
  done
  echo 'Fiber shadow hook unavailable' >&2; return 1
}
start_fiber first
FIRST_FIBER_PID="$FIBER_PID"
"$CLI_BIN" devnet --devnet-only --rpc-url "$RPC_URL" mine --blocks 6 --json >"$OUT_DIR/mine.json"
"$CLI_BIN" devnet --devnet-only --rpc-url "$RPC_URL" deploy-contracts --contracts-dir "$OUT_DIR/contracts" --json >"$OUT_DIR/deployment.json" 2>"$OUT_DIR/logs/deployment.log"
"$CLI_BIN" devnet --devnet-only --rpc-url "$RPC_URL" multi-asset-smoke --shadow-provider-rpc "$FIBER_RPC" --asset-count 2 --fee 100000 --contracts-dir "$OUT_DIR/contracts" --store-dir "$OUT_DIR/packages" --json >"$OUT_DIR/acceptance.json" 2>"$OUT_DIR/logs/acceptance.log" &
CLI_PID="$!"
for _ in $(seq 1 600); do
  [ -f "$OUT_DIR/packages/shadow-service/provider-restart.request" ] && break
  kill -0 "$CLI_PID"; sleep 0.25
done
[ -f "$OUT_DIR/packages/shadow-service/provider-restart.request" ]
kill -9 "$FIBER_PID"; wait "$FIBER_PID" || true
start_fiber restarted
printf 'actual Fiber process %s replaced by %s\n' "$FIRST_FIBER_PID" "$FIBER_PID" >"$OUT_DIR/provider-restart.txt"
printf 'restarted\n' >"$OUT_DIR/packages/shadow-service/provider-restart.ack"
wait "$CLI_PID"; CLI_PID=""
fingerprint >"$OUT_DIR/source-after.json"
cmp "$OUT_DIR/source-before.json" "$OUT_DIR/source-after.json"
python3 - "$OUT_DIR" <<'PY'
import hashlib,json,pathlib,sys
r=pathlib.Path(sys.argv[1]);a=json.loads((r/'acceptance.json').read_text())['shadow_service']
for k in ['registered','morph_process_restarted','fiber_process_restart_acknowledged','journal_busy_disabled','journal_released_reactivated','spent_custody_disabled','orphaned_activation_disabled','exact_activation_replay_reactivated','reorg_preserved_backend_authority']: assert a[k] is True,k
assert a['forwarding'] is False and a['provider_revision_before_restart']=='1'
assert all(m['state']=='disabled' and m['forwarding'] is False for m in a['final_mirrors'])
(r/'public-summary.json').write_text(json.dumps(a,indent=2)+'\n')
files=['morph-cli','fnn','source-before.json','source-after.json','contracts.json','genesis.json','deployment.json','public-summary.json','provider-restart.txt']
v={'schema':'morph.shadow_service_native.v1','passed':True,'forwarding':False,'real_fiber_and_ckb':True,'source_unchanged':True,'sha256':{p:hashlib.sha256((r/p).read_bytes()).hexdigest() for p in files},'limits':['no routed payment','Root XUDT service source only; Factory/splice observer evidence is separate','not final release qualification']}
(r/'verification.json').write_text(json.dumps(v,indent=2)+'\n');print(json.dumps(v))
PY
