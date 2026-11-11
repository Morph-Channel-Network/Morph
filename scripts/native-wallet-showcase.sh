#!/usr/bin/env bash
# Disposable real-chain showcase. No fixture rows are injected into the product.
set -euo pipefail
cd "$(dirname "$0")/.."
ckb_bin="${CKB_BIN:-$(command -v ckb || true)}"
[[ -x "$ckb_bin" ]] || { echo 'Set CKB_BIN to a CKB 0.209 executable.' >&2; exit 1; }
showcase_rpc_port="${SHOWCASE_RPC_PORT:-18414}"
showcase_p2p_port="${SHOWCASE_P2P_PORT:-18415}"
[[ "$showcase_rpc_port" =~ ^[0-9]+$ && "$showcase_p2p_port" =~ ^[0-9]+$ ]] || exit 1
if (echo > "/dev/tcp/127.0.0.1/$showcase_rpc_port") 2>/dev/null; then
    echo "Port $showcase_rpc_port is occupied. Set SHOWCASE_RPC_PORT to a free port." >&2; exit 1
fi
mkdir -p target
showcase_root="$(mktemp -d "$PWD/target/native-showcase.XXXXXXXX")"
scripts/prepare-native-desktop.sh
export LIBRARY_PATH="$PWD/target/native-libs${LIBRARY_PATH:+:$LIBRARY_PATH}"
cargo build --locked -p morph-desktop --profile desktop
cargo build --locked -p morph-wallet --example native_showcase
"$ckb_bin" init -C "$showcase_root/node" --chain dev --rpc-port "$showcase_rpc_port" --p2p-port "$showcase_p2p_port" --ba-code-hash 0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8 --ba-arg 0xc8328aabcd9b9e8e64fbc566c4385c3bdeb219d7 --ba-hash-type type --log-to stdout > "$showcase_root/init.log"
# ckb init puts wall-clock time in genesis_cell.message; pin the public fixture identity.
perl -0pi -e 's/(\[genesis\.genesis_cell\]\nmessage = ")[^"]*(")/${1}1794268425000${2}/' "$showcase_root/node/specs/dev.toml"
perl -0pi -e 's/^modules = \[[^\n]*\]/modules = ["Net", "Pool", "Miner", "Chain", "Stats", "Subscription", "Experiment", "IntegrationTest", "Indexer"]/m; s|/ip4/0.0.0.0/tcp/|/ip4/127.0.0.1/tcp/|g' "$showcase_root/node/ckb.toml"
"$ckb_bin" -C "$showcase_root/node" run --indexer > "$showcase_root/node.log" 2>&1 &
showcase_node_pid=$!
cleanup() { kill "$showcase_node_pid" 2>/dev/null || true; wait "$showcase_node_pid" 2>/dev/null || true; }
trap cleanup EXIT INT TERM
for _ in {1..60}; do
    kill -0 "$showcase_node_pid" 2>/dev/null || { cat "$showcase_root/node.log" >&2; exit 1; }
    if curl -fsS --max-time 2 -H 'content-type: application/json' --data '{"id":1,"jsonrpc":"2.0","method":"get_indexer_tip","params":[]}' "http://127.0.0.1:$showcase_rpc_port" 2>/dev/null | jq -e '.result.block_hash' >/dev/null; then break; fi
    sleep 0.5
done
target/debug/examples/native_showcase "$showcase_root/session" "http://127.0.0.1:$showcase_rpc_port"
printf 'Opening a disposable development wallet. Evidence remains in %s\n' "$showcase_root/session"
if [[ "${SHOWCASE_NO_UI:-0}" != 1 ]]; then
    XDG_CONFIG_HOME="$showcase_root/session/preferences" MORPH_CKB_RPC="http://127.0.0.1:$showcase_rpc_port" target/desktop/morph-desktop
fi
