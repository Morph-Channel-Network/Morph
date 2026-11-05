#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/scripts/private-key-files.sh"
morph_reject_raw_private_keys || exit 1
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT_DIR="${OUT_DIR:-$ROOT_DIR/target/morph-agent-fiber-devnet-e2e/$RUN_ID}"
FIBER_CKB_RPC_URL="${FIBER_CKB_RPC_URL:-http://127.0.0.1:8114}"
FIBER_NODE1_RPC_URL="${FIBER_NODE1_RPC_URL:-http://127.0.0.1:21714}"
FIBER_NODE2_RPC_URL="${FIBER_NODE2_RPC_URL:-http://127.0.0.1:21715}"
FIBER_NODE3_RPC_URL="${FIBER_NODE3_RPC_URL:-http://127.0.0.1:21716}"
PAYEE_LISTEN="${MORPH_AGENT_PAYEE_LISTEN:-127.0.0.1:24620}"
PAYER_LISTEN="${MORPH_AGENT_PAYER_LISTEN:-127.0.0.1:24621}"
PAYEE_URL="http://$PAYEE_LISTEN"
PAYER_URL="http://$PAYER_LISTEN"
PAYER_PUBLIC_KEY="${MORPH_AGENT_DEVNET_PAYER_PUBLIC_KEY:-0x02989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f}"
AGENT_BIN="$ROOT_DIR/target/debug/morph-agent"
PAYEE_PID=""
PAYER_PID=""

log() {
  printf '[morph-agent-fiber-e2e] %s\n' "$*"
}

fail() {
  printf '[morph-agent-fiber-e2e] error: %s\n' "$*" >&2
  exit 1
}

cleanup() {
  local pid
  for pid in "$PAYEE_PID" "$PAYER_PID"; do
    if [ -n "$pid" ] && kill -0 "$pid" >/dev/null 2>&1; then
      kill "$pid" >/dev/null 2>&1 || true
      wait "$pid" 2>/dev/null || true
    fi
  done
  morph_fixture_keys_cleanup
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

for tool in cargo curl jq node npm sha256sum; do
  command -v "$tool" >/dev/null 2>&1 || fail "missing required tool: $tool"
done

mkdir -p "$OUT_DIR/bin"
OUT_DIR="$(cd "$OUT_DIR" && pwd)"

rpc() {
  local url="$1"
  local method="$2"
  local params="$3"
  curl -fsS \
    -H 'content-type: application/json' \
    -d "$(jq -cn --arg method "$method" --argjson params "$params" \
      '{jsonrpc:"2.0",id:1,method:$method,params:$params}')" \
    "$url"
}

rpc_result() {
  local response
  response="$(rpc "$1" "$2" "$3")"
  jq -e 'if .error then error(.error.message // "JSON-RPC error") else .result end' \
    <<<"$response"
}

write_generated_secret() {
  local path="$1" command="$2" output line secret=""
  output="$("$AGENT_BIN" "$command")"
  while IFS= read -r line; do
    case "$line" in
      private_key=*) secret="${line#private_key=}" ;;
    esac
  done <<<"$output"
  [ -n "$secret" ] || fail "key generation did not return a private key"
  # printf is a shell builtin: generated material never enters process argv/env.
  (umask 077; printf '%s\n' "$secret" >"$path")
}

account_id() {
  local output
  output="$("$AGENT_BIN" account-id --pubkey "$1")"
  output="${output#account_id=}"
  [[ "$output" =~ ^0x[0-9a-f]{64}$ ]] || fail "invalid account ID derived from Fiber pubkey"
  printf '%s' "$output"
}

wait_for_agent() {
  local url="$1"
  local pid="$2"
  local label="$3"
  local deadline=$((SECONDS + 30))
  while [ "$SECONDS" -lt "$deadline" ]; do
    if curl -fsS "$url/health" | jq -e '.status == "ok"' >/dev/null; then
      return
    fi
    if ! kill -0 "$pid" >/dev/null 2>&1; then
      fail "$label exited before becoming healthy"
    fi
    sleep 1
  done
  fail "$label did not become healthy"
}

log "building Morph Agent and TypeScript SDK"
(cd "$ROOT_DIR" && cargo build -p morph-agent) >"$OUT_DIR/morph-agent-build.log" 2>&1
(cd "$ROOT_DIR/sdk/typescript" && npm run build) >"$OUT_DIR/typescript-sdk-build.log" 2>&1
cp "$AGENT_BIN" "$OUT_DIR/bin/morph-agent"
AGENT_BIN="$OUT_DIR/bin/morph-agent"

ckb_network_id="$(rpc_result "$FIBER_CKB_RPC_URL" get_block_hash '["0x0"]' | jq -er '.')"
node1_pubkey="$(rpc_result "$FIBER_NODE1_RPC_URL" node_info '[]' | jq -er '.pubkey')"
node2_pubkey="$(rpc_result "$FIBER_NODE2_RPC_URL" node_info '[]' | jq -er '.pubkey')"
node3_pubkey="$(rpc_result "$FIBER_NODE3_RPC_URL" node_info '[]' | jq -er '.pubkey')"
[[ "$ckb_network_id" =~ ^0x[0-9a-f]{64}$ ]] || fail "CKB genesis hash is malformed"
[[ "$node1_pubkey" =~ ^[0-9a-f]{66}$ ]] || fail "Fiber node1 pubkey is malformed"
[[ "$node2_pubkey" =~ ^[0-9a-f]{66}$ ]] || fail "Fiber node2 pubkey is malformed"
[[ "$node3_pubkey" =~ ^[0-9a-f]{66}$ ]] || fail "Fiber node3 pubkey is malformed"

node1_account_id="$(account_id "$node1_pubkey")"
node3_account_id="$(account_id "$node3_pubkey")"
payer_account_id="$(account_id "$PAYER_PUBLIC_KEY")"
[ "$payer_account_id" != "$node1_account_id" ] || fail "devnet payer aliases Fiber node1"
[ "$payer_account_id" != "$node3_account_id" ] || fail "devnet payer aliases Fiber node3"

morph_fixture_keys_init || fail "cannot prepare private fixture key files"
PAYEE_BISCUIT_KEY_FILE="$MORPH_FIXTURE_KEY_DIR/payee-biscuit.key"
PAYER_BISCUIT_KEY_FILE="$MORPH_FIXTURE_KEY_DIR/payer-biscuit.key"
PAYEE_RECEIPT_KEY_FILE="$MORPH_FIXTURE_KEY_DIR/payee-receipt.key"
PAYER_RECEIPT_KEY_FILE="$MORPH_FIXTURE_KEY_DIR/payer-receipt.key"
write_generated_secret "$PAYEE_BISCUIT_KEY_FILE" generate-key
write_generated_secret "$PAYER_BISCUIT_KEY_FILE" generate-key
write_generated_secret "$PAYEE_RECEIPT_KEY_FILE" generate-receipt-key
write_generated_secret "$PAYER_RECEIPT_KEY_FILE" generate-receipt-key
PAYER_PRIVATE_KEY_FILE="${MORPH_AGENT_DEVNET_PAYER_PRIVATE_KEY_FILE:-}"
if [ -z "$PAYER_PRIVATE_KEY_FILE" ]; then
  # Public scalar 0x07 repeated is a no-value fixture for this isolated harness.
  PAYER_PRIVATE_KEY_FILE="$MORPH_FIXTURE_KEY_DIR/sdk-payer.key"
  (umask 077; printf '07%.0s' {1..32} >"$PAYER_PRIVATE_KEY_FILE")
fi
tracked_worktree_clean=false
if [ -z "$(git -C "$ROOT_DIR" status --porcelain --untracked-files=no)" ]; then
  tracked_worktree_clean=true
fi

log "starting payee Agent on Fiber node3"
(
  export MORPH_AGENT_BISCUIT_PRIVATE_KEY_FILE="$PAYEE_BISCUIT_KEY_FILE"
  export MORPH_AGENT_RECEIPT_PRIVATE_KEY_FILE="$PAYEE_RECEIPT_KEY_FILE"
  exec "$AGENT_BIN" serve \
    --listen "$PAYEE_LISTEN" \
    --fiber-rpc "$FIBER_NODE3_RPC_URL" \
    --store "$OUT_DIR/payee-agent.db" \
    --payee "$node3_account_id" \
    --ckb-network-id "$ckb_network_id"
) >"$OUT_DIR/payee-agent.log" 2>&1 &
PAYEE_PID="$!"

log "starting payer Agent on Fiber node1"
(
  export MORPH_AGENT_BISCUIT_PRIVATE_KEY_FILE="$PAYER_BISCUIT_KEY_FILE"
  export MORPH_AGENT_RECEIPT_PRIVATE_KEY_FILE="$PAYER_RECEIPT_KEY_FILE"
  exec "$AGENT_BIN" serve \
    --listen "$PAYER_LISTEN" \
    --fiber-rpc "$FIBER_NODE1_RPC_URL" \
    --store "$OUT_DIR/payer-agent.db" \
    --payee "$node1_account_id" \
    --outgoing-payer "$payer_account_id" \
    --outgoing-max-fee-amount 1000 \
    --outgoing-payment-timeout-seconds 60 \
    --ckb-network-id "$ckb_network_id"
) >"$OUT_DIR/payer-agent.log" 2>&1 &
PAYER_PID="$!"

wait_for_agent "$PAYEE_URL" "$PAYEE_PID" "payee Agent"
wait_for_agent "$PAYER_URL" "$PAYER_PID" "payer Agent"

log "running x402, credential, and fair-exchange payments over the Fiber route"
MORPH_AGENT_PAYEE_URL="$PAYEE_URL" \
MORPH_AGENT_PAYER_URL="$PAYER_URL" \
MORPH_AGENT_CKB_NETWORK_ID="$ckb_network_id" \
MORPH_AGENT_PAYER_PRIVATE_KEY_FILE="$PAYER_PRIVATE_KEY_FILE" \
MORPH_AGENT_EXPECTED_PAYEE="$node3_account_id" \
MORPH_AGENT_FIBER_NODE1_PUBKEY="$node1_pubkey" \
MORPH_AGENT_FIBER_NODE2_PUBKEY="$node2_pubkey" \
MORPH_AGENT_FIBER_NODE3_PUBKEY="$node3_pubkey" \
  node "$ROOT_DIR/sdk/typescript/test/fiber-devnet.mjs" >"$OUT_DIR/result.json"

jq -e \
  '.schema == "morph.agent_fiber_devnet_e2e" and .status == "passed" and
   .route == "fiber-node1 -> fiber-node2 -> fiber-node3" and
   (.routing.x402_node_pubkeys | length == 3) and
   (.routing.fair_exchange_node_pubkeys | length == 3) and
   .x402.terminal_status == "Settled" and
   (.fair_exchange.receipt_id | type == "string")' \
  "$OUT_DIR/result.json" >/dev/null

jq -n \
  --arg schema "morph.agent_fiber_devnet_manifest" \
  --arg status "passed" \
  --arg finished_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg git_commit "$(git -C "$ROOT_DIR" rev-parse --short HEAD)" \
  --arg agent_binary_sha256 "$(sha256sum "$AGENT_BIN" | cut -d' ' -f1)" \
  --arg sdk_index_sha256 "$(sha256sum "$ROOT_DIR/sdk/typescript/dist/index.js" | cut -d' ' -f1)" \
  --arg ckb_network_id "$ckb_network_id" \
  --arg fiber_node1_pubkey "$node1_pubkey" \
  --arg fiber_node2_pubkey "$node2_pubkey" \
  --arg fiber_node3_pubkey "$node3_pubkey" \
  --arg payer_account_id "$payer_account_id" \
  --arg payee_account_id "$node3_account_id" \
  --argjson tracked_worktree_clean "$tracked_worktree_clean" \
  '{
    schema:$schema,
    status:$status,
    finished_at_utc:$finished_at_utc,
    git_commit:$git_commit,
    agent_binary_sha256:$agent_binary_sha256,
    sdk_index_sha256:$sdk_index_sha256,
    proof_scope:"fiber_provider_route",
    morph_custody_backing_proven:false,
    ckb_network_id:$ckb_network_id,
    fiber_node1_pubkey:$fiber_node1_pubkey,
    fiber_node2_pubkey:$fiber_node2_pubkey,
    fiber_node3_pubkey:$fiber_node3_pubkey,
    payer_account_id:$payer_account_id,
    payee_account_id:$payee_account_id,
    tracked_worktree_clean:$tracked_worktree_clean,
    result:"result.json",
    secrets_recorded:false
  }' >"$OUT_DIR/manifest.json"

log "passed; evidence -> $OUT_DIR"
