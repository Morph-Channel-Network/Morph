#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
source scripts/private-key-files.sh
morph_reject_raw_private_keys || exit 1

CKB_SOURCE_DIR="${CKB_SOURCE_DIR:-$ROOT_DIR/../ckb}"
CKB_BIN="${CKB_BIN:-}"
RPC_PORT="${RPC_PORT:-18414}"
P2P_PORT="${P2P_PORT:-18415}"
RPC_URL="http://127.0.0.1:$RPC_PORT"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
EVIDENCE_DIR="${EVIDENCE_DIR:-target/devnet-publication-reliability/$RUN_ID}"
CKB_DIR="$EVIDENCE_DIR/node"
OUT_DIR="$EVIDENCE_DIR/evidence"
LOG_DIR="$EVIDENCE_DIR/logs"
LATEST_LINK="${LATEST_LINK:-target/devnet-publication-reliability/latest}"
BUILD_CONTRACTS="${BUILD_CONTRACTS:-1}"
# Exercise an actual node fee floor and a distinct replacement floor.
MIN_FEE_RATE="${MIN_FEE_RATE:-10000}"
MIN_RBF_RATE="${MIN_RBF_RATE:-15000}"
INJECTED_DELAY_MS="${INJECTED_DELAY_MS:-500}"
FIBER_DIR="${FIBER_DIR:-$ROOT_DIR/../fiber}"
DEPLOYER_KEY_FILE="${MORPH_E2E_DEPLOYER_KEY_FILE:-$FIBER_DIR/tests/nodes/deployer/ckb/plain_key}"
ALICE_KEY_FILE="${MORPH_E2E_ALICE_KEY_FILE:-$FIBER_DIR/tests/nodes/1/ckb/plain_key}"
BOB_KEY_FILE="${MORPH_E2E_BOB_KEY_FILE:-$FIBER_DIR/tests/nodes/2/ckb/plain_key}"
CKB_NODE_PID=""
OPERATOR_A_KEY_TMP=""
OPERATOR_B_KEY_TMP=""
WATCHER_ENV_PROBE_PASSED=false

log() {
  printf '[publication-reliability] %s\n' "$*"
}

fail() {
  printf '[publication-reliability] error: %s\n' "$*" >&2
  exit 1
}

require_tool() {
  command -v "$1" >/dev/null 2>&1 || fail "missing required tool: $1"
}

run_without_private_keys() {
  env -u MORPH_DEVNET_PRIVATE_KEY_FILE \
    -u MORPH_ALICE_PRIVATE_KEY_FILE \
    -u MORPH_BOB_PRIVATE_KEY_FILE \
    -u MORPH_CHANNEL_PRIVATE_KEY_FILE \
    -u MORPH_OPERATOR_B_PRIVATE_KEY_FILE \
    "$@"
}

run_morph_no_keys() {
  run_without_private_keys "$MORPH_BIN" "$@"
}

run_morph_deployer() {
  env -u MORPH_ALICE_PRIVATE_KEY_FILE \
    -u MORPH_BOB_PRIVATE_KEY_FILE \
    -u MORPH_CHANNEL_PRIVATE_KEY_FILE \
    -u MORPH_OPERATOR_B_PRIVATE_KEY_FILE \
    MORPH_DEVNET_PRIVATE_KEY_FILE="$MORPH_DEVNET_PRIVATE_KEY_FILE" \
    "$MORPH_BIN" "$@"
}

run_morph_channel_keys() {
  env -u MORPH_OPERATOR_B_PRIVATE_KEY_FILE \
    MORPH_DEVNET_PRIVATE_KEY_FILE="$MORPH_DEVNET_PRIVATE_KEY_FILE" \
    MORPH_ALICE_PRIVATE_KEY_FILE="$MORPH_ALICE_PRIVATE_KEY_FILE" \
    MORPH_BOB_PRIVATE_KEY_FILE="$MORPH_BOB_PRIVATE_KEY_FILE" \
    "$MORPH_BIN" "$@"
}

resolve_ckb_bin() {
  if [ -n "$CKB_BIN" ]; then
    [ -x "$CKB_BIN" ] || fail "CKB_BIN is not executable: $CKB_BIN"
    return
  fi
  for candidate in \
    "$CKB_SOURCE_DIR/target/debug/ckb" \
    "$CKB_SOURCE_DIR/target/release/ckb" \
    "$ROOT_DIR/../ckb-bin/ckb_v0.207.0_x86_64-unknown-linux-gnu-portable/ckb"
  do
    if [ -x "$candidate" ]; then
      CKB_BIN="$candidate"
      return
    fi
  done
  fail "cannot locate CKB binary; set CKB_BIN"
}

wait_for_rpc() {
  local deadline=$((SECONDS + 90))
  local request='{"id":1,"jsonrpc":"2.0","method":"get_tip_header","params":[]}'
  while [ "$SECONDS" -lt "$deadline" ]; do
    if curl -fsS -H 'content-type: application/json' -d "$request" "$RPC_URL" |
      jq -e '.result != null' >/dev/null 2>&1
    then
      return
    fi
    if ! kill -0 "$CKB_NODE_PID" >/dev/null 2>&1; then
      fail "CKB node exited before RPC became ready; inspect $LOG_DIR/ckb-node.log"
    fi
    sleep 1
  done
  fail "timed out waiting for CKB RPC at $RPC_URL"
}

rpc_transaction() {
  local tx_hash="$1"
  jq -n --arg tx_hash "$tx_hash" \
    '{id: 1, jsonrpc: "2.0", method: "get_transaction", params: [$tx_hash, "0x2", null]}' |
    curl -fsS -H 'content-type: application/json' -d @- "$RPC_URL"
}

rpc_block_hash() {
  local block_number="$1"
  jq -n --arg block_number "$block_number" \
    '{id: 1, jsonrpc: "2.0", method: "get_block_hash", params: [$block_number]}' |
    curl -fsS -H 'content-type: application/json' -d @- "$RPC_URL"
}

mine_to_canonical_depth() {
  local tx_status_path="$1"
  local evidence_prefix="$2"
  local block_hex block_number tip_number confirmations attempts max_attempts
  block_hex="$(jq -r '.result.tx_status.block_number' "$tx_status_path")"
  block_number="$((16#${block_hex#0x}))"
  attempts=0
  max_attempts="$((CANONICAL_DEPTH + 16))"
  while [ "$attempts" -lt "$max_attempts" ]; do
    run_morph_no_keys devnet --devnet-only --rpc-url "$RPC_URL" tip --json \
      >"${evidence_prefix}-tip.json"
    tip_number="$(jq -r '.number_value' "${evidence_prefix}-tip.json")"
    confirmations="$((tip_number - block_number + 1))"
    if [ "$confirmations" -ge "$CANONICAL_DEPTH" ]; then
      return
    fi
    attempts="$((attempts + 1))"
    run_morph_no_keys devnet --devnet-only --rpc-url "$RPC_URL" mine --blocks 1 --json \
      >"${evidence_prefix}-mine-${attempts}.json"
    # IntegrationTest generate_block can return the same template if called in
    # the same clock tick; make the depth loop observe real tip advancement.
    sleep 0.02
  done
  fail "transaction in $tx_status_path did not reach canonical depth $CANONICAL_DEPTH"
}

rpc_tx_pool_info() {
  curl -fsS -H 'content-type: application/json' \
    -d '{"id":1,"jsonrpc":"2.0","method":"tx_pool_info","params":[]}' "$RPC_URL"
}

rpc_live_cell() {
  local out_point="$1"
  local tx_hash="${out_point%:*}"
  local index="${out_point##*:}"
  jq -n \
    --arg tx_hash "$tx_hash" \
    --arg index "$(printf '0x%x' "$index")" \
    '{id: 1, jsonrpc: "2.0", method: "get_live_cell", params: [{tx_hash: $tx_hash, index: $index}, true, true]}' |
    curl -fsS -H 'content-type: application/json' -d @- "$RPC_URL"
}

clear_tx_pool() {
  local response
  response="$(curl -fsS -H 'content-type: application/json' \
    -d '{"id":1,"jsonrpc":"2.0","method":"clear_tx_pool","params":[]}' "$RPC_URL")"
  jq -e '.error == null and .result == null' <<<"$response" >/dev/null ||
    fail "failed to clear detached transactions from the devnet pool"
}

stop_node() {
  if [ -n "$CKB_NODE_PID" ] && kill -0 "$CKB_NODE_PID" >/dev/null 2>&1; then
    kill "$CKB_NODE_PID" >/dev/null 2>&1 || true
    wait "$CKB_NODE_PID" >/dev/null 2>&1 || true
  fi
  morph_fixture_keys_cleanup
}

trap stop_node EXIT

require_tool cargo
require_tool curl
require_tool git
require_tool jq
require_tool perl
require_tool python3
require_tool sha256sum
resolve_ckb_bin

[ ! -e "$EVIDENCE_DIR" ] || fail "evidence directory already exists: $EVIDENCE_DIR"
mkdir -p "$OUT_DIR/operator-a/store" "$OUT_DIR/operator-b/store" "$LOG_DIR"
EVIDENCE_DIR="$(cd "$EVIDENCE_DIR" && pwd)"
CKB_DIR="$EVIDENCE_DIR/node"
OUT_DIR="$EVIDENCE_DIR/evidence"
LOG_DIR="$EVIDENCE_DIR/logs"

if [ "$BUILD_CONTRACTS" = "1" ]; then
  log "building current RISC-V contracts"
  make build-contracts >"$LOG_DIR/build-contracts.log" 2>&1
fi
log "building Morph CLI"
cargo build -q -p morph-cli --features devnet >"$LOG_DIR/build-cli.log" 2>&1
mkdir -p "$EVIDENCE_DIR/bin" "$EVIDENCE_DIR/contracts"
cp "$ROOT_DIR/target/debug/morph-cli" "$EVIDENCE_DIR/bin/morph-cli"
MORPH_BIN="$EVIDENCE_DIR/bin/morph-cli"
CONTRACTS_DIR="$EVIDENCE_DIR/contracts"
for contract in morph-state-lock morph-state-type morph-vault-lock morph-batch-lock morph-sponsor-lock morph-factory-type morph-factory-vault-lock morph-devnet-xudt; do
  cp "$ROOT_DIR/target/riscv64imac-unknown-none-elf/release/$contract" "$CONTRACTS_DIR/$contract"
done

morph_fixture_keys_init || fail "cannot prepare private fixture key files"
morph_fixture_key_file MORPH_DEVNET_PRIVATE_KEY_FILE "$DEPLOYER_KEY_FILE" deployer.key
morph_fixture_key_file MORPH_ALICE_PRIVATE_KEY_FILE "$ALICE_KEY_FILE" alice.key
morph_fixture_key_file MORPH_BOB_PRIVATE_KEY_FILE "$BOB_KEY_FILE" bob.key
OPERATOR_A_KEY_TMP="$MORPH_DEVNET_PRIVATE_KEY_FILE"
if [ -z "${MORPH_OPERATOR_B_PRIVATE_KEY_FILE:-}" ]; then
  # Public scalar 4 is a no-value development identity, never a deployment key.
  MORPH_OPERATOR_B_PRIVATE_KEY_FILE="$MORPH_FIXTURE_KEY_DIR/operator-b.key"
  (umask 077; printf '04%.0s' {1..32} >"$MORPH_OPERATOR_B_PRIVATE_KEY_FILE")
fi
OPERATOR_B_KEY_TMP="$MORPH_OPERATOR_B_PRIVATE_KEY_FILE"
# Exercise the exact key-scrubbing wrapper used by every watcher launch below.
# This proves the launch boundary, not introspection inside the watcher binary.
run_without_private_keys sh -c '
  test -z "${MORPH_DEVNET_PRIVATE_KEY_FILE+x}" &&
  test -z "${MORPH_ALICE_PRIVATE_KEY_FILE+x}" &&
  test -z "${MORPH_BOB_PRIVATE_KEY_FILE+x}" &&
  test -z "${MORPH_OPERATOR_B_PRIVATE_KEY_FILE+x}" &&
  test -z "${MORPH_CHANNEL_PRIVATE_KEY_FILE+x}"
' || fail "watchtower child environment retained a private-key variable"
WATCHER_ENV_PROBE_PASSED=true

log "starting fee-pressure CKB devnet"
CKB_BIN="$CKB_BIN" \
CKB_DIR="$CKB_DIR" \
RPC_PORT="$RPC_PORT" \
P2P_PORT="$P2P_PORT" \
MORPH_CKB_MIN_FEE_RATE="$MIN_FEE_RATE" \
MORPH_CKB_MIN_RBF_RATE="$MIN_RBF_RATE" \
  scripts/devnet-node.sh >"$LOG_DIR/ckb-node.log" 2>&1 &
CKB_NODE_PID="$!"
wait_for_rpc

run_morph_no_keys devnet --devnet-only --rpc-url "$RPC_URL" fee-market --json \
  >"$OUT_DIR/fee-market.json"
jq -e \
  --argjson min_fee "$MIN_FEE_RATE" \
  --argjson min_rbf "$MIN_RBF_RATE" \
  '.observation.pool_min_fee_rate == $min_fee and
   .observation.pool_min_rbf_rate == $min_rbf and
   .observation.rbf_enabled == true' \
  "$OUT_DIR/fee-market.json" >/dev/null || fail "node fee/RBF policy mismatch"

log "deploying contracts and creating a current channel through independent journals"
run_morph_deployer devnet --devnet-only --rpc-url "$RPC_URL" deploy-contracts --contracts-dir "$CONTRACTS_DIR" \
  --fee 100000000 --mine-blocks 4 --json >"$OUT_DIR/deploy.json"
run_morph_channel_keys devnet --devnet-only --rpc-url "$RPC_URL" multi-asset-smoke --contracts-dir "$CONTRACTS_DIR" \
  --shared-funding --asset-count 2 --finalise-since 40 --fee 100000000 \
  --mine-blocks 4 --store-dir "$OUT_DIR/setup-packages" --json >"$OUT_DIR/open.json"
jq -e '.schema == "morph.multi_asset_devnet_acceptance.v1" and .shared_funding == true and
  .finalise.status == "Committed" and (.publications | length) == 2' "$OUT_DIR/open.json" >/dev/null ||
  fail "current setup did not complete independent funding and signed state progression"
CHANNEL_ID="$(jq -er '.channel_id' "$OUT_DIR/open.json")"
STALE_TX_HASH="$(jq -er '.publications[0].tx_hash' "$OUT_DIR/open.json")"
STATE_OUT_POINT="$STALE_TX_HASH:0"
rpc_transaction "$STALE_TX_HASH" >"$OUT_DIR/setup-stale-publication.json"
rpc_transaction "$(jq -er '.fund.tx_hash' "$OUT_DIR/open.json")" >"$OUT_DIR/setup-funding.json"
OPEN_HEX="$(jq -er '.result.tx_status.block_number' "$OUT_DIR/setup-funding.json")"
OPEN_BLOCK="$((16#${OPEN_HEX#0x}))"
# Return to the genuine Settling/1 branch. The complete newer state-2 evidence
# was independently signed before rollback and remains valid for this exact
# funding context. Neither a synthetic header nor an old-format builder is used.
STALE_BLOCK="$(jq -er '.result.tx_status.block_hash' "$OUT_DIR/setup-stale-publication.json")"
run_morph_no_keys devnet --devnet-only --rpc-url "$RPC_URL" truncate "$STALE_BLOCK" --json >"$OUT_DIR/setup-truncate.json"
clear_tx_pool
rpc_live_cell "$STATE_OUT_POINT" >"$OUT_DIR/setup-live-state.json"
jq -e '.result.status == "live" and (.result.cell.data.content | length) == 638' "$OUT_DIR/setup-live-state.json" >/dev/null ||
  fail "rollback did not restore the actual current 318-byte State"
PACKAGE_PATH="$(jq -er '.recovery_packages[-1]' "$OUT_DIR/open.json")"
run_morph_no_keys validate-multi-asset-package "$PACKAGE_PATH" --json >"$OUT_DIR/state-package.json"
jq -e '.state_number == "2" and .vaults_bound == true and .vault_count == 2' "$OUT_DIR/state-package.json" >/dev/null ||
  fail "latest saved evidence is not the complete current state-2 package"
PACKAGE_SIGNING_DIGEST="$(jq -er '.package_id' "$OUT_DIR/state-package.json")"
PACKAGE_HEADER_HEX="$(jq -er '.header_hex' "$PACKAGE_PATH")"
PACKAGE_WITNESS_HEX="$(jq -er '.witness_hex' "$PACKAGE_PATH")"
[ "${#PACKAGE_HEADER_HEX}" -eq 638 ] || fail "saved package header is not 318 bytes"
run_morph_no_keys store-multi-asset-package "$PACKAGE_PATH" --store-dir "$OUT_DIR/operator-a/store" >"$OUT_DIR/operator-a/stored-path.txt"
run_morph_no_keys store-multi-asset-package "$PACKAGE_PATH" --store-dir "$OUT_DIR/operator-b/store" >"$OUT_DIR/operator-b/stored-path.txt"
OPERATOR_A_PUBKEY="$(run_morph_deployer devnet --devnet-only --rpc-url "$RPC_URL" derive-operator-pubkey --json | jq -er '.pubkey_sec1')"
OPERATOR_B_PUBKEY="$(env -u MORPH_ALICE_PRIVATE_KEY_FILE -u MORPH_BOB_PRIVATE_KEY_FILE -u MORPH_CHANNEL_PRIVATE_KEY_FILE \
  MORPH_DEVNET_PRIVATE_KEY_FILE="$OPERATOR_B_KEY_TMP" "$MORPH_BIN" devnet --devnet-only --rpc-url "$RPC_URL" derive-operator-pubkey --json | jq -er '.pubkey_sec1')"
[ "$OPERATOR_A_PUBKEY" != "$OPERATOR_B_PUBKEY" ] || fail "operators share a sponsor-change identity"
for operator in operator-a operator-b low-cap; do
  pubkey="$OPERATOR_A_PUBKEY"; cap=1000000000
  [ "$operator" != "operator-b" ] || pubkey="$OPERATOR_B_PUBKEY"
  [ "$operator" != "low-cap" ] || cap=1000000
  run_morph_deployer devnet --devnet-only --rpc-url "$RPC_URL" fund-sponsor --contracts-dir "$CONTRACTS_DIR" \
    --state-out-point "$STATE_OUT_POINT" --sponsor-change-pubkey "$pubkey" \
    --sponsor-min-state-number 2 --sponsor-max-state-number 2 \
    --sponsor-max-fee-per-tx "$cap" --sponsor-max-total-fee "$cap" \
    --fee 100000000 --mine-blocks 4 --json >"$OUT_DIR/$operator-sponsor.json"
done
SPONSOR_A_OUT_POINT="$(jq -er '.sponsor_out_point.tx_hash + ":" + (.sponsor_out_point.index | tostring)' "$OUT_DIR/operator-a-sponsor.json")"
SPONSOR_B_OUT_POINT="$(jq -er '.sponsor_out_point.tx_hash + ":" + (.sponsor_out_point.index | tostring)' "$OUT_DIR/operator-b-sponsor.json")"
LOW_CAP_SPONSOR_OUT_POINT="$(jq -er '.sponsor_out_point.tx_hash + ":" + (.sponsor_out_point.index | tostring)' "$OUT_DIR/low-cap-sponsor.json")"
[ "$SPONSOR_A_OUT_POINT" != "$SPONSOR_B_OUT_POINT" ] || fail "operators share a SponsorCell"

run_current_watch() {
  local operator="$1" sponsor="$2" cursor="$3" attempts="$4" timeout="$5"
  local pubkey="$OPERATOR_A_PUBKEY"
  [ "$operator" != "operator-b" ] || pubkey="$OPERATOR_B_PUBKEY"
  run_morph_no_keys devnet --devnet-only --rpc-url "$RPC_URL" multi-asset-watch --contracts-dir "$CONTRACTS_DIR" \
    --fee-out-point "$sponsor" --store-dir "$OUT_DIR/$operator/store" \
    --channel-id "$CHANNEL_ID" --from-block "$OPEN_BLOCK" --cursor-file "$cursor" \
    --alert-file "$OUT_DIR/$operator/alerts.jsonl" --publication-profile "$OUT_DIR/$operator/profile.json" \
    --attempt-log "$attempts" --detection-depth 1 --timeout-secs "$timeout" --poll-ms 50 \
    --max-fee 1000000000 --mine-blocks 0 sponsor --change-pubkey "$pubkey"
}
run_current_publish() {
  local sponsor="$1" pubkey="$2" store="$3" fee="$4"
  run_morph_no_keys devnet --devnet-only --rpc-url "$RPC_URL" multi-asset-transact --contracts-dir "$CONTRACTS_DIR" \
    --operation publish --package "$PACKAGE_PATH" --state-out-point "$STATE_OUT_POINT" \
    --fee-out-point "$sponsor" --store-dir "$store" --fee "$fee" --max-fee 1000000000 \
    --mine-blocks 0 sponsor --change-pubkey "$pubkey"
}

jq -n \
  --arg operator_id "watchtower-a" \
  --argjson min_fee_rate 1000000 \
  '{
    schema: "morph.publication_profile",
    operator_id: $operator_id,
    fee: {
      min_fee_rate: $min_fee_rate,
      max_fee_rate: 400000000,
      max_fee: 1000000000,
      estimator_multiplier_bps: 10000,
      replacement_multiplier_bps: 12500,
      max_attempts: 1,
      bump_after_ms: 50,
      require_rbf: false
    },
    window: {
      configured_challenge_blocks: 40,
      conservative_block_ms: 10000,
      canonical_confirmation_blocks: 4,
      reorg_budget_blocks: 6,
      failover_budget_blocks: 3,
      safety_margin_blocks: 6,
      max_measurement_age_secs: 604800
    }
  }' >"$OUT_DIR/operator-a/profile.json"

jq -n \
  --arg operator_id "watchtower-b" \
  '{
    schema: "morph.publication_profile",
    operator_id: $operator_id,
    fee: {
      min_fee_rate: 1000000,
      max_fee_rate: 400000000,
      max_fee: 1000000000,
      estimator_multiplier_bps: 10000,
      replacement_multiplier_bps: 12500,
      max_attempts: 2,
      bump_after_ms: 50,
      require_rbf: true
    },
    window: {
      configured_challenge_blocks: 40,
      conservative_block_ms: 10000,
      canonical_confirmation_blocks: 4,
      reorg_budget_blocks: 6,
      failover_budget_blocks: 3,
      safety_margin_blocks: 6,
      max_measurement_age_secs: 604800
    }
  }' >"$OUT_DIR/operator-b/profile.json"

log "proving SponsorPolicy fee caps stop publication before broadcast"
rpc_tx_pool_info >"$OUT_DIR/sponsor-cap-pool-before.json"
set +e
run_current_watch "operator-a" "$LOW_CAP_SPONSOR_OUT_POINT" "$OUT_DIR/operator-a/sponsor-cap-cursor.db" "$OUT_DIR/operator-a/sponsor-cap-attempts.jsonl" 5 >"$OUT_DIR/sponsor-cap.stdout" 2>"$OUT_DIR/sponsor-cap.stderr"
SPONSOR_CAP_STATUS="$?"
set -e
[ "$SPONSOR_CAP_STATUS" -ne 0 ] || fail "over-cap publication unexpectedly entered tx-pool"
grep -Eqi 'SponsorPolicy|max_fee_per_tx|sponsor.*cap|sponsor.*fee' "$OUT_DIR/sponsor-cap.stderr" ||
  fail "over-cap publication did not identify the SponsorPolicy boundary"
rpc_tx_pool_info >"$OUT_DIR/sponsor-cap-pool-after.json"
jq -e --slurpfile before "$OUT_DIR/sponsor-cap-pool-before.json" \
  '(.result.pending == $before[0].result.pending) and
   (.result.proposed == $before[0].result.proposed) and
   (.result.total_tx_size == $before[0].result.total_tx_size)' \
  "$OUT_DIR/sponsor-cap-pool-after.json" >/dev/null ||
  fail "SponsorPolicy cap failure changed the transaction pool"
rpc_live_cell "$LOW_CAP_SPONSOR_OUT_POINT" >"$OUT_DIR/sponsor-cap-live-cell.json"
jq -e '.result.status == "live"' "$OUT_DIR/sponsor-cap-live-cell.json" >/dev/null ||
  fail "SponsorPolicy cap failure consumed the low-cap SponsorCell"

log "proving real fee-floor rejection"
set +e
run_current_publish "$SPONSOR_A_OUT_POINT" "$OPERATOR_A_PUBKEY" "$OUT_DIR/operator-a/store" 1 >"$OUT_DIR/fee-floor.stdout" 2>"$OUT_DIR/fee-floor.stderr"
LOW_FEE_STATUS="$?"
set -e
[ "$LOW_FEE_STATUS" -ne 0 ] || fail "below-floor transaction unexpectedly entered tx-pool"
grep -Eq 'PoolRejectedTransactionByMinFeeRate|fee rate' "$OUT_DIR/fee-floor.stderr" ||
  fail "below-floor rejection did not identify the fee-rate boundary"

START_MS="$(date +%s%3N)"
sleep "$(awk -v ms="$INJECTED_DELAY_MS" 'BEGIN { printf "%.3f", ms / 1000 }')"
DETECTION_END_MS="$(date +%s%3N)"
DETECTION_MS="$((DETECTION_END_MS - START_MS))"

log "operator A submits the first pending publication without participant keys"
A_BUILD_START_MS="$(date +%s%3N)"
run_current_watch "operator-a" "$SPONSOR_A_OUT_POINT" "$OUT_DIR/operator-a/cursor.db" "$OUT_DIR/operator-a/attempts.jsonl" 5 >"$OUT_DIR/operator-a/watch.json"
A_BUILD_END_MS="$(date +%s%3N)"
BUILD_AND_VERIFY_MS="$((A_BUILD_END_MS - A_BUILD_START_MS))"
A_TX_HASH="$(jq -r '.publication.tx_hash' "$OUT_DIR/operator-a/watch.json")"
A_FEE="$(jq -r '.publication.fee' "$OUT_DIR/operator-a/watch.json")"
[ "$(jq -r '.operator_id' "$OUT_DIR/operator-a/watch.json")" = "watchtower-a" ] ||
  fail "operator A identity missing from report"
jq -e '.publication.status == "Pending" and .publication.canonical_confirmed == false' \
  "$OUT_DIR/operator-a/watch.json" >/dev/null ||
  fail "operator A submission was incorrectly reported as canonically confirmed"

log "proving restart recovery after mempool eviction without a reorg"
DROPPED_A_TX_HASH="$A_TX_HASH"
run_morph_no_keys devnet --devnet-only --rpc-url "$RPC_URL" tip --json \
  >"$OUT_DIR/operator-a/mempool-retry-tip-before.json"
clear_tx_pool
rpc_transaction "$DROPPED_A_TX_HASH" >"$OUT_DIR/operator-a/evicted-tx-status.json"
jq -e '.result.tx_status.status == "unknown" or .result.tx_status.status == "rejected"' \
  "$OUT_DIR/operator-a/evicted-tx-status.json" >/dev/null ||
  fail "cleared publication remained active in the transaction pool"
run_current_watch "operator-a" "$SPONSOR_A_OUT_POINT" "$OUT_DIR/operator-a/cursor.db" "$OUT_DIR/operator-a/attempts.jsonl" 5 >"$OUT_DIR/operator-a/retry-watch.json"
run_morph_no_keys devnet --devnet-only --rpc-url "$RPC_URL" tip --json \
  >"$OUT_DIR/operator-a/mempool-retry-tip-after.json"
jq -e --slurpfile before "$OUT_DIR/operator-a/mempool-retry-tip-before.json" \
  '.hash == $before[0].hash' "$OUT_DIR/operator-a/mempool-retry-tip-after.json" >/dev/null ||
  fail "mempool retry test unexpectedly changed the canonical tip"
jq -e '.retry_rescan == true and .reorg_recovery == null and
       .publication.status == "Pending"' "$OUT_DIR/operator-a/retry-watch.json" >/dev/null ||
  fail "watchtower did not republish the canonical-live stale StateCell after eviction"
A_TX_HASH="$(jq -r '.publication.tx_hash' "$OUT_DIR/operator-a/retry-watch.json")"
A_FEE="$(jq -r '.publication.fee' "$OUT_DIR/operator-a/retry-watch.json")"
[ "$A_TX_HASH" = "$DROPPED_A_TX_HASH" ] ||
  fail "mempool retry changed the deterministic carrier without a fee or input change"

log "proving duplicate rebroadcast is reconciled as an accepted pending transaction"
run_current_watch "operator-a" "$SPONSOR_A_OUT_POINT" "$OUT_DIR/operator-a/cursor.db" "$OUT_DIR/operator-a/attempts.jsonl" 5 >"$OUT_DIR/operator-a/duplicate-watch.json"
jq -e --arg tx_hash "$A_TX_HASH" \
  '.retry_rescan == true and .publication.status == "Pending" and
   .publication.tx_hash == $tx_hash' "$OUT_DIR/operator-a/duplicate-watch.json" >/dev/null ||
  fail "duplicate carrier was not reconciled as the already-pending transaction"

log "proving an insufficient cross-operator replacement is rejected"
set +e
run_current_publish "$SPONSOR_B_OUT_POINT" "$OPERATOR_B_PUBKEY" "$OUT_DIR/operator-b/store" "$A_FEE" >"$OUT_DIR/rbf-insufficient.stdout" 2>"$OUT_DIR/rbf-insufficient.stderr"
INSUFFICIENT_STATUS="$?"
set -e
[ "$INSUFFICIENT_STATUS" -ne 0 ] || fail "insufficient replacement unexpectedly entered tx-pool"
grep -Eqi 'replace old txs|replacement|RBF|expect it to' "$OUT_DIR/rbf-insufficient.stderr" ||
  fail "insufficient replacement did not identify the RBF boundary"

FAILOVER_START_MS="$(date +%s%3N)"
log "operator B replaces operator A using an independent sponsor and package store"
sleep 0.050
B_WATCH_START_MS="$(date +%s%3N)"
run_current_watch "operator-b" "$SPONSOR_B_OUT_POINT" "$OUT_DIR/operator-b/cursor.db" "$OUT_DIR/operator-b/attempts.jsonl" 5 >"$OUT_DIR/operator-b/watch.json"
B_WATCH_END_MS="$(date +%s%3N)"
FAILOVER_MS="$((B_WATCH_START_MS - FAILOVER_START_MS))"
QUEUE_AND_RBF_MS="$((B_WATCH_END_MS - B_WATCH_START_MS))"
B_TX_HASH="$(jq -r '.publication.tx_hash' "$OUT_DIR/operator-b/watch.json")"
B_FEE="$(jq -r '.publication.fee' "$OUT_DIR/operator-b/watch.json")"
[ "$A_TX_HASH" != "$B_TX_HASH" ] || fail "operator B did not build a replacement"
[ "$B_FEE" -gt "$A_FEE" ] || fail "operator B replacement fee did not increase"
[ "$(jq -r '.operator_id' "$OUT_DIR/operator-b/watch.json")" = "watchtower-b" ] ||
  fail "operator B identity missing from report"
jq -s -e '
  any(.[]; .attempt == 1 and .status == "rejected" and
    .error_class == "rbf_fee_too_low" and (.node_min_replace_fee | type) == "number") and
  any(.[]; .attempt == 2 and
    (.status == "pending" or .status == "proposed" or .status == "committed"))' \
  "$OUT_DIR/operator-b/attempts.jsonl" >/dev/null ||
  fail "operator B evidence does not prove node-floor learning followed by attempt 2"
jq -e '.publication.canonical_confirmed == false' "$OUT_DIR/operator-b/watch.json" >/dev/null ||
  fail "pending operator B replacement was incorrectly reported as canonically confirmed"

CONFIRMATION_START_MS="$(date +%s%3N)"
run_morph_no_keys devnet --devnet-only --rpc-url "$RPC_URL" mine --blocks 4 --json \
  >"$OUT_DIR/replacement-mining.json"
rpc_transaction "$A_TX_HASH" >"$OUT_DIR/operator-a/tx-status.json"
rpc_transaction "$B_TX_HASH" >"$OUT_DIR/operator-b/tx-status.json"
jq -e '.result.tx_status.status == "rejected" and (.result.tx_status.reason | contains("RBFRejected"))' \
  "$OUT_DIR/operator-a/tx-status.json" >/dev/null || fail "operator A transaction was not RBF-rejected"
jq -e '.result.tx_status.status == "committed"' "$OUT_DIR/operator-b/tx-status.json" >/dev/null ||
  fail "operator B replacement did not commit"
jq -e --arg header "$PACKAGE_HEADER_HEX" --arg witness "$PACKAGE_WITNESS_HEX" '
  .result.transaction.outputs_data[0] == $header and
  (.result.transaction.witnesses[0] | contains($witness[2:]))
' "$OUT_DIR/operator-b/tx-status.json" >/dev/null ||
  fail "operator B carrier changed participant-signed package evidence"
CANONICAL_DEPTH="$(jq -r '.window.canonical_confirmation_blocks' "$OUT_DIR/operator-b/profile.json")"
REPLACEMENT_BLOCK_HEX="$(jq -r '.result.tx_status.block_number' "$OUT_DIR/operator-b/tx-status.json")"
REPLACEMENT_BLOCK_DEC="$((16#${REPLACEMENT_BLOCK_HEX#0x}))"
mine_to_canonical_depth "$OUT_DIR/operator-b/tx-status.json" \
  "$OUT_DIR/operator-b/confirmation"
ORIGINAL_PUBLICATION_BLOCK_HASH="$(jq -r '.result.tx_status.block_hash' "$OUT_DIR/operator-b/tx-status.json")"
CONFIRMATION_MS="$(($(date +%s%3N) - CONFIRMATION_START_MS))"

log "reconciling durable attempt logs and advancing the cursor"
run_current_watch "operator-b" "$SPONSOR_B_OUT_POINT" "$OUT_DIR/operator-b/cursor.db" "$OUT_DIR/operator-b/attempts.jsonl" 1 >"$OUT_DIR/operator-b/reconciled-watch.json"
jq -e --arg tx_hash "$B_TX_HASH" \
  'select(.tx_hash == $tx_hash and .status == "confirmed")' \
  "$OUT_DIR/operator-b/attempts.jsonl" >/dev/null ||
  fail "operator B attempt log did not reconcile the configured canonical depth"

log "inducing a canonical reorg with IntegrationTest truncate"
run_morph_no_keys devnet --devnet-only --rpc-url "$RPC_URL" mine --blocks 1 --json \
  >"$OUT_DIR/pre-reorg-mine.json"
run_current_watch "operator-b" "$SPONSOR_B_OUT_POINT" "$OUT_DIR/operator-b/cursor.db" "$OUT_DIR/operator-b/attempts.jsonl" 1 >"$OUT_DIR/operator-b/pre-reorg-watch.json"
run_morph_no_keys devnet --devnet-only --rpc-url "$RPC_URL" tip --json >"$OUT_DIR/pre-reorg-tip.json"
CURSOR_BLOCK="$(jq -r '.scanned_to_block' "$OUT_DIR/operator-b/pre-reorg-watch.json")"
TIP_BLOCK="$(jq -r '.number_value' "$OUT_DIR/pre-reorg-tip.json")"
[ "$CURSOR_BLOCK" -eq "$TIP_BLOCK" ] || fail "cursor did not reach the pre-reorg tip"
[ "$REPLACEMENT_BLOCK_DEC" -gt 0 ] || fail "replacement committed in an invalid block"
TRUNCATE_HEIGHT_DEC="$((REPLACEMENT_BLOCK_DEC - 1))"
TRUNCATE_HEIGHT_HEX="$(printf '0x%x' "$TRUNCATE_HEIGHT_DEC")"
rpc_block_hash "$TRUNCATE_HEIGHT_HEX" >"$OUT_DIR/truncate-target.json"
TRUNCATE_TO="$(jq -r '.result' "$OUT_DIR/truncate-target.json")"
[ "$TRUNCATE_TO" != "null" ] || fail "failed to resolve the pre-publication truncate target"
REORG_START_MS="$(date +%s%3N)"
run_morph_no_keys devnet --devnet-only --rpc-url "$RPC_URL" truncate "$TRUNCATE_TO" --json \
  >"$OUT_DIR/truncate.json"
# CKB may return detached transactions to the pool. Clear them so recovery is
# proven by the watchtower's durable package, not by automatic pool replay.
clear_tx_pool
run_current_watch "operator-b" "$SPONSOR_B_OUT_POINT" "$OUT_DIR/operator-b/cursor.db" "$OUT_DIR/operator-b/attempts.jsonl" 1 >"$OUT_DIR/operator-b/reorg-watch.json"
REORG_TX_HASH="$(jq -r '.publication.tx_hash' "$OUT_DIR/operator-b/reorg-watch.json")"
jq -e '(.reorg_recovery.reason == "cursor_block_missing" or
        .reorg_recovery.reason == "cursor_block_hash_mismatch") and
       .publication != null' \
  "$OUT_DIR/operator-b/reorg-watch.json" >/dev/null ||
  fail "watchtower did not reset, rescan, and republish after the induced reorg"
run_morph_no_keys devnet --devnet-only --rpc-url "$RPC_URL" mine --blocks 4 --json \
  >"$OUT_DIR/alternate-branch.json"
rpc_transaction "$REORG_TX_HASH" >"$OUT_DIR/operator-b/reorg-tx-status.json"
jq -e '.result.tx_status.status == "committed"' \
  "$OUT_DIR/operator-b/reorg-tx-status.json" >/dev/null ||
  fail "reorg recovery publication did not commit on the alternate branch"
jq -e --arg header "$PACKAGE_HEADER_HEX" --arg witness "$PACKAGE_WITNESS_HEX" \
  --slurpfile original "$OUT_DIR/operator-b/tx-status.json" '
  .result.transaction.outputs_data[0] == $header and
  (.result.transaction.witnesses[0] | contains($witness[2:])) and
  .result.transaction.outputs_data[0] == $original[0].result.transaction.outputs_data[0] and
  .result.transaction.witnesses[0] == $original[0].result.transaction.witnesses[0]
' "$OUT_DIR/operator-b/reorg-tx-status.json" >/dev/null ||
  fail "alternate-branch carrier changed participant-signed package evidence"
REORG_BLOCK_HEX="$(jq -r '.result.tx_status.block_number' "$OUT_DIR/operator-b/reorg-tx-status.json")"
REORG_BLOCK_DEC="$((16#${REORG_BLOCK_HEX#0x}))"
mine_to_canonical_depth "$OUT_DIR/operator-b/reorg-tx-status.json" \
  "$OUT_DIR/operator-b/reorg-confirmation"
REORG_PUBLICATION_BLOCK_HASH="$(jq -r '.result.tx_status.block_hash' "$OUT_DIR/operator-b/reorg-tx-status.json")"
[ "$ORIGINAL_PUBLICATION_BLOCK_HASH" != "$REORG_PUBLICATION_BLOCK_HASH" ] ||
  fail "reorg recovery publication did not land on a distinct canonical block"
run_current_watch "operator-b" "$SPONSOR_B_OUT_POINT" "$OUT_DIR/operator-b/cursor.db" "$OUT_DIR/operator-b/attempts.jsonl" 1 >"$OUT_DIR/operator-b/reorg-reconciled-watch.json"
jq -e --arg tx_hash "$REORG_TX_HASH" \
  'select(.tx_hash == $tx_hash and .status == "confirmed")' \
  "$OUT_DIR/operator-b/attempts.jsonl" >/dev/null ||
  fail "reorg recovery attempt log did not reconcile the configured canonical depth"

log "checking bounded current service lifecycle and durable health"
run_morph_no_keys print-watch-policy-fixture | jq --arg channel "$CHANNEL_ID" \
  '.channel_id=$channel | .min_detection_depth=1 | .min_timeout_secs=1 | .max_poll_ms=50 |
   .max_fee=1000000000 | .require_mine_blocks=false | .allow_webhook_alerts=false' \
  >"$OUT_DIR/operator-b/service-policy.json"
run_morph_no_keys print-watch-config-fixture | jq \
  --arg channel "$CHANNEL_ID" --arg dir "$OUT_DIR/operator-b" \
  --arg sponsor "$SPONSOR_B_OUT_POINT" --argjson from "$OPEN_BLOCK" \
  '.operator_id="watchtower-b" | .defaults.store_dir=($dir+"/store") |
   .defaults.watch_policy=($dir+"/service-policy.json") |
   .defaults.publication_profile=($dir+"/profile.json") |
   .defaults.publication_attempt_log=($dir+"/service-attempts.jsonl") |
   .defaults.alert_file=($dir+"/service-alerts.jsonl") |
   .defaults.detection_depth=1 | .defaults.timeout_secs=1 | .defaults.poll_ms=50 |
   .defaults.fee=1000000000 | .defaults.mine_blocks=0 | .defaults.auto_fund_sponsor=false |
   .channels[0].channel_id=$channel | .channels[0].from_block=$from |
   .channels[0].sponsor_out_point=$sponsor | .channels[0].cursor_file=($dir+"/service-cursor.db")' \
  >"$OUT_DIR/operator-b/service-config.json"
run_morph_no_keys devnet --devnet-only --rpc-url "$RPC_URL" watch-config-service --contracts-dir "$CONTRACTS_DIR" \
  --private-key-file "$OPERATOR_B_KEY_TMP" --config "$OUT_DIR/operator-b/service-config.json" \
  --max-passes 1 --sleep-ms 1 --error-backoff-ms 1 --max-consecutive-errors 1 \
  --health-file "$OUT_DIR/operator-b/service-health.json" --json >"$OUT_DIR/operator-b/service.json"
jq -e '.completed_passes==1 and .published_count==0 and .error_count==0 and .stopped_reason=="max_passes"' \
  "$OUT_DIR/operator-b/service.json" >/dev/null || fail "bounded current service did not finish an idle pass"
jq -e '.status=="stopped" and .completed_passes==1 and .error_count==0 and .updated_unix_ms>0' \
  "$OUT_DIR/operator-b/service-health.json" >/dev/null || fail "current service health is missing or inconsistent"

END_MS="$(date +%s%3N)"
TOTAL_MS="$((END_MS - START_MS))"
REORG_RECOVERY_MS="$((END_MS - REORG_START_MS))"
[ "$DETECTION_END_MS" -ge "$START_MS" ] || fail "detection timing moved backwards"
[ "$BUILD_AND_VERIFY_MS" -gt 0 ] || fail "build-and-verify timing was not measured"
[ "$QUEUE_AND_RBF_MS" -gt 0 ] || fail "queue-and-RBF timing was not measured"
[ "$CONFIRMATION_MS" -gt 0 ] || fail "confirmation timing was not measured"
[ "$REORG_RECOVERY_MS" -gt 0 ] || fail "reorg recovery timing was not measured"
[ "$FAILOVER_MS" -gt 0 ] || fail "failover timing was not measured"
COMPONENT_TOTAL_MS="$((DETECTION_MS + BUILD_AND_VERIFY_MS + QUEUE_AND_RBF_MS + CONFIRMATION_MS + REORG_RECOVERY_MS + FAILOVER_MS))"
[ "$COMPONENT_TOTAL_MS" -le "$TOTAL_MS" ] || fail "challenge-window component timings overlap or exceed end-to-end time"
GENERATED_MS="$(date +%s%3N)"
run_morph_no_keys devnet --devnet-only --rpc-url "$RPC_URL" fee-market \
  --profile "$OUT_DIR/operator-b/profile.json" --json \
  >"$OUT_DIR/operator-b/fee-market.json"
PROFILE_DIGEST="$(jq -r '.profile_digest' "$OUT_DIR/operator-b/fee-market.json")"
GENESIS_HASH="$(curl -fsS -H 'content-type: application/json' \
  -d '{"id":1,"jsonrpc":"2.0","method":"get_block_hash","params":["0x0"]}' "$RPC_URL" |
  jq -r '.result')"
curl -fsS -H 'content-type: application/json' \
  -d '{"id":1,"jsonrpc":"2.0","method":"get_blockchain_info","params":[]}' "$RPC_URL" \
  >"$OUT_DIR/chain-info.json"
curl -fsS -H 'content-type: application/json' \
  -d '{"id":1,"jsonrpc":"2.0","method":"local_node_info","params":[]}' "$RPC_URL" \
  >"$OUT_DIR/node-info.json"
NETWORK="$(jq -er '.result.chain' "$OUT_DIR/chain-info.json")"
CKB_VERSION="$(jq -er '.result.version' "$OUT_DIR/node-info.json")"
jq -n \
  --arg network "$NETWORK" \
  --arg genesis_hash "$GENESIS_HASH" \
  --arg ckb_version "$CKB_VERSION" \
  --arg profile_digest "$PROFILE_DIGEST" \
  --argjson generated_unix_ms "$GENERATED_MS" \
  --argjson started_unix_ms "$START_MS" \
  --argjson end_to_end_ms "$TOTAL_MS" \
  --argjson detection_ms "$DETECTION_MS" \
  --argjson build_and_verify_ms "$BUILD_AND_VERIFY_MS" \
  --argjson queue_and_rbf_ms "$QUEUE_AND_RBF_MS" \
  --argjson confirmation_ms "$CONFIRMATION_MS" \
  --argjson reorg_recovery_ms "$REORG_RECOVERY_MS" \
  --argjson failover_ms "$FAILOVER_MS" \
  '{
    schema: "morph.challenge_window_dataset",
    network: $network,
    genesis_hash: $genesis_hash,
    ckb_version: $ckb_version,
    profile_digest: $profile_digest,
    generated_unix_ms: $generated_unix_ms,
    samples: [{
      started_unix_ms: $started_unix_ms,
      end_to_end_ms: $end_to_end_ms,
      detection_ms: $detection_ms,
      build_and_verify_ms: $build_and_verify_ms,
      queue_and_rbf_ms: $queue_and_rbf_ms,
      confirmation_ms: $confirmation_ms,
      reorg_recovery_ms: $reorg_recovery_ms,
      failover_ms: $failover_ms,
      fault_labels: ["ordinary_load", "fee_pressure", "rpc_delay", "operator_failover", "induced_reorg", "rbf_contention", "injected_delay"]
    }]
  }' >"$OUT_DIR/challenge-window-dataset.json"
DATASET_SHA256="0x$(sha256sum "$OUT_DIR/challenge-window-dataset.json" | awk '{print $1}')"
run_morph_no_keys devnet --devnet-only --rpc-url "$RPC_URL" assess-challenge-window --contracts-dir "$CONTRACTS_DIR" \
  --profile "$OUT_DIR/operator-b/profile.json" \
  --dataset "$OUT_DIR/challenge-window-dataset.json" \
  --expected-dataset-sha256 "$DATASET_SHA256" \
  --state-out-point "$REORG_TX_HASH:0" \
  --json >"$OUT_DIR/challenge-window-assessment.json"
set +e
run_morph_no_keys devnet --devnet-only --rpc-url "$RPC_URL" assess-challenge-window --contracts-dir "$CONTRACTS_DIR" \
  --profile "$OUT_DIR/operator-b/profile.json" \
  --dataset "$OUT_DIR/challenge-window-dataset.json" \
  --state-out-point "$SPONSOR_A_OUT_POINT" \
  --json >"$OUT_DIR/challenge-window-fake-state.stdout" \
  2>"$OUT_DIR/challenge-window-fake-state.stderr"
FAKE_STATE_STATUS="$?"
set -e
[ "$FAKE_STATE_STATUS" -ne 0 ] ||
  fail "SponsorCell unexpectedly passed as a challenge-window StateCell"
grep -Eq 'has no type script|does not use the deployed morph-state-type' \
  "$OUT_DIR/challenge-window-fake-state.stderr" ||
  fail "fake challenge-window StateCell rejection did not identify authenticity"
jq '.network = "wrong-network"' "$OUT_DIR/challenge-window-dataset.json" \
  >"$OUT_DIR/challenge-window-wrong-network.json"
set +e
run_morph_no_keys devnet --devnet-only --rpc-url "$RPC_URL" assess-challenge-window --contracts-dir "$CONTRACTS_DIR" \
  --profile "$OUT_DIR/operator-b/profile.json" \
  --dataset "$OUT_DIR/challenge-window-wrong-network.json" \
  --state-out-point "$REORG_TX_HASH:0" \
  --json >"$OUT_DIR/challenge-window-wrong-network.stdout" \
  2>"$OUT_DIR/challenge-window-wrong-network.stderr"
WRONG_NETWORK_STATUS="$?"
set -e
[ "$WRONG_NETWORK_STATUS" -ne 0 ] ||
  fail "challenge-window dataset for a different network unexpectedly passed"
grep -q 'does not match connected node network' "$OUT_DIR/challenge-window-wrong-network.stderr" ||
  fail "challenge-window network mismatch was not identified"
set +e
run_morph_no_keys devnet --devnet-only --rpc-url "$RPC_URL" assess-challenge-window --contracts-dir "$CONTRACTS_DIR" \
  --profile "$OUT_DIR/operator-b/profile.json" \
  --dataset "$OUT_DIR/challenge-window-dataset.json" \
  --expected-dataset-sha256 "$DATASET_SHA256" \
  --state-out-point "$REORG_TX_HASH:0" \
  --production \
  --json >"$OUT_DIR/challenge-window-production-assessment.json" \
  2>"$OUT_DIR/challenge-window-production-assessment.stderr"
PRODUCTION_ASSESSMENT_STATUS="$?"
set -e
[ "$PRODUCTION_ASSESSMENT_STATUS" -ne 0 ] ||
  fail "one-sample devnet dataset unexpectedly passed the production gate"
jq -e '.passes == false and .sufficient_samples == false and
       .production_provenance_verified == false and
       .production_network_eligible == false and
       .unique_samples == true and .fault_evidence_valid == true and
       .rbf_profile_eligible == true and
       .required_faults_present == true and (.missing_fault_labels | length) == 0 and
       .sufficient_fault_samples == false and
       .deployment_matches_profile == true and
       (.under_sampled_fault_labels | index("fee_pressure")) != null and
       (.under_sampled_fault_labels | index("induced_reorg")) != null' \
  "$OUT_DIR/challenge-window-production-assessment.json" >/dev/null ||
  fail "production challenge-window rejection did not identify missing evidence"

MORPH_REVISION="$(git rev-parse HEAD)"
WORKTREE_CONTENT_SHA256="$({
  git rev-parse HEAD
  git diff --binary --no-ext-diff HEAD
  python3 - <<'PY_SOURCE_HASH'
import hashlib, json, os, pathlib, subprocess
paths = subprocess.check_output(["git", "ls-files", "--others", "--exclude-standard", "-z"])
for raw in sorted(filter(None, paths.split(b"\0"))):
    path = pathlib.Path(os.fsdecode(raw))
    if path.is_symlink():
        kind, data = "symlink", os.fsencode(os.readlink(path))
    elif path.is_file():
        kind, data = "file", path.read_bytes()
    else:
        raise SystemExit(f"unsupported untracked source entry: {path}")
    print(json.dumps([kind, str(path), hashlib.sha256(data).hexdigest()], ensure_ascii=True))
PY_SOURCE_HASH
} | sha256sum | awk '{print $1}')"
MORPH_CLI_SHA256="$(sha256sum "$MORPH_BIN" | awk '{print $1}')"
HARNESS_SHA256="$(sha256sum scripts/devnet-publication-reliability.sh | awk '{print $1}')"
CONTRACT_HASH_MANIFEST="$OUT_DIR/contract-sha256.txt"
for contract in \
  morph-state-lock morph-state-type morph-vault-lock morph-batch-lock morph-sponsor-lock \
  morph-factory-type morph-factory-vault-lock morph-devnet-xudt
do
  sha256sum "$CONTRACTS_DIR/$contract"
done >"$CONTRACT_HASH_MANIFEST"
CONTRACT_SET_SHA256="$(sha256sum "$CONTRACT_HASH_MANIFEST" | awk '{print $1}')"

jq -n \
  --slurpfile fee "$OUT_DIR/fee-market.json" \
  --slurpfile service "$OUT_DIR/operator-b/service.json" \
  --slurpfile service_health "$OUT_DIR/operator-b/service-health.json" \
  --slurpfile open "$OUT_DIR/open.json" \
  --slurpfile aw "$OUT_DIR/operator-a/watch.json" \
  --slurpfile arw "$OUT_DIR/operator-a/retry-watch.json" \
  --slurpfile adw "$OUT_DIR/operator-a/duplicate-watch.json" \
  --slurpfile evicted "$OUT_DIR/operator-a/evicted-tx-status.json" \
  --slurpfile bw "$OUT_DIR/operator-b/watch.json" \
  --slurpfile ats "$OUT_DIR/operator-a/tx-status.json" \
  --slurpfile bts "$OUT_DIR/operator-b/tx-status.json" \
  --slurpfile reorg "$OUT_DIR/operator-b/reorg-watch.json" \
  --slurpfile reorg_status "$OUT_DIR/operator-b/reorg-tx-status.json" \
  --slurpfile attempts_a "$OUT_DIR/operator-a/attempts.jsonl" \
  --slurpfile attempts_b "$OUT_DIR/operator-b/attempts.jsonl" \
  --slurpfile window "$OUT_DIR/challenge-window-assessment.json" \
  --slurpfile production_window "$OUT_DIR/challenge-window-production-assessment.json" \
  --slurpfile profile_b "$OUT_DIR/operator-b/profile.json" \
  --arg sponsor_a "$SPONSOR_A_OUT_POINT" \
  --arg sponsor_b "$SPONSOR_B_OUT_POINT" \
  --arg cursor_a "$OUT_DIR/operator-a/cursor.db" \
  --arg cursor_b "$OUT_DIR/operator-b/cursor.db" \
  --arg dataset_sha256 "$DATASET_SHA256" \
  --arg package_signing_digest "$PACKAGE_SIGNING_DIGEST" \
  --arg morph_revision "$MORPH_REVISION" \
  --arg worktree_content_sha256 "$WORKTREE_CONTENT_SHA256" \
  --arg morph_cli_sha256 "$MORPH_CLI_SHA256" \
  --arg harness_sha256 "$HARNESS_SHA256" \
  --arg contract_set_sha256 "$CONTRACT_SET_SHA256" \
  --argjson watcher_env_probe "$WATCHER_ENV_PROBE_PASSED" \
  '{
    schema: "morph.devnet_publication_reliability",
    status: "passed",
    no_participant_keys_in_watchtower: true,
    watcher_environment_probe_passed: $watcher_env_probe,
    distinct_operator_signing_identities: true,
    state_header_bytes: 318,
    descriptor_version: 6,
    independent_current_funding_journals: true,
    immutable_signed_evidence: {
      package_signing_digest: $package_signing_digest,
      original_carrier_matches_package: true,
      alternate_carrier_matches_package: true,
      original_and_alternate_evidence_identical: true
    },
    source_binding: {
      morph_revision: $morph_revision,
      worktree_content_sha256: $worktree_content_sha256,
      morph_cli_sha256: $morph_cli_sha256,
      harness_sha256: $harness_sha256,
      contract_set_sha256: $contract_set_sha256,
      dataset_sha256: $dataset_sha256
    },
    node_fee_market: $fee[0].observation,
    channel_id: $open[0].channel_id,
    operators: [
      {operator_id: "watchtower-a", sponsor_out_point: $sponsor_a, cursor: $cursor_a, initial_publication: $aw[0].publication, publication: $arw[0].publication},
      {operator_id: "watchtower-b", sponsor_out_point: $sponsor_b, cursor: $cursor_b, publication: $bw[0].publication}
    ],
    runtime_deadline_budget: {
      configured_challenge_blocks: $profile_b[0].window.configured_challenge_blocks,
      canonical_confirmation_blocks: $profile_b[0].window.canonical_confirmation_blocks,
      recovery_reserve_blocks: (
        $profile_b[0].window.reorg_budget_blocks +
        $profile_b[0].window.failover_budget_blocks +
        $profile_b[0].window.safety_margin_blocks
      ),
      operator_a_observed_confirmations: $aw[0].observed.confirmations,
      operator_b_observed_confirmations: $bw[0].observed.confirmations,
      reorg_observed_confirmations: $reorg[0].observed.confirmations,
      operator_a_runtime_blocks: (
        $profile_b[0].window.configured_challenge_blocks - $aw[0].observed.confirmations -
        $profile_b[0].window.reorg_budget_blocks - $profile_b[0].window.failover_budget_blocks -
        $profile_b[0].window.safety_margin_blocks
      ),
      operator_b_runtime_blocks: (
        $profile_b[0].window.configured_challenge_blocks - $bw[0].observed.confirmations -
        $profile_b[0].window.reorg_budget_blocks - $profile_b[0].window.failover_budget_blocks -
        $profile_b[0].window.safety_margin_blocks
      ),
      reorg_runtime_blocks: (
        $profile_b[0].window.configured_challenge_blocks - $reorg[0].observed.confirmations -
        $profile_b[0].window.reorg_budget_blocks - $profile_b[0].window.failover_budget_blocks -
        $profile_b[0].window.safety_margin_blocks
      )
    },
    service_health: $service_health[0],
    bounded_service: $service[0],
    fee_floor_rejected: true,
    sponsor_cap_rejected_before_broadcast: true,
    insufficient_rbf_rejected: true,
    rbf_floor_learning: {
      rejected_attempt: ($attempts_b | map(select(.attempt == 1 and .error_class == "rbf_fee_too_low")) | first),
      replacement_attempt: ($attempts_b | map(select(.attempt == 2)) | first)
    },
    publication_attempts: {operator_a: $attempts_a, operator_b: $attempts_b},
    mempool_eviction_recovery: {
      without_reorg: ($arw[0].reorg_recovery == null),
      cursor_forced_rescan: $arw[0].retry_rescan,
      evicted_status: $evicted[0].result.tx_status,
      retry_publication: $arw[0].publication
    },
    duplicate_rebroadcast: {
      cursor_forced_rescan: $adw[0].retry_rescan,
      publication: $adw[0].publication
    },
    dataset_network_mismatch_rejected: true,
    fake_challenge_state_rejected: true,
    replaced_status: $ats[0].result.tx_status,
    replacement_status: $bts[0].result.tx_status,
    induced_reorg: $reorg[0].reorg_recovery,
    reorg_republication: $reorg[0].publication,
    reorg_republication_status: $reorg_status[0].result.tx_status,
    challenge_window: $window[0],
    production_challenge_window: $production_window[0],
    production_measurement_sufficient: $production_window[0].passes,
    note: "One deterministic devnet sample validates code paths; production still requires at least 1000 fresh public-network samples and independent infrastructure."
  }' >"$OUT_DIR/report.json"

EVIDENCE_DIR_ABS="$(cd "$EVIDENCE_DIR" && pwd)"
mkdir -p "$(dirname "$LATEST_LINK")"
if [ ! -e "$LATEST_LINK" ] || [ -L "$LATEST_LINK" ]; then
  rm -f "$LATEST_LINK"
  ln -s "$EVIDENCE_DIR_ABS" "$LATEST_LINK"
fi
log "passed; evidence: $OUT_DIR/report.json"
