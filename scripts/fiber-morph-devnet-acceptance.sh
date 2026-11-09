#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/scripts/private-key-files.sh"
PARENT_DIR="$(cd "$ROOT_DIR/.." && pwd)"

FIBER_DIR="${FIBER_DIR:-$PARENT_DIR/fiber}"
CKB_SOURCE_DIR="${CKB_SOURCE_DIR:-$PARENT_DIR/ckb}"
CKB_CLI_SOURCE_DIR="${CKB_CLI_SOURCE_DIR:-$PARENT_DIR/ckb-cli}"

RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT_DIR="${OUT_DIR:-$ROOT_DIR/target/fiber-morph-devnet-acceptance/$RUN_ID}"
LOG_DIR="$OUT_DIR/logs"
TOOL_BIN_DIR="$OUT_DIR/tool-bin"
MODE="${FIBER_MORPH_ACCEPTANCE_MODE:-coexistence}"
FIBER_TEST_ENV="${FIBER_TEST_ENV:-debug}"
FIBER_CKB_RPC_URL="${FIBER_CKB_RPC_URL:-http://127.0.0.1:8114}"
FIBER_NODE1_RPC_URL="${FIBER_NODE1_RPC_URL:-http://127.0.0.1:21714}"
FIBER_NODE2_RPC_URL="${FIBER_NODE2_RPC_URL:-http://127.0.0.1:21715}"
FIBER_NODE3_RPC_URL="${FIBER_NODE3_RPC_URL:-http://127.0.0.1:21716}"
FIBER_COEXISTENCE_SUITE="${FIBER_COEXISTENCE_SUITE:-e2e/external-funding-open}"
FIBER_PAYMENT_GATEWAY_ROUTER_SUITE="e2e/router-pay"
FIBER_PERIOD_CHECK_EXPIRY_SUITE="${FIBER_PERIOD_CHECK_EXPIRY_SUITE:-e2e/period-check/force-close-expiry}"
DEFAULT_FIBER_RUST_SUITES="e2e/open-use-close-a-channel e2e/3-nodes-transfer e2e/router-pay e2e/reestablish e2e/shutdown-force e2e/hold-invoice-cancel-failure $FIBER_PERIOD_CHECK_EXPIRY_SUITE e2e/udt e2e/udt-router-pay e2e/watchtower/force-close-after-open-channel e2e/watchtower/force-close-with-pending-tlcs e2e/watchtower/force-close-after-multiple-payments e2e/watchtower/force-close-remote-with-pending-tlcs-and-stop-watchtower"
FIBER_RUST_SUITES="${FIBER_RUST_SUITES:-$DEFAULT_FIBER_RUST_SUITES}"
FIBER_FUNDING_TX_VERIFICATION_CASES="${FIBER_FUNDING_TX_VERIFICATION_CASES:-remove_change modify_change fund_from_peer missing_inputs}"
FIBER_ACCEPTANCE_TCP_PORTS="${FIBER_ACCEPTANCE_TCP_PORTS:-8114 8115 21714 21715 21716 8343 8344 8345 8346}"
RUST_RUNNER="$OUT_DIR/bin/morph-xtask"
RUN_FIBER_RESTART_REGRESSION="1"
FIBER_STACK_START_ATTEMPTS="${FIBER_STACK_START_ATTEMPTS:-3}"
# ckb-librocksdb-sys 8.5.4 relies on transitive fixed-width integer includes;
# modern GCC/Clang require the standard header to be explicit.
FIBER_CXXFLAGS="${FIBER_CXXFLAGS:--include cstdint}"
FIBER_STACK_BUILDER_ARGS=""
MORPH_FIBER_DEPLOYER_KEY_FILE="${MORPH_FIBER_DEPLOYER_KEY_FILE:-$FIBER_DIR/tests/nodes/deployer/ckb/plain_key}"
MORPH_FIBER_ALICE_KEY_FILE="${MORPH_FIBER_ALICE_KEY_FILE:-$FIBER_DIR/tests/nodes/1/ckb/plain_key}"
MORPH_FIBER_BOB_KEY_FILE="${MORPH_FIBER_BOB_KEY_FILE:-$FIBER_DIR/tests/nodes/2/ckb/plain_key}"

CKB_BIN="${CKB_BIN:-}"
CKB_CLI_BIN="${CKB_CLI_BIN:-}"
NC_BIN=""
FIBER_STACK_PID=""
FIBER_STACK_STARTED=0

if [ "${1:-}" = "--preflight" ]; then
  MODE="preflight"
elif [ -n "${1:-}" ]; then
  MODE="$1"
fi

mkdir -p "$LOG_DIR" "$TOOL_BIN_DIR"

log() {
  printf '[fiber-morph-acceptance] %s\n' "$*"
}

fail() {
  printf '[fiber-morph-acceptance] error: %s\n' "$*" >&2
  exit 1
}

morph_reject_raw_private_keys || fail "use protected private-key file paths"

require_tool() {
  local name="$1"
  command -v "$name" >/dev/null 2>&1 || fail "missing required tool: $name"
}

clone_repo_if_missing() {
  local dir="$1"
  local url="$2"
  if [ -d "$dir/.git" ]; then
    return
  fi
  if [ -e "$dir" ]; then
    fail "$dir exists but is not a git checkout"
  fi
  log "cloning missing dependency: $url -> $dir"
  git clone "$url" "$dir"
}

git_value() {
  local dir="$1"
  shift
  git -C "$dir" "$@" 2>/dev/null || printf 'unknown'
}

write_repo_state() {
  local path="$OUT_DIR/repo-state.json"
  jq -n \
    --arg morph_dir "$ROOT_DIR" \
    --arg morph_branch "$(git_value "$ROOT_DIR" branch --show-current)" \
    --arg morph_head "$(git_value "$ROOT_DIR" rev-parse --short HEAD)" \
    --arg morph_status "$(git_value "$ROOT_DIR" status --porcelain --untracked-files=no)" \
    --arg morph_worktree_status "$(git_value "$ROOT_DIR" status --porcelain)" \
    --arg fiber_dir "$FIBER_DIR" \
    --arg fiber_branch "$(git_value "$FIBER_DIR" branch --show-current)" \
    --arg fiber_head "$(git_value "$FIBER_DIR" rev-parse --short HEAD)" \
    --arg fiber_status "$(git_value "$FIBER_DIR" status --porcelain --untracked-files=no)" \
    --arg ckb_dir "$CKB_SOURCE_DIR" \
    --arg ckb_branch "$(git_value "$CKB_SOURCE_DIR" branch --show-current)" \
    --arg ckb_head "$(git_value "$CKB_SOURCE_DIR" rev-parse --short HEAD)" \
    --arg ckb_status "$(git_value "$CKB_SOURCE_DIR" status --porcelain)" \
    --arg ckb_cli_dir "$CKB_CLI_SOURCE_DIR" \
    --arg ckb_cli_branch "$(git_value "$CKB_CLI_SOURCE_DIR" branch --show-current)" \
    --arg ckb_cli_head "$(git_value "$CKB_CLI_SOURCE_DIR" rev-parse --short HEAD)" \
    --arg ckb_cli_status "$(git_value "$CKB_CLI_SOURCE_DIR" status --porcelain)" \
    '{
      schema: "morph.fiber_morph_repo_state",
      morph: {
        dir: $morph_dir,
        branch: $morph_branch,
        head: $morph_head,
        status: $morph_status,
        worktree_status: $morph_worktree_status
      },
      fiber: { dir: $fiber_dir, branch: $fiber_branch, head: $fiber_head, status: $fiber_status },
      ckb: { dir: $ckb_dir, branch: $ckb_branch, head: $ckb_head, status: $ckb_status },
      ckb_cli: { dir: $ckb_cli_dir, branch: $ckb_cli_branch, head: $ckb_cli_head, status: $ckb_cli_status }
    }' >"$path"
  log "repo state -> $path"
}

assert_clean_for_production() {
  local morph_status
  morph_status="$(git -C "$ROOT_DIR" status --porcelain --untracked-files=no)"
  if [ -n "$morph_status" ]; then
    fail "Morph tracked worktree is dirty; production acceptance requires committed tracked inputs because acceptance binds current source and executed artifacts"
  fi
  local fiber_status
  fiber_status="$(git -C "$FIBER_DIR" status --porcelain --untracked-files=no)"
  if [ -n "$fiber_status" ]; then
    fail "Fiber tracked worktree is dirty; commit or stash tracked changes before production acceptance"
  fi
}

resolve_ckb_bin() {
  if [ -n "$CKB_BIN" ]; then
    [ -x "$CKB_BIN" ] || fail "CKB_BIN is not executable: $CKB_BIN"
    return
  fi
  if command -v ckb >/dev/null 2>&1; then
    CKB_BIN="$(command -v ckb)"
    return
  fi
  for candidate in \
    "$CKB_SOURCE_DIR/target/release/ckb" \
    "$CKB_SOURCE_DIR/target/debug/ckb"
  do
    if [ -x "$candidate" ]; then
      CKB_BIN="$candidate"
      return
    fi
  done
  [ -f "$CKB_SOURCE_DIR/Cargo.toml" ] || fail "cannot find CKB source at $CKB_SOURCE_DIR"
  log "building ckb from $CKB_SOURCE_DIR"
  cargo build --manifest-path "$CKB_SOURCE_DIR/Cargo.toml" -p ckb
  CKB_BIN="$CKB_SOURCE_DIR/target/debug/ckb"
  [ -x "$CKB_BIN" ] || fail "CKB build did not produce $CKB_BIN"
}

resolve_ckb_cli_bin() {
  if [ -n "$CKB_CLI_BIN" ]; then
    [ -x "$CKB_CLI_BIN" ] || fail "CKB_CLI_BIN is not executable: $CKB_CLI_BIN"
    return
  fi
  if command -v ckb-cli >/dev/null 2>&1; then
    CKB_CLI_BIN="$(command -v ckb-cli)"
    return
  fi
  for candidate in \
    "$CKB_CLI_SOURCE_DIR/target/release/ckb-cli" \
    "$CKB_CLI_SOURCE_DIR/target/debug/ckb-cli"
  do
    if [ -x "$candidate" ]; then
      CKB_CLI_BIN="$candidate"
      return
    fi
  done
  [ -f "$CKB_CLI_SOURCE_DIR/Cargo.toml" ] || fail "cannot find ckb-cli source at $CKB_CLI_SOURCE_DIR"
  log "building ckb-cli from $CKB_CLI_SOURCE_DIR"
  cargo build --manifest-path "$CKB_CLI_SOURCE_DIR/Cargo.toml"
  CKB_CLI_BIN="$CKB_CLI_SOURCE_DIR/target/debug/ckb-cli"
  [ -x "$CKB_CLI_BIN" ] || fail "ckb-cli build did not produce $CKB_CLI_BIN"
}

resolve_nc_bin() {
  if command -v nc >/dev/null 2>&1; then
    NC_BIN="$(command -v nc)"
    return
  fi
  NC_BIN="$ROOT_DIR/scripts/nc-z-shim.sh"
  [ -x "$NC_BIN" ] || fail "netcat is unavailable and the local nc -z shim is not executable: $NC_BIN"
}

prepare_tool_path() {
  resolve_ckb_bin
  resolve_ckb_cli_bin
  resolve_nc_bin
  ln -sf "$CKB_BIN" "$TOOL_BIN_DIR/ckb"
  ln -sf "$CKB_CLI_BIN" "$TOOL_BIN_DIR/ckb-cli"
  ln -sf "$NC_BIN" "$TOOL_BIN_DIR/nc"
  export PATH="$TOOL_BIN_DIR:$PATH"
  log "ckb -> $CKB_BIN"
  log "ckb-cli -> $CKB_CLI_BIN"
  log "nc -> $NC_BIN"
}

write_manifest() {
  cat >"$OUT_DIR/manifest.txt" <<EOF
schema=morph.fiber_morph_devnet_acceptance
started_at_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)
run_id=$RUN_ID
mode=$MODE
root_dir=$ROOT_DIR
fiber_dir=$FIBER_DIR
ckb_source_dir=$CKB_SOURCE_DIR
ckb_cli_source_dir=$CKB_CLI_SOURCE_DIR
ckb_bin=$CKB_BIN
ckb_cli_bin=$CKB_CLI_BIN
nc_bin=$NC_BIN
fiber_ckb_rpc_url=$FIBER_CKB_RPC_URL
fiber_node1_rpc_url=$FIBER_NODE1_RPC_URL
fiber_node2_rpc_url=$FIBER_NODE2_RPC_URL
fiber_node3_rpc_url=$FIBER_NODE3_RPC_URL
fiber_test_env=$FIBER_TEST_ENV
fiber_coexistence_suite=$FIBER_COEXISTENCE_SUITE
fiber_payment_gateway_router_suite=$FIBER_PAYMENT_GATEWAY_ROUTER_SUITE
fiber_rust_suites=$FIBER_RUST_SUITES
fiber_funding_tx_verification_cases=$FIBER_FUNDING_TX_VERIFICATION_CASES
fiber_acceptance_tcp_ports=$FIBER_ACCEPTANCE_TCP_PORTS
run_fiber_restart_regression=$RUN_FIBER_RESTART_REGRESSION
fiber_stack_start_attempts=$FIBER_STACK_START_ATTEMPTS
fiber_cxxflags=$FIBER_CXXFLAGS
morph_fiber_deployer_key_file=$MORPH_FIBER_DEPLOYER_KEY_FILE
morph_fiber_alice_key_file=$MORPH_FIBER_ALICE_KEY_FILE
morph_fiber_bob_key_file=$MORPH_FIBER_BOB_KEY_FILE
EOF
}

require_devnet_fixture_key_file() {
  local path="$1"
  local label="$2"
  [ -f "$path" ] || fail "missing $label devnet fixture key file: $path"
  grep -Eq '^(0x)?[0-9a-fA-F]{64}$' "$path" ||
    fail "$label devnet fixture key file must contain exactly one secp256k1 key: $path"
}

rpc_ready() {
  local url="$1"
  local method="$2"
  local params="${3:-[]}"
  local payload
  payload="$(jq -cn --arg method "$method" --argjson params "$params" \
    '{id:1,jsonrpc:"2.0",method:$method,params:$params}')"
  curl -fsS -H 'content-type: application/json' -d "$payload" "$url" 2>/dev/null |
    jq -e '.result != null' >/dev/null
}

wait_for_rpc_ready() {
  local url="$1"
  local method="$2"
  local label="$3"
  local deadline=$((SECONDS + 240))
  while [ "$SECONDS" -lt "$deadline" ]; do
    if rpc_ready "$url" "$method" "[]"; then
      return 0
    fi
    if [ -n "$FIBER_STACK_PID" ] && ! kill -0 "$FIBER_STACK_PID" >/dev/null 2>&1; then
      return 2
    fi
    sleep 2
  done
  return 1
}

wait_for_rpc() {
  local url="$1"
  local method="$2"
  local label="$3"
  local status=0
  wait_for_rpc_ready "$url" "$method" "$label" || status=$?
  if [ "$status" -eq 0 ]; then
    return
  fi
  if [ "$status" -eq 2 ]; then
    fail "Fiber stack exited while waiting for $label; see the current fiber-stack*.log under $LOG_DIR"
  fi
  fail "timed out waiting for $label at $url"
}

wait_for_stable_rpc_ready() {
  local url="$1"
  local method="$2"
  local label="$3"
  local checks="${4:-3}"
  local interval="${5:-2}"
  local check
  for ((check = 1; check <= checks; check++)); do
    wait_for_rpc_ready "$url" "$method" "$label stable check $check/$checks" || return $?
    if [ "$check" -lt "$checks" ]; then
      sleep "$interval"
    fi
  done
  return 0
}

wait_for_stable_rpc() {
  local url="$1"
  local method="$2"
  local label="$3"
  local checks="${4:-3}"
  local interval="${5:-2}"
  local status=0
  wait_for_stable_rpc_ready "$url" "$method" "$label" "$checks" "$interval" || status=$?
  if [ "$status" -eq 0 ]; then
    return
  fi
  if [ "$status" -eq 2 ]; then
    fail "Fiber stack exited while waiting for $label; see the current fiber-stack*.log under $LOG_DIR"
  fi
  fail "timed out waiting for stable $label at $url"
}

kill_tree() {
  local pid="$1"
  local child
  if command -v pgrep >/dev/null 2>&1; then
    for child in $(pgrep -P "$pid" 2>/dev/null || true); do
      kill_tree "$child"
    done
  fi
  kill "$pid" >/dev/null 2>&1 || true
}

acceptance_port_listener_pids() {
  local port
  if command -v lsof >/dev/null 2>&1; then
    local args=()
    for port in $FIBER_ACCEPTANCE_TCP_PORTS; do
      args+=("-iTCP:$port")
    done
    lsof -nP "${args[@]}" -sTCP:LISTEN -t 2>/dev/null | sort -u
    return
  fi

  if command -v ss >/dev/null 2>&1; then
    for port in $FIBER_ACCEPTANCE_TCP_PORTS; do
      ss -H -ltnp "sport = :$port" 2>/dev/null
    done | sed -n 's/.*pid=\([0-9][0-9]*\).*/\1/p' | sort -u
  fi
}

wait_for_acceptance_ports_free() {
  local deadline=$((SECONDS + 30))
  local pids
  while [ "$SECONDS" -lt "$deadline" ]; do
    pids="$(acceptance_port_listener_pids || true)"
    if [ -z "$pids" ]; then
      return 0
    fi
    sleep 1
  done

  return 1
}

stop_acceptance_port_listeners() {
  local pids pid
  pids="$(acceptance_port_listener_pids || true)"
  if [ -z "$pids" ]; then
    return 0
  fi

  log "stopping lingering Fiber acceptance listeners on ports: $FIBER_ACCEPTANCE_TCP_PORTS"
  for pid in $pids; do
    kill_tree "$pid"
  done

  sleep 2
  pids="$(acceptance_port_listener_pids || true)"
  if [ -n "$pids" ]; then
    log "force-stopping lingering Fiber acceptance listener pids: $(printf '%s' "$pids" | tr '\n' ' ')"
    for pid in $pids; do
      kill -KILL "$pid" >/dev/null 2>&1 || true
    done
  fi
}

stop_fiber_stack() {
  local should_clean_ports=0
  if [ -n "$FIBER_STACK_PID" ] && kill -0 "$FIBER_STACK_PID" >/dev/null 2>&1; then
    log "stopping Fiber stack pid=$FIBER_STACK_PID"
    kill_tree "$FIBER_STACK_PID"
    wait "$FIBER_STACK_PID" >/dev/null 2>&1 || true
    should_clean_ports=1
  elif [ "$FIBER_STACK_STARTED" = "1" ]; then
    should_clean_ports=1
  fi
  FIBER_STACK_PID=""
  if [ "$should_clean_ports" = "1" ]; then
    if ! wait_for_acceptance_ports_free; then
      stop_acceptance_port_listeners
      wait_for_acceptance_ports_free || fail "Fiber acceptance ports stayed busy after teardown: $FIBER_ACCEPTANCE_TCP_PORTS"
    fi
  fi
}

trap 'stop_fiber_stack; morph_fixture_keys_cleanup' EXIT

start_fiber_stack_once() {
  local testcase="$1"
  local log_file="$2"
  local attempt="$3"
  stop_fiber_stack
  wait_for_acceptance_ports_free || return 3
  log "starting Fiber stack for $testcase (attempt $attempt/$FIBER_STACK_START_ATTEMPTS)"
  (
    printf '\n=== Fiber stack attempt %s/%s for %s at %s ===\n' \
      "$attempt" "$FIBER_STACK_START_ATTEMPTS" "$testcase" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    cd "$FIBER_DIR"
    CXXFLAGS="$FIBER_CXXFLAGS" \
      REMOVE_OLD_STATE=y \
    TEST_ENV="$FIBER_TEST_ENV" \
    EXTRA_BRU_ARGS="$FIBER_STACK_BUILDER_ARGS" \
    PATH="$TOOL_BIN_DIR:$PATH" \
      ./tests/nodes/start.sh "$testcase"
  ) >>"$log_file" 2>&1 &
  FIBER_STACK_PID="$!"
  FIBER_STACK_STARTED=1
  wait_for_rpc_ready "$FIBER_CKB_RPC_URL" "get_tip_header" "Fiber CKB" || return $?
  wait_for_rpc_ready "$FIBER_NODE1_RPC_URL" "node_info" "Fiber node1" || return $?
  wait_for_rpc_ready "$FIBER_NODE2_RPC_URL" "node_info" "Fiber node2" || return $?
  wait_for_rpc_ready "$FIBER_NODE3_RPC_URL" "node_info" "Fiber node3" || return $?
  wait_for_stable_rpc_ready "$FIBER_CKB_RPC_URL" "get_tip_header" "Fiber CKB" 4 2 || return $?
  log "Fiber stack ready for $testcase"
}

start_fiber_stack() {
  local testcase="$1"
  local log_file="$2"
  local attempt status last_status=0
  : >"$log_file"
  for ((attempt = 1; attempt <= FIBER_STACK_START_ATTEMPTS; attempt++)); do
    status=0
    start_fiber_stack_once "$testcase" "$log_file" "$attempt" || status=$?
    last_status="$status"
    if [ "$status" -eq 0 ]; then
      return
    fi
    log "Fiber stack startup attempt $attempt/$FIBER_STACK_START_ATTEMPTS failed for $testcase with status $status; see $log_file"
    stop_fiber_stack
    if [ "$attempt" -lt "$FIBER_STACK_START_ATTEMPTS" ]; then
      sleep 5
    fi
  done
  if [ "$last_status" -eq 3 ]; then
    fail "Fiber acceptance ports stayed busy before starting $testcase: $FIBER_ACCEPTANCE_TCP_PORTS"
  fi
  fail "Fiber stack failed to become ready for $testcase after $FIBER_STACK_START_ATTEMPTS attempts; see $log_file"
}

run_rust_suite() {
  local suite="$1" suite_id="${2:-$1}"
  local label="${suite_id//\//_}" fixture="${suite#e2e/}"
  local log_file="$LOG_DIR/fiber-rust-$label.log"
  fixture="${fixture//\//_}"
  local evidence="$OUT_DIR/fiber-rust-$label.evidence.json"
  log "running native Rust Fiber suite $suite_id"
  FIBER_CKB_RPC_URL="$FIBER_CKB_RPC_URL" \
  FIBER_NODE1_RPC_URL="$FIBER_NODE1_RPC_URL" \
  FIBER_NODE2_RPC_URL="$FIBER_NODE2_RPC_URL" \
  FIBER_NODE3_RPC_URL="$FIBER_NODE3_RPC_URL" \
  MORPH_FIBER_EXTERNAL_PRIVATE_KEY_FILE="$MORPH_FIBER_EXTERNAL_PRIVATE_KEY_FILE" \
    "$RUST_RUNNER" fiber-scenario "$ROOT_DIR/fixtures/fiber/$fixture.json" --output "$evidence" >"$log_file" 2>&1
  "$RUST_RUNNER" verify-fiber-evidence "$ROOT_DIR/fixtures/fiber/$fixture.json" "$evidence"
  jq -e '.schema == "morph.rust_fiber_result.v1" and .runner == "rust" and .status == "passed" and all(.steps[]; .status == "passed" and .assertions > 0)' "$evidence" >/dev/null
  jq -n --arg suite "$suite_id" --arg log "$log_file" --arg evidence "$evidence" \
    --arg runner_sha256 "$(sha256sum "$RUST_RUNNER" | cut -d' ' -f1)" \
    '{suite:$suite,status:"passed",runner:"rust",runner_sha256:$runner_sha256,log:$log,evidence:$evidence}' >"$OUT_DIR/fiber-rust-$label.json"
}

run_external_funding_open_suite() { run_rust_suite "$FIBER_COEXISTENCE_SUITE"; }

run_period_check_expiry_suite() {
  local suite="$FIBER_PERIOD_CHECK_EXPIRY_SUITE"
  start_fiber_stack "$suite" "$LOG_DIR/fiber-stack-${suite//\//_}.log"
  run_rust_suite "$suite"
  stop_fiber_stack
}

run_morph_stateful_on_fiber_ckb() {
  local current_dir="$OUT_DIR/morph-stateful"
  # The runner owns its fresh output directory and never starts/stops the
  # external Fiber chain. Preserve an independent same-genesis observation.
  [ ! -e "$current_dir" ] || fail "current Morph evidence already exists: $current_dir"
  curl -fsS -H 'content-type: application/json' \
    -d '{"id":1,"jsonrpc":"2.0","method":"get_block_hash","params":["0x0"]}' \
    "$FIBER_CKB_RPC_URL" >"$OUT_DIR/fiber-coexistence-genesis.json"
  jq -e '.error == null and (.result | test("^0x[0-9a-f]{64}$"))' \
    "$OUT_DIR/fiber-coexistence-genesis.json" >/dev/null || fail "Fiber genesis observation failed"
  log "running the sole current Morph matrix on Fiber's actual CKB RPC"
  (
    cd "$ROOT_DIR"
    EXTERNAL_RPC_URL="$FIBER_CKB_RPC_URL" \
    CKB_BIN="$CKB_BIN" FIBER_DIR="$FIBER_DIR" \
    MORPH_E2E_DEPLOYER_KEY_FILE="$MORPH_FIBER_DEPLOYER_KEY_FILE" \
    MORPH_E2E_ALICE_KEY_FILE="$MORPH_FIBER_ALICE_KEY_FILE" \
    MORPH_E2E_BOB_KEY_FILE="$MORPH_FIBER_BOB_KEY_FILE" \
    OUT_DIR="$current_dir" \
      scripts/devnet-current-e2e.sh
  ) >"$LOG_DIR/morph-stateful-on-fiber-ckb.log" 2>&1
  jq -e --slurpfile observed "$OUT_DIR/fiber-coexistence-genesis.json" \
    --arg rpc "$FIBER_CKB_RPC_URL" \
    '.rpc_url == $rpc and .genesis_hash == $observed[0].result and .descriptor_version == 5' \
    "$current_dir/evidence.json" >/dev/null || fail "current runner did not use Fiber's exact chain"
  log "current Morph matrix -> $current_dir/scenarios/smoke/matrix.json"
}

run_fiber_restart_regression() {
  local log_file="$LOG_DIR/fiber-external-funding-restart.log"
  local evidence="$OUT_DIR/fiber-external-funding-restart.evidence.json"
  log "running owned-node external-funding restart regression in Rust"
  FIBER_CKB_RPC_URL="$FIBER_CKB_RPC_URL" FIBER_NODE1_RPC_URL="$FIBER_NODE1_RPC_URL" \
  FIBER_NODE2_RPC_URL="$FIBER_NODE2_RPC_URL" FIBER_NODE3_RPC_URL="$FIBER_NODE3_RPC_URL" \
  MORPH_FIBER_EXTERNAL_PRIVATE_KEY_FILE="$MORPH_FIBER_EXTERNAL_PRIVATE_KEY_FILE" \
    "$RUST_RUNNER" fiber-restart --fiber-dir "$FIBER_DIR" --stack-pid "$FIBER_STACK_PID" \
      --output "$evidence" --log "$LOG_DIR/fiber-node1-native-restart.log" >"$log_file" 2>&1
  jq -n --arg log "$log_file" --arg evidence "$evidence" \
    --arg runner_sha256 "$(sha256sum "$RUST_RUNNER" | cut -d' ' -f1)" \
    '{suite:"e2e/external-funding-open/restart",status:"passed",runner:"rust",runner_sha256:$runner_sha256,log:$log,evidence:$evidence}' >"$OUT_DIR/fiber-external-funding-restart.json"
}

run_coexistence_gate() {
  assert_clean_for_production
  start_fiber_stack "$FIBER_COEXISTENCE_SUITE" "$LOG_DIR/fiber-stack-coexistence.log"
  run_morph_stateful_on_fiber_ckb
  if [ "$FIBER_COEXISTENCE_SUITE" = "e2e/external-funding-open" ]; then
    run_external_funding_open_suite
  else
    run_rust_suite "$FIBER_COEXISTENCE_SUITE"
  fi
  run_fiber_restart_regression
  stop_fiber_stack
  run_morph_payment_gateway_fiber_gate
}

run_morph_payment_gateway_fiber_gate() {
  local suite="$FIBER_PAYMENT_GATEWAY_ROUTER_SUITE"
  local label="${suite//\//_}"
  start_fiber_stack "$suite" "$LOG_DIR/fiber-stack-morph-payment-gateway-$label.log"
  run_rust_suite "$suite"
  log "running Morph Payment Gateway x402 and fair-exchange flows over Fiber's three-node route"
  FIBER_CKB_RPC_URL="$FIBER_CKB_RPC_URL" \
  FIBER_NODE1_RPC_URL="$FIBER_NODE1_RPC_URL" \
  FIBER_NODE2_RPC_URL="$FIBER_NODE2_RPC_URL" \
  FIBER_NODE3_RPC_URL="$FIBER_NODE3_RPC_URL" \
  OUT_DIR="$OUT_DIR/morph-payment-gateway-fiber-e2e" \
    "$ROOT_DIR/scripts/morph-payment-gateway-fiber-devnet-e2e.sh" \
    >"$LOG_DIR/morph-payment-gateway-fiber-e2e.log" 2>&1
  stop_fiber_stack
}

run_extended_fiber_suites() {
  local suite
  for suite in $FIBER_RUST_SUITES; do
    if [ "$suite" = "$FIBER_PAYMENT_GATEWAY_ROUTER_SUITE" ] &&
      [ -s "$OUT_DIR/fiber-rust-${suite//\//_}.json" ]; then
      log "Fiber Rust suite $suite already passed as the Morph Payment Gateway routing substrate"
      continue
    fi
    if [ "$suite" = "$FIBER_PERIOD_CHECK_EXPIRY_SUITE" ]; then
      run_period_check_expiry_suite
      continue
    fi
    start_fiber_stack "$suite" "$LOG_DIR/fiber-stack-${suite//\//_}.log"
    run_rust_suite "$suite"
    stop_fiber_stack
  done
  run_fiber_funding_tx_verification_cases
}

run_fiber_funding_tx_verification_cases() {
  local case_name previous_extra_args
  if [ -z "$FIBER_FUNDING_TX_VERIFICATION_CASES" ]; then
    log "Fiber funding-tx verification cases skipped"
    return
  fi

  previous_extra_args="$FIBER_STACK_BUILDER_ARGS"
  for case_name in $FIBER_FUNDING_TX_VERIFICATION_CASES; do
    FIBER_STACK_BUILDER_ARGS="FUNDING_TX_VERIFICATION_CASE=$case_name"
    start_fiber_stack "e2e/funding-tx-verification" "$LOG_DIR/fiber-stack-e2e_funding-tx-verification_$case_name.log"
    run_rust_suite "e2e/funding-tx-verification" "e2e/funding-tx-verification/$case_name"
    stop_fiber_stack
  done
  FIBER_STACK_BUILDER_ARGS="$previous_extra_args"
}

write_acceptance_matrix() {
  local path="$OUT_DIR/acceptance-matrix.json"
  jq -n \
    --arg mode "$MODE" \
    --arg morph_stateful "$OUT_DIR/morph-stateful/scenarios/summary-check.json" \
    --arg fiber_external "$OUT_DIR/fiber-rust-${FIBER_COEXISTENCE_SUITE//\//_}.json" \
    --arg fiber_payment_gateway_router "$OUT_DIR/fiber-rust-${FIBER_PAYMENT_GATEWAY_ROUTER_SUITE//\//_}.json" \
    --arg morph_payment_gateway_result "$OUT_DIR/morph-payment-gateway-fiber-e2e/result.json" \
    --arg morph_payment_gateway_manifest "$OUT_DIR/morph-payment-gateway-fiber-e2e/manifest.json" \
    --arg business_flow_audit "$OUT_DIR/business-flow-audit.json" \
    '{
      schema: "morph.fiber_morph_devnet_acceptance_matrix",
      mode: $mode,
      gates:
        (
          (if $mode == "coexistence" or $mode == "full" then [
            {
              id: "same_ckb_devnet_coexistence",
              required: true,
              evidence: [
                "Fiber three-node devnet started on CKB RPC",
                $morph_stateful,
                $fiber_external
              ]
            },
            {
              id: "morph_channel_factory_matrix",
              required: true,
              evidence: [
                "Current Morph devnet-stateful-assert on the same Fiber CKB RPC",
                "bilateral_shared",
                "bilateral_splice",
                "factory_custody_and_children",
                "watch_service_reorg",
                "maximum_asset_lifecycle"
              ]
            },
            {
              id: "fiber_channel_external_funding",
              required: true,
              evidence: [
                "Rust external-funding-open",
                "required restart regression before submit_signed_funding_tx"
              ]
            },
            {
              id: "morph_payment_gateway_fiber_multihop",
              required: true,
              evidence: [
                $fiber_payment_gateway_router,
                $morph_payment_gateway_result,
                $morph_payment_gateway_manifest,
                "x402 credential settlement and hash-locked fair exchange over Fiber node1 -> node2 -> node3"
              ]
            }
          ] else [] end)
          + (if $mode == "fiber" or $mode == "full" then [
            {
              id: "fiber_security_and_recovery_matrix",
              required: true,
              evidence: [
                "Fiber router-pay, reestablish, force-close, expiry, UDT, watchtower, hold-invoice, and funding-tx verification Rust scenarios",
                "Funding tx verification cases: remove_change, modify_change, fund_from_peer, missing_inputs"
              ]
            }
          ] else [] end)
          + [
            {
              id: "business_flow_and_security_audit",
              required: true,
              evidence: [
                $business_flow_audit,
                "only business flows and security families executed by this mode"
              ]
            }
          ]
        )
    }' >"$path"
  log "acceptance matrix -> $path"
}

write_summary() {
  write_acceptance_matrix
  cat >>"$OUT_DIR/manifest.txt" <<EOF
finished_at_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)
status=passed
EOF
  jq -n \
    --arg manifest "$OUT_DIR/manifest.txt" \
    --arg repo_state "$OUT_DIR/repo-state.json" \
    --arg matrix "$OUT_DIR/acceptance-matrix.json" \
    --arg mode "$MODE" \
    --arg morph_stateful_summary_check "$OUT_DIR/morph-stateful/scenarios/summary-check.json" \
    --arg morph_payment_gateway_fiber_result "$OUT_DIR/morph-payment-gateway-fiber-e2e/result.json" \
    --arg business_flow_audit "$OUT_DIR/business-flow-audit.json" \
    --arg status "passed" \
    '{
      schema:"morph.fiber_morph_devnet_acceptance_summary",
      status:$status,
      mode:$mode,
      manifest:$manifest,
      repo_state:$repo_state,
      acceptance_matrix:$matrix,
      morph_stateful_summary_check:$morph_stateful_summary_check,
      morph_payment_gateway_fiber_result:$morph_payment_gateway_fiber_result,
      business_flow_audit:$business_flow_audit
    }' \
    >"$OUT_DIR/summary.json"
  "$ROOT_DIR/scripts/fiber-morph-devnet-audit.sh" "$OUT_DIR"
  log "summary -> $OUT_DIR/summary.json"
}

preflight() {
  require_tool git
  require_tool cargo
  require_tool jq
  require_tool curl
  require_tool grep
  require_tool sha256sum
  if ! command -v lsof >/dev/null 2>&1 && ! command -v ss >/dev/null 2>&1; then
    fail "missing required TCP listener inspector: install lsof or iproute2/ss"
  fi
  clone_repo_if_missing "$FIBER_DIR" "https://github.com/nervosnetwork/fiber.git"
  clone_repo_if_missing "$CKB_SOURCE_DIR" "https://github.com/nervosnetwork/ckb.git"
  clone_repo_if_missing "$CKB_CLI_SOURCE_DIR" "https://github.com/nervosnetwork/ckb-cli.git"
  [ -f "$FIBER_DIR/Cargo.toml" ] || fail "Fiber checkout missing Cargo.toml: $FIBER_DIR"
  [ -f "$CKB_SOURCE_DIR/Cargo.toml" ] || fail "CKB checkout missing Cargo.toml: $CKB_SOURCE_DIR"
  [ -f "$CKB_CLI_SOURCE_DIR/Cargo.toml" ] || fail "ckb-cli checkout missing Cargo.toml: $CKB_CLI_SOURCE_DIR"
  require_devnet_fixture_key_file "$MORPH_FIBER_DEPLOYER_KEY_FILE" "deployer"
  require_devnet_fixture_key_file "$MORPH_FIBER_ALICE_KEY_FILE" "Alice"
  require_devnet_fixture_key_file "$MORPH_FIBER_BOB_KEY_FILE" "Bob"
  morph_fixture_keys_init || fail "cannot prepare protected public fixture key"
  morph_fixture_key_file MORPH_FIBER_EXTERNAL_PRIVATE_KEY_FILE "$FIBER_DIR/tests/nodes/2/ckb/plain_key" external-funder.key || fail "external key setup failed"
  (cd "$ROOT_DIR" && cargo build --locked -p morph-xtask) >"$LOG_DIR/rust-runner-build.log" 2>&1
  mkdir -p "$OUT_DIR/bin"
  cp "$ROOT_DIR/target/debug/morph-xtask" "$RUST_RUNNER"
  prepare_tool_path
  write_manifest
  write_repo_state
}

case "$MODE" in
  scenario)
    # Iterative development evidence is deliberately not accepted by the clean
    # full/coexistence auditor. It cannot stand in for final qualification.
    preflight
    suite="${FIBER_SCENARIO:-e2e/router-pay}"
    suite_id="$suite"
    if [ "$suite" = e2e/funding-tx-verification ]; then
      case "${FIBER_FUNDING_CASE:-}" in
        remove_change|modify_change|fund_from_peer|missing_inputs) ;;
        *) fail "set FIBER_FUNDING_CASE to one of the four documented mutation cases" ;;
      esac
      FIBER_STACK_BUILDER_ARGS="FUNDING_TX_VERIFICATION_CASE=$FIBER_FUNDING_CASE"
      suite_id="$suite/$FIBER_FUNDING_CASE"
    fi
    start_fiber_stack "$suite" "$LOG_DIR/fiber-stack-scenario.log"
    run_rust_suite "$suite" "$suite_id"
    if [ "${FIBER_SCENARIO_GATEWAY:-0}" = 1 ]; then
      FIBER_CKB_RPC_URL="$FIBER_CKB_RPC_URL" FIBER_NODE1_RPC_URL="$FIBER_NODE1_RPC_URL" \
      FIBER_NODE2_RPC_URL="$FIBER_NODE2_RPC_URL" FIBER_NODE3_RPC_URL="$FIBER_NODE3_RPC_URL" \
      OUT_DIR="$OUT_DIR/morph-payment-gateway-fiber-e2e" "$ROOT_DIR/scripts/morph-payment-gateway-fiber-devnet-e2e.sh" >"$LOG_DIR/morph-payment-gateway-fiber-e2e.log" 2>&1
    fi
    if [ "${FIBER_SCENARIO_RESTART:-0}" = 1 ]; then run_fiber_restart_regression; fi
    log "development scenario passed; dirty-tree evidence is not final qualification: $OUT_DIR"
    ;;
  preflight)
    preflight
    cat >>"$OUT_DIR/manifest.txt" <<EOF
finished_at_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)
status=preflight-passed
EOF
    log "preflight passed; artifacts are in $OUT_DIR"
    ;;
  coexistence)
    preflight
    run_coexistence_gate
    write_summary
    log "coexistence acceptance passed; artifacts are in $OUT_DIR"
    ;;
  fiber)
    preflight
    assert_clean_for_production
    run_extended_fiber_suites
    write_summary
    log "Fiber acceptance passed; artifacts are in $OUT_DIR"
    ;;
  full)
    preflight
    run_coexistence_gate
    run_extended_fiber_suites
    write_summary
    log "full Fiber/Morph acceptance passed; artifacts are in $OUT_DIR"
    ;;
  *)
    fail "unknown mode: $MODE (expected preflight, scenario, coexistence, fiber, full)"
    ;;
esac
