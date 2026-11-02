#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

RPC_URL="${MORPH_CKB_RPC:-http://127.0.0.1:18114}"
OUT_DIR="${OUT_DIR:-target/devnet-smoke/$(date -u +%Y%m%dT%H%M%SZ)}"
LATEST_LINK="${LATEST_LINK:-target/devnet-smoke/latest}"
MINE_BLOCKS="${MINE_BLOCKS:-4}"
SKIP_LOCAL_CHECKS="${MORPH_DEVNET_SMOKE_SKIP_LOCAL_CHECKS:-0}"

mkdir -p "$OUT_DIR"

if ! command -v jq >/dev/null 2>&1; then
  printf 'missing: jq is required by scripts/devnet-smoke.sh\n' >&2
  exit 1
fi

GIT_COMMIT="$(git rev-parse --short HEAD 2>/dev/null || printf 'unknown')"
if [ -n "$(git status --porcelain --untracked-files=no 2>/dev/null)" ]; then
  GIT_DIRTY="true"
else
  GIT_DIRTY="false"
fi

log() {
  printf '[devnet-smoke] %s\n' "$*"
}

run_log() {
  local name="$1"
  shift
  local path="$OUT_DIR/$name.log"
  log "$name -> $path"
  "$@" >"$path" 2>&1
}

run_json() {
  local name="$1"
  shift
  local path="$OUT_DIR/$name.json"
  log "$name -> $path"
  if [ "${1:-}" = "devnet" ]; then
    shift
    cargo run -q -p morph-cli --features devnet -- devnet --devnet-only "$@" --json >"$path"
  else
    cargo run -q -p morph-cli -- "$@" --json >"$path"
  fi
}

run_cli_without_devnet_key_env() {
  if [ "${1:-}" = "devnet" ]; then
    shift
    env -u MORPH_DEVNET_PRIVATE_KEY cargo run -q -p morph-cli --features devnet -- devnet --devnet-only "$@"
  else
    env -u MORPH_DEVNET_PRIVATE_KEY cargo run -q -p morph-cli -- "$@"
  fi
}

cat >"$OUT_DIR/manifest.txt" <<EOF
rpc_url=$RPC_URL
started_at_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)
mine_blocks=$MINE_BLOCKS
git_commit=$GIT_COMMIT
git_dirty=$GIT_DIRTY
EOF

run_log check-devnet-env scripts/check-devnet-env.sh
if [ "$SKIP_LOCAL_CHECKS" = "1" ]; then
  log "local fixture/cargo/testtool checks skipped by MORPH_DEVNET_SMOKE_SKIP_LOCAL_CHECKS=1"
  cat >>"$OUT_DIR/manifest.txt" <<EOF
local_checks=skipped
EOF
else
  run_log validate-fixture cargo run -q -p morph-cli -- validate-fixture
  run_log cargo-test cargo test --workspace
  run_log contract-tests make contract-tests
fi

run_json devnet-check devnet --rpc-url "$RPC_URL" check
run_json devnet-mine devnet --rpc-url "$RPC_URL" mine --blocks "$MINE_BLOCKS"
run_json devnet-tip devnet --rpc-url "$RPC_URL" tip
TIP_NUMBER="$(jq -r '.number_value' "$OUT_DIR/devnet-tip.json")"
run_json devnet-wait-tip devnet --rpc-url "$RPC_URL" wait-tip "$TIP_NUMBER" \
  --timeout-secs 5 \
  --poll-ms 100
run_json deploy-contracts devnet --rpc-url "$RPC_URL" deploy-contracts
run_json supersede-smoke devnet --rpc-url "$RPC_URL" supersede-smoke
run_json finalise-since-negative-smoke devnet --rpc-url "$RPC_URL" finalise-since-negative-smoke
run_json sponsor-policy-negative-smoke devnet --rpc-url "$RPC_URL" sponsor-policy-negative-smoke
run_json sponsor-budget-negative-smoke devnet --rpc-url "$RPC_URL" sponsor-budget-negative-smoke
run_json competing-spend-smoke devnet --rpc-url "$RPC_URL" competing-spend-smoke

MANUAL_CHANNEL_DIR="$OUT_DIR/manual-channel"
mkdir -p "$MANUAL_CHANNEL_DIR"
log "manual-channel-open -> $MANUAL_CHANNEL_DIR/open.json"
cargo run -q -p morph-cli --features devnet -- devnet --devnet-only --rpc-url "$RPC_URL" open-channel \
  --vault-capacity 30000000000 \
  --alice-capacity 18000000000 \
  --bob-capacity 12000000000 \
  --sponsor-capacity 60000000000 \
  --sponsor-min-state-number 3 \
  --sponsor-max-state-number 3 \
  --sponsor-max-fee-per-tx 200000000 \
  --sponsor-max-total-fee 300000000 \
  --json >"$MANUAL_CHANNEL_DIR/open.json"
MANUAL_STATE_OUT_POINT="$(jq -r '.cells[] | select(.role == "state") | .out_point.tx_hash + ":" + (.out_point.index | tostring)' "$MANUAL_CHANNEL_DIR/open.json")"
MANUAL_VAULT_OUT_POINT="$(jq -r '.cells[] | select(.role == "vault") | .out_point.tx_hash + ":" + (.out_point.index | tostring)' "$MANUAL_CHANNEL_DIR/open.json")"
MANUAL_SPONSOR_OUT_POINT="$(jq -r '.cells[] | select(.role == "sponsor") | .out_point.tx_hash + ":" + (.out_point.index | tostring)' "$MANUAL_CHANNEL_DIR/open.json")"
MANUAL_CHANNEL_ID="$(jq -r '.channel_id' "$MANUAL_CHANNEL_DIR/open.json")"

log "manual-channel-save-package -> $MANUAL_CHANNEL_DIR/package.json"
cargo run -q -p morph-cli --features devnet -- devnet --devnet-only --rpc-url "$RPC_URL" save-state-package \
  --state-out-point "$MANUAL_STATE_OUT_POINT" \
  --state-number 3 \
  --store-dir "$MANUAL_CHANNEL_DIR/packages" \
  --json >"$MANUAL_CHANNEL_DIR/package.json"
log "manual-channel-list-packages -> $MANUAL_CHANNEL_DIR/list-packages.json"
cargo run -q -p morph-cli --features devnet -- devnet --devnet-only --rpc-url "$RPC_URL" list-state-packages \
  --channel-id "$MANUAL_CHANNEL_ID" \
  --store-dir "$MANUAL_CHANNEL_DIR/packages" \
  --json >"$MANUAL_CHANNEL_DIR/list-packages.json"
log "manual-channel-latest-package -> $MANUAL_CHANNEL_DIR/latest-package.json"
cargo run -q -p morph-cli --features devnet -- devnet --devnet-only --rpc-url "$RPC_URL" latest-state-package \
  --channel-id "$MANUAL_CHANNEL_ID" \
  --store-dir "$MANUAL_CHANNEL_DIR/packages" \
  --json >"$MANUAL_CHANNEL_DIR/latest-package.json"
log "manual-channel-publish-latest -> $MANUAL_CHANNEL_DIR/publish-latest.json"
cargo run -q -p morph-cli --features devnet -- devnet --devnet-only --rpc-url "$RPC_URL" publish-latest-package \
  --state-out-point "$MANUAL_STATE_OUT_POINT" \
  --sponsor-out-point "$MANUAL_SPONSOR_OUT_POINT" \
  --channel-id "$MANUAL_CHANNEL_ID" \
  --store-dir "$MANUAL_CHANNEL_DIR/packages" \
  --json >"$MANUAL_CHANNEL_DIR/publish-latest.json"
MANUAL_PUBLISHED_STATE_OUT_POINT="$(jq -r '.publication.state_out_point.tx_hash + ":" + (.publication.state_out_point.index | tostring)' "$MANUAL_CHANNEL_DIR/publish-latest.json")"
log "manual-channel-finalise -> $MANUAL_CHANNEL_DIR/finalise.json"
cargo run -q -p morph-cli --features devnet -- devnet --devnet-only --rpc-url "$RPC_URL" finalise-channel \
  --state-out-point "$MANUAL_PUBLISHED_STATE_OUT_POINT" \
  --vault-out-point "$MANUAL_VAULT_OUT_POINT" \
  --alice-capacity 18000000000 \
  --bob-capacity 12000000000 \
  --json >"$MANUAL_CHANNEL_DIR/finalise.json"

MANUAL_SPONSOR_DIR="$OUT_DIR/manual-sponsor"
mkdir -p "$MANUAL_SPONSOR_DIR"
log "manual-sponsor-open -> $MANUAL_SPONSOR_DIR/open.json"
cargo run -q -p morph-cli --features devnet -- devnet --devnet-only --rpc-url "$RPC_URL" open-channel \
  --vault-capacity 22000000000 \
  --alice-capacity 11000000000 \
  --bob-capacity 11000000000 \
  --sponsor-min-state-number 0 \
  --sponsor-max-state-number 0 \
  --json >"$MANUAL_SPONSOR_DIR/open.json"
SPONSOR_STATE_OUT_POINT="$(jq -r '.cells[] | select(.role == "state") | .out_point.tx_hash + ":" + (.out_point.index | tostring)' "$MANUAL_SPONSOR_DIR/open.json")"
SPONSOR_VAULT_OUT_POINT="$(jq -r '.cells[] | select(.role == "vault") | .out_point.tx_hash + ":" + (.out_point.index | tostring)' "$MANUAL_SPONSOR_DIR/open.json")"
log "manual-sponsor-fund -> $MANUAL_SPONSOR_DIR/fund.json"
cargo run -q -p morph-cli --features devnet -- devnet --devnet-only --rpc-url "$RPC_URL" fund-sponsor \
  --state-out-point "$SPONSOR_STATE_OUT_POINT" \
  --sponsor-capacity 60000000000 \
  --sponsor-min-state-number 5 \
  --sponsor-max-state-number 5 \
  --sponsor-max-fee-per-tx 200000000 \
  --sponsor-max-total-fee 200000000 \
  --json >"$MANUAL_SPONSOR_DIR/fund.json"
SPONSOR_NEW_OUT_POINT="$(jq -r '.sponsor_out_point.tx_hash + ":" + (.sponsor_out_point.index | tostring)' "$MANUAL_SPONSOR_DIR/fund.json")"
log "manual-sponsor-publish -> $MANUAL_SPONSOR_DIR/publish.json"
cargo run -q -p morph-cli --features devnet -- devnet --devnet-only --rpc-url "$RPC_URL" publish-state \
  --state-out-point "$SPONSOR_STATE_OUT_POINT" \
  --sponsor-out-point "$SPONSOR_NEW_OUT_POINT" \
  --state-number 5 \
  --json >"$MANUAL_SPONSOR_DIR/publish.json"
SPONSOR_PUBLISHED_STATE_OUT_POINT="$(jq -r '.state_out_point.tx_hash + ":" + (.state_out_point.index | tostring)' "$MANUAL_SPONSOR_DIR/publish.json")"
log "manual-sponsor-finalise -> $MANUAL_SPONSOR_DIR/finalise.json"
cargo run -q -p morph-cli --features devnet -- devnet --devnet-only --rpc-url "$RPC_URL" finalise-channel \
  --state-out-point "$SPONSOR_PUBLISHED_STATE_OUT_POINT" \
  --vault-out-point "$SPONSOR_VAULT_OUT_POINT" \
  --alice-capacity 11000000000 \
  --bob-capacity 11000000000 \
  --json >"$MANUAL_SPONSOR_DIR/finalise.json"

run_json xudt-smoke devnet --rpc-url "$RPC_URL" xudt-smoke
run_json xudt-one-sided-smoke devnet --rpc-url "$RPC_URL" xudt-smoke \
  --alice-xudt-amount 0 \
  --bob-xudt-amount 1000000
run_json xudt-negative-smoke devnet --rpc-url "$RPC_URL" xudt-negative-smoke
mkdir -p "$OUT_DIR/splice-packages"
run_json splice-in-smoke devnet --rpc-url "$RPC_URL" splice-in-smoke \
  --store-dir "$OUT_DIR/splice-packages"
run_json splice-out-smoke devnet --rpc-url "$RPC_URL" splice-out-smoke \
  --store-dir "$OUT_DIR/splice-packages"
run_json splice-in-asymmetric-smoke devnet --rpc-url "$RPC_URL" splice-in-smoke \
  --vault-capacity 30000000000 \
  --splice-amount 3000000000 \
  --alice-capacity 18000000000 \
  --bob-capacity 12000000000 \
  --store-dir "$OUT_DIR/splice-packages"
run_json splice-out-asymmetric-smoke devnet --rpc-url "$RPC_URL" splice-out-smoke \
  --vault-capacity 30000000000 \
  --splice-amount 7000000000 \
  --alice-capacity 18000000000 \
  --bob-capacity 12000000000 \
  --store-dir "$OUT_DIR/splice-packages"
run_json xudt-splice-in-smoke devnet --rpc-url "$RPC_URL" xudt-splice-in-smoke \
  --store-dir "$OUT_DIR/splice-packages"
run_json xudt-splice-out-smoke devnet --rpc-url "$RPC_URL" xudt-splice-out-smoke \
  --store-dir "$OUT_DIR/splice-packages"
run_json xudt-splice-in-one-sided-smoke devnet --rpc-url "$RPC_URL" xudt-splice-in-smoke \
  --alice-xudt-amount 0 \
  --bob-xudt-amount 1000000 \
  --store-dir "$OUT_DIR/splice-packages"
run_json xudt-splice-out-one-sided-smoke devnet --rpc-url "$RPC_URL" xudt-splice-out-smoke \
  --alice-xudt-amount 0 \
  --bob-xudt-amount 1000000 \
  --splice-xudt-amount 100000 \
  --store-dir "$OUT_DIR/splice-packages"
run_json splice-negative-smoke devnet --rpc-url "$RPC_URL" splice-negative-smoke \
  --store-dir "$OUT_DIR/splice-negative-packages"
mkdir -p "$OUT_DIR/factory-reduced-rights-packages"
run_json factory-smoke devnet --rpc-url "$RPC_URL" factory-smoke \
  --store-dir "$OUT_DIR/factory-state-packages"
run_json factory-reduced-rights-smoke devnet --rpc-url "$RPC_URL" factory-reduced-rights-smoke \
  --store-dir "$OUT_DIR/factory-reduced-rights-packages"
FACTORY_REDUCED_RIGHTS_PACKAGE_PATH="$(jq -r '.package.path' "$OUT_DIR/factory-reduced-rights-smoke.json")"
run_json factory-reduced-rights-package-check validate-factory-reduced-rights-package \
  "$FACTORY_REDUCED_RIGHTS_PACKAGE_PATH"
run_json factory-reduced-rights-tight-smoke devnet --rpc-url "$RPC_URL" factory-reduced-rights-smoke \
  --touched-after-balance 1 \
  --store-dir "$OUT_DIR/factory-reduced-rights-packages"

mkdir -p "$OUT_DIR/factory-merkle-update-packages"
run_json factory-merkle-update-smoke devnet --rpc-url "$RPC_URL" factory-merkle-update-smoke \
  --store-dir "$OUT_DIR/factory-merkle-update-packages"
run_json factory-merkle-update-tight-smoke devnet --rpc-url "$RPC_URL" factory-merkle-update-smoke \
  --touched-after-balance 1 \
  --store-dir "$OUT_DIR/factory-merkle-update-packages"

run_json factory-reduced-exit-smoke devnet --rpc-url "$RPC_URL" factory-reduced-exit-smoke
run_json factory-reduced-exit-asymmetric-smoke devnet --rpc-url "$RPC_URL" factory-reduced-exit-smoke \
  --child-vault-capacity 24000000000 \
  --alice-capacity 15000000000 \
  --bob-capacity 9000000000
run_json factory-reduced-xudt-exit-smoke devnet --rpc-url "$RPC_URL" factory-reduced-xudt-exit-smoke \
  --factory-vault-xudt-surplus 100000
run_json factory-reduced-xudt-exit-full-smoke devnet --rpc-url "$RPC_URL" factory-reduced-xudt-exit-smoke
run_json factory-reduced-xudt-exit-one-sided-smoke devnet --rpc-url "$RPC_URL" factory-reduced-xudt-exit-smoke \
  --alice-xudt-amount 0 \
  --bob-xudt-amount 1000000
run_json factory-reduced-xudt-negative-exit-smoke devnet --rpc-url "$RPC_URL" factory-reduced-xudt-negative-exit-smoke
mkdir -p "$OUT_DIR/factory-splice-packages"
run_json factory-splice-in-smoke devnet --rpc-url "$RPC_URL" factory-splice-in-smoke \
  --store-dir "$OUT_DIR/factory-splice-packages"
run_json factory-splice-out-smoke devnet --rpc-url "$RPC_URL" factory-splice-out-smoke \
  --store-dir "$OUT_DIR/factory-splice-packages"
run_json factory-splice-in-asymmetric-smoke devnet --rpc-url "$RPC_URL" factory-splice-in-smoke \
  --splice-amount 3000000000 \
  --child-vault-capacity 24000000000 \
  --alice-capacity 15000000000 \
  --bob-capacity 9000000000 \
  --store-dir "$OUT_DIR/factory-splice-packages"
run_json factory-splice-out-asymmetric-smoke devnet --rpc-url "$RPC_URL" factory-splice-out-smoke \
  --splice-amount 7000000000 \
  --child-vault-capacity 24000000000 \
  --alice-capacity 15000000000 \
  --bob-capacity 9000000000 \
  --store-dir "$OUT_DIR/factory-splice-packages"
run_json factory-reduced-splice-in-smoke devnet --rpc-url "$RPC_URL" factory-reduced-splice-in-smoke \
  --store-dir "$OUT_DIR/factory-splice-packages"
run_json factory-reduced-splice-out-smoke devnet --rpc-url "$RPC_URL" factory-reduced-splice-out-smoke \
  --store-dir "$OUT_DIR/factory-splice-packages"
run_json factory-reduced-splice-in-asymmetric-smoke devnet --rpc-url "$RPC_URL" factory-reduced-splice-in-smoke \
  --splice-amount 3000000000 \
  --child-vault-capacity 24000000000 \
  --alice-capacity 15000000000 \
  --bob-capacity 9000000000 \
  --store-dir "$OUT_DIR/factory-splice-packages"
run_json factory-reduced-splice-out-asymmetric-smoke devnet --rpc-url "$RPC_URL" factory-reduced-splice-out-smoke \
  --splice-amount 7000000000 \
  --child-vault-capacity 24000000000 \
  --alice-capacity 15000000000 \
  --bob-capacity 9000000000 \
  --store-dir "$OUT_DIR/factory-splice-packages"
run_json factory-reduced-xudt-splice-in-smoke devnet --rpc-url "$RPC_URL" factory-reduced-xudt-splice-in-smoke \
  --store-dir "$OUT_DIR/factory-splice-packages"
run_json factory-reduced-xudt-splice-out-smoke devnet --rpc-url "$RPC_URL" factory-reduced-xudt-splice-out-smoke \
  --store-dir "$OUT_DIR/factory-splice-packages"
run_json factory-reduced-xudt-splice-in-one-sided-smoke devnet --rpc-url "$RPC_URL" factory-reduced-xudt-splice-in-smoke \
  --alice-xudt-amount 0 \
  --bob-xudt-amount 1000000 \
  --store-dir "$OUT_DIR/factory-splice-packages"
run_json factory-reduced-xudt-splice-out-one-sided-smoke devnet --rpc-url "$RPC_URL" factory-reduced-xudt-splice-out-smoke \
  --alice-xudt-amount 0 \
  --bob-xudt-amount 1000000 \
  --splice-xudt-amount 100000 \
  --store-dir "$OUT_DIR/factory-splice-packages"
run_json factory-xudt-splice-in-smoke devnet --rpc-url "$RPC_URL" factory-xudt-splice-in-smoke \
  --store-dir "$OUT_DIR/factory-splice-packages"
run_json factory-xudt-splice-out-smoke devnet --rpc-url "$RPC_URL" factory-xudt-splice-out-smoke \
  --store-dir "$OUT_DIR/factory-splice-packages"
run_json factory-xudt-splice-in-one-sided-smoke devnet --rpc-url "$RPC_URL" factory-xudt-splice-in-smoke \
  --alice-xudt-amount 0 \
  --bob-xudt-amount 1000000 \
  --store-dir "$OUT_DIR/factory-splice-packages"
run_json factory-xudt-splice-out-one-sided-smoke devnet --rpc-url "$RPC_URL" factory-xudt-splice-out-smoke \
  --alice-xudt-amount 0 \
  --bob-xudt-amount 1000000 \
  --splice-xudt-amount 100000 \
  --store-dir "$OUT_DIR/factory-splice-packages"

FACTORY_DIR="$OUT_DIR/factory"
mkdir -p "$FACTORY_DIR"
log "factory-open -> $FACTORY_DIR/open.json"
cargo run -q -p morph-cli --features devnet -- devnet --devnet-only --rpc-url "$RPC_URL" open-factory --json >"$FACTORY_DIR/open.json"
FACTORY_OUT_POINT="$(jq -r '.cells[] | select(.role == "factory") | .out_point.tx_hash + ":" + (.out_point.index | tostring)' "$FACTORY_DIR/open.json")"
FACTORY_VAULT_OUT_POINT="$(jq -r '.cells[] | select(.role == "factory-vault") | .out_point.tx_hash + ":" + (.out_point.index | tostring)' "$FACTORY_DIR/open.json")"
FACTORY_ID="$(jq -r '.factory_id' "$FACTORY_DIR/open.json")"

log "factory-save-package -> $FACTORY_DIR/package.json"
cargo run -q -p morph-cli --features devnet -- devnet --devnet-only --rpc-url "$RPC_URL" save-factory-state-package \
  --factory-out-point "$FACTORY_OUT_POINT" \
  --store-dir "$FACTORY_DIR/packages" \
  --json >"$FACTORY_DIR/package.json"
FACTORY_PACKAGE_PATH="$(jq -r '.path' "$FACTORY_DIR/package.json")"

log "factory-latest-package -> $FACTORY_DIR/latest-package.json"
cargo run -q -p morph-cli --features devnet -- devnet --devnet-only --rpc-url "$RPC_URL" latest-factory-state-package \
  --factory-id "$FACTORY_ID" \
  --store-dir "$FACTORY_DIR/packages" \
  --json >"$FACTORY_DIR/latest-package.json"
log "factory-list-packages -> $FACTORY_DIR/list-packages.json"
cargo run -q -p morph-cli --features devnet -- devnet --devnet-only --rpc-url "$RPC_URL" list-factory-state-packages \
  --factory-id "$FACTORY_ID" \
  --store-dir "$FACTORY_DIR/packages" \
  --json >"$FACTORY_DIR/list-packages.json"

log "factory-update -> $FACTORY_DIR/update.json"
cargo run -q -p morph-cli --features devnet -- devnet --devnet-only --rpc-url "$RPC_URL" update-factory \
  --factory-out-point "$FACTORY_OUT_POINT" \
  --factory-state-package "$FACTORY_PACKAGE_PATH" \
  --json >"$FACTORY_DIR/update.json"
FACTORY_OUT_POINT_AFTER_UPDATE="$(jq -r '.factory_out_point.tx_hash + ":" + (.factory_out_point.index | tostring)' "$FACTORY_DIR/update.json")"

log "factory-exit-channel -> $FACTORY_DIR/exit-channel.json"
cargo run -q -p morph-cli --features devnet -- devnet --devnet-only --rpc-url "$RPC_URL" factory-exit-channel \
  --factory-out-point "$FACTORY_OUT_POINT_AFTER_UPDATE" \
  --factory-vault-out-point "$FACTORY_VAULT_OUT_POINT" \
  --json >"$FACTORY_DIR/exit-channel.json"
log "factory-local-exit-package -> $FACTORY_DIR/local-exit-package.json"
jq '.local_exit_package' "$FACTORY_DIR/exit-channel.json" >"$FACTORY_DIR/local-exit-package.json"
log "factory-local-exit-package-check -> $FACTORY_DIR/local-exit-package-check.json"
cargo run -q -p morph-cli -- validate-factory-local-exit-package \
  "$FACTORY_DIR/local-exit-package.json" \
  --json >"$FACTORY_DIR/local-exit-package-check.json"
FACTORY_CHILD_STATE_OUT_POINT="$(jq -r '.state_out_point.tx_hash + ":" + (.state_out_point.index | tostring)' "$FACTORY_DIR/exit-channel.json")"
FACTORY_CHILD_VAULT_OUT_POINT="$(jq -r '.vault_out_point.tx_hash + ":" + (.vault_out_point.index | tostring)' "$FACTORY_DIR/exit-channel.json")"
FACTORY_CHILD_SPONSOR_OUT_POINT="$(jq -r '.sponsor_out_point.tx_hash + ":" + (.sponsor_out_point.index | tostring)' "$FACTORY_DIR/exit-channel.json")"

log "factory-child-publish -> $FACTORY_DIR/child-publish.json"
cargo run -q -p morph-cli --features devnet -- devnet --devnet-only --rpc-url "$RPC_URL" publish-state \
  --state-out-point "$FACTORY_CHILD_STATE_OUT_POINT" \
  --sponsor-out-point "$FACTORY_CHILD_SPONSOR_OUT_POINT" \
  --json >"$FACTORY_DIR/child-publish.json"
FACTORY_CHILD_PUBLISHED_STATE_OUT_POINT="$(jq -r '.state_out_point.tx_hash + ":" + (.state_out_point.index | tostring)' "$FACTORY_DIR/child-publish.json")"

log "factory-child-finalise -> $FACTORY_DIR/child-finalise.json"
cargo run -q -p morph-cli --features devnet -- devnet --devnet-only --rpc-url "$RPC_URL" finalise-channel \
  --state-out-point "$FACTORY_CHILD_PUBLISHED_STATE_OUT_POINT" \
  --vault-out-point "$FACTORY_CHILD_VAULT_OUT_POINT" \
  --json >"$FACTORY_DIR/child-finalise.json"

FACTORY_XUDT_DIR="$OUT_DIR/factory-xudt"
mkdir -p "$FACTORY_XUDT_DIR"
log "factory-xudt-smoke -> $FACTORY_XUDT_DIR/smoke.json"
cargo run -q -p morph-cli --features devnet -- devnet --devnet-only --rpc-url "$RPC_URL" factory-xudt-smoke \
  --store-dir "$FACTORY_XUDT_DIR/packages" \
  --json >"$FACTORY_XUDT_DIR/smoke.json"
log "factory-xudt-local-exit-package -> $FACTORY_XUDT_DIR/local-exit-package.json"
jq '.exit.local_exit_package' "$FACTORY_XUDT_DIR/smoke.json" >"$FACTORY_XUDT_DIR/local-exit-package.json"
log "factory-xudt-local-exit-package-check -> $FACTORY_XUDT_DIR/local-exit-package-check.json"
cargo run -q -p morph-cli -- validate-factory-local-exit-package \
  "$FACTORY_XUDT_DIR/local-exit-package.json" \
  --json >"$FACTORY_XUDT_DIR/local-exit-package-check.json"

FACTORY_XUDT_ONE_SIDED_DIR="$OUT_DIR/factory-xudt-one-sided"
mkdir -p "$FACTORY_XUDT_ONE_SIDED_DIR"
log "factory-xudt-one-sided-smoke -> $FACTORY_XUDT_ONE_SIDED_DIR/smoke.json"
cargo run -q -p morph-cli --features devnet -- devnet --devnet-only --rpc-url "$RPC_URL" factory-xudt-smoke \
  --alice-xudt-amount 0 \
  --bob-xudt-amount 1000000 \
  --store-dir "$FACTORY_XUDT_ONE_SIDED_DIR/packages" \
  --json >"$FACTORY_XUDT_ONE_SIDED_DIR/smoke.json"
log "factory-xudt-one-sided-local-exit-package -> $FACTORY_XUDT_ONE_SIDED_DIR/local-exit-package.json"
jq '.exit.local_exit_package' "$FACTORY_XUDT_ONE_SIDED_DIR/smoke.json" >"$FACTORY_XUDT_ONE_SIDED_DIR/local-exit-package.json"
log "factory-xudt-one-sided-local-exit-package-check -> $FACTORY_XUDT_ONE_SIDED_DIR/local-exit-package-check.json"
cargo run -q -p morph-cli -- validate-factory-local-exit-package \
  "$FACTORY_XUDT_ONE_SIDED_DIR/local-exit-package.json" \
  --json >"$FACTORY_XUDT_ONE_SIDED_DIR/local-exit-package-check.json"

FACTORY_XUDT_NEGATIVE_DIR="$OUT_DIR/factory-xudt-negative"
mkdir -p "$FACTORY_XUDT_NEGATIVE_DIR"
log "factory-xudt-negative-smoke -> $FACTORY_XUDT_NEGATIVE_DIR/smoke.json"
cargo run -q -p morph-cli --features devnet -- devnet --devnet-only --rpc-url "$RPC_URL" factory-xudt-negative-smoke \
  --store-dir "$FACTORY_XUDT_NEGATIVE_DIR/packages" \
  --json >"$FACTORY_XUDT_NEGATIVE_DIR/smoke.json"
log "factory-xudt-negative-local-exit-package -> $FACTORY_XUDT_NEGATIVE_DIR/local-exit-package.json"
jq '.exit.local_exit_package' "$FACTORY_XUDT_NEGATIVE_DIR/smoke.json" >"$FACTORY_XUDT_NEGATIVE_DIR/local-exit-package.json"
log "factory-xudt-negative-local-exit-package-check -> $FACTORY_XUDT_NEGATIVE_DIR/local-exit-package-check.json"
cargo run -q -p morph-cli -- validate-factory-local-exit-package \
  "$FACTORY_XUDT_NEGATIVE_DIR/local-exit-package.json" \
  --json >"$FACTORY_XUDT_NEGATIVE_DIR/local-exit-package-check.json"

WATCH_DIR="$OUT_DIR/watch-auto-sponsor"
mkdir -p "$WATCH_DIR"
WATCH_DIR_ABS="$(cd "$WATCH_DIR" && pwd)"
WATCH_KEY_FILE="$(mktemp "${TMPDIR:-/tmp}/morph-watchtower-key.XXXXXX")"
trap 'rm -f "$WATCH_KEY_FILE"' EXIT
printf '%s\n' "${MORPH_DEVNET_PRIVATE_KEY:-0xd00c06bfd800d27397002dca6fb0993d5ba6399b4238b2f29ee9deb97593d2bc}" >"$WATCH_KEY_FILE"
chmod 600 "$WATCH_KEY_FILE" 2>/dev/null || true
log "watch-auto-sponsor-open -> $WATCH_DIR/open.json"
cargo run -q -p morph-cli --features devnet -- devnet --devnet-only --rpc-url "$RPC_URL" open-channel --json >"$WATCH_DIR/open.json"
STATE_OUT_POINT="$(jq -r '.cells[] | select(.role == "state") | .out_point.tx_hash + ":" + (.out_point.index | tostring)' "$WATCH_DIR/open.json")"
VAULT_OUT_POINT="$(jq -r '.cells[] | select(.role == "vault") | .out_point.tx_hash + ":" + (.out_point.index | tostring)' "$WATCH_DIR/open.json")"
CHANNEL_ID="$(jq -r '.channel_id' "$WATCH_DIR/open.json")"
OPEN_BLOCK="$(jq -r '.activation_block_number' "$WATCH_DIR/open.json")"

log "watch-auto-sponsor-package -> $WATCH_DIR/package.json"
cargo run -q -p morph-cli --features devnet -- devnet --devnet-only --rpc-url "$RPC_URL" save-state-package \
  --state-out-point "$STATE_OUT_POINT" \
  --state-number 2 \
  --store-dir "$WATCH_DIR/packages" \
  --json >"$WATCH_DIR/package.json"

log "watch-auto-sponsor-policy -> $WATCH_DIR/watch-policy.json"
cargo run -q -p morph-cli -- print-watch-policy-fixture >"$WATCH_DIR/watch-policy.json"

log "watch-auto-sponsor-config -> $WATCH_DIR/watch-config.json"
jq -n \
  --arg channel_id "$CHANNEL_ID" \
  --argjson from_block "$OPEN_BLOCK" \
  --arg store_dir "$WATCH_DIR_ABS/packages" \
  --arg watch_policy "$WATCH_DIR_ABS/watch-policy.json" \
  --arg alert_file "$WATCH_DIR_ABS/watch-alerts.jsonl" \
  '{
    schema: "morph.watchtower_config",
    operator_id: "watchtower-local",
    defaults: {
      store_dir: $store_dir,
      watch_policy: $watch_policy,
      alert_file: $alert_file,
      detection_depth: 3,
      timeout_secs: 30,
      poll_ms: 250,
      fee: 100000000,
      mine_blocks: 4,
      auto_fund_sponsor: true,
      auto_sponsor_capacity: 50000000000
    },
    channels: [{
      channel_id: $channel_id,
      from_block: $from_block
    }]
  }' >"$WATCH_DIR/watch-config.json"

log "watch-auto-sponsor-config-check -> $WATCH_DIR/watch-config-check.json"
cargo run -q -p morph-cli -- validate-watch-config \
  "$WATCH_DIR/watch-config.json" \
  --json >"$WATCH_DIR/watch-config-check.json"

touch "$WATCH_DIR/service.stop"
log "watch-auto-sponsor-service-stop -> $WATCH_DIR/service.json"
run_cli_without_devnet_key_env devnet --rpc-url "$RPC_URL" watch-config-service \
  --config "$WATCH_DIR/watch-config.json" \
  --private-key-file "$WATCH_KEY_FILE" \
  --stop-file "$WATCH_DIR/service.stop" \
  --health-file "$WATCH_DIR/service-health.json" \
  --json >"$WATCH_DIR/service.json"

log "watch-auto-sponsor-depth -> $WATCH_DIR/depth.json"
cargo run -q -p morph-cli --features devnet -- devnet --devnet-only --rpc-url "$RPC_URL" mine \
  --blocks 5 \
  --json >"$WATCH_DIR/depth.json"

log "watch-auto-sponsor-publish -> $WATCH_DIR/watch.json"
run_cli_without_devnet_key_env devnet --rpc-url "$RPC_URL" watch-config-once \
  --config "$WATCH_DIR/watch-config.json" \
  --private-key-file "$WATCH_KEY_FILE" \
  --json >"$WATCH_DIR/watch.json"

PUBLISHED_STATE_OUT_POINT="$(jq -r '.channels[0].report.publication.state_out_point.tx_hash + ":" + (.channels[0].report.publication.state_out_point.index | tostring)' "$WATCH_DIR/watch.json")"
log "watch-auto-sponsor-finalise -> $WATCH_DIR/finalise.json"
cargo run -q -p morph-cli --features devnet -- devnet --devnet-only --rpc-url "$RPC_URL" finalise-channel \
  --state-out-point "$PUBLISHED_STATE_OUT_POINT" \
  --vault-out-point "$VAULT_OUT_POINT" \
  --json >"$WATCH_DIR/finalise.json"

WATCH_DIRECT_DIR="$OUT_DIR/watch-direct-sponsor"
mkdir -p "$WATCH_DIRECT_DIR"
log "watch-direct-sponsor-open -> $WATCH_DIRECT_DIR/open.json"
cargo run -q -p morph-cli --features devnet -- devnet --devnet-only --rpc-url "$RPC_URL" open-channel \
  --sponsor-min-state-number 4 \
  --sponsor-max-state-number 4 \
  --sponsor-max-fee-per-tx 200000000 \
  --sponsor-max-total-fee 200000000 \
  --json >"$WATCH_DIRECT_DIR/open.json"
WATCH_DIRECT_STATE_OUT_POINT="$(jq -r '.cells[] | select(.role == "state") | .out_point.tx_hash + ":" + (.out_point.index | tostring)' "$WATCH_DIRECT_DIR/open.json")"
WATCH_DIRECT_VAULT_OUT_POINT="$(jq -r '.cells[] | select(.role == "vault") | .out_point.tx_hash + ":" + (.out_point.index | tostring)' "$WATCH_DIRECT_DIR/open.json")"
WATCH_DIRECT_SPONSOR_OUT_POINT="$(jq -r '.cells[] | select(.role == "sponsor") | .out_point.tx_hash + ":" + (.out_point.index | tostring)' "$WATCH_DIRECT_DIR/open.json")"
WATCH_DIRECT_CHANNEL_ID="$(jq -r '.channel_id' "$WATCH_DIRECT_DIR/open.json")"
WATCH_DIRECT_OPEN_BLOCK="$(jq -r '.activation_block_number' "$WATCH_DIRECT_DIR/open.json")"
log "watch-direct-sponsor-package -> $WATCH_DIRECT_DIR/package.json"
cargo run -q -p morph-cli --features devnet -- devnet --devnet-only --rpc-url "$RPC_URL" save-state-package \
  --state-out-point "$WATCH_DIRECT_STATE_OUT_POINT" \
  --state-number 4 \
  --store-dir "$WATCH_DIRECT_DIR/packages" \
  --json >"$WATCH_DIRECT_DIR/package.json"
log "watch-direct-sponsor-watch -> $WATCH_DIRECT_DIR/watch.json"
run_cli_without_devnet_key_env devnet --rpc-url "$RPC_URL" watch-latest-package \
  --channel-id "$WATCH_DIRECT_CHANNEL_ID" \
  --from-block "$WATCH_DIRECT_OPEN_BLOCK" \
  --store-dir "$WATCH_DIRECT_DIR/packages" \
  --sponsor-out-point "$WATCH_DIRECT_SPONSOR_OUT_POINT" \
  --private-key-file "$WATCH_KEY_FILE" \
  --ignore-cursor \
  --detection-depth 1 \
  --timeout-secs 5 \
  --poll-ms 100 \
  --alert-file "$WATCH_DIRECT_DIR/watch-alerts.jsonl" \
  --json >"$WATCH_DIRECT_DIR/watch.json"
WATCH_DIRECT_PUBLISHED_STATE_OUT_POINT="$(jq -r '.publication.state_out_point.tx_hash + ":" + (.publication.state_out_point.index | tostring)' "$WATCH_DIRECT_DIR/watch.json")"
log "watch-direct-sponsor-finalise -> $WATCH_DIRECT_DIR/finalise.json"
cargo run -q -p morph-cli --features devnet -- devnet --devnet-only --rpc-url "$RPC_URL" finalise-channel \
  --state-out-point "$WATCH_DIRECT_PUBLISHED_STATE_OUT_POINT" \
  --vault-out-point "$WATCH_DIRECT_VAULT_OUT_POINT" \
  --json >"$WATCH_DIRECT_DIR/finalise.json"

WATCH_LOOP_DIR="$OUT_DIR/watch-config-loop"
mkdir -p "$WATCH_LOOP_DIR"
WATCH_LOOP_DIR_ABS="$(cd "$WATCH_LOOP_DIR" && pwd)"
log "watch-config-loop-open -> $WATCH_LOOP_DIR/open.json"
cargo run -q -p morph-cli --features devnet -- devnet --devnet-only --rpc-url "$RPC_URL" open-channel --json >"$WATCH_LOOP_DIR/open.json"
WATCH_LOOP_STATE_OUT_POINT="$(jq -r '.cells[] | select(.role == "state") | .out_point.tx_hash + ":" + (.out_point.index | tostring)' "$WATCH_LOOP_DIR/open.json")"
WATCH_LOOP_VAULT_OUT_POINT="$(jq -r '.cells[] | select(.role == "vault") | .out_point.tx_hash + ":" + (.out_point.index | tostring)' "$WATCH_LOOP_DIR/open.json")"
WATCH_LOOP_CHANNEL_ID="$(jq -r '.channel_id' "$WATCH_LOOP_DIR/open.json")"
WATCH_LOOP_OPEN_BLOCK="$(jq -r '.activation_block_number' "$WATCH_LOOP_DIR/open.json")"
log "watch-config-loop-package -> $WATCH_LOOP_DIR/package.json"
cargo run -q -p morph-cli --features devnet -- devnet --devnet-only --rpc-url "$RPC_URL" save-state-package \
  --state-out-point "$WATCH_LOOP_STATE_OUT_POINT" \
  --state-number 2 \
  --store-dir "$WATCH_LOOP_DIR/packages" \
  --json >"$WATCH_LOOP_DIR/package.json"
log "watch-config-loop-config -> $WATCH_LOOP_DIR/watch-config.json"
jq -n \
  --arg channel_id "$WATCH_LOOP_CHANNEL_ID" \
  --argjson from_block "$WATCH_LOOP_OPEN_BLOCK" \
  --arg store_dir "$WATCH_LOOP_DIR_ABS/packages" \
  --arg alert_file "$WATCH_LOOP_DIR_ABS/watch-alerts.jsonl" \
  '{
    schema: "morph.watchtower_config",
    operator_id: "watchtower-local",
    defaults: {
      store_dir: $store_dir,
      alert_file: $alert_file,
      detection_depth: 1,
      timeout_secs: 5,
      poll_ms: 100,
      fee: 100000000,
      mine_blocks: 4,
      auto_fund_sponsor: true,
      auto_sponsor_capacity: 50000000000
    },
    channels: [{
      channel_id: $channel_id,
      from_block: $from_block
    }]
  }' >"$WATCH_LOOP_DIR/watch-config.json"
log "watch-config-loop-run -> $WATCH_LOOP_DIR/loop.json"
run_cli_without_devnet_key_env devnet --rpc-url "$RPC_URL" watch-config-loop \
  --config "$WATCH_LOOP_DIR/watch-config.json" \
  --private-key-file "$WATCH_KEY_FILE" \
  --passes 2 \
  --sleep-ms 100 \
  --stop-after-publication \
  --json >"$WATCH_LOOP_DIR/loop.json"
WATCH_LOOP_PUBLISHED_STATE_OUT_POINT="$(jq -r '.passes[0].report.channels[0].report.publication.state_out_point.tx_hash + ":" + (.passes[0].report.channels[0].report.publication.state_out_point.index | tostring)' "$WATCH_LOOP_DIR/loop.json")"
log "watch-config-loop-finalise -> $WATCH_LOOP_DIR/finalise.json"
cargo run -q -p morph-cli --features devnet -- devnet --devnet-only --rpc-url "$RPC_URL" finalise-channel \
  --state-out-point "$WATCH_LOOP_PUBLISHED_STATE_OUT_POINT" \
  --vault-out-point "$WATCH_LOOP_VAULT_OUT_POINT" \
  --json >"$WATCH_LOOP_DIR/finalise.json"

WATCH_SPLICE_DIR="$OUT_DIR/watch-splice-stale"
mkdir -p "$WATCH_SPLICE_DIR"
log "watch-splice-stale-open -> $WATCH_SPLICE_DIR/open.json"
cargo run -q -p morph-cli --features devnet -- devnet --devnet-only --rpc-url "$RPC_URL" open-channel --json >"$WATCH_SPLICE_DIR/open.json"
WATCH_SPLICE_STATE_OUT_POINT="$(jq -r '.cells[] | select(.role == "state") | .out_point.tx_hash + ":" + (.out_point.index | tostring)' "$WATCH_SPLICE_DIR/open.json")"
WATCH_SPLICE_VAULT_OUT_POINT="$(jq -r '.cells[] | select(.role == "vault") | .out_point.tx_hash + ":" + (.out_point.index | tostring)' "$WATCH_SPLICE_DIR/open.json")"
WATCH_SPLICE_CHANNEL_ID="$(jq -r '.channel_id' "$WATCH_SPLICE_DIR/open.json")"
WATCH_SPLICE_OLD_FUNDING_ANCHOR="$(jq -r '.funding_anchor' "$WATCH_SPLICE_DIR/open.json")"

log "watch-splice-stale-package -> $WATCH_SPLICE_DIR/state-package.json"
cargo run -q -p morph-cli --features devnet -- devnet --devnet-only --rpc-url "$RPC_URL" save-state-package \
  --state-out-point "$WATCH_SPLICE_STATE_OUT_POINT" \
  --state-number 1 \
  --store-dir "$WATCH_SPLICE_DIR/state-packages" \
  --json >"$WATCH_SPLICE_DIR/state-package.json"
WATCH_SPLICE_OLD_FUNDING_CONTEXT_ID="$(jq -r '.package.funding_context_id' "$WATCH_SPLICE_DIR/state-package.json")"

log "watch-splice-stale-splice-package -> $WATCH_SPLICE_DIR/splice-package.json"
cargo run -q -p morph-cli --features devnet -- devnet --devnet-only --rpc-url "$RPC_URL" save-splice-package \
  --state-out-point "$WATCH_SPLICE_STATE_OUT_POINT" \
  --vault-out-point "$WATCH_SPLICE_VAULT_OUT_POINT" \
  --kind splice-in \
  --ckb-amount 1000000000 \
  --store-dir "$WATCH_SPLICE_DIR/splice-packages" \
  --json >"$WATCH_SPLICE_DIR/splice-package.json"
WATCH_SPLICE_PACKAGE_PATH="$(jq -r '.path' "$WATCH_SPLICE_DIR/splice-package.json")"

log "watch-splice-stale-apply -> $WATCH_SPLICE_DIR/apply.json"
cargo run -q -p morph-cli --features devnet -- devnet --devnet-only --rpc-url "$RPC_URL" apply-splice \
  --state-out-point "$WATCH_SPLICE_STATE_OUT_POINT" \
  --vault-out-point "$WATCH_SPLICE_VAULT_OUT_POINT" \
  --splice-package "$WATCH_SPLICE_PACKAGE_PATH" \
  --json >"$WATCH_SPLICE_DIR/apply.json"
WATCH_SPLICE_APPLY_BLOCK="$(jq -r '.activation_block_number' "$WATCH_SPLICE_DIR/apply.json")"
WATCH_SPLICE_SCANNED_TO_BLOCK="$((WATCH_SPLICE_APPLY_BLOCK - 1))"
WATCH_SPLICE_CURSOR="$WATCH_SPLICE_DIR/cursor.json"
WATCH_SPLICE_UPDATED_MS="$(($(date +%s) * 1000))"
jq -n \
  --arg channel_id "$WATCH_SPLICE_CHANNEL_ID" \
  --arg current_funding_anchor "$WATCH_SPLICE_OLD_FUNDING_ANCHOR" \
  --arg current_funding_context_id "$WATCH_SPLICE_OLD_FUNDING_CONTEXT_ID" \
  --arg last_observed_out_point "$WATCH_SPLICE_STATE_OUT_POINT" \
  --argjson next_block "$WATCH_SPLICE_APPLY_BLOCK" \
  --argjson scanned_to_block "$WATCH_SPLICE_SCANNED_TO_BLOCK" \
  --argjson updated_unix_ms "$WATCH_SPLICE_UPDATED_MS" \
  '{
    schema: "morph.watch_cursor",
    channel_id: $channel_id,
    next_block: $next_block,
    scanned_to_block: $scanned_to_block,
    current_funding_anchor: $current_funding_anchor,
    current_funding_context_id: $current_funding_context_id,
    last_observed_state_number: 0,
    last_observed_out_point: $last_observed_out_point,
    updated_unix_ms: $updated_unix_ms
  }' >"$WATCH_SPLICE_CURSOR"

log "watch-splice-stale-watch -> $WATCH_SPLICE_DIR/watch.json"
run_cli_without_devnet_key_env devnet --rpc-url "$RPC_URL" watch-latest-package \
  --channel-id "$WATCH_SPLICE_CHANNEL_ID" \
  --from-block "$WATCH_SPLICE_APPLY_BLOCK" \
  --cursor-file "$WATCH_SPLICE_CURSOR" \
  --store-dir "$WATCH_SPLICE_DIR/state-packages" \
  --private-key-file "$WATCH_KEY_FILE" \
  --auto-fund-sponsor \
  --detection-depth 1 \
  --timeout-secs 1 \
  --poll-ms 100 \
  --alert-file "$WATCH_SPLICE_DIR/watch-alerts.jsonl" \
  --json >"$WATCH_SPLICE_DIR/watch.json"

cat >>"$OUT_DIR/manifest.txt" <<EOF
finished_at_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)
status=passed
EOF

log "summary -> $OUT_DIR/summary.md"
cargo run -q -p morph-cli -- devnet-smoke-report --dir "$OUT_DIR" >"$OUT_DIR/summary.md"
log "summary-json -> $OUT_DIR/summary.json"
cargo run -q -p morph-cli -- devnet-smoke-report --dir "$OUT_DIR" --json >"$OUT_DIR/summary.json"
log "summary-check -> $OUT_DIR/summary-check.json"
cargo run -q -p morph-cli -- devnet-smoke-assert --dir "$OUT_DIR" --json >"$OUT_DIR/summary-check.json"

if [ ! -e "$LATEST_LINK" ] || [ -L "$LATEST_LINK" ]; then
  OUT_DIR_ABS="$(cd "$OUT_DIR" && pwd)"
  mkdir -p "$(dirname "$LATEST_LINK")"
  rm -f "$LATEST_LINK"
  ln -s "$OUT_DIR_ABS" "$LATEST_LINK"
  log "latest -> $LATEST_LINK"
else
  log "latest link skipped because $LATEST_LINK exists and is not a symlink"
fi

log "passed; artefacts are in $OUT_DIR"
