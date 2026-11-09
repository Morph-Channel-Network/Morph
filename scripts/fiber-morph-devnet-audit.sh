#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEFAULT_BASE_DIR="$ROOT_DIR/target/fiber-morph-devnet-acceptance"

log() {
  printf '[fiber-morph-audit] %s\n' "$*"
}

fail() {
  printf '[fiber-morph-audit] error: %s\n' "$*" >&2
  exit 1
}

require_tool() {
  local name="$1"
  command -v "$name" >/dev/null 2>&1 || fail "missing required tool: $name"
}

resolve_run_dir() {
  local requested="${1:-}"
  if [ -z "$requested" ]; then
    [ -d "$DEFAULT_BASE_DIR" ] || fail "no acceptance run directory found under $DEFAULT_BASE_DIR"
    requested="$(find "$DEFAULT_BASE_DIR" -mindepth 1 -maxdepth 1 -type d | sort | tail -1)"
    [ -n "$requested" ] || fail "no acceptance run directory found under $DEFAULT_BASE_DIR"
  fi

  case "$requested" in
    /*) printf '%s\n' "$requested" ;;
    *) printf '%s\n' "$ROOT_DIR/$requested" ;;
  esac
}

require_file() {
  local path="$1"
  [ -s "$path" ] || fail "missing or empty file: $path"
}

jq_check() {
  local path="$1"
  local expression="$2"
  local description="$3"
  jq -e "$expression" "$path" >/dev/null || fail "$description ($path)"
}

require_manifest_status() {
  local path="$1"
  grep -qx 'status=passed' "$path" || fail "manifest does not contain status=passed: $path"
}

require_fiber_result() {
  local run_dir="$1"
  local file_name="$2"
  local suite="$3"
  local path="$run_dir/$file_name"
  require_file "$path"
  jq -e --arg suite "$suite" \
    '.suite == $suite and .status == "passed" and .runner == "rust" and (.runner_sha256 | test("^[0-9a-f]{64}$")) and (.log | type == "string" and length > 0) and (.evidence | type == "string" and length > 0)' \
    "$path" >/dev/null || fail "Fiber suite did not pass with expected suite id: $suite"

  local evidence_path
  evidence_path="$(jq -r '.evidence' "$path")"
  require_file "$evidence_path"
  jq -e '.status == "passed" and .runner == "rust" and .secrets_recorded == false and ((.schema == "morph.rust_fiber_result.v1" and (.steps | length > 0) and all(.steps[]; .status == "passed" and .assertions > 0 and .rpc_attempts > 0)) or (.schema == "morph.rust_fiber_restart.v1" and (.checkpoints | length == 5)))' "$evidence_path" >/dev/null || fail "invalid native Fiber evidence: $evidence_path"
  local log_path
  log_path="$(jq -r '.log' "$path")"
  case "$log_path" in
    /*) ;;
    *) log_path="$run_dir/$log_path" ;;
  esac
  require_file "$log_path"
}

fiber_result_log_path() {
  local run_dir="$1"
  local file_name="$2"
  local path="$run_dir/$file_name"
  local log_path
  require_file "$path"
  log_path="$(jq -r '.log' "$path")"
  case "$log_path" in
    /*) ;;
    *) log_path="$run_dir/$log_path" ;;
  esac
  require_file "$log_path"
  printf '%s\n' "$log_path"
}

require_fiber_suite_evidence() {
  local run_dir="$1"
  local file_name="$2"
  local suite="$3"
  shift 3
  require_fiber_result "$run_dir" "$file_name" "$suite"

  local log_path pattern
  log_path="$(fiber_result_log_path "$run_dir" "$file_name")"
  for pattern in "$@"; do
    grep -Fq "$pattern" "$log_path" ||
      fail "Fiber suite log is missing required evidence '$pattern': $log_path"
  done
}

require_log_count_at_least() {
  local path="$1"
  local pattern="$2"
  local expected="$3"
  local count
  count="$(grep -Fc "$pattern" "$path" || true)"
  [ "$count" -ge "$expected" ] ||
    fail "log evidence '$pattern' appeared $count times, expected at least $expected: $path"
}

require_fiber_period_check_expiry_evidence() {
  local run_dir="$1"
  local file_name="fiber-rust-e2e_period-check_force-close-expiry.json"
  local result_path="$run_dir/$file_name"
  local stack_log

  require_fiber_suite_evidence "$run_dir" "$file_name" "e2e/period-check/force-close-expiry" \
    "e2e/period-check/force-close-expiry/09-node1-add-tlc" \
    "e2e/period-check/force-close-expiry/10-node2-add-tlc" \
    "e2e/period-check/force-close-expiry/12-node1-list-channels"

  local evidence
  evidence="$(jq -r '.evidence' "$result_path")"
  jq -e '([.steps[] | select(.id | endswith("11-node2-list-channels") or endswith("12-node1-list-channels"))] | length) == 2' "$evidence" >/dev/null || fail "missing native expiry cleanup assertions"

}

require_morph_payment_gateway_fiber_evidence() {
  local run_dir="$1"
  local result="$run_dir/morph-payment-gateway-fiber-e2e/result.json"
  local manifest="$run_dir/morph-payment-gateway-fiber-e2e/manifest.json"

  require_file "$result"
  require_file "$manifest"
  jq_check "$result" \
    '.schema == "morph.payment_gateway_fiber_devnet_e2e" and
     .status == "passed" and
     .route == "fiber-node1 -> fiber-node2 -> fiber-node3" and
     (.routing.x402_node_pubkeys | length == 3) and
     (.routing.fair_exchange_node_pubkeys | length == 3) and
     .payer != .payee and
     .x402.terminal_status == "Settled" and
     (.x402.payment_hash | test("^0x[0-9a-f]{64}$")) and
     (.x402.receipt_id | test("^0x[0-9a-f]{64}$")) and
     (.x402.credential_id | test("^0x[0-9a-f]{64}$")) and
     (.fair_exchange.payment_hash | test("^0x[0-9a-f]{64}$")) and
     (.fair_exchange.offer_id | test("^0x[0-9a-f]{64}$")) and
     (.fair_exchange.receipt_id | test("^0x[0-9a-f]{64}$")) and
     (.fair_exchange.plaintext_sha256 | test("^0x[0-9a-f]{64}$"))' \
    'Morph Payment Gateway Fiber devnet result is incomplete'
  jq_check "$manifest" \
    '.schema == "morph.payment_gateway_fiber_devnet_manifest" and
     .status == "passed" and
     .result == "result.json" and
     .secrets_recorded == false and
     .proof_scope == "fiber_provider_route" and .morph_custody_backing_proven == false and
     (.payment_gateway_binary_sha256 | test("^[0-9a-f]{64}$")) and
     (.rust_runner_sha256 | test("^[0-9a-f]{64}$")) and
     .tracked_worktree_clean == true and
     (.ckb_network_id | test("^0x[0-9a-f]{64}$")) and
     (.fiber_node1_pubkey | test("^[0-9a-f]{66}$")) and
     (.fiber_node2_pubkey | test("^[0-9a-f]{66}$")) and
     (.fiber_node3_pubkey | test("^[0-9a-f]{66}$")) and
     (.payer_account_id | test("^0x[0-9a-f]{64}$")) and
     (.payee_account_id | test("^0x[0-9a-f]{64}$"))' \
    'Morph Payment Gateway Fiber devnet manifest is incomplete'
  jq -e -s \
    '.[0].ckb_network_id == .[1].ckb_network_id and
     .[0].payer == .[1].payer_account_id and
     .[0].payee == .[1].payee_account_id and
     .[0].routing.x402_node_pubkeys ==
       [.[1].fiber_node1_pubkey, .[1].fiber_node2_pubkey, .[1].fiber_node3_pubkey] and
     .[0].routing.fair_exchange_node_pubkeys ==
       [.[1].fiber_node1_pubkey, .[1].fiber_node2_pubkey, .[1].fiber_node3_pubkey]' \
    "$result" "$manifest" >/dev/null ||
    fail "Morph Payment Gateway result and manifest identities do not match"
}

verify_morph_stateful() {
  local run_dir="$1"
  local current="$run_dir/morph-stateful"
  local scenarios="$current/scenarios"
  local matrix_dir="$scenarios/smoke"
  local morph_bin="${MORPH_BIN:-$ROOT_DIR/target/debug/morph-cli}"
  [ -x "$morph_bin" ] || fail "build the current morph-cli before auditing"
  require_file "$scenarios/summary-check.json"
  require_file "$scenarios/summary.json"
  require_file "$matrix_dir/matrix.json"
  require_file "$current/evidence.json"
  require_file "$run_dir/fiber-coexistence-genesis.json"
  # The sole current stateful verifier owns scenario dimensions, negative
  # evidence, code identity, budget checks and source freshness. Do not retain
  # the retired implementation's transaction-count/proof-profile thresholds.
  (cd "$ROOT_DIR" && "$morph_bin" devnet-stateful-assert --dir "$scenarios" \
    --contracts-dir "$matrix_dir/contracts" \
    --budget-profile "$ROOT_DIR/docs/devnet-stateful-budget.example.json" \
    --audit-profile "$ROOT_DIR/docs/devnet-audit-profile.example.json" \
    --json) >"$current/current-assertion.json"
  python3 - "$current" "$run_dir/fiber-coexistence-genesis.json" "$morph_bin" "$run_dir/manifest.txt" <<'CURRENT_MATRIX_PY'
from pathlib import Path
import json,subprocess,sys
root=Path(sys.argv[1]).resolve(); matrix_dir=root/'scenarios/smoke'
def read(path):
    return json.loads(path.read_text())
def check(condition,message):
    if not condition: raise SystemExit(message)
evidence=read(root/'evidence.json'); observed=read(Path(sys.argv[2]))
check(evidence.get('descriptor_version')==5,'current descriptor evidence missing')
check(evidence.get('genesis_hash')==observed.get('result'),'Morph/Fiber genesis mismatch')
manifest=dict(line.split('=',1) for line in Path(sys.argv[4]).read_text().splitlines() if '=' in line)
check(evidence.get('rpc_url')==manifest.get('fiber_ckb_rpc_url'),'Morph/Fiber RPC endpoint mismatch')
matrix=read(matrix_dir/'matrix.json')
check(matrix.get('schema')=='morph.current_acceptance_matrix.v1','wrong current matrix schema')
expected={'bilateral_shared':'bilateral_shared','bilateral_splice':'splice',
'factory_custody_and_children':'factory','watch_service_reorg':'watch_service',
'maximum_asset_lifecycle':'bilateral_max_assets'}
cases=matrix.get('cases',[])
check(len(cases)==len(expected) and {c.get('name') for c in cases}==set(expected),'current case set mismatch')
reports={}
for case in cases:
    check(case.get('kind')==expected[case['name']],'wrong current case kind')
    path=(matrix_dir/case['report_path']).resolve()
    check(path.is_relative_to(matrix_dir),'report path leaves captured current matrix')
    reports[case['name']]=read(path)
shared=reports['bilateral_shared']; splice=reports['bilateral_splice']
factory=reports['factory_custody_and_children']; watch=reports['watch_service_reorg']
maximum=reports['maximum_asset_lifecycle']
packages=set()
for report in [shared,watch,maximum]:
    check(report.get('schema')=='morph.multi_asset_devnet_acceptance.v1','wrong current channel report')
    check(report['finalise']['status']=='Committed','complete-set finalisation missing')
    check(len(report['recovery_packages'])==2,'current channel recovery evidence missing')
    packages.update(report['recovery_packages'])
check(splice.get('schema')=='morph.current_splice_devnet_acceptance.v1','wrong current splice report')
check(splice['fund']['status']=='Committed' and splice['activation']['status']=='Committed','splice funding/activation missing')
packages.add(splice['fund']['durable_package'])
packages.add(splice['activation']['durable_package'])
for operation in splice['transitions']['operations']:
    check(operation['submission']['status']=='Committed' and operation['activation']['status']=='Committed','splice submission/activation missing')
    packages.update([operation['submission']['old_recovery_package'],operation['submission']['new_recovery_package']])
for terminal in splice['transitions']['terminal']:
    packages.add(terminal['durable_package'])
for path in packages:
    path=Path(path).resolve()
    check(path.is_relative_to(root),'recovery artifact leaves captured current run')
    package=read(path)
    check(len(bytes.fromhex(package['header_hex'].removeprefix('0x')))==318,'not a current State header')
    subprocess.run([sys.argv[3],'validate-multi-asset-package',str(path),'--json'],check=True,stdout=subprocess.DEVNULL)
check(shared['shared_funding'] and maximum['shared_funding'] and maximum['asset_count']==8,'funding/max asset evidence missing')
check(len(splice['transitions']['operations'])==2 and all(x['withheld_bridge_receipt_reconciled'] for x in splice['transitions']['operations']),'splice recovery evidence missing')
check(len(splice['transitions']['terminal'])==2 and all(x['status']=='Committed' for x in splice['transitions']['terminal']),'splice terminal evidence missing')
check(factory['root']['report']['status']=='Committed' and factory['activation']['report']['status']=='Committed','native Factory funding/activation missing')
check(factory['canonical_replay']['canonical_replay'] and factory['same_path_handoff'],'Factory canonical journal handoff missing')
check(factory['transitions']['withheld_full_consent_escaped'] and factory['transitions']['peer_refreshed_from_public_changes'],'Factory unilateral/proof-data evidence missing')
check(factory['transitions']['child']['reduced']['finalise']['status']=='Committed','reduced child exit missing')
check(factory['transitions']['child']['terminal']['finalise']['status']=='Committed' and factory['transitions']['child']['terminal']['retained_factory']['retired'],'parent retirement and child exit missing')
check(any(p.get('reorg_recovery') for p in watch['watch_passes']),'canonical watch rollback evidence missing')
check(any(p.get('service',{}).get('published_count')==1 for p in watch['watch_passes']),'current watch service publication missing')
CURRENT_MATRIX_PY
}

write_report() {
  local run_dir="$1"
  local mode="$2"
  local include_morph="$3"
  local include_coexistence_fiber="$4"
  local include_extended_fiber="$5"
  local report="$run_dir/business-flow-audit.json"
  local audited_at_utc
  audited_at_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  jq -n \
    --arg run_dir "$run_dir" \
    --arg mode "$mode" \
    --arg audited_at_utc "$audited_at_utc" \
    --arg manifest "$run_dir/manifest.txt" \
    --arg repo_state "$run_dir/repo-state.json" \
    --arg summary "$run_dir/summary.json" \
    --arg matrix "$run_dir/acceptance-matrix.json" \
    --arg morph_summary_check "$run_dir/morph-stateful/scenarios/summary-check.json" \
    --arg morph_summary "$run_dir/morph-stateful/scenarios/summary.json" \
    --arg fiber_external "$run_dir/fiber-rust-e2e_external-funding-open.json" \
    --arg morph_payment_gateway_result "$run_dir/morph-payment-gateway-fiber-e2e/result.json" \
    --arg morph_payment_gateway_manifest "$run_dir/morph-payment-gateway-fiber-e2e/manifest.json" \
    --arg fiber_restart "$run_dir/fiber-external-funding-restart.json" \
    --arg fiber_open_close "$run_dir/fiber-rust-e2e_open-use-close-a-channel.json" \
    --arg fiber_three_nodes "$run_dir/fiber-rust-e2e_3-nodes-transfer.json" \
    --arg fiber_router_pay "$run_dir/fiber-rust-e2e_router-pay.json" \
    --arg fiber_reestablish "$run_dir/fiber-rust-e2e_reestablish.json" \
    --arg fiber_shutdown_force "$run_dir/fiber-rust-e2e_shutdown-force.json" \
    --arg fiber_hold_invoice_cancel "$run_dir/fiber-rust-e2e_hold-invoice-cancel-failure.json" \
    --arg fiber_force_close_expiry "$run_dir/fiber-rust-e2e_period-check_force-close-expiry.json" \
    --arg fiber_udt "$run_dir/fiber-rust-e2e_udt.json" \
    --arg fiber_udt_router "$run_dir/fiber-rust-e2e_udt-router-pay.json" \
    --arg fiber_watchtower_force_open "$run_dir/fiber-rust-e2e_watchtower_force-close-after-open-channel.json" \
    --arg fiber_watchtower_force_pending "$run_dir/fiber-rust-e2e_watchtower_force-close-with-pending-tlcs.json" \
    --arg fiber_watchtower_force_multiple "$run_dir/fiber-rust-e2e_watchtower_force-close-after-multiple-payments.json" \
    --arg fiber_watchtower_remote_stopped "$run_dir/fiber-rust-e2e_watchtower_force-close-remote-with-pending-tlcs-and-stop-watchtower.json" \
    --arg fiber_funding_remove_change "$run_dir/fiber-rust-e2e_funding-tx-verification_remove_change.json" \
    --arg fiber_funding_modify_change "$run_dir/fiber-rust-e2e_funding-tx-verification_modify_change.json" \
    --arg fiber_funding_from_peer "$run_dir/fiber-rust-e2e_funding-tx-verification_fund_from_peer.json" \
    --arg fiber_funding_missing_inputs "$run_dir/fiber-rust-e2e_funding-tx-verification_missing_inputs.json" \
    --argjson include_morph "$include_morph" \
    --argjson include_coexistence_fiber "$include_coexistence_fiber" \
    --argjson include_extended_fiber "$include_extended_fiber" \
    '{
      schema: "morph.fiber_morph_business_flow_audit",
      status: "passed",
      mode: $mode,
      audited_at_utc: $audited_at_utc,
      run_dir: $run_dir,
      evidence: {
        manifest: $manifest,
        repo_state: $repo_state,
        summary: $summary,
        acceptance_matrix: $matrix,
        morph_stateful_summary_check: (if $include_morph == 1 then $morph_summary_check else null end),
        morph_stateful_summary: (if $include_morph == 1 then $morph_summary else null end)
      },
      business_flows:
        (
          (if $include_morph == 1 and $include_coexistence_fiber == 1 then [
            {
              id: "same_ckb_devnet_coexistence",
              system: "cross_repo",
              description: "Morph stateful acceptance and Fiber external funding execute against the same local CKB devnet.",
              evidence: [$matrix, $morph_summary_check, $fiber_external]
            }
          ] else [] end)
          + (if $include_morph == 1 then [
            {id: "morph_current_shared_funding_and_settlement", system: "morph", case_id: "bilateral_shared", evidence: [$morph_summary]},
            {id: "morph_current_splice_and_recovery", system: "morph", case_id: "bilateral_splice", evidence: [$morph_summary]},
            {id: "morph_current_factory_custody_and_children", system: "morph", case_id: "factory_custody_and_children", evidence: [$morph_summary]},
            {id: "morph_current_watch_service_and_reorg", system: "morph", case_id: "watch_service_reorg", evidence: [$morph_summary]},
            {id: "morph_current_maximum_asset_lifecycle", system: "morph", case_id: "maximum_asset_lifecycle", evidence: [$morph_summary]}
          ] else [] end)
          + (if $include_coexistence_fiber == 1 then [
            {id: "fiber_external_funding_open", system: "fiber", suite: "e2e/external-funding-open", evidence: [$fiber_external]},
            {id: "fiber_external_funding_restart", system: "fiber", suite: "e2e/external-funding-open/restart", evidence: [$fiber_restart]},
            {id: "morph_payment_gateway_x402_fiber_multihop", system: "morph_payment_gateway", description: "Signed x402 payment, terminal Fiber settlement, and paid Biscuit credential over a three-node route.", evidence: [$morph_payment_gateway_result, $morph_payment_gateway_manifest, $fiber_router_pay]},
            {id: "morph_payment_gateway_fair_exchange_fiber_multihop", system: "morph_payment_gateway", description: "Hash-locked encrypted result release after terminal three-node Fiber payment.", evidence: [$morph_payment_gateway_result, $morph_payment_gateway_manifest, $fiber_router_pay]}
          ] else [] end)
          + (if $include_extended_fiber == 1 then [
            {id: "fiber_open_use_close_channel", system: "fiber", suite: "e2e/open-use-close-a-channel", evidence: [$fiber_open_close]},
            {id: "fiber_three_node_transfer", system: "fiber", suite: "e2e/3-nodes-transfer", evidence: [$fiber_three_nodes]},
            {id: "fiber_router_pay_graph_invoice_and_failure", system: "fiber", suite: "e2e/router-pay", evidence: [$fiber_router_pay]},
            {id: "fiber_reestablish_after_disconnect", system: "fiber", suite: "e2e/reestablish", evidence: [$fiber_reestablish]},
            {id: "fiber_force_shutdown_after_peer_disconnect", system: "fiber", suite: "e2e/shutdown-force", evidence: [$fiber_shutdown_force]},
            {id: "fiber_hold_invoice_cancel_failure_decode", system: "fiber", suite: "e2e/hold-invoice-cancel-failure", evidence: [$fiber_hold_invoice_cancel]},
            {id: "fiber_periodic_expiry_cleanup", system: "fiber", suite: "e2e/period-check/force-close-expiry", evidence: [$fiber_force_close_expiry]},
            {id: "fiber_udt_channel_flow", system: "fiber", suite: "e2e/udt", evidence: [$fiber_udt]},
            {id: "fiber_udt_router_pay", system: "fiber", suite: "e2e/udt-router-pay", evidence: [$fiber_udt_router]},
            {id: "fiber_watchtower_force_close_after_open", system: "fiber", suite: "e2e/watchtower/force-close-after-open-channel", evidence: [$fiber_watchtower_force_open]},
            {id: "fiber_watchtower_force_close_with_pending_tlcs", system: "fiber", suite: "e2e/watchtower/force-close-with-pending-tlcs", evidence: [$fiber_watchtower_force_pending]},
            {id: "fiber_watchtower_force_close_after_multiple_payments", system: "fiber", suite: "e2e/watchtower/force-close-after-multiple-payments", evidence: [$fiber_watchtower_force_multiple]},
            {id: "fiber_watchtower_remote_force_close_with_watchtower_stopped", system: "fiber", suite: "e2e/watchtower/force-close-remote-with-pending-tlcs-and-stop-watchtower", evidence: [$fiber_watchtower_remote_stopped]},
            {id: "fiber_funding_tx_verify_remove_change", system: "fiber", suite: "e2e/funding-tx-verification/remove_change", evidence: [$fiber_funding_remove_change]},
            {id: "fiber_funding_tx_verify_modify_change", system: "fiber", suite: "e2e/funding-tx-verification/modify_change", evidence: [$fiber_funding_modify_change]},
            {id: "fiber_funding_tx_verify_fund_from_peer", system: "fiber", suite: "e2e/funding-tx-verification/fund_from_peer", evidence: [$fiber_funding_from_peer]},
            {id: "fiber_funding_tx_verify_missing_inputs", system: "fiber", suite: "e2e/funding-tx-verification/missing_inputs", evidence: [$fiber_funding_missing_inputs]}
          ] else [] end)
        ),
      security_families:
        (
          (if $include_morph == 1 then [
            {id: "state_authority_authenticity", system: "morph", severity: "P0", evidence: [$morph_summary]},
            {id: "canonical_relative_maturity", system: "morph", severity: "P0", evidence: [$morph_summary]},
            {id: "state_retirement_non_orphaning", system: "morph", severity: "P0", evidence: [$morph_summary]},
            {id: "signed_descriptor_evolution", system: "morph", severity: "P0", evidence: [$morph_summary]},
            {id: "non_interference_not_authorisation", system: "morph", severity: "P0", evidence: [$morph_summary]},
            {id: "factory_value_delta_binding", system: "morph", severity: "P0", evidence: [$morph_summary]},
            {id: "typed_asset_binding", system: "morph", severity: "P0", evidence: [$morph_summary]},
            {id: "sponsor_policy_boundary", system: "morph", severity: "P1", evidence: [$morph_summary]},
            {id: "watchtower_authority_and_cursor", system: "morph", severity: "P2", evidence: [$morph_summary]},
            {id: "negative_recovery_continuity", system: "morph", severity: "P1", evidence: [$morph_summary]},
            {id: "budget_regression", system: "morph", severity: "P2", evidence: [$morph_summary]}
          ] else [] end)
          + (if $include_coexistence_fiber == 1 then [
            {id: "fiber_external_funding_persistence", system: "fiber", severity: "P0", evidence: [$fiber_external, $fiber_restart]},
            {id: "morph_payment_gateway_terminal_payment_identity_binding", system: "morph_payment_gateway", severity: "P0", evidence: [$morph_payment_gateway_result, $morph_payment_gateway_manifest]},
            {id: "morph_payment_gateway_credential_hashlock_release", system: "morph_payment_gateway", severity: "P0", evidence: [$morph_payment_gateway_result, $morph_payment_gateway_manifest]}
          ] else [] end)
          + (if $include_extended_fiber == 1 then [
            {id: "fiber_funding_tx_shape_validation", system: "fiber", severity: "P0", evidence: [$fiber_funding_remove_change, $fiber_funding_modify_change, $fiber_funding_from_peer, $fiber_funding_missing_inputs]},
            {id: "fiber_cooperative_close_settlement", system: "fiber", severity: "P0", evidence: [$fiber_open_close, $fiber_three_nodes]},
            {id: "fiber_force_close_watchtower_settlement", system: "fiber", severity: "P0", evidence: [$fiber_shutdown_force, $fiber_watchtower_force_open, $fiber_watchtower_force_pending, $fiber_watchtower_force_multiple, $fiber_watchtower_remote_stopped]},
            {id: "fiber_tlc_error_and_failure_semantics", system: "fiber", severity: "P1", evidence: [$fiber_open_close, $fiber_hold_invoice_cancel, $fiber_force_close_expiry]},
            {id: "fiber_routing_graph_and_duplicate_payment_controls", system: "fiber", severity: "P1", evidence: [$fiber_router_pay, $fiber_three_nodes]},
            {id: "fiber_reconnect_reestablish_recovery", system: "fiber", severity: "P1", evidence: [$fiber_reestablish]},
            {id: "fiber_typed_asset_channel_binding", system: "fiber", severity: "P0", evidence: [$fiber_udt, $fiber_udt_router]},
            {id: "fiber_periodic_expiry_recovery", system: "fiber", severity: "P1", evidence: [$fiber_force_close_expiry]}
          ] else [] end)
        ),
      minimum_evidence:
        (
          (if $include_morph == 1 then {
            morph_current_case_ids: ["bilateral_shared", "bilateral_splice", "factory_custody_and_children", "watch_service_reorg", "maximum_asset_lifecycle"],
            morph_descriptor_version: 5,
            morph_state_header_bytes: 318,
            morph_stateful_assertion: "morph-stateful/current-assertion.json",
            evidence_scope: "actual current reports, independent journals, same Fiber genesis; not production approval"
          } else {} end)
          + (if $include_extended_fiber == 1 then {
            fiber_required_business_flows: (17 + (if $include_coexistence_fiber == 1 then 2 else 0 end)),
            fiber_required_security_families: (8 + (if $include_coexistence_fiber == 1 then 1 else 0 end)),
            fiber_funding_tx_verification_cases: 4
          } else {} end)
          + (if $include_coexistence_fiber == 1 then {
            morph_payment_gateway_required_business_flows: 2,
            morph_payment_gateway_required_security_families: 2
          } else {} end)
        )
    }' >"$report"

  log "business-flow audit -> $report"
}

main() {
  require_tool python3
  require_tool jq
  require_tool grep
  require_tool find
  require_tool sort
  require_tool tail

  local run_dir
  run_dir="$(resolve_run_dir "${1:-}")"
  [ -d "$run_dir" ] || fail "acceptance run directory does not exist: $run_dir"

  local manifest="$run_dir/manifest.txt"
  local repo_state="$run_dir/repo-state.json"
  local matrix="$run_dir/acceptance-matrix.json"
  local summary="$run_dir/summary.json"

  require_file "$manifest"
  require_file "$repo_state"
  require_file "$matrix"
  require_file "$summary"

  require_manifest_status "$manifest"
  jq_check "$summary" '.schema == "morph.fiber_morph_devnet_acceptance_summary" and .status == "passed"' 'top-level acceptance summary did not pass'
  jq_check "$matrix" '.schema == "morph.fiber_morph_devnet_acceptance_matrix"' 'acceptance matrix schema mismatch'
  jq_check "$repo_state" '.schema == "morph.fiber_morph_repo_state"' 'repo-state schema mismatch'
  jq_check "$repo_state" '.morph.status == ""' 'Morph worktree was not clean when the run recorded repo state'
  jq_check "$repo_state" '.fiber.status == ""' 'Fiber tracked worktree was not clean when the run recorded repo state'
  jq_check "$matrix" 'all(.gates[]; .required == true)' 'acceptance matrix contains a non-required gate'
  jq_check "$matrix" '([.gates[].id] | length) == ([.gates[].id] | unique | length)' 'acceptance matrix contains duplicate gates'

  local mode
  mode="$(jq -r '.mode // empty' "$matrix")"

  local include_morph=0
  local include_coexistence_fiber=0
  local include_extended_fiber=0
  case "$mode" in
    coexistence)
      include_morph=1
      include_coexistence_fiber=1
      jq_check "$matrix" \
        '([.gates[].id] | sort) == (["business_flow_and_security_audit", "fiber_channel_external_funding", "morph_payment_gateway_fiber_multihop", "morph_channel_factory_matrix", "same_ckb_devnet_coexistence"] | sort)' \
        'coexistence acceptance matrix gate set is inaccurate'
      ;;
    full)
      include_morph=1
      include_coexistence_fiber=1
      include_extended_fiber=1
      jq_check "$matrix" \
        '([.gates[].id] | sort) == (["business_flow_and_security_audit", "fiber_channel_external_funding", "fiber_security_and_recovery_matrix", "morph_payment_gateway_fiber_multihop", "morph_channel_factory_matrix", "same_ckb_devnet_coexistence"] | sort)' \
        'full acceptance matrix gate set is inaccurate'
      ;;
    fiber)
      include_extended_fiber=1
      jq_check "$matrix" \
        '([.gates[].id] | sort) == (["business_flow_and_security_audit", "fiber_security_and_recovery_matrix"] | sort)' \
        'Fiber-only acceptance matrix gate set is inaccurate'
      ;;
    *)
      fail "unsupported acceptance audit mode: ${mode:-<empty>}"
      ;;
  esac

  if [ "$include_morph" = "1" ]; then
    verify_morph_stateful "$run_dir"
  fi

  if [ "$include_coexistence_fiber" = "1" ]; then
    require_fiber_suite_evidence "$run_dir" "fiber-rust-e2e_external-funding-open.json" "e2e/external-funding-open" \
      "e2e/external-funding-open/08-open-channel-with-external-funding" \
      "e2e/external-funding-open/09-sign-external-funding-tx" \
      "e2e/external-funding-open/10-submit-signed-funding-tx" \
      "e2e/external-funding-open/18-wait-channel-closed-and-capture-shutdown-tx" \
      "e2e/external-funding-open/19-inspect-shutdown-tx"
    require_fiber_suite_evidence "$run_dir" "fiber-external-funding-restart.json" "e2e/external-funding-open/restart" \
      "opening external-funded channel" \
      "restarting node1" \
      "submitting signed funding tx" \
      "waiting for Closed" \
      "success"
    require_fiber_suite_evidence "$run_dir" "fiber-rust-e2e_router-pay.json" "e2e/router-pay" \
      "e2e/router-pay/12-node1-send-payment" \
      "e2e/router-pay/13-node-send-duplicate-payment-err" \
      "e2e/router-pay/33-node2-update-channel"
    require_morph_payment_gateway_fiber_evidence "$run_dir"
    jq -e -s '.[0].git_commit == .[1].morph.head' \
      "$run_dir/morph-payment-gateway-fiber-e2e/manifest.json" "$repo_state" >/dev/null ||
      fail "Morph Payment Gateway evidence was not generated from the recorded Morph commit"
  fi

  if [ "$include_extended_fiber" = "1" ]; then
    require_fiber_suite_evidence "$run_dir" "fiber-rust-e2e_open-use-close-a-channel.json" "e2e/open-use-close-a-channel" \
      "e2e/open-use-close-a-channel/08-add-tlc-from-NODE1-err" \
      "e2e/open-use-close-a-channel/10-add-tlc-from-NODE1-amount-err" \
      "e2e/open-use-close-a-channel/15-shutdown-from-NODE1" \
      "e2e/open-use-close-a-channel/23-list-channel-with-closed-status-NODE1"
    require_fiber_suite_evidence "$run_dir" "fiber-rust-e2e_3-nodes-transfer.json" "e2e/3-nodes-transfer" \
      "e2e/3-nodes-transfer/12-node1-add-tlc" \
      "e2e/3-nodes-transfer/14-node3-remove-tlc" \
      "e2e/3-nodes-transfer/21-node1-send-shutdown-channel-1" \
      "e2e/3-nodes-transfer/23-node2-send-shutdown-channel-2"
    require_fiber_suite_evidence "$run_dir" "fiber-rust-e2e_router-pay.json" "e2e/router-pay" \
      "e2e/router-pay/13-node-send-duplicate-payment-err" \
      "e2e/router-pay/23-node1-send-payment-will-fail" \
      "e2e/router-pay/25-node1-pay-self-with-node2-err" \
      "e2e/router-pay/29-node1-pay-self-with-node2-succ" \
      "e2e/router-pay/33-node2-update-channel"
    require_fiber_suite_evidence "$run_dir" "fiber-rust-e2e_reestablish.json" "e2e/reestablish" \
      "e2e/reestablish/08-disconnect-NODE1" \
      "e2e/reestablish/09-reconnect-peer-NODE1" \
      "e2e/reestablish/10-remove-tlc-from-NODE1" \
      "e2e/reestablish/11-shutdown-from-NODE1"
    require_fiber_suite_evidence "$run_dir" "fiber-rust-e2e_shutdown-force.json" "e2e/shutdown-force" \
      "e2e/shutdown-force/05-disconnect-peer" \
      "e2e/shutdown-force/06-shutdown-force-NODE1" \
      "e2e/shutdown-force/11-trigger-check-shutdown" \
      "e2e/shutdown-force/12-list-channel-NODE3"
    require_fiber_suite_evidence "$run_dir" "fiber-rust-e2e_hold-invoice-cancel-failure.json" "e2e/hold-invoice-cancel-failure" \
      "e2e/hold-invoice-cancel-failure/07-send-payment" \
      "e2e/hold-invoice-cancel-failure/09-cancel-invoice" \
      "e2e/hold-invoice-cancel-failure/10-get-payment-decoded-final-error"
    require_fiber_period_check_expiry_evidence "$run_dir"
    require_fiber_suite_evidence "$run_dir" "fiber-rust-e2e_udt.json" "e2e/udt" \
      "e2e/udt/02-node1-node2-open-channel-amount-err" \
      "e2e/udt/08-node1-add-tlc" \
      "e2e/udt/10-node1-node2-open-channel-invalid" \
      "e2e/udt/12-node2-accept-channel"
    require_fiber_suite_evidence "$run_dir" "fiber-rust-e2e_udt-router-pay.json" "e2e/udt-router-pay" \
      "e2e/udt-router-pay/12-node1-send-payment" \
      "e2e/udt-router-pay/14-node1-send-payment-with-invoice" \
      "e2e/udt-router-pay/16-node1-send-payment-keysend-large-amount"
    require_fiber_suite_evidence "$run_dir" "fiber-rust-e2e_watchtower_force-close-after-open-channel.json" "e2e/watchtower/force-close-after-open-channel" \
      "e2e/watchtower/force-close-after-open-channel/09-force-close" \
      "e2e/watchtower/force-close-after-open-channel/15-check-commitment-tx" \
      "e2e/watchtower/force-close-after-open-channel/16-check-balance-node1" \
      "e2e/watchtower/force-close-after-open-channel/17-check-balance-node2"
    require_fiber_suite_evidence "$run_dir" "fiber-rust-e2e_watchtower_force-close-with-pending-tlcs.json" "e2e/watchtower/force-close-with-pending-tlcs" \
      "e2e/watchtower/force-close-with-pending-tlcs/12-force-close" \
      "e2e/watchtower/force-close-with-pending-tlcs/13-node2-remove-tlc" \
      "e2e/watchtower/force-close-with-pending-tlcs/21-check-commitment-tx" \
      "e2e/watchtower/force-close-with-pending-tlcs/22-check-balance-node1" \
      "e2e/watchtower/force-close-with-pending-tlcs/23-check-balance-node2"
    require_fiber_suite_evidence "$run_dir" "fiber-rust-e2e_watchtower_force-close-after-multiple-payments.json" "e2e/watchtower/force-close-after-multiple-payments" \
      "e2e/watchtower/force-close-after-multiple-payments/10-node1-send-payment-with-invoice" \
      "e2e/watchtower/force-close-after-multiple-payments/12-node2-send-payment-with-invoice" \
      "e2e/watchtower/force-close-after-multiple-payments/13-force-close" \
      "e2e/watchtower/force-close-after-multiple-payments/19-check-commitment-tx"
    require_fiber_suite_evidence "$run_dir" "fiber-rust-e2e_watchtower_force-close-remote-with-pending-tlcs-and-stop-watchtower.json" "e2e/watchtower/force-close-remote-with-pending-tlcs-and-stop-watchtower" \
      "e2e/watchtower/force-close-remote-with-pending-tlcs-and-stop-watchtower/10-node2-stop-watchtower" \
      "e2e/watchtower/force-close-remote-with-pending-tlcs-and-stop-watchtower/11-force-close" \
      "e2e/watchtower/force-close-remote-with-pending-tlcs-and-stop-watchtower/18-check-commitment-tx" \
      "e2e/watchtower/force-close-remote-with-pending-tlcs-and-stop-watchtower/19-check-balance-node1" \
      "e2e/watchtower/force-close-remote-with-pending-tlcs-and-stop-watchtower/20-check-balance-node2"
    require_fiber_suite_evidence "$run_dir" "fiber-rust-e2e_funding-tx-verification_remove_change.json" "e2e/funding-tx-verification/remove_change" \
      "e2e/funding-tx-verification/02-open-channel" \
      "e2e/funding-tx-verification/03-get-auto-accepted-channel"
    require_fiber_suite_evidence "$run_dir" "fiber-rust-e2e_funding-tx-verification_modify_change.json" "e2e/funding-tx-verification/modify_change" \
      "e2e/funding-tx-verification/02-open-channel" \
      "e2e/funding-tx-verification/03-get-auto-accepted-channel"
    require_fiber_suite_evidence "$run_dir" "fiber-rust-e2e_funding-tx-verification_fund_from_peer.json" "e2e/funding-tx-verification/fund_from_peer" \
      "e2e/funding-tx-verification/02-open-channel" \
      "e2e/funding-tx-verification/03-get-auto-accepted-channel"
    require_fiber_suite_evidence "$run_dir" "fiber-rust-e2e_funding-tx-verification_missing_inputs.json" "e2e/funding-tx-verification/missing_inputs" \
      "e2e/funding-tx-verification/02-open-channel" \
      "e2e/funding-tx-verification/03-get-auto-accepted-channel"
  fi

  write_report "$run_dir" "$mode" "$include_morph" "$include_coexistence_fiber" "$include_extended_fiber"
  log "audit passed for $mode run: $run_dir"
}

main "$@"
