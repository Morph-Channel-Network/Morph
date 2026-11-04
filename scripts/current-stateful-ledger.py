#!/usr/bin/env python3
"""Build the current stateful ledger from retained, verified native acceptance facts.

This tool never signs, uses RPC, or decodes protocol wire bytes. Public package
and Factory reviews are delegated to the exact CLI retained by the run.
"""

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
IMPLEMENTATION_PATHS = [
    "crates", "contracts", "scripts", "sdk", "ui", ".github", "Cargo.toml",
    "Cargo.lock", "Makefile", "rust-toolchain.toml", "AGENTS.md",
]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read_json(path):
    require(path.is_file() and path.stat().st_size <= 64 * 1024 * 1024,
            f"missing or oversized JSON artifact: {path}")
    return json.loads(path.read_text())


def write_immutable(path, value):
    raw = (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode()
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        require(path.read_bytes() == raw, f"refusing to replace different evidence: {path}")
        return
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(raw)
        output.flush()
        os.fsync(output.fileno())


def git(*arguments):
    return subprocess.check_output(["git", *arguments], cwd=ROOT, text=True).strip()


def source_digest():
    """Hash actual tracked source plus untracked implementation, never target data."""
    tracked = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT).split(b"\0")
    untracked = subprocess.check_output(
        ["git", "ls-files", "--others", "--exclude-standard", "-z", "--", *IMPLEMENTATION_PATHS],
        cwd=ROOT,
    ).split(b"\0")
    digest = hashlib.sha256()
    for raw_name in sorted(set(tracked + untracked) - {b""}):
        path = ROOT / os.fsdecode(raw_name)
        digest.update(raw_name + b"\0")
        if path.is_symlink():
            digest.update(b"symlink\0" + os.fsencode(os.readlink(path)))
        elif path.is_file():
            digest.update(hashlib.sha256(path.read_bytes()).digest())
        else:
            digest.update(b"missing")
    return digest.hexdigest()


def capture_provenance(run, phase):
    path = run / "source-provenance.json"
    if path.exists():
        value = read_json(path)
        require(value.get("schema") == "morph.current_run_provenance.v1",
                "unsupported source provenance")
        require(value.get("phase") in ("pre_build", "post_run"), "invalid provenance phase")
        require(phase != "pre_build", "source provenance already exists; use a fresh run")
        return value
    tracked = git("status", "--porcelain", "--untracked-files=no")
    untracked = git("ls-files", "--others", "--exclude-standard", "--", *IMPLEMENTATION_PATHS)
    value = {
        "schema": "morph.current_run_provenance.v1",
        "phase": phase,
        "git_commit": git("rev-parse", "--short", "HEAD"),
        "git_commit_full": git("rev-parse", "HEAD"),
        "git_dirty": bool(tracked or untracked),
        "source_tree_sha256": source_digest(),
        "tracked_status": tracked.splitlines(),
        "untracked_implementation_files": untracked.splitlines(),
        "recorded_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "runner_sha256": hashlib.sha256((ROOT / "scripts/devnet-current-e2e.sh").read_bytes()).hexdigest(),
        "ledger_generator_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    }
    write_immutable(path, value)
    return value


def pointer(document, path):
    value = document
    require(path.startswith("/"), f"invalid evidence pointer {path}")
    for part in path[1:].split("/"):
        key = part.replace("~1", "/").replace("~0", "~")
        value = value[int(key)] if isinstance(value, list) else value[key]
    return value


def exact(left, right):
    # JSON bool is not an integer. Floats are never accepted as economic facts.
    return json.dumps(left, sort_keys=True) == json.dumps(right, sort_keys=True)


class Evidence:
    def __init__(self, run, cli):
        self.directory = run / "scenarios"
        self.cli = cli
        self.documents = {}

    def reference(self, filename):
        path = Path(filename)
        if not path.is_absolute():
            path = self.directory / path
        path = path.resolve(strict=True)
        require(path.is_file() and path.is_relative_to(self.directory.resolve()),
                f"evidence must be a file inside the scenario directory: {path}")
        return path.relative_to(self.directory).as_posix()

    def document(self, filename):
        name = self.reference(filename)
        if name not in self.documents:
            self.documents[name] = read_json(self.directory / name)
        return self.documents[name]

    def inspect(self, name, command, filename):
        reference = self.reference(filename)
        environment = {key: value for key, value in os.environ.items()
                       if "PRIVATE_KEY" not in key and "AUTH_TOKEN" not in key}
        arguments = [str(self.cli), command, str(self.directory / reference)]
        if command == "validate-multi-asset-package":
            arguments.append("--json")
        result = json.loads(subprocess.check_output(arguments, cwd=ROOT, env=environment, text=True))
        destination = self.directory / "smoke" / "ledger-evidence" / f"{name}.json"
        write_immutable(destination, result)
        return self.reference(destination), result

    def scenario(self, identifier, description, check, tags):
        return {"schema": "morph.current_stateful_scenario.v1", "scenario_id": identifier,
                "category": "current_native_acceptance", "description": description,
                "references": [], "required_committed_checks": [check],
                "expected_failures": [], "coverage": tags, "assertions": []}

    def add(self, scenario, dimension, artifact, path, expected):
        name = self.reference(artifact)
        actual = pointer(self.document(name), path)
        require(exact(actual, expected), f"{scenario['scenario_id']}: {name}{path}: expected {expected!r}, got {actual!r}")
        require(not any(item["artifact"] == name and item["pointer"] == path
                        for item in scenario["assertions"]), "duplicate evidence pointer")
        if name not in scenario["references"]:
            scenario["references"].append(name)
        scenario["assertions"].append({"dimension": dimension, "artifact": name,
                                       "pointer": path, "expected": expected})

    def keep(self, scenario, *filenames):
        for filename in filenames:
            name = self.reference(filename)
            if name not in scenario["references"]:
                scenario["references"].append(name)

    def check(self, scenario, dimension, report, check):
        checks = self.document(report)["operator_checks"]
        require(checks.count(check) == 1, f"missing or duplicated operational fact: {check}")
        self.add(scenario, dimension, report, f"/operator_checks/{checks.index(check)}", check)


def ckb_assets(reserve, business):
    return [{"type_hash": None, "reserve": str(reserve * 100_000_000),
             "business_ckb": str(business * 100_000_000), "amount": "0"}]


def generate(run, cli):
    provenance = capture_provenance(run, "post_run")
    evidence = Evidence(run, cli)
    shared_path = "smoke/shared-acceptance.json"
    splice_path = "smoke/acceptance.json"
    factory_path = "smoke/factory-acceptance.json"
    watch_path = "smoke/watch-service-acceptance.json"
    maximum_path = "smoke/eight-asset-acceptance.json"
    shared, splice, factory, watched, maximum = [evidence.document(path) for path in
        (shared_path, splice_path, factory_path, watch_path, maximum_path)]
    require(shared["schema"] == watched["schema"] == maximum["schema"] ==
            "morph.multi_asset_devnet_acceptance.v1", "unexpected bilateral acceptance schema")
    require(splice["schema"] == "morph.current_splice_devnet_acceptance.v1", "unexpected splice schema")
    require(factory["schema"] == "morph.current_factory_acceptance.v1", "unexpected Factory schema")
    scenarios = []

    initial_path, initial = evidence.inspect("root-initial-exit", "validate-multi-asset-package",
                                            shared["pre_funding_recovery_package"])
    require(initial["state_number"] == "1" and initial["vault_count"] == 2,
            "root initial recovery must be complete state 1 with both assets")
    scenario = evidence.scenario("root_funding", "Independent funding wallets preserve a complete initial exit and hand off the same signer paths.",
        "bilateral_shared", ["state_authority_authenticity", "state_retirement_non_orphaning", "negative_recovery_continuity"])
    evidence.add(scenario, "state", shared_path, "/activation/resulting_state", {"state_number": "0", "phase": "active"})
    evidence.add(scenario, "assets", shared_path, "/summary/assets", initial["assets"])
    evidence.check(scenario, "persistence", shared_path, "independent_initial_exit_before_creation_and_same_path_confirmation")
    evidence.check(scenario, "authority", shared_path, "three_distinct_funders_signed_only_their_own_groups")
    evidence.check(scenario, "authority", shared_path, "unsigned_wallet_preflight_cannot_poison_funding_artifact")
    evidence.keep(scenario, initial_path, shared["pre_funding_recovery_package"], shared["root_funding_terms"], shared["root_funding_draft"])
    scenarios.append(scenario)

    transitions = splice["transitions"]
    require(len(transitions["operations"]) == 2, "splice must demonstrate removal and admission")
    scenario = evidence.scenario("bilateral_splice", "Exact-transaction asset removal and admission reconcile withheld bridge receipts without replacing signer authority.",
        "bilateral_splice", ["signed_descriptor_evolution", "typed_asset_binding", "state_retirement_non_orphaning", "budget_regression"])
    for index, operation in enumerate(("remove", "admit")):
        entry = transitions["operations"][index]
        require(entry["operation"] == operation, "unexpected native splice operation")
        evidence.add(scenario, "state", splice_path, f"/transitions/operations/{index}/submission/status", "Committed")
        evidence.add(scenario, "persistence", splice_path, f"/transitions/operations/{index}/withheld_bridge_receipt_reconciled", True)
    final_path, final = evidence.inspect("splice-final-exit", "validate-multi-asset-package", transitions["terminal"][0]["durable_package"])
    evidence.add(scenario, "assets", splice_path, "/transitions/summary/assets", final["assets"])
    evidence.add(scenario, "authority", splice_path, "/transitions/operations/1/activation/canonical_confirmed", True)
    evidence.keep(scenario, transitions["trace_file"], final_path, transitions["terminal"][0]["durable_package"])
    scenarios.append(scenario)

    scenario = evidence.scenario("bilateral_unilateral_close", "A saved signed settling package publishes and finalises after canonical relative maturity.",
        "bilateral_splice", ["canonical_relative_maturity", "state_retirement_non_orphaning"])
    evidence.add(scenario, "state", splice_path, "/transitions/terminal/1/status", "Committed")
    evidence.add(scenario, "assets", splice_path, "/transitions/terminal/1/package/assets", final["assets"])
    evidence.add(scenario, "authority", splice_path, "/transitions/terminal/1/canonical_confirmed", True)
    evidence.add(scenario, "state", splice_path, "/transitions/terminal/1/resulting_state", None)
    evidence.keep(scenario, final_path)
    scenarios.append(scenario)

    factory_transitions = factory["transitions"]
    for name, identifier, reserve, business, quantities in [
        ("escape", "factory_reduced_escape", 239, 61, ["3000000000", "13000000000"]),
        ("deposit", "factory_deposit", 439, 61, ["23000000000", "13000000000"]),
    ]:
        entry = factory_transitions[name]
        review_path, review = evidence.inspect(f"factory-{name}", "inspect-factory-request", entry["request"])
        require([right["quantity"] for right in review["target_rights"]] == quantities,
                f"{name}: incorrect per-member claims")
        scenario = evidence.scenario(identifier,
            "A withheld all-member approval remains recorded while an explicit unilateral escape spends the exact source." if name == "escape" else
            "A member deposits explicit wallet value, updates its backed claim, and the peer refreshes from public changes.",
            "factory_custody_and_children", ["factory_value_delta_binding"] +
            (["non_interference_not_authorisation", "negative_recovery_continuity"] if name == "escape" else []))
        evidence.add(scenario, "state", factory_path, f"/transitions/{name}/report/status", "Committed")
        evidence.add(scenario, "assets", review_path, "/target/assets", ckb_assets(reserve, business))
        evidence.add(scenario, "assets", review_path, "/target_rights", review["target_rights"])
        evidence.add(scenario, "authority", factory_path, "/transitions/peer_refreshed_from_public_changes", True)
        if name == "escape":
            evidence.add(scenario, "persistence", factory_path, "/transitions/previous_approval_not_revoked", True)
            evidence.add(scenario, "authority", factory_path, "/transitions/withheld_full_consent_escaped", True)
            evidence.add(scenario, "persistence", factory_path, "/transitions/stale_context_preserves_journal", True)
        evidence.keep(scenario, entry["request"], entry["transaction"])
        scenarios.append(scenario)

    for kind, identifier, reserve, business in [
        ("reduced", "factory_children", 180, 20),
        ("terminal", "factory_terminal_materialisation", 259, 41),
    ]:
        child = factory_transitions["child"][kind]
        base = f"/transitions/child/{kind}"
        require(len(child["private_exits"]) == len(child["same_path_handoffs"]) ==
                len(child["independent_update"]) == 2, "child requires two independent signer paths")
        review_path, review = evidence.inspect(f"factory-child-{kind}", "inspect-factory-request", child["parent"]["request"])
        require(review["missing_deliveries"] == [] and review["delivery_count"] == 2,
                "parent approval requires two complete private-exit possession receipts")
        scenario = evidence.scenario(identifier,
            "An independently signed private child exit precedes parent approval; the same child paths update, correct a stale state, and finalise." +
            (" The terminal all-member operation retires all parent custody and refunds its carrier." if kind == "terminal" else ""),
            "factory_custody_and_children", ["factory_value_delta_binding", "state_retirement_non_orphaning"])
        evidence.add(scenario, "state", factory_path, base + "/finalise/status", "Committed")
        evidence.add(scenario, "authority", factory_path, base + "/initial_exit_required_before_parent_vote", True)
        evidence.add(scenario, "authority", factory_path, base + "/private_exit_signatures_absent_from_parent", True)
        evidence.add(scenario, "state", factory_path, base + "/latest_package_watch/publication/canonical_confirmed", True)
        for index in range(2):
            saved_path, saved = evidence.inspect(f"child-{kind}-exit-{index}", "validate-multi-asset-package", child["private_exits"][index])
            latest_path, latest = evidence.inspect(f"child-{kind}-latest-{index}", "validate-multi-asset-package", child["independent_update"][index]["recovery_package"])
            require(saved["state_number"] == "1" and latest["state_number"] == "2", "child recovery/update numbers are incorrect")
            evidence.add(scenario, "persistence", factory_path, base + f"/same_path_handoffs/{index}/session/current/package_id", saved["package_id"])
            evidence.add(scenario, "authority", factory_path, base + f"/same_path_handoffs/{index}/session/lineage/origin/kind", "factory")
            evidence.add(scenario, "assets", latest_path, "/assets", ckb_assets(reserve, business))
            handoff = child["same_path_handoffs"][index]
            evidence.keep(scenario, saved_path, child["private_exits"][index],
                          handoff["initial_exit_archive"], handoff["factory_origin_archive"])
        evidence.add(scenario, "assets", factory_path, base + "/external_child_carrier", "49600000000")
        evidence.add(scenario, "authority", review_path, "/delivery_count", 2)
        if kind == "terminal":
            evidence.add(scenario, "state", factory_path, base + "/retained_factory/retired", True)
            evidence.add(scenario, "assets", factory_path, base + "/retained_factory/carrier_refund/capacity", "50000000000")
            evidence.add(scenario, "state", review_path, "/target", None)
        else:
            evidence.add(scenario, "assets", review_path, "/target/assets", ckb_assets(259, 41))
        evidence.keep(scenario, child["parent"]["request"], child["parent"]["transaction"])
        scenarios.append(scenario)

    scenario = evidence.scenario("watch_service_reorg", "The continuous watch service publishes with a bounded sponsor, persists health, and rescans canonical history after a reorg.",
        "watch_service_reorg", ["watchtower_authority_and_cursor", "sponsor_policy_boundary", "negative_recovery_continuity"])
    watch_initial_path, watch_initial = evidence.inspect("watch-initial-exit", "validate-multi-asset-package", watched["pre_funding_recovery_package"])
    evidence.add(scenario, "state", watch_path, "/finalise/status", "Committed")
    evidence.add(scenario, "assets", watch_path, "/summary/assets", watch_initial["assets"])
    evidence.check(scenario, "authority", watch_path, "sponsor_fee_cap_rejected")
    evidence.check(scenario, "persistence", watch_path, "current_watch_service_health_verified")
    evidence.check(scenario, "reorg", watch_path, "watch_reorg_rescan_republished")
    service_passes = [(index, entry) for index, entry in enumerate(watched["watch_passes"])
                      if entry.get("service", {}).get("published_count") == 1]
    require(len(service_passes) == 1, "expected exactly one current service publication pass")
    index, entry = service_passes[0]
    evidence.add(scenario, "state", watch_path, f"/watch_passes/{index}/service/published_count", 1)
    reorgs = [(index, entry["reorg_recovery"]) for index, entry in enumerate(watched["watch_passes"])
              if entry.get("reorg_recovery")]
    require(reorgs, "missing actual cursor reorg recovery")
    index, reorg = reorgs[-1]
    require(reorg["reason"] in ("cursor_block_hash_mismatch", "cursor_block_missing", "cursor_missing_block_hash"),
            f"unknown canonical reorg reason: {reorg['reason']}")
    require(reorg["reset_from_block"] <= reorg["cursor_scanned_to_block"], "reorg did not rewind cursor")
    evidence.add(scenario, "reorg", watch_path, f"/watch_passes/{index}/reorg_recovery/reason", reorg["reason"])
    evidence.keep(scenario, watch_initial_path, "smoke/watch-service-packages/current-watch-service-health.json")
    scenarios.append(scenario)

    scenario = evidence.scenario("maximum_asset_lifecycle", "The full eight-asset complete set is independently funded, activated, updated and settled on the development chain; this is no-value dimension evidence.",
        "maximum_asset_lifecycle", ["typed_asset_binding", "budget_regression"])
    maximum_initial_path, maximum_initial = evidence.inspect("maximum-initial-exit", "validate-multi-asset-package", maximum["pre_funding_recovery_package"])
    require(maximum_initial["vault_count"] == len(maximum_initial["assets"]) == 8, "maximum lifecycle must preserve all eight assets")
    evidence.add(scenario, "state", maximum_path, "/finalise/status", "Committed")
    evidence.add(scenario, "assets", maximum_path, "/summary/assets", maximum_initial["assets"])
    evidence.add(scenario, "assets", maximum_path, "/asset_count", 8)
    evidence.check(scenario, "authority", maximum_path, "three_distinct_funders_signed_only_their_own_groups")
    evidence.keep(scenario, maximum_initial_path, maximum["pre_funding_recovery_package"])
    scenarios.append(scenario)

    require(len(scenarios) == 9, "incomplete current stateful matrix")
    for scenario in scenarios:
        write_immutable(evidence.directory / f"{scenario['scenario_id']}.json", scenario)
    unchanged = (provenance["git_commit_full"] == git("rev-parse", "HEAD") and
                 provenance["source_tree_sha256"] == source_digest())
    # Post-run capture never upgrades old artifacts to clean evidence, even if
    # the operator happened to commit before invoking this generator.
    dirty = provenance["git_dirty"] or provenance["phase"] != "pre_build" or not unchanged
    manifest = {
        "schema": "morph.current_stateful_matrix.v1", "status": "passed",
        "git_commit": provenance["git_commit"], "git_commit_full": provenance["git_commit_full"],
        "git_dirty": str(dirty).lower(), "provenance_phase": provenance["phase"],
        "source_unchanged": str(unchanged).lower(), "source_tree_sha256": provenance["source_tree_sha256"],
        "recorded_at_utc": provenance["recorded_at_utc"],
        "scope": "development-only; maximum dimensions do not approve pilot admission or real assets",
    }
    raw = "".join(f"{key}={value}\n" for key, value in manifest.items()).encode()
    path = evidence.directory / "manifest.txt"
    if path.exists():
        require(path.read_bytes() == raw, "refusing to restamp an existing stateful manifest")
    else:
        with path.open("xb") as output:
            output.write(raw)
    print(f"[current-ledger] nine verified scenarios; {sum(len(s['assertions']) for s in scenarios)} evidence assertions; provenance={provenance['phase']}; dirty={str(dirty).lower()}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", required=True, type=Path)
    parser.add_argument("--cli", type=Path)
    parser.add_argument("--capture-provenance", action="store_true")
    args = parser.parse_args()
    run = args.run_dir.resolve(strict=True)
    if args.capture_provenance:
        capture_provenance(run, "pre_build")
        print(f"[current-ledger] captured immutable pre-build provenance: {run}")
        return
    generate(run, (args.cli or run / "morph-cli").resolve(strict=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        print(f"[current-ledger] {error}", file=sys.stderr)
        sys.exit(1)
