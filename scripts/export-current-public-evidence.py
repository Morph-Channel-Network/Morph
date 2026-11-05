#!/usr/bin/env python3
"""Export bounded, allowlisted public evidence from a completed current run.

This does not execute a protocol, sign, query RPC, or turn local evidence into
an independent attestation. Original private packages and journals are omitted.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_PUBLIC_BYTES = 2 * 1024 * 1024
SCRIPTS = {
    "morph-state-lock", "morph-state-type", "morph-factory-type",
    "morph-factory-vault-lock", "morph-vault-lock", "morph-batch-lock",
    "morph-sponsor-lock", "morph-devnet-xudt",
}
AUDIT_FAMILIES = set("""state_authority_authenticity signed_descriptor_evolution
non_interference_not_authorisation typed_asset_binding state_retirement_non_orphaning
canonical_relative_maturity sponsor_policy_boundary factory_value_delta_binding
watchtower_authority_and_cursor negative_recovery_continuity budget_regression""".split())
CASE_KINDS = {
    "bilateral_shared": "bilateral_shared", "bilateral_splice": "splice",
    "factory_custody_and_children": "factory", "watch_service_reorg": "watch_service",
    "maximum_asset_lifecycle": "bilateral_max_assets", "deployment": "deployment",
}
CASES = {
    "bilateral_shared", "bilateral_splice", "factory_custody_and_children",
    "watch_service_reorg", "maximum_asset_lifecycle",
}
SCENARIOS = {
    "root_funding", "bilateral_splice", "bilateral_unilateral_close",
    "factory_reduced_escape", "factory_deposit", "factory_children",
    "factory_retained_materialisation", "factory_terminal_materialisation", "watch_service_reorg", "maximum_asset_lifecycle",
}
PUBLIC_ARTIFACTS = {
    "smoke/acceptance.json", "smoke/shared-acceptance.json",
    "smoke/factory-acceptance.json", "smoke/watch-service-acceptance.json",
    "smoke/eight-asset-acceptance.json",
} | {
    f"smoke/ledger-evidence/{name}.json" for name in (
        "child-reduced-latest-0", "child-reduced-latest-1",
        "child-terminal-latest-0", "child-terminal-latest-1",
        "child-retained-latest-0", "child-retained-latest-1",
        "factory-child-reduced", "factory-child-retained", "factory-child-terminal", "factory-deposit", "factory-escape",
    )
}
POINTER_PARTS = set("""transitions operations submission status
withheld_bridge_receipt_reconciled summary assets activation canonical_confirmed
terminal package resulting_state child reduced retained finalise
initial_exit_required_before_parent_vote private_exit_signatures_absent_from_parent
latest_package_watch publication same_path_handoffs session current package_id
lineage origin kind external_child_carrier delivery_count target retained_factory
retired carrier_refund capacity escape deposit report peer_refreshed_from_public_changes
previous_approval_not_revoked withheld_full_consent_escaped stale_context_preserves_journal
target_rights operator_checks service published_count watch_passes reorg_recovery reason
asset_count rights_updates full_consent_metadata changed_right_count funding_replay
orphaned exact_body_and_witnesses unchanged_signer_journals peer_creation_receipt_withheld
canonical_reorg_replay authentic_source_live no_new_participant_signatures""".split())
VALUE_FIELDS = {
    "type_hash", "reserve", "business_ckb", "amount", "state_number", "phase",
    "asset_type", "kind", "participant", "quantity", "subchannel",
}
TOTAL_FIELDS = (
    "transaction_count", "committed_count", "pending_count", "total_estimated_cycles",
    "max_estimated_cycles", "total_tx_size_bytes", "max_tx_size_bytes",
)
TX_FIELDS = ("check", "path", "tx_hash", "status", "block_number", "estimated_cycles", "tx_size_bytes")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def decode(raw):
    require(len(raw) <= MAX_JSON_BYTES, "oversized JSON evidence")
    return json.loads(raw, object_pairs_hook=unique_object)


def token(value):
    require(isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,100}", value), "invalid public identifier")
    return value


def integer(value):
    require(type(value) is int and value >= 0, "invalid nonnegative integer")
    return value


def digest(value, prefixed=False):
    pattern = r"0x[0-9a-f]{64}" if prefixed else r"[0-9a-f]{64}"
    require(isinstance(value, str) and re.fullmatch(pattern, value), "invalid digest")
    return value


def commit(value):
    require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{40}", value), "invalid source commit")
    return value


def bounded_file(root, relative):
    require(not Path(relative).is_absolute(), "absolute artifact reference")
    path = (root / relative).resolve(strict=True)
    require(path.is_relative_to(root.resolve()) and path.is_file(), "artifact leaves run directory")
    require(path.stat().st_size <= MAX_JSON_BYTES, "oversized evidence file")
    return path


class Reader:
    def __init__(self, root):
        self.root = root
        self.raw = {}

    def read(self, relative):
        if relative not in self.raw:
            self.raw[relative] = bounded_file(self.root, relative).read_bytes()
        return decode(self.raw[relative])


def provenance(source, manifest, expected_commit=None):
    require(source["schema"] == "morph.current_run_provenance.v1", "unsupported source provenance")
    require(source["phase"] == "pre_build" and source["git_dirty"] is False, "run was not clean before building")
    actual = commit(source["git_commit_full"])
    if expected_commit is not None:
        require(commit(expected_commit) == actual, "requested commit does not match actual run source")
    require(manifest["schema"] == "morph.current_stateful_matrix.v1" and manifest["status"] == "passed", "stateful run did not pass")
    require(manifest["git_commit_full"] == actual and manifest["git_dirty"] == "false", "manifest source mismatch or dirty run")
    require(manifest["provenance_phase"] == "pre_build" and manifest["source_unchanged"] == "true", "source changed or post-run provenance")
    require(manifest["source_tree_sha256"] == source["source_tree_sha256"], "source digest mismatch")
    recorded = source["recorded_at_utc"]
    require(isinstance(recorded, str) and re.fullmatch(r"[0-9T:.+Z-]{20,40}", recorded), "invalid recorded time")
    return {
        "source_commit": actual, "provenance_phase": "pre_build", "git_dirty": False,
        "source_unchanged": True, "recorded_at_utc": recorded,
        "source_tree_sha256": digest(source["source_tree_sha256"]),
        "runner_sha256": digest(source["runner_sha256"]),
        "ledger_generator_sha256": digest(source["ledger_generator_sha256"]),
    }


def project_transactions(items):
    result = []
    hashes = set()
    for item in items:
        value = {key: item[key] for key in TX_FIELDS}
        token(value["check"])
        require(value["check"] in CASES | {"deployment"}, "unknown transaction case")
        digest(value["tx_hash"], True)
        require(value["tx_hash"] not in hashes, "duplicate transaction hash")
        hashes.add(value["tx_hash"])
        require(value["status"] == "Committed", "noncommitted unique transaction")
        require(isinstance(value["path"], str) and re.fullmatch(r"\$[A-Za-z0-9_.\[\]]{0,240}", value["path"]), "invalid transaction locator")
        if value["block_number"] is not None:
            integer(value["block_number"])
        for key in ("estimated_cycles", "tx_size_bytes"):
            integer(value[key])
        result.append(value)
    require(result, "no transactions")
    return result


def public_value(value):
    if value is None or type(value) in (bool, int):
        return value
    if isinstance(value, str):
        require(len(value) <= 100 and re.fullmatch(r"[A-Za-z0-9_]+", value), "nonpublic assertion string")
        if value.startswith("0x"):
            digest(value, True)
        return value
    if isinstance(value, list):
        require(len(value) <= 16, "oversized assertion list")
        return [public_value(item) for item in value]
    require(isinstance(value, dict) and set(value) <= VALUE_FIELDS, "private or unsupported assertion fields")
    return {key: public_value(item) for key, item in value.items()}


def inspect_assertion(reader, item):
    artifact = item["artifact"]
    require(artifact in PUBLIC_ARTIFACTS, "assertion references private or unsupported artifact")
    pointer = item["pointer"]
    require(isinstance(pointer, str) and pointer.startswith("/"), "invalid assertion pointer")
    parts = pointer[1:].split("/")
    require(all(part in POINTER_PARTS or (part.isdecimal() and int(part) <= 64) for part in parts), "private or unsupported assertion pointer")
    observed = reader.read("scenarios/" + artifact)
    for part in parts:
        observed = observed[int(part)] if isinstance(observed, list) else observed[part]
    expected = public_value(item["expected"])
    require(json.dumps(observed, sort_keys=True) == json.dumps(expected, sort_keys=True), "assertion does not match retained evidence")
    dimension = token(item["dimension"])
    require(dimension in {"state", "assets", "persistence", "reorg", "authority"}, "unknown assertion dimension")
    return {"dimension": dimension, "source_artifact": artifact,
            "pointer": pointer, "expected": expected, "matched": True}


def public_contract_manifest(source):
    require(source["schema"] == "morph.contract_release_manifest", "unsupported ELF manifest")
    require(source["release_profile"] == "morph-current-custody", "wrong release profile")
    require(source["target"] == "riscv64imac-unknown-none-elf" and source["build_profile"] == "release" and source["cargo_locked"] is True, "unexpected contract build profile")
    require(re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", source["rust_toolchain"]), "invalid Rust version")
    scripts = []
    for item in source["scripts"]:
        require(item["name"] in SCRIPTS and item["file"] == item["name"], "unexpected script name")
        require(item["deployment_scope"] in {"controlled_devnet", "devnet_only"}, "unexpected deployment scope")
        scripts.append({"name": item["name"], "file": item["file"], "deployment_scope": item["deployment_scope"],
                        "size_bytes": integer(item["size_bytes"]), "ckb_data_hash": digest(item["ckb_data_hash"], True)})
    return {key: source[key] for key in ("schema", "release_profile", "rust_toolchain", "target", "build_profile", "cargo_locked")} | {"scripts": scripts}


def contract_evidence(reader, manifest, recorded_hashes):
    require(manifest["schema"] == "morph.contract_release_manifest", "unsupported ELF manifest")
    require({item["name"] for item in manifest["scripts"]} == SCRIPTS and len(manifest["scripts"]) == 8, "expected all eight scripts")
    require(set(recorded_hashes) == SCRIPTS, "captured ELF hash set differs")
    result = []
    for item in manifest["scripts"]:
        name = item["name"]
        require(item["file"] == name, "noncanonical script filename")
        raw = bounded_file(reader.root, "scenarios/smoke/contracts/" + name).read_bytes()
        require(raw.startswith(b"\x7fELF") and len(raw) == item["size_bytes"], "ELF size or format mismatch")
        actual_sha = sha256(raw)
        actual_ckb = "0x" + hashlib.blake2b(raw, digest_size=32, person=b"ckb-default-hash").hexdigest()
        require(actual_sha == digest(recorded_hashes[name]), "captured ELF SHA-256 mismatch")
        require(actual_ckb == digest(item["ckb_data_hash"], True), "ELF CKB data hash mismatch")
        result.append({"name": name, "size_bytes": len(raw), "sha256": actual_sha, "ckb_data_hash": actual_ckb})
    return result


def public_budget_limits(policy):
    """Keep nonuniform case, transaction and proof ceilings explicitly scoped."""
    require(policy["schema"] == "morph.current_acceptance_budget.v1", "unsupported source budget")
    limits = {key: integer(policy[key]) for key in ("max_total_cycles", "max_tx_cycles", "max_total_bytes", "max_tx_bytes")}
    require({item["name"] for item in policy["cases"]} == CASES | {"deployment"}, "wrong source budget cases")
    optional = lambda value: integer(value) if value is not None else None
    limits["cases"] = [{"name": token(item["name"]), **{key: optional(item[key])
        for key in ("max_cycles", "max_bytes", "max_tx_cycles", "max_tx_bytes")}} for item in policy["cases"]]
    limits["transactions"] = []
    for item in policy["transactions"]:
        require(item["check"] in CASES | {"deployment"}, "unknown transaction budget case")
        path = item["path"]
        require(isinstance(path, str) and re.fullmatch(r"\$[A-Za-z0-9_.\[\]]{0,240}", path), "invalid budget transaction path")
        limits["transactions"].append({"check": item["check"], "path": path,
            **{key: optional(item[key]) for key in ("max_cycles", "max_bytes")}})
    limits["proof_profiles"] = []
    for item in policy["proof_profiles"]:
        require(item["check"] in CASES | {"deployment"}, "unknown proof budget case")
        limits["proof_profiles"].append({"check": item["check"], "operation": token(item["operation"]),
            **{key: optional(item[key]) for key in ("max_witness_len", "max_proof_siblings", "max_cycles", "max_bytes")}})
    return limits


def ci_results(raw):
    require(len(raw) <= 20 * 1024 * 1024, "oversized CI log")
    lines = raw.decode(errors="replace").splitlines()
    selected = []
    contract_vm = None
    in_contract_tests = False
    patterns = (
        r"test [A-Za-z0-9_:]+ \.\.\. (?:ok|ignored)",
        r"test result: ok\. [0-9]+ passed; 0 failed; [0-9]+ ignored; [0-9]+ measured; [0-9]+ filtered out; finished in [0-9.]+s",
        r"Ran [0-9]+ tests in [0-9.]+s", r"OK",
        r"Tests\s+[0-9]+ passed \([0-9]+\)",
        r"Test Files\s+[0-9]+ passed \([0-9]+\)",
        r"Morph current custody release-readiness documents verified",
    )
    for index, line in enumerate(lines, 1):
        clean = line.strip()
        if "Running tests/contract_scripts.rs " in clean:
            in_contract_tests = True
        match = re.fullmatch(r"test result: ok\. ([0-9]+) passed; 0 failed; ([0-9]+) ignored; [0-9]+ measured; [0-9]+ filtered out; finished in [0-9.]+s", clean)
        if in_contract_tests and match:
            if int(match.group(1)) > 0 and int(match.group(2)) == 0:
                contract_vm = {"passed": int(match.group(1)), "failed": 0, "ignored": 0}
            in_contract_tests = False
        if re.search(r"(?:0x)?[0-9a-fA-F]{64,}", clean):
            continue
        if any(re.fullmatch(pattern, clean) for pattern in patterns):
            selected.append({"line": index, "result": clean})
    return {"schema": "morph.public_local_ci_evidence.v1", "original_log_sha256": sha256(raw),
            "original_log_size_bytes": len(raw), "publication": "allowlisted result lines only; original stdout omitted",
            "local_reporting_only": True, "contract_vm_tests": contract_vm, "result_lines": selected}


def readme(origin, totals, tx_count, assertions, audits, native_cycles, ci):
    return f"""# Public local migration evidence

Protocol checkpoint: `{origin['source_commit']}`. This package preserves that
original run's source identity. A later PR commit may add publication tooling,
CI or documentation; it does not change which protocol checkpoint these local
results measured.

This is a whitelist export of retained local records, not an independent
attestation, a public-network finality proof or production approval.

## Recorded results

| Item | Local result |
| --- | ---: |
| Native acceptance cases | 5 |
| Derived stateful scenarios | {len(SCENARIOS)} |
| Exact retained-artifact assertions | {assertions} |
| Passing audit categories | {audits} |
| CKB-VM tests in supplied local CI stdout | {ci["contract_vm_tests"]["passed"] if ci and ci["contract_vm_tests"] else "Not inferred"} |
| Distinct transaction hashes observed as Committed | {tx_count} |
| Total measured cycles | {totals['total_estimated_cycles']:,} |
| Maximum measured transaction cycles | {totals['max_estimated_cycles']:,} |
| Total transaction bytes | {totals['total_tx_size_bytes']:,} |
| Maximum transaction bytes | {totals['max_tx_size_bytes']:,} |
| Matching ELF CKB/SHA hashes and sizes | 8 |

The pre-build record says `git_dirty=false`, and the completed manifest says
`source_unchanged=true`. These are the original run's records, not a fresh
statement about the tree that exports or publishes this directory.

There are six resource groups: five native cases plus eight ELF deployment
transactions. Transactions are deduplicated by hash; group totals do not add a
second copy of deployment. The run deliberately exercises a chain rollback.
Committed status describes the observation at that step and does not assert
that every historical branch transaction is canonical at the final tip.

## Resource scopes

The source-commit default node profile has a {native_cycles:,}-cycle outer
transaction ceiling. Individual cases, named transactions and proof shapes
retain their explicit stricter limits, all exported in `resource-budgets.json`.
This does not assign the largest ceiling to every native operation.
The separate 70,000,000-cycle joint-dimension CKB-VM
fixture ceiling is not this native-node ceiling, and is not a universal bound
for arbitrary wallet/asset scripts or all proof topologies.

Maximum-dimension VM fixture measurements are documented in
[`current-protocol-coverage.md`](https://github.com/Morph-Channel-Network/Morph/blob/{origin['source_commit']}/docs/current-protocol-coverage.md#measured-dimensional-limits).
Retained Factory floors, proof-data availability and signer rollback assumptions
remain material. Full external Fiber/Bruno traffic was not executed in this
migration checkpoint; no real-asset or mainnet admission is implied.

## Files and publication boundary

- `checkpoint.json`: original source identity, counts, public node genesis and
  captured CLI/ELF hashes; the CLI and ELFs are not copied into this directory.
- `contracts.json`: the canonical eight-script release manifest, with only its
  published manifest fields. Rebuilt ELF bytes must match it.
- `transactions.json`: public hashes, observed status, block number when
  recorded, cycle/byte measurements and resource groups.
- `acceptance.json`: all {assertions} allowlisted assertion expectations, matched
  again against the retained local artifacts during export, plus audit results.
- `publication-policy.json`: the actual bounded watch publication fee and
  challenge-window policy retained by this run.
- `source-artifacts.json`: exact hashes/sizes of source records, without copying
  their potentially private contents.
- `resource-budgets.json`: public default budget fields read from the actual
  source commit, rather than a later mutable working tree.
{"- `ci-results.json`: original local CI stdout hash/size and strictly allowlisted passing test/result lines. Freeform stdout is omitted." if ci else "- No CI stdout was supplied to this export; no CI result is inferred here."}
- `SHA256SUMS`: checksums of every public file above, including this README.

Private journals, private initial-exit packages/signatures, raw witnesses,
signed unbroadcast transactions, keys, tokens and absolute home paths are
omitted. The hashes and filtered records make the local claim inspectable;
they do not independently establish the contents of withheld recovery data.

## Verify or reproduce

Verify the public package's own bytes:

```sh
sha256sum -c SHA256SUMS
```

On a clean checkout of the recorded source commit, run:

```sh
make ci
```

Run an isolated node using the same public disposable fixture scalars 1, 2
and 3 as the CI workflow. This example supplies them directly to the child
process without printing key values or requiring a separate Fiber checkout:

```sh
python3 - <<'FIXTURE'
import os
import subprocess

env = os.environ.copy()
for scalar, name in enumerate(("MORPH_DEVNET_PRIVATE_KEY", "MORPH_ALICE_PRIVATE_KEY", "MORPH_BOB_PRIVATE_KEY"), 1):
    env[name] = format(scalar, "064x")
env["CKB_BIN"] = "/path/to/ckb"
env["OUT_DIR"] = "target/current-protocol-e2e/reproduction"
subprocess.run(["bash", "scripts/devnet-current-e2e.sh"], env=env, check=True)
FIXTURE
```

These scalars are public test data for a disposable development chain; use no
real funds. See the repository CI workflow for its pinned CKB download and the
same fixture setup. A fresh run has new transaction hashes and its own immutable
provenance; it must pass artifact, budget, audit-category and source-freshness
checks. The original checkpoint's private key files are not needed or published.

On a checkout containing the publication tool, export a completed run with:

```sh
python3 -B scripts/export-current-public-evidence.py --run-dir target/current-protocol-e2e/reproduction --source-commit FULL_RECORDED_COMMIT --ci-log target/reproduction-ci.log --output-dir target/current-public-evidence
```

`--source-commit` verifies the recorded full commit and cannot relabel it. Use a
fresh output directory. `--ci-log` is optional and never uploads raw stdout.
The original private run directory must not be uploaded as a substitute.
"""


def export(run, output, expected_commit=None, ci_log=None):
    reader = Reader(run.resolve(strict=True))
    original = reader.read("source-provenance.json")
    manifest_raw = bounded_file(reader.root, "scenarios/manifest.txt").read_bytes()
    manifest = dict(line.split("=", 1) for line in manifest_raw.decode().splitlines())
    origin = provenance(original, manifest, expected_commit)
    facts = reader.read("evidence.json")
    smoke = reader.read("scenarios/smoke/summary.json")
    assertion = reader.read("scenarios/summary-check.json")
    stateful = reader.read("scenarios/summary.json")
    contracts = public_contract_manifest(reader.read("scenarios/smoke/contracts.json"))
    elf_hashes = contract_evidence(reader, contracts, facts["contract_sha256"])
    release_raw = subprocess.check_output(["git", "show", f"{origin['source_commit']}:release/factory-preproduction/contracts.json"], cwd=ROOT)
    require(public_contract_manifest(decode(release_raw)) == contracts, "captured ELF manifest differs from source-commit release manifest")
    txs = project_transactions(smoke["transactions"])
    require(len(txs) == assertion["smoke"]["transaction_count"] == smoke["totals"]["transaction_count"], "transaction count mismatch")
    cases = []
    for item in smoke["cases"]:
        name = token(item["name"])
        require(name in CASES | {"deployment"}, "unsupported resource group")
        require(item["kind"] == CASE_KINDS[name], "wrong resource-group kind")
        cases.append({"name": name, "kind": item["kind"],
                      "totals": {key: integer(item["totals"][key]) for key in TOTAL_FIELDS}})
    require({item["name"] for item in cases} == CASES | {"deployment"}, "missing resource group")
    public_scenarios = []
    for scenario in stateful["scenarios"]:
        identifier = token(scenario["scenario_id"])
        require(identifier in SCENARIOS, "unknown scenario")
        require(set(scenario["coverage"]) <= AUDIT_FAMILIES, "unknown audit coverage")
        public_scenarios.append({"scenario_id": identifier,
            "coverage": [token(tag) for tag in scenario["coverage"]],
            "assertions": [inspect_assertion(reader, item) for item in scenario["assertions"]]})
    require({s["scenario_id"] for s in public_scenarios} == SCENARIOS and len(public_scenarios) == len(SCENARIOS), "scenario set differs")
    count = sum(len(item["assertions"]) for item in public_scenarios)
    require(count == assertion["evidence_assertions"], "assertion count mismatch")
    audits = []
    for item in stateful["audit_families"]:
        require(item["passed"] is True and all(item[key] == [] for key in ("missing_tags", "missing_scenarios", "missing_checks", "missing_failures", "evidence_errors")), "audit family did not pass")
        require(item["id"] in AUDIT_FAMILIES and item["severity"] in {"P0", "P1", "P2", "P3"}, "unknown audit identifier/severity")
        audits.append({"id": item["id"], "severity": item["severity"], "passed": True})
    require(len(audits) == assertion["audit_families_passed"] == assertion["audit_families"] and {item["id"] for item in audits} == AUDIT_FAMILIES, "audit count/set mismatch")
    totals = {key: integer(smoke["totals"][key]) for key in TOTAL_FIELDS}
    require(sum(item["estimated_cycles"] for item in txs) == totals["total_estimated_cycles"] and
            sum(item["tx_size_bytes"] for item in txs) == totals["total_tx_size_bytes"] and
            max(item["estimated_cycles"] for item in txs) == totals["max_estimated_cycles"] and
            max(item["tx_size_bytes"] for item in txs) == totals["max_tx_size_bytes"] and
            totals["committed_count"] == len(txs) and totals["pending_count"] == 0, "transaction totals differ")
    cli = reader.root / "morph-cli"
    require(cli.is_file(), "captured CLI is missing")
    if cli.is_file():
        hasher = hashlib.sha256()
        with cli.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                hasher.update(block)
        require(hasher.hexdigest() == facts["cli_sha256"], "captured CLI hash mismatch")
    publication = reader.read("scenarios/smoke/publication-profile.json")
    require(publication["schema"] == "morph.publication_profile", "wrong publication profile")
    public_publication = {"schema": publication["schema"], "operator_id": token(publication["operator_id"]),
        "fee": {key: integer(publication["fee"][key]) for key in ("min_fee_rate", "max_fee_rate", "max_fee", "estimator_multiplier_bps", "replacement_multiplier_bps", "max_attempts", "bump_after_ms")},
        "window": {key: integer(publication["window"][key]) for key in ("configured_challenge_blocks", "conservative_block_ms", "canonical_confirmation_blocks", "reorg_budget_blocks", "failover_budget_blocks", "safety_margin_blocks", "max_measurement_age_secs")}}
    require(type(publication["fee"]["require_rbf"]) is bool, "invalid RBF policy")
    public_publication["fee"]["require_rbf"] = publication["fee"]["require_rbf"]
    files = {
        "checkpoint.json": {"schema": "morph.public_checkpoint_evidence.v1", **origin,
            "genesis_hash": digest(facts["genesis_hash"], True), "descriptor_version": integer(facts["descriptor_version"]),
            "cli_sha256": digest(facts["cli_sha256"]), "release_manifest_sha256": sha256(release_raw),
            "release_manifest_matches_captured": True, "contracts": elf_hashes,
            "scope": "Controlled development-node local evidence; not independent attestation or production approval.",
            "counts": {"native_cases": 5, "deployment_transactions": 8, "stateful_scenarios": len(public_scenarios),
                       "evidence_assertions": count, "audit_families": len(audits), "unique_transactions": len(txs),
                       "transaction_observations": len(smoke["transaction_observations"])},
            "totals": totals},
        "contracts.json": contracts,
        "publication-policy.json": public_publication,
        "transactions.json": {"schema": "morph.public_transaction_evidence.v1",
            "source_commit": origin["source_commit"], "status_scope": "Statuses observed during a controlled development run, including controlled reorg branches; not public-network finality.",
            "resource_groups": cases, "transactions": txs},
        "acceptance.json": {"schema": "morph.public_acceptance_evidence.v1", "source_commit": origin["source_commit"],
            "scenarios": public_scenarios, "audit_families": audits},
    }
    # The source-commit profile is public configuration, never the mutable working tree.
    policy_raw = subprocess.check_output(["git", "show", f"{origin['source_commit']}:docs/devnet-stateful-budget.example.json"], cwd=ROOT)
    policy = decode(policy_raw)
    limits = public_budget_limits(policy)
    files["resource-budgets.json"] = {"schema": "morph.public_budget_evidence.v1", "source_commit": origin["source_commit"],
        "source_profile": "docs/devnet-stateful-budget.example.json", "source_profile_sha256": sha256(policy_raw),
        "scope": "Source-commit default node profile; 70M joint-dimension VM fixture ceilings are separate measurements, not this run's native transaction budget.",
        "limits": limits}
    if ci_log is not None:
        files["ci-results.json"] = ci_results(ci_log.read_bytes())
    files["source-artifacts.json"] = {"schema": "morph.public_evidence_sources.v1", "source_commit": origin["source_commit"],
        "artifacts": [{"path": key, "size_bytes": len(value), "sha256": sha256(value)} for key, value in sorted(reader.raw.items())],
        "stateful_manifest_sha256": sha256(manifest_raw)}
    encoded = {name: (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode() for name, value in files.items()}
    encoded["README.md"] = readme(origin, totals, len(txs), count, len(audits), limits["max_tx_cycles"], files.get("ci-results.json")).encode()
    encoded["SHA256SUMS"] = "".join(f"{sha256(raw)}  {name}\n" for name, raw in sorted(encoded.items())).encode()
    require(sum(map(len, encoded.values())) <= MAX_PUBLIC_BYTES, "public evidence exceeds size bound")
    require(not output.exists(), "output already exists; use a fresh evidence directory")
    output.mkdir(parents=True)
    for name, raw in encoded.items():
        (output / name).write_bytes(raw)
    return {"source_commit": origin["source_commit"], "files": len(encoded), "bytes": sum(map(len, encoded.values())),
            "transactions": len(txs), "scenarios": len(public_scenarios), "assertions": count, "audit_families": len(audits)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--source-commit", help="Expected full commit; verifies recorded provenance and cannot relabel it")
    parser.add_argument("--ci-log", type=Path)
    args = parser.parse_args()
    print(json.dumps(export(args.run_dir, args.output_dir, args.source_commit, args.ci_log)))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError) as error:
        print(f"[public-evidence] {error}", file=sys.stderr)
        sys.exit(1)
