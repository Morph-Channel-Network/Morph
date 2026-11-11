"""Negative evidence-boundary tests; no node, private key, or wire fixture needed."""

import importlib.util
import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


HELPER = Path(__file__).resolve().parents[1] / "current-stateful-ledger.py"
SPEC = importlib.util.spec_from_file_location("current_stateful_ledger", HELPER)
LEDGER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LEDGER)


class LedgerBoundaries(unittest.TestCase):
    def test_child_close_requires_canonical_depth_payouts_and_honest_fork_labels(self):
        close = {
            "submitted": {"status": {"state": "finalised", "depth": 4}},
            "zero_since": True, "all_payouts_verified": True,
            "parent_journals_unchanged": True, "child_journals_unchanged_after_rollback": True,
            "branch": "cooperative_branch_orphaned_before_existing_unilateral_acceptance",
            "batch": {"fulfilled": {"status": "Committed"}, "refunded": {"status": "Committed"},
                      "canonical_payouts_verified": True,
                      "branches": "fulfilment_orphaned_then_refund_before_outer_close_rollback"},
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "scenarios" / "factory.json"
            path.parent.mkdir()
            def check(value, kind="terminal"):
                path.write_text(json.dumps({"transitions": {"child": {kind: {"cooperative_close": value}}}}))
                evidence = LEDGER.Evidence(root, Path("unused"))
                scenario = evidence.scenario("factory_children", "test", "factory_custody_and_children", [])
                LEDGER.child_close_assertions(evidence, scenario, path, kind)
                return scenario
            self.assertEqual(len(check(close)["assertions"]), 11)
            for kind in ("reduced", "retained"):
                ordinary = dict(close, batch=None)
                self.assertEqual(len(check(ordinary, kind)["assertions"]), 8)
            mutations = [
                ("submitted/status/state", "submitted"), ("submitted/status/depth", 3),
                ("submitted/status/depth", True), ("submitted/status/depth", 4.0),
                ("zero_since", False), ("all_payouts_verified", False),
                ("parent_journals_unchanged", False), ("child_journals_unchanged_after_rollback", False),
                ("branch", "canonical"), ("batch/fulfilled/status", "Rejected"),
                ("batch/refunded/status", "Rejected"), ("batch/canonical_payouts_verified", False),
                ("batch/branches", "both_canonical"),
            ]
            for pointer, value in mutations:
                with self.subTest(pointer=pointer, value=value):
                    changed = copy.deepcopy(close)
                    target = changed
                    keys = pointer.split("/")
                    for key in keys[:-1]: target = target[key]
                    target[keys[-1]] = value
                    with self.assertRaises(ValueError): check(changed)
            with self.assertRaises(KeyError): check({})

    def test_existing_provenance_cannot_be_recaptured_or_upgraded(self):
        with tempfile.TemporaryDirectory() as directory:
            run = Path(directory)
            provenance = {"schema": "morph.current_run_provenance.v1", "phase": "post_run",
                          "git_commit": "old", "git_dirty": True}
            LEDGER.write_immutable(run / "source-provenance.json", provenance)
            original = (run / "source-provenance.json").read_bytes()
            with self.assertRaisesRegex(ValueError, "already exists"):
                LEDGER.capture_provenance(run, "pre_build")
            self.assertEqual(LEDGER.capture_provenance(run, "post_run"), provenance)
            self.assertEqual((run / "source-provenance.json").read_bytes(), original)

    def test_old_evidence_cannot_be_restamped(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence.json"
            LEDGER.write_immutable(path, {"status": "Rejected"})
            with self.assertRaisesRegex(ValueError, "refusing to replace"):
                LEDGER.write_immutable(path, {"status": "Committed"})
            self.assertEqual(json.loads(path.read_text())["status"], "Rejected")

    def test_false_state_fact_and_boolean_capacity_are_not_accepted(self):
        with tempfile.TemporaryDirectory() as directory:
            run = Path(directory)
            path = run / "scenarios" / "smoke" / "report.json"
            LEDGER.write_immutable(path, {"status": "Rejected", "capacity": True})
            evidence = LEDGER.Evidence(run, Path("unused"))
            scenario = evidence.scenario("root_funding", "test", "bilateral_shared", [])
            with self.assertRaisesRegex(ValueError, "expected 'Committed'"):
                evidence.add(scenario, "state", path, "/status", "Committed")
            with self.assertRaisesRegex(ValueError, "expected 1"):
                evidence.add(scenario, "assets", path, "/capacity", 1)
            self.assertEqual(scenario["assertions"], [])

    def test_symlink_cannot_import_outside_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            run = Path(directory)
            outside = run / "outside.json"
            LEDGER.write_immutable(outside, {"status": "Committed"})
            scenarios = run / "scenarios"
            scenarios.mkdir()
            (scenarios / "escape.json").symlink_to(outside)
            with self.assertRaisesRegex(ValueError, "inside the scenario"):
                LEDGER.Evidence(run, Path("unused")).reference("escape.json")

    def test_source_digest_covers_untracked_implementation_and_midrun_edits(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            (root / "scripts").mkdir()
            runner = root / "scripts" / "devnet-current-e2e.sh"
            runner.write_text("original source")
            with patch.object(LEDGER, "ROOT", root):
                before = LEDGER.source_digest()
                runner.write_text("changed source")
                self.assertNotEqual(LEDGER.source_digest(), before)
                before = LEDGER.source_digest()
                (root / "user-notes.md").write_text("unrelated untracked user prose")
                self.assertEqual(LEDGER.source_digest(), before)
                (root / "scripts" / "new-implementation.py").write_text("new executable authority")
                self.assertNotEqual(LEDGER.source_digest(), before)


if __name__ == "__main__":
    unittest.main()
