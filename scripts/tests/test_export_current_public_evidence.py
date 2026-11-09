"""Publication-boundary negatives for public evidence; no node or signing keys."""

import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

PATH = Path(__file__).resolve().parents[1] / "export-current-public-evidence.py"
SPEC = importlib.util.spec_from_file_location("export_current_public_evidence", PATH)
PUBLIC = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PUBLIC)


class PublicEvidenceBoundaries(unittest.TestCase):
    def test_public_budget_export_preserves_scoped_factory_exception_without_private_fields(self):
        policy = json.loads((PUBLIC.ROOT / "docs/devnet-stateful-budget.example.json").read_text())
        policy["private_key"] = "never-export-budget-key"
        policy["transactions"][0]["private_journal"] = "never-export-authority"
        limits = PUBLIC.public_budget_limits(policy)
        self.assertNotIn("never-export", json.dumps(limits))
        self.assertEqual(limits["max_tx_cycles"], 55_000_000)
        for case in limits["cases"]:
            expected = 2_000_000 if case["name"] == "deployment" else (
                55_000_000 if case["name"] == "factory_custody_and_children" else 40_000_000)
            self.assertEqual(case["max_tx_cycles"], expected)
        exceptions = [item for item in limits["transactions"] if item["max_cycles"] > 40_000_000]
        self.assertEqual(len(exceptions), 1)
        self.assertEqual(exceptions[0]["path"], "$.transitions.rights_updates.operations[2].report")
        self.assertEqual(exceptions[0]["max_cycles"], 55_000_000)
        reduced = next(item for item in limits["proof_profiles"] if item["operation"] == "ReducedRights")
        self.assertEqual(reduced["max_proof_siblings"], 96)
        self.assertEqual(reduced["max_witness_len"], 8192)
        policy["transactions"][0]["max_cycles"] = True
        with self.assertRaisesRegex(ValueError, "invalid nonnegative integer"):
            PUBLIC.public_budget_limits(policy)

    def source(self):
        source = {
            "schema": "morph.current_run_provenance.v1", "phase": "pre_build",
            "git_dirty": False, "git_commit_full": "1" * 40,
            "source_tree_sha256": "2" * 64, "runner_sha256": "3" * 64,
            "ledger_generator_sha256": "4" * 64,
            "recorded_at_utc": "2026-11-04T20:17:42.810649+00:00",
            "private_journal": "never-export-private-journal",
        }
        manifest = {
            "schema": "morph.current_stateful_matrix.v1", "status": "passed",
            "git_commit_full": "1" * 40, "git_dirty": "false",
            "provenance_phase": "pre_build", "source_unchanged": "true",
            "source_tree_sha256": "2" * 64,
        }
        return source, manifest

    def test_source_identity_cannot_be_relabelled_or_upgraded(self):
        source, manifest = self.source()
        result = PUBLIC.provenance(source, manifest, "1" * 40)
        self.assertEqual(result["source_commit"], "1" * 40)
        self.assertNotIn("private_journal", result)
        with self.assertRaisesRegex(ValueError, "does not match"):
            PUBLIC.provenance(source, manifest, "5" * 40)
        source["phase"] = "post_run"
        with self.assertRaisesRegex(ValueError, "not clean"):
            PUBLIC.provenance(source, manifest)
        source["phase"] = "pre_build"
        manifest["source_unchanged"] = "false"
        with self.assertRaisesRegex(ValueError, "source changed"):
            PUBLIC.provenance(source, manifest)

    def test_transaction_projection_excludes_private_payload_and_signed_body(self):
        transaction = {
            "check": "bilateral_shared", "path": "$.fund", "tx_hash": "0x" + "1" * 64,
            "status": "Committed", "block_number": None, "estimated_cycles": 123,
            "tx_size_bytes": 456, "private_key": "never-export-key",
            "journal": {"authority": "never-export-authority"},
            "raw_transaction_hex": "never-export-signed-unbroadcast-body",
            "authorization": {"signatures": ["never-export-signature"]},
        }
        result = PUBLIC.project_transactions([transaction])
        self.assertEqual(set(result[0]), set(PUBLIC.TX_FIELDS))
        self.assertIsNone(result[0]["block_number"])
        self.assertNotIn("never-export", json.dumps(result))
        transaction["status"] = "Pending"
        with self.assertRaisesRegex(ValueError, "noncommitted"):
            PUBLIC.project_transactions([transaction])

    def test_private_artifacts_pointers_and_nested_fields_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "scenarios/smoke/shared-acceptance.json"
            path.parent.mkdir(parents=True)
            raw = json.dumps({"finalise": {"status": "Committed"},
                              "private_key": "never-export-key",
                              "journal": "never-export-journal"}).encode()
            path.write_bytes(raw)
            reader = PUBLIC.Reader(root)
            assertion = {"artifact": "smoke/shared-acceptance.json", "pointer": "/finalise/status",
                         "dimension": "state", "expected": "Committed"}
            result = PUBLIC.inspect_assertion(reader, assertion)
            self.assertNotIn("never-export", json.dumps(result))
            self.assertEqual(path.read_bytes(), raw)
            assertion["pointer"] = "/private_key"
            with self.assertRaisesRegex(ValueError, "unsupported assertion pointer"):
                PUBLIC.inspect_assertion(reader, assertion)
            assertion["artifact"] = "private-initial-exit.json"
            with self.assertRaisesRegex(ValueError, "private or unsupported artifact"):
                PUBLIC.inspect_assertion(reader, assertion)
            with self.assertRaisesRegex(ValueError, "private or unsupported assertion fields"):
                PUBLIC.public_value({"signature_hex": "never-export-private-exit"})

    def test_elf_bytes_must_match_manifest_and_captured_sha(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            folder = root / "scenarios/smoke/contracts"
            folder.mkdir(parents=True)
            manifest = {
                "schema": "morph.contract_release_manifest", "release_profile": "morph-current-custody",
                "rust_toolchain": "1.95.0", "target": "riscv64imac-unknown-none-elf",
                "build_profile": "release", "cargo_locked": True, "scripts": [],
                "private_key": "never-export-manifest-secret",
            }
            recorded = {}
            for name in sorted(PUBLIC.SCRIPTS):
                raw = b"\x7fELF" + name.encode()
                (folder / name).write_bytes(raw)
                recorded[name] = hashlib.sha256(raw).hexdigest()
                manifest["scripts"].append({
                    "name": name, "file": name, "deployment_scope": "controlled_devnet",
                    "size_bytes": len(raw),
                    "ckb_data_hash": "0x" + hashlib.blake2b(raw, digest_size=32, person=b"ckb-default-hash").hexdigest(),
                    "raw_exit": "never-export-exit",
                })
            public = PUBLIC.public_contract_manifest(manifest)
            self.assertNotIn("never-export", json.dumps(public))
            verified = PUBLIC.contract_evidence(PUBLIC.Reader(root), public, recorded)
            self.assertEqual(len(verified), 8)
            first = manifest["scripts"][0]["name"]
            (folder / first).write_bytes(b"\x7fELF" + b"x" * (manifest["scripts"][0]["size_bytes"] - 4))
            with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                PUBLIC.contract_evidence(PUBLIC.Reader(root), public, recorded)

    def test_ci_export_omits_freeform_stdout_and_token_values(self):
        raw = ("PRIVATE_KEY=never-export-key\nAuthorization: Bearer never-export-token\n"
               "secret_log_context never-export-journal\n"
               "Running tests/contract_scripts.rs (target/debug/deps/contract-tests)\n"
               "test ordinary_module::recovers ... ok\n"
               "test result: ok. 77 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 20.48s\n"
               "Morph current custody release-readiness documents verified\n").encode()
        result = PUBLIC.ci_results(raw)
        self.assertEqual(result["original_log_sha256"], hashlib.sha256(raw).hexdigest())
        self.assertNotIn("never-export", json.dumps(result))
        self.assertEqual(len(result["result_lines"]), 3)
        self.assertEqual(result["contract_vm_tests"], {"passed": 77, "failed": 0, "ignored": 0})

    def test_symlink_cannot_import_an_outside_record(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "run").mkdir()
            outside = root / "outside.json"
            outside.write_text('{"private_key":"never-export-key"}')
            (root / "run/escaped.json").symlink_to(outside)
            with self.assertRaisesRegex(ValueError, "leaves run"):
                PUBLIC.bounded_file(root / "run", "escaped.json")


if __name__ == "__main__":
    unittest.main()
