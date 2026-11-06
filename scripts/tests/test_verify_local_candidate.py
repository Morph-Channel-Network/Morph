import hashlib
import importlib.util
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location("local_candidate", Path(__file__).parents[1] / "verify-local-candidate.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class LocalCandidateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def bundle(self, *, changed_elf=False, changed_policy=False, changed_watch=False, linked=False, duplicate=False):
        elf = b"test ELF bytes"
        manifest = {"scripts": [{"name": "state", "size_bytes": len(elf),
                     "ckb_data_hash": "0x" + hashlib.blake2b(elf, digest_size=32, person=b"ckb-default-hash").hexdigest()}]}
        policy = b'{"real_assets_allowed": false}'
        files = {"contracts.json": json.dumps(manifest).encode(), "envelope.json": policy,
                 "contracts/state": elf, "README.md": b"local only", "watch-policy.json": b"{}",
                 "publication-profile.json": b"{}", "watch-config.example.json": b"{}"}
        metadata = {name: files[name] for name in
                    ("README.md", "watch-policy.json", "publication-profile.json", "watch-config.example.json")}
        if changed_elf:
            files["contracts/state"] = b"another executable"
        if changed_policy:
            files["envelope.json"] = b'{"real_assets_allowed": true}'
        if changed_watch:
            files["watch-policy.json"] = b'{"publication_budget":"different source"}'
        files["SHA256SUMS"] = "".join(f"{MODULE.sha(raw)}  {name}\n" for name, raw in sorted(files.items())).encode()
        path = self.root / "bundle.tar.gz"
        with tarfile.open(path, "w:gz") as archive:
            parent = tarfile.TarInfo("morph-current-custody")
            parent.type = tarfile.DIRTYPE
            archive.addfile(parent)
            for name, raw in files.items():
                info = tarfile.TarInfo(MODULE.PREFIX + name)
                if linked and name == "contracts/state":
                    info.type = tarfile.SYMTYPE
                    info.linkname = "/tmp/another-file"
                    archive.addfile(info)
                    continue
                info.size = len(raw)
                archive.addfile(info, io.BytesIO(raw))
                if duplicate and name == "contracts/state":
                    archive.addfile(info, io.BytesIO(raw))
        evidence = [manifest["scripts"][0] | {"sha256": MODULE.sha(elf)}]
        return path, manifest, policy, evidence, metadata

    def test_real_archive_reader_accepts_exact_bytes_and_matches_ckb_personalization(self):
        MODULE.verify_archive(*self.bundle())

    def test_self_consistent_archive_checksums_cannot_replace_expected_executable_or_policy(self):
        for mutation in ("changed_elf", "changed_policy", "changed_watch"):
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                MODULE.verify_archive(*self.bundle(**{mutation: True}))

    def test_bundle_links_and_duplicate_members_reject_without_extracting(self):
        for mutation in ("linked", "duplicate"):
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                MODULE.verify_archive(*self.bundle(**{mutation: True}))

    def test_public_evidence_detects_modified_artifact_and_unindexed_file(self):
        evidence = self.root / "public"
        evidence.mkdir()
        original = b'{"status": "passed"}'
        (evidence / "checkpoint.json").write_bytes(original)
        (evidence / "SHA256SUMS").write_text(f"{MODULE.sha(original)}  checkpoint.json\n")
        self.assertEqual(MODULE.verify_public(evidence)["checkpoint.json"]["status"], "passed")
        (evidence / "checkpoint.json").write_bytes(b'{"status": "failed"}')
        with self.assertRaisesRegex(ValueError, "checksum mismatch"):
            MODULE.verify_public(evidence)
        (evidence / "checkpoint.json").write_bytes(original)
        (evidence / "private-snapshot.json").write_bytes(b"{}")
        with self.assertRaisesRegex(ValueError, "file set differs"):
            MODULE.verify_public(evidence)

    def test_duplicate_json_and_unsafe_checksum_references_reject(self):
        with self.assertRaisesRegex(ValueError, "duplicate JSON"):
            MODULE.decode(b'{"passed":true,"passed":false}')
        digest = "a" * 64
        for name in ("../private.json", "/tmp/private.json", "dir/../private.json"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                MODULE.checksums(f"{digest}  {name}\n".encode())
        with self.assertRaisesRegex(ValueError, "duplicate checksum"):
            MODULE.checksums(f"{digest}  same\n{digest}  same\n".encode())

    def test_unindexed_directory_symlink_cannot_hide_outside_private_files(self):
        evidence = self.root / "public"
        evidence.mkdir()
        (evidence / "checkpoint.json").write_bytes(b"{}")
        (evidence / "SHA256SUMS").write_text(f"{MODULE.sha(b'{}')}  checkpoint.json\n")
        outside = self.root / "private"
        outside.mkdir()
        (outside / "snapshot.json").write_bytes(b'{"private":true}')
        (evidence / "hidden").symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "contains a link"):
            MODULE.verify_public(evidence)

    def test_historical_artifacts_cannot_mint_current_qualification_after_policy_expiry(self):
        envelope = {"effective_unix": 10, "review_by_unix": 20}
        MODULE.verify_policy_window(envelope, 10)
        MODULE.verify_policy_window(envelope, 20)
        for now in (9, 21):
            with self.subTest(now=now), self.assertRaisesRegex(ValueError, "not effective or has expired"):
                MODULE.verify_policy_window(envelope, now)
        for start in (True, 21):
            with self.subTest(start=start), self.assertRaisesRegex(ValueError, "invalid envelope"):
                MODULE.verify_policy_window({"effective_unix": start, "review_by_unix": 20}, 15)


if __name__ == "__main__":
    unittest.main()
