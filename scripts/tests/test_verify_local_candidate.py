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



class NativeDesktopQualificationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.root = Path(__file__).resolve().parents[2]

    def native_bundle(self, *, dirty=False, forged_binary=False, forged_source=False,
                      linked=False, duplicate=False):
        lock = (self.root / "Cargo.lock").read_bytes()
        vendor = (self.root / "vendor/provenance.json").read_bytes()
        provenance = json.loads(vendor)
        original = b"native binary expected by the caller"
        binary = b"another executable" if forged_binary else original
        files = {"bin/morph-desktop": binary, "Cargo.lock": lock,
                 "vendor-provenance.json": vendor, "THIRD_PARTY_NOTICES.md": b"notices",
                 "native-gui-dependencies.md": b"redistribution policy"}
        for item in provenance["redistribution_sources"]:
            raw = (self.root / "vendor" / item["path"]).read_bytes()
            files["sources/mpl/" + Path(item["path"]).name] = b"forged" if forged_source else raw
        for item in provenance["license_notices"]:
            if item["path"].startswith("licenses/native-desktop/"):
                files[item["path"]] = (self.root / "vendor" / item["path"]).read_bytes()
        files["sources/registry/option-ext-0.2.0.crate"] = (self.root / "vendor/redistribution/option-ext-0.2.0.crate").read_bytes()
        files["manifest.json"] = json.dumps({
            "schema": "morph.native_desktop_bundle.v1", "platform": "x86_64-unknown-linux-gnu",
            "source_commit": "1" * 40, "tracked_clean": not dirty, "published": False,
            "cargo_lock_sha256": MODULE.sha(lock), "vendor_provenance_sha256": MODULE.sha(vendor),
            "binary_sha256": MODULE.sha(binary), "packages": [
                {"name": "option-ext", "version": "0.2.0", "source_kind": "registry_archive"}]
        }).encode()
        files["SHA256SUMS"] = "".join(f"{MODULE.sha(raw)}  ./{name}\n" for name, raw in sorted(files.items())).encode()
        path = self.directory / "native.tar.gz"
        with tarfile.open(path, "w:gz") as archive:
            for name, raw in files.items():
                entry = tarfile.TarInfo("morph-desktop-linux-x86_64/" + name)
                entry.mode = 0o755 if name == "bin/morph-desktop" else 0o644
                if linked and name == "bin/morph-desktop":
                    entry.type, entry.linkname = tarfile.SYMTYPE, "/tmp/outside-the-bundle"
                    archive.addfile(entry)
                else:
                    entry.size = len(raw)
                    archive.addfile(entry, io.BytesIO(raw))
                if duplicate and name == "manifest.json":
                    archive.addfile(entry, io.BytesIO(raw))
        return path, "1" * 40, lock, vendor, MODULE.sha(original)

    def test_native_reader_binds_binary_lock_sources_and_mpl_without_extracting(self):
        result = MODULE.verify_desktop_archive(*self.native_bundle())
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["mpl_source_archives"], 2)

    def test_consistent_new_checksums_cannot_replace_native_binary_or_mpl_source(self):
        for mutation in ("forged_binary", "forged_source", "dirty"):
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                MODULE.verify_desktop_archive(*self.native_bundle(**{mutation: True}))

    def test_native_links_and_duplicate_members_are_rejected(self):
        for mutation in ("linked", "duplicate"):
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                MODULE.verify_desktop_archive(*self.native_bundle(**{mutation: True}))


if __name__ == "__main__":
    unittest.main()
