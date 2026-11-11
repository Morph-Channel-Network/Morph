#!/usr/bin/env python3
"""Bind a local controlled-devnet qualification to one clean candidate.

This checks locally executed evidence, not independent attestations, and never
authorizes publication or real assets. Inputs are read without extracting tar.
"""
import argparse
import hashlib
import importlib.util
import json
import re
import subprocess
import tarfile
import time
import tomllib
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
PREFIX = "morph-current-custody/"
MAX_FILE = 16 * 1024 * 1024


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def unique(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, "duplicate JSON field")
        value[key] = item
    return value


def decode(raw):
    require(len(raw) <= MAX_FILE, "oversized qualification input")
    return json.loads(raw, object_pairs_hook=unique)


def read(path):
    require(path.is_file() and not path.is_symlink(), "missing or linked qualification file")
    require(path.stat().st_size <= MAX_FILE, "oversized qualification file")
    return path.read_bytes()


def checksums(raw):
    result = {}
    for line in raw.decode("ascii").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        require(match is not None, "malformed checksum record")
        digest, name = match.groups()
        path = PurePosixPath(name)
        require(not path.is_absolute() and ".." not in path.parts and str(path) == name,
                "unsafe checksum path")
        require(name not in result, "duplicate checksum path")
        result[name] = digest
    require(result, "empty checksum list")
    return result


def verify_public(directory):
    indexed = checksums(read(directory / "SHA256SUMS"))
    paths = list(directory.rglob("*"))
    require(not directory.is_symlink() and all(not path.is_symlink() for path in paths),
            "public evidence contains a link")
    actual = {str(path.relative_to(directory)) for path in paths if path.is_file()}
    require(actual == set(indexed) | {"SHA256SUMS"}, "public evidence file set differs")
    require(len(indexed) <= 32 and sum(path.stat().st_size for path in paths if path.is_file()) <= 8 * 1024 * 1024,
            "public evidence exceeds qualification size budget")
    for name, digest in indexed.items():
        path = directory / name
        require(path.resolve().is_relative_to(directory.resolve()), "public evidence path escaped")
        require(sha(read(path)) == digest, "public evidence checksum mismatch")
    return {name: decode(read(directory / name)) for name in indexed if name.endswith(".json")}


def verify_archive(path, manifest, envelope_raw, contracts, source_metadata):
    allowed = {"contracts.json", "envelope.json", "README.md", "watch-policy.json",
               "publication-profile.json", "watch-config.example.json", "SHA256SUMS"}
    allowed |= {"contracts/" + item["name"] for item in manifest["scripts"]}
    files = {}
    require(path.stat().st_size <= MAX_FILE and not path.is_symlink(), "oversized or linked bundle")
    with tarfile.open(path, "r:gz") as archive:
        members = archive.getmembers()
        require(len(members) <= 32, "too many archive members")
        for member in members:
            if member.isdir() and member.name == PREFIX.rstrip("/"):
                continue
            require(member.name.startswith(PREFIX), "archive member outside bundle")
            name = member.name[len(PREFIX):]
            if member.isdir():
                require(name in {"", "contracts"}, "unexpected bundle directory")
                continue
            require(member.isfile() and name in allowed and name not in files,
                    "unexpected, duplicate or linked bundle member")
            require(0 <= member.size <= MAX_FILE, "oversized bundle member")
            handle = archive.extractfile(member)
            require(handle is not None, "unreadable bundle member")
            files[name] = handle.read(MAX_FILE + 1)
    require(set(files) == allowed, "incomplete bundle")
    require(decode(files["contracts.json"]) == manifest, "bundle contract manifest mismatch")
    require(files["envelope.json"] == envelope_raw, "bundle envelope mismatch")
    required_metadata = {"README.md", "watch-policy.json", "publication-profile.json", "watch-config.example.json"}
    require(set(source_metadata) == required_metadata, "missing candidate bundle metadata")
    require(all(files[name] == raw for name, raw in source_metadata.items()),
            "bundle metadata differs from the exact candidate")
    indexed = checksums(files["SHA256SUMS"])
    require(set(indexed) == allowed - {"SHA256SUMS"}, "bundle checksum coverage differs")
    for name, digest in indexed.items():
        require(sha(files[name]) == digest, "bundle checksum mismatch")
    by_name = {item["name"]: item for item in contracts}
    require(set(by_name) == {item["name"] for item in manifest["scripts"]}, "ELF set mismatch")
    for item in manifest["scripts"]:
        raw = files["contracts/" + item["name"]]
        ckb_hash = "0x" + hashlib.blake2b(raw, digest_size=32, person=b"ckb-default-hash").hexdigest()
        measured = by_name[item["name"]]
        require(len(raw) == item["size_bytes"] == measured["size_bytes"]
                and ckb_hash == item["ckb_data_hash"] == measured["ckb_data_hash"]
                and sha(raw) == measured["sha256"], "native/bundle/manifest ELF identity mismatch")


def source_digest():
    spec = importlib.util.spec_from_file_location("local_candidate_source", ROOT / "scripts/current-stateful-ledger.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.source_digest()


def verify_policy_window(envelope, now_unix):
    start, end = envelope["effective_unix"], envelope["review_by_unix"]
    require(type(start) is int and type(end) is int and start <= end,
            "invalid envelope approval window")
    require(start <= now_unix <= end, "local qualification envelope is not effective or has expired")


def sha_file(path):
    require(path.is_file() and not path.is_symlink(), "missing or linked native artifact")
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for block in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def verify_desktop_archive(path, source_commit, lock_raw, vendor_raw, binary_sha256):
    prefix = "morph-desktop-linux-x86_64/"
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 512 * 1024 * 1024,
            "oversized, linked or missing native bundle")
    digests, selected, seen = {}, {}, set()
    total = 0
    with tarfile.open(path, "r:gz") as archive:
        for member in archive:
            require(len(seen) < 100000, "too many native archive members")
            require(member.name not in seen, "duplicate native archive member")
            seen.add(member.name)
            normalized = PurePosixPath(member.name)
            require(not normalized.is_absolute() and ".." not in normalized.parts
                    and str(normalized) == member.name.rstrip("/"), "unsafe native archive path")
            if member.name.rstrip("/") == prefix.rstrip("/"):
                require(member.isdir(), "invalid native archive root")
                continue
            require(member.name.startswith(prefix), "native archive escaped its root")
            name = member.name[len(prefix):]
            if member.isdir():
                continue
            require(member.isfile(), "native archive contains a link or special file")
            require(0 <= member.size <= 64 * 1024 * 1024, "oversized native archive member")
            total += member.size
            require(total <= 1024 * 1024 * 1024, "native archive exceeds total size bound")
            file = archive.extractfile(member)
            require(file is not None, "unreadable native archive member")
            digest = hashlib.sha256()
            keep = name in {"manifest.json", "Cargo.lock", "vendor-provenance.json", "SHA256SUMS"}
            raw = bytearray()
            for block in iter(lambda: file.read(1024 * 1024), b""):
                digest.update(block)
                if keep:
                    require(len(raw) + len(block) <= MAX_FILE, "oversized native metadata")
                    raw.extend(block)
            digests[name] = digest.hexdigest()
            if keep:
                selected[name] = bytes(raw)
            if name == "bin/morph-desktop":
                require(member.mode & 0o111 != 0, "native bundle binary is not executable")
    indexed = checksums(selected["SHA256SUMS"].replace(b"  ./", b"  "))
    require(set(indexed) | {"SHA256SUMS"} == set(digests), "native archive checksum inventory differs")
    require(all(digests[name] == digest for name, digest in indexed.items()), "native archive checksum mismatch")
    manifest = decode(selected["manifest.json"])
    require(manifest["schema"] == "morph.native_desktop_bundle.v1"
            and manifest["platform"] == "x86_64-unknown-linux-gnu"
            and manifest["source_commit"] == source_commit and manifest["tracked_clean"] is True
            and manifest["published"] is False, "native bundle is dirty, stale or another platform")
    require(selected["Cargo.lock"] == lock_raw and selected["vendor-provenance.json"] == vendor_raw,
            "native dependency metadata differs from the candidate")
    require(manifest["cargo_lock_sha256"] == sha(lock_raw)
            and manifest["vendor_provenance_sha256"] == sha(vendor_raw), "native dependency digest mismatch")
    require(manifest["binary_sha256"] == binary_sha256 == digests["bin/morph-desktop"],
            "native executable differs from the built candidate")
    lock = tomllib.loads(lock_raw.decode())
    registry = {(p["name"], p["version"]): p["checksum"] for p in lock["package"] if "checksum" in p}
    packages = manifest["packages"]
    require(packages and len({(p["name"], p["version"]) for p in packages}) == len(packages),
            "missing or duplicate native dependency records")
    archives = 0
    for package in packages:
        if package["source_kind"] == "registry_archive":
            name = f"sources/registry/{package['name']}-{package['version']}.crate"
            require(digests.get(name) == registry[(package["name"], package["version"])],
                    "native registry source archive differs from Cargo.lock")
            archives += 1
        else:
            kind = {"verified_patched_source": "patched", "pinned_git_source": "git", "morph_source": "morph"}
            require(package["source_kind"] in kind, "unknown native source origin")
            folder = package["name"] if package["source_kind"] == "morph_source" else f"{package['name']}-{package['version']}"
            require(f"sources/{kind[package['source_kind']]}/{folder}/Cargo.toml" in digests,
                    "native dependency source omitted")
    provenance = decode(vendor_raw)
    for item in provenance["redistribution_sources"]:
        require(digests.get("sources/mpl/" + Path(item["path"]).name) == item["archive_sha256"],
                "exact MPL source archive missing or changed")
    for item in provenance["license_notices"]:
        if item["path"].startswith("licenses/native-desktop/"):
            require(digests.get(item["path"]) == item["sha256"], "native MPL notice missing or changed")
    require("THIRD_PARTY_NOTICES.md" in digests and "native-gui-dependencies.md" in digests,
            "native redistribution documentation omitted")
    return {"schema": "morph.native_desktop_qualification.v1", "status": "passed",
            "binary_sha256": binary_sha256, "bundle_sha256": sha_file(path),
            "dependency_records": len(packages), "registry_source_archives": archives,
            "archive_files": len(digests), "mpl_source_archives": len(provenance["redistribution_sources"])}


def verify(public, bundle, ci_receipt, envelope_path, desktop_bundle):
    git = lambda *args: subprocess.check_output(["git", *args], cwd=ROOT).decode().strip()
    head = git("rev-parse", "HEAD")
    require(not git("status", "--porcelain", "--untracked-files=no"), "candidate has tracked changes")
    reports = verify_public(public)
    checkpoint = reports["checkpoint.json"]
    require(checkpoint["schema"] == "morph.public_checkpoint_evidence.v1"
            and checkpoint["source_commit"] == head, "wrong candidate source")
    require(checkpoint["git_dirty"] is False and checkpoint["source_unchanged"] is True
            and checkpoint["provenance_phase"] == "pre_build"
            and checkpoint["source_tree_sha256"] == source_digest(), "dirty or stale native evidence")
    receipt = decode(read(ci_receipt))
    require(receipt["schema"] == "morph.local_ci_receipt.v1"
            and receipt["command"] == ["make", "ci"] and receipt["exit_code"] == 0
            and receipt["source_commit"] == head
            and receipt["source_tree_sha256"] == checkpoint["source_tree_sha256"]
            and receipt["tracked_clean_before"] is True and receipt["source_unchanged"] is True,
            "incomplete or stale full CI receipt")
    ci = reports["ci-results.json"]
    require(ci["schema"] == "morph.public_local_ci_evidence.v1"
            and ci["original_log_sha256"] == receipt["log_sha256"]
            and ci["contract_vm_tests"]["passed"] > 0
            and ci["contract_vm_tests"]["failed"] == 0
            and ci["contract_vm_tests"]["ignored"] == 0, "CI evidence did not execute the complete VM gate")
    acceptance = reports["acceptance.json"]
    spec = importlib.util.spec_from_file_location("local_evidence_rules", ROOT / "scripts/export-current-public-evidence.py")
    rules = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(rules)
    rules.descriptor_version(head, checkpoint["descriptor_version"])
    require({item["id"] for item in acceptance["audit_families"]} == rules.AUDIT_FAMILIES
            and len(acceptance["audit_families"]) == len(rules.AUDIT_FAMILIES)
            and {item["scenario_id"] for item in acceptance["scenarios"]} == rules.SCENARIOS
            and len(acceptance["scenarios"]) == len(rules.SCENARIOS), "missing or duplicate native coverage")
    require(acceptance["source_commit"] == head and all(item["passed"] is True for item in acceptance["audit_families"])
            and all(assertion["matched"] is True for scenario in acceptance["scenarios"]
                    for assertion in scenario["assertions"]), "failed native assertions or audit families")
    counts = checkpoint["counts"]
    require(sum(len(scenario["assertions"]) for scenario in acceptance["scenarios"]) == counts["evidence_assertions"],
            "native assertion count mismatch")
    require(counts["native_cases"] == 5 and counts["stateful_scenarios"] >= 10
            and counts["evidence_assertions"] >= 99 and counts["audit_families"] == 11,
            "incomplete current native matrix")
    envelope_raw = read(envelope_path)
    envelope = decode(envelope_raw)
    now_unix = int(time.time())
    verify_policy_window(envelope, now_unix)
    require(envelope["schema"] == "morph.preproduction_envelope.v3"
            and envelope["approved_networks"] == ["devnet"]
            and envelope["real_assets_allowed"] is False
            and envelope["qualification"]["release_admitted"] is False
            and envelope["qualification"]["production_allowed"] is False
            and envelope["qualification"]["request_shape_enforcement"] == "exact_request_and_durable_admission",
            "unsupported or widened local qualification envelope")
    require(envelope_raw == subprocess.check_output(["git", "show", head + ":release/factory-preproduction/envelope.json"], cwd=ROOT),
            "envelope is not the candidate's policy")
    manifest_raw = read(ROOT / "release/factory-preproduction/contracts.json")
    manifest = decode(manifest_raw)
    require(sha(manifest_raw) == checkpoint["release_manifest_sha256"]
            and checkpoint["release_manifest_matches_captured"] is True,
            "native evidence used another ELF manifest")
    metadata = {name: read(ROOT / "release/factory-preproduction" / name) for name in
                ("README.md", "watch-policy.json", "publication-profile.json", "watch-config.example.json")}
    verify_archive(bundle, manifest, envelope_raw, checkpoint["contracts"], metadata)
    desktop = verify_desktop_archive(desktop_bundle, head, read(ROOT / "Cargo.lock"),
                                     read(ROOT / "vendor/provenance.json"),
                                     sha_file(ROOT / "target/desktop/morph-desktop"))
    return {"schema": "morph.local_candidate_qualification.v1", "source_commit": head,
            "source_tree_sha256": checkpoint["source_tree_sha256"], "status": "passed",
            "verified_at_unix": now_unix, "policy_review_by_unix": envelope["review_by_unix"],
            "scope": "controlled_devnet_local_only", "release_published": False, "real_assets_allowed": False,
            "independent_attestation_required": False, "release_admitted": False,
            "envelope_sha256": sha(envelope_raw), "contract_manifest_sha256": sha(manifest_raw),
            "cargo_lock_sha256": sha(read(ROOT / "Cargo.lock")),
            "toolchain_sha256": sha(read(ROOT / "rust-toolchain.toml")),
            "contract_bundle_sha256": sha(read(bundle)), "public_evidence_index_sha256": sha(read(public / "SHA256SUMS")),
            "ci_receipt_sha256": sha(read(ci_receipt)), "genesis_hash": checkpoint["genesis_hash"],
            "counts": counts, "contract_vm_tests": ci["contract_vm_tests"], "native_desktop": desktop}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--public-evidence", type=Path, required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--desktop-bundle", type=Path, required=True)
    parser.add_argument("--ci-receipt", type=Path, required=True)
    parser.add_argument("--envelope", type=Path, default=ROOT / "release/factory-preproduction/envelope.json")
    args = parser.parse_args()
    print(json.dumps(verify(args.public_evidence, args.bundle, args.ci_receipt, args.envelope, args.desktop_bundle), indent=2))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError, subprocess.CalledProcessError) as error:
        raise SystemExit(f"[local-qualification] {error}") from None
