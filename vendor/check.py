#!/usr/bin/env python3
"""Verify published dependency identities, upstream bytes and reviewed deltas."""

import argparse
import difflib
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tomllib
import urllib.request


NATIVE_SOURCE_PATCHES = {'accesskit_atspi_common': ['src/action.rs', 'src/rect.rs'],
 'accesskit_unix': ['src/atspi/bus.rs',
                    'src/atspi/object_address.rs',
                    'src/atspi/object_id.rs',
                    'src/context.rs',
                    'src/executor.rs'],
 'cosmic-text': ['.gitattributes'],
 'atspi': [],
 'atspi-common': ['src/action.rs',
                  'src/cache.rs',
                  'src/error.rs',
                  'src/events/cache.rs',
                  'src/events/event_body.rs',
                  'src/events/event_wrappers.rs',
                  'src/events/keyboard.rs',
                  'src/events/mouse.rs',
                  'src/events/object.rs',
                  'src/events/registry.rs',
                  'src/events/traits.rs',
                  'src/events/window.rs',
                  'src/interface.rs',
                  'src/lib.rs',
                  'src/macros.rs',
                  'src/object_match.rs',
                  'src/object_ref.rs',
                  'src/relation_type.rs',
                  'src/role.rs',
                  'src/state.rs'],
 'atspi-proxies': ['src/accessible.rs',
                   'src/collection.rs',
                   'src/device_event_controller.rs',
                   'src/proxy_ext.rs',
                   'src/socket.rs',
                   'src/text.rs'],
 'zbus-lockstep': ['src/lib.rs', 'src/macros.rs'],
 'zbus-lockstep-macros': ['src/lib.rs']}

def digest(data):
    return hashlib.sha256(data).hexdigest()


def check(upstream_archives):
    vendor = Path(__file__).resolve().parent
    manifest = json.loads((vendor / "provenance.json").read_text())
    if manifest["format"] != 1:
        raise ValueError("unsupported vendor provenance format")
    patches = tomllib.loads((vendor.parent / "Cargo.toml").read_text())["patch"]["crates-io"]
    expected_patches = {}
    for package in manifest["packages"]:
        name, version = package["name"], package["version"]
        directory_name = f"{name}-{version}"
        directory = vendor / directory_name
        expected_patches[name] = {"path": f"vendor/{directory_name}"}
        original = package["original_files"]
        changed = package["modified_files"]
        allowed = {"Cargo.toml"}
        if name == "ckb-verification":
            allowed.add("src/cache.rs")
        if name == "gpui-pre":
            allowed.add("src/svg_renderer.rs")
        if name == "gpui-kit":
            allowed.add("src/lib.rs")
        if name == "gpui-pre-linux":
            allowed.update({"src/linux/platform.rs", "src/linux/power.rs"})
        allowed.update(NATIVE_SOURCE_PATCHES.get(name, []))
        if name == "gpui-base":
            # Only qualified imports move to the maintained timing package.
            allowed.update(['src/hover_card.rs', 'src/measure.rs', 'src/scrollable_mask.rs', 'src/scrollbar.rs', 'src/undo_history.rs', 'src/input/base/blink_cursor.rs', 'src/input/editor/lsp/document_colors.rs', 'src/input/editor/lsp/hover.rs', 'src/input/editor/lsp/semantic_tokens.rs'])
        if changed.keys() != allowed:
            raise ValueError(f"unexpected dependency patch scope in {directory_name}")
        if not changed.keys() <= original.keys():
            raise ValueError(f"unpublished file added to {directory_name}")
        actual = {}
        for path in directory.rglob("*"):
            if path.is_symlink():
                raise ValueError(f"unexpected symlink: {path}")
            if path.is_file():
                actual[path.relative_to(directory).as_posix()] = digest(path.read_bytes())
        if actual != original | changed:
            raise ValueError(f"unrecorded dependency changes in {directory_name}")
        identity = tomllib.loads((directory / "Cargo.toml").read_text())["package"]
        for field in ("name", "version", "license"):
            if identity[field] != package[field]:
                raise ValueError(f"changed upstream {field} in {directory_name}")
        patch = (vendor / "patches" / f"{directory_name}.patch").read_bytes()
        if digest(patch) != package["patch_sha256"]:
            raise ValueError(f"changed reviewed delta for {directory_name}")
        if upstream_archives:
            url = f"https://static.crates.io/crates/{name}/{directory_name}.crate"
            if package["archive_url"] != url:
                raise ValueError(f"unexpected registry archive URL for {directory_name}")
            request = urllib.request.Request(url, headers={"User-Agent": "Morph-vendor-check"})
            with urllib.request.urlopen(request, timeout=60) as response:
                archive = response.read()
            if digest(archive) != package["archive_sha256"]:
                raise ValueError(f"registry archive checksum mismatch for {directory_name}")
            published = {}
            with tarfile.open(fileobj=io.BytesIO(archive)) as source:
                for member in source.getmembers():
                    path = Path(member.name)
                    if path.parts[0] != directory_name or ".." in path.parts:
                        raise ValueError("unexpected registry archive path")
                    if member.isdir():
                        continue
                    if not member.isfile():
                        raise ValueError("unexpected registry archive entry")
                    published[Path(*path.parts[1:]).as_posix()] = source.extractfile(member).read()
            if {path: digest(data) for path, data in published.items()} != original:
                raise ValueError(f"upstream file inventory mismatch for {directory_name}")
            actual_patch = "".join(
                line
                for path in sorted(changed)
                for line in difflib.unified_diff(
                    published[path].decode().splitlines(keepends=True),
                    (directory / path).read_text().splitlines(keepends=True),
                    fromfile=f"{directory_name}/{path}.orig-registry",
                    tofile=f"{directory_name}/{path}",
                )
            )
            if actual_patch.encode() != patch:
                raise ValueError(f"reviewed delta differs from registry source for {directory_name}")
    if patches != expected_patches:
        raise ValueError("workspace patches differ from the verified dependency inventory")
    for notice in manifest["license_notices"]:
        if digest((vendor / notice["path"]).read_bytes()) != notice["sha256"]:
            raise ValueError(f"changed upstream license notice: {notice['path']}")
    lock = tomllib.loads((vendor.parent / "Cargo.lock").read_text())
    for source in manifest.get("redistribution_sources", []):
        identity = f"{source['name']}-{source['version']}"
        expected_url = f"https://static.crates.io/crates/{source['name']}/{identity}.crate"
        checksum = next(
            package["checksum"] for package in lock["package"]
            if package["name"] == source["name"] and package["version"] == source["version"]
        )
        if source["modified"] or source["archive_url"] != expected_url:
            raise ValueError(f"unexpected redistribution source identity: {identity}")
        if checksum != source["archive_sha256"] or digest((vendor / source["path"]).read_bytes()) != checksum:
            raise ValueError(f"changed redistribution source archive: {identity}")
    print(f"Verified {len(expected_patches)} vendored dependencies and their reviewed deltas")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--upstream-archives", action="store_true", help="also compare exact crates.io archives"
    )
    arguments = parser.parse_args()
    try:
        check(arguments.upstream_archives)
    except (KeyError, OSError, ValueError, tarfile.TarError) as error:
        parser.exit(1, f"vendor integrity check failed: {error}\n")
