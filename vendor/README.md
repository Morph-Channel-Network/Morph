# Reviewed upstream dependency patches

These are exact published crates.io packages with their original names,
versions, source, embedded system scripts and license metadata. They are
excluded from Morph's workspace members and selected through the root
`[patch.crates-io]`. No vulnerable package is renamed or assigned a fake version.

`provenance.json` records each original archive URL and SHA-256 (verified against
the pre-migration Cargo.lock), original file hashes, the small modified-file
hashes, upstream revision when published, and the digest of its readable delta
under `patches/`. `Cargo.toml.orig`, upstream nested lockfiles and all other
archive contents remain unchanged as provenance; the patched `Cargo.toml` and
Morph's root Cargo.lock determine the actual build.

The root `.gitattributes` preserves vendored CRLF/LF bytes exactly. Do not run
formatters or newline normalization over these archives: upstream whitespace is
part of the checked file inventory. Morph-owned changes follow the workspace
style; vendor integrity is checked against the original bytes and declared
deltas instead of reformatting third-party sources.

The complete local changes are:

| Consumers | Change |
| --- | --- |
| ckb-crypto, ckb-fixed-hash-core, ckb-jsonrpc-types, ckb-script, ckb-system-scripts, ckb-testtool, molecule | Select registry faster-hex =0.10.1 with std and without its optional serde feature. Molecule retains its optional dependency and existing std feature gate. |
| ckb-types, ckb-vm-definitions, gpui-component | Select the maintained pastey =0.2.3 macro package under the existing `paste` Rust import name. This replaces the original unmaintained paste package. |
| gpui-base, gpui-component | Select maintained web-time =1.1.0 for timing; gpui-base changes only the former `instant::` import qualifications. |
| gpui-pre, cosmic-text | Select resvg/usvg =0.49.0 and fontdb =0.24.0; the sole GPUI SVG glyph-coverage query uses maintained skrifa =0.44.0 instead of ttf-parser. Public GUI APIs and the GPUI 0.3.11 family stay pinned. |
| cacache | Select registry memmap2 =0.9.12; preserve its optional mmap feature. |
| ckb-verification | Select registry lru =0.18.2; construct the same 30,000-entry cache using the required positive capacity type. |

The registry archives retain their declared licenses and all included notices.
Most CKB/Molecule archives omit a separate license file; pinned upstream MIT
notices are also provided in `licenses/`. The cacache archive includes its
original `LICENSE.md`. The authoritative system-scripts 0.5.4 archive publishes
no `.cargo_vcs_info.json`; its archive checksum pins its full source and binaries.

`make supply-chain` runs `make vendor-check` before audit/deny. To additionally
download and compare every original registry archive and reconstruct all deltas:

```sh
python3 vendor/check.py --upstream-archives
```

Remove each patch once a compatible published upstream consumer accepts the
patched dependency. Update the original archive evidence and readable delta
together whenever a consumer version changes. CKB wire, signing and no_std
compatibility requirements and the remaining rand 0.7 waiver are documented in
[`docs/ckb-toolchain-upgrade.md`](../docs/ckb-toolchain-upgrade.md).
