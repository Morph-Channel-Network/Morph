# Native GUI dependency qualification

The desktop uses one exact GPUI Kit 0.9.0 / GPUI pre 0.3.11 family. Its Rust
component, rendering, platform and accessibility dependencies are independent
of the no_std custody scripts. Native dependency changes do not authorize a
protocol format change or a new signing authority.

The current qualification status is in [the migration ledger](gpui-migration-status.md).
No release, mainnet readiness or native OS input qualification is inferred from
this document.

## Reviewed source deltas

`vendor/provenance.json` pins the original registry archives, every source byte,
changed-file inventories and readable deltas under `vendor/patches`. Run
`python3 vendor/check.py --upstream-archives` to reconstruct the deltas against
the downloaded original archives. The package names, versions and original
licenses remain intact. There are no fake patched versions or advisory ignores.

- GPUI base/component timing uses maintained `web-time`; component macro
  expansion uses `pastey`. Native `Instant`/`Duration` behavior remains the
  platform's standard timing implementation.
- GPUI SVG rendering and cosmic-text's font database use current usvg/resvg and
  fontdb; the glyph-coverage query uses skrifa. The existing GPUI public types,
  assets and renderer family are retained.
- The optional Fast renderer dependencies are removed from the curated Kit
  manifests. Enabling that unsupported Kit feature fails explicitly. Morph has
  no feature that switches rendering engines.
- The assets crate's non-native HTTP dependency selects the maintained mainline
  reqwest package. This removes the obsolete fork from the resolved lockfile;
  it does not add a browser frontend or a supported Morph WASM build.
- Native portals, notifications and keyring clients use maintained ashpd/oo7/
  notify-rust. Accessibility name, wire, proxy and introspection types move to
  the maintained merged zbus 6 API, including its managed connection I/O tasks.
  Interface insertion handles zbus 6's `None = inserted` result explicitly;
  duplicate-interface results are not inverted. Message bodies use checked
  deserialization. AT-SPI names and wire signatures remain the protocol boundary.
- The lockfile's optional AV1 encoder selects maintained pastey through a
  manifest-only rav1e patch. The obsolete paste waiver is not restored.

These patches must retain native rendering, file dialogs, accessibility,
notifications and keyring behavior. Compilation and headless GUI tests are
necessary but do not replace native platform integration evidence.

## Narrow license policy additions

Only **option-ext =0.2.0** and **cbindgen =0.28.0** receive MPL-2.0 exceptions in
`deny.toml`. All other MPL packages remain outside the allowlist. option-ext is
an unmodified runtime dependency through directory discovery. cbindgen is an
unmodified macOS build tool and is not embedded in the Linux desktop executable.

The unchanged registry source archives are retained in `vendor/redistribution`,
and their original license texts in `vendor/licenses/native-desktop`.
`vendor/check.py` compares the archive digests with Cargo.lock. Native desktop
packaging must include these archives, notices, and this explanation, and must
not remove or restrict the source license notices. This packaging requirement
is a gate, not a claim that a bundle has already been qualified.

The source-availability and notice requirements come from MPL 2.0 sections
3.1–3.3 and Mozilla's distribution FAQ. The general MPL license is not added to
Morph's project-wide allowlist. [MPL 2.0](https://www.mozilla.org/en-US/MPL/2.0/),
[Mozilla FAQ, questions 8–11](https://www.mozilla.org/en-US/MPL/2.0/FAQ/).

Remove each source patch when a compatible upstream release incorporates the
maintained dependency/API migration. Remove each exact license exception when
that package leaves the admitted graph; do not broaden its version range
without updating source/notices and packaging evidence.

The published cosmic-text archive includes full font/image fixtures and upstream Git LFS attributes. The reviewed `.gitattributes` delta stores those exact fixture bytes as ordinary Git blobs, so checkout/build does not require an external LFS service. Font/image contents remain byte-identical to the source archive.
