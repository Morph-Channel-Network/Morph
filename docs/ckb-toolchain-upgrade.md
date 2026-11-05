# CKB dependency and Rust toolchain migration

This is the CKB-only qualification snapshot for issue #25, checked on
2026-11-05 against release baseline `c8787f0`. It upgrades the published CKB
family and Rust build together. It does **not** close the remaining upstream
advisories or qualify an integrated release candidate for deployment.

## Version selection

| Boundary | Previous | Selected |
| --- | --- | --- |
| Workspace MSRV and pinned compiler | Rust 1.92.0 | Rust 1.95.0 |
| Host canonical types | `ckb-types` 1.1.1 | 1.1.4 |
| Host RPC types | `ckb-jsonrpc-types` 1.1.1 | 1.2.1 |
| Host crypto and shared hash | `ckb-crypto` / `ckb-hash` 1.1.0 | 1.1.1 |
| Contract support | `ckb-std` 1.1.0 | 1.1.0, current published release |
| Contract packed types | `ckb-gen-types` 1.1.0 | 1.1.2 |
| Molecule | 0.9.2 | 0.9.2, current published release |
| VM test harness | `ckb-testtool` 1.1.1 | 1.1.1, current published release |
| Test verification / VM | `ckb-verification` 1.1.0 / `ckb-vm` 0.24.14 | 1.2.1 / 0.24.15 |

The upgraded host, packed-type and verification crates declare Rust 1.95.0;
using Rust 1.92 would leave Cargo on older compatible packages. The exact
published dependency closure is in `Cargo.lock`. The selected type, RPC,
packed-type and verification releases record upstream revision
`6b3453f5a691a446de0148a9982f5e6a08b91e78` in `.cargo_vcs_info.json`;
crypto/hash 1.1.1 record `44e7d791f253b9a1921e7eaddfdde65e0b0b1c9b`.
See the [upstream workspace manifest](https://github.com/nervosnetwork/ckb/blob/6b3453f5a691a446de0148a9982f5e6a08b91e78/Cargo.toml)
and [canonical-types manifest](https://github.com/nervosnetwork/ckb/blob/6b3453f5a691a446de0148a9982f5e6a08b91e78/util/types/Cargo.toml).

Both CI workflows install the same pinned Rust action revision. Release
metadata and current operator runbooks use Rust 1.95.0. Historical rehearsal
records and already published evidence retain the compiler that produced them.
The native acceptance node remains its existing pinned CKB 0.210.0 release.

## Contract build compatibility

CKB-VM cannot execute the RISC-V A extension. With this compiler, `ckb-std`'s
former `dummy-atomic` plus `target-feature=-a` combination is unsupported.
Both `.cargo/config.toml` and the deterministic contract builder now use
`-C passes=lower-atomic`, and the workspace disables `dummy-atomic`. This is
the solution documented by [ckb-std](https://github.com/nervosnetwork/ckb-std#upgrading-issues)
and the [CKB script templates](https://github.com/cryptape/ckb-script-templates#molecule-uses-bytes-crates).

No Morph domain, witness format, `since` rule, signing role or capacity rule
changes. Compiler and dependency changes nevertheless relink the ELFs: the
integrated candidate must rebuild every script, regenerate its manifest, and
repeat its VM, cost and native acceptance qualification before using those
hashes. Earlier manifests and cycle evidence do not qualify the new build.

## Advisory reachability and remaining work

The unwaived audit on this CKB-only branch still reports the same seven
advisories. No waiver is added or removed. In particular, the prior suggestion
that `ckb-verification` 1.2 removes `lru` is incorrect: 1.2.1 still requires 0.7.

`faster-hex` 0.6.1 has seven direct incoming dependency roots in the resolved
workspace graph:

| Direct dependency | Scope |
| --- | --- |
| `ckb-crypto` 1.1.1 | Host wallet/RPC support; also VM tests |
| `ckb-fixed-hash-core` 1.1.2 | Host packed types and build-time hash macros |
| `ckb-jsonrpc-types` 1.2.1 | Host RPC serialization |
| `molecule` 0.9.2 with `std` | Host packed serialization |
| `ckb-script` 1.2.1 | VM tests through `ckb-testtool` |
| `ckb-testtool` 1.1.1 | VM tests |
| `ckb-system-scripts` 0.5.4 | Build dependency of test-only CKB resources |

All seven require `^0.6`; `cargo update` cannot select the patched
`faster-hex >=0.10.1`. The [RustSec advisory](https://rustsec.org/advisories/RUSTSEC-2026-0306.html)
describes an AVX2 unchecked-decoder out-of-bounds read. Source inspection finds
no call to `hex_decode_unchecked` in Morph or these seven consumers. The
isolated RISC-V normal/build graph uses Molecule without `std`, and does not
include `faster-hex`.

CKB's development branch has moved its own requirement to 1.0, but the current
[testtool manifest](https://github.com/nervosnetwork/ckb-testtool/blob/master/Cargo.toml),
[Molecule manifest](https://github.com/nervosnetwork/molecule/blob/master/bindings/rust/Cargo.toml)
and [system-script manifest](https://github.com/nervosnetwork/ckb-system-scripts/blob/master/Cargo.toml)
retain 0.6 requirements. Moving the whole CKB family to Git would therefore
still leave affected paths. This migration uses published releases rather than
introducing additional Git sources or replacing an upstream dependency across
major versions locally. Closing this part of #25 requires compatible patched
upstream requirements across **all** incoming paths, followed by graph and
boundary verification.

The other CKB-related waivers also remain present:

| Advisory | Resolved package and path | Removal condition |
| --- | --- | --- |
| `RUSTSEC-2024-0436` | `paste` 1.0.15, through `ckb-types` and VM definitions | Upstream consumers replace the unmaintained macro crate. |
| `RUSTSEC-2026-0097` | `rand` 0.7.3, through `numext-fixed-uint`, VM and resource code generation | All incoming paths leave the affected release family; Morph defines no reentrant custom logger. |
| `RUSTSEC-2026-0186` | `memmap2` 0.5.10, through test-only `ckb-chain-spec -> cacache` | Upstream cache dependency accepts a patched release. |
| `RUSTSEC-2026-0253` | `lru` 0.7.8, through test-only `ckb-verification` | Upstream verification uses a patched release; its `Byte32` keys have no panicking destructor. |

The independent `proc-macro-error2` and `crypto-bigint` paths belong to the
Biscuit/RustCrypto migration. Their waivers are unchanged by this CKB-only
snapshot. `make supply-chain` passes with the existing policy; that outcome
does not mean an unwaived audit is clean. `cargo deny` scopes unsound external
crates differently from `cargo audit` and reports its existing unused
`faster-hex` ignore warning; the affected crate remains in `Cargo.lock`.

Reproduce the graph checks with:

```sh
cargo tree --locked --workspace --all-features -i faster-hex
cargo tree --locked --workspace --all-features -i lru
cargo tree --locked --workspace --all-features -i memmap2
cargo tree --locked --workspace --all-features -i rand@0.7.3
cargo tree --locked -p morph-script-common --target riscv64imac-unknown-none-elf --edges normal,build
cargo audit --json
make supply-chain
```

## Local verification

- `cargo check --workspace --all-features --locked` passes.
- All eight RISC-V contracts build with the selected compiler and atomic
  lowering flags.
- The three `ckb_compatibility` tests pass: fixed Molecule/Script/hash vectors,
  occupied capacity across every accepted hash type, and packed canonical
  relative-block `since` with negative flag and maturity cases.
- All four existing `hash_parity` tests pass.
- All 84 contract VM tests pass against those rebuilt ELFs, including positive
  lifecycles and negative authority, capacity, `since`, splice and Factory paths.
- All 12 Python script tests pass, including current public-evidence export.
- `make lint`, `make source-hygiene`, formatting and whitespace checks pass.

Integrated release-manifest refresh, cost comparison, full CI and clean-source
native qualification remain the responsibility of the final combined candidate.
