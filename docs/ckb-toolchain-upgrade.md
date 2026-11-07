# CKB dependency and Rust toolchain migration

This is the CKB dependency qualification for issue #25, updated on 2026-11-06.
The Rust/CKB version selection was checked against release baseline `c8787f0`;
the subsequent dependency closure removes four advisory families with actual
patched registry packages and auditable upstream-consumer patches. One explicit
rand 0.7 waiver remains for the public API constraints described below. This
work qualifies controlled local development; it does not publish or authorize a
mainnet or real-asset release.

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
| Host/test hex implementation | `faster-hex` 0.6.1 | 0.10.1, official patched release |
| Token-pasting macros | `paste` 1.0.15 | maintained `pastey` 0.2.3 |
| Test cache mapping | `memmap2` 0.5.10 | 0.9.12, official patched release |
| Test verification cache | `lru` 0.7.8 | 0.18.2, official patched release |

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

## Advisory boundary and complete hex migration

The latest registry CKB/Molecule consumers still constrain `faster-hex` to
`^0.6`. Merely updating Cargo.lock or Rust cannot select the official patched
`>=0.10.1` release. There are seven direct incoming dependency roots:

| Direct dependency | Scope |
| --- | --- |
| `ckb-crypto` 1.1.1 | Host wallet/RPC support; also VM tests |
| `ckb-fixed-hash-core` 1.1.2 | Host packed types and build-time hash macros |
| `ckb-jsonrpc-types` 1.2.1 | Host RPC serialization |
| `molecule` 0.9.2 with `std` | Host packed serialization |
| `ckb-script` 1.2.1 | VM tests through `ckb-testtool` |
| `ckb-testtool` 1.1.1 | VM tests |
| `ckb-system-scripts` 0.5.4 | Build dependency of test-only CKB resources |

The [RustSec advisory](https://rustsec.org/advisories/RUSTSEC-2026-0306.html)
identifies the safe unchecked decoder's AVX2 out-of-bounds read. External CKB
RPC bytes reach checked `hex_decode` through `JsonBytes`, `Byte32` and
`ProposalShortId`; those parsers enforce exact lengths or derive output length
from validated input. Its checked wrapper bounds the read. The other compiled
consumers use hex encoders. No direct unchecked-decoder call was found in Morph
or these consumers, so an exploitable Morph input path was not demonstrated.
That reachability observation alone did not remove the unsound dependency.

The root `[patch.crates-io]` now selects exact published copies of all seven
consumers under `vendor/`, changing their effective manifests to registry
`faster-hex =0.10.1`, with `std` and without optional serde. The actual decoder is
the unmodified official patched registry package. Version 0.10.1 retains the
checked return/error API used by CKB; 1.0 changes those interfaces and was not
needed. The new library's empty-input behavior does not change RPC parsing:
JsonBytes already has an explicit empty branch and fixed-size values enforce
their lengths. Molecule retains its optional dependency and existing std gate.
No consumer source change is needed for this hex migration.

CKB develop has moved its own hex requirement to 1.0, while current testtool,
Molecule and system-script requirements remain on 0.6. Switching the full CKB
family to Git would leave those paths affected and introduce unrelated changes.
The local consumer patches are bounded bridges until compatible published
upstream requirements replace them.

## Other advisory removals and remaining waiver

Four more exact upstream consumers provide three additional removals:

| Advisory | Complete migration | Behavior retained |
| --- | --- | --- |
| `RUSTSEC-2024-0436` | ckb-types 1.1.4 and ckb-vm-definitions 0.24.15 select maintained pastey =0.2.3 using the existing `paste` import name | Macro callers and generated CKB interfaces remain unchanged; the unmaintained paste package leaves Cargo.lock. |
| `RUSTSEC-2026-0186` | cacache 13.1.0 selects memmap2 =0.9.12 | The optional mmap feature and map/write/whole-map flush calls remain intact. |
| `RUSTSEC-2026-0253` | ckb-verification 1.2.1 selects lru =0.18.2 | Its sole source delta supplies NonZeroUsize to the cache constructor; capacity remains 30,000 and lookup semantics remain intact. |

The LRU dependency's positive-capacity constructor is a dependency API change;
Morph and testtool do not directly construct this verification-cache alias.
No Morph API, serialization, signature, domain, witness, capacity rule or
consensus validation is changed. The isolated RISC-V normal/build graph uses
Molecule without std and includes none of faster-hex, paste/pastey, rand 0.7,
memmap2 or lru.

`RUSTSEC-2026-0097` is the sole remaining explicit audit waiver. Its resolved
rand 0.7.3 package has three incoming roots: `numext-fixed-uint-core` 0.1.6,
`ckb-vm` 0.24.15 and `phf_generator` 0.8.0 through resource code generation.
The [advisory](https://rustsec.org/advisories/RUSTSEC-2026-0097.html) requires a
custom reentrant logger that obtains thread-local randomness during reseeding;
Morph defines no such logger. The isolated contract graph does not include it.
This is a documented unresolved upstream dependency, not a claim that rand 0.7
is patched. Its removal requires all three roots to use a patched rand family.
In particular, numext emits public `rand::AsByteSliceMut` implementations and
RngCore-based methods; a manifest-only upgrade to rand 0.8 does not compile, and
disabling support_rand would remove legitimate public APIs. That broader
generated-code/RNG API migration is outside this bounded compatibility change.

The former faster-hex, paste, memmap2 and lru audit ignores are removed;
deny.toml has no advisory ignores. The independent Biscuit/RustCrypto migration
also removes the prior proc-macro-error2/crypto-bigint paths; those waivers must
not be restored. An unwaived audit still reports the explicit rand warning.

## Vendored source integrity

[`vendor/README.md`](../vendor/README.md) describes all eleven exact upstream
consumer copies. Names, versions, original manifests, archive contents and
license metadata are retained. The original archive SHA-256 values were checked
against the pre-migration lockfile and fetched official crates.io archives.
`vendor/provenance.json` records every original file hash, each reviewed changed
file, upstream revisions when published, and readable patch digests. All changes
are dependency manifests except the one positive-capacity LRU constructor.
Most upstream archives omit separate MIT text; pinned upstream notices are
retained alongside the included cacache license.

`make supply-chain` runs the offline vendor integrity check before audit/deny.
The verifier rejects changed identities/licenses, extra source files, symlinks,
unrecorded content, expanded patch scope and divergence from root Cargo patches.
Its optional archive check also reconstructs every readable delta from official
published bytes. Vendored packages remain outside the fourteen workspace
members, so Morph lint policy does not rewrite or lint upstream test fixtures as
Morph production targets. Remove these patches as compatible upstream releases
become available.

Reproduce the graph checks with:

```sh
cargo tree --locked --workspace --all-features -i faster-hex
cargo tree --locked --workspace --all-features -i lru
cargo tree --locked --workspace --all-features -i memmap2
cargo tree --locked --workspace --all-features -i rand@0.7.3
python3 vendor/check.py --upstream-archives
cargo tree --locked -p morph-script-common --target riscv64imac-unknown-none-elf --edges normal,build
cargo audit --json
make supply-chain
```

## Local verification

The initial toolchain upgrade established:

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

The subsequent advisory migration adds focused evidence:

- All eleven archive checksums, complete file inventories and exact deltas
  match the official registry archives; `make vendor-check` passes.
- Seven ckb_compatibility tests pass: the three original fixed-boundary tests,
  unchecked hex decoding over 1,040 short-source/output combinations, actual RPC
  valid/malformed hex boundaries, memory-map overflow/range validation and LRU
  operation after a removed key destructor panics.
- All four hash_parity tests still pass.
- Reverse dependency trees select only faster-hex 0.10.1, pastey 0.2.3, memmap2
  0.9.12 and lru 0.18.2; the isolated contract normal/build graph remains free of
  all five waived package families.
- An unwaived audit reports no vulnerability entries and only the documented
  rand 0.7.3 unsoundness warning. Audit/deny policy removes the four fixed waivers.

Integrated ELF rebuild, manifest refresh, cost comparison, full CI and
clean-source local native qualification remain required for the final combined
candidate. Earlier ELF hashes and resource results do not qualify relinked code.
