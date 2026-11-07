# RustCrypto dependency migration

The candidate replaces `k256` 0.13.4 / `ecdsa` 0.16.9 /
`elliptic-curve` 0.13.8 / `crypto-bigint` 0.5.5 with the locked combination
`k256` 0.14.0, `ecdsa` 0.17.0, `elliptic-curve` 0.14.3 and
`crypto-bigint` 0.7.10. The fixed `crypto-bigint` release floor is 0.7.6;
[RUSTSEC-2026-0387](https://rustsec.org/advisories/RUSTSEC-2026-0387.html)
describes secret-dependent arithmetic timing in older releases. This migration
removes its Makefile and cargo-deny waivers. Supply-chain checks must continue to
reject a reintroduced vulnerable version anywhere in the workspace graph.

`k256` 0.14.0 requires Rust 1.85; the selected `elliptic-curve` and
`crypto-bigint` releases require Rust 1.87. The RustCrypto dependency keeps default features disabled and does not enable
its `std` or `alloc` features. The shared script crate continues to build for
`riscv64imac-unknown-none-elf`.
The workspace toolchain and CKB family migration are coordinated separately.

## Biscuit source pin

The published `biscuit-auth` 6.0.0 unconditionally depends on `p256` 0.13,
`ecdsa` 0.16 and `elliptic-curve` 0.13, so changing only Morph's direct `k256`
dependency leaves `crypto-bigint` 0.5.5 in the graph. The candidate pins the
[official Biscuit repository](https://github.com/biscuit-auth/biscuit-rust)
to commit `21e650f31a8521af575f968925acbb56486172f9`. That revision includes the
[upstream RustCrypto migration](https://github.com/biscuit-auth/biscuit-rust/commit/1cb632fa40995cce85b7d8d830ffe5a4c8756999)
and resolves `p256` 0.14 through the same fixed arithmetic stack. Cargo.lock pins
all three Biscuit workspace packages to that exact revision. cargo-deny's git
source allowance is limited to this single repository; unknown git sources
remain denied. Replace the pin with a registry release containing the upstream
migration and remove the source allowance when that release becomes available.
No local crypto fork is used.

The upstream change also removes `proc-macro-error2` from the graph, so its
`RUSTSEC-2026-0173` Makefile waiver is removed.

## Compatibility evidence and remaining release work

The current Morph protocol encoders, digest domains, 33-byte compressed public
keys, and 64-byte prehashed signatures are unchanged. The mechanical API changes
are SEC1's `to_encoded_point` rename to `to_sec1_point`, and adapting explicit
high-S checks to the now-idempotent `normalize_s` return value. Verification
continues to reject high-S signatures; it does not normalize received signatures
into accepted authority. Biscuit now signs through `PrivateKey` directly instead
of the removed `KeyPair` wrapper.

`morph-script-common::crypto_compatibility` pins deterministic signature bytes
captured from k256 0.13.4 and checks both bilateral and Factory verifiers against
low-S signatures, high-S twins, modified digests, wrong signers, malformed keys,
zero scalars and incorrect witness lengths. Existing hash-parity and protocol
fixture tests cover unchanged domain and wire commitments. The credential tests
exercise both Ed25519 and P-256 roots, restored authority, wrong roots, substituted
claims and expiry.

Relinking scripts changes their ELF data hashes even with identical protocol
encodings. Fresh integrated ELFs, the release manifest, VM boundary tests,
worst-case cycle/capacity budgets, native acceptance and final CI remain required
before release. Passing dependency and host/no_std checks alone does not satisfy
those gates or authorize real-asset deployment.

## Integrated VM and ELF measurements

The combined development candidate includes the Factory delegation checks and
CKB/Rust 1.95 migration, so these results must not be attributed solely to the
crypto dependency. Its rebuilt eight ELFs total 755,456 bytes, versus 947,928 in
the published `c8787f0` baseline. Their exact code identities and sizes are in
`release/factory-preproduction/contracts.json`; historical release assets remain
unchanged. All 89 registered VM tests pass against the rebuilt scripts, including
the five new delegated-boundary tests.

| Same bounded VM fixture | Published baseline cycles | Combined candidate cycles | Transaction bytes |
| --- | ---: | ---: | ---: |
| Full materialisation, 8 assets / 4 children / 16 members / maximum Scripts | 64,410,680 | 51,988,923 | 75,098 |
| Reduced child, 8 assets / 4 children / 16 members / 9 claims | 61,741,373 | 61,243,393 | 85,535 |
| Reduced release, 8 assets / 16 members / 9 claims | 49,018,410 | 48,121,086 | 32,985 |
| Reduced metadata, 10 rights / 8 assets / 16 members / maximum Scripts | 50,019,528 | 48,698,490 | 14,600 |

These are CKB-VM fixture resource counts under the existing 70M ceiling, not
production fees or latency. The clean `ed870817` native checkpoint subsequently passed the five-case matrix
and its separate one/four/ten-right budgets. That historical evidence does not
qualify the later vendor/admission candidate. The current no-value envelope is
`B_controlled_devnet_local`; `make qualify-local-candidate` re-executes all local
gates against its exact source and artifact identities, with
`release_admitted=false` and no publication.
