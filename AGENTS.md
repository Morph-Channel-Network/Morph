# AGENTS.md — Morph Channel

Guidance for LLM/AI agents working in this repository. Focus on non-obvious knowledge: build/test commands, contract layout, witness/wire-format gotchas, and conventions that are not self-evident from a single file. For protocol context, read `README.md`; for readiness gates, read `docs/mainnet-readiness.md`.

## Project Snapshot

- Morph Channel is a CKB-native off-chain channel + factory implementation being developed for production deployment. Host-side protocol semantics live in `morph-core`; the on-chain boundary is a set of `no_std` CKB scripts built for `riscv64imac-unknown-none-elf`.
- Workspace members: four Rust crates (`crates/morph-core`, `crates/morph-cli`, `crates/morph-agent`, `crates/morph-fiber-adapter`) and nine contract crates under `contracts/` (including the shared script crate). Plus a TypeScript SDK (`sdk/typescript`), a React UI (`ui/morph-hub`).
- Production implementation is the development focus; current deployment evidence is from controlled devnet. Mainnet and real-asset releases require the gates in `docs/mainnet-readiness.md`. The bilateral multi-asset wire profile is implemented; remaining integrations are tracked in `docs/multi-asset-channels.md`.

## Build, Test, Lint

Use `make` targets — they orchestrate the right flags.

| Command | What it does |
| --- | --- |
| `make ci` | `fmt-check` + `lint` + `source-hygiene` + `supply-chain` + `test` + `fixture-checks` + SDK/UI checks + `contract-tests`. Use this for a full local gate. |
| `make test` | `cargo test --workspace --all-features`. |
| `make lint` | `cargo clippy --workspace --all-features --all-targets -- -D warnings`. Treat warnings as errors. |
| `make fmt` / `make fmt-check` | Apply / verify `cargo fmt --all`. |
| `make source-hygiene` | Syntax-check every shell script, reject npm lockfiles pinned to the unsupported `npmmirror.com` registry, and deny `unwrap`/`expect`/`panic!` in production Rust targets. |
| `make build-contracts` | Build all RISC-V scripts to `target/riscv64imac-unknown-none-elf/release/`. Required before `make contract-tests`. |
| `make contract-tests` | Runs `crates/morph-core/tests/contract_scripts.rs` against the built ELFs (uses `--ignored --test-threads=1`). Fails if ELFs are missing. |
| `make release-readiness` | Verifies all eight built ELF CKB data hashes, the v3 conditional-batch/dynamic-N no-real-assets envelope, and required operator runbooks. Run after `make build-contracts`. |
| `make package-contract-release` | Stages a deterministic bundle under `target/contract-release.*` and writes `target/factory-dynamic-n.tar.gz` after readiness checks pass. |
| `make supply-chain` | `cargo audit` then `cargo deny check`. See `Makefile` for ignored advisory IDs. |
| `make fixture-checks` | Generates and validates every protocol fixture (bilateral, factory, splice, watch). Writes to `target/fixture-checks/`. |
| `make smoke` | Workspace tests plus `cargo run -p morph-cli -- validate-fixture`. |

Devnet orchestration (requires a local CKB node binary and `jq`):

| Command | Purpose |
| --- | --- |
| `scripts/check-devnet-env.sh` | Confirms `ckb`, `jq`, and the `riscv64imac-unknown-none-elf` target are present. |
| `scripts/devnet-node.sh` | Boots a local CKB devnet with the IntegrationTest RPC module enabled. |
| `scripts/devnet-smoke.sh` / `make devnet-smoke` | Drives the smoke matrix against the local node. |
| `scripts/devnet-e2e.sh` / `make devnet-e2e` | End-to-end smoke. |
| `scripts/devnet-stateful-e2e.sh` / `make devnet-stateful-e2e` | Stateful acceptance matrix. |
| `scripts/fiber-morph-devnet-{preflight,acceptance,audit}.sh` | Cross-stack acceptance with Fiber (see `docs/fiber-morph-devnet-runbook.md`). |

UI (`ui/morph-hub`):

| Command | Purpose |
| --- | --- |
| `npm install` | One-time install. |
| `npm run build` | Type-check (`tsc --noEmit`) and produce `ui/morph-hub/dist/`, which the hub server serves. |
| `npm run dev` | Vite dev server; proxies `/api` to `http://127.0.0.1:4617` (see `ui/morph-hub/vite.config.ts`). |

Notes:

- The `audit` step ignores `RUSTSEC-2024-0436` (paste, unmaintained) and `RUSTSEC-2026-0097` (rand 0.7, unsound); comment in `Makefile` lines 5–11 explains why. Don't add new ignore flags without justification in the Makefile.
- The CI workflow (`.github/workflows/ci.yml`) mirrors `make ci` and pins Rust 1.92.0 plus the RISC-V target.
- `cargo audit` historically failed with IO errors when fetching the RustSec DB; see `SECURITY-FIXES.md` "Evidence run" for context.

## Repository Layout

```
crates/morph-core          Host-side protocol objects, signing digests, validation. No CKB runtime deps.
crates/morph-cli           CLI entry point. Subcommands: print/validate fixtures, devnet ops (devnet feature),
                           Morph Hub server, splice/factory/watchtower packages, smoke reports.
contracts/morph-script-common    Shared no_std parsers, lengths, domains, witness envelope dispatch.
contracts/morph-state-{lock,type}      State cell boundary.
contracts/morph-vault-lock            Vault settlement, splice checks.
contracts/morph-batch-lock            Bounded CKB conditional preimage/refund settlement.
contracts/morph-sponsor-lock          Bounded sponsor budget.
contracts/morph-factory-{type,vault-lock}  Factory state + reserve, with WitnessEnvelope dispatch.
contracts/morph-devnet-xudt           Devnet-only xUDT issuer/conservation script.
docs/                          Audits, runbooks, readiness gates, tutorials.
scripts/                       Devnet orchestration (see table above).
ui/morph-hub                   React + Vite + TypeScript operator console.
```

## Code Patterns and Conventions

- Support only current unpublished formats. Do not add old JSON aliases, missing-field migrations, alternate old wire parsers, or funding-anchor fallbacks. Reset development state after an incompatible change; see `docs/runbooks/upgrade-and-migration.md`.

### Crate boundaries

- `morph-core` is plain Rust (no CKB runtime). It defines types, signing digests, and host-side validation. It is used by both `morph-cli` and the contract tests.
- `morph-script-common` is `no_std` and shared by every contract crate. All length constants, domain-separation strings (e.g. `STATE_DOMAIN`, `FUNDING_CONTEXT_DOMAIN`), `WitnessEnvelope` dispatch, and helper parsers live here. Any change here is a wire-format change.
- CKB scripts use `#![cfg_attr(target_arch = "riscv64", no_std)]` plus `#![cfg_attr(target_arch = "riscv64", no_main)]` and provide a stub `fn main() {}` for host builds so `cargo check` works. `entry!(program_entry)` and `default_alloc!()` are gated the same way.
- Contract crates depend only on `ckb-std` + `morph-script-common`. Do not pull in `morph-core` from a contract — it would pull non-`no_std` code.

### Hashing and domain separation

- All commitments use `blake2b256` with the CKB personalization `b"ckb-default-hash"`, prefixed by an explicit domain string defined as a `const` next to the hasher. See `crates/morph-core/src/hash.rs`.
- Domain strings are duplicated between `morph-core` and `morph-script-common` (e.g. `STATE_DOMAIN`, `FUNDING_CONTEXT_DOMAIN`, `WITNESS_ENVELOPE_BODY_DOMAIN`, `SPLICE_HEADER_DOMAIN`, `FACTORY_SPLICE_HEADER_DOMAIN`, `FACTORY_VAULT_DESCRIPTOR_DOMAIN`, `FACTORY_VAULT_DELTA_DOMAIN`, `PARTICIPANTS_DOMAIN`). Any change must land in both places and is a wire-format break. `crates/morph-core/tests/hash_parity.rs` enforces parity.

### State header and witness formats

- `StateHeader` has a fixed encoded length of 346 bytes (`STATE_HEADER_LEN` in `morph-script-common`). `encode_state_header` / `StateHeader::parse` are the only legal encoders; treat the byte order as load-bearing.
- The multi-asset candidate uses the separate `multi_asset::MultiAssetStateHeader` parser and encoder: 318 bytes, State layout 2, descriptor 4, and domain-separated content/OutPoint set commitments. It has no single-Vault materialisation/OutPoint fields or duplicate content root. `StateHeader::parse` rejects that shape. See `docs/multi-asset-wire.md`; do not feed candidate packages through legacy single-Vault helpers.
- `pub vault_materialisation_root: Bytes32` in `crates/morph-core/src/types.rs` is the sole JSON and Rust field name; unpublished aliases are intentionally unsupported.
- Factory state headers (`FACTORY_STATE_HEADER_LEN = 302`), splice headers (`SPLICE_HEADER_LEN = 485`, `FACTORY_SPLICE_HEADER_LEN = 469`), and witness envelopes (`WITNESS_ENVELOPE_LEN = 8 + 2 + 2 + 2 + 4 + 32`, magic `b"MORPHW!!"`) are likewise fixed-layout. Splice-out headers sign the exact `withdrawal_lock_hash`; splice-in headers require it to be zero.

### Witness envelope dispatch

- Factory authorisations are carried in a single `WitnessEnvelope` and dispatched by kind/format/body length and a body commitment. See `WITNESS_ENVELOPE_KIND_*` constants and `WitnessEnvelopeKindSpec` table in `contracts/morph-script-common/src/lib.rs`. Bodies are parsed only after the envelope body's `blake2b256` matches the embedded commitment. The sole unpublished envelope format is `WITNESS_ENVELOPE_FORMAT = 1` with Factory kinds 1–8 (kind 8 `FACTORY_MULTI_RIGHT_UPDATE` is the 2.0 multi-right path; see `docs/factory-multi-right.md`).
- Factory participant sets support 2–16 members. All-participant paths require `N-of-N`; reduced paths commit the complete sorted membership but authorise exactly the touched participant. Reduced-rights/sparse-Merkle/reduced-exit/splice proofs retain `FACTORY_SPARSE_MERKLE_DEPTH = 256` and limited `FACTORY_*_COUNT` constants. Unknown proof shapes must remain rejected.
- Kind 8 multi-right updates: the touched participant updates 1–4 of their own value rights (`FACTORY_MULTI_RIGHT_MAX_COUNT = 4`), each proven independently against both state roots with compact proofs (`FACTORY_COMPACT_PROOF_MAX_SIBLINGS = 64` strictly-descending `(depth, hash)` pairs; omitted siblings must reconstruct from the canonical `FACTORY_RIGHT_EMPTY_DOMAIN` chain). Verification also enforces cross-side localization: any sibling subtree whose before/after hashes differ must contain another listed right, so no unlisted right can change between the committed roots. Quantity non-increase is enforced separately for CKB and every xUDT type; never sum quantities across asset domains. Host, CLI, and script arrays use raw `FactoryRightId` order, not hashed Merkle-key order. Host support lives in `morph-core` (`FactoryMultiRightMerkleUpdate`, `factory_right_sparse_proof_compact`) and `morph-cli` (`print|validate-factory-multi-right-update-package`); the devnet save/publication command is future work.
- Operator value-limit policy: `morph-core::policy` (`ValueLimitPolicy`, fail-closed, unlisted xUDT assets rejected) plus `morph-cli value-limit-check` / `validate-value-limit-policy`. Runbook: `docs/runbooks/value-limits.md`. It is an operator control only and never weakens script consensus.

### CKB cell selection discipline

- Scripts rely on `zero_or_one_group_cell_data` to detect create/supersede/finalise/splice-retire paths. The match arms in `contracts/morph-state-type/src/main.rs` are exhaustive over `(input, output)` shape.
- Vault finalisation requires exactly one authentic StateCell input with the expected StateType **and** StateLock hash. See "Authentic StateCell authority" in `SECURITY-FIXES.md` and tests `vault_lock_rejects_fake_state_header_without_state_type`, etc.
- `since` is encoded as canonical relative block (`relative_block_since` in `morph-script-common`). Raw `u64` is not a valid CKB `since`. CLI arguments are block counts.
- State retirement cannot orphan value: StateType finalise and splice retire paths require an input whose VaultCell commitment matches `StateHeader.vault_materialisation_root`.

### Multi-asset splice signing

- `multi_asset_splice` defines a 200-byte bridge header and up to 16 sorted per-asset flows. The complete transaction hash is signed; changing fees/inputs/dependencies requires fresh bridge and exact-OutPoint initial-exit signatures. Both new Active/0 and new Settling/1 authorizations must validate before old-context signing.
- Backend snapshots require explicit `splice` (including null). A prepared splice blocks updates; after local signature reservation it cannot be cancelled or reset by restart. `confirm-splice` now switches the same active session file only after canonical splice/State confirmation; the old backend remains irreversibly sealed in `morph.multi_asset_retired_session.v1` evidence. Never add an old-context unfreeze flag. StateType creation/retirement and Vault Lock now verify the bounded `MORPHMS!` envelope; old State is input 0, old Vaults follow, new State is output 0, then new Vaults and withdrawals. Both bridge and new-creation signatures are required. Native construction/submission and confirmed journal switching are implemented; continuous reconciliation service and terminal abort tracking remain open. See `docs/multi-asset-splice.md`.

### Watchtower reorg recovery

- Current watch cursors require `from_block`, contiguous scan heights, and `scanned_to_block_hash`; missing old fields are rejected. At startup and while scanning, the watchtower compares that hash with the canonical block returned by CKB RPC.
- An uninitialised cursor hash or a missing/mismatched canonical block emits a critical `chain_reorg_detected` alert, clears orphanable funding/observation context, and rescans from the channel's configured `from_block`.
- Operators must set `from_block` no later than channel creation and retain packages across funding contexts. Do not weaken this to resume from an unverifiable height.
- `devnet multi-asset-watch` is passive dispute correction: Active cells do not trigger settlement. It rejects conflicting saved/on-chain states, matches exact funding context and authentic scripts, and uses explicit plain fee inputs plus a bounded publication profile. Current support is finite watch passes for activated bilateral channels; service and automatic funding-activation integration remain work. Sponsor publication is supported.

### Signatures

- Signatures are prehashed secp256k1 with the CKB personalization. Bilateral signatures are 2-of-2; Factory all-participant signatures are N-of-N for N=2..16; reduced witnesses carry exactly one authorised touched-participant signature.
- Compressed pubkeys are exactly 33 bytes (`COMPRESSED_SECP256K1_PUBKEY_LEN = 33`).

### Sponsor policy boundary (script vs operator)

Each sponsor cell carries an immutable per-cell policy in its lock args. The sponsor lock enforces the state type, channel/state-number range, per-transaction fee cap, the cell's `already_spent + fee <= max_total_fee` bound, exact attribution of the transaction fee to sponsor capacity, and clean change. A separately funded output under new sponsor-lock args is a new budget; it cannot consume extra capacity from the input sponsor because `sponsor_fee == transaction_fee`. Expiry, sponsor-source, cadence, and similar runtime controls are **operator/watchtower policy only** and are not fields in the current 136-byte script policy.

### Multi-asset signing sessions

- `MultiAssetChannelBackend` uses the current multi-asset profile only. Persist `reserve_signature()` before invoking the local signer, then persist `record_signature()` before releasing its receipt. Cancel never resets the reservation. Only two valid signatures can commit a publishable recovery package.
- `multi-asset-session` enforces that order with a stable OS-locked sidecar and fsynced atomic snapshots; never unlink its `.lock` file, clone an active authority, or restore an older signer snapshot. Recovery package backups do not replace the monotonic signer journal.
- Splice sessions retain the exact packed raw transaction in required `splice_draft` evidence. `sign`/`add-signature` require an explicit `--target update|splice-creation|splice-recovery|splice-bridge`; no implicit signing role. Export persists the fully signed initial recovery package before returning the Morph-signed transaction. `init` accepts epoch 0 only; `confirm-splice` retains the same active session path; never initialise a second authority at a new funding-context path. Current snapshots require explicit `lineage`, including null. A non-null lineage requires RPC-enabled canonical/dependency checks before signing; `refresh-chain --package` updates evidence without resetting votes. Retired evidence is rejected as an active session.
- Root creation is epoch-0 unbound Active/0, signed over `MULTI_ASSET_ROOT_FUNDING_DOMAIN || state_digest || raw_tx_hash`. Ordinary state votes are rejected; public recovery validation requires bound epoch-0 evidence. Preserve a complete exact-TX exit before broadcasting. `bind-root` adds confirmed provenance to the existing journal without resetting votes; `export-root-funding` works offline/orphaned and `multi-asset-funding-submit` validates exact signed replay. Lineage uses explicit tagged Root/Splice origins, with no old-shape parser.
- `multi-asset-supervise` observes 1–32 registered session paths with four workers, nonblocking journal locks and one total RPC budget per check. Its atomic health has a config-bound expiry and is never signing authority; `multi-asset-supervision-health` fails on stale/unverified entries. Stable alert history survives busy checks and restart. Unguarded epoch-0 sessions are explicitly unmanaged; independent initial signing/failover remain open. Runbook: `docs/runbooks/signer-supervision.md`.
- Public proposal/signature messages use decimal strings and canonical hex. The private backend snapshot uses Rust serde integers and is not a JavaScript interchange format. SDK inspection is stateless and does not reserve a signer state number.

### Morph Hub server

- `crates/morph-cli/src/hub.rs` implements the full hub server from scratch (stdlib `TcpListener` + threads + `Mutex<HubStore>`); no HTTP framework. Constants `MAX_REQUEST_BODY_BYTES`, `MAX_REQUEST_LINE_BYTES`, `MAX_REQUEST_HEADER_BYTES`, `REQUEST_IO_TIMEOUT`, `MAX_CONCURRENT_CONNECTIONS`, `MAX_CONCURRENT_MUTATIONS`, `MAX_CONCURRENT_SSE_STREAMS`, mutation rate limit, and `MAX_INVOICE_EXPIRY_SECS` are all explicit guard rails; respect them.
- Server-sent events use `/api/events` only for the unauthenticated loopback path; token-protected sessions use authenticated short polling so the bearer token never appears in a URL.
- The Hub state file has one current unpublished shape; replacing it via the UI is disabled unless `--allow-state-restore` is passed.
- CORS for direct browser API access requires an explicit `--cors-origin http(s)://...`. Loopback is the default; `--allow-unauthenticated-loopback` is for local dev only.
- `--pubkey` is the **33-byte compressed secp256k1 pubkey as 66 hex chars without `0x`**; the 32-byte node id is derived from it. This matches Fiber's RPC-facing node-identity format.
- Auth tokens support `read,write,restore,sign:<secret>` scopes. Rotation is restart-based via `--rotate-auth-token-on-restart`.

### Devnet CLI

- `multi-asset-transact --operation activate ... wallet` recovers an unbound Active/0 State using its original on-chain funding witness and a saved signed settling package. It preserves the original descriptor, binds only the complete direct Vault set, and needs no participant keys. Never replace the initial descriptor with a newer saved one or reuse creation signatures for the bound header.

- `multi-asset-smoke --sponsor-publication` funds a separate target-state policy for each publication; combine with `--watch-publication --watch-reorg` for sponsor rollback acceptance. Operator/watch `sponsor --change-pubkey` takes no fee private key. Funding, activation and finalisation still use wallet fees.

- `cargo run -p morph-cli --features devnet -- devnet ...` is required for any `--devnet-only` subcommand (open-channel, supersede-smoke, factory-*-smoke, xudt-smoke, watch-config-once). Without the feature, the `devnet`, `rpc`, `watch_alert`, `watch_config`, and `watch_policy` modules are compile-gated out.
- Private-key env vars (`MORPH_DEVNET_PRIVATE_KEY`, `MORPH_ALICE_PRIVATE_KEY`, `MORPH_BOB_PRIVATE_KEY`, `MORPH_HUB_INVOICE_PRIVATE_KEY`, `MORPH_HUB_AUTH_TOKEN`, `MORPH_CHANNEL_PRIVATE_KEY`) are declared with clap's `hide_env_values = true` so they don't leak in `--help`. Don't print them anywhere.
- `MORPH_CKB_RPC` defaults to `http://127.0.0.1:18114` and is set up by `scripts/devnet-node.sh`.

### Wire format and fixtures

- The live wire format is defined by `morph-script-common` encoders and parsers; do not maintain a second schema draft.
- `make fixture-checks` regenerates every fixture under `target/fixture-checks/` and writes a JSON summary next to each. Check the JSON summaries when reviewing fixture-format changes.

## Testing Patterns

- Unit / invariant / hash-parity / invoice tests are plain Rust: `crates/morph-core/tests/{invariants,hash_parity,node_invoice}.rs` use `cargo test --workspace` and `proptest` for invariant fuzzing.
- Script integration tests live in `crates/morph-core/tests/contract_scripts.rs` and require the RISC-V ELFs on disk. They are `#[ignore]`-marked and run via `make contract-tests` with `--test-threads=1`. They read binaries from `target/riscv64imac-unknown-none-elf/release/` and will panic with a clear "run `make build-contracts` first" message if missing.
- Devnet smoke / stateful reports produce JSON + Markdown reports under `target/devnet-smoke/` and `target/devnet-stateful-e2e/` respectively; a `latest` symlink points to the newest successful run. `morph-cli` has `devnet-smoke-report`, `devnet-smoke-compare`, `devnet-smoke-assert`, `devnet-stateful-report`, `devnet-stateful-assert`, and `devnet-stateful-compare` subcommands for summarising and diffing these.
- Negative tests are first-class: every safety boundary in `SECURITY-FIXES.md` lists the negative-path test names. Add new negatives when adding new safety boundaries.
- Sample budget profiles are in `docs/devnet-smoke-budget.example.json`, `docs/devnet-stateful-budget.example.json`, and `docs/devnet-audit-profile.example.json`.

## Style

- Edition `2024`, Rust `1.92.0`. Pinned by `rust-toolchain.toml`; CI installs the same toolchain.
- `morph-cli` uses `clap` with the `derive` and `env` features; subcommands are an explicit `enum Command` with `#[command(subcommand)]`. New subcommands should follow the same shape and carry `#[arg(long)]` for any boolean toggle.
- Two crates use a `devnet` Cargo feature to gate devnet-only modules behind `#[cfg(feature = "devnet")]`. Don't put devnet code paths behind `#[cfg(devnet_only)]` ad hoc.
- JSON in/out is via `serde` + `serde_json`; many types re-export through `morph-core::*`. The codebase avoids `unwrap` in non-test code and prefers `anyhow::Result`/`ensure!` in CLI code and `Result<_, ScriptError>` in scripts.
- RISC-V contracts store `i8` error codes cast from `ScriptError` discriminants; `program_entry` returns `err as i8`. When adding a new error variant, also assign it a distinct numeric value (existing variants live in `morph-script-common`).

## Gotchas and Non-Obvious Rules

- **Both domain-string locations must change together.** `morph-core/src/hash.rs` and `contracts/morph-script-common/src/lib.rs` declare duplicate domain constants for use across the host/script boundary. `hash_parity.rs` enforces equality at test time.
- **`vault_materialisation_root` is the only accepted JSON name.** Do not reintroduce unpublished aliases.
- **Boundary versions are not free.** Bumping `WITNESS_ENVELOPE_FORMAT`, any `FACTORY_*_WITNESS_VERSION`, the `STATE_HEADER_LEN`, or any `*_LEN` constant is a wire-format break and breaks every dependency on it (parsers, fixtures, contract tests, devnet smoke). Check fixtures and security audits first.
- **Reduced-rights factories only support the documented proof shapes.** Signer membership is dynamic from 2–16; kind 8 supports bounded multi-right compact proofs. Additional proof shapes must remain rejected. Multi-asset rights do not imply that the physical Vault or child-settlement paths support multiple xUDT types.
- **Devnet-only `morph-devnet-xudt`.** It is not safe for non-devnet use. The contract name and the README both call this out.
- **`devnet` feature on `morph-cli`.** The `devnet` feature gates RPC client, fixture-server utilities, `watch_*`, and the entire `devnet` subcommand. A default build will silently lack these.
- **Hub auth tokens are scoped.** `read,write,restore,sign:<secret>` is the documented scope syntax; an unprefixed token is all-scope. Don't log the secret.
- **Mutation rate limit is per-instance.** `MAX_MUTATIONS_PER_WINDOW = 120` over `MUTATION_RATE_LIMIT_WINDOW = 60s` applies per hub process. Be aware when load-testing.
- **Invoices are Morph-native, not Fiber or Lightning.** Encoding/decoding/settle live in `crates/morph-cli` (`new-invoice`, `decode-invoice`, `settle-invoice`) and `crates/morph-core/src/node.rs`. The sole encoding is Bech32m with HRP `morph`.
- **Local semantic tests don't need CKB.** `cargo test --workspace` and `cargo run -p morph-cli -- validate-fixture` run without any CKB binary. Only `make contract-tests` and the `scripts/*` flows need `ckb`.
- **CI caches the cargo target.** First CI run is slow; locally expect a multi-minute `make build-contracts` plus initial tests.

## Where to Look

- Protocol object model: `crates/morph-core/src/types.rs`
- Signing digests and domain strings: `crates/morph-core/src/hash.rs`, `contracts/morph-script-common/src/lib.rs`
- Validation errors and rules: `crates/morph-core/src/validation.rs`
- Witnesses, splice envelopes: `contracts/morph-script-common/src/lib.rs` (length table, envelope dispatch)
- State cell script entrypoint and shape dispatch: `contracts/morph-state-type/src/main.rs`
- Fixtures: `crates/morph-cli/src/{packages,splice_packages,factory_packages}.rs`
- Hub server: `crates/morph-cli/src/hub.rs`
- Devnet flows: `crates/morph-cli/src/devnet.rs`, `scripts/devnet-*.sh`
- Safety boundaries and their tests: `SECURITY-FIXES.md`
- Audit findings and remediation: `docs/swarm-audit-*.md`, `docs/audit-*.md`
- Readiness gates: `docs/mainnet-readiness.md`, `docs/roadmap.md`
