# AGENTS.md — Morph Channel

Guidance for LLM/AI agents working in this repository. Focus on non-obvious knowledge: build/test commands, contract layout, witness/wire-format gotchas, and conventions that are not self-evident from a single file. For protocol context, read `README.md`; for readiness gates, read `docs/mainnet-readiness.md`.

## Project Snapshot

- Morph Channel is a CKB-native off-chain channel + factory implementation being developed for production deployment. Host-side protocol semantics live in `morph-core`; the on-chain boundary is a set of `no_std` CKB scripts built for `riscv64imac-unknown-none-elf`.
- Workspace members: ten host Rust crates (`morph-core`, `morph-key-input`, `morph-cli`, `morph-payment-gateway`, `morph-fiber-adapter`, `morph-packages`, `morph-hub-api`, `morph-sdk`, `morph-desktop`, `morph-xtask`) and nine contract crates under `contracts/` (including the shared script crate). The sole frontend is native GPUI; JavaScript/TypeScript sources, Node tooling and browser UI builds are retired.
- Morph Payment Gateway (`morph-payment-gateway`) is the application-layer payment and access gateway: payment processing, signed receipts, Biscuit authorization, and paid API access. Its current name is the sole supported crate, binary, SDK, and environment namespace.
- Production implementation is the development focus; current deployment evidence is from controlled devnet. Mainnet and real-asset releases require the gates in `docs/mainnet-readiness.md`. The bilateral multi-asset wire profile is implemented; remaining integrations are tracked in `docs/multi-asset-channels.md`.

## Build, Test, Lint

Use `make` targets — they orchestrate the right flags.

| Command | What it does |
| --- | --- |
| `make ci` | `fmt-check` + `lint` + `source-hygiene` + `supply-chain` + `test` + `fixture-checks` + Rust client/native desktop checks + `contract-tests`. Use this for a full local gate. |
| `make test` | `cargo test --workspace --all-features`. |
| `make lint` | `cargo clippy --workspace --all-features --all-targets -- -D warnings`. Treat warnings as errors. |
| `make fmt` / `make fmt-check` | Apply / verify `cargo fmt --all`. |
| `make source-hygiene` | Syntax-check every shell script, reject JS/TS source and retired client dependency manifests, and deny `unwrap`/`expect`/`panic!` in production Rust targets. |
| `make build-contracts` | Build all RISC-V scripts to `target/riscv64imac-unknown-none-elf/release/`. Required before `make contract-tests`. |
| `make contract-tests` | Runs `crates/morph-core/tests/contract_scripts.rs` against the built ELFs (uses `--ignored --test-threads=1`). Fails if ELFs are missing. |
| `make release-readiness` | Verifies all eight built ELF CKB data hashes, the current-custody no-real-assets envelope, and required operator runbooks. Run after `make build-contracts`. |
| `make qualify-local-candidate` | Runs full CI, clean-source native acceptance, local packaging and exact source/artifact qualification without publishing. |
| `make package-contract-release` | Stages a deterministic bundle under `target/contract-release.*` and writes `target/morph-current-custody.tar.gz` after readiness checks pass. |
| `make supply-chain` | `cargo audit` then `cargo deny check`. See `Makefile` for ignored advisory IDs. |
| `make fixture-checks` | Generates and validates every protocol fixture (bilateral, factory, splice, watch). Writes to `target/fixture-checks/`. |
| `make smoke` | Workspace tests plus `cargo run -p morph-cli -- validate-fixture`. |

Devnet orchestration (requires a local CKB node binary and `jq`):

| Command | Purpose |
| --- | --- |
| `scripts/check-devnet-env.sh` | Confirms `ckb`, `jq`, and the `riscv64imac-unknown-none-elf` target are present. |
| `scripts/devnet-node.sh` | Boots a local CKB devnet with the IntegrationTest RPC module enabled. |
| `scripts/devnet-current-e2e.sh` / `make devnet-current-e2e` | Runs the sole current native matrix, derived stateful evidence, budgets and clean-source checks on a fresh development node; `EXTERNAL_RPC_URL` explicitly selects an existing development RPC. |
| `scripts/devnet-smoke.sh` / `make devnet-smoke` | Delegates to the same current acceptance pipeline. |
| `scripts/devnet-e2e.sh` / `make devnet-e2e` | Delegates to the same current acceptance pipeline. |
| `scripts/devnet-stateful-e2e.sh` / `make devnet-stateful-e2e` | Delegates to the same current acceptance pipeline. |
| `scripts/fiber-morph-devnet-{preflight,acceptance,audit}.sh` | Cross-stack acceptance with Fiber (see `docs/fiber-morph-devnet-runbook.md`). |

Native desktop and clients:

| Command | Purpose |
| --- | --- |
| `make desktop` | Check native Linux build inputs and start the GPUI application. |
| `make desktop-check` | Native headless interaction/model tests and desktop binary build. |
| `make rust-client-check` | Shared codecs, Rust SDK review/transport and native acceptance runner tests. |

`morph-cli hub serve` serves JSON `/api` only; it has no static directory or browser fallback. Start it separately, then connect from the native desktop. See `docs/native-desktop.md` for platform, dependency and runtime limits. Private signing journals stay in the existing operator ceremony; the desktop has no channel signing authority.

Notes:

- The `audit` step carries explicit upstream waivers in `AUDIT_IGNORE` (top of `Makefile`); each has a rationale and removal condition in the comment block above it. Don't add new ignore flags without the same justification. The RustCrypto/Biscuit migration removes `RUSTSEC-2026-0387` and `RUSTSEC-2026-0173`; never restore those waivers. Current CKB patches are verified by `vendor/check.py`; only the explicit rand 0.7 upstream waiver remains, with its removal condition in `docs/ckb-toolchain-upgrade.md`. Relinked ELFs require fresh manifest and resource evidence even when wire encoding is unchanged.
- The CI workflow (`.github/workflows/ci.yml`) mirrors `make ci` and pins Rust 1.95.0 plus the RISC-V target.
- `cargo audit` historically failed with IO errors when fetching the RustSec DB; see `SECURITY-FIXES.md` "Evidence run" for context.

## Repository Layout

```
crates/morph-core          Host-side protocol objects, signing digests, validation. No CKB runtime deps.
crates/morph-key-input     Shared host-only protected key-file loader and zeroizing/redacted key material.
crates/morph-cli           CLI entry point. Subcommands: print/validate fixtures, devnet ops (devnet feature),
                           Morph Hub server, splice/factory/watchtower packages, smoke reports.
contracts/morph-script-common    Shared no_std parsers, lengths, domains and typed capability frames.
contracts/morph-state-{lock,type}      State cell boundary.
contracts/morph-vault-lock            Vault settlement, splice checks.
contracts/morph-batch-lock            Bounded CKB conditional preimage/refund settlement.
contracts/morph-sponsor-lock          Bounded sponsor budget.
contracts/morph-factory-{type,vault-lock}  Current Factory authority + Vault-set custody (FS/FM/FR).
contracts/morph-devnet-xudt           Devnet-only xUDT issuer/conservation script.
docs/                          Audits, runbooks, readiness gates, tutorials.
scripts/                       Devnet orchestration (see table above).
crates/morph-packages          Sole shared public package codecs, construction/review and persistence.
crates/morph-hub-api           Owned typed public Hub requests/responses, no private store state.
crates/morph-sdk               Bounded authenticated Rust HTTP client and stateless protocol inspection.
crates/morph-desktop           Native GPUI operator console; bounded worker, review/confirm, no signer.
crates/morph-xtask             Rust protocol/Fiber/Gateway regression and source-hygiene tools.
fixtures/                     Minimal current protocol samples, Gateway vector and native scenario definitions.
```

## Code Patterns and Conventions

- Support only current unpublished formats. Do not add old JSON aliases, missing-field migrations, alternate old wire parsers, or funding-anchor fallbacks. Reset development state after an incompatible change; see `docs/runbooks/upgrade-and-migration.md`.
- The shared-foundation architecture (option C) is implemented; see `docs/unified-protocol-migration.md`. New capabilities use the current Vault-set model and common signing/recovery components. Retired single-Vault State, Factory, splice and package codecs must not be reintroduced. Capability migration and verified retirement are both required; removal of a feature is not a completed migration.

### Crate boundaries

- `morph-core` is plain Rust (no CKB RPC or VM runtime). It uses `ckb-types` for canonical host-side packed transaction/Script serialization, shared by the Factory journal and CLI instead of duplicating physical-body parsing. It defines types, signing digests, and host-side validation. It is used by both `morph-cli` and the contract tests.
- `morph-script-common` is `no_std` and shared by every contract crate. All current length constants, role-separated domains (e.g. `MULTI_ASSET_STATE_DOMAIN`, `MULTI_ASSET_FUNDING_CONTEXT_DOMAIN`), bounded capability frames, and helper parsers live here. Changes to encodings, domains or field layouts are wire-format changes; verifier-only changes still alter ELF identity and require rebuilt evidence.
- CKB scripts use `#![cfg_attr(target_arch = "riscv64", no_std)]` plus `#![cfg_attr(target_arch = "riscv64", no_main)]` and provide a stub `fn main() {}` for host builds so `cargo check` works. `entry!(program_entry)` and `default_alloc!()` are gated the same way.
- Contract crates depend only on `ckb-std` + `morph-script-common`. Do not pull in `morph-core` from a contract — it would pull non-`no_std` code.
- Rust 1.95 contract builds use `-C passes=lower-atomic` in both `.cargo/config.toml` and `scripts/build-contracts.sh`. Keep these aligned and leave `ckb-std`'s `dummy-atomic` feature disabled; the former `target-feature=-a` combination is unsupported by this toolchain. CKB-VM does not support RISC-V atomic instructions.

### Hashing and domain separation

- All commitments use `blake2b256` with the CKB personalization `b"ckb-default-hash"`, prefixed by an explicit domain string defined as a `const` next to the hasher. See `crates/morph-core/src/hash.rs`.
- Shared current domains are pinned across `morph-core::hash` and `morph-script-common`; `hash_parity.rs` verifies equality. Factory root funding, exact metadata updates, materialisation, reduced transitions, bilateral state votes and splice bridges have distinct roles. Never replace one role with another even when the participant keys coincide.

### Current State and witness formats

- Bilateral State uses `multi_asset::MultiAssetStateHeader`: 318 bytes, layout 2 and descriptor 5. One to eight Vaults share a content commitment and exact OutPoint-set commitment. A one-asset channel uses this same implementation.
- Descriptor 5 requires an explicit `Ordinary` or `CkbConditional` capability. Pending conditions consume CKB business value only; reserves, other assets and the signed State carrier remain independently conserved. The canonical inner Batch terms codec is 828 bytes; that shared primitive is not an older State profile. The Batch lock has 104-byte args binding channel, exact funding context, state number and terms commitment.
- `MultiAssetStateTypeArgs::parse` is the sole Type-args parser: direct origin is `anchor32 || since8`; Factory child origin is `anchor32 || FactoryTypeHash32 || since8`. Since occupies the final eight bytes. Reject zero Factory origin and noncanonical relative since. Vault args are 116 bytes and bind anchor, since, authentic StateType and StateLock.
- Factory State is 306 bytes, with 44-byte `MORPHFT!` Type args and 64-byte reserve-lock args. Its custody uses the same bounded manifest and per-Type values. There are no old State/Vault, descriptor1/2, old splice or envelope-kind fallbacks.

### Typed Factory authority and proofs

- `MORPHFS!` format2 carries root, permissionless activation and exact-transaction metadata update. Full consent is N-of-N for 2–16 sorted members. `MORPHFM!` is full-consent materialisation with optional retained custody. `MORPHFR!` operations are reduced release0, rights1, deposit2, full custody4 and reduced child5; unknown tag3 is rejected.
- Reduced transitions commit the complete membership and carry exactly the touched member's signature. Compact SMT proofs have depth 256 and at most 64 descending sibling pairs per leaf. Public before/after root localization prevents unlisted leaf changes. Raw `FactoryRightId` order is canonical; never sort by hashed key.
- Reduced metadata supports up to 10 value rights; physical transitions support at most 9 claims (global CKB plus up to 8 token Types). Quantity rules are independent for every asset. CKB reserve/business lanes are global across Vaults; tokens remain per-Type. Never sum token amounts across Types or use carriers/fees as claims.
- Physical release, deposit and child operations use precommitted `ReserveClaim` leaves. Initial allocation must provide intended rights and enough operating reserve for payout geometry and the retained Factory floor. Backing checks alone do not prove arbitrary allocations withdrawable. Last retained reserve and the shared carrier require full consent.
- Every member retains a complete initial rights snapshot. Given that saved data, reduced public changes permit local proof refresh without peer interaction; the chain's root commitment alone cannot reconstruct lost rights data. Full-consent replacement requires delivery of a complete new snapshot before signing. `factory-session refresh/reconcile` retains prior reservations and approvals across canonical changes. Explicit replacement does not revoke an older approval: first canonical source consumption settles the operation.
- Full-consent `FullCustody` permits all-member rights redistribution without the single-member claim-delta predicate. It still enforces actual complete custody, independent asset conservation, occupied capacity, carrier and external fee/funding checks. Never describe it as skipping physical conservation.
- Child parties may be outside the Factory roster. Their committed two keys and private exits are independent of parent authority: only roster members/all-N or the touched member can authorize Factory consumption. Provider routing reservation/liquidity admission is a separate check.
- Child initial exits use independent `factory-child-session` journals. Both child parties persist their complete private exit before public possession attestations. Parent requests contain only public terms/receipts. Confirmed Factory-origin provenance performs same-path handoff into the ordinary bilateral journal; it cannot masquerade as Root funding or initialise another authority.
- Operator value limits are fail-closed and admit every committed token right even when its quantity is zero. They remain an operator control, never a weaker consensus rule.

### CKB cell selection discipline

- Scripts rely on `zero_or_one_group_cell_data` to detect create/supersede/finalise/splice-retire paths. The match arms in `contracts/morph-state-type/src/main.rs` are exhaustive over `(input, output)` shape.
- Vault finalisation requires exactly one authentic StateCell input with the expected StateType **and** StateLock hash. Current VM boundary matrices cover fake/cloned authority, wrong script identity and duplicated State inputs; historical audit names are mapped to current tests.
- `since` is encoded as canonical relative block (`relative_block_since` in `morph-script-common`). Raw `u64` is not a valid CKB `since`. CLI arguments are block counts.
- State retirement cannot orphan value: StateType finalise and splice retire paths authenticate and consume the complete committed Vault set.

### Multi-asset splice signing

- `multi_asset_splice` defines a 200-byte bridge header and up to 16 sorted per-asset flows. The complete transaction hash is signed; changing fees/inputs/dependencies requires fresh bridge and exact-OutPoint initial-exit signatures. Both new Active/0 and new Settling/1 authorizations must validate before old-context signing.
- Backend snapshots require explicit `splice` (including null). A prepared splice blocks updates; after local signature reservation it cannot be cancelled or reset by restart. `confirm-splice` now switches the same active session file only after canonical splice/State confirmation; the old backend remains irreversibly sealed in `morph.multi_asset_retired_session.v1` evidence. Never add an old-context unfreeze flag. StateType creation/retirement and Vault Lock now verify the bounded `MORPHMS!` envelope; old State is input 0, old Vaults follow, new State is output 0, then new Vaults and withdrawals. Both bridge and new-creation signatures are required. Native construction/submission and confirmed journal switching are implemented; continuous reconciliation service and terminal abort tracking remain open. See `docs/multi-asset-splice.md`.

### Watchtower reorg recovery

- Current watch cursors require `from_block`, contiguous scan heights, and `scanned_to_block_hash`; missing old fields are rejected. At startup and while scanning, the watchtower compares that hash with the canonical block returned by CKB RPC.
- An uninitialised cursor hash or a missing/mismatched canonical block emits a critical `chain_reorg_detected` alert, clears orphanable funding/observation context, and rescans from the channel's configured `from_block`.
- Operators must set `from_block` no later than channel creation and retain packages across funding contexts. Do not weaken this to resume from an unverifiable height.
- `devnet multi-asset-watch` is passive dispute correction: Active cells do not trigger settlement. It rejects conflicting saved/on-chain states, matches exact funding context and authentic scripts, and uses explicit plain fee inputs plus a bounded publication profile. Finite passes and the continuous configuration service share this sole current observer/publisher. Service health, validated configuration reload, policy/webhook alerts and exact-state sponsor funding are implemented. Automatic funding activation, independent failover and pooled publication remain separate work.

### Signatures

- Signatures are prehashed secp256k1 with the CKB personalization. Bilateral signatures are 2-of-2; Factory all-participant signatures are N-of-N for N=2..16; reduced witnesses carry exactly one authorised touched-participant signature.
- Compressed pubkeys are exactly 33 bytes (`COMPRESSED_SECP256K1_PUBKEY_LEN = 33`).

### Sponsor policy boundary (script vs operator)

Each sponsor cell carries an immutable per-cell policy in its lock args. The sponsor lock enforces the state type, channel/state-number range, per-transaction fee cap, the cell's `already_spent + fee <= max_total_fee` bound, exact attribution of the transaction fee to sponsor capacity, and clean change. A separately funded output under new sponsor-lock args is a new budget; it cannot consume extra capacity from the input sponsor because `sponsor_fee == transaction_fee`. Expiry, sponsor-source, cadence, and similar runtime controls are **operator/watchtower policy only** and are not fields in the current 136-byte script policy.

### Multi-asset signing sessions

- `MultiAssetChannelBackend` uses the current multi-asset profile only. Persist `reserve_signature()` before invoking the local signer, then persist `record_signature()` before releasing its receipt. Cancel never resets the reservation. Only two valid signatures can commit a publishable recovery package.
- `multi-asset-session` enforces that order with a stable OS-locked sidecar and fsynced atomic snapshots; never unlink its `.lock` file, clone an active authority, or restore an older signer snapshot. Recovery package backups do not replace the monotonic signer journal.
- Splice sessions retain the exact packed raw transaction in required `splice_draft` evidence. `sign`/`add-signature` require an explicit `--target update|splice-creation|splice-recovery|splice-bridge`; no implicit signing role. Export persists the fully signed initial recovery package before returning the Morph-signed transaction. Initial funding uses the immutable `multi-asset-funding-session` ceremony and confirmed same-path handoff; operational `init`/`bind-root` are removed; `confirm-splice` retains the same active session path; never initialise a second authority at a new funding-context path. Operational commands reject null `lineage`; new journals obtain confirmed provenance only through same-path handoff. Lineage requires RPC-enabled canonical/dependency checks before signing; `refresh-chain --package` updates evidence without resetting votes. Retired evidence is rejected as an active session.
- Root creation is epoch-0 unbound Active/0, signed over `MULTI_ASSET_ROOT_FUNDING_DOMAIN || state_digest || raw_tx_hash`. Ordinary state votes are rejected; public recovery validation requires bound epoch-0 evidence. Preserve a complete exact-TX exit before broadcasting. The funding ceremony collects a complete exit before creation, then `confirm` seals initial reservations and switches the same path to a guarded session; `export-root-funding` works offline/orphaned and `multi-asset-funding-submit` validates exact signed replay. Lineage uses explicit tagged Root/Splice/Factory origins, with no old-shape parser.
- Public root construction uses `multi-asset-funding-prepare` and strict `morph.multi_asset_root_terms.v1`: canonical explicit funders/inputs, exact per-wallet CKB/fee and per-Type token contributions, and owner-only change. The native builder never mints or selects replacement inputs. `multi-asset-funding-wallet-sign` reconstructs the exact body before signing only the declared wallet group, after complete root/exit authorization. `multi-asset-funding-submit` is keyless with no wallet/presigned fallback; full VM preflight precedes immutable binary persistence, preventing partial-witness attempts from poisoning that path. The harness uses these public paths.
- `multi-asset-supervise` observes 1–32 registered session paths with four workers, nonblocking journal locks and one total RPC budget per check. Its atomic health has a config-bound expiry and is never signing authority; `multi-asset-supervision-health` fails on stale/unverified entries. Stable alert history survives busy checks and restart. Unguarded epoch-0 sessions are explicitly unmanaged; failover and pooled publication remain open. Runbook: `docs/runbooks/signer-supervision.md`.
- Public proposal/signature messages use decimal strings and canonical hex. Private snapshots use Rust serde integers. `serde_json` arbitrary_precision is required when passing state-file JSON through the SDK so u128 values remain exact. SDK inspection is stateless and does not reserve a signer state number.
- Payment intent expiry gates preparation and new local signing reservations. Already issued valid state signatures remain authority after expiry; `commit_payment` may reconcile the exact co-signed proposal or recover its already committed result. Expiry alone never authorizes cancellation, refund or journal reset.

### Morph Hub server

- `crates/morph-cli/src/hub.rs` implements the API-only hub server from scratch (stdlib `TcpListener` + threads + `Mutex<HubStore>`); no HTTP framework. Constants `MAX_REQUEST_BODY_BYTES`, `MAX_REQUEST_LINE_BYTES`, `MAX_REQUEST_HEADER_BYTES`, `REQUEST_IO_TIMEOUT`, `MAX_CONCURRENT_CONNECTIONS`, `MAX_CONCURRENT_MUTATIONS`, `MAX_CONCURRENT_SSE_STREAMS`, mutation rate limit, and `MAX_INVOICE_EXPIRY_SECS` are all explicit guard rails; respect them.
- The server retains `/api/events` for explicit unauthenticated loopback clients. The native application uses bounded authenticated polling in both modes; tokens never enter URLs or persistent preferences.
- The Hub state file has one current unpublished shape; replacing it via the UI is disabled unless `--allow-state-restore` is passed.
- CORS for direct browser API access requires an explicit `--cors-origin http(s)://...`. Loopback is the default; `--allow-unauthenticated-loopback` is for local dev only.
- `--pubkey` is the **33-byte compressed secp256k1 pubkey as 66 hex chars without `0x`**; the 32-byte node id is derived from it. This matches Fiber's RPC-facing node-identity format.
- Auth tokens support `read,write,restore,sign:<secret>` scopes. Rotation is restart-based via `--rotate-auth-token-on-restart`.

### Devnet CLI

- `multi-asset-transact --operation activate ... wallet` recovers an unbound Active/0 State using its original on-chain funding witness and a saved signed settling package. It preserves the original descriptor, binds only the complete direct Vault set, and needs no participant keys. Never replace the initial descriptor with a newer saved one or reuse creation signatures for the bound header.

- `multi-asset-smoke --sponsor-publication` funds a separate target-state policy for each publication; combine with `--watch-publication --watch-reorg` for sponsor rollback acceptance. Operator/watch `sponsor --change-pubkey` takes no fee private key. Funding, activation and finalisation still use wallet fees.

- `cargo run -p morph-cli --features devnet -- devnet ...` is required for any `--devnet-only` subcommand (multi-asset-smoke, factory smoke, multi-asset-transact, watch-config-once). The `devnet` namespace requires the feature. Initial-funding participant signing also refreshes its pinned admission RPC in the default build; inspection and saved recovery exports remain offline. Package, watch-policy/config and alert helpers remain usable without the feature.
- Private keys enter through `--*-private-key-file` or `*_PRIVATE_KEY_FILE` paths only. Shared Linux-only `morph-key-input` validates the opened regular file, current owner, owner-only permissions, bounded single-key encoding and scalar; symlinks/FIFOs and unsupported platforms fail closed. Raw-key argv/env aliases are removed. Keep `SecretString` Debug redacted and buffers zeroizing. Never pass secret bytes to child-process argv/env. See `docs/runbooks/key-input.md`. Hub auth tokens have their separate scoped input policy.
- `MORPH_CKB_RPC` defaults to `http://127.0.0.1:18114` and is set up by `scripts/devnet-node.sh`.

### Wire format and fixtures

- The live wire format is defined by `morph-script-common` encoders and parsers; do not maintain a second schema draft.
- `make fixture-checks` regenerates every fixture under `target/fixture-checks/` and writes a JSON summary next to each. Check the JSON summaries when reviewing fixture-format changes.

## Testing Patterns

- Unit / invariant / hash-parity / invoice tests are plain Rust: `crates/morph-core/tests/{invariants,hash_parity,node_invoice}.rs` use `cargo test --workspace` and `proptest` for invariant fuzzing.
- Script integration tests live in `crates/morph-core/tests/contract_scripts.rs` and require the RISC-V ELFs on disk. They are `#[ignore]`-marked and run via `make contract-tests` with `--test-threads=1`. They read binaries from `target/riscv64imac-unknown-none-elf/release/` and will panic with a clear "run `make build-contracts` first" message if missing.
- The current native runner writes JSON evidence under `target/current-protocol-e2e/<run>/scenarios/smoke` and derived stateful scenarios under `.../scenarios`. Only a successful budget/audit/source-freshness run updates `target/current-protocol-e2e/latest`. The default `devnet-smoke-report|compare|assert` and `devnet-stateful-report|assert|compare` commands consume these current directories; the earlier shell entrypoints delegate to this same runner.
- Negative tests are first-class: every safety boundary in `SECURITY-FIXES.md` lists the negative-path test names. Add new negatives when adding new safety boundaries.
- Sample budget profiles are in `docs/devnet-smoke-budget.example.json`, `docs/devnet-stateful-budget.example.json`, and `docs/devnet-audit-profile.example.json`.

## Style

- Edition `2024`, Rust `1.95.0`. Pinned by `rust-toolchain.toml`; CI installs the same toolchain.
- `morph-cli` uses `clap` with the `derive` and `env` features; subcommands are an explicit `enum Command` with `#[command(subcommand)]`. New subcommands should follow the same shape and carry `#[arg(long)]` for any boolean toggle.
- Two crates use a `devnet` Cargo feature to gate devnet-only modules behind `#[cfg(feature = "devnet")]`. Don't put devnet code paths behind `#[cfg(devnet_only)]` ad hoc.
- JSON in/out is via `serde` + `serde_json`; many types re-export through `morph-core::*`. The codebase avoids `unwrap` in non-test code and prefers `anyhow::Result`/`ensure!` in CLI code and `Result<_, ScriptError>` in scripts.
- RISC-V contracts store `i8` error codes cast from `ScriptError` discriminants; `program_entry` returns `err as i8`. When adding a new error variant, assign it a distinct numeric value (existing variants live in `morph-script-common`). Retired values remain reserved; do not renumber or reuse them.

## Gotchas and Non-Obvious Rules

- **Both domain-string locations must change together.** `morph-core/src/hash.rs` and `contracts/morph-script-common/src/lib.rs` declare duplicate domain constants for use across the host/script boundary. `hash_parity.rs` enforces equality at test time.
- **Current custody commits complete sets.** Bilateral `MultiAssetState` has `vault_content_set_root`, `vault_outpoint_set_root` and `vault_count`; Factory headers have their corresponding content/OutPoint commitments. Use the current encoders and exact set helpers, not removed single-Vault fields or aliases.
- **Boundary versions are not free.** Changes to `MULTI_ASSET_STATE_HEADER_LEN`, `FACTORY_MULTI_ASSET_STATE_HEADER_LEN`, `MULTI_ASSET_DESCRIPTOR_VERSION`, `FACTORY_MULTI_ASSET_STATE_WITNESS_FORMAT`, `MULTI_ASSET_SPLICE_FORMAT` or other current length/format constants affect the wire boundary and its parsers, fixtures, contract tests and native evidence. Check those dependencies before changing them.
- **Reduced factories accept only current documented proofs.** Signer membership is 2–16; rights and physical custody share current per-asset compact proofs and resource limits. Unknown shapes remain rejected.
- **Devnet-only `morph-devnet-xudt`.** It is not safe for non-devnet use. The contract name and the README both call this out.
- **`devnet` feature on `morph-cli`.** The `devnet` feature gates native operators, fixture-server utilities, watcher services and the entire `devnet` subcommand. Shared bounded RPC primitives also support fresh admission before initial-funding signatures in the default build; offline recovery exports do not depend on them.
- **Hub auth tokens are scoped.** `read,write,restore,sign:<secret>` is the documented scope syntax; an unprefixed token is all-scope. Don't log the secret.
- **Mutation rate limit is per-instance.** `MAX_MUTATIONS_PER_WINDOW = 120` over `MUTATION_RATE_LIMIT_WINDOW = 60s` applies per hub process. Be aware when load-testing.
- **Invoices are Morph-native, not Fiber or Lightning.** Encoding/decoding/settle live in `crates/morph-cli` (`new-invoice`, `decode-invoice`, `settle-invoice`) and `crates/morph-core/src/node.rs`. The sole encoding is Bech32m with HRP `morph`.
- **Local semantic tests don't need CKB.** `cargo test --workspace` and `cargo run -p morph-cli -- validate-fixture` run without any CKB binary. Only `make contract-tests` and the `scripts/*` flows need `ckb`.
- **CI caches the cargo target.** First CI run is slow; locally expect a multi-minute `make build-contracts` plus initial tests.

## Where to Look

- Protocol object model: `crates/morph-core/src/{types,multi_asset,factory_multi_asset,factory_backend}.rs`
- Signing digests and domain strings: `crates/morph-core/src/hash.rs`, `contracts/morph-script-common/src/lib.rs`
- Validation errors and rules: `crates/morph-core/src/validation.rs`
- Current witnesses and dispatch: `contracts/morph-script-common/src/{multi_asset,multi_asset_splice,factory_multi_asset,factory_multi_asset_runtime}.rs` and `factory_multi_asset/{state,materialisation,reduced}.rs`; shared primitives/errors remain in `lib.rs`
- State cell script entrypoint and shape dispatch: `contracts/morph-state-type/src/main.rs`
- Fixtures: `crates/morph-cli/src/{multi_asset_packages,factory_packets,factory_transaction,fixture_exports}.rs`
- Hub server: `crates/morph-cli/src/hub.rs`
- Devnet flows: `crates/morph-cli/src/devnet.rs`, `scripts/devnet-*.sh`
- Safety boundaries and their tests: `SECURITY-FIXES.md`
- Audit findings and remediation: `docs/swarm-audit-*.md`, `docs/audit-*.md`
- Readiness gates: `docs/mainnet-readiness.md`, `docs/roadmap.md`

### Native client boundaries

- Keep the GPUI 0.3.11 / Kit 0.9.0 family pinned together; the exact native consumer deltas and archives are verified by `vendor/check.py`. No alternate Fast/WebView/WASM UI is supported. Read `docs/native-gui-dependencies.md` before changing the family or packaging it.
- `morph-packages` is the sole package implementation. CLI thin modules retain test namespaces; never rebuild a separate signing digest/parser in SDK/UI.
- SDK writes are never automatically retried. A lost mutation response is an unknown outcome, which blocks automatic polling/resubmission until explicit reconciliation. Cancelling a UI wait does not undo server effects.
- GUI mutation confirmation binds the reviewed request and the latest event id; edits/new events invalidate it. Empty scopes with explicit unauthenticated loopback follow the server's policy; offline/stale state still disables writes.
- Native task drafts are ephemeral and keyed by operation plus object. Do not share IDs or document buffers between tasks, persist sensitive drafts, or silently evict them. File completion, network completion and inspector revisions have independent correlation checks.
- Keep presentation in `morph-desktop/src/presentation.rs` and `views/`, visual tokens in `design.rs`, and job control in `main.rs` / `worker.rs`. JSON is an advanced view; object details and exact review are the primary flow. CKB conversion must remain integer-based; unknown token precision stays in base units. Field validation is UX feedback only; canonical SDK/service validation remains mandatory. Long evidence hex uses a monospace editor without soft wrapping.
- Unknown writes survive reconnect until the same endpoint and Hub identity are explicitly refreshed and reviewed. A file/parser failure must not make the network stale. Review summaries never replace private original recovery evidence.
- Fiber scenario definitions use the closed Rust vocabulary in `morph-xtask`, preserve named economic/recovery assertions and source hashes, and never evaluate script strings. `scenario` mode records development evidence only; final full/coexistence qualification still requires committed tracked source. External funding signatures use a protected key file; restart may stop only an exact node1 executable in the owned stack tree.
