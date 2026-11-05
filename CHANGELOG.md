# Changelog

## v4.0.0-alpha.1 — 2026-11-05

This prerelease consolidates the unpublished channel and Factory capabilities
onto one current custody/signing/recovery implementation. It is for controlled
devnet use with no real assets.

- Close #15: separate public Factory intent/possession receipts from private
  child exits; create private Unix directories with 0700 and files/sidecars with
  0600, reject overly broad existing private files, and document confidential
  delivery/backup recipients. Platforms without equivalent implemented access
  controls fail closed for private persistence.
- Close #19: verify independent two-, three- and sixteen-member Factory journals,
  OS locks, partial authorization and actual process crashes before/after durable
  signing. Reject foreign child recovery before persistence; failed delivery or
  receipt writes retain the complete private exit without releasing parent
  authority. Parent members validate both child-key possession attestations;
  private exit signatures remain with child parties.
- Close #56: retain/export complete root recovery even if a peer withholds its
  final creation receipt; recover the missing authorization from authenticated
  canonical funding during the same-path handoff. Add actual root orphaning and
  byte-identical signed replay without new peer votes. Incomplete initial exits
  still cannot authorize creation or export recovery.
- Close #46 and #20: exercise one/four/ten-right current reduced updates through
  native preparation, independent signing, wallet funding, keyless submission
  and public proof refresh. Cover full-consent metadata, retained/full
  materialisation, private child delivery, independent child closure and parent
  retirement in the current native lifecycle.
- Qualify the measured ten-right native update under an explicit 55M-cycle
  fixture allowance, with 15M/30M one/four-right named caps, unchanged aggregate
  budgets and 40M ceilings for other native cases. Export exact case,
  transaction and proof limits with public evidence.
- Retire obsolete State/Factory/splice codecs, commands and duplicate backends;
  preserve conditional CKB Batch and reduced Factory capabilities in the current
  descriptor-5/FS/FM/FR model. Strengthen current Factory/Batch VM negatives,
  align Hub/UI profile metadata and isolate CI evidence from restored caches.
- Align Rust workspace, SDK and Hub versions to 4.0.0-alpha.1. Publish the
  deterministic eight-ELF current-custody bundle and sanitized source-bound
  acceptance evidence using the existing `vMAJOR.MINOR.PATCH` tag convention.

This does not add conditional token routing, cooperative terminal bilateral
close, membership changes or protection against rollback of an entire signer
authority store. Public-network, independent-operator and real-asset admission
remain separate readiness work. See [the alpha release record](docs/releases/v4.0.0-alpha.1.md).

## v4.0.0 — 2026-11-04

- Add multi-asset Factory consensus to the Factory Type and Factory Vault Lock
  scripts: a 306-byte layout-2 Factory State header with 44-byte Type args,
  `MORPHFS!` N-of-N root-creation, whole-set activation and custody-preserving
  metadata updates, and `MORPHFM!` complete materialisation into 1-4 bilateral
  children with separate reserve, business CKB and per-Type conservation.
  Children use 72-byte State Type args binding the originating Factory and a
  fixed origin hash across splices. Update the reviewed pre-production contract
  manifest to the rebuilt ELFs (six of eight data hashes change) and roll the
  envelope review window to 2026-11-04/2026-12-04.

- Add independent root funding sessions with durable initial-exit reservations,
  two-party exit-before-creation signing, approved local artifact checks and
  confirmed same-path handoff. Remove direct operational `init`/`bind-root`.
  Add public root construction from explicit per-wallet contribution terms,
  independent wallet-group signing and keyless funding submission; remove the
  former wallet/presigned submission modes. Share complete registered-Type and
  CKB accounting with splice submission. Signed recovery exports remain
  available without RPC or installed artifacts.

- Add multi-asset splice intent validation and durable old-context signing
  freeze, requiring exact transaction identity and a complete future exit.
  Add State/Vault splice execution, whole-transaction per-type conservation
  and CKB-VM recovery/negative acceptance. Add native construction/submission,
  same-journal confirmed switching, explicit reorg refresh and bounded signer
  supervision with durable alerts and expiring health.
- Bind root creation signatures to the exact raw funding transaction; reject
  ordinary state signatures and transaction-free root recovery packages.
  Add confirmed root journal binding and keyless exact funding replay, keeping
  reserved votes across reorg refresh and later splice retirement.

- Recover interrupted multi-asset activation from authenticated creation
  evidence and the latest saved recovery package, without participant keys.
  Remove the harness-only activation builder.
- Add durable bilateral multi-asset signing sessions, recovery packages and
  canonical dispute-watch passes with reorg recovery.
- Reconstruct complete-set publication and finalisation from saved evidence;
  keep wallet and policy-bound sponsor fee authorization explicit. Add
  two/eight-asset sponsor rollback acceptance and independent CLI evidence
  with Morph private-key environment variables removed.
- Reject historical Vault arguments, missing required persistence fields and
  funding-anchor package fallbacks. Development deployments require fresh state.
- Remove the unused schema draft and consolidate current protocol documentation.
- Use an independent 318-byte multi-asset State header, removing three
  single-Vault fields and rejecting the earlier unpublished layout.

## v3.0.0 — 2026-08-25

Morph 3.0 closes the conditional-settlement gap exposed by the Counter-Strike
comparison. It adds a bounded CKB-native conditional batch primitive instead
of treating a game-server result or an invoice status as enforceable channel
state.

### Consensus and wire boundary

- Added bilateral descriptor version 3: two participants, zero to eight sorted
  conditional transfers, SHA-256 or CKB-personalised Blake2b payment hashes,
  and canonical absolute-block refund heights.
- Added `morph-batch-lock`. A dispute materialises the whole Vault into one
  code-hash-pinned Batch Cell; resolution requires every preimage/refund and
  exactly two plain participant outputs with exact conservation.
- Extended `morph-vault-lock` with Vault args v2 and fail-closed descriptor-v3
  dispatch. Conditional xUDT inputs remain rejected.
- Added distinct conditional parser/lock/value/preimage/timeout error codes and
  fixed-size host/script parity tests.

### Host, recovery, and application surface

- Added `morph-core::conditional` plus the bilateral backend lifecycle for
  arming batches, recording idempotent preimages, cooperative consolidation,
  deterministic force-close construction, and settlement confirmation.
- Added `morph.conditional_batch_package`, CLI fixture/validator, and Morph Hub
  durable import. Hub packages must match the current channel ID, funding
  context, and state number and survive restart.
- Added TypeScript conditional package types and an authenticated
  `MorphHubClient.importConditionalBatch` entry point for game/service adapters.

### Release profile

- The controlled-devnet bundle is now `morph-v3-conditional-batch.tar.gz` and
  contains eight reviewed ELFs. New bilateral Vaults pin the Batch Lock identity
  at creation.
- The machine-checked envelope caps batches at eight CKB transfers and a 2,016
  block refund horizon. Mainnet, real assets, and conditional xUDT remain out of
  scope.
- See `docs/conditional-batches.md` for the architecture, invariants, and Counter-Strike
  integration guidance.

## v2.0.0 — 2026-08-16

Morph Channel 2.0 closes the deferred factory reduced-proof protocol work and
adds the operator value-limit policy. The plan of record is
`docs/factory-multi-right.md`.

### Factory protocol surface

- Added `WitnessEnvelope` kind 8
  (`WITNESS_ENVELOPE_KIND_FACTORY_MULTI_RIGHT_UPDATE`, body version 1): one
  touched participant atomically updates 1-4 of their own value rights
  (`Balance`, `ReserveClaim`, `SponsorBudgetClaim`) in a single factory
  update, each right localised by an independent sparse-Merkle proof against
  both the old and new state roots. The touched participant's claim in each
  asset domain can never increase, so one asset cannot be burned to mint
  another; the access manifest cannot move, and the non-interference digest
  binds every before/after right body.
- Added compact variable-depth sparse-Merkle proofs: only non-empty sibling
  hashes are carried (at most 64 `(depth, hash)` pairs per proof, strictly
  descending depth); the script completes the omitted positions with the
  canonical `CKB_MORPH_FACTORY_RIGHT_EMPTY` subtree hash chain, so proofs that
  omit a real sibling fail root reconstruction. This delivers the deferred
  "variable-depth proof profile" work item with strictly smaller witnesses.
- `morph-factory-type` dispatches kind 8 through the same state-preserving
  update arm as kinds 1-3 (monotonic update number, unchanged context, bound
  vault OutPoint, preserved carrier capacity).
- Security fix (2026-08-17, review finding): kind-8 verification now enforces
  cross-side localization. The per-side compact proofs alone only constrained
  the listed rights; the touched participant could commit a new state root
  that changed an unlisted right (for example another participant's balance).
  The verifier now walks each before/after proof pair in lockstep and rejects
  any differing sibling subtree that no other listed right can excuse, on
  both the host and the script. No wire-format change; honest witnesses are
  unaffected.
- Security fix (2026-08-17, review finding): kind-8 quantity conservation is
  now enforced independently for CKB and every xUDT type. Host, CLI, and
  script ordering also use the same canonical raw right identity order.

### Host tooling

- `morph-core`: `FactoryMultiRightMerkleUpdate` model, compact proof
  generation/verification (`factory_right_sparse_proof_compact`,
  `verify_factory_right_compact_proof`), host validation mirroring the script
  predicate, and the shared `CKB_MORPH_FACTORY_MULTI_RIGHT_UPDATE` /
  `CKB_MORPH_FACTORY_RIGHT_EMPTY` domains (parity enforced by
  `hash_parity.rs`, including host/script proof-root equivalence).
- `morph-cli`: `print-factory-multi-right-update-fixture`,
  `validate-factory-multi-right-update-package`, and a real-tree fixture
  (compact proofs built from a 96-right factory) wired into
  `make fixture-checks`.

### Operator value-limit policy

- `morph-core::policy`: fail-closed `ValueLimitPolicy` (CKB capacity cap plus
  per-asset xUDT caps; unlisted assets rejected) with a deterministic digest.
- `morph-cli`: `print-value-limit-policy-fixture`,
  `validate-value-limit-policy`, and `value-limit-check` (applies the policy
  to fully validated bilateral/factory/reduced-splice packages or explicit
  amounts; unknown, incomplete, or invalid packages and arithmetic overflow
  fail closed).
- Runbook: `docs/runbooks/value-limits.md`.

### Release boundary

Kind 8 is additive: kinds 1-7, all fixed lengths, and existing fixtures are
unchanged. The four contract ELFs that statically link `morph-script-common`
(`morph-state-type`, `morph-factory-type`, `morph-factory-vault-lock`,
`morph-vault-lock`) were rebuilt for 2.0 and the reviewed manifest
`release/factory-preproduction/contracts.json` was regenerated; a fresh devnet
deployment is required for the 2.0 line. Known follow-up: the devnet
save/publication command for kind 8 state-cell packages (mirroring
`save-factory-merkle-update-package`) is not yet implemented; host
validation, fixtures, and on-chain CKB-VM evidence exist today.

## Unreleased

- Add multi-asset splice intent validation and durable old-context signing
  freeze, requiring exact transaction identity and a complete future exit.
  Add State/Vault splice execution, whole-transaction per-type conservation
  and CKB-VM recovery/negative acceptance. Add native construction/submission,
  same-journal confirmed switching, explicit reorg refresh and bounded signer
  supervision with durable alerts and expiring health.
- Bind root creation signatures to the exact raw funding transaction; reject
  ordinary state signatures and transaction-free root recovery packages.
  Add confirmed root journal binding and keyless exact funding replay, keeping
  reserved votes across reorg refresh and later splice retirement.

### Security and reliability follow-up

- Bound Morph Hub request-head and request-body reads by a 30-second total
  deadline in addition to the existing per-I/O timeout, preventing unauthenticated
  slow connections from retaining all server slots indefinitely.
- Remove the Hub UI's build-time bearer-token fallback; browser tokens now come
  only from the operator's per-tab session storage.
- Refresh the canonical CKB tip immediately before deriving a watchtower
  publication deadline, so catch-up scans cannot reclaim already-consumed
  challenge-window blocks.
- Correct the v1.10.0 release boundary to record its included splice wire-format
  update explicitly.

## v1.11.0 — 2026-08-15

### Publication verification follow-up

- Fail closed if rebuilding the initial publication carrier changes its final
  serialized size without converging to the fee selected from the observed fee
  market. The controller now verifies both the exact recomputed fee and the
  final effective fee rate before broadcast.
- Clarify that the deterministic private-key environment probe exercises the
  same key-scrubbing launch wrapper used by every harness watcher process; it
  does not introspect the watcher binary after launch.
- Align the host crates, Fiber adapter, TypeScript SDK, Morph Hub frontend, and
  their lockfiles at v1.11.0; the Hub displays its package version in the
  operator console.
- Preserve the controlled-devnet and production-measurement boundaries from
  v1.10.0. No CKB contract source or wire-format change is included.

## v1.10.0 — 2026-08-15

Publication Reliability Hardening for the controlled-devnet Morph Channel
implementation.

### Security and reliability

- Added a bounded fee and RBF publication controller that observes the live CKB
  fee market, learns structured node replacement floors, and fails closed at
  operator and SponsorPolicy caps.
- Added an absolute challenge deadline that deducts already-consumed
  confirmations and reserves canonical-confirmation, reorg, failover, and
  safety blocks.
- Made Pending, Proposed, Committed, Rejected, and Unknown explicit states;
  watcher completion now requires configured canonical depth.
- Added canonical reconciliation for restarts, mempool eviction, duplicate
  broadcast, replacement races, and induced reorganisation.
- Isolated deployer, participant, and independent operator keys into disjoint
  subprocess environments.
- Serialized attempt-log append and torn-tail recovery with a shared durable
  file lock.
- Bounded publication-critical RPC response bodies and diagnostic excerpts.
- Made production reliability assessment fail closed without trusted external
  measurement provenance.

### Operations and evidence

- Added path-aware multi-channel watchtower preflight and operator/profile/log
  binding.
- Added a deterministic devnet reliability harness covering live fee rejection,
  real RBF, two-operator failover, pool eviction, duplicate submission,
  SponsorPolicy rejection, canonical reorg recovery, and signed-package byte
  identity across branches.
- Added architecture, implementation, parent-source comparison, production
  gates, and completion-audit documentation under
  `docs/hardening/production-publication-reliability/`.

### Release boundary

The publication-controller and host/watchtower hardening itself does not alter
the contract wire. However, the `v1.10.0` tag also contains the earlier
withdrawal-destination binding from commit `1cc830f`. That change deliberately
extends `SpliceHeader` from 453 to 485 bytes and `FactorySpliceHeader` from 437
to 469 bytes, and bumps the affected splice witness body versions to 2. It is an
unpublished wire-format break and requires a fresh devnet deployment; pre-v1.10
splice packages and witnesses are not compatible.

The seven contract crate versions remain `0.1.0`. Their reviewed ELF Data Hashes
are refreshed because the withdrawal binding changed the scripts and because
the release build now remaps machine-specific source paths and rejects
restored-target contamination. The resulting hashes are stable across local and
GitHub runners.

v1.10.0 remains a controlled-devnet release. It is not approved for
mainnet or real assets. Trusted public-network measurements, independently
administered operator infrastructure, external review, and a dated value-limit
decision remain mandatory production gates.
