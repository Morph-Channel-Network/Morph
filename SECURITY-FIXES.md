# Security Fixes And Trust-Boundary Closeout

This is the living reviewer index for security-boundary fixes and explicitly
accepted trust boundaries. The earliest safety-kernel closeout was baseline
`8944bf7`; current executable acceptance commands and release posture are
tracked in [`docs/devnet.md`](docs/devnet.md) and
[`docs/mainnet-readiness.md`](docs/mainnet-readiness.md). Superseded closeout
snapshots remain available from git history rather than the current docs tree.

The 2026-08-15 swarm audit was performed at `9ab9ec1` and is preserved in
[`docs/swarm-audit-glm-2026-08-15.md`](docs/swarm-audit-glm-2026-08-15.md).
Commit `1cc830f` closes AUD-01, AUD-03, AUD-04, and AUD-05. AUD-02 is an
explicit code-identity trust boundary rather than a hidden signature check: a
FactoryProof child delegates creation authority to the exact FactoryType hash
in its StateType args, so deployments must pin the audited FactoryType code.

None of these closeouts is a mainnet-ready or production-ready claim. External
review, mainnet-like fee/reorg evidence, independent release verification,
multi-operator rehearsal, and a real-asset value policy remain required.

## Current source boundary and historical evidence (2026-11-05)

The current predeployment implementation has one 318-byte channel State,
descriptor 5, one complete Vault-set lifecycle, and one 306-byte Factory
State. The former 346/302-byte headers, single-Vault settlement/splice
codecs, 485/469-byte bridges and `MORPHW!!` kinds 1–8 are removed. Direct and
Factory-child StateType args use the shared strict 40/72-byte parser; both
read canonical relative since from their final eight bytes.

Current Factory root and metadata roles are exact-transaction `MORPHFS!`
format 2; child materialisation uses `MORPHFM!`; localized rights and funded
custody changes use `MORPHFR!`. Reduced paths authenticate the actual State,
StateLock and complete exact custody, protect untouched rights/reserve, and
isolate external funding/fees. Conditional CKB uses descriptor-5 capability 1
and the sole Batch executor; 104-byte Batch args bind the exact funding context.
The shared 828-byte inner Batch terms and compact Merkle algorithms survive
as current capability primitives.

The chronological sections below preserve the findings and fixes at their
original baselines. Their old wire lengths, activation-fee rules, API names
and removed test names describe historical evidence. They do **not** specify
current parser acceptance, prove the changed binaries independently reviewed,
or establish release readiness. Current test names, operation mapping,
measured budgets and data-availability limits are recorded in
[the coverage ledger](docs/current-protocol-coverage.md).

| Historical negative family | Current coverage entry |
| --- | --- |
| `state_type_rejects_equal_state_number`, signature/context/carrier drift | `current_state_supersede_preserves_carrier_context_lock_and_signature_authority`; current header context/digest properties. |
| Fake State header, StateLock mismatch and ambiguous authority | `multi_asset_rejects_fake_state_authority`; `current_vault_authority_checks_state_lock_identity_and_unique_authentic_state`. |
| Raw absolute since, dirty/typed/split settlement and standalone retirement | `current_finalise_rejects_absolute_since_dirty_typed_split_and_standalone_retirement`. |
| Sponsor diversion, dirty change, overflow and fake/unbacked publication | `current_sponsor_bounds_fee_budget_change_attribution_and_authentic_publication`. |
| Kind-8 foreign/nonvalue/unlisted/cross-asset/proof-order negatives | Current `multi_right.rs` invokes the production reduced frame; 17 compact proof/current-rights tests and 11 reduced/proof-data tests. |
| Old withdrawal-lock and splice physical-delta negatives | Current exact-body splice mutation matrix and Factory freshly-authorized physical mismatch tests. |
| Factory child authority/private exit | Full/reduced materialisation VM tests, child exit after parent retirement, independent delivery/journal tests. |

The original migration checkpoint passed 77 CKB-VM tests after runtime/common
pruning and the external-child capability parity check. Current release results
are recorded separately rather than relabelling that historical checkpoint.
This is local migration evidence. Independent protocol/script review,
public-network fee/reorg/latency evidence, independent operators/builds and a
real-asset value envelope remain required. Complete repository CI and report
refresh are tracked separately in [the migration ledger](docs/unified-protocol-migration.md).

## Alpha private delivery and initial funding recovery (2026-11-05)

- Private artifact writers create missing Unix directories with 0700 and
  files/sidecars with 0600, preserving existing shared ancestor permissions and
  directory fsync. Immutable replay, append and locks reject broader existing
  private files. Tests:
  `private_writers_create_restricted_trees_without_chmodding_existing_parents`,
  `private_replay_append_and_locks_reject_broad_existing_files_without_repair`,
  `multi_asset_recovery_store_is_durable_idempotent_and_private`.
- Factory members keep independent durable journals. Reservation precedes the
  signer and signature recording precedes receipt release, including actual
  process exits and failed persistence. Tests:
  `independent_factory_journals_require_all_members_for_two_three_and_sixteen`,
  `factory_process_exit_preserves_reservation_and_lost_signature_receipt_is_recoverable`,
  `failed_checkpoint_or_record_persistence_never_releases_a_factory_receipt`.
- Private delivery verifies the exact child/context before storing recovery.
  Both child-party possession attestations are required by every parent signer;
  they cannot substitute for parent authority even when keys coincide. Each
  honest child verifies and persists its complete private exit before attesting.
  Test: `child_possession_receipts_cannot_replace_parent_votes_or_cross_child_identity`.
  These attestations are not consensus proof of private disk availability.
- Initial funding can export the complete retained exit offline without the
  peer's last creation receipt. Confirmed same-path handoff still requires a
  durable local creation vote, exact canonical funding/activation and both valid
  on-chain creation signatures. Tests:
  `incomplete_initial_exit_cannot_export_or_authorize_after_peer_loss`,
  `retained_exit_survives_withheld_creation_receipt_and_requires_local_handoff_vote`.
  The native matrix also orphans and replays the byte-identical signed funding
  transaction without new peer votes or journal mutation.
- Full-store signer rollback remains the separate trusted-freshness boundary in
  #55. Neither fsync nor these crash tests establishes independent monotonicity
  after rollback of an entire consistent authority store.
- Current reduced Factory VM negatives independently check authentic Factory
  Type/StateLock authority and checked u128 aggregation with valid localized
  proofs and fresh signatures:
  `factory_multi_asset_reduced_release_authenticates_factory_type_and_state_lock`
  (errors 14/69) and
  `factory_multi_asset_reduced_rights_rejects_u128_group_overflow_with_valid_locality_proofs`
  (separate before/after sum overflow, error 39). The alpha VM corpus has 84
  registered tests; the historical 77/82-test checkpoints remain distinct.

## Factory-materialised State authority binding (2026-08-13)

- Issue: a FactoryProof State creation parsed the Factory exit envelope from
  input zero but did not bind that carrier to the exact FactoryType script
  authorised by the child transaction.
- Fix: FactoryProof StateType args now commit the 32-byte FactoryType script
  hash between the funding anchor and required relative `since`. Creation
  rejects bilateral witnesses with Factory args, rejects Factory witnesses
  without those args, and requires input zero's Type Script hash to match the
  committed FactoryType identity before accepting the materialised child.
- Negative test:
  `state_type_rejects_factory_exit_without_bound_factory_authority`.
- Current boundary: bilateral StateType args are exactly 40 bytes and Factory
  child args are exactly 72 bytes. Unpublished shorter forms are rejected.
- Trust boundary: the child StateType delegates authorisation to the exact
  FactoryType script hash committed in those 72-byte args; it does not
  independently repeat the Factory witness signature checks. Deployments must
  therefore pin an audited FactoryType code identity. Committing a permissive
  script can create only a fresh, separately addressed child authority and does
  not grant access to children committed to the audited FactoryType.

## Signed splice withdrawal destinations (2026-08-15)

- Issue: bilateral, full-factory, and reduced-factory splice-out signatures
  committed withdrawal amounts but not the output lock, allowing a transaction
  assembler to redirect the payout.
- Fix: `SpliceHeader` and `FactorySpliceHeader` now include a signed
  `withdrawal_lock_hash`. Vault scripts require every nonzero CKB/xUDT
  withdrawal delta to have exactly one output with that lock, asset type, and
  amount. Splice-in requires a zero target; splice-out requires a nonzero
  target. This is an intentional unpublished wire-format break: header lengths
  are now 485/469 bytes and the affected witness body versions are 2.
- Negative tests:
  `vault_lock_rejects_splice_out_with_substituted_withdrawal_lock` and
  `factory_vault_rejects_reduced_splice_out_with_substituted_withdrawal_lock`.

## Settlement and host/script parity fixes (2026-08-15)

- Plain CKB settlement rejects typed Vault inputs, matching the CKB-only
  descriptor profile. Negative test:
  `vault_lock_rejects_ckb_only_settlement_with_typed_vault_input`.
- Host splice validation now requires both current and successor states to be
  Active, and reduced Factory splice validation requires a bound old Vault
  outpoint plus an unbound successor, matching the on-chain scripts.

## Agent and remote HTTP boundaries (2026-08-13)

- Issue: Agent/Fiber/Gateway/hook clients admitted remote cleartext HTTP,
  response limits were applied only after whole-body buffering, durable public
  challenge and offer creation was unbounded, and the payment index exposed
  raw provider metadata.
- Fix: remote service URLs require HTTPS while loopback HTTP remains available
  for local devnet. Response readers enforce limits incrementally. Non-loopback
  Agent listeners require a minimum-length API bearer token; the token gates
  durable creation and operator-observability routes. Transient records have
  count and serialized-size reserves, expired records are pruned, creation is
  rate limited, raw payment metadata is size bounded, and the public response
  is a redacted projection.
- Tests: `plaintext_http_is_loopback_only`,
  `chunked_response_is_rejected_as_soon_as_the_limit_is_crossed`,
  `outstanding_challenge_quota_rejects_without_corrupting_existing_state`,
  `payment_index_requires_auth_and_redacts_raw_fiber_metadata`, and the
  Agent/Fiber/hook TLS constructor tests.

## Watchtower alert egress and file privacy (2026-08-13)

- Issue: a validated webhook could redirect to an unvalidated destination and
  JSONL alert files inherited ambient process permissions.
- Fix: webhook redirects are disabled, including for loopback development
  URLs. On Unix, alert files are created and tightened to mode `0600` on every
  append.
- Tests: `webhook_does_not_follow_redirects` and `appends_jsonl_alerts`.

## Post-baseline sovereign Factory hardening (2026-07-22)

- Issue: the devnet transaction layer placed FactoryStateCells under an
  operator secp lock. Participant/reduced proof acceptance was therefore not
  sufficient to spend the cell without the fee payer's private key.
- Fix: newly created FactoryStateCells use `morph-state-lock` with the exact
  FactoryType hash as lock args. Factory protocol evidence remains in
  `input_type`; the operator secp signature signs only a distinct fee-input
  lock group. Update, full/reduced splice, exit, and activation paths validate
  the type-bound lock before building a transaction. Reduced exit can use the
  non-signing counterparty's compressed public key instead of their private
  key.
- Tests: `factory_fee_signature_does_not_gate_the_factory_state_witness`,
  `reduced_exit_witness_needs_only_counterparty_public_key`, and
  `factory_type_and_vault_accept_reduced_exit_reserve_release` using the real
  StateLock.
- Pre-release policy: no owner-locked Factory shape is supported; no-value
  devnet state is discarded and recreated after a boundary change.

## Exact State/Factory carrier conservation (2026-07-22)

- Issue: the State and Factory type scripts rejected outputs below occupied
  capacity but did not require the remaining carrier capacity to stay in the
  successor. A valid protocol witness could therefore accompany a carrier
  drain.
- Fix: ordinary updates preserve capacity exactly. Deterministic Vault binding
  consumes exactly `STATE_CARRIER_ACTIVATION_FEE = 10_000` shannons, while
  splice/exit creates the next unbound carrier with exactly that reserve added.
- Negative tests:
  `state_type_rejects_signed_supersede_carrier_drain`,
  `factory_type_rejects_signed_factory_update_carrier_drain`,
  `state_type_rejects_vault_activation_carrier_drain`,
  `factory_type_rejects_vault_activation_carrier_drain`,
  `state_type_rejects_splice_without_carrier_activation_reserve`, and
  `factory_type_rejects_splice_without_carrier_activation_reserve`.

## Bilateral backend commit deadline (2026-07-22)

- Issue: payment preparation rejected expired intents, but commit did not bind
  a commit time and could accept a previously prepared intent after expiry.
- Fix: `ChannelBackend::commit_payment` requires `committed_at_unix` and accepts
  only `prepared_at_unix <= committed_at_unix < expires_at_unix`.
- Negative test: `commit_rejects_times_outside_the_prepared_intent_window`.

## Authentic StateCell authority

- Issue: Vault and sponsor paths must not treat bytes that decode as a
  `StateHeader` as protocol authority.
- Attack model: an attacker publishes an ordinary cell whose data parses as a
  Morph state header and points settlement or sponsor publication at their own
  outputs.
- Fix: Vault finalisation now requires exactly one authentic StateCell input
  with the expected StateType and StateLock identity. Watchtower detection also
  filters StateCells by StateType/StateLock identity instead of data alone.
- Negative tests: `vault_lock_rejects_fake_state_header_without_state_type`,
  `sponsor_lock_rejects_fake_state_header_without_state_type`,
  `watchtower_state_detection_requires_authentic_state_scripts`.
- Remaining limitation: this closes the current authenticity boundary for the
  implemented fixed-width state scripts; future descriptor runtimes or new
  state script versions must add equivalent authenticity tests before use.

## Canonical relative since

- Issue: raw `u64` comparison does not implement CKB `since` semantics.
- Attack model: a raw absolute value such as `4` can mature immediately once
  the chain height is above that value.
- Fix: finalisation uses canonical relative-block `since`; CLI arguments remain
  relative block counts and are encoded before transaction construction.
- Negative tests: `vault_lock_rejects_raw_absolute_since`,
  `finalise-since-negative-smoke`.
- Remaining limitation: current intentionally supports only relative block-number
  maturity. Epoch or timestamp maturity remains future work.

## State retirement cannot orphan value

- Issue: retiring a StateCell without consuming the bound VaultCell can remove
  the current state evidence while leaving value locked.
- Attack model: a standalone settling close or active splice retire consumes
  the StateCell but leaves the VaultCell without usable current-state evidence.
- Fix: StateType finalise and active splice-retire paths require the exact
  VaultCell input named by `StateHeader.vault_outpoint_commitment`, and also
  require its content to match `vault_materialisation_root`.
- Negative tests:
  `state_type_rejects_standalone_settling_close_without_matching_vault`,
  `state_type_rejects_standalone_active_splice_retire_without_matching_vault`.
- Remaining limitation: any future multi-vault set must version the locator
  commitment and tests together.

## FactoryVault materialisation authority

- Issue: the original `FactoryStateHeader` committed rights and reserve-policy
  roots, but not the actual shared-pool Cell. Factory creation signatures and
  ordinary updates therefore did not bind the FactoryVault lock, capacity,
  type, or data, and Factory splice signatures bound descriptors/deltas without
  binding their concrete old/new Cell materialisations.
- Attack model: a host or transaction builder substitutes a different reserve
  Cell while presenting otherwise valid Factory rights, exit, or splice
  evidence; a bridge cannot derive the current pool materialisation from the
  canonical Factory state alone.
- Fix: `FactoryStateHeader` includes
  `vault_materialisation_root = H(lock_hash, capacity, type_hash, data)`.
  Creation emits an unbound State/Factory plus exactly one matching Vault. A
  separate activation transaction must preserve every signed field and bind
  `vault_outpoint_commitment = H("CKB_MORPH_VAULT_OUTPOINT_V1", tx_hash,
  u32_le(index))` to the exact live Vault presented as the first direct
  CellDep. Ordinary signature, reduced-rights, and sparse-Merkle updates must
  preserve both commitments. Local/reduced exits and full/reduced splices
  require the exact old Vault input, emit an unbound reserve-changing
  successor, and reactivate it before later use. `FactorySpliceHeader` signs
  both old/new content roots and OutPoint locators. The Factory type and vault
  lock check these boundaries independently.
- Negative tests:
  `factory_type_rejects_initial_state_without_committed_factory_vault`,
  `factory_type_rejects_initial_state_with_wrong_factory_vault_commitment`,
  `factory_type_rejects_initial_state_with_ambiguous_factory_vaults`,
  `factory_type_rejects_signed_ordinary_update_with_factory_vault_root_drift`,
  `state_type_rejects_byte_identical_clone_vault_activation`,
  `factory_type_rejects_byte_identical_clone_vault_activation`,
  `state_type_rejects_vault_activation_lock_drift`,
  `factory_type_rejects_vault_activation_lock_drift`,
  `factory_type_rejects_noncanonical_vault_activation_dep`,
  plus the existing Factory splice/exit capacity, type, and amount mismatch
  families.
- Remaining limitation: this closes the known clone/substitution path in the
  implemented single-Vault profile, but still requires independent review and
  an explicit deployment policy before mainnet deployment.

## Merkle locality is not mint authority

- Issue: a single-right sparse Merkle proof proves locality, not economic
  validity.
- Attack model: an authorised participant uses the generic Merkle update path
  to increase a value-bearing right without a matching FactoryVault delta or
  full-participant consent.
- Fix: the plain single-right Merkle update path accepts only authorised
  value-right decreases. Increases remain available only through full consent
  or dedicated vault-delta-bound splice paths.
- Negative tests: `factory_sparse_merkle_update_rejects_value_right_increase`,
  `factory_type_rejects_sparse_merkle_right_increase`.
- Remaining limitation: generic multi-right or variable-depth reduced proofs
  are still deferred; unknown proof shapes must remain rejected.

## Reduced exit release binding

- Issue: reserve-claim reduction must be tied to the actual child-vault asset
  release.
- Attack model: a reduced exit decreases the claim by a smaller amount than the
  child vault receives.
- Fix: reduced-exit current now checks the ReserveClaim asset domain. CKB releases
  require an untyped claim and bind `release_quantity` to child vault capacity.
  xUDT releases require a typed claim whose asset type matches the descriptor
  and bind `release_quantity` to the child vault token amount.
- Negative tests: `factory_type_and_vault_accept_reduced_exit_reserve_release`,
  `rejects_reduced_factory_exit_release_mismatch`,
  `factory_type_rejects_reduced_exit_typed_claim_for_ckb_release`,
  `factory_type_and_vault_accept_reduced_exit_xudt_reserve_release`,
  `factory_type_and_vault_accept_reduced_exit_xudt_full_release_without_typed_change`,
  `factory_type_rejects_reduced_exit_xudt_claim_asset_type_mismatch`.
- Devnet evidence: CKB and xUDT reduced-exit smoke paths are active. The xUDT
  smoke covers partial typed FactoryVault change, full release with CKB-only
  change, one-sided child settlement, and child token amount mismatch rejection.

## xUDT reduced-exit typed binding

- Current status: contract, CKB-VM, and devnet smoke coverage are active for
  xUDT reduced-exit current. The witness reuses the fixed-width xUDT descriptor
  variant; no new schema is introduced.
- Fix: the factory type checks child-vault type hash, token amount, capacity,
  descriptor version, and descriptor commitment. The factory vault lock checks
  FactoryVault capacity conservation and typed xUDT change amount.
- Negative tests:
  `factory_type_rejects_reduced_exit_xudt_amount_mismatch`,
  `factory_type_rejects_reduced_exit_xudt_type_mismatch`,
  `factory_vault_rejects_reduced_exit_xudt_change_amount_mismatch`,
  `factory_vault_rejects_reduced_exit_xudt_missing_typed_change`,
  `factory_type_rejects_reduced_exit_xudt_capacity_mismatch`.
- Devnet negative smoke:
  `factory-reduced-xudt-negative-exit-smoke` rejects child token amount mismatch
  even when the FactoryVault change preserves total token supply.

## Sponsor policy boundary

- Issue: expiry, sponsor-source, and cadence are meaningful operator policy,
  but the current sponsor lock has no verifiable clock/source evidence for
  enforcing them on chain.
- Attack model: documentation overstates script-enforced sponsor safety and a
  reviewer assumes operator-only policy fields are consensus checks.
- Fix: current documents the script-enforced sponsor boundary as state type,
  channel/state-number range, per-cell fee caps, exact fee attribution, and
  clean change. The current 136-byte `SponsorPolicy` has no expiry or sponsor
  source field. Expiry windows, sponsor source, cadence, webhook policy, and
  similar runtime bounds are operator/watchtower policy until a future
  script-verifiable design exists.
- Negative tests: `sponsor_lock_rejects_fee_above_per_tx_limit`,
  `sponsor_lock_rejects_state_number_outside_policy_range`,
  `sponsor_lock_rejects_third_party_capacity_diversion`,
  `rejects_fee_above_operator_limit`,
  `rejects_explicit_sponsor_when_policy_forbids_it`.
- Remaining limitation: expiry windows and sponsor source are not current
  script-enforced fields.

## Multi-right factory updates and compact proofs (v2.0, 2026-08-16)

- Issue (deferred protocol work, not a discovered vulnerability): the reduced
  factory paths could prove and change exactly one right per update, and every
  sparse-Merkle witness carried all 256 sibling hashes.
- Fix: `WitnessEnvelope` kind 8
  (`WITNESS_ENVELOPE_KIND_FACTORY_MULTI_RIGHT_UPDATE`, body version 1) lets the
  single touched participant atomically update 1-4 of their own value rights,
  each localised by an independent compact sparse-Merkle proof. Compact proofs
  carry only non-empty siblings (bounded by `FACTORY_COMPACT_PROOF_MAX_SIBLINGS
  = 64` pairs, strictly descending depth); the script completes the omitted
  positions with the canonical `CKB_MORPH_FACTORY_RIGHT_EMPTY` subtree hash
  chain, so a proof that omits a real sibling cannot reconstruct the committed
  root and fails closed.
- Safety boundaries and their negative tests (script level, in
  `contracts/morph-script-common`): exactly one authorisation signature from
  the touched participant (`rejects_multi_right_update_bad_signature`); every
  right belongs to the touched participant
  (`rejects_multi_right_update_foreign_participant_right`); only value kinds
  (`rejects_multi_right_update_non_value_kind`); stable identities
  (`rejects_multi_right_update_identity_swap`); strictly ordered rights
  (`rejects_multi_right_update_unsorted_rights`); unchanged access manifest
  (`rejects_multi_right_update_manifest_change`); every asset-domain claim
  never increases and something must change
  (`rejects_multi_right_update_total_increase`,
  `rejects_multi_right_update_cross_asset_rebalance`,
  `rejects_multi_right_update_without_change`); proof localisation
  (`rejects_multi_right_update_sibling_tamper`,
  `rejects_multi_right_update_ascending_pairs`,
  `rejects_multi_right_update_wrong_capacity`). On-chain CKB-VM negatives:
  `factory_type_rejects_multi_right_total_increase`,
  `factory_type_rejects_multi_right_cross_asset_rebalance`,
  `factory_type_rejects_multi_right_compact_pair_tamper`,
  `factory_type_rejects_multi_right_foreign_signature`. Host mirrors live in
  `crates/morph-core/tests/multi_right.rs` and the parity suite pins the
  domain constants and proof-root equivalence in `tests/hash_parity.rs`.
- Boundary note: kind 8 is additive. Kinds 1-7, all fixed lengths, and the
  existing fixtures are unchanged; the four contract ELFs that statically link
  `morph-script-common` were rebuilt and the reviewed manifest
  `release/factory-preproduction/contracts.json` was regenerated for the 2.0
  boundary. The devnet save/publication command for kind 8 state-cell packages
  (mirroring `save-factory-merkle-update-package`) remains future work; the
  host package layer validates and fixtures kind 8 today.

## Kind-8 cross-side localization (v2.0 fix, 2026-08-17)

- Issue (high, found in review): the kind-8 per-side compact proofs
  established that each listed right exists in both committed trees but
  placed no constraint on the unlisted leaves. The touched participant could
  commit a new state root that mints or burns any other participant's rights
  while decreasing their own listed total; host validation returned success
  and the on-chain script enforced the same missing constraint. Kind 3 is not
  affected: its wire format carries a single sibling list shared by both
  sides, so the two reconstructed roots can only differ at the changed leaf.
- Fix: `verify_factory_multi_right_update` (script) and
  `validate_factory_multi_right_merkle_update` (host) now walk each
  before/after proof pair in lockstep and require every sibling subtree whose
  hash differs between the sides to contain one of the other listed changed
  rights. A differing subtree with no listed excuse means an unlisted right
  changed between the committed roots, and the witness fails closed. No
  wire-format change: the existing witness already carries everything the
  check needs, and honest witnesses are unaffected.
- Negative tests: script level `rejects_multi_right_update_unlisted_change`
  (which first asserts per-side inclusion still holds, isolating the new
  check) and `sibling_subtree_membership_matches_naive_prefix_check` pinning
  the subtree-membership mask against a bit-by-bit oracle; host mirror
  `multi_right_update_rejects_unlisted_foreign_change`; on-chain CKB-VM
  `factory_type_rejects_multi_right_unlisted_change`.
- Boundary note: the four contract ELFs that statically link
  `morph-script-common` were rebuilt and the reviewed manifest regenerated
  for the tightened kind-8 boundary.

## Kind-8 per-asset conservation and ordering parity (v2.0 fix, 2026-08-17)

- Issue (critical, found in review): kind 8 compared one global quantity sum
  across all listed rights. Quantities from different assets are not
  interchangeable, so a participant could burn CKB or xUDT-A while minting an
  equal numeric amount of xUDT-B. Separately, host/CLI arrays were ordered by
  hashed Merkle key while the script required raw right-identity order, which
  could make a host-valid package fail on chain.
- Fix: host and script now accumulate and compare quantities independently for
  CKB and every xUDT type. Rebalancing remains possible only within the same
  asset domain. Host validation, CLI package generation, script verification,
  and test witness builders all use canonical raw `FactoryRightId` order.
- Negative tests: script
  `rejects_multi_right_update_cross_asset_rebalance`; host
  `multi_right_update_rejects_cross_asset_rebalance`; CKB-VM
  `factory_type_rejects_multi_right_cross_asset_rebalance`. Existing positive
  rebalance tests pin same-asset behavior and the generated fixture pins the
  common identity ordering.

## Operator value-limit policy (v2.0, 2026-08-16)

- Issue: the roadmap required a value-limit policy and operator runbook before
  any real-assets claim; none existed.
- Fix: `morph-core::policy` defines a fail-closed `ValueLimitPolicy` (per
  deployment CKB capacity cap and per-asset xUDT caps; unlisted assets are
  rejected) with a deterministic digest. `morph-cli value-limit-check` applies
  it to fully validated value-bearing splice packages or to explicit amounts;
  `validate-value-limit-policy` reviews a policy file. Unknown, incomplete, or
  invalid package schemas and arithmetic overflow fail closed. The extracted
  subject is the component-wise peak across old/new vault descriptors rather
  than their sum. Runbook: `docs/runbooks/value-limits.md`.
- Negative tests: `policy_rejects_ckb_over_limit`,
  `policy_rejects_xudt_over_limit`, `policy_rejects_unlisted_assets`,
  `policy_rejects_malformed_keys_and_zero_caps`,
  `extraction_rejects_unknown_schemas`,
  `extraction_rejects_malformed_supported_schema`,
  `bilateral_extraction_uses_validated_old_and_expected_new_vaults`,
  `subject_addition_fails_closed_on_overflow`,
  `unlisted_xudt_fails_closed`.
- Boundary note: the policy is an operator control only. It never authorises
  anything and does not replace script consensus or package validation.

## Evidence run

The local verification run for this closeout passed:

- `make test`
- `make lint`
- `make fixture-checks`
- `make contract-tests`
- `make fmt-check`
- `git diff --check`

Historical supply-chain status for the earliest closeout: `cargo audit` could
not fetch the RustSec advisory database because the GitHub request failed with
an IO error. Later cached and CI runs passed the repository's narrow reviewed
waiver policy. Every release candidate must still rerun `make supply-chain` and
record fresh CI/independent-build evidence.
## Historical Morph 3.0 conditional-batch boundary

Morph 3.0 adds descriptor version 3 and `morph-batch-lock`. Conditional CKB
value is never paid directly from an application result: the signed descriptor
commits every transfer, the Vault can materialise only the pinned Batch Lock,
and the Batch Lock independently verifies preimages, canonical absolute-block
refunds, exact capacity conservation, and exactly two plain settlement outputs.
Negative CKB-VM coverage rejects wrong preimages, premature refunds, descriptor
substitution, wrong Batch Lock identity/args, and capacity loss. Conditional
xUDT remains rejected by design.

## Historical multi-asset bilateral candidate boundary (descriptor 4)

The candidate adds a separate 318-byte State layout and descriptor version 4.
Legacy encodings are unchanged. Both StateType and Vault Lock validate the
entire bounded content/OutPoint set; exact canonical payout positions and a
complete carrier refund conserve reserve, business CKB, and every xUDT type
independently. Script preimages in recovery evidence prove occupied capacity
before signing. Activation preserves the complete carrier capacity, with fees
funded externally. Plain external fee change may share a refund address without
being counted toward the canonical channel outputs.

The activation recovery operator validates original on-chain creation evidence
and signatures, keeps the original descriptor even when the saved unilateral
state has different payouts, and places the complete exact Vault set first in
direct dependencies. No participant key or reused creation signature authorises
the new bound header. Host negatives reject foreign funding contexts/transactions,
missing creation evidence and already-bound States; independent eight-asset
node recovery confirms activation, latest publication and full finalisation
using only an external fee wallet.

Named CKB-VM boundaries include:

- `multi_asset_rejects_partial_set_retirement` and
  `multi_asset_rejects_extra_vault_input`;
- `multi_asset_rejects_byte_identical_vault_substitution` and
  `multi_asset_rejects_activation_with_reordered_direct_dependencies`;
- `multi_asset_rejects_fake_state_authority` and
  `multi_asset_rejects_premature_finalise`;
- `multi_asset_rejects_payout_reallocation_not_in_signed_descriptor`;
- `multi_asset_rejects_missing_carrier_refund` and
  `multi_asset_rejects_activation_carrier_fee_leakage`;
- `multi_asset_rejects_signed_publication_in_changed_chain_context`.

The host suite separately rejects cross-asset minting, reserve reclassification,
overflow, noncanonical asset sets, missing scripts, inadequate capacity, and
incomplete/exchanged OutPoints. Rust and TypeScript share a signed recovery
fixture with quantities above JavaScript's safe integer range; the SDK also
rejects a freshly signed cross-asset mint and preserves a u64-max state number.
Hub import binds the two signers to the actual local channel participants and
retains validated evidence across restart. Recovery packages count as
operational records for the bootstrap-only restore boundary. Value-limit
extraction counts every Vault, every xUDT type, and the State carrier.

Whole-lifecycle CKB-VM evidence includes balanced, one-sided, plain-CKB plus
two-xUDT, maximum-eight-Vault, and Sponsor-funded publication paths. Isolated
real-node acceptance has committed two- and eight-xUDT funding, activation,
publication, supersede, and finalisation, with initial signed exit evidence
durably retained before funding broadcast. Candidate implementation details
and commands are in [multi-asset-wire.md](docs/multi-asset-wire.md).

This section does not close multi-asset splice, Factory reserve/child paths,
typed conditions, publication/reorg automation, reviewed release manifests,
or independent review. The v3 release manifest must not be relabelled as
qualification for those pending surfaces.

### Multi-asset package-based transaction admission

`devnet multi-asset-transact` requires exact canonical live State/Vault
identities, complete registered asset quantities, independent plain fee input,
matching carrier capacity, and live script dependencies. Code/DepGroup
resolution is bounded to 64 unique code cells; Morph authority code must match
the selected local artifacts. Finalisation checks canonical State inclusion and
relative-block maturity before VM preflight. Publication can reuse the bounded
fee/RBF controller and its durable attempt log; recovery evidence is persisted
before submission.

`dependency_resolution_distinguishes_code_data_hash_from_type_identity` tests
hash-type-specific dependency resolution. Real-node `multi-asset-smoke`
`operator_checks` exercises missing code, changed carrier, and signed preview
paths through the same operator used for its committed publications and exit.
This evidence does not close backend, sponsor/watchtower, splice, Factory,
typed-condition, or independent-release-review gates.

### Multi-asset state agreement and durable signing reservations

The native `MultiAssetChannelBackend` validates complete unsigned proposal
contents before reserving a vote, then verifies each exact participant signature
and commits only a complete two-signature recovery package. The local signing
reservation never decreases, including after cancellation or delayed peer-state
recovery. Restored snapshots revalidate current evidence, context, pending
signatures and the reservation. The standalone `multi-asset-session` CLI locks
the stable sidecar across reads and atomic writes, fsyncs the reservation before
invoking its signer, and fsyncs the receipt before exposing it. Keys are not
stored in snapshots. This guarantee assumes one authoritative journal without
operator-induced rollback or independent cloned stores.

Evidence: `multi_asset_backend_cancel_and_restart_cannot_reuse_signed_state_number`,
`multi_asset_backend_rejects_mint_context_changes_and_foreign_signatures_without_mutation`,
`multi_asset_backend_restoration_rejects_tampered_pending_and_vote_snapshots`,
`multi_asset_backend_recovers_delayed_complete_update_without_resetting_newer_vote`,
`durable_session_negotiates_both_signers_and_exports_lossless_recovery`,
`cancelled_signature_survives_restart_and_wrong_key_does_not_reserve`, and
`session_lock_covers_read_reserve_and_atomic_snapshot_replacement` cover these
boundaries. Rust and TypeScript share proposal/signature fixtures containing
u128 quantities above JavaScript's safe integer range. Payment/Hub integration,
Factory, splice, typed conditions and full watcher/release qualification remain
separate gates.

### Multi-asset canonical dispute monitoring

`multi-asset-watch` matches exact funding contexts and authentic State scripts,
rechecks saved signatures, rejects same-context/number equivocation and
same-number on-chain conflicts, and preserves normal Active channels. Only an
older Settling state can trigger automatic publication. Late packages force a
rescan when the observed stale State is still canonical and live. Profile fee,
poll, detection and challenge budgets apply before using the explicit fee input.

Cursors bind a required scan origin and contiguous prefix, are privately and
atomically fsynced under a stable lock, and check checkpoint/parent hashes.
Reorg recovery clears orphanable observations before rescanning from creation.
A failed or Pending publication does not advance observation to an unconfirmed
success. Restart reconciles the shared durable attempt records. Alert append
uses a file lock, one encoded record write and fsync, preventing interleaved
writers from silently corrupting critical events.

Unit evidence: `saved_packages_are_selected_per_context_and_conflicting_votes_fail_closed`
and `shared_scanner_recognises_current_profile_and_rejects_fake_authority`.
Real-node `watch-eight-final.json` records Active no-op, late saved-package
rescan, deliberate stored and on-chain conflicts, rejected late origin, real
node truncation, critical reorg recovery and canonical republication followed
by full-set finalisation. Finite passes are not the complete sponsor-backed
multi-channel watch service or an independent production release qualification.

## Multi-asset splice authority and conservation

The `MORPHMS!` path requires the exact signed raw transaction hash, authentic old
State input zero, all exact old Vault OutPoints, matching authority code/policy,
new unbound State output zero and canonical complete new Vault/withdrawal outputs.
State carrier capacity is preserved; per-asset reserve, business CKB and token
flows balance independently. Whole-transaction Type-quantity checks protect
registered assets even when their own Type script permits minting. Bridge and
new-State creation signatures are independently required.

CKB-VM cases in `contract_scripts/multi_asset.rs`:

- `multi_asset_splice_reanchors_full_set_with_asset_admission_withdrawal_and_recovery`
  covers count changes, full replacement, 512-byte Scripts and pre-signed exit.
- `multi_asset_splice_rejects_body_changes_clone_partial_sets_withdrawal_and_carrier_substitution`
  rejects body mutation, incomplete/duplicate custody, fake authority and value loss.
- `multi_asset_splice_requires_both_bridge_and_new_creation_authorizations` rejects
  missing, invalid and cross-domain signature reuse.
- `multi_asset_splice_independently_rejects_mint_under_a_permissive_asset_type` and
  `multi_asset_splice_rejects_reserve_business_reclassification_even_with_valid_bridge_signatures`
  check conservation beyond signature validity and external Type behavior.

Native publication, canonical signer completion/abort and node/reorg acceptance
remain separate gates; VM success does not satisfy those gates.

## Root funding transaction replacement

Root creation signatures bind the complete raw funding transaction in addition
to the unbound State digest. Binding only the anchor and State permits a wallet
owner to replace fee/change/dependencies and invalidate the pre-signed exit's
exact Vault OutPoints. StateType now rejects ordinary state votes for root
creation. Splice retains its transaction-bound bridge. Host funding validation
and activation enforce the same distinction. Negative coverage:
`multi_asset_root_creation_rejects_transaction_replacement` and
`root_authorization_rejects_replaced_raw_body_even_with_fresh_exit_signatures`.

## Independent initial funding votes

Root creation cannot be released until both exact initial-exit signatures are
persisted. Initial reservations and receipts use the same locked/fsynced journal
path that later becomes the confirmed operational session; the initial journal
is sealed before handoff and State 1 retains its exact exit vote. Direct
operational `init`/`bind-root` and null-lineage operational snapshots are rejected.
Signed exports remain available after artifact or RPC loss. Native funding and
context checks also compare the signed chain ID to the RPC genesis before
fee signing, persisting network artifacts or broadcasting. Negative coverage:
`initial_ceremony_requires_full_exit_before_creation_and_exports_exact_custody`,
`initial_reservations_survive_restart_and_reject_forged_local_receipts_and_artifact_drift`,
`operational_commands_reject_unconfirmed_recovery_bootstrap`, and
`recovery_package_cannot_bypass_initial_funding_ceremony`.

## Per-wallet root funding authority

Root construction derives State/Vault outputs from the descriptor and takes
explicit CKB, fee and per-Type contributions from each declared wallet. Every
input must belong to its funder, and all change remains with that wallet. A
shortfall cannot consume another wallet's change; token quantities never cross
Type domains. Tiny residual CKB stays in that wallet's token change or rejects
when no occupied change output can carry it. Wallet signing reconstructs the
exact raw body and requires complete root/initial-exit authorization. The former
signing modes on funding submission have been removed.

Submission performs full VM preflight before writing its immutable binary,
so an attempt missing wallet signatures cannot occupy the later valid
transaction's path. The synthetic shared-funding harness retains that negative
and completes submission through the same store. Unit negatives:
`root_builder_rejects_cross_wallet_subsidies_ownership_and_cross_type_quantity_changes`
and `root_builder_keeps_tiny_change_with_the_owner_without_changing_fee`.
