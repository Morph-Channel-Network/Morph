# Multi-Asset Splice

Host intents, shared wire validation, durable backend freeze and the StateType/
Vault Lock consensus path, exact offline transaction drafts and session signing
are implemented. CKB-VM acceptance covers complete
re-anchor, activation, pre-signed exit publication and finalisation. Native
construction and submission support asset admission/removal. Isolated-node
acceptance covers a 2→1→2 asset roundtrip, exact signed replay after reorg and
final unilateral settlement. Confirmed session switching and explicit reorg
reconciliation are implemented. Root binding, exact keyless funding replay and
bounded session supervision are implemented. Public root construction and
per-wallet contribution signing are implemented. Failover, pooled publication and terminal abort tracking remain open. Host
checks do not establish that a proposed State input is currently live.

## Authorization and transaction identity

A splice replaces one funding context with another while retaining the channel
ID, participants, authority code, challenge policy and State carrier capacity.
The old State is transaction input zero with `since = 0`; the new unbound
Active/0 State is output zero, followed by the complete new Vault set in asset
order. The new funding anchor uses the existing CKB-personalised hash of input
zero and output index zero. The funding epoch increases by exactly one.

The intent requires complete bilateral authorizations for both the new unbound
State and the exact transaction's initial settling state 1. The initial recovery
OutPoints are `(transaction_hash, 1..=new_vault_count)`. Its descriptor is the
signed initial funding descriptor. Preserve that complete recovery evidence
before releasing either old-context bridge signature.

The bridge must sign the complete CKB transaction body hash. A fee-input,
change-output or dependency change can alter every new Vault OutPoint even
when the new State header and quantities are unchanged. Such a replacement
needs a new initial recovery authorization and new bridge signatures. CKB's
transaction hash excludes witnesses, so committing it in the witness-carried
bridge authorization is not circular.

The shared header is 200 bytes, little endian:

| Offset | Field | Bytes |
| --- | --- | --- |
| 0 | Format 1 | 2 |
| 2 | Reserved zero | 2 |
| 4 | Old funding-context ID | 32 |
| 36 | Exact old State OutPoint | 36 |
| 72 | New Active/0 State signing digest | 32 |
| 104 | Asset-flow commitment | 32 |
| 136 | Withdrawal Script hash, zero only without withdrawals | 32 |
| 168 | Exact transaction body hash | 32 |

The signing domain is `CKB_MORPH_MULTI_ASSET_SPLICE_V1`. Ordinary State
signatures cannot authorize this bridge. A completed transaction must also
validate the normal new-State creation signatures.

## Transaction witness

`WitnessArgs.input_type` carries the new Active/0 creation signatures.
`output_type` carries one `MORPHMS!` envelope. Its 32-byte prefix contains magic
(8), u16 format 1, u16 reserved zero, u32 old-manifest byte length, u16 old
OutPoint count, u16 reserved zero, u32 new-evidence length, u32 withdrawal-Script
length and u32 flow-table length. The body is ordered as follows:

1. Bridge header (200), new State header (318), bridge signatures (198).
2. Old manifest and complete old OutPoint set in manifest order.
3. New unbound `MultiAssetWitness`, withdrawal Script and flow table.

Every component is length-bounded and its commitment is checked. Old payout
descriptors are not duplicated in the bridge: the old manifest/provenance prove
custody; joint bridge signatures authorize the new allocation. The transaction
hash is checked against the actual raw transaction. State input zero and Vault
inputs 1..N consume the exact old set; new State output zero and Vault outputs
1..M establish the new set. Nonempty withdrawals follow in flow order. Extra
old/new Vaults and duplicate State authorities are rejected.

StateType retirement, StateType creation and the old Vault Lock independently
verify the same bridge. New-State creation also verifies its ordinary creation
signatures. Retirement can consume an Active or Settling old State without
waiting for a dispute timeout because both participants authorize this exact
transaction. All registered old/new Type identities undergo independent
whole-transaction quantity conservation, including external inputs/change;
a permissive asset script cannot mask protocol-level minting.

## Asset flows and capacity

The flow table is a u16 count, u16 reserved zero, then 1–16 entries. Each entry
is an asset ID (33 bytes), deposit allocation (32), and withdrawal allocation
(32). It covers the complete sorted union of old/new manifest assets exactly
once. Its domain is `CKB_MORPH_MULTI_ASSET_SPLICE_FLOW_V1`.

For each asset, check separately:

- old reserve + deposited reserve = new reserve + withdrawn reserve;
- old business CKB + deposited business CKB = new business CKB + withdrawn
  business CKB;
- old token quantity + deposited quantity = new quantity + withdrawn quantity.

Missing sides use zero. Tokens are never summed across Type Script identities.
All arithmetic is checked, including the total physical CKB capacity. Deposit
allocations describe deltas, so a retained asset can receive tokens without
additional channel capacity. Withdrawal allocations describe physical outputs:
their reserve must cover the exact signed withdrawal Script and applicable Type
Script. Zero-token withdrawals use plain CKB outputs. Business value cannot
substitute for occupied reserve.

The new manifest, descriptor and Script preimages pass the ordinary complete
recovery-content and occupied-capacity checks. Retained participant/refund
Scripts and authority code identities cannot silently change. The canonical
transaction path enforces complete old-set consumption, new-set creation, exact
withdrawal placement, per-type transaction conservation, carrier preservation
and external fee attribution.

## Signing freeze

`MultiAssetChannelBackend::prepare_splice` requires the exact current signed
state, no pending ordinary update, and no unresolved higher signing reservation.
Preparation accepts partially signed new-context funding terms and verifies
all signatures already present. `reserve_splice_funding_signature` reserves the
creation or initial-recovery digest independently; persist that reservation
before signing and the resulting signature before exposing it. Both pairs of
funding signatures must be complete before an old-context bridge can be signed.

Before a bridge signer is invoked, `reserve_splice_signature` sets a durable freeze;
fsync the entire backend snapshot, including the complete future recovery
intent, before invoking the private signer. Persist a returned signature before
exposing it to the peer, as with ordinary state updates.

Ordinary proposals, signatures, commits and delayed-update imports are rejected
while a splice is prepared. Preparation can be cancelled before a local splice
signature is reserved. After reservation, neither cancellation nor restart can
unfreeze the old context. The old complete recovery package remains available
for unilateral publication. No trusted-looking boolean is accepted as evidence
that the exact old State input was retired.

Before signing, the transaction layer must verify the canonical live old State
and the actual transaction body. Persist that body and its new code-dependency
records alongside the protocol snapshot before signing; core objects do not
replace a canonical transaction builder. Completion/abort must reconcile its exact
input, canonical history, new complete set and reorg policy before advancing or
resuming a signer. The session commands below perform that reconciliation;
[signer supervision](runbooks/signer-supervision.md) continuously checks those
journals and persists expiring health and transition alerts.

Draft review and receipt import accept the current `morph.multi_asset_splice_draft.v1`
shape: `base_state_digest`, lossless packed CKB `transaction_hex`, unsigned
`new_witness_hex` and canonical `flows_hex`, all hexadecimal strings. The new
State and old State OutPoint are derived from the transaction; duplicate JSON
versions of those fields are rejected. Its Morph witness zero must be empty.
The draft verifier checks input order, complete new Vaults, withdrawal outputs,
carrier capacity and authority boundaries. Live input values, canonical history,
approved executable code and dep-group members require online verification.

The Rust SDK checks this same draft through the shared canonical implementation with
`morph_sdk::inspection::inspect(draft, Some(current))`. Its summary includes the
exact creation, recovery and bridge digests, old State input, future Vault
OutPoints, bound new funding-context ID, per-participant payouts and per-asset
deposit/withdrawal lanes. All amounts remain decimal strings. Asset admission
may change the registry; channel identity, participant/refund Scripts, authority
code, challenge policy and State carrier stay fixed. Token-only deposits into
an existing asset need no extra reserve when its existing reserve suffices.

`morph_sdk::packages::construction::splice_signature` verifies a public receipt against one of
`splice-creation`, `splice-recovery` and `splice-bridge`.
`morph_sdk::packages::construction::assemble_splice` requires all three complete pairs, verifies
the future exit first and returns `morph.multi_asset_splice_funding.v1` containing
both the packed transaction and full recovery package.
`morph_sdk::inspection::inspect(export, Some(current))` independently verifies a completed export,
including the exact initial exit and the canonical bridge envelope. Repricing
an external input, dependency or change output changes the future exit and
bridge digests even when the new allocation stays the same.

Import the SDK export with `morph-cli import-splice-funding funding.json
--old-package old-recovery.json --store-dir recovery`. This default-build
command verifies both complete contexts and all three authorisations before
writing anything, persists the future recovery package before the transaction,
and returns their paths for the native submission flow. It never initialises
or replaces signer history. Fee-wallet authorisation, live-input checking,
submission and confirmed same-path handoff still use the session/native steps
below.

The SDK shares bounded CKB transaction parsing and public receipt verification
with root funding. Rust/SDK fixtures check exact transaction and recovery bytes
for unchanged asset sets, actual 2→1 withdrawals and 1→2 admission. These
stateless checks do not replace the session's durable reservations, freeze or
canonical handoff; assembly neither spends inputs nor broadcasts.

```sh
morph-cli multi-asset-session --session alice.json prepare-splice --draft splice.json \
  --admission-config /srv/morph/admission.json --contracts-dir /srv/morph/contracts
morph-cli multi-asset-session --session alice.json sign --target splice-creation > alice-creation.json
morph-cli multi-asset-session --session alice.json add-signature --target splice-creation --signature bob-creation.json
morph-cli multi-asset-session --session alice.json sign --target splice-recovery > alice-recovery.json
morph-cli multi-asset-session --session alice.json add-signature --target splice-recovery --signature bob-recovery.json
morph-cli multi-asset-session --session alice.json sign --target splice-bridge > alice-bridge.json
morph-cli multi-asset-session --session alice.json add-signature --target splice-bridge --signature bob-bridge.json
morph-cli multi-asset-session --session alice.json export-splice --store-dir recovery
```

Both signers prepare the same exact draft and exchange each signature role.
The public native preparation must first reserve that exact new custody body in
the shared controlled-devnet admission ledger. Each journal persists its explicit
admission binding alongside the draft. Before every local splice Creation,
Recovery or Bridge signature, it connects to the pinned configuration's RPC,
reconciles canonical Factory closures and the shared pilot budget under the
stable ledger lock, and rechecks the current conditional refund horizon. Changed configuration, policy expiry, missing ledger, unadmitted
Types (including zero quantities), non-reviewed issuer code and excess capacity
or token quantities fail before key use. The ledger charges the channel's peak
reserved custody across splice alternatives and never refunds a cancellation.
Complete saved exit exports and ordinary recovery publication remain independent
of admission policy availability.
`MORPH_CHANNEL_PRIVATE_KEY_FILE` supplies the protected file path for the local signer key; see [key input](runbooks/key-input.md). The snapshot
retains the exact transaction before any signature is produced. Export durably
writes the full future unilateral recovery package before returning a binary
packed `.tx` with the complete Morph witness, preserving other input witnesses.
An external fee signer can fill its witness without changing the committed raw
body. `cancel-splice` works only before a local bridge reservation; export never
unseals the old signing context.

## Native draft construction

`morph.multi_asset_splice_terms.v1` contains `descriptor_hex`, `flows_hex`,
`new_type_scripts_hex`, `withdrawal_lock_hex` and `cell_deps`. Every field is
required. Descriptor and flow quantities use canonical binary encodings, so
JSON tooling cannot round a token quantity. The Type Script list is the exact
sorted set for the new manifest; dependencies use the recovery package shape.
The withdrawal Script is `0x` only when no withdrawal allocation is present.

```sh
morph-cli devnet --devnet-only --rpc-url "$CKB_RPC" multi-asset-splice-prepare \
  --admission-config /srv/morph/admission.json \
  --old-package old-recovery.json --state-out-point "$OLD_STATE" \
  --terms splice-terms.json --external-input "$FEE_INPUT" \
  --external-input "$TOKEN_DEPOSIT_INPUT" --change-pubkey "$OWNER_PUBKEY" \
  --fee 100000000 --output splice.json
```

Preparation requires no private key. It derives epoch, anchor, State/Vault
Scripts and Vault totals from the exact old State input and the new descriptor.
It checks actual live old custody and approved dependencies, then constructs
new Vaults, sorted withdrawal outputs, per-Type token change at occupied
capacity and plain CKB change. All external inputs must belong to the public
wallet identity. Insufficient token/CKB funding or dust change fails explicitly;
no fee increase or source selection is implicit. The saved draft is immutable
at its chosen path. Participants review it through the normal session flow.

## Exact transaction submission

```sh
morph-cli devnet --devnet-only --rpc-url "$CKB_RPC" multi-asset-splice-submit \
  --admission-config /srv/morph/admission.json \
  --transaction recovery/splice-TRANSACTION_HASH.tx \
  --old-package old-recovery.json --new-package new-recovery.json \
  --store-dir recovery --max-fee 100000000 --dry-run wallet
```

`wallet` reads the protected key file named by `MORPH_DEVNET_PRIVATE_KEY_FILE`
for independent external funding
inputs. Every such input must belong to that wallet and carry only a registered
token or plain CKB. All extra change must return to the same wallet; carrier,
new Vault and withdrawal allocations are checked separately. `presigned` accepts
complete external wallet witnesses without requesting any signing key. Neither
role accepts an implicit fallback or changes the raw body to adjust fees.

Submission verifies both signed contexts, full bridge and creation witnesses,
canonical State/Vault liveness, exact future exit OutPoints, occupied capacity,
per-Type transaction conservation and the explicit fee cap. It resolves code and
dep-group members, rejects consumed recovery dependencies, checks selected Morph
artifacts and all committed payout/refund/Type Scripts, then checks a canonical
checkpoint before and after VM preflight. Both recovery packages survive restart
before wallet signing. The complete fee-signed transaction is persisted under
`submitted-splices/` before broadcast. A successful RPC or confirmation report
does not switch or unfreeze either participant journal.

## Confirmed signer switching

The initial [funding ceremony](runbooks/initial-funding.md) confirms the root
on the same signer path; operational `init`/`bind-root` have been removed.
Later epochs must pass through `confirm-splice`; they cannot initialise an
independent journal and bypass the lineage guard. Keep the same authoritative session path across funding epochs. After the new
State has been activated and both the splice and State transactions have the
explicit required confirmation depth:

```sh
morph-cli multi-asset-session --session alice.json confirm-splice \
  --rpc-url "$CKB_RPC" --state-out-point "$NEW_BOUND_STATE" \
  --min-confirmations 4 --archive-dir signer-archive
```

This read-only RPC operation requires a build with `--features devnet`. It
checks actual transaction membership in canonical blocks, exact signed raw
body, authentic bound State authority, complete live Vault custody and approved
exit dependencies. It derives the transaction and initial exit from the frozen
journal rather than accepting a replacement intent. The command first fsyncs a
content-addressed private `morph.multi_asset_retired_session.v1` archive and the
full initial exit package, then atomically replaces the same active session
with the new funding context. The old signer stays sealed. Retired evidence has
its own shape and cannot be opened as an active signing session.

The new snapshot pins the RPC endpoint, contract-artifact directory, depth,
canonical funding/State inclusions and the exact predecessor archive hash.
Every new-context proposal, vote and commit checks that evidence and live exit
custody again; signing also checks immediately before private-key use and after
persisting the signature. Missing evidence, insufficient confirmations, changed
inclusion, spent Vaults or unavailable code fails closed. A build without RPC
support refuses guarded signing. `inspect` shows cached evidence; it is not an
online health assertion. Keep the selected approved artifact directory and all
retired archives available.

After a reorg, replay the original retained transaction if appropriate, restore
activation, wait for the pinned depth and reconcile the **same** context:

```sh
morph-cli multi-asset-session --session alice.json refresh-chain \
  --state-out-point "$BOUND_STATE" --package latest-complete-recovery.json
```

Refresh does not weaken the depth, change the endpoint, replace the funding
body or reset vote history. An already pending proposal survives a refresh of
the current recovery package. A newer complete package is imported only if the
existing local vote reservation permits it; unknown future local signatures
remain rejected. If the exact funding cannot be restored, the new signer stays
stopped. Neither command re-enables the bridge-reserved old context.

Snapshots require explicit `splice`, `splice_draft` and `lineage`, including
null outside those roles, and all funding reservation fields for a prepared
splice. Missing old fields are rejected; no migration fills a missing guard.

## Verification

`cargo test -p morph-core --test multi_asset --test hash_parity` covers admission
and removal, the maximum 16-flow union, per-asset/lane/overflow negatives,
creation and initial-exit prerequisites, transaction replacement, domain parity,
signature replay, durable freeze/restart and malformed/missing snapshot fields.
`make contract-tests` additionally verifies asset admission/removal (2→3 and
2→1), complete eight-asset replacement with the 16-flow union, and post-splice
activation/publication/finalisation. Negatives cover raw-body mutation, cloned/
missing/extra Vaults, a fake new State authority, substituted withdrawals, carrier
loss, missing/replayed authorizations, signed invalid lane accounting and minting
under a permissive asset Type.

The maximum-Script fixture uses 512-byte payout, refund, withdrawal and new
asset Scripts, with sufficient signed reserve. It measured 25,014 transaction
bytes and 32,575,578 cycles for full eight-asset replacement, within the unchanged
50,000,000-cycle test cap. This is CKB-VM profile evidence, not node/reorg or
release approval; remaining transaction-cell extremes and independent review
still require qualification. Evidence: `target/splice-runtime-vm-max.log`.

## Isolated-node native acceptance

The current source passed a fresh two-xUDT 2→1→2 workflow with both signer files
switched by `confirm-splice` after each activation. Confirmation depth 4 was
explicit in this isolated test. An early transition was rejected without any
snapshot change. The removal was then orphaned: signing failed before reserving
a vote. Exact keyless replay and activation did not silently re-enable signing;
`refresh-chain` was required, and it preserved the pending state-2 proposal.
Both signers subsequently signed and committed that update, restored the removed
asset from its actual wallet UTXO, switched again and completed unilateral
publication/finalisation. Signing after closure was rejected. All four retired
journals remained sealed and were rejected as active-session inputs.

Current evidence:
`target/multi-asset-devnet/splice-journal-final/lineage-report.json`.
The earlier native transaction measurements remain 4,219 bytes / 29,026,486
cycles for removal and 4,392 bytes / 29,176,109 cycles for restoration. They
supplement the eight-asset, maximum-Script CKB-VM bound above; they do not replace
that bound, continuous-service acceptance or independent review. The isolated
setup's first finalisation was deliberately orphaned; the final native
roundtrip was closed on the canonical branch.
