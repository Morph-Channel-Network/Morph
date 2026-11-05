# Current State and Vault-Set Wire Profile

Status: current unpublished implementation, 2026-11-05. The shared parsers in
`morph-script-common` are the executable wire definition. This is the sole
current channel custody implementation; the Factory is a separate authority
object over the same custody primitives. Unsupported prior bytes are rejected.
See [current capability coverage](current-protocol-coverage.md) for migration,
negative tests, measured limits and the remaining release gates.

## State and Vault Authority

State layout 2 is an independent 318-byte encoding. It contains no single-Vault
materialisation field, single-Vault OutPoint field, or duplicate content root.
All integers use little endian order. Protocol version 1, signature scheme 1,
bilateral mode 1, descriptor version 5, and layout version 2 are required.

| Byte offset | Field | Bytes |
| --- | --- | --- |
| 0 | Protocol version | 2 |
| 2 | Chain ID | 32 |
| 34 | Signature scheme | 2 |
| 36 | Channel ID | 32 |
| 68 | Funding epoch | 8 |
| 76 | Funding anchor | 32 |
| 108 | State number | 8 |
| 116 | Mode | 1 |
| 117 | Phase | 1 |
| 118 | Participants commitment | 32 |
| 150 | Asset registry commitment | 32 |
| 182 | Settlement descriptor commitment | 32 |
| 214 | Descriptor version | 2 |
| 216 | Challenge policy commitment | 32 |
| 248 | State layout version | 2 |
| 250 | Vault content-set root | 32 |
| 282 | Exact-OutPoint-set root | 32 |
| 314 | Vault count | 2 |
| 316 | Reserved zero | 2 |

Active states may be unbound; settling states must be bound. The signing domain
is `CKB_MORPH_MULTI_ASSET_STATE_V1` followed by all 318 bytes. Historical
414-byte packages and snapshots with single-Vault header fields are rejected.
Replace development state after this change; there is no conversion parser.

Each Vault uses 116-byte args: `MORPHMV!`, u16 encoding version 1, u16 reserved
zero, funding anchor (32), canonical relative-block `since` (8), exact StateType
Script hash (32), and exact StateLock Script hash (32). All Vaults share one
lock. The scripts independently require the authentic State input and the
complete exact set; partial State retirement is rejected.

Creation signs and checks the unbound manifest. Activation preserves the
entire State except its OutPoint-set root and preserves carrier capacity
exactly. Its first N raw CellDeps must be direct Vault dependencies in manifest
order, all from the transaction that created the unbound State. Publication
and supersede preserve the entire funding context and require newer,
two-participant signed settling evidence. The [current splice bridge](multi-asset-splice.md) implements exact-transaction
State/Vault retirement and successor creation. Native submission, durable
signing and canonical same-session handoff are implemented; terminal abort
tracking and production qualification remain open.

StateType args have one shared parser: `MultiAssetStateTypeArgs`. Direct args
are `anchor[32] || since[8]`; Factory child args are
`anchor[32] || originating_FactoryType_hash[32] || since[8]`. Only lengths 40
and 72 are accepted. Child origin is nonzero and since is canonical relative
block encoding. The clock is always the final eight bytes, not the beginning
of the Factory origin.

## Manifest, Descriptor, and Witness

All integers are little endian. All reserved fields are zero. Counted arrays
are bounded to 1–8 Vaults, including an optional plain CKB Vault. Asset IDs are
33 bytes: kind 0 plus a zero Type hash for CKB, or kind 1 plus the full nonzero
xUDT Type Script hash. IDs are strictly ordered and unique.

An allocation is 32 bytes: reserve u64, business CKB u64, token quantity u128.
Capacity is the checked sum of reserve and business CKB. Plain CKB allocations
have zero token quantity. Empty payouts have all three quantities zero and
produce no Cell. A funded typed Vault has a positive quantity and exactly
16 data bytes; plain Vault data is empty.

| Object | Encoding |
| --- | --- |
| Manifest | u16 version 1, u8 count, u8 reserved; N entries of asset ID (33), Vault lock hash (32), allocation (32). Length `4 + N*97`. |
| Settlement descriptor | u16 version 5, u8 count, u8 capability; two sorted nonzero payout lock hashes (64), carrier-refund lock hash (32); N entries of asset ID (33) and two allocations (64). Ordinary length `100 + N*97`; capability 1 appends a 36-byte executor prefix and 828-byte Batch terms. |
| Recovery witness | `MORPHMA!` (8), u16 version 1, u16 flags 0, u32 manifest length, u32 descriptor length, u16 OutPoint count, u16 reserved, u32 scripts length; manifest, descriptor, OutPoints, script evidence. |
| OutPoints | N canonical 36-byte CKB OutPoints in manifest asset order; zero entries only for an unbound State. Duplicates and zero transaction hashes are rejected. |
| Script evidence | Six scripts (payout 0, payout 1, carrier refund, Vault Lock, State Type, State Lock), followed by each xUDT Type Script in asset order. Each is a u32 length and complete canonical Molecule Script, bounded to 512 bytes. |

Content commitment hashes `CKB_MORPH_MULTI_ASSET_VAULT_SET_V1 || manifest`.
Descriptor commitment hashes `CKB_MORPH_MULTI_ASSET_DESCRIPTOR_V1 || descriptor`.
Exact provenance hashes `CKB_MORPH_MULTI_ASSET_OUTPOINT_SET_V1 || content_root ||
u16(count) || outpoints`. Hashing uses CKB-personalised Blake2b-256 throughout.
The asset-registry commitment retains its existing canonical domain and sorted
Type hash list. Funding-context identity has its own
`CKB_MORPH_MULTI_ASSET_FUNDING_CONTEXT_V1` domain and binds chain ID, channel ID,
funding anchor, content-set root, and OutPoint-set root.

Script evidence proves actual lock/Type identities and occupied bytes before
funding or accepting a signed state. State/Vault args must agree on anchor,
challenge delay, StateType, and StateLock. Every Vault and payout reserve must
cover its exact occupied capacity. Carrier capacity covers both the live State
and its plain refund output.

Capability tag 0 means ordinary settlement. Tag 1 requires the exact current
CKB conditional trailer and at least one pending transfer; unknown tags,
descriptor 4, zero/malformed conditional shapes and trailing bytes are rejected.
The trailer commits executor code/hash type and the canonical 828-byte Batch
terms. Those inner terms are reused by one Batch executor, not another State
profile. Its sole 104-byte args bind channel ID, exact funding context, state
number and complete terms commitment. See [conditional execution](conditional-batches.md).

## Conservation and Finalisation

Each manifest asset must have the same descriptor identity. Its two payouts
independently sum to its reserve, business CKB, and token quantity. Checked
arithmetic rejects overflow, cross-asset minting, and reserve reclassification.
The current profile conserves those lanes per Vault, a stronger restriction
than pooling reserve across assets.

Finalisation consumes all committed Vault OutPoints. Outputs appear in
asset/participant order, omitting only empty allocations. Nonzero token
quantities produce typed outputs; zero-token allocations produce plain outputs.
The complete State carrier refund follows those payouts. Each position is
checked exactly once. Subsequent plain fee change may share a payout/refund
address without contributing to channel conservation. Extra Vault outputs and
extra registered-token outputs are rejected. Fees require external funding;
the current profile never deducts activation or finalisation fees from carrier value.

Signed recovery evidence must be retained before funding broadcast. The raw
funding transaction hash excludes witnesses, so its exact future Vault
OutPoints can be used in a pre-signed settling state without embedding the
transaction's own hash in its output State data.

## State Negotiation and Signer Journal

`morph-core::MultiAssetChannelBackend` negotiates the current multi-asset
profile from a complete, bound, two-signature settling recovery package. It
validates proposals against the exact prior signed state and funding context,
conserves every asset and capacity lane, and keeps the existing manifest,
OutPoints, scripts and carrier. Both signatures are checked independently;
a complete update produces the same recovery package consumed by the
standalone transaction operator.

The backend keeps one local signing reservation (state number and digest).
The caller must persist that reservation before invoking its private signer,
and persist the signature before releasing it to its peer. Duplicate delivery
is idempotent. Cancelling preserves the reservation, so a different proposal
must use a greater number. A delayed complete peer update can be recovered
without clearing a newer reservation. An unknown future local signature is
rejected as inconsistent with this signer's journal.

`multi-asset-funding-session` implements independent offline initial signing;
[initial funding](runbooks/initial-funding.md) describes its exit-before-creation
ordering and confirmed handoff. Operational `multi-asset-session` commands
retain these persistence requirements and canonical lineage checks. Its current session
schema is `morph.multi_asset_session.v1`; snapshots contain public recovery and
signature data, never a private key. The CLI holds an OS file lock on a stable
sidecar inode across read, reservation, signing and atomic snapshot replacement.
Private snapshots are mode 0600 on Unix; writes fsync the file and directories.
Operational commands reject snapshots without confirmed lineage. The RPC
genesis must match the signed chain ID for funding, native state operations,
splice and context verification.

The reservation is persisted before calling the signer and the signature is
persisted before stdout returns its receipt. A crashed process releases the OS
lock. Initialization refuses an existing session rather than resetting history.

Each participant runs its own session and supplies the path to its protected
signing-key file through `MORPH_CHANNEL_PRIVATE_KEY_FILE`; see
[key input](runbooks/key-input.md). `--local-pubkey` is the
canonical `0x`-prefixed compressed 33-byte key. Review `inspect` output, including
all proposed per-asset allocations and payout-lock identities, before `sign`.

```sh
morph-cli multi-asset-session --session alice.json propose \
  --descriptor-hex "$DESCRIPTOR_HEX" > proposal.json
morph-cli multi-asset-session --session bob.json accept --proposal proposal.json
morph-cli multi-asset-session --session alice.json inspect
morph-cli multi-asset-session --session alice.json sign --target update > alice-signature.json
morph-cli multi-asset-session --session alice.json add-signature --target update \
  --signature bob-signature.json
morph-cli multi-asset-session --session alice.json commit --store-dir recovery
```

Both paths must first complete the independent initial funding ceremony. The
old recovery-package `init` and `bind-root` commands are removed; packages cannot
replace signing history. Post-splice epochs use `confirm-splice` on the same
authoritative session path and retain canonical lineage guards; see
[multi-asset splice](multi-asset-splice.md).
`cancel` discards a pending proposal; `recover --package PATH` imports an
already completed peer update while preserving the local reservation. Peer
proposal schema `morph.multi_asset_proposal.v1` contains the prior state digest,
canonical decimal state number, descriptor hex and signing digest. Signature
receipts use `morph.multi_asset_signature.v1`. All public quantities are strings.
The private Rust snapshot is not a JavaScript interchange format.

Keep one authoritative session per signer/funding context. Never clone an
active signer journal into concurrent authorities or restore an older snapshot;
local file locking cannot detect deliberate file rollback or separate stores.
Retain complete recovery packages separately for watchtower use. The SDK's
`createMultiAssetProposal`, `inspectMultiAssetProposal`, and
`inspectMultiAssetProposalSignature` validate proposal content and signatures
independently, but are stateless helpers and do not implement a signing journal.
Current payment/conditional services use this backend; SDK helpers remain
stateless. Factory signing has a separate durable rights/custody authority,
with the shared current custody validators.

## Multi-Asset Dispute Watch Passes

`devnet multi-asset-watch` scans activated multi-asset State Cells using the
approved local State Type/Lock artifacts. It only defends an older **Settling**
state. A normal Active channel stays open when newer off-chain recovery
packages arrive. Full Type/Lock identities, funding context and carrier must
match saved evidence; a same-number on-chain/header conflict is a critical
error rather than an arbitrary tie-break.

The store is indexed by exact channel and funding context, with at most 4096
packages and 4096 retained context directories per watched channel. Each
package is revalidated; different evidence at one context/state number fails
closed with `recovery_data_invalid`. A higher number in another context cannot
supersede the observed channel. Packages remain retained across reorgs.

A cursor contains mandatory `from_block`, contiguous `next_block` and
`scanned_to_block`, the scanned block hash, and a complete or empty observation
context. Its origin must match the configured origin and cannot start after
any known canonical retained funding transaction. Unsupported/missing fields
are rejected. Changing origin requires a fresh watch cursor, not a signer
journal reset. New cursor writes use private fsynced atomic replacement.

At startup, each poll boundary and between scanned blocks, canonical hash and
parent linkage are checked. A missing/mismatched checkpoint or a block changing
mid-scan emits `chain_reorg_detected`, durably clears orphanable observation
context and resumes from configured creation `from_block`. An uninitialised
persisted checkpoint also triggers the critical rescan. If a newer package
arrives after the cursor passed a live stale Settling cell, the pass rescans
without requiring a new block.

Automatic publication requires a validated publication profile, durable attempt
log, explicit plain secp fee input and maximum fee. Polling cannot be slower
than the profile's conservative block interval; detection depth must leave the
profile's challenge-window reserve. Before spending, the shared transaction
operator checks complete Vault liveness, script dependencies and release code,
preserves carrier/value and applies the bounded fee/RBF controller. Restart
reconciles prior attempts. Pending results remain unconfirmed; a later pass
retries while the old State is canonically live. No wallet cell is selected or
replenished implicitly. After a confirmed spend, supply another explicit fee
input for later disputes.

```sh
morph-cli devnet --devnet-only multi-asset-watch \
  --store-dir recovery --channel-id "$CHANNEL_ID" --from-block "$CREATION_BLOCK" \
  --cursor-file operator-a/cursor.json --alert-file operator-a/alerts.jsonl \
  --publication-profile publication-profile.json --attempt-log operator-a/attempts.jsonl \
  --fee-out-point FEE_TX_HASH:0 --max-fee 100000000 --timeout-secs 30 wallet
```

Fee keys use the existing hidden-value environment option. Keep each operator's
cursor/attempt files separate. `publication_failed` and `recovery_data_invalid`
are critical alerts consumable by Hub. Pass reports expose State numbers as
strings and report catch-up separately from submission. Configured once/loop/service
commands reuse these same passes with bounded
backoff, health and alerts; see [current watch service](runbooks/current-watch-service.md).
Independent-host failover, pooled publication, terminal abort tracking and
production operational qualification remain open. Explicit service configuration
may authorize separate bounded Sponsor funding; that policy does not turn a
watch pass into participant signing authority.

## Tooling and Evidence

The stored schema is `morph.multi_asset_recovery_package.v1`. It contains
canonical lowercase hex for the header, recovery witness, and bilateral
signature witness, decimal-string carrier capacity, and a canonical bounded
`cell_deps` list with exact OutPoints and Code or DepGroup kinds. Dependency
liveness and approved deployed code require chain checks before broadcast.
Rust and TypeScript
share a signed fixture with token amounts above JavaScript's safe integer
range; all exposed monetary quantities and state numbers remain strings.

```sh
cargo run -p morph-cli -- print-multi-asset-fixture
cargo run -p morph-cli -- validate-multi-asset-package package.json --json
cargo run -p morph-cli -- store-multi-asset-package package.json --store-dir recovery
make fixture-checks
make build-contracts
cargo test -p morph-core --test multi_asset
cargo test -p morph-core --test contract_scripts multi_asset:: -- --ignored --test-threads=1 --nocapture
```

`devnet multi-asset-transact` reconstructs transactions from a stored package;
participant private keys and synthetic issuer helpers are not needed. It
supports `--operation activate|publish|finalise`, an explicit live
`--state-out-point`, a distinct plain `--fee-out-point`, mandatory `--max-fee`,
and `--dry-run`. The required `wallet` fee authorization uses the hidden-value
`MORPH_DEVNET_PRIVATE_KEY_FILE` environment option naming its protected key file. Dry run persists the recovery evidence and returns the signed
transaction plus VM estimates without submitting it.

Before constructing any transaction, the command validates every live Vault
against its exact committed OutPoint, script, capacity, and token data. It
resolves bounded Code/DepGroup dependencies from the canonical chain, verifies
that they resolve every committed script and the fee lock, and checks Morph
authority code against `--contracts-dir`. Publication preserves the authentic
State carrier and advances the state number in the exact same funding context.
Finalisation requires the exact current published header, canonical inclusion,
and matured relative-block delay, then creates all signed payouts and the
complete carrier refund. Channel funds never contribute to fees.

Root creation requires two signatures over
`blake2b256(CKB_MORPH_MULTI_ASSET_ROOT_FUNDING_V1 || state_signing_digest || raw_transaction_hash)`.
The header must be unbound epoch-0 Active/0; witnesses are outside CKB's raw
transaction identity. Repricing fees, changing dependencies or replacing any
raw input/output therefore requires fresh creation signatures and a new
pre-signed bound exit. The 198-byte signature encoding is unchanged. Ordinary
state signatures are rejected for root creation, with no compatibility path.
Splice creation instead uses its full-transaction bridge authorization plus
the new state's ordinary creation signatures.

Activation requires the original unbound Active state zero and a complete,
valid signed settling recovery package for the same funding bundle. The
canonical RPC must supply the original funding transaction and witness zero.
The operator verifies its transaction hash and the creation signatures, then
reconstructs the original descriptor with the recovery package's exact Vault
OutPoints. The first N dependencies are those direct Vaults in manifest order;
all must originate in that funding transaction. State bytes and carrier stay
unchanged except for binding the OutPoint root. Creation signatures are not
reused to sign the activated header, and participant keys are never requested.

A newer recovery descriptor can differ from the original funding descriptor.
Activation preserves the original; publication is a separate signed progress
step. Reports expose both the retained recovery `package` and the actual
`resulting_state`: Active/0 after activation, Settling/N after publication, or
null after finalisation. Activation uses explicit bounded wallet fees and
rejects sponsor authorization and already-bound State inputs.

```sh
morph-cli devnet --devnet-only multi-asset-transact \
  --operation activate --package latest-recovery.json \
  --state-out-point FUNDING_TX_HASH:0 --fee-out-point FEE_TX_HASH:0 \
  --fee 100000000 --max-fee 100000000 --dry-run wallet
```

Current release evidence must use rebuilt descriptor-5 artifacts and current
reports. Historical descriptor-4 reports and old deployment hashes do not
qualify this boundary. See [the coverage ledger](current-protocol-coverage.md)
for current host/CKB-VM evidence and reproduction commands.

## Factory authority over current custody

Factory State is 306 bytes/layout 2; its Type args are 44 bytes (`MORPHFT!`,
format 1, reserved zero, Factory identity). `MORPHFS!` format 2 has root,
activation and update roles. Root and update have distinct exact-transaction
signing domains; a header-only vote cannot authorize UPDATE. Activation binds
the complete sibling set without member keys and preserves carrier capacity.

`MORPHFM!` authorizes N-of-N materialisation. `MORPHFR!` version 1 is the sole
current reduced/funded transition frame: ReducedRights, ReducedDeposit,
ReducedRelease, ReducedChild and FullCustody. Pure metadata remains the one
FS UPDATE path. Source, retained and child manifests use the shared custody
encoders. The runtime authenticates actual State/StateLock identity, exact
source OutPoints, complete custody, outputs, external funding and raw transaction.

See [Factory operations](factory-multi-right.md) and [the coverage ledger](current-protocol-coverage.md)
for authority, proof data, capacity floors and supported operation limits.
