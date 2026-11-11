# Initial Multi-Asset Funding

Each participant keeps one authoritative session path from the initial funding
ceremony through later splice epochs. Every new initial Exit or Creation
signature refreshes the pinned controlled-devnet RPC and shared admission
ledger, including the current refund horizon when conditional. Draft review,
receipt import and saved exit export can run offline with the default CLI
build. Chain submission and confirmed handoff require
`cargo build -p morph-cli --features devnet`. No ceremony command accepts both
participant secrets.

## Construct exact root funding

The SDK independently checks root drafts with `inspectMultiAssetRootDraft` and
public receipts with `inspectMultiAssetFundingSignature`. Amounts stay decimal
strings, including quantities above JavaScript's safe integer range.
`assembleMultiAssetRootFunding` requires two valid exit receipts before two
creation receipts and produces the complete recovery package and transaction.
These stateless helpers do not replace either participant's durable signing
journal.

The Hub coordinates public evidence through `POST /api/root-fundings`,
`POST /api/root-fundings/<transaction-hash>/signatures` (body `{target,receipt}`),
and `GET /api/root-fundings/<transaction-hash>[/export]`. Targets are `exit` and
`creation`. The authenticated Hub identity must participate and its counterparty
must be a known peer when importing a draft. Read and write scopes apply;
coordination needs no signing key. Drafts are immutable, receipts are verified
and persisted before acknowledgement, and creation receipts require the full
exit. The UI exposes these proposals separately from active channels. Collecting
all receipts does not broadcast, confirm funding, or create an operating channel.

`MorphHubClient` provides `importRootFunding`, `rootFunding`,
`addRootFundingSignature`, and `exportRootFunding`; returned collections and
exports are independently verified. Export includes the recovery package, not
just transaction bytes. Import it locally with
`morph-cli import-root-funding funding.json --store-dir recovery`: the CLI
verifies both authorisations and physical custody, writes the recovery package
durably, then writes the transaction. Wallet authorisation and chain submission
still follow the steps below. Import cannot initialise or reset signing history.
Export inspection can accept a newer positive settling recovery state for the
same funding context; its initial payout summary always describes the original
root draft. The supplied recovery package retains its own state and descriptor.

The eight-asset SDK/HTTP Hub acceptance run on 2026-11-02 used separate
participant signing processes and three independent wallet signers. SDK, Hub
and CLI exports matched byte-for-byte; scoped read/write access and Hub restart
preserved the public receipts without creating an operating channel. The exact
7,673-byte transaction used 12,315,278 VM cycles, completed canonical activation,
same-path signer handoff and final unilateral settlement. Local evidence:
`target/multi-asset-devnet/hub-sdk-root-eight/report.json`; funding transaction
`0xdd412860b0502999ee698e6a1539ae0cad137e1aa06d86b6ab029b776a4e71ef`, finalisation
`0x9f3c53f72bccae6d88a2b9919a3d0741feb889da766eee58ccf400b735702383`.
This is isolated devnet acceptance, not release qualification.

`devnet multi-asset-funding-prepare` builds a draft from explicit
`morph.multi_asset_root_terms.v1` terms. It takes no keys and performs no
issuance, automatic input selection, signing or broadcast. The terms contain:

| Field | Meaning |
| --- | --- |
| `participants` | Two distinct compressed keys in raw key order. |
| `participant_locks_hex` | Two actual payout Scripts, in the descriptor's sorted lock-hash order. This ordering is independent of public-key order. |
| `carrier_refund_lock_hex` | Actual Script receiving the exact State carrier on exit. |
| `descriptor_hex` | Canonical descriptor-6 allocations with an explicit ordinary/asset-bound conditional capability; Vault totals include only each exact asset's pending lane. |
| `challenge_blocks` | Positive canonical decimal relative-block count. |
| `type_scripts_hex` | Complete actual xUDT Scripts in Type-hash order; omit for plain CKB only. |
| `cell_deps` | Explicit canonical code/dep-group records `{tx_hash,index,dep_type}`, sorted by OutPoint. |
| `funders` | 1–16 explicit wallets, sorted by compressed public key. |

Every funder record has `pubkey`, ordered `inputs` (`{tx_hash,index}`),
`ckb_contribution`, `fee_contribution`, and ordered `tokens` records
(`{type_hash,amount}`). Quantities and block counts are decimal strings; CKB quantities use shannons. Each
wallet owns all its inputs. Inputs are unique across wallets, with at most 64
in total, and can contain plain CKB or registered xUDTs only.

CKB contributions must sum exactly to all signed Vault capacity plus the State
carrier; fee contributions independently sum to the actual fee, bounded by
`--max-fee`. For each Type, token contributions must sum exactly to that Vault's
quantity. The allocation descriptor and funding contributions are separate
explicit decisions: a participant can agree to an initial transfer, and a
third wallet can fund the carrier or fees. No wallet subsidises another wallet's
shortfall implicitly.

State output zero and the complete Vault set come first. Change stays with
its original wallet. Token change funds occupied capacity; plain change funds
its own minimum. Tiny residual CKB can be added to that wallet's token change;
if it has no token change the builder rejects dust instead of increasing fees.
The first declared input fixes the funding anchor and derived channel ID.
The RPC genesis and locally approved `data1` artifacts fix chain and authority.

All new root custody requires an explicit reviewed `--admission-config`. Create
it with `devnet factory admission-config --no-real-assets`, naming the exact
built artifact manifest, controlled-devnet genesis, one stable pilot ledger and
every permitted token Type hash through `--admitted-asset-type`. The same ledger
must cover Factory custody, its children and bilateral channels. The exact
manifest plus State carrier must fit the current 4,000 CKB channel limit and
40,000 CKB combined pilot limit; each token Type is bounded to 10^12 units.
Zero participant token balances still require an allowlisted Type whose code is the
reviewed `morph-devnet-xudt`. Preparation and wallet/submission paths check the
current envelope, actual fees and occupied output capacity before reserving the
exact body under the stable, fsynced ledger lock.

```sh
morph-cli devnet --devnet-only --rpc-url "$CKB_RPC" multi-asset-funding-prepare \
  --admission-config /srv/morph/admission.json \
  --terms root-terms.json --max-fee 100000000 \
  --contracts-dir /srv/morph/contracts --output root-draft.json
```

Preparation verifies canonical live inputs, code and dep-group resolution,
occupied capacity, per-owner funding and whole-transaction conservation before
writing an immutable draft. Its report includes both signing digests, custody,
allocations, funder budgets and transaction identity. Identical retries reuse
the artifact; another intent cannot overwrite it. A concurrent reorg rejects
the preparation. Output count and transaction bytes retain the root profile's
bounds. The smoke harness now uses this same public constructor.

New conditional updates on a confirmed channel use the canonical session RPC
tip and the binary's reviewed public envelope/Batch artifact pin. Each new
proposal, acceptance and local signature enforces the 2,016-block refund horizon.
This applies equally to Root and Factory-origin channels and requires no Factory
operator ledger or private policy file. Already signed states remain recovery
authority after their deadlines; export and finalisation do not rerun admission.

## Review the exact proposal

The transaction builder produces `morph.multi_asset_root_draft.v1`:

```json
{
  "schema": "morph.multi_asset_root_draft.v1",
  "transaction_hex": "0xPACKED_UNSIGNED_CKB_TRANSACTION",
  "participants": ["0xSORTED_COMPRESSED_KEY_0", "0xSORTED_COMPRESSED_KEY_1"]
}
```

The packed transaction carries unbound epoch-0 Active/0 State data, complete
`MORPHMA!` evidence in witness zero's `output_type`, and no `lock` or
`input_type` signature in that witness. The participants are distinct sorted
33-byte compressed secp256k1 keys matching the State commitment. The initial
Settling/1 exit is derived from the exact raw transaction hash, actual Vault
output indices, original descriptor and complete custody set. Amounts, roots,
State capacity and dependencies are not repeated as independently editable
proposal fields. Extra Vaults, duplicate State authority outputs and StateLock
clones are rejected.

The ceremony checks proposed outputs and authority. Each new participant
signature also rechecks the configured RPC genesis/network, canonical Factory
closure observations, current combined pilot capacity and conditional refund
horizon. Preparation and submission additionally verify live exact inputs and
canonical chain evidence.
Submission checks the RPC genesis against the signed chain ID, deployed code,
occupied capacity, CKB fees and independent conservation of every registered
Type before VM preflight and network writes.

Each signer independently chooses approved local `data1` artifacts named
`morph-state-type`, `morph-state-lock`, and `morph-vault-lock`. Their hashes must
match the proposal before initialization and each signing operation; the
absolute artifact path is persisted. Initialization also requires the exact
body's prior shared-ledger reservation and persists the admission configuration
path and content hash, including its required `rpc_url`. Each new signing
operation rechecks that binding and refreshes canonical admission under the same
ledger lock immediately before using the participant key. Configuration edits, expired policy, lost ledger or
artifact drift stop new signatures. Exporting a complete saved exit or funding
body and confirmed same-path handoff remain available without admission policy
access. Review the chain ID, channel, participants, funding
hash, payout-lock hashes, carrier and every allocation in `inspect` output.

```sh
morph-cli multi-asset-funding-session --session /srv/morph/alice.json init \
  --admission-config /srv/morph/admission.json \
  --draft root-draft.json --local-pubkey "$LOCAL_PUBKEY" \
  --contracts-dir /srv/morph/contracts
morph-cli multi-asset-funding-session --session /srv/morph/alice.json inspect
morph-cli multi-asset-funding-session --session /srv/morph/alice.json sign \
  --target exit > alice-exit-signature.json
```

`MORPH_CHANNEL_PRIVATE_KEY_FILE` supplies the protected file path for this
participant's secret; see [key input](key-input.md). Exchange exit receipts with the peer and import the peer's receipt:

```sh
morph-cli multi-asset-funding-session --session /srv/morph/alice.json add-signature \
  --target exit --signature bob-exit-signature.json
morph-cli multi-asset-funding-session --session /srv/morph/alice.json export-recovery \
  --store-dir /srv/morph/recovery
morph-cli multi-asset-funding-session --session /srv/morph/alice.json sign \
  --target creation > alice-creation-signature.json
morph-cli multi-asset-funding-session --session /srv/morph/alice.json add-signature \
  --target creation --signature bob-creation-signature.json
morph-cli multi-asset-funding-session --session /srv/morph/alice.json export \
  --store-dir /srv/morph/recovery
```

Bob runs the same steps on his own path with his own key. Creation is blocked
until a complete valid two-party initial exit is persisted. Each reservation is
fsynced before crypto; the receipt is fsynced before stdout. Repeated signing
returns the same receipt. Peer imports verify membership and the exact target
digest; importing an unreserved local receipt is rejected. The current private
schema is `morph.multi_asset_funding_session.v1`, with all reservation fields
required and unknown fields rejected. There is no cancellation, draft
replacement, reset, missing-field default or historical session parser.

Export saves the full recovery package before the Morph-authorised funding
binary. Already signed evidence remains exportable without RPC or installed
artifacts. A wallet may add witnesses but cannot change the raw body: the root
creation signatures bind it and the exit signs its exact future Vault OutPoints.

`export-recovery` separately saves the complete private initial exit once both
exit signatures are retained. It needs no creation receipt, peer connection,
RPC or installed artifacts, and emits no funding transaction. An incomplete
exit is rejected without creating a recovery artifact. Retain this package
even if the coordinator withholds the peer's final creation receipt: the
coordinator can still combine both creation approvals and fund the channel.
Keep the package private under the [recovery delivery and backup
rules](operations.md); its path, rather than its signed contents, is returned.

## Submit and confirm the same path

After the two participant roles are complete, each funding wallet signs only
its own group. It supplies its own protected key file path through
`MORPH_DEVNET_PRIVATE_KEY_FILE`; no participant
secret or other wallet's secret is needed. Pass each returned transaction to
the next wallet, retaining the same raw body:

```sh
morph-cli devnet --devnet-only --rpc-url "$CKB_RPC" multi-asset-funding-wallet-sign \
  --admission-config /srv/morph/admission.json \
  --terms root-terms.json --transaction exported-funding.tx \
  --package initial-exit.json --max-fee 100000000 \
  --contracts-dir /srv/morph/contracts --store-dir /srv/morph/recovery
```

The wallet independently reconstructs the transaction from the exact terms and
live inputs. A different body or undeclared key is rejected. The complete
participant-authorised initial exit and root creation must already be present.
The exit is persisted before wallet crypto; the resulting partial transaction
is stored immutably before returning. Other wallet witnesses and Morph witness
fields are preserved. This command never broadcasts.

After all wallets sign, submit the complete binary:

```sh
morph-cli devnet --devnet-only --rpc-url "$CKB_RPC" multi-asset-funding-submit \
  --admission-config /srv/morph/admission.json \
  --transaction fully-signed-funding.tx --package initial-exit.json \
  --contracts-dir /srv/morph/contracts --store-dir /srv/morph/recovery \
  --max-fee 100000000 --mine-blocks 4
```

Submission accepts no signing key or legacy `wallet`/`presigned` mode. It checks
all wallet signatures in CKB-VM before reserving the immutable submitted-binary
path, so an incomplete attempt cannot block a later fully signed submission.
The complete exit and valid signed transaction are fsynced before broadcast.
Exact replay uses the same keyless submission command.

Activate the funded State using the saved exit with
`devnet multi-asset-transact --operation activate ... wallet`. Once both funding
and the bound State reach the chosen confirmation depth, each participant runs:

```sh
morph-cli multi-asset-funding-session --session /srv/morph/alice.json confirm \
  --rpc-url "$CKB_RPC" --state-out-point 0xACTIVATION_HASH:0 \
  --min-confirmations 4 --archive-dir /srv/morph/initial-journals \
  --contracts-dir /srv/morph/contracts
morph-cli multi-asset-session --session /srv/morph/alice.json inspect
```

Confirmation seals the initial journal, checks actual canonical funding and
State inclusion, complete live custody and approved code, then atomically
switches the **same path** to a guarded operational session. State 1 remains
reserved for the exact already signed exit; ordinary updates start above it.
Failed confirmation leaves the initial journal unchanged. Retrying after a lost
response must first inspect the existing path; never reinitialize it.

Confirmation requires the complete retained exit and this journal's durably
recorded local creation approval. A reservation without a recorded local
signature is insufficient. The peer's creation receipt need not have been
delivered locally: confirmation obtains the actual canonical funding witness
and verifies both creation signatures, the exact raw-body-derived funding
context and dependency/custody checks before handing off. The operational
lineage retains that complete funding transaction for exact replay. No fresh
peer signature or second authority path is required.

The old `multi-asset-session init` and `bind-root` entry points have been
removed. Recovery packages remain unilateral-exit evidence, not a replacement
for a lost monotonic signer journal. Never clone an active path or restore a
prior snapshot. Register the path with [signer supervision](signer-supervision.md)
after confirmed handoff. Later reorgs use explicit `refresh-chain`; later funding
epochs use `confirm-splice`, retaining the same authority path.

## Acceptance

The checked-in synthetic-asset harness exercises the public constructor,
independent initial voting, wallet-group signing and same-path confirmation:

```sh
morph-cli devnet --devnet-only --rpc-url "$CKB_RPC" multi-asset-smoke \
  --asset-count 8 --shared-funding --store-dir target/shared-root-acceptance --json
```

`--shared-funding` uses the two participants for asset inputs and a distinct
third fee/carrier wallet. Issuance belongs only to this devnet harness. It also
requires missing-wallet VM preflight to fail without occupying the immutable
submitted-transaction path, then successfully submits the complete transaction
through that same store. Public preparation and wallet-sign commands perform
no issuance. Real-node 2/8-asset evidence additionally covers separate signing
processes, changed-body/missing-Morph/undeclared-wallet rejection, activation,
confirmed handoff and unilateral settlement.

The sole native acceptance pipeline adds `--funding-reorg` to its isolated
shared-funding case. This explicitly rolls back the initial funding to its
canonical predecessor, re-exports the retained exit while the peer creation
receipt is withheld, and replays the identical fully wallet-signed binary.
The transaction hash, all witness bytes and both signer journals must remain
unchanged. Activation and canonical same-path handoff then proceed without
another peer vote. Ordinary `--shared-funding` does not truncate the chain;
the explicit reorg flag is only for an isolated development-node rehearsal.
