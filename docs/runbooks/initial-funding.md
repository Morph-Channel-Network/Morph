# Initial Multi-Asset Funding

Each participant keeps one authoritative session path from the initial funding
ceremony through later splice epochs. Initial signing runs offline with the
default CLI build. Chain submission and confirmed handoff require
`cargo build -p morph-cli --features devnet`. No ceremony command accepts both
participant secrets.

## Construct exact root funding

`devnet multi-asset-funding-prepare` builds a draft from explicit
`morph.multi_asset_root_terms.v1` terms. It takes no keys and performs no
issuance, automatic input selection, signing or broadcast. The terms contain:

| Field | Meaning |
| --- | --- |
| `participants` | Two distinct compressed keys in raw key order. |
| `participant_locks_hex` | Two actual payout Scripts, in the descriptor's sorted lock-hash order. This ordering is independent of public-key order. |
| `carrier_refund_lock_hex` | Actual Script receiving the exact State carrier on exit. |
| `descriptor_hex` | Canonical descriptor-4 initial allocations; Vault totals are derived from them. |
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

```sh
morph-cli devnet --devnet-only --rpc-url "$CKB_RPC" multi-asset-funding-prepare \
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

The offline ceremony checks proposed outputs and authority; preparation and
submission separately establish live inputs and canonical chain evidence.
Submission checks the RPC genesis against the signed chain ID, deployed code,
occupied capacity, CKB fees and independent conservation of every registered
Type before VM preflight and network writes.

Each signer independently chooses approved local `data1` artifacts named
`morph-state-type`, `morph-state-lock`, and `morph-vault-lock`. Their hashes must
match the proposal before initialization and each signing operation; the
absolute artifact path is persisted. Review the chain ID, channel, participants, funding
hash, payout-lock hashes, carrier and every allocation in `inspect` output.

```sh
morph-cli multi-asset-funding-session --session /srv/morph/alice.json init \
  --draft root-draft.json --local-pubkey "$LOCAL_PUBKEY" \
  --contracts-dir /srv/morph/contracts
morph-cli multi-asset-funding-session --session /srv/morph/alice.json inspect
morph-cli multi-asset-funding-session --session /srv/morph/alice.json sign \
  --target exit > alice-exit-signature.json
```

`MORPH_CHANNEL_PRIVATE_KEY` supplies only this participant's secret, hidden in
help output. Exchange exit receipts with the peer and import the peer's receipt:

```sh
morph-cli multi-asset-funding-session --session /srv/morph/alice.json add-signature \
  --target exit --signature bob-exit-signature.json
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

## Submit and confirm the same path

After the two participant roles are complete, each funding wallet signs only
its own group. It supplies its own `MORPH_DEVNET_PRIVATE_KEY`; no participant
secret or other wallet's secret is needed. Pass each returned transaction to
the next wallet, retaining the same raw body:

```sh
morph-cli devnet --devnet-only --rpc-url "$CKB_RPC" multi-asset-funding-wallet-sign \
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
