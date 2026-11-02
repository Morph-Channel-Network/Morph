# Initial Multi-Asset Funding

Each participant keeps one authoritative session path from the initial funding
ceremony through later splice epochs. Initial signing runs offline with the
default CLI build. Chain submission and confirmed handoff require
`cargo build -p morph-cli --features devnet`. No ceremony command accepts both
participant secrets.

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

A general public root transaction builder remains open. The acceptance harness
constructs this format; external wallet builders can supply it. This ceremony
checks proposed outputs and authority but does not establish that inputs are
currently live. Submission separately checks the RPC genesis against the signed chain ID,
canonical inputs, deployed code,
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

Choose an explicit wallet role for first submission or `presigned` for a fully
wallet-signed binary or exact replay:

```sh
morph-cli devnet --devnet-only --rpc-url "$CKB_RPC" multi-asset-funding-submit \
  --transaction exported-funding.tx --package initial-exit.json \
  --contracts-dir /srv/morph/contracts --store-dir /srv/morph/recovery \
  --max-fee 100000000 --mine-blocks 4 wallet
```

Wallet mode uses `MORPH_DEVNET_PRIVATE_KEY` for a single funding owner. All inputs
must belong to that wallet; non-channel change must return to it and cannot
carry unregistered assets or unexpected data. Multi-owner wallets must provide
all their own signatures and use `presigned`. Exact replay requires no keys.
The signed transaction and full exit are durably stored before broadcast.

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
