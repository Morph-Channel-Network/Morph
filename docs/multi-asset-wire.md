# Multi-Asset Candidate Wire Profile

Status: bilateral implementation under development, 2026-11-02. These are the
actual candidate encodings in `morph-script-common::multi_asset`, not a claim
that the complete production extension or its release review is finished.
Legacy profiles keep their original encodings and reject these headers.

## State and Vault Authority

State layout 2 is 414 bytes: the 346-byte State prefix followed by a 32-byte
Vault content-set root, a 32-byte exact-OutPoint-set root, a u16 Vault count,
and two reserved zero bytes. The prefix uses protocol version 1, signature
scheme 1, bilateral mode 1, descriptor version 4, and layout version 2. Its
legacy single-Vault materialisation and OutPoint fields must be zero;
`vault_set_commitment` must equal the appended content-set root. Active states
may be unbound; settling states must be bound. The signing domain is
`CKB_MORPH_MULTI_ASSET_STATE_V1` followed by all 414 bytes.

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
two-participant signed settling evidence. The candidate does not admit active
State retirement through legacy splice witnesses.

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
| Settlement descriptor | u16 version 4, u8 count, u8 reserved; two sorted nonzero payout lock hashes (64), carrier-refund lock hash (32); N entries of asset ID (33) and two allocations (64). Length `100 + N*97`. |
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
the candidate never deducts activation or finalisation fees from carrier value.

Signed recovery evidence must be retained before funding broadcast. The raw
funding transaction hash excludes witnesses, so its exact future Vault
OutPoints can be used in a pre-signed settling state without embedding the
transaction's own hash in its output State data.

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

Hub provides authenticated `POST /api/multi-asset-packages` and
`GET /api/multi-asset-packages/{package_id}`. Import verifies both channel
participants, funding context, current state number, signatures, all roots,
and capacity. Recovery is retained across restart and old funding contexts;
conflicting signed states at the same context/number are rejected. The normal
state view contains at most 32 cached summaries, with a total package count;
full evidence is retrieved separately. The store has an explicit 4096-package
limit and never silently evicts recovery data. Packages count as operational
records for the bootstrap-only restore restriction.

The TypeScript SDK's `inspectMultiAssetPackage` performs independent binary,
signature, commitment, per-asset, and capacity validation. Hub's State panel
imports and retrieves these packages. Neither local package validation nor a
Hub record substitutes for checking chain liveness and approved contract code.

Initial CKB-VM measurements for eight typed Vaults: funding 6,810 transaction
bytes and about 7.04 million cycles; finalisation 7,003 bytes and about
1.95 million cycles. Measurements include the complete witness and canonical
carrier refund. Live-node fee, confirmation, restart, and reorg evidence must
be recorded separately before final release budgets are approved.

The isolated live-node acceptance on CKB 0.210.0 committed funding, activation,
publication, supersede, and finalisation for both two and eight xUDT types.
The eight-asset run measured 7,183 bytes / 8,970,458 estimated cycles for funding
and 7,730 bytes / 3,622,763 estimated cycles for finalisation, including real
secp fee inputs and distinct fee change. Reports and pre-broadcast recovery
packages are under `target/multi-asset-devnet/`. Reproduce against an isolated
node with deployed current binaries:

```sh
cargo run -p morph-cli --features devnet -- devnet --devnet-only \
  multi-asset-smoke --asset-count 8 --json
```

Provide the documented funding and participant keys through the hidden-value
environment options. The harness uses the devnet-only issuer for synthetic
assets; it does not admit that issuer for production assets.
