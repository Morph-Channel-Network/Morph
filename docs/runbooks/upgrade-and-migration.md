# Deployment Replacement and Rollback

CKB cells commit script hashes, so a contract upgrade is a new deployment and
fresh channel state, not an in-place binary replacement.

## Prepare a Replacement Deployment

1. Freeze new Factory creation and concurrent splices.
2. Build from a clean candidate with Rust 1.95.0 and `Cargo.lock`.
3. Run `make ci`, `make devnet-stateful-e2e`, and independent review for every
   wire-format or contract change.
4. Generate a fresh candidate profile and manifest from the current source.
5. Verify domain strings, versions, fixed lengths, witness-kind tables,
   descriptor versions, and deployed script hashes against the candidate.
6. Rehearse deployment replacement and rollback using no-value devnet cells.

Any change to the supported signer-count bounds, proof depth, right count,
witness layout, envelope format, or `*_LEN` rule is a new protocol profile. The
dynamic-N manifest covers only 2–16 signers and must not be relabelled as
supporting a wider or threshold-based profile.

## Pre-release Reset Policy

The current participant backend snapshot requires `close`, including explicit
null when no cooperative close is prepared. Missing close history is rejected,
not migrated into fresh signing authority. The Core close state machine is
implemented; disk/key-service and operational close integration remain pending.
Do not edit an old active journal to insert null or remove a close reservation.
Use saved unilateral recovery for existing disposable custody before replacing
development state; a consistent old snapshot cannot establish fresh authority.

Morph supports only the current cells, packages, witnesses and JSON shape.
Historical formats and in-place migrations are rejected. A contract or wire
change invalidates prior no-value development state. Stop the devnet, discard
that state, deploy the current manifest, and create new channel/Factory IDs and watch
cursors. Do not add alternate parsers to preserve an unpublished shape. Hub JSON projections
require every current collection, watch configs require explicit operator and
scan origin, and Payment Gateway requests require an explicit HTTP operation. The current bilateral State uses 318 bytes and descriptor 6; Factory State uses 306 bytes. The Batch identity is 104 bytes and includes the exact funding context. Single-asset custody is a one-entry current manifest; old single-Vault State, Factory and splice layouts are rejected.

Morph Payment Gateway uses only the `morph-payment-gateway` crate/binary and
`MORPH_PAYMENT_GATEWAY_*` environment namespace. Built-in clients and tooling are
Rust, and authorization uses
`/v1/payment-gateway/authorize`. Replace development launch commands and key-file
variable names together, then create a fresh `morph-payment-gateway.db` and
fresh no-value payment/receipt fixtures. The gateway store identity, key
derivation label, and asset commitment domain use the current product name;
previous stores and asset-bound receipts are not imported or accepted through
alternate parsers. Historical audit and captured evidence files retain the names
used when they were produced.

Hub, Gateway and watch now use the sole current SQLite runtime schema. Old JSON and
encrypted snapshot files and JSON watch cursors are rejected; choose a new private development path. Watch config removes inline webhook URLs; configure the independent event consumer with a protected HMAC key file and explicit watch-policy egress permission. Keep publication attempt logs as immutable evidence; the local alert JSONL is only a rebuildable display.
Public Hub JSON exports are not raw database snapshots. See
[runtime-store.md](runtime-store.md) for initialization, validation and recovery.
This runtime reset does not reset signer journals, reservations or lineage.

Gateway public durations/counters now use decimal strings; Core intent/receipt
transport uses canonical hex IDs/signatures and decimal amounts. Its encrypted
runtime records embed those current public objects. Reset disposable Gateway
development data and recreate challenges/offers/receipts when adopting this
shape; do not add an old numeric/array parser. This does not change Core signing
encodings or authorize resetting live signer journals. Public Hub administrative
archives are separately typed and never import a private runtime snapshot.

## Rollback

Before any value enters a candidate deployment, rollback means abandoning its
no-value cells and returning to the last reviewed source revision. There is no
in-place downgrade path.

Never point an existing cell at an older code hash, reuse splice packages after
a funding-context change, or edit a candidate manifest to match an unreviewed
binary.

## Post-deployment Verification

Verify deployed hashes, open/update/reduced update/exit/splice paths, negative
attacks, watch cursor canonicality, reorg rescan, package restoration, and
emergency stop. The watchtower must scan the recreated channels from creation
through the current canonical tip.


Gateway event production now requires projection schema 3. Schema 2 is rejected
on open: there is no generic-event fallback, backfill or in-place state migration.
Use fresh unpublished test state after preserving evidence and resolving any
uncertain external operation. Never restore an older outgoing ledger to regain
submission permission. See [event delivery](event-delivery.md).


Event consumer metadata uses only `morph.event.consumer.v2`. It rejects the former
v1 metadata; no alternate reader or in-place migration is provided. Retain evidence
when replacing disposable development subscriptions, and account for replay from a
new empty source cursor. Normal current-generation capacity recovery must use
`event-delivery archive --next-store ...`, retaining the old database and all
unresolved-job budgets; see [event-delivery.md](event-delivery.md).
