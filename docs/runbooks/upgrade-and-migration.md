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

Morph supports only the current cells, packages, witnesses and JSON shape.
Historical formats and in-place migrations are rejected. A contract or wire
change invalidates prior no-value development state. Stop the devnet, discard
that state, deploy the current manifest, and create new channel/Factory IDs and watch
cursors. Do not add alternate parsers to preserve an unpublished shape. Hub state files
require every current collection, watch configs require explicit operator and
scan origin, and Payment Gateway requests require an explicit HTTP operation. The current bilateral State uses 318 bytes and descriptor 5; Factory State uses 306 bytes. The Batch identity is 104 bytes and includes the exact funding context. Single-asset custody is a one-entry current manifest; old single-Vault State, Factory and splice layouts are rejected.

Morph Payment Gateway uses only the `morph-payment-gateway` crate/binary and
`MORPH_PAYMENT_GATEWAY_*` environment namespace. The TypeScript package is
`@morph-network/payment-gateway-sdk`, and authorization uses
`/v1/payment-gateway/authorize`. Replace development launch commands and key-file
variable names together, then create a fresh `morph-payment-gateway.db` and
fresh no-value payment/receipt fixtures. The gateway store identity, key
derivation label, and asset commitment domain use the current product name;
previous stores and asset-bound receipts are not imported or accepted through
alternate parsers. Historical audit and captured evidence files retain the names
used when they were produced.

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
