# Conditional Batch Settlement

## Chosen architecture

A v3 bilateral state commits one fixed 828-byte descriptor. It contains two
settlement locks, their unconditional capacities, and zero to eight sorted
conditional transfers. Every transfer binds its own ID, payer, hash algorithm,
payment hash, amount, and canonical absolute-block refund height.

The cooperative path signs the next empty v3 descriptor. Known preimages pay
the receiver and unrevealed conditions are mutually cancelled to the payer.
This needs no on-chain timeout.

The dispute path is deliberately two-stage:

1. State/Vault finalisation moves the entire CKB Vault into exactly one
   `morph-batch-lock` cell. Vault args pin the Batch Lock code hash and hash
   type, while Batch args bind channel ID, state number, and descriptor hash.
2. The Batch Cell is consumed with one fixed resolution witness. Each transfer
   either supplies the exact preimage or uses an input `since` at/after its
   absolute refund height. The transaction must create exactly one plain output
   for each participant with the script-computed capacity.

Keeping the whole Vault together avoids the occupied-capacity and fee leakage
problems of creating one cell per conditional transfer. Eight leaves bound CKB
VM work, witness size, and application retry complexity.

## Fixed safety invariants

- Batch IDs derive from channel ID, funding context, armed state number, and
  application-context commitment.
- Transfer IDs are strictly sorted and unique; payment hashes are unique.
- Participant settlement locks are non-zero, sorted, and distinct.
- No transfer amount is zero, and all additions are checked for overflow.
- Only exact 32-byte preimages are admitted.
- Refund heights use absolute block-number `since`; relative/timestamp/epoch
  encodings fail closed.
- Descriptor total equals Vault/Batch input capacity.
- Batch resolution creates exactly two plain participant outputs whose sum is
  the complete input value.
- Conditional batches are CKB-only in this release. Typed Vault inputs fail.

Current scope is CKB-only with at most eight leaves. Remaining multi-asset
work is tracked in [the roadmap](roadmap.md); release gates are tracked in
[mainnet readiness](mainnet-readiness.md).
