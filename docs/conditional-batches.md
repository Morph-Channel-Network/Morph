# Conditional Batch Settlement

Scope: the implemented current Vault-set capability. Repository-wide retirement
and integration status is tracked in [the migration ledger](unified-protocol-migration.md).

## One current custody model

Conditional CKB settlement is an explicit capability of the current
318-byte State and bounded Vault-set model. The State commits descriptor
version 5. Its capability tag is `0` for ordinary allocations or `1` for the
bounded CKB conditional trailer. The Vault-set parser rejects descriptor 4 and
346-byte single-Vault Headers after an incompatible development reset.

The descriptor retains canonical per-asset payouts and a separate carrier
refund. The conditional trailer pins the Batch executor's code hash/hash type
and its fixed 828-byte terms. Those terms contain two settlement locks,
unconditional capacities, and one to eight sorted transfers. Each transfer
binds an ID, payer, hash algorithm, payment hash, amount and canonical absolute
block refund height. All trailer bytes are part of the signed State commitment.

The Batch terms are a capability's own encoding. Reusing their sole executor
and preimage/refund verifier does not retain a second State/Vault lifecycle.

## Accounting and execution

A pending transfer uses only CKB business value. Signed payout reserves remain
intact, the State carrier refunds separately, and every xUDT quantity conserves
within its own Type. The shared funding helper derives the CKB Vault total from
already settled allocations plus the pending amounts; root and splice builders
use this same interpretation.

When both participants agree, they can co-sign the next allocation that
fulfills or cancels conditions. Existing signed pending terms cannot be erased
by one participant or by a local cancellation after signature reservation.

Disputed execution has two stages:

1. After the challenge delay, finalisation consumes the complete authentic
   State and exact Vault set atomically. The CKB lane becomes one Batch Cell;
   other assets pay their canonical ordinary outputs, and the full State
   carrier refunds independently. The sole 104-byte Batch args bind the channel
   ID, canonical exact funding-context ID, state number and complete Batch-terms
   commitment. Retired 72-byte args and zero contexts are rejected.
2. The Batch Cell is consumed with one fixed complete resolution witness.
   Each transfer either supplies the exact 32-byte preimage or refunds to its
   payer with a mature absolute-block `since`. Two plain participant outputs
   receive the complete script-computed value; no partial claim remains.

Keeping pending CKB in one bounded executor avoids one output per transfer.
Atomic Vault-set finalisation still depends on the admitted asset scripts;
this capability does not create a per-asset escape from a refusing Type script.

## Recovery and signing review

`morph.conditional_batch_package.v1` contains the complete signed current
`source_package`, ordered resolutions, canonical decimal `input_since`, the
resolution witness and decimal resolved capacities. It does not accept detached
channel/state metadata as authority. Unknown fields, old schemas, incomplete
resolutions, altered preimages and noncanonical refund clocks fail closed.

CLI, SDK and funding reviews expose the capability, pending amounts, payer and
payee, hash algorithm/hash, refund block and signed Batch identity. Public JSON
amounts remain decimal strings. The SDK can construct and inspect a resolution
with `createConditionalBatchPackage` and `inspectConditionalBatchPackage`;
inspection reserves no signer vote and proves no live chain inclusion.
Funding and splice reviews display the Batch identity of the exact future
bound Settling/1 exit. An unbound Active/0 creation preflight checks occupancy;
its hypothetical Batch identity does not stand in for the future exit.

Morph Hub retains a conditional package only against the exact registered
signed source recovery. New admission cannot use an older retained state for
that funding context. Historical packages can remain after newer states arrive,
but restoration must retain their original signed source too. No mock-channel
balance record substitutes for that evidence.

## Boundaries and evidence

- Transfer IDs are strictly sorted; payment hashes are unique.
- Participant settlement locks are nonzero, sorted and distinct.
- Amounts are positive and additions are checked.
- Relative, timestamp and epoch encodings cannot authorise refunds.
- Pending value cannot borrow reserve, carrier, another asset or fee change.
- The Batch identifier is signed application data. The lock's channel/state/
  terms commitment supplies execution binding; an identifier alone is not
  authority for a Batch Cell.
- Native publication qualifies the future Batch executor against the selected
  approved artifact and live dependencies before accepting its use.

VM tests cover current CKB-plus-token finalisation, independent carrier refund,
fulfillment, refund maturity, destination substitution and incomplete source
sets. Cross-language fixtures cover exact signed bytes, public reviews and
complete resolutions. These tests do not enlarge the release envelope; actual
Batch OutPoints, canonical publication and deployment-specific script budgets
still require native chain qualification.
