# ADR 007: asset-bound conditional settlement over the current Vault set

Status: implemented and locally qualified, 2026-11-11, on signed code `bc4be3ff`. See [exact-candidate evidence](../evidence/typed-conditions-bc4be3ff/README.md). Real assets and release remain unapproved.

## Decision

Replace the unpublished CKB-only conditional encoding with one current typed
encoding. Ordinary and conditional settlement share the same State, Vault set,
signing journals, complete-custody checks and terminal-close implementation.
No old descriptor, JSON alias or legacy Batch executor is retained.

The current descriptor carries either ordinary allocation or an explicit
conditional capability: one pinned Batch executable and 1–8 asset-sorted batches.
Each batch binds exactly one complete asset identity (plain CKB or exact UDT
Type hash), both settlement locks, their settled capacities and u128 token
amounts, and 1–8 ordered conditions. Thus simultaneous CKB and different UDT
conditions cannot be combined into a cross-asset balance.

For a CKB batch, pending u128 quantities must fit u64 and consume business CKB;
settled token amounts are zero. For a UDT batch, quantities consume that Type's
u128 token lane; both signed CKB capacities (reserve plus any business CKB) remain fixed and independently cover payout occupancy.
Reserve, carrier and external fees cannot satisfy a pending token quantity.
Host and script use the same checked totals and resolution primitive.

Complete finalisation or explicit cooperative close produces one Batch cell for
each conditional asset, ordinary outputs for all remaining assets, and the
separate full State carrier refund. Typed Batch cells contain the exact Type
and canonical 16-byte amount. Occupied capacity is checked for the Batch and both
possible participant outputs before a funding/recovery package is accepted.

Each Batch is independently spendable with a complete fulfill/refund vector.
It must be transaction input zero and the only input of its lock group; another
Batch cannot reuse its payouts. Fees follow as plain independently funded CKB.
Its 104-byte arguments bind channel, exact funding context, state number and
complete asset-bearing terms. Fulfill validates the full preimage; refund uses
canonical absolute block since. Per-asset batch independence is intentional:
publishing one preimage can authorize other explicitly signed hash-linked
conditions, but it cannot change their Type, quantity, payer or refund deadline.

## Required implementation and evidence

- One authoritative typed terms/capability codec; strict version/length/order,
  u64/u128 overflow, unknown algorithm and duplicate identities rejected.
- Conservation, funding, splice, unilateral finalise and cooperative-close
  construction/verification all consume the same descriptor interpretation.
- Saved recovery selects an exact batch in its authenticated source package;
  public DTOs/SDK/signing review expose asset, base-unit quantity and CKB capacity.
- New/edited signing terms require fresh bounded refund horizons; exact unchanged
  Batches from the current authenticated package can be retained past maturity
  while another asset resolves. Initial/new-context funding has no such exception.
- Tests cover mixed assets and resolutions, u128 amounts, wrong Type/data/lock,
  reserve theft, early refund, missing/duplicate batches, role/context replay,
  complete custody and independent provider-loss exits.
- Rebuild affected ELF identities and fixtures; collect real-node fulfillment
  and refund plus bounded resource evidence. Old W1 records remain historical.
- Fiber integration binds exact asset/hash/amount/expiry semantics. Fiber's own
  deployment is not proof of Morph compatibility, live forwarding or Morph
  mainnet readiness. Real-asset admission and release remain separate decisions.

## Reset policy

This ADR introduced descriptor 6. ADR 008 supersedes its byte encoding with
descriptor 7, counted terms version 5 and resolutions version 3, preserving
the asset/value/admission semantics here. Existing disposable development states must be recreated.
There is no in-place upgrade, compatibility reader or dual protocol family.
