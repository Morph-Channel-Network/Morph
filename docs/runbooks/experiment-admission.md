# Controlled-devnet experiment admission

This guard admits local, no-value experiments under the checked-in envelope.
It grants no production, mainnet, real-asset or publication approval. The
envelope/manifest identity pins policy bytes and eight reviewed ELF identities;
the separate local-candidate verifier binds source, CI, native reports and the
packaged bundle.

## Establish one pilot authority

Create one configuration and one stable ledger for the complete pilot. Every
Factory member, external funding wallet and bilateral funding/splice operation
must use that same configuration. An alternative configuration or ledger is
not a way to restart the pilot's lifetime allowance.

```sh
cargo run -p morph-cli --features devnet -- devnet --devnet-only factory admission-config \
  --no-real-assets \
  --ledger /absolute/private/pilot/admission-ledger.json \
  --output /absolute/private/pilot/admission-config.json
```

Use the CLI's RPC selection for the controlled development node. Add an
explicit `--admitted-asset-type 0x…` for each bilateral devnet token Type
identity. The empty list admits no token identities. A matching contract name,
zero quantity or modified Type args never supplies asset admission. Factory
custody and Factory rights remain plain CKB under this experiment, including
zero-quantity rights.

The configuration records a required canonical `rpc_url` without embedded
credentials, the exact canonical genesis, envelope/artifact identity, absolute
ledger path and explicit no-real-assets declaration. Native operations must use
that reviewed endpoint. Initial bilateral and splice signatures refresh that
endpoint immediately before participant crypto, even for ordinary custody. The
CLI writes it immutably. Rebuilding scripts or changing the envelope requires
reviewed matching evidence and a deliberate experiment reset under the upgrade
runbook; an active ledger cannot silently adopt another identity.

## Prepare before signing

Pass `--admission-config /absolute/private/pilot/admission-config.json` to
Factory prepare, root-prepare, wallet signing, submission, activation and
Factory signer-session initialization. Subsequent session operations retain
the canonical configuration path in the existing authority file. The native
prepare path verifies the live exact source and independently funded body
before recording the exact request reservation. A saved request or signing
journal cannot import a request that has no reservation. Before each new
value-creating participant signature, the approved RPC context is refreshed,
closure/reorg observations and the shared pilot budget are reconciled, and
conditional refund horizons are checked again. An earlier prepare result is
not fresh signing authority after a chain change. Saved recovery export and
keyless finalisation do not require these admission files.

The guard enforces two Factory members, one plain-CKB Vault, one child per
transaction, the declared 1/4/10-right metadata shapes, occupied outputs,
independently payable standard-wallet ReserveClaims and a retained custody
floor. Existing exact-body, canonical dependency, conservation, independent
carrier/fee and VM checks still apply. Public native entry points reject
unknown wallet/payout scripts and non-plain external fee/funding cells.

Complete initial and replacement rights snapshots remain in the signer
journals and admission history. Both child parties must persist their complete
private exits before issuing public possession receipts. Those private signing
APIs do not authorize parent custody consumption; the exact parent request
still needs admission and its appropriate Factory signatures. A possession
receipt does not establish continuing backup availability.

The native allocation rehearsal now keeps every positive ReserveClaim payable.
Its earlier 3-billion-shannon Alice remainder was below a standard wallet's
6.1-billion-shannon occupied payout. The reduced escape now withdraws 6.9 billion
instead of 10 billion, retaining that 3.1-billion difference throughout the
later operations. The explicit allocation is:

| After operation | Alice / Bob claims (shannons) | Factory reserve / business CKB (shannons) |
| --- | --- | --- |
| Root | 13,000,000,000 / 13,000,000,000 | 30,000,000,000 / 10,000,000,000 |
| Reduced escape | 6,100,000,000 / 13,000,000,000 | 23,900,000,000 / 9,200,000,000 |
| Deposit | 46,100,000,000 / 13,000,000,000 | 63,900,000,000 / 9,200,000,000 |
| Reduced child | 26,100,000,000 / 13,000,000,000 | 45,900,000,000 / 7,200,000,000 |
| Retained full materialisation | 6,100,000,000 / 13,000,000,000 | 27,900,000,000 / 5,200,000,000 |
| Terminal materialisation | No retained rights | Entire 33,100,000,000 moves to the final child |

The escape payout is 6,100,000,000 reserve plus 800,000,000 business CKB.
The final child's two allocations each contain 13,950,000,000 reserve and
2,600,000,000 business CKB. Child carriers and transaction fees still come from
independent funding.

## Lifetime accounting and recovery

The ledger uses a stable OS-locked sidecar, private files and fsynced atomic
snapshots. Do not unlink its `.lock` file, clone an active authority, restore an
older snapshot or delete its identity marker. A missing ledger with an existing
marker fails closed. Retain the complete ledger alongside monotonic signer
journals and private exits. Chain roots cannot reconstruct lost rights or
lifetime admission reservations.

Each exact request reserves its children once, before any parent signature or
submission. Repeated preparation, multiple independent signers, wallet signing
and exact signed replay share that reservation. Cancellation, alternative
spends, rejected signing, parent closure and chain reorgs never refund lifetime
children. Alternatives therefore consume conservative headroom even when only
one can become canonical. Retained batches accumulate in the same Factory
history; terminal materialisation preserves all earlier children.

Canonical terminal parent consumption frees its active-Factory slot. Before
new native admissions, closure observations are checked against the canonical
chain. A missing, orphaned or unverifiable closure reoccupies that slot and its
parent capacity. Child exposure remains charged after parent closure. Bilateral
channel capacity uses the maximum reserved capacity across funding contexts
and splices and is conservatively never refunded. All three share one atomic
pilot budget. Parent/child overlap and alternative spends may reserve more
than current live capacity; reduce the experiment rather than resetting its
history to recover headroom.

The native Factory report exposes sanitized `operator_checks.admission`
counts, identity and idempotency facts. Child cases retain before/after counts.
With the isolated `--reorg` rehearsal, terminal closure is orphaned and exactly
replayed before the child proceeds; the report records the reopened active
slot, unchanged lifetime children and subsequent canonical closure. These are
local engineering measurements, not independent-operator attestations.
