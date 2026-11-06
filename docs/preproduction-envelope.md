# Controlled-devnet experiment admission

Policy revision: 2026-11-06. Effective window: 2026-11-05 through 2026-12-04
(Asia/Shanghai). Current schema: `morph.preproduction_envelope.v3`.

The current implementation is `morph-current-custody`, with one channel
custody implementation and a distinct Factory authority over the same bounded
Vault set. This envelope admits **local controlled-devnet experiments only**.
It does not publish a release or permit production, mainnet or real assets.

| Operating boundary | Status |
| --- | --- |
| Real assets | Prohibited |
| Release/tag publication | Not performed |
| Allowed experiment scope | Local controlled devnet only |

On 2026-11-06 the release owner explicitly removed independent-operator
measurements (#27) and externally supplied evidence records (#44) as
prerequisites for closing #21. Local qualification now requires the exact
candidate's complete CI, actual-node matrix, code/policy identity checks,
request admission and durable lifetime accounting. Those removed prerequisites
are not recorded as successful experiments. Broader operational and mainnet
evidence remains a separate scope in `docs/mainnet-readiness.md`.

The canonical policy is
[`release/factory-preproduction/envelope.json`](../release/factory-preproduction/envelope.json).
Missing or unknown fields and earlier schemas are rejected without aliases.
`qualification.phase` is `B_controlled_devnet_local`;
`release_admitted=false` and `production_allowed=false` are deliberate because
this work does not authorize publication or production. Policy validation
alone is not an exact-candidate qualification receipt.

## Protocol limits versus admitted experiments

| Dimension | Executable protocol | This experiment |
| --- | --- | --- |
| Factory members | 2–16, full consent N-of-N | Exactly 2 |
| Factory Vaults | Up to 8 | One plain-CKB Vault |
| Children per transaction | Up to 4 | At most 1 |
| Changed metadata rights | Up to 10 | Declared 1, 4 and 10-right cases |
| Physical claims | Up to 9 | Plain CKB within feasible payout/floor geometry |
| Compact proofs | Depth 256, at most 64 carried siblings per proof | Also bounded by aggregate transaction/proof budgets |
| Bilateral Vaults | Up to 8 | Up to 8; CKB and explicitly admitted devnet-issued token instances |
| Concurrent active Factories | No consensus cumulative counter | At most 4 in the shared operator ledger |
| Lifetime child reservations per Factory | No consensus cumulative counter | At most 10, across every retained batch and terminal parent closure |
| Factory capacity | Geometry-dependent | At most 1,000,000,000,000 shannons |
| Bilateral/child capacity | Geometry-dependent | At most 400,000,000,000 shannons |
| Combined pilot capacity | Operator scope | At most 4,000,000,000,000 shannons |
| Token units per Type per bilateral channel | Per-Type conservation | At most 1,000,000,000,000 |
| Sponsored transaction fee | Script policy plus operator budget | At most 200,000,000 shannons |

The former 1,000 CKB channel declaration could not admit its own eight-Vault
fixture: the measured State carrier is 464 CKB and each token Vault carries
284 CKB reserve plus 100 CKB business value, giving 3,536 CKB for eight Vaults.
This local no-value revision uses a 4,000 CKB channel ceiling, preserving the
10,000 CKB Factory and 40,000 CKB total limits. The fresh native run must qualify
that exact geometry; this is not a real-asset value-limit increase.

The joint 16-member/four-child/eight-asset Factory profile remains outside this
experiment. Its VM fixture measurements do not constitute native admission.
The 1/4/10-right cases and the separate eight-Vault bilateral lifecycle remain
separately measured shapes. Qualifying one does not qualify their combination.

## Exact-request enforcement

Use the keyless `devnet factory admission-config` helper to create an immutable
configuration with explicit `--no-real-assets`, an absolute policy path, a
stable absolute `--ledger` path, the canonical genesis identity, exact admitted
asset Type hashes and the verified policy/eight-ELF identity. Run its `--help`
for the current flags. Every public value-creating prepare/sign/wallet/submit
path requires the explicit admission configuration. Existing offline exits and
keyless finalisation remain recovery authority rather than new admission.

Factory preparation checks the exact source/target custody, complete rights,
participant/child/Vault counts, quantity-zero token identities, occupied
outputs, actual fee and independently feasible ReserveClaim payouts. It then
persists a reservation before any participant or wallet signature is released.
Signers and submission must find that exact request in the same ledger.
Full-consent replacement still requires complete rights snapshots; child
initial exits and public possession receipts are still required before a parent
vote. An offline child receipt alone grants no parent consumption authority.

Bilateral funding/splice admission checks the exact current custody and the
shared pilot budget. A token's name is insufficient: its exact Type hash must
be explicitly admitted and its actual Type Script must use the manifest-pinned
devnet issuer. Altered args require another admission. Existing native code,
live-dependency, authentic State/Vault and VM checks remain mandatory.

## Durable lifecycle accounting

One stable OS-locked, private, fsynced ledger is authoritative for one pilot.
It retains root history, exact request reservations, canonical observations,
closure evidence and bilateral capacity reservations. Deleting the ledger
while its immutable identity marker survives fails closed. A new path is not
a legitimate migration of existing history; do not clone or roll back the
operator ledger. Like signer journals, it relies on operator storage freshness,
not a cryptographic proof that an old whole-disk snapshot is current.

The same exact request is idempotent. A changed raw transaction or request
is a new reservation, including an alternative that may later lose the UTXO
race. Lifetime child reservations are conservative: they are never refunded by
closure, cancellation or reorg. This can consume policy headroom without an
actual child being created; it cannot exceed the cap by replaying an approval.

Only verified canonical parent closure releases its active-Factory slot.
Reconciliation before a new reservation reopens that slot if closure becomes
orphaned. Parent retirement does not free obligations for independent children.
Child capacity stays conservatively charged across parent closure; per-channel
bilateral peaks likewise retain headroom across contexts. All participating
objects share one lock and combined capacity check, avoiding separate-ledger
races. Independent pilots on separate ledger paths are an operator governance
choice, not a consensus-enforced global network cap.

## An allocation must permit an executable exit

Backing alone is insufficient. Every positive ReserveClaim must fund a standard
wallet payout, and the sum of claims must leave the Factory's collective
occupied floor. Child carriers and actual fees are external funding. No member
may spend another member's claim, the last collective carrier or an untouched
asset lane. The standard wallet payout floor is 61 CKB in the native shape;
the retained-child fixture now allocates 61/99 CKB rather than an unpayable
30/130 CKB split, preserving the same 160 CKB total and 300 CKB retained floor.

Reduced proof refresh requires the saved complete initial rights snapshot.
The chain root alone cannot recover lost rights. Full-consent replacement
requires delivery of a complete new snapshot before signing. These obligations
remain separate from the policy ledger and private child recovery evidence.

## Exact local qualification and publication boundary

`make qualify-local-candidate` runs full CI, a fresh five-case native matrix,
local deterministic contract packaging, allowlisted evidence export and the
candidate verifier. It requires a clean committed source, rejects changed
source/artifacts and binds source, Cargo lock, toolchain, envelope, eight ELF
hashes, local bundle, CI receipt, native genesis and report checksums. Failed,
skipped, stale or mismatched evidence cannot produce a successful receipt.
See [the local qualification runbook](runbooks/local-candidate-qualification.md).

Only a local no-value candidate is qualified. No release/tag/main merge or
production approval is performed. Hub chain actions remain disabled. Public
network measurements, independent review and operator diversity are not
fabricated; a later deployment decision must state its own scope and evidence.
The policy still expires on 2026-12-04 and fails closed after expiry.
