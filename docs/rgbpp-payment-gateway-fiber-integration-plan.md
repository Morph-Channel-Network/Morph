# Morph Payment Gateway × RGB++ × Fiber Integration Plan

Status: implementation plan and release gate. Passing unit tests does not imply
mainnet readiness.

Reference: [Fiber issue #1255 — AI Agent Payment Integration Design for Fiber Network](https://github.com/nervosnetwork/fiber/issues/1255)

## 1. Architectural Decision

Morph retains protocol and liquidity sovereignty:

- `FactoryStateCell + FactoryVaultCell` owns the shared pool, virtual child
  rights, non-interference, local/reduced exits, splice, and liquidity reuse.
- Morph's bilateral `StateCell + VaultCell` is the `ChannelBackend` that owns
  CKB-enforceable signed state.
- Fiber is a replaceable provider for peer communication, gossip, route
  finding, MPP, invoices, and multi-hop payment sessions.
- Morph Payment Gateway is an application-layer payment and access gateway
  for apps, services, and AI agents. It provides x402, Biscuit credentials,
  idempotency, terminal receipts, and fair exchange.
- Batch Cell may later aggregate pending conditional settlements. It is not a
  Factory and cannot replace Factory rights, shared reserve, or local exit.

The integration path is:

```text
Factory right
  -> reserved right with proof and expiry
  -> committed child State/Vault materialisation
  -> exact Vault OutPoint activation
  -> deployment/provenance/confirmation verification
  -> provider-neutral Morph edge descriptor
  -> explicit Fiber external-edge hook
  -> Fiber routing/MPP/invoice transport
```

Morph evidence is authoritative at every arrow. Fiber may mirror or route an
edge; it may not manufacture, mutate, settle, or delete the underlying Morph
right/channel.

## 2. Why Morph Does Not Build Its Own Multi-hop Network Now

Routing, onion transport, gossip, MPP, peer recovery, and network operations
are a separate product. Reimplementing them before proving Morph's unique
state/liquidity model would dilute security work and create a small isolated
network.

Morph therefore implements a provider-neutral edge/payment boundary and uses
Fiber first. The boundary remains replaceable and contains no Fiber type in
`morph-core` or any CKB contract.

This decision changes only if Fiber cannot or will not support an explicit
external enforcement hook and carrying a small isolated adapter patch becomes
more expensive than a routing provider of our own. Even then, Morph's current
Factory/Channel wire model remains unchanged.

## 3. Issue #1255 Equivalent Capability Owned by Morph

| Capability | Morph implementation | Fiber dependency |
| --- | --- | --- |
| x402 exact challenge | `PAYMENT-REQUIRED`, canonical requirement ID | invoice creation |
| one-shot x402 access | `PAYMENT-SIGNATURE` -> verify/settle -> upstream | payment/invoice status |
| terminal response | `PAYMENT-RESPONSE` with signed Morph receipt | opaque provider evidence |
| reusable credential | payment-bound Biscuit | none |
| delegation | Biscuit attenuation/policy | none |
| fair exchange | SHA-256 preimage as AES-256-GCM key, AAD/result hash | paid hold/standard invoice status |
| payment index | encrypted atomic Morph store | provider reconciliation input |
| Rust SDK | Morph-owned API, payer signing, receipt types, and authenticated native AES-GCM decryption | none |
| RGB++ identity | CKB genesis + xUDT Type Script hash + Bitcoin network + binding code hash | UDT invoice transport |
| RGB++ provenance | allowlisted binding/proof-program hashes + proof Cell/outpoint + Bitcoin depth | operator admits only verifier-produced commitments; live watcher pending |

The gateway does not claim that an ordinary UDT invoice is an RGB++ proof. An
RGB++ payment requirement must also carry a verified binding-proof commitment.

## 4. Canonical Payment Gateway Protocol

### Payment requirement

Every requirement commits:

- `scheme=exact`, `network=morph-ckb`, and an explicit payment rail;
- CKB genesis identity;
- CKB or full RGB++ asset identity;
- exact Type Script JSON whose computed hash matches the committed hash;
- raw base-unit `u128` amount;
- challenge-bound payer, payee, invoice, payment hash, SHA-256 algorithm;
- exact HTTP resource (including query when present) and method;
- random nonce, expiry, and optional verified RGB++ proof commitment.

The client supplies its Morph payer ID when it requests a challenge, and that
identity is committed into the requirement before the invoice can be paid.
The subsequent `PaymentPayload` carries the corresponding compressed
secp256k1 public key and a low-S signature over the exact requirement, payment
hash, derived payer ID, and optional preimage. The payer ID is
`blake2b256(pubkey)`. Pre-committing the payer is necessary with current Fiber:
`get_invoice` exposes paid status but not the final-hop custom records, while
`get_payment` does not expose the learned preimage. A signature introduced only
after an invoice became public would therefore prove key ownership, not that
the signer was the intended claimant. Challenge binding prevents first-claim
credential theft without making Fiber a trust root. Outgoing `/v1/pay` remains
disabled unless that payer ID and a deployment-level maximum routing fee are
both configured; caller-provided fee and timeout values may only tighten the
deployment caps.

### Terminal receipt

The Morph terminal receipt is secp256k1-signed and binds:

- canonical Morph payment-intent ID;
- terminal status (`settled`, `cancelled`, `expired`, or `failed`);
- provider ID and provider settlement ID;
- opaque provider commitment;
- optional Morph channel/state/descriptor evidence;
- optional CKB transaction/block anchor;
- optional RGB++ proof commitment;
- finalisation time and receipt signer identity.

The response also carries the full canonical `PaymentIntent`, so an independent
verifier can recompute the intent ID and check the receipt against a pinned
Payment Gateway receipt key. Merely accepting the self-contained signer public
key is not an identity check.

An RPC success boolean is never a terminal receipt. A Fiber-routed payment is
labelled `fiber-json-rpc`; a Morph-native channel payment must include the exact
Morph state/funding/descriptor evidence.

### Replay and restart rules

- requirement ID, nonce, payment hash, and idempotency key are distinct fields;
- settle is durable and idempotent;
- the first committed terminal receipt wins;
- retry with a different payer or requirement body is rejected;
- a concurrent settle that loses the durable first-writer race rechecks the
  winning receipt's payer before releasing a credential or preimage;
- retries still require a valid payer signature after the first receipt exists;
- the encrypted store is fsynced through a temporary file and atomic rename;
- restart reconciliation disables provider edges not backed by live Morph
  evidence.

## 5. Native RGB++ Model

### Asset identity

`RgbppAssetId` is:

```text
(ckb_genesis_hash,
 xudt_type_script_hash,
 bitcoin_network,
 rgbpp_binding_code_hash)
```

Ticker, name, icon, and decimals are display metadata and never authorize
value. The Payment Gateway parses canonical CKB Script JSON and independently
computes its Script hash.

### Binding evidence

`RgbppBindingEvidence` binds:

- the asset identity;
- consumed Bitcoin seal outpoint;
- corresponding CKB asset Cell outpoint and amount;
- Bitcoin inclusion block/hash/height and observed tip;
- the allowlisted proof-program Type hash;
- proof Cell outpoint and proof-payload commitment.

Morph host validation verifies binding-code identity, proof-program identity,
network, confirmation depth, and freshness. Bitcoin SPV validity is delegated
only to a pinned proof program/light-client deployment. The current Payment
Gateway process accepts only operator-admitted proof commitments; its live proof
watcher and automatic admission path remain Phase E work.

### Leap lifecycle to implement

1. `Observed`: Bitcoin transaction and candidate CKB Cell are observed.
2. `Proving`: proof payload is built against a known canonical Bitcoin tip.
3. `Verified`: allowlisted proof program commits the proof Cell.
4. `Available`: Factory/right/channel may reserve the asset.
5. `Reserved`: exact proof commitment is bound into a payment/edge.
6. `Spent` or `LeapingOut`: next seal is committed.
7. `Finalised`: both chains meet configured confirmation/finality policy.
8. `RolledBack`: Bitcoin or CKB reorg invalidates descendants and mirrored
   Fiber edges before reuse.

No edge becomes routable in phases 1-3. A reorg from phases 4-7 disables the
edge and invalidates pending Payment Gateway receipts that have not reached
the required terminal anchor policy.

## 6. Morph Native Bilateral ChannelBackend

The implemented backend wraps the existing Morph `StateCell`,
`StateAuthorization`, settlement descriptor, participants, and asset registry.
It does not define a second commitment transaction format.

For a payment it:

1. validates the canonical intent and exact funding context;
2. checks the xUDT registry and, for RGB++, a previously verified proof
   commitment;
3. permits one expected successor descriptor in the current wire profile;
4. validates the next full 2-of-2 signed State transition;
5. parses the CKB/xUDT settlement descriptors;
6. checks payer decrease, payee increase, exact amount, asset, lock hashes, and
   value conservation, while forbidding an xUDT payment from changing either
   participant's CKB carrier amount;
7. accepts commit only after preparation and strictly before the intent expiry;
8. returns canonical Morph state settlement evidence.

Channel node IDs are hashes of the actual signed-State participant public keys;
they are not caller-selected aliases. The payment asset's CKB genesis must also
match the signed State chain ID.

This is the CKB-force-enforceable backend. Payment Gateway/Fiber provider
status cannot substitute for step 4-6.

## 7. Factory Right to Provider Edge

### Required evidence

- Factory ID, update number, exact source right ID and quantity;
- explicit intended physical `target_channel_id`, independently committed in the reservation ID;
- state/access roots, full sparse-Merkle right proof, and proof commitment;
- reservation expiry and idempotency key;
- committed child State and Vault outpoints;
- content root plus the activated exact Vault OutPoint commitment;
- full child State authorization and settlement descriptor;
- exact State/StateLock/VaultLock/Factory/FactoryVault code hashes;
- CKB block hash/height and confirmation depth;
- optional RGB++ proof commitment.

### Lifecycle

```text
Reserved -> Materializing -> Active -> Draining -> Disabled
                                 \----------------> Invalidated
```

- reservation cannot be reused for a different intent;
- Factory-origin child evidence requires the trusted Factory code set, actual
  historical source, matching access/state roots and intended physical channel
  ID. Current ReserveClaims may have a zero bookkeeping label; that label is
  not the future physical channel ID.
- direct Root channels must not claim Factory provenance;
- splice creates a new funding-context edge only after the old edge drains and
  disables;
- reorg/proof invalidation can move any published edge to `Invalidated`;
- restart treats the Morph registry as source of truth.

An edge ID is stable across signed balance/state-number refreshes and changes
only with stable identity such as funding context (therefore splice),
participants, asset, deployment, or Factory origin. Fiber endpoint IDs use the
actual compressed participant secp256k1 keys; the corresponding Morph account
hashes are carried separately.

## 8. Minimal Fiber Hook

The audited Fiber revision has read-only `graph_channels`, native
`open_channel`/external funding, and channel actor update RPCs. None registers
an externally enforced Morph state machine as a routable edge.

The adapter therefore targets four explicit methods:

- `morph_register_external_edge`
- `morph_update_external_edge`
- `morph_disable_external_edge`
- `morph_list_external_edges`

Registration includes real Fiber-compatible signer public keys, Morph account
IDs, directional liquidity, asset identity,
funding-context version, deployment ID, evidence height, opaque Morph
commitment, and a fixed callback endpoint. It deliberately does not invent a
Fiber funding outpoint.

Fiber must call Morph for:

- payment prepare/reservation;
- signed-state commit;
- fulfill/fail/cancel;
- capacity refresh;
- edge disable/replace acknowledgement.

All mutations use optimistic provider revisions. On restart, the adapter:

- registers missing verified Morph edges;
- updates stale provider commitments;
- disables Fiber mirrors that lack live Morph evidence.

If upstream Fiber declines this hook, Morph may maintain a narrow patch/fork in
the adapter layer. Morph core and contracts remain unchanged.

## 9. Conditional Payments and Batch Cell

Current Morph State/Vault settlement supports final signed CKB/xUDT payout
descriptors. It does not yet provide a hashlock/refund script for an arbitrary
set of pending Fiber TLCs.

The next contract profile may add one Batch Cell per channel close:

- ordered conditional-transfer root committed by signed State;
- payment hash, algorithm, amount, direction, and absolute expiry per leaf;
- one bounded witness resolves all leaves by preimage or mature refund;
- at most two aggregate participant payouts;
- explicit CKB carrier reserve for xUDT/RGB++ payouts;
- host/script differential and CKB-VM tests for 1, 2, and the configured maximum
  pending transfers.

This Batch Cell is only a close-time conditional-settlement optimization. It
does not own Factory membership, shared liquidity, child materialisation,
splice, or local exit.

Until this profile is implemented and audited, a Fiber TLC cannot be advertised
as independently force-enforceable by Morph during its pending window. Final
settled Morph signed states remain enforceable.

## 10. Delivery Phases

### Phase A — corrected Morph baseline and exact Vault authority (complete)

- restore native Factory architecture;
- initial State/Factory consent;
- exact initial Vault commitment;
- two-stage exact Vault OutPoint activation/rotation for bilateral and Factory
  profiles, with byte-identical-clone and noncanonical-CellDep rejection;
- type-bound FactoryState locking, independent fee-input signatures, and exact
  State/Factory carrier-capacity deltas across update/activation/splice/exit;
- signed descriptor progress and fixed Vault root;
- dynamic 2–16 participant Factory signer profile with N-of-N full consent;
- full baseline CI and CKB-VM suite.

### Phase B — sovereign host interfaces (implemented, audit pending)

- RGB++ identity and proof policy;
- canonical Payment Gateway intents and signed terminal receipts;
- native bilateral ChannelBackend on existing State/descriptor model;
- Factory reservation/materialisation/edge registry;
- strict positive/negative/idempotency tests.

The present host boundary additionally enforces stable edge identity across
liquidity refresh, signer-derived endpoint IDs, sparse-Merkle right proof
consistency, exact vault asset shape, and trusted CKB genesis/deployment IDs.

### Phase C — issue #1255 Payment Gateway capability (implemented and real-Fiber E2E gated)

- x402 JSON and HTTP headers;
- Fiber invoice/pay/status integration;
- Biscuit credential mint/verify;
- AES-256-GCM fair exchange;
- encrypted atomic store and payment index;
- fixed-upstream Gateway;
- One native Rust SDK, reusing the canonical service/protocol implementation.

The acceptance harness establishes Fiber's native three-node `router-pay`
topology, then executes one x402 credential purchase and one hash-locked fair
exchange through payer/payee Morph Payment Gateway instances attached to Fiber
node1/node3. This proves the application gateway against real Fiber routing. It
does not satisfy Phase D: those route edges are still Fiber-native, not
Morph-backed.

### Phase D — Fiber hook control plane (Morph adapter implemented; Fiber hook pending)

- external-edge wire schema and strict JSON-RPC client;
- registration/update/disable/list;
- payment prepare/resolve callback schema;
- restart reconciliation;
- implement and upstream or isolate the Fiber graph/forwarding hook;
- run registration, liquidity refresh, splice replacement, disable, callback,
  and restart reconciliation in shadow mode without carrying user value.

The control plane must not mark the edge routable for real funds yet. A Fiber
TLC traversing a Morph edge is sovereign only if Morph can force-close every
pending outcome after Fiber disappears.

### Phase E — RGB++ chain lifecycle

- pin production script deployment registry;
- integrate reviewed RGB++ light client/proof Type;
- leap-in/leap-out builders;
- Bitcoin/CKB confirmation and reorg watchers;
- Factory reserve and splice with proof/seal continuation;
- two distinct RGB++ assets and substitution-negative tests.

### Phase F — conditional force-close

- Batch Cell profile without changing Factory;
- pending-transfer root in signed Morph state;
- preimage/timeout resolution and bounded aggregate payouts;
- force-close tests with Fiber stopped at prepare, forward, fulfill, fail, and
  timeout boundaries.

### Phase G — routed data plane and operational hardening

- enable real three-node routing and MPP over at least one Morph-backed edge
  only after Phases D-F pass;
- exercise mixed native-Fiber/Morph routes, partial MPP failure, fee updates,
  splice drain/replacement, RGB++ proof invalidation, and provider replacement;
- watchtower splice publication;
- hash-checkpointed CKB reorg rollback;
- encrypted store key rotation/backup;
- rate limits, TLS/mTLS, audit logs, metrics, fuzzing, cycle/size budgets;
- reproducible builds, SBOM, dependency review, and independent contract audit.

## 11. Release Gate

Morph may be called production-ready for RGB++ Payment Gateway workflows only
when all items below have reproducible evidence:

- repository format, clippy, RustSec, cargo-deny, unit/property tests, fixtures,
  RISC-V builds, CKB-VM tests, Hub build, and Payment Gateway SDK build pass;
- real CKB devnet open/update/splice/factory local+reduced exit/force close pass;
- real three-node Fiber multi-hop and MPP route over a Morph-backed hook edge;
- edge disable on close, splice, stale state, proof invalidation, and reorg;
- Payment Gateway/Fiber/Morph restart at every durable boundary does not
  duplicate settle or resurrect an invalid edge;
- two same-ticker/different-Type-Script assets cannot substitute;
- wrong Bitcoin network, proof program, confirmation depth, seal, CKB Cell,
  preimage, payer, amount, method, resource, nonce, and idempotency key fail;
- pending conditional payments remain CKB-enforceable after Fiber disappears;
- code-hash deployment identity is pinned on chain or by an equivalently
  reviewed registry;
- watchtower performs canonical-hash rollback and republishes the latest valid
  package;
- contract cycle/transaction-size budgets and independent security review pass.

Until then, documentation and APIs must distinguish:

- implemented and unit-tested;
- demonstrated on real Morph/Fiber devnet;
- audited mainnet-ready.

## 12. Current Blockers

- current public Fiber RPC does not implement the external-edge hook;
- current public Fiber RPC does not expose the sender's learned preimage or a
  receiver RPC for final-hop custom records; Morph therefore uses
  challenge-bound payer identity until a minimal proof hook is available;
- Morph watchtower now persists canonical block hashes, resets orphanable
  context, and rescans from the channel floor after a mismatch; repeated public
  network reorg evidence remains open;
- deployed State args do not yet pin the full trusted script code set on chain;
- real Bitcoin SPV/proof-program integration and leap lifecycle are absent;
- Factory reservation roots still need to be fetched and matched against a
  canonical CKB FactoryStateCell by the live bridge watcher; host proof
  consistency alone is not chain inclusion;
- conditional pending TLC force-close/Batch Cell is absent;
- Factory full-consent membership is bounded to 2–16 and does not yet support
  threshold subsets or membership changes in place;
- real three-node Morph-backed Fiber routing evidence is absent;
- no independent contract/Payment Gateway security audit has been completed.
- production ingress controls (TLS/mTLS, rate limits, admin protection for the
  payment index, and proof-admission service authentication) are not yet wired.
- legacy owner-locked devnet factories require recreation under the type-bound
  StateLock profile; no mainnet migration mechanism is claimed.

These blockers are reasons not to claim completion. They are not reasons to
delete Factory, weaken the bilateral backend, or let Fiber become the source of
truth.
