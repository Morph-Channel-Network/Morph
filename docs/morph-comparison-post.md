# Morph Channel vs. Lightning/eltoo, Perun, and the CKB Generic Payment Channel — A Comparative Reading

> Note: this post is comparative positioning — how Morph relates to the
> construction families that already exist for CKB and for Bitcoin. Morph's
> current implementation-security baseline is the 2026-08-15 swarm audit, with
> remediation status in `SECURITY-FIXES.md`.
>
> Refresh note, 2026-08-15: external-project statements remain a source
> snapshot and must be revalidated before publication as current deployment
> claims. Morph statements below reflect the bounded devnet implementation:
> exact Vault provenance, 2–16 Factory participants, fixed reduced proof shapes,
> and signed splice-out withdrawal locks. This is not production evidence.

I read four reference materials end-to-end before writing this:

1. **Lightning / eltoo** — the "eltoo" paper by Decker, Russell,
   Osuntokun (`eltoo.pdf`), and `Ademan/multi-party-eltoo-with-bounded-settlement`
   — a Rust implementation of Ademan's multi-party eltoo variant.
2. **Perun** — the original paper by Dziembowski, Eckey, Faust, Malinowski
   (IEEE S&P 2019, DOI 10.1109/SP.2019.00020), and the CKB port:
   `perun-network/perun-ckb-contract` (Rust on CKB) and
   `perun-network/perun-ckb-backend` (Go on top of `go-perun`).
3. **The CKB Generic Payment Channel** (GPC) — `janx`'s talk on Nervos
   Talk, 2020-05-18: *"A Generic Payment Channel Construction and Its
   Composability"*. This is the CKB-native baseline that any new CKB
   channel construction has to position against.
4. **Morph Channel** — my own construction. The implementation and
   current docs are in this repo; the research paper draft is external,
   the latest audit baseline is `docs/swarm-audit-glm-2026-08-15.md`, and
   remediation status is recorded in `SECURITY-FIXES.md`.

The reference materials I pulled into the workspace are at
`~/Documents/morph-comparison/`. I was unable to download the Perun
PDF directly (the IACR ePrint mirror is behind Cloudflare and IEEE
returns 418); the DOI is `10.1109/SP.2019.00020`. I worked from the
IACR abstract, the Go backend code, and the CKB contract code. If you
have a direct Perun PDF and want me to revise specific numbers below,
say the word.

The structure of this post is:

1. A one-page summary table.
2. Each construction, with the part of Morph that overlaps it and the
   part that does not.
3. A "what would it take to deploy each on CKB today" reading.
4. A "what Morph borrows from each, and what it adds" reading.

---

## 1. The summary

| Axis                              | eltoo (Lightning)               | Perun                                 | GPC (CKB talk)                          | Morph Channel                         |
| --------------------------------- | ------------------------------- | ------------------------------------- | --------------------------------------- | ------------------------------------- |
| Update rule                       | Replace-by-version              | Replace-by-version + signing set     | Replace-by-version                     | Replace-by-version                    |
| Dispute rule                      | Newer state wins (sig on no-input hash) | Newer state wins with watchtowers and challenge period | Newer state wins (timeout-after-state) | Newer state wins (challenge window + relative `since`) |
| Required Bitcoin opcode            | `SIGHASH_ANYPREVOUT` (NOINPUT/ANYONECANPAY) | None (Turing-complete smart contract) | None (UTXO + scripts)                  | None (UTXO + scripts)                  |
| Script footprint                  | One sighash flag change         | Smart contracts; CKB port in Rust       | One lock script (GPC lock)              | Type + lock + sponsor lock + envelope |
| Funding anchor                    | The funding outpoint            | Contract reference                     | Funding outpoint                         | Type-ID-style derivation OR live Fund Cell |
| Multi-asset                       | Single asset                    | Multi-asset (EVM tokens)              | Native (any UDT/SUDT/CKB)                | Current settlement: CKB + one xUDT type; multi-xUDT Vault sets planned |
| Sponsor / fee model                | Channel pays fees                | Channel pays fees                      | Channel pays fees                        | Sponsor partition (channel never pays fees) |
| Splice / resize                    | Not in paper                     | Re-fund / new channel                   | Not in paper                              | Resize/re-anchor (`SPLICE` on wire) with exact old/new Vault binding |
| Channel factory                   | Not in paper                     | Layered virtual channels               | Not in paper                              | Bounded devnet implementation (2–16 participants) |
| Reduced signing set               | Not in paper                     | Not in paper                            | Not in paper                              | Bounded single-participant proof families, including up to four value rights with compact proofs |
| Composability with L1 assets      | Low (Bitcoin only)               | Medium (token interface)               | High (any UDT/CKB)                       | CKB + one xUDT type per current settlement profile |
| Has a deployed Bitcoin/CKB impl?  | No (SIGHASH_ANYPREVOUT not deployed) | Yes (Ethereum, CKB via perun-ckb-contract) | Talk only — no impl                      | Yes, with controlled-devnet evidence; exact counts are snapshot-specific |
| Maturity for bilateral profile     | Academic                         | Production (Ethereum); experimental (CKB) | Spec only                                | Devnet-evidenced                        |

The next four sections explain why each row looks the way it does.

---

## 2. Lightning / eltoo

`eltoo.pdf` (Decker, Russell, Osuntokun) is a *replace-by-version* scheme
for Bitcoin. Every state update produces a new "update transaction"
that consumes the current update and creates the next one. The dispute
rule is "the update with the highest version number wins, provided it
was confirmed". The catch is the `SIGHASH_NOINPUT` (later renamed
`SIGHASH_ANYPREVOUT`) sighash flag, which lets a signature commit to
outputs without committing to the input outpoint. Without that flag,
an attacker can malleate the previous txid, breaking the
parent-pointer that the replace-by-version rule relies on.

`Ademan/multi-party-eltoo-with-bounded-settlement` is a 1,901-line Rust
implementation of *Ademan's variant*, a multi-party extension with
bounded-settlement semantics. It is not a Lightning implementation; it
is a state-update bench. The README explicitly states:

> The asymptotic performance of the scheme is exponential so either way
> we'll hit a hard limit pretty quickly, on my computer that seems to be
> between 10 and 16 channel parties, closer to 10.

There is no production eltoo Lightning implementation, because
`SIGHASH_ANYPREVOUT` is not deployed on Bitcoin. Lightning uses the
older Poon-Dryja penalty construction, which has the well-known
toxic-waste problem. eltoo is, in practice, a research artefact today.

### Where Morph overlaps eltoo

The state-update and dispute rule are the same family:
*replace-by-version, newer state wins*. Morph's `phase = settling`
plus strictly monotonic `state_number` (defined in the external paper draft)
is the same rule that eltoo enforces via update transactions with
strictly increasing version numbers. Both schemes require the dispute
window to be sufficient for confirmation, and both schemes make the
challenge window a deployment parameter.

### Where Morph does not overlap

eltoo requires `SIGHASH_ANYPREVOUT`. Morph requires nothing — the CKB
transaction hash covers inputs and outputs, so the parent-pointer is
stable by construction. The state uniqueness comes from CKB's
single-spend rule plus Morph's "exactly one input, exactly one output"
type script rule (`verify_state_cell_type` in the external paper draft).

eltoo has no splice and no factory. Morph has both — and its resize/re-anchor
(historically `SPLICE` in the wire/API) is
the only construction in this comparison that script-level checks a
signed splice event against the current state, the successor's preserved
context, and the splice-specific vault roots
(`SpliceHeader::matches_current_state` plus
`state_context_matches_splice_next`). eltoo's update transactions are signed
by `SIGHASH_ANYPREVOUT`
over their inputs, so the eltoo update already commits to its own
"next state's full content" — but only at the transaction-graph level,
not at the script level. Morph's splice content binding is enforced
inside CKB-VM and is testable by the unit tests in
`contracts/morph-script-common/src/lib.rs`.

eltoo has no sponsor partition. Morph does. This is a CKB-friendly
extension: sponsor funds sit in a separate Cell that pays the
publication carrier without touching channel value. eltoo's analogue
would be a separate fee-bumping wallet that publishes the update, which
is operationally possible but not protocol-blessed.

CKB does support replacement of pending conflicting transactions. Morph's
distinction is not “no RBF”: participant signatures authorise the State Header,
not sponsor coin selection or fee rate. A publisher can rebuild or replace the
carrier transaction with different sponsor inputs without asking participants
to re-sign the channel state.

### Where eltoo is better than Morph

eltoo's update-and-update transactions are simpler to reason about
than Morph's `verify_splice_state_transition_bundle` (state + vault +
signature + splice-event, plus the audit-style `SpliceHeader::matches_current_state`
check added after the audit). If you have `SIGHASH_ANYPREVOUT`, eltoo
is one elegant construction; on CKB Morph has to express the same
guarantees in script logic.

---

## 3. Perun

The Perun paper (Dziembowski et al., IEEE S&P 2019; DOI
10.1109/SP.2019.00020) introduces *virtual channels*: a three-party
construct where Alice and Bob open a virtual channel on top of two
ledger channels they already have with Carol, without involving Carol
per-payment. Carol collateralises but does not interact. The
construction is general (any Turing-complete chain) and was
implemented on Ethereum first.

`perun-network/perun-ckb-contract` and `perun-network/perun-ckb-backend`
are the CKB port. The contract repo provides:
`perun-channel-lockscript`, `perun-channel-typescript`,
`perun-funds-lockscript`, plus the virtual-channel pair
`perun-vchannel-lockscript` and `perun-vchannel-typescript`. The backend
is a Go server on top of `go-perun`. Perun on CKB uses Ethereum-style
binary encoding for state, so the same off-chain signed messages are
valid on Ethereum and on CKB. That is its strongest claim.

### Where Morph overlaps Perun

Both use the newer-state-wins rule. Both have a state-evidence object
(`StatePackage` in Morph, signed update in Perun). Both have a
challenge window. Both can do multi-asset on CKB (Perun via SUDT, Morph
via xUDT).

Both separate the funding object from the state evidence object.
Perun's contract locks the channel funds behind a Perun-specific
lock; Morph's `vault_set_commitment` lives in the State Header and
the vault lock checks it. Both have a notion of "current live state".

### Where Morph does not overlap

Perun has *virtual channels*. Morph has *factories*. The two are
different:

- Perun's virtual channel is a three-party construct that builds on
  top of two existing ledger channels. The intermediary (Carol)
  collateralises the virtual channel and does not interact per payment.
- Morph's factory is a single state object with multiple child channels
  plus optional reduced signing per factory root. The factory is
  itself a single channel with a more complex authorisation model.

Morph does not have a virtual-channel construction. Its Factory is now a
bounded executable devnet profile: 2–16 participants, N-of-N conservative
paths, fixed reduced-right/sparse-Merkle/reduced-exit/reduced-splice proof
families, and exact FactoryVault provenance. General multi-right rebalancing,
variable-depth proofs, and virtual-channel layering remain open.

Perun's encoding is Ethereum-first. Morph's encoding is CKB-native
(fixed-layout parsers, Molecule schema in `schemas/morph.mol`). They
are not wire-compatible. A Morph → Perun bridge would require a
translator at the L2 boundary.

### Where Perun is better than Morph

Perun has a published multi-chain architecture. The cited `go-perun` backend
and CKB contract sources describe the same state encoding across Ethereum and
CKB. Morph has only CKB-native bilateral and bounded Factory profiles;
cross-chain Morph would need to be built from scratch. Perun also has an
academic formal security proof; Morph has audit-driven definitional hardening
and devnet evidence, but not a formal proof.

Perun's watchtower design is cleaner. Perun's watchtowers operate
inside the channel's adjudication phase and the protocol supports
delegation; Morph's watchtower can force-settle but cannot redirect,
and the external paper draft explicitly notes that delegation is
out of scope for the current profile.

---

## 4. The CKB Generic Payment Channel (GPC)

The GPC construction (Nervos Talk, 2020-05-18) is the first published
CKB-native payment channel construction I know of. It is "basically
an eltoo port on CKB", as the author writes, but with one critical
difference: GPC does not need a SIGHASH_NOINPUT analogue, because CKB
transaction hashing already separates inputs from outputs cleanly
enough that the closing transactions can be signed over a "no-input
hash" using a different witness encoding.

The construction is:

- A **GPC lock** script on the funding output. Lock args carry
  `(state, timeout, pubkey_a, pubkey_b, nonce)`. State is `OPEN` or
  `CLOSING`.
- Three transaction kinds: funding, closing, settlement.
- Closing transactions are signed using a no-input hash (inputs are
  not committed to the signature). This is what lets a single signed
  closing transaction be attached to the funding output *or* to
  another closing output with a higher nonce.
- The "ugly" case — Bob publishes an obsolete closing transaction —
  is handled by Alice publishing a higher-nonce closing transaction
  in response, which consumes the obsolete closing output. Because the
  closing output has a higher nonce than the input, the obsolete one
  cannot respond.

This is a clean construction and the CKB-native idea of using
no-input hashing via witness encoding is genuinely elegant.

### Where Morph overlaps GPC

Both are CKB-native. Both use replace-by-version. Both separate the
funding object from the state evidence object. Both have a challenge
window (relative `since`). Both can ride any UDT/SUDT/xUDT on CKB.

GPC puts the channel state in the *lock args* of a single funding Cell.
Morph puts the channel state in a separate State Cell whose data is
the canonical State Header, and uses the vault lock to authorise
value-bearing operations. This is a different decomposition. GPC's
single-Cell model is simpler on a small channel; Morph's split model
makes sponsor fees, splice, and factory possible without disturbing
the funding Cell.

### Where Morph does not overlap

GPC has no splice. GPC has no factory. GPC has no sponsor partition.
GPC has no script-level binding of the "complete successor State
Header" — GPC relies on the lock args being signed by both parties
together with the witness, and on the no-input hash discipline. The
no-input hash is a witness-encoding trick; Morph's content-binding is
a script-level predicate (`SpliceHeader::matches_current_state`).

GPC's "ugly" case has a known worst-case latency of `O(i × T)` blocks
where `i` is the number of obsolete states Bob can submit. Morph's
challenge window is a single `Δ`, and superseded states cannot keep
the dispute open in this way — the State Cell uniqueness rule
(`exactly one input, exactly one output`) plus CKB's single-spend rule
mean the dispute closes once one supersession transaction confirms.
GPC's worst case is genuinely worse than Morph's, though GPC's argument
is that the attacker pays an `O(i)` cost, so the attack is
uneconomical.

GPC's lock-args state model is harder to upgrade. Once a GPC channel
exists, its lock args carry the channel parameters; you cannot add
new fields to the lock args without a new deployment. Morph's State
Header is a separate Cell; its canonical encoding can evolve across
deployments because the State Cell type script can gate on
`state_layout_version`. The Morph paper declares
`state_layout_version` as a deployment-versioned field.

### Where GPC is better than Morph

GPC is *smaller*. The entire construction fits in one lock script,
three transaction shapes, and one state machine. Morph has a State
Cell type script, a vault lock, a sponsor lock, a witness envelope,
a factory type, a factory vault lock, an operation envelope, a
canonical operation envelope, a vault manifest, and a partition
classifier (after the audit). GPC is the kind of construction you can
hand to one engineer and expect a working bilateral implementation in
a week. Morph is the kind of construction that needs the audit
process we just went through.

GPC is *elegant on no-input hashing*. The CKB-native trick of
committing to outputs only is the kind of design choice that does
not depend on `SIGHASH_ANYPREVOUT` and works today. Morph's signing
domain is bigger but follows the same idea.

---

## 5. CKB implementation posture (source snapshot)

| Construction  | Evidence represented by the reviewed sources                                                              |
| ------------- | -------------------------------------------------------------------------------------- |
| Lightning (Poon-Dryja penalty) | The reviewed material does not provide a first-class CKB deployment of the Bitcoin penalty construction. |
| eltoo         | No — requires `SIGHASH_ANYPREVOUT`, which CKB does not have and which Morph does not need. The Ademan reference implementation is a Rust bench, not a wire-level implementation. |
| Perun         | The cited repositories provide CKB contracts and a Go backend. Current deployment availability and maintenance status must be checked against fresh upstream evidence before publication. |
| GPC           | The reviewed Nervos Talk post specifies the construction; this comparison did not identify a maintained implementation artifact. |
| Morph Channel | The repository implements bilateral and bounded Factory profiles, including exact Vault provenance, sponsor policy, resize, full/reduced Factory paths, release artefacts, and negative CKB-VM tests. Production implementation is the development focus; current evidence is controlled-devnet, with production release subject to the readiness gates. |

The "what would it take" reading is:

- Perun is the relevant published CKB/multi-chain implementation family, but a
  deployment decision requires fresh upstream build, maintenance, and network
  evidence.
- GPC is the smallest CKB-native specification in this comparison; an actual
  deployment still needs an implementation and independent review.
- If you want a CKB-native channel with sponsor partitioning, splice,
  and bounded Factory paths, Morph supplies executable devnet evidence. It also
  has the largest local script surface here. Its production implementation
  work is subject to the documented release and value-limit gates.
- If you want eltoo on Bitcoin, the answer is "wait for
  `SIGHASH_ANYPREVOUT`" plus "there is no testnet deployment today".

---

## 6. What Morph borrows from each, and what it adds

### Borrowed

- **From eltoo:** the replace-by-version dispute rule and the
  newer-state-wins safety property.
- **From Perun:** the multi-asset accounting model. Both schemes
  treat each xUDT as a separate conservation lane; both have the same
  notion of "challenge window"; both have explicit witness envelopes
  (Perun's encoding is wire-format; Morph's paper-side
  `MorphOperationEnvelope` maps to the implementation's structural
  witness envelope rather than a Perun-compatible wire format).
- **From GPC:** the CKB-native realisation that a channel state
  pointer can be a Cell, not a global registry; the relative-time
  challenge window via CKB's `since` field; the explicit use of
  CKB's single-spend rule as the state-uniqueness mechanism.

### Added

- **Sponsor partition** — channel value never pays publication fees.
  The external paper draft's Proposition 1 ("Zero Channel-Paid Publication
  Fees") is provable from the partition-conservation linear-algebra
  identity now that the partition classifier is fully defined. None
  of the four reference constructions isolate a sponsor partition at
  the protocol level; they rely on a wallet signature or a watchtower
  fee policy.
- **Script-level splice** with content-binding of the successor State
  Header. eltoo's signature covers the next-update outputs at the
  transaction-graph level; Morph's `SpliceHeader::matches_current_state`
  and `state_context_matches_splice_next` checks bind the current
  vault-materialisation root, the successor vault-materialisation root,
  exact old/new Vault OutPoints, and the signed splice-out withdrawal lock.
  This is closer to Perun's
  strict state-binding than to eltoo's update-transaction model, and it
  is what makes the C-01 attack from the June 2026 audit impossible in
  the current bilateral profile.
- **Type-ID-style profile** that does not require a live Fund Cell.
  The external paper draft formally declares two profiles (Live Fund Cell vs
  Type-ID-style) and the current devnet implements the latter. GPC
  and Perun both have a live funding cell. Morph's Type-ID-style
  profile is one of the more opinionated choices in the comparison.
- **Bounded Factory implementation** with envelope-first admission and rights
  non-interference as an explicit condition. None of the four
  reference constructions has a factory profile. Perun has
  *layered* virtual channels, but factories (single-channel with
  children + reduced signing) are different. Morph implements the admitted
  2–16 participant, fixed-proof devnet profile; general multi-right and
  variable-depth proof families remain deferred.

### What Morph does not yet have

- **Virtual channels.** Perun has them. Morph's factory could
  eventually host virtual channels, but the acceptance agenda does
  not include them.
- **Cross-chain wire format.** Perun has it (Ethereum + CKB).
  Morph has only the CKB profile.
- **Formal security proof.** Perun has it. Morph has the audit-driven
  definitional hardening and devnet evidence, but not a published
  proof.
- **Deployed production.** Perun-ckb has devnet. Morph has devnet.
  Perun-eth has the more mature deployment story.

---

## 7. What this means for the audit verdict

The 2026-08-15 swarm audit at `9ab9ec1` found one High, four Medium,
seventeen Low, and twenty-two Informational items. On the current implementation
line:

- AUD-01 is closed by adding signed `withdrawal_lock_hash` fields to bilateral
  and Factory resize headers and enforcing exact CKB/xUDT withdrawal outputs;
- AUD-03 is closed by rejecting typed Vault inputs in the CKB-only settlement
  branch;
- AUD-04 and AUD-05 are closed by aligning host validation with the script's
  successor phase and Factory Vault-OutPoint lifecycle rules;
- AUD-02 is documented as an explicit code-identity trust boundary: a
  FactoryProof child delegates creation authority to the exact FactoryType hash
  in its args, so deployments must pin the audited FactoryType code identity;
- the Low/Informational hardening backlog and mainnet-readiness gates remain
  visible rather than being promoted into production claims.

The header additions are an intentional unpublished wire-format break:
`SpliceHeader`/`FactorySpliceHeader` are 485/469 bytes and the affected witness
body versions are 2. Historical audit counts and layouts remain valid only for
their recorded baseline.

For positioning against eltoo, Perun, and GPC: the bilateral profile
is now defensible relative to eltoo and GPC on the spec-and-evidence
axis. It is *complementary* to Perun, not competitive — Perun's
virtual channels and cross-chain story are not part of Morph's
bilateral profile, and Morph's sponsor partition and splice are not
part of Perun's profile.

---

## 8. The honest assessment

If I were picking a channel construction to ship on CKB today, I
would pick **Perun** for any deployment that needs cross-chain
interop or virtual channels, and **GPC** as the baseline for any
deployment that wants the smallest possible spec surface and is
willing to hand-engineer sponsor policy and splice off-chain.

**Morph** is being developed for production applications that need a separate
sponsor budget, resize/re-anchor, or Factory paths. Its current deployment
evidence is from controlled devnet. Production and real-asset deployment
requires closing the explicit mainnet-readiness gates. The planned
[multi-asset profile](multi-asset-channels.md) extends the current single-xUDT
settlement boundary.

Read `docs/swarm-audit-glm-2026-08-15.md`, `SECURITY-FIXES.md`, and
`docs/mainnet-readiness.md` alongside this post for the current audit baseline,
remediation status, and remaining release blockers.

— Mavis, originally 2026-06-20; comparison snapshot refreshed 2026-08-15;
Morph positioning and asset boundary updated 2026-11-02.
