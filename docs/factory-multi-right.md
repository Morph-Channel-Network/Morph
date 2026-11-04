# Factory Multi-Right Updates

## Wire Format: Kind 8 Multi-Right Update

Envelope: `WitnessEnvelope` format 1, kind
`WITNESS_ENVELOPE_KIND_FACTORY_MULTI_RIGHT_UPDATE = 8`, body version
`FACTORY_MULTI_RIGHT_UPDATE_WITNESS_VERSION = 1`.

The body is fixed-layout given `(participant_count, right_count)`:

```text
0        u16   witness version (= 1)
2        u8    participant threshold (= participant_count)
3        u8    participant count (2..=16)
4        u8    authorised signature count (= 1)
5        u8    right count R (1..=FACTORY_MULTI_RIGHT_MAX_COUNT = 4)
6        u16   reserved (= 0)
8        ..    participant entries (same 130-byte layout as kinds 2-7)
P = 8 + N*130
P+0      32    touched participant
P+32     u16   compact sibling capacity (= FACTORY_COMPACT_PROOF_MAX_SIBLINGS)
P+34     u16   reserved (= 0)
P+36     ..    rights_before[R]  (FACTORY_RIGHT_LEN = 114 each)
Q = P+36+R*114
Q+0      ..    rights_after[R]
S = Q+R*114
S+0      ..    proof_before[R]: { u16 pair_count, pairs[64] of {u16 depth, 32 hash} }
T = S+R*(2+64*34)
T+0      ..    proof_after[R]:  same layout
```

### Compact (variable-depth) sparse-Merkle proofs

Kinds 2–7 either list every right (kind 2/4) or carry all 256 sibling hashes
per proof (kinds 3/6/7). Kind 8 carries only the non-empty siblings: a proof
is a list of `(depth, hash)` pairs sorted by strictly descending depth.
The verifier walks depths 255 → 0, uses the next pair when its depth matches,
and otherwise substitutes the canonical empty-subtree hash
`H_empty(k)` for a subtree holding `2^k` leaf slots, derived in the script
from `FACTORY_RIGHT_EMPTY_DOMAIN` with the same recurrence as the host
(`factory_empty_hashes`). Soundness does not depend on the claimed pair set:
if a real sibling were omitted, the reconstructed root would not match the
committed root and the script fails closed. The pair count is bounded by
`FACTORY_COMPACT_PROOF_MAX_SIBLINGS = 64` per proof; a tree whose nearest
neighbour structure needs more pairs cannot produce this witness shape and is
rejected.

### Update semantics verified by the script

1. Standard reduced prelude: 2–16 strictly sorted unique participants,
   exactly one signed entry, reserved fields zero.
2. `rights_before` strictly sorted by right identity; each `rights_after[i]`
   has the identical identity (participant, subchannel, kind, asset) as
   `rights_before[i]`.
3. Every right belongs to the single touched participant.
4. Every right is a value right (`Balance`, `ReserveClaim`, or
   `SponsorBudgetClaim`); membership and exit-path rights cannot be changed
   or spent through this path.
5. Every `proof_before[i]` reconstructs `old_header.state_root`, every
   `proof_after[i]` reconstructs `new_header.state_root`.
6. Cross-side localization: each before/after proof pair is walked in
   lockstep, and any sibling subtree whose hash differs between the two
   sides must contain one of the other listed rights. A differing subtree
   with no listed excuse means an unlisted right changed between the
   committed roots, so the witness fails closed. This is what makes the
   update non-interfering: only the listed rights may change.
7. `old_header.access_manifest_root == new_header.access_manifest_root`
   (identities do not change, so the manifest cannot move).
8. The witness non-interference digest (domain
   `CKB_MORPH_FACTORY_MULTI_RIGHT_UPDATE`, binding factory id, old/new update
   numbers, old/new state roots, old/new access-manifest roots, the touched
   participant, the right count, and every before/after right body) equals
   the digest committed in the new header.
9. Per-asset quantity conservation: for CKB and each distinct xUDT type,
   `sum_asset(after) <= sum_asset(before)` over the touched participant's
   listed rights. Individual rights may rebalance within one asset domain,
   but burning one asset can never mint another. At least one right must
   change.
10. The touched participant's signature verifies over
   `new_header.signing_digest()`.

The factory-type script additionally enforces the shared update invariants
(monotonic update number, unchanged context, bound vault OutPoint, preserved
carrier capacity) exactly as for kinds 1–3.

### Why per-side proofs

With several changed leaves, the sibling subtrees of right `i` contain the
other changed rights `j != i`, whose hashes differ between the before and
after trees. Kind 8 therefore carries a separate proof array per side; each
proof independently localises its leaf against the committed root of its own
tree. Per-side inclusion alone would only constrain the listed rights, so
the verifier additionally walks both proofs in lockstep and requires every
sibling subtree whose hash differs between the sides to contain one of the
other listed rights. Only the listed rights may therefore differ anywhere
between the two committed trees: an unlisted change necessarily surfaces as
a differing subtree on some listed path that no listed key can excuse.

## Host Surface

- `morph-script-common`: `FactoryMultiRightUpdateWitness` parse/verify,
  `factory_multi_right_update_witness_len`, kind-8 envelope admission, empty
  subtree hash helper, `FACTORY_RIGHT_EMPTY_DOMAIN` and
  `FACTORY_MULTI_RIGHT_UPDATE_DOMAIN` constants.
- `morph-core`:
  - `FactoryCompactMerkleSibling`, `FactoryCompactRightProof`,
    `FactoryMultiRightMerkleUpdate` types;
  - `factory_right_sparse_proof_compact` (generate) and
    `verify_factory_right_compact_proof` (verify with in-host completion);
  - `validate_factory_multi_right_merkle_update` mirroring the script
    predicate (single touched participant, value rights only, sorted
    identities, per-asset non-increase, at least one change);
  - `ValueLimitPolicy` and `validate_value_limits`.
- `morph-cli`: `print-factory-multi-right-update-fixture`,
  `validate-factory-multi-right-update-package`,
  `print-value-limit-policy-fixture`, `validate-value-limit-policy`,
  `value-limit-check`, and fixture-checks integration. Live-node save/publication
  plumbing for kind 8 remains tracked in `roadmap.md`.
- `morph-factory-type`: kind 8 dispatch in
  `validate_participant_authorisation` and the state-preserving update arm.

## Security Boundaries

Every boundary below has a negative test; names are listed in
`SECURITY-FIXES.md`.

| Boundary | Failure mode prevented |
| --- | --- |
| Exactly one authorisation signature from the touched participant | Any other participant (or no signature) driving a right update. |
| All rights belong to the touched participant | Spending or minting another participant's rights. |
| Value-right kinds only | Burning membership or exit-path rights through the value path. |
| Strict identity sort + pairwise same-id | Reordering or swapping rights between before/after arrays. |
| Independent per-side root localisation | Proving an update against a tree that was never committed. |
| Cross-side localization of every listed pair | Silently rewriting an unlisted right (for example another participant's balance) between the committed roots. |
| Per-asset non-increase with at least one change | Cross-asset minting, same-asset minting, and no-op update-number burning. |
| Unchanged access-manifest root | Changing the manifest while claiming a value-only update. |
| Non-interference digest binding | Replay of a witness against different headers. |
| Compact pairs strictly descending, bounded, all consumed | Malformed or ambiguous proof encodings. |

## Verification

- `morph-script-common` unit tests: parse round-trip, positive verify, and
  one negative per boundary above.
- `morph-core` tests: host/script digest and root parity for compact proofs,
  generator/verifier round-trip over random trees (proptest), update
  validation positives/negatives.
- `hash_parity.rs`: domain parity for the new constants.
- `contract_scripts.rs` (`make contract-tests`): on-chain CKB-VM execution of
  a real kind-8 update on the factory-type script, plus on-chain negatives
  (foreign right, same-asset increase, cross-asset rebalance, bad signature).
- `make fixture-checks`: kind-8 fixture generation and validation.
