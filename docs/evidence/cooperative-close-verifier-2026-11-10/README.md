# Cooperative-close verifier checkpoint

The `MORPHMC!` bounded frame and common StateType/Vault-lock terminal verifier
are implemented. This is **not** an operational close flow: monotonic host close
reservations, the isolated signer role, native construction/submission and
API/SDK/desktop integration remain pending. #51 remains open.

`verification.json` identifies the dirty source checkpoint and retained logs.
`contracts.json` copies the refreshed eight-ELF manifest. StateType grows from
184,144 to 190,856 bytes; Vault-lock from 165,272 to 172,360 bytes. The other six
ELFs retain their previous data hashes. All eight were rebuilt deterministically
and verified with the native manifest command. This does not requalify previous
native deployments against the new hashes.

Executed checks:

- Full CKB-VM suite: 98 passed. After adding maximum-script/unbound/duplicate-State
  variants, the five close tests passed again. These are subsets, not 103 unique tests.
- Current multi-asset host suite: 67 passed, including three new close parser,
  digest/role and bounded random-input tests.
- Script-common: eight tests passed; hash parity: four passed.
- xtask: nine tests passed, including actual 11-worker bounded campaign and
  deadline failures. Expected timeout-worker failure logs do not fail that test.
- Eleven mutation targets × 1,000 cases passed; `fuzz.json` records per-target
  acceptance/rejection counts and executable identity. `close-frame` checks
  parsing/commitments/roundtrip, not signature authority or VM execution.
- Core/script-common/xtask all-target Clippy, format and diff checks passed.

Negative VM cases reject ordinary state-vote replay; changed raw capacities or
dependency order; malformed frame/version/reserved/length/signature fields;
missing/cloned/extra/reordered Vaults; payout lock/value/carrier corruption even
with fresh close signatures; newer/different source context; unbound source;
duplicate State; unsigned fee replacement and dirty fee inputs. The conditional
test closes an old Active State using the latest target Batch, rejects a Batch
bound to an older number, and actually fulfills the resulting independent Batch.
The existing suite exercises the unchanged unilateral, splice and Factory paths.

Measured fresh-close samples use simplified fixture wallets/assets:

| Custody | Packed bytes | Observed cycles across three source shapes |
| --- | ---: | ---: |
| CKB | 2,024 | 10,046,487–10,096,294 |
| One token | 2,352 | 9,879,449–10,177,634 |
| Four tokens | 4,587 | 10,805,326–10,893,363 |
| Eight tokens | 7,567 | 12,152,571–12,207,457 |
| Eight tokens, maximum fixture script args | 16,727 | 12,242,223 |

These source shapes are bound Active, older Settling and equal latest Settling.
The maximum-script row uses Active only. These are samples, not worst-case cycle
proofs or real-asset limits. Close does two-party verification in both StateType
and Vault-lock; it can use more cycles than publish+finalise while removing an
intermediate transaction and dispute waiting. Default comparison: CKB uses 2,024
versus the preceding ordinary baseline's combined 3,303 serialized bytes, while
eight tokens use 7,567 versus 11,168. These fixture savings omit real fee wallet
groups and cannot establish production fee savings.

Source hashes were captured after runs, not as clean-source build attestation.
No release, issue closure, native transaction submission, key deployment or new
UI capability was performed. Whole-store rollback remains ADR 003's explicit
assumption. The next dependent work is irreversible host close intent/reservation
before any close signature becomes operationally accessible.
