# Cooperative-close Core journal checkpoint

Core now owns exact-body close proposals and the close state in the existing
participant backend. The host payout builder has been moved out of the CLI and
is shared by ordinary finalisation and close review. There is no alternate
settlement codec or legacy backend reader.

The required `close` snapshot field holds bounded approval history. Preparation
uses the latest complete saved recovery; it cannot substitute a caller's older
allocation. Reservation freezes updates/splice/cancellation even without a saved
receipt. Receipt operations identify an exact transaction hash. Replacements
keep the source and settlement, retain every old approval and require fresh
signatures. At most 32 bodies of at most 128 KiB each are accepted by Core; history
exhaustion never resets authority. Existing CLI file limits are a separate bound.

`verification.json` and logs record:

| Check | Result |
| --- | --- |
| Current multi-asset host tests | 74 passed, including seven new journal cases |
| CLI binary, all features | 307 passed, including existing six-role process/I/O regressions |
| Complete rebuilt CKB-VM suite | 100 passed |
| Host/VM tests after clarifying snapshot test name | Two passed again; already included in the 100 |
| Hash parity | Four passed |
| Core + CLI Clippy | All features/all targets passed |
| Deterministic contract build / manifest | All eight verified |

The new source/target predicate is shared between host and verifier. Extracting
it changed the StateType/Vault-lock ELF hashes despite unchanged binary sizes
(190,856 and 172,360 bytes). The remaining six hashes are unchanged. The current
manifest was refreshed; this checkpoint's copied manifest and logs are distinct
from the preceding verifier checkpoint. Old native-deployment evidence does not
qualify these new identities.

Journal tests cover pre-reservation cancellation, crash-like snapshot roundtrip
after reservation and recording, exact receipt retry, blocked ordinary/splice
signing, wrong-body signatures, retained old approvals, source replacement,
missing required fields, inconsistent local reservation, duplicate history,
history capacity and explicit whole-store rollback limitation. Actual VM tests
consume the Core-exported witness for one/eight-token retirement and conditional
Batch fulfillment. Snapshot roundtrip is **not** a process kill or fsync test for
the new close role. Existing CLI process tests still exercise their old six roles.

Pending work: integrate the close role with private OS-locked/fsynced session
files, independent key service, canonical input resolver and full VM preflight;
bound serialized session history against the current 512 KiB file ceiling;
implement native transaction/reorg reconciliation and API/SDK/desktop operations;
qualify the final candidate. The proposal validator checks committed output/body
geometry, not live RPC provenance or actual external fee input values by itself.
No operative close-signing command is exposed yet.

Evidence was captured from a dirty working tree after testing. Source hashes
identify what was inspected, not a clean-source build or independent audit.
No commit, push, release, issue closure or native close submission occurred.
