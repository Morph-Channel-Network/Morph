# ADR 003: participant signer review, transport and authority boundary

Status: implementation and qualification in progress for #31 / #55, 2026-11-10.
Request review, private IPC, the isolated key service and the original six caller
roles are implemented. ADR 005 adds the seventh `cooperative_close` role and its
separate exact-body journal/chain checks; see the close execution evidence. All six roles now have real-node acceptance, including unavailable
service, expired requests, signed-response loss, fresh caller/service restart and
cached receipt recovery. The six-role combined host/key fault matrix is also implemented;
remaining integrated candidate qualification is listed below.
Neither issue is complete. The original six-role signer work changed no consensus
encoding or domain; the later cooperative-close capability deliberately adds its
own `MORPHMC!` frame and `CKB_MORPH_MULTI_ASSET_CLOSE_V1` domain under ADR 005.

## Selected freshness assumption

The first isolated implementation retains **one intact, non-cloned participant
authority** and the existing monotonic journal. Ordinary crash recovery must
preserve every reservation. Restoring an older active journal or running a cloned
authority is prohibited. This is an explicit storage/operating assumption, not a
cryptographic guarantee of freshness. The runtime SQLite database is not a source
of participant authority.

A hash chain, encryption, fsync or a separate process does not detect rollback of
an entire consistent store. One honest participant restored to an old snapshot,
combined with a malicious peer, can authorize conflicting allocations at the same
number. Both parties do not need to roll back. The new executable Core test
`multi_asset_backend_whole_consistent_snapshot_rollback_is_not_detectable_locally`
demonstrates two valid packages for the same custody and number. It does **not**
demonstrate consuming a CKB cell twice or claim an exploitable deployed service.

The contrasting test
`multi_asset_backend_reserved_but_unrecorded_vote_survives_restart` reopens the
intact post-reservation snapshot, with no saved signature. A conflicting proposal
fails; the exact original intent can be retried. Snapshot decoding tests already
reject inconsistent/corrupt reservations. These are different failure classes.

| Event | Required behavior / evidence | Freshness claim |
| --- | --- | --- |
| Crash before reservation is durable | No key use or released signature | Existing reserve-before-sign rule |
| Signed response lost | Keep reservation; reconcile/retry only original intent | Intact journal prevents a conflicting vote |
| Crash after recording but before receipt delivery | Return the saved verified receipt | Idempotent delivery, not another approval |
| Corrupt snapshot | Fail closed; preserve evidence and saved exits | Corruption detection only |
| Complete old snapshot or cloned authority | Do not provision/restore it as an active signer | Cannot be detected by local consistency alone |
| Future independent high-water service/HSM | Separate protocol, ownership and crash proof required | Not implemented or assumed here |

This bounds #55A without pretending #55B's full capability/custody/evidence matrix
is complete. Any later requirement to tolerate hostile whole-store rollback needs
an actual independent freshness source and an explicit authority transfer design.

## Request and review contract

`morph-packages::signer_protocol` contains one versioned request/response shape.
The canonical existing package, proposal and transaction validators remain the
only protocol implementation. A temporary Core backend used for validation has
**no durable authority** and must never be treated as a new active journal.

| Target | Signed role | Required canonical evidence |
| --- | --- | --- |
| `root_exit` | Ordinary state vote for the exact initial exit | Root collection and exact funding transaction |
| `root_creation` | Root-funding domain | Same body plus complete initial exit authorization |
| `update` | Ordinary state vote | Signed current package and valid monotonic proposal |
| `splice_creation` | New-state vote | Current package and exact splice draft |
| `splice_recovery` | New initial-exit vote | Current package and exact splice draft |
| `splice_bridge` | Old-context bridge domain | Exact body plus both complete future authorizations |
| `cooperative_close` | New close domain | Exact source/body, latest saved complete allocation, irreversible close reservation |

The request binds its version, expected key, network genesis, expiry, target and
canonical payload. A domain-separated CKB-personalized digest identifies the
complete serialized object after sorting object keys and clearing `request_id`.
Changing the expiry changes that transport ID. **A request ID is not the durable
vote identity**: new transport metadata cannot grant another signature at a
reserved coordinate. The integration maps it to the existing journal's exact target/digest and
irreversible splice reservation.

The signer derives, rather than trusts, the displayed chain/channel/funding
context, epoch/number, deployed script identities, participants, payout locks,
carrier/refund lock, per-asset allocations and conditional terms. Splice-bridge
review distinguishes its old signing context from resulting new custody. Physical
transactions include their exact hash, ordered inputs, output capacities and
lock/Type/data hashes, total input/output capacity and fee.

Physical input capacities come only through an independently configured
`InputResolver`, with exact input order/count and pinned genesis checked. The CLI
resolver uses the existing RPC client with one total budget, no retries and a
4 MiB response ceiling. It requests canonical live outputs, rejects missing/spent
inputs and rejects a changed tip during the input scan. Initial protocol tests
use a controlled resolver; the root process unit test uses explicitly installed RPC outputs, while the
separate native runner exercises actual CKB dependencies and canonical inputs. A header's application `chain_id` is not silently equated with
the CKB genesis hash. State updates have no physical transaction; this validator
does not replace live lineage/admission checking for them.

The caller cannot supply its own trusted policy: allowed deployment identities,
key, chain, genesis, target set and maximum request lifetime are out-of-band inputs.
Before a real service uses a key it also needs installed channel/operation
authorization, live lineage/admission and deadline checks. `Request::validate`
alone does not establish user consent or journal freshness.

Responses bind the original request ID, target, expected key and exact digest and
reuse the current canonical secp256k1 receipt verifier, including high-s rejection.
There is no response field for replacing a transaction. Issuance must stop at
expiry; an already issued signature remains authority after expiry and must still
be retained and reconciled.

Unknown roles fail closed. Factory authorization, wallet fees, Sponsor funding
and release signing are **not** aliases for participant votes. The first six-role
contract supplies none of those key capabilities. Existing keyless watch and
Sponsor publication paths gain no signer handle.

## Implemented Linux IPC

`morph-signer::ipc` owns no keys or journal. The CLI's
`participant-signer-serve` command owns the key in an independent process, using
this library and the existing journal validators. Its installed config fixes the
socket, one absolute stable journal path, RPC, key, channel, network, deployment
allowlist and targets. Requests cannot select another journal or install policy.

| Boundary | Current implementation |
| --- | --- |
| Address | Absolute filesystem Unix socket; no TCP or abstract socket |
| Filesystem | Owner-only `0700` parent, `0600` single-link socket; no symlink path components; controlled ancestors |
| Authentication | Kernel peer credentials must match the effective UID on both ends |
| Trust scope | Root and same-account processes remain trusted; this is not hostile same-UID isolation |
| Framing | One four-byte big-endian length and JSON body per connection direction; half-close required; trailing bytes rejected |
| Bounds | Request ≤ 1 MiB, response ≤ 4 KiB; zero-length/oversize rejected before body allocation |
| Timing | All socket I/O nonblocking; one monotonic total I/O budget, capped at 30 seconds |
| Concurrency | One accepted request per listener; an `Incoming` borrow prevents another acceptance; small kernel backlog |
| Retry | No automatic reconnect or retry; after an attempted write, I/O failures report unknown outcome |
| Cleanup | Bind never removes an existing endpoint; drop removes only its own unchanged socket inode |
| Diagnostics | Fixed transport errors; request/response Debug omit canonical bodies/signatures; raw frame buffers zeroize on drop |

Nonblocking Unix connection establishment can report EAGAIN when it cannot finish
immediately; the client returns unavailable/busy rather than retrying implicitly.
See the [Linux connect manual](https://man7.org/linux/man-pages/man2/connect.2.html).
The monotonic budget covers socket activity; it is not a guarantee against a hung
filesystem syscall, arbitrary user validation code or future blocking RPC. The
service must bound those separately and use `Incoming::remaining()` to share its
remaining budget. Wall-clock request expiry must be rechecked before key use.

Independent child-process tests send the **existing public fixture signatures**
through the real socket. They prove receipt transport and response-loss handling,
not an isolated key custodian or durable signer restart. Further tests cover
permissions, symlinks, replaced endpoints, partial/trailing/oversize frames, slow
senders, wrong-target replies and a silent peer. No fixture private key is added
to a production input path.

## Implemented authority integration

```mermaid
sequenceDiagram
    participant C as Existing ceremony owner
    participant J as Sole participant journal
    participant S as Isolated signer service
    participant K as Protected key
    C->>C: Review canonical intent; check lineage/admission
    C->>J: Reserve exact target/digest
    J-->>C: Fsync complete
    C->>S: Versioned request over bounded private IPC
    S->>S: Authenticate; derive review; validate installed policy and deadline
    Note over C,S: Preserve one intact authority; request metadata never resets a vote
    S->>K: Sign only the authorized exact digest
    K-->>S: Signature
    S-->>C: Bound response (may be lost)
    C->>C: Verify response against frozen request
    C->>J: Record signature and fsync
    C-->>C: Release receipt
    Note over C,J: Timeout or missing receipt never removes the reservation
```

The host's `sign --signer-config` path uses the same reservation/record branches
as the explicit `sign-local` development path. Local signing is rejected outside
the devnet build; it is not a fallback when the service is unavailable. Factory,
child, wallet and publication roles are not silently routed into this protocol.

The service opens the configured owner-only journal read-only. Root must already
have the exact target reservation and future exit prerequisites. For a channel,
re-running the existing reservation function on a disposable clone must be a
no-op. This checks the actual engine's rules instead of duplicating its counters
or seal state. The reconstructed canonical payload and local key must exactly
match the request. Live admission/lineage checks use the installed RPC; the
service rechecks snapshot bytes and both deadlines before using its key. It never
writes, initializes, resets or hands off a journal. The host remains the sole
writer and holds its existing sidecar lock across the call.

The process test now uses a real signing key loaded only from a protected file
inside the child process. It rejects an unreserved root, produces a signature
whose response is discarded before caller recording, then restarts and retries
the same persisted reservation through the real host command. It also signs root
creation after full exits are available. The node is a bounded RPC fixture, so
this is not native chain acceptance. Earlier IPC fixture-only tests remain
separate evidence.

## Real-node and process evidence

`scripts/devnet-external-signer-e2e.sh` builds one CLI and starts a new controlled
CKB node. Its root/update/splice scenarios use the normal public host CLI in
separate processes and the same binary's key service. The harness owns devnet
fixture keys; it is not a demonstration of hostile isolation from that harness.
Only protected key-file paths are passed to child processes.

| Role | Completed attempts | Per-attempt injected failures / recovery |
| --- | ---: | --- |
| Root initial exit | 4 | Unavailable service, correctly identified expired request, response loss after key use, fresh-process exact retry, cached receipt without a service |
| Root creation | 4 | Same |
| State update | 2 | Same |
| Splice creation | 4 | Same |
| Splice initial recovery | 4 | Same |
| Splice bridge | 4 | Same |

The 2026-11-10 run at
`target/participant-signer-e2e/20261110T043343-86246/verification.json` passed:
22 role attempts, 66 service processes (44 reach key use, 22 reject expiry),
44 distinct successful/cached caller processes. The unavailable-service caller
also exits before the retry. No saved journal is restored or cloned to simulate
restart. Each error/loss leaves the durable reservation unchanged; normal retry
records through the existing host path. A final fresh caller retrieves the exact
receipt with no listener and leaves journal bytes unchanged.

For response loss the harness deliberately reads only the response length after
the service signs, discards the body, then starts a fresh caller. This is a real
socket loss and key-service restart test, not a SIGKILL at every host instruction.
Authority advancement during review and application-level host kill cuts now have
the separate controlled-RPC combination evidence below; kernel fsync/power-loss
and the broader runtime #43 matrix remain distinct. Malformed/oversized replies, role/context substitution and
slow/silent peers have separate protocol/IPC tests; do not label those as all
being injected into this native runner.

The native scenario includes shared funding reorg/exact replay, state publication
and finalisation, asset removal/admission splice and withheld bridge receipt
reconciliation. Before/after source fingerprints match; the built CLI and all
reports are hashed, and all eight copied ELFs match the existing manifest. This
is an unchanged **dirty worktree** checkpoint, not a clean release or rebuilt
contract qualification. The first attempt failed at a legitimate 1 MiB secp data
cell: RPC hex+JSON was 2,097,566 bytes. The signer RPC ceiling is now 4 MiB, with
its shared deadline and one-attempt policy preserved and a regression test.

### Root authority/host-crash combination checkpoint

The controlled-RPC test `multi_asset_funding_session::tests::fault_tests` now
exercises both RootExit and RootCreation through actual host/key subprocesses:
three SIGKILL cuts (after fsynced reservation, after receiving a valid signature
but before recording, and after fsynced receipt), plus malformed JSON, oversized
framing and a cryptographically valid receipt labelled for the wrong role.
Each failure retains the reservation. Crash recovery and cached-return checks
start fresh host processes; the recorded cut needs no key service and leaves
journal bytes unchanged. No old authority snapshot is restored or cloned.

For each root role a separate race pauses the key process after authorization,
then adds a valid peer receipt through the ordinary journal command. That is a
legitimate forward change. The post-review reread rejects before a test-only
key-use marker can be written; the advanced journal remains intact and a fresh
review can complete the same reserved role. Fourteen injected scenarios cover
the two root roles. Checkpoints exist only under `cfg(test)`; the normal/devnet
binary has no environment-controlled pause or key-use instrumentation.

This does not extend the native six-role acceptance claim: the RPC peer is a
controlled live-cell fixture. The update/splice extension is recorded below; the
remaining #43 runtime/fuzz matrix is not completed by these signer tests. The tests do not inject a kernel power
failure inside fsync/rename and do not demonstrate detection of whole-authority
rollback. Existing persistence tests and the explicit intact-authority assumption
remain distinct evidence.

### Update and splice combination checkpoint

`multi_asset_session::tests::fault_tests` adds the same seven fault families for
Update, SpliceCreation, SpliceRecovery and SpliceBridge: **28 injected scenarios**
across three matrix tests, plus a child-process entrypoint. Both new-context
creation and initial-recovery authorizations are collected normally before the
bridge matrix. All host calls use the production command path with canonical
lineage checking; they do not use the older test wrapper that skips that guard.

The fixture supplies exact committed transaction status, block contents, current
Vaults and complete code dependencies through a bounded controlled RPC server.
It confirms the same-path root handoff before preparing updates/splices. Real
hashes and canonical serialization are checked; this is not CKB-VM execution or
an assertion that those synthetic blocks are valid on a real chain. Three
additional negatives remove canonical inclusion, spend a Vault or remove a code
dependency; independent external authority review rejects each and preserves the
saved reservation. Historical State inclusion alone is not a claim that the
original State output remains live after subsequent supersession.

For all four roles, a new host process recovers each SIGKILL cut. Cached receipts
need no signer and leave journal bytes unchanged. Malformed/oversized/wrong-role
replies preserve the same reservation; a real signer retry succeeds. A valid peer
receipt advances the journal while the key service is paused after authorization;
the final authority reread rejects before key use, and a fresh review completes
normally. No old authority is restored, cloned or unsealed. These tests plus the
root matrices cover **42 signer fault scenarios across all six roles**; the
three chain-guard negatives are separate from that count.

### Six-role persistence I/O failures

The Root and session fault modules also run **48 syscall-injected scenarios**:
six roles × reservation/receipt persistence × write ENOSPC, file fsync EIO,
rename EIO and post-rename directory fsync EIO. A test-only C interposer is loaded
into owned caller subprocesses, scoped to that caller's journal temporary files
and parent directory. Each test requires an injection-hit marker, so a changed
syscall path cannot silently make the negative test pass. No hook is compiled
into the ordinary CLI.

Before reservation persistence succeeds, a private listening socket observes no
external signer connection. Before-rename failures leave the canonical old file
unchanged. A directory fsync failure can follow a successful rename: the caller
still fails, but recovery reads the new canonical journal rather than restoring
the old bytes. Receipt-write failures after signing retain the same reservation;
a fresh caller retries the exact digest, or reads the saved receipt without a
signer if rename had already installed it. Leftover temporary files never become
authority, and the stable journal lock is not removed.

These 48 cases supplement the earlier 42 process/protocol cases: **90 declared
signer fault scenarios**, not kernel power-loss proof or whole-store freshness.
The existing runtime-store fsync/ENOSPC subprocess tests are separate evidence;
no claim that every payment/outbox/operation persistence boundary is covered.

### Acceptance mapping for issue #31

This is a local source/evidence mapping, not issue closure or release approval.
The GitHub checklist was reread on 2026-11-10.

| Acceptance item | Implementation and executable evidence |
| --- | --- |
| Root/update/splice ordering | Funding/session `Sign`, existing atomic persistence, six-role native runner and both combined fault modules |
| ID/key/digest/role/context/canonical encoding | `signer_protocol::tests::all_six_targets_rederive_the_existing_exact_digest_and_verify_original_receipts` and `summaries_policy_context_and_deadlines_cannot_substitute_for_payload_validation`; includes high-s rejection |
| Derived summaries / frozen body | `changing_any_frozen_physical_body_invalidates_the_existing_review_and_receipts`; `creation_and_bridge_require_complete_future_exits_and_role_shapes_are_closed` |
| Authority separation | Closed six-target enum and approved deployment/channel policy. Factory/child N-of-N or touched-member authority, wallet fee inputs, Sponsor funding and release signing retain separate APIs. No external Factory/HSM support is claimed or implicitly granted |
| Unknown outcome / no unseal | Six-role native signed-response-loss/retry evidence and 42 process/protocol cases plus 48 syscall I/O failures; journals never reset on missing receipts |
| Watch profiles / local development | `watch_profiles_reject_participant_keys_and_signer_handles_at_every_level`; ordinary `sign` accepts only signer config, `sign-local` rejects use without devnet support, no local fallback |
| Negative protocol and IPC cases | Package negatives above; `morph-signer` private-endpoint, bounded frame, total-deadline and response tests; combined malformed/cross-role/advance/SIGKILL cases |
| Secret-safe diagnostics and custody runbook | Redacted request/response Debug; `rejection_diagnostics_never_format_inner_payloads`; fixed rejection categories, private files/socket, recovery instructions in the runbook |

Outstanding before #31 closeout:

1. Bind the integrated source, ordinary CLI, native acceptance and regression
   results to the eventual reviewable candidate. The current evidence windows
   are explicitly dirty-worktree checkpoints, not immutable release evidence.
2. Keep the larger #43 fuzz, I/O-failure, payment/edge/operation/outbox crash
   campaign separate. The signer-specific combined matrix is complete for the
   declared seven application-level fault families, not every possible fault.

Deployment, explicit local development selection and recovery procedures are in
[the external participant signer runbook](../runbooks/external-participant-signer.md).

No test in this checkpoint requalifies an ELF, enables forwarding or expands the
no-value development envelope. #31 and #55 remain open.
