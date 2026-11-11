# Durable shadow coordination and authoritative session observations

Date: 2026-11-10. W1 #37 implementation checkpoint, not issue closure or release
qualification. All provider mirrors remain diagnostic: `forwarding=false`.

## Implemented behavior

- Morph-owned bounded SQLite projection, exact queued mutations, immutable
  attempts and typed Edge events commit atomically with global expected revision.
- Installed policy/RPC/callback bindings reject accidental reuse under another
  deployment. Public provider messages cannot manufacture local observations.
- Historical retries recover original receipts without restoring old desired
  state. A process restart requires a new canonical observation before enabling.
- Observations expire within 60 seconds. Time regression is rejected; detecting
  expiry/backward time invalidates the process lease until a new observation.
- Expired/retired/unknown edges drain then disable before successor registration.
  Explicit operator draining persists; same-context updates preserve identity.
- Provider revision conflicts cause replanning. Lost responses retain the exact
  request; strict acknowledgements cannot renew or rewrite local observations.
- Capability negotiation finishes before the final pre-send validity check.
  A deliberately delayed real HTTP handshake cannot send expired activation.
- Current-session capture derives the latest private recovery and provenance
  under a short lock, releases before RPC, and rejects journal changes afterward.
  Prepared update/splice/close states drain. Immutable ancestry is bounded at 32.

```mermaid
sequenceDiagram
    participant J as Authoritative signer session
    participant C as Canonical CKB observer
    participant M as Morph coordinator database
    participant F as Diagnostic provider hook
    J->>C: Current recovery and confirmed lineage under short lock
    C->>C: Verify live custody and historical origin
    C->>J: Check unchanged session fingerprint
    C->>M: CAS observation + typed event
    M->>F: Fresh list and capabilities
    M->>M: Persist exact operation; finish handshake; recheck expiry
    M->>F: Send persisted mutation
    F-->>M: Expected-revision acknowledgement
    M->>M: Atomic receipt + event; do not renew observation
    Note over M,F: Lost response: reopen, reobserve, reconcile exact request
```

## Evidence scopes

| Evidence | Result | What it establishes |
| --- | --- | --- |
| CLI all-features unit binary | 333 passed | Existing session/funding/signer/watch/operation regressions |
| Shared packages/events/API/SDK/adapter checkpoint | 80 passed | Typed event schema parity, shared consumers and initial 35 adapter cases |
| Final adapter after handshake/time hardening | 36 passed | Includes delayed handshake expiry; four real SIGKILL boundaries and HTTP success-response loss |
| Scoped all-target Clippy; default CLI Clippy; fmt/diff | Passed | Build/lint/format checks, not complete CI |
| Native CKB six-source run | Passed | Reduced/retained/terminal Factory children; Root and two successive splices; current-session parity |
| Native source binding | 4,143 entries unchanged | Exact before/after source hashes during that native run |
| Existing eight ELF manifest | Matched | No contract changes or rebuild in this checkpoint |

The shared checkpoint includes 35 adapter tests. The final 36-test adapter run
supersedes that subset, for **414 distinct passed tests** across these scopes,
not 449. The CLI/native runs precede the final adapter-only pre-send timing
hardening. That native executable never invokes the coordinator; its exact
source/binary identity remains separately pinned. Do not claim these as one
clean final candidate or as new native provider qualification.

`native-verification.json` retains original private-run filenames and hashes;
the public copies use `native-*` names. `native-source-before.json` equals
`native-source-after.json`. Private transactions, signer journals, database
contents and recovery signatures remain under
`/tmp/morph-shadow-coordinator-session-20261110/` and are not published here.
Only diagnostic observations, source hashes, manifest and test logs are copied.

The response-loss test is a real HTTP server that commits through the shared
provider database and substitutes HTTP 503 for the successful registration
reply. It is not a dropped TCP packet and not a Fiber binary. The four SIGKILL
cuts are after observation, after queue persistence, after provider application,
and after local acknowledgement. Both databases reopen and reconcile to one
provider revision. The delayed-handshake test asserts zero mutation requests.

## Reproduction and remaining work

```sh
cargo test --locked -p morph-cli --all-features --bin morph-cli
cargo test --locked -p morph-packages -p morph-events -p morph-hub-api -p morph-sdk -p morph-fiber-adapter
cargo clippy --locked -p morph-cli -p morph-fiber-adapter -p morph-packages -p morph-events -p morph-hub-api -p morph-sdk --all-features --all-targets -- -D warnings
CKB_BIN=/absolute/path/to/ckb OUT_DIR=/tmp/morph-shadow-fresh-run bash scripts/devnet-shadow-observer-e2e.sh
```

The coordinator is a library, not yet the continuously running canonical
service. Its observation method accepts trusted internal Rust input; callers
must actually perform canonical/current-session verification. Remaining #37
work is that service integration, ownership/readiness, prompt failure/reorg
quarantine and real pinned Fiber + CKB combined restart/fault evidence. The
native matrix does not exercise Factory-child splice or external-child provider
reservations. No forwarding, independent audit, mainnet qualification or
whole-authority rollback detection is claimed. No commit, push, release or issue
closure accompanies this checkpoint.
