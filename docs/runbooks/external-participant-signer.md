# External participant signer: controlled-devnet operation

The isolated service and seven caller roles are implemented. The new
`cooperative_close` role has separate [execution evidence](../evidence/cooperative-close-execution-2026-11-10/README.md)
and a [close runbook](cooperative-close.md). The original six-role evidence follows. The real-node runner
covers all six roles with unavailable service, expiry, signed-response loss and
fresh-process retry. Separate controlled-RPC tests cover 42 combined host/key
fault scenarios (three SIGKILL cuts, three bad-response cases and authority
advancement for each role), plus 48 targeted persistence I/O failures. They do not emulate kernel power loss or replace the
remaining #43 runtime/fuzz campaign. Integrated candidate qualification remains
open; this is not mainnet or real-asset approval. See
[ADR 003](../adr/003-participant-signer-boundary.md).

## Ownership and provisioning

Retain one stable journal per participant/channel across root funding and later
same-path handoffs. The ceremony process remains its sole writer and holds the
existing sidecar lock across signing. The key service reads that **same existing
journal**, independently verifies its persisted reservation and canonical request,
and never initializes, changes, restores or migrates authority.

Run both processes under the same dedicated Linux account. The socket checks
kernel peer credentials; journal/config files must be owner-only `0600`, their
immediate directories `0700`. Symlinks, hard-linked files, unsafe ancestors and
special files are rejected. Keep the Unix socket path short enough for Linux's
filesystem socket limit. The key file uses the existing protected-key loader
(`0600` or `0400`). There are no raw key argv/env inputs.

Root and same-account processes are trusted. This isolates key ownership between
processes, not against a malicious same-UID process. Do not clone or roll back the
active journal, and do not provision a second independent journal for this key and
channel. An old consistent journal is not detected by local hashes or this service.

Create a private config with exactly these fields:

| Field | Required value |
| --- | --- |
| `schema` | `morph.participant_signer_config.v1` |
| `socket` | Absolute private filesystem Unix socket path |
| `journal` | Absolute canonical existing funding/session path; no caller-selected override |
| `rpc_url` | Pinned HTTP(S) endpoint, no credentials/query/fragment; must match journal admission/lineage |
| `expected_pubkey` | Canonical `0x`-prefixed 33-byte compressed participant key |
| `network_genesis` | Canonical 32-byte CKB genesis hash, independently checked on the pinned RPC |
| `chain_id` | Signed Morph application chain ID; do not infer it from an untrusted request |
| `channel_id` | The exact channel authorized by this service |
| `deployments` | 1–16 approved objects, each containing `state_type`, `state_lock`, `vault_lock`; each code identity has canonical `code_hash` and numeric `hash_type` |
| `targets` | Explicit nonempty subset of `root_exit`, `root_creation`, `update`, `splice_creation`, `splice_recovery`, `splice_bridge`, `cooperative_close`; duplicates rejected |

Use the reviewed local journal and approved deployment manifest when preparing
this policy. A code hash is the script's code identity, not the hash of its entire
args-bearing Script. This configuration grants signing scope; copying untrusted
request fields into it would defeat the boundary. It contains no private key.

The service loads policy once at startup. Stop it before changing policy, preserve
the journal and recovery packages, review the replacement, then restart. The host
loads its selected configuration for each signing command; a different file does
not change the running service's installed policy.

## Start and sign

Use the RPC-enabled devnet build for current channel lineage checking:

```sh
cargo build -p morph-cli --features devnet
target/debug/morph-cli participant-signer-serve \
  --config /srv/morph/alice/signer.json \
  --private-key-file /srv/morph/keys/alice.key
```

Run the service under your supervisor. It processes one request at a time and
continues after bounded idle waits or rejected requests. `--once` handles one
request and exits, for supervised activation/testing. It does not create a journal
or remove an existing socket on startup. After an abnormal termination, establish
that the old process is stopped before removing its stale socket; never remove the
signing journal's `.lock` file.

In the separate ceremony process, review the current intent first. Then:

```sh
target/debug/morph-cli multi-asset-funding-session \
  --session /srv/morph/alice/session.json sign --target exit \
  --signer-config /srv/morph/alice/signer.json
# Exchange/persist both exits before selecting --target creation.

target/debug/morph-cli multi-asset-session \
  --session /srv/morph/alice/session.json sign --target update \
  --signer-config /srv/morph/alice/signer.json
```

The normal `sign` command accepts no participant key option. The service must
match the session path and local public key. Splice uses the same `sign` command
with explicit `splice-creation`, `splice-recovery`, then `splice-bridge`; both
future authorizations remain prerequisites for bridge signing. Root creation
still requires a complete bound initial exit. There is no new bootstrap or
old-context unfreeze path.

For explicit local development only, the devnet build exposes:

```sh
target/debug/morph-cli multi-asset-session \
  --session /srv/morph/alice/session.json sign-local --target update \
  --private-key-file /srv/morph/keys/alice.key
```

There is no alias preserving the old local-key `sign` form and no automatic local
fallback. Builds without the devnet feature reject local participant signing.
Factory/child authority, wallets, Sponsor funding and release signing have their
own existing roles; this seven-target service cannot sign those digests. Watch and
keyless publication commands do not obtain a participant signer handle.

## Deadlines, RPC and recovery

The client creates a maximum-30-second request after persisting its reservation.
Request construction and socket exchange share a total budget. The service shares
its remaining I/O budget with a one-attempt RPC client, capped at 4 MiB per
response. This accommodates the standard 1 MiB secp dependency after RPC hex
encoding and JSON overhead; a 2 MiB cap rejects that valid cell. The independent physical-input review uses `get_live_cell` with
canonical-only outputs and no data, checked genesis, exact count/order and a
stable tip across the scan. Missing/spent inputs, changed genesis or advancing tip
fail closed; retry only the same authorized intent after fresh review.

Socket deadlines do not force-cancel a blocked filesystem or arbitrary library
operation. The service checks its remaining budget, expiry and journal snapshot
again before key use. This is not a stronger atomic chain-snapshot guarantee than
the underlying canonical RPC checks. Existing watcher/reorg assumptions remain.

| Result | Required action |
| --- | --- |
| Verified receipt returned | Host already recorded and fsynced it; deliver through the existing ceremony |
| Cached receipt | Same prior valid authorization, no new external call needed |
| Timeout/disconnect/invalid reply | Preserve journal and reservation; signing may have happened; never choose a conflicting intent based on missing receipt |
| Exact retry | Reload the same journal and run `sign` again; request ID/expiry may refresh but durable target/digest cannot be reset |
| Request expired | No new issuance from that request; an already issued valid signature remains authority |
| Service rejected authorization | Check installed key/channel/deployment, exact journal, live lineage/admission and complete exits; errors intentionally omit request bodies |
| Corruption or lost journal | Stop signing, preserve evidence and independently saved recovery packages; restoring an old active snapshot is not recovery |
| Chain reorg/consumed context | Use the existing guarded reconciliation/recovery procedures; do not change config to bypass lineage |

The service keeps no second signature counter or approval database. Replaying an
identical, unexpired request matching the same persisted reservation can reproduce
the same signature; it cannot create a different vote. Changed payloads, stale
contexts, disallowed roles and expired requests are rejected. Recovery package
backups remain essential and do not replace the journal.

Never log request bodies, private exits, keys or preimages. Service diagnostics
use fixed strings; typed Debug output omits bodies and unvalidated identifiers.
The test evidence directory records only hashes/results and synthetic test data.

## Reproduce the controlled native checkpoint

```sh
CKB_BIN=/absolute/path/to/ckb scripts/devnet-external-signer-e2e.sh
```

The runner requires `jq`, Python, the current manifest-matched eight ELFs and
protected devnet fixture files from the sibling Fiber checkout (override
`FIBER_DIR` or the documented `*_PRIVATE_KEY_FILE` paths). It builds the current
CLI, uses fresh private output under `target/participant-signer-e2e/`, starts its
own node on ports 19964/19965 (override `RPC_PORT`/`P2P_PORT`), and terminates only
that node. Do not point it at real assets or modify source during the run.

Each of the six targets is exercised with `--signer-faults`: unavailable service
after durable reservation, rejection of an expired but correctly identified
request, deliberate loss of a signed response, exact retry in a fresh CLI and
key-service process, then cached receipt retrieval in another CLI with no signer.
The JSON evidence checks role counts, distinct caller/service PIDs, unchanged
reservation bytes after rejection/loss and unchanged bytes on cached retrieval.
The normal native smoke paths use the same external caller/service commands;
`--signer-faults` only adds the explicit failures.

`verification.json` hashes the copied CLI, reports, manifest and before/after
source inventories. It records a dirty worktree honestly and checks existing
ELFs against the manifest; it does not rebuild contracts or run all release gates.
Secret fixture copies and transient IPC configuration/key files are cleaned up.
Keep the output private: recovery packages and signer journals are not public
publication artifacts. Public process observations contain role/digest/identity
and result metadata, never signature bodies or private keys.

Rejection diagnostics expose only fixed categories (policy, protected authority
read, canonical authority, canonical review, or generic authorization); inner
RPC/payload errors are not printed. Investigate via the installed configuration
and ordinary protected session inspection, without enabling payload logging.

## Reproduce the combined signer fault matrix

```sh
cargo test -p morph-cli --all-features multi_asset_funding_session::tests::fault_tests
cargo test -p morph-cli --all-features multi_asset_session::tests::fault_tests
cargo test -p morph-cli --all-features multi_asset_session::tests::canonical_fixture
```

These Linux tests start actual host/key subprocesses and bounded controlled RPC
servers in private temporary directories. The normal CLI has no fault-control
environment switches; pause/key-use hooks are compiled only in test binaries.
A passing test preserves the same live journal across failures and starts fresh
processes for retries. It must never restore an older active journal to make a
failure reproducible. No contract ELFs or running CKB node are required for this
controlled-RPC matrix; use the native runner above for actual chain evidence.

The same fault-test commands now compile a small C interposer with `cc` for the
48 I/O cases. It runs only in owned host test subprocesses. File write/sync and
rename failure do not acknowledge success. Directory-sync failure may occur
after rename, so inspect/reconcile the canonical journal and retry the exact
intent; do not restore a prior journal or infer from the error that no new state
was installed. This is syscall-error evidence, not simulated machine power loss.

## Read-only key-process policy readiness

```sh
morph-cli participant-signer-readiness --config /srv/morph/alice/signer.json
morph-cli participant-signer-readiness --config /srv/morph/alice/signer.json --metrics
```

The probe contacts the **same private socket and serial request loop** used for
signing. It does not construct a vote, reserve a state number, read/write a journal,
contact CKB or use a private key. At startup the service already validates the
loaded key against the installed public key. A fresh random challenge binds the
reply to this connection; a domain-separated digest covers all protected config
fields, including allowed roles, network/deployment pins, journal and endpoint.
The service re-reads its configuration and the caller rechecks its own pin before
reporting a match. Changes require the documented reviewed restart; this is not
policy hot reload. Same-account/root trust still applies: this observation is not
anything stronger than the existing local process trust boundary.

The current `morph.participant_signer_readiness.v1` JSON names only the
`key_process_policy` scope. `responsive` distinguishes a timely negative policy
reply from unavailable/expired evidence; `policy_ready` additionally requires a
matching installed/current policy. No aggregate channel-signing readiness is
claimed. Combine this dependency with actual canonical context supervision,
intact journal/reservation checks and request-specific validation. A policy probe
can succeed while a journal is absent or the chain is unavailable, deliberately.
It must never be used as authorization or a substitute for those dependencies.

The total observation budget is two seconds from start, including configuration
reads and socket exchange. Wall and Linux boot clocks reject backward time,
suspend/expiry and reboot changes. There is one worker per CLI invocation and no
automatic retry or replacement worker. Slow filesystem calls cannot be forcibly
cancelled, but their late results cannot refresh readiness. The two-second bound
is a local observation policy, not a production signing-latency objective.

JSON mode prints the redacted report and returns nonzero unless policy-ready.
Metrics mode returns two fixed gauges, `morph_signer_responsive` and
`morph_signer_policy_ready`, with no labels or private identifiers; unavailable
evidence is zero. Protect command execution and config access with the service's
existing OS account boundary. There is no network exporter or anonymous socket.
An expired result must be probed again, not re-timestamped. `--once` on the service
counts a probe as its one handled message and then exits; use continuous mode for
normal monitoring. Do not busy-loop scrapes on the shared serial signing queue.

| Signal | Action |
| --- | --- |
| Responsive, policy denied | Review config drift and approved targets/pins; stop and restart with the reviewed policy, preserving the journal |
| Unavailable or stale | Check process and socket ownership, active signing work, I/O and queue pressure; no new conflicting intent or reservation reset |
| Clock invalid | Repair the observation environment and probe again; do not edit timestamps |
| Policy ready, context supervision unready | Resolve the canonical context/authority issue; the key process being available does not make the channel safe to mutate |

The real CLI regression uses an unavailable RPC and absent journal to demonstrate
this boundary, then occupies the actual socket, changes policy, kills the service
and verifies restart recovery. Transport tests reject replayed challenges, wrong
policy replies, signature-shaped replies, malformed frames and hangs. These are
host/process tests, not additional native-chain or deployment qualification.
