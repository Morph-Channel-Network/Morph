# Signer Supervision

`multi-asset-supervise` continuously checks registered authoritative session
files. It reads signer evidence and RPC; it never signs, broadcasts, changes a
journal or unfreezes a context. Signature commands retain their own independent
canonical checks. The supervisor supports root and post-splice lineage guards.
Epoch-0 sessions without a bound chain guard report `unmanaged`. Endpoint
failover and pooled dispute publication remain open.

Build the RPC-enabled CLI with `cargo build -p morph-cli --features devnet`.
Keep one stable session path per channel/signer across funding epochs, as used
by [`confirm-splice`](../multi-asset-splice.md#confirmed-signer-switching).
Retain all referenced retired journals and approved contract artifacts.

## Root funding provenance

Complete the [independent initial funding ceremony](initial-funding.md) on each
signer's stable path. Its `confirm` command seals the initial votes and checks
canonical funding and bound State inclusion before switching the same path to
a guarded operational session. Register it here only after that handoff. The
old operational `init` and `bind-root` entry points are removed.

`refresh-chain` requires an explicit State OutPoint and complete recovery
package and preserves reserved votes, endpoint and depth. Root and splice
origins have distinct required shapes; there is no migration or fallback parser.

`export-root-funding --store-dir /srv/morph/recovery` exports the retained
funding transaction and current exit even while the chain is unavailable or
orphaned. `devnet multi-asset-funding-submit --transaction ... --package ...
--store-dir ... --max-fee ...` validates, preflights and durably saves both before
broadcast; it needs no participant or funding key because the original binary
is already signed. Re-mining it never silently refreshes a signer checkpoint.
After confirming canonical custody, use `refresh-chain` explicitly. Splice
confirmation seals the old root journal and switches the same active path.

## Configuration

```json
{
  "schema": "morph.multi_asset_supervision.v1",
  "sessions": [
    "/srv/morph/signers/alice.json",
    "/srv/morph/signers/bob.json"
  ],
  "poll_ms": 1000,
  "rpc_budget_ms": 3000,
  "stale_after_ms": 10000
}
```

All fields are required. Paths are absolute and cannot contain parent
traversal. There are 1–32 sessions, four concurrent workers, a 100–60,000 ms
poll interval and a 100–10,000 ms total RPC budget per check. The budget applies
across all requests in that check; transport/status retries are disabled.

`stale_after_ms` must cover at least
`ceil(session_count / 4) * rpc_budget_ms + poll_ms`, up to 3,600,000 ms. Allow
margin for local file and signature validation. The health expiry is measured
from cycle start, before any check begins, so a slow cycle cannot renew earlier results
as if they had just been verified. Current v2 snapshots also bind the Linux boot
ID and CLOCK_BOOTTIME start/completion/expiry, including time spent suspended.
Reboot, clock reversal or expiry on either clock makes evidence stale. This is
observation freshness, not whole-store rollback protection. A busy signer lock is sampled without waiting
for the signing operation to finish.

Use distinct configuration, session, health and alert paths. Existing health
must have the current schema; alerts must be a complete newline-terminated
stream with the matching schema. Another schema or a partial final record is
rejected without overwriting/truncating its contents. Missing current fields
are rejected; no compatibility defaults fill previous formats.

## Run and probe

```sh
morph-cli multi-asset-supervise \
  --config /srv/morph/supervision.json \
  --health-file /srv/morph/monitor/health.json \
  --alert-file /srv/morph/monitor/alerts.jsonl

morph-cli multi-asset-supervision-health \
  --config /srv/morph/supervision.json \
  --health-file /srv/morph/monitor/health.json
```

The first command runs until stopped. `--cycles N` performs a finite number of
checks and returns the last snapshot even when it is unhealthy. Use the second
command as the readiness probe: it prints the current health and returns a
failing exit status if any session is unverified or the snapshot is expired.
It checks the exact configured session set/digest and freshness policy; it does
not treat the presence of a health file as a successful probe.

A private stable sidecar lock prevents two supervisors from owning the same
health file. Health is atomically replaced and fsynced; alert records are locked
and fsynced. Both outputs use mode 0600 on Unix. An unreadable journal or failed
check affects that session while the remaining sessions continue to be checked.
Malformed service configuration or an unwritable output stops the service;
the previous health then expires. Restart after a deliberate configuration
change checks the new set before producing matching health.

## States and alerts

| State | Meaning |
| --- | --- |
| `verified` | The complete canonical guard passed for this observation. |
| `busy` | Another operation owns the journal lock; this check did not verify it. |
| `unmanaged` | No canonical lineage guard is present. |
| `blocked` | Journal evidence, canonicality, depth, custody or exit dependencies failed. |
| `unreadable` | The journal could not be opened or decoded as the current shape. |
| `duplicate_authority` | Multiple registered paths claim the same channel and signer, even across funding contexts. |

Only fresh `verified` entries produce healthy readiness. A temporary busy check
is quiet and retains the prior stable state for deduplication. New stable
failures produce critical `guard_blocked` or `authority_conflict` records;
recovery produces `guard_recovered`, and a verified funding-context change
produces `context_changed`. Repeated unchanged failures stay quiet across normal
restarts. Alerts are at-least-once: a crash after appending an alert but before
saving health may repeat that transition. Messages and metadata contain no
signing keys.

After a reorg, the supervisor does not refresh a journal on its own. Follow the
exact replay/activation and `refresh-chain --package` procedure in the splice
runbook. Re-mining a transaction does not silently replace its stored canonical
inclusion. Once a context's Vaults are consumed, the active signer reports
blocked; reconcile its lifecycle and remove it from the active monitoring set
when appropriate. Terminal abort tracking is not yet automated.

## Evidence

Unit checks cover stale/future health, exact configuration binding, busy-state
history, restart deduplication, duplicate authorities, nonblocking journal locks,
unmanaged roots and output alias protection. Existing watch-alert tests also
cover the shared append-only stream's schema/tail and permission boundaries.

An isolated-node run supervised two real signer files through healthy checks,
a held journal lock, reorg, restart, keyless exact replay, explicit refresh,
recovery, process-stop expiry and final settlement. It produced two reorg alerts,
two recovery alerts and two closure alerts, while leaving signer journals
unchanged except for the explicit refresh commands. Evidence:
`target/multi-asset-devnet/splice-supervision/supervision-report.json`.


## Redacted scoped observations

```sh
morph-cli multi-asset-supervision-readiness \
  --config /srv/morph/supervision.json \
  --health-file /srv/morph/monitor/health.json

# Same command and paths, with --metrics for fixed Prometheus text.
```

This emits the shared `Readiness` DTO for service `signer_supervisor` and scope
`authority_supervision`. The existing detailed health command remains the private
operator diagnostic. The new report exports no journal paths, public keys,
funding-context IDs or raw errors. Its sole configured scope reflects all
registered contexts: fresh verified entries pass; busy, unmanaged, blocked,
unreadable or duplicate authority entries fail. `channel_signing` is explicitly
unsupported in this report. A recent successful chain guard does not prove that
the external key process is running, has approved a request or will sign.

The command observes only saved current evidence and returns nonzero when unready;
it never refreshes or initializes a signer journal, sends a signing request or
changes the supervisor snapshot. Reads have a 2-second observation budget. It
checks freshness again at response construction so time spent reading cannot
renew a lease. Files must be bounded regular files; symlinks and named pipes are
rejected. Eight fixed metric series show readiness, observation availability and
six status counts. Stale/missing status counts are `NaN`, never a fabricated zero.

`morph.multi_asset_supervision_health.v2` is the sole current snapshot shape;
boot-clock fields are mandatory and v1 is rejected. During this predeployment
update, stop the supervisor, retain the old health/alert evidence separately, and
start a new health output path. Do not delete or restore participant journals.
Old observation data is never converted into signing authority. A finite
`--cycles` run produces expiring observations, not a continuously live worker
claim; after SIGKILL the existing evidence expires without needing a clean stop.
