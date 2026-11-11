# Exact transaction recovery and observation

The current `devnet multi-asset-close submit` adapter registers fully signed
transactions in a private runtime store. Other transaction commands have not yet
been migrated to this shared lifecycle. This is no-value development support.

Use a separate protected location, for example
`/srv/morph/operations/operations.db`, with an owner-only parent and trusted
ancestors. A private subdirectory inside a group/world-writable repository does
not repair that repository's unsafe ancestor. Do not weaken the directory checks
or change unrelated repository permissions to accommodate a runtime database.

Submit requires both `--operation-store` for durable observations and `--store-dir`
for immutable transaction/recovery files. Save the returned `operation.operation_id`.
The journal, wallet key and recovery backup retain their separate roles.

```sh
# Fresh query, no broadcast. RPC comes from the operation's pinned record.
target/debug/morph-cli devnet --devnet-only operation-status \
  --store /srv/morph/operations/operations.db --operation-id "$OPERATION_ID" \
  --depth 4 --wait-ms 0

# Independent subscriber; does not change the registered depth or send authority.
target/debug/morph-cli devnet --devnet-only operation-status \
  --store /srv/morph/operations/operations.db --operation-id "$OPERATION_ID" \
  --depth 8 --wait-ms 30000

# Offline recovery if the original signed file is missing. Does not call the node.
target/debug/morph-cli devnet --devnet-only operation-export \
  --store /srv/morph/operations/operations.db --operation-id "$OPERATION_ID" \
  --output /srv/morph/recovery/recovered-close.tx

# Read-only structural/integrity validation; this is not canonical confirmation.
target/debug/morph-cli runtime-store-validate /srv/morph/operations/operations.db
```

Status responses distinguish the subscriber's `required_depth`/`depth_reached`
from the operation's registered depth. `committed` below that policy is not
`finalised`. A fresh failure returns zero canonical confirmations rather than the
last successful depth. An `operator_action` result requires checking which input
was consumed; it is not a failed-signature verdict or permission to unfreeze.
`replaced` identifies a canonically included competitor in the explicitly declared
replacement family. Its nested `depth` belongs to that competitor; the queried
operation's `canonical_confirmations` and `depth_reached` remain zero/false.
Actionable source/rejection results return immediately even with a wait budget.
`finalised` can revert after a reorg because it is a depth threshold, not a guarantee
of irreversible CKB history.

Offline export has `canonical_confirmation_checked=false` and no status field.
The same output/bytes can be exported repeatedly; different existing bytes are
never overwritten. Exporting old bytes does not make them spendable. Keep the
original close draft and complete unilateral recovery package as well: replay
still uses the close adapter's review, not a generic database send command.

If a submit response disappears, query the operation first. A canonical repeat
returns the same operation identity and immutable artifact paths without another
broadcast. For `unknown`/`reorged`, rerunning the exact original submit invokes live
review and VM preflight before replay. Respect the one-second cadence and 32-send
ceiling; do not reset the database to get more attempts. A changed fee/body needs
new role-correct approval through the existing ceremony.

To declare a close fee version, first wallet-sign and register the older exact
body with `submit --dry-run`. Save its operation ID. Independently authorize and
wallet-sign the new exact body, then add `--replaces-operation "$OLDER_OPERATION_ID"`
to its submit command. Include that same flag on later repeats of that body.
The source State, target allocation, network, RPC and confirmation policy must
match the predecessor. Registration neither broadcasts nor revokes the older body.
If either later wins source consumption, fresh status can attribute that canonical
winner. Old approval export and unilateral recovery remain intact. A changed
State source is not a fee replacement and cannot be registered through this flag.

The store also exposes typed operation outbox records to the existing
`event-delivery` consumer. Configure a separate delivery database/endpoint only
when delivery is desired; creating an operation does not send webhooks. Kinds are
`operation_registered`, `operation_broadcast_intent`, and `operation_observed`.
The latter is deliberately a query notification, not a settlement proof. The
operation ID is `subject_id`; correlation identifies the local transition commit.
Events omit raw transactions, signatures, paths, endpoint URLs and private exits.

Do not remove `.lock` files or SQLite journals. On busy/CAS conflict, retry a fresh
query with bounded delay. On store exhaustion, retain evidence and stop new work;
producer rotation is not implemented. Backup requires all owners stopped and
read-only validation as described in the [runtime-store runbook](runtime-store.md).
An offline database copy does not establish signer freshness.

See [ADR 006](../adr/006-exact-ckb-operations.md) for states, resource bounds,
authorization ownership and unfinished integrations.

## Saved lifecycle metrics

```sh
morph-cli operation-observability --store /srv/morph/operations/operations.db
morph-cli operation-observability --store /srv/morph/operations/operations.db --metrics
```

This keyless command works in the default build. It reads the private database
without acquiring operation writer locks, sending a transaction, making RPC calls
or advancing its revision. JSON uses `morph.operation_observability.v1` with scope
`saved_operation_history`; `store_available` means the bounded current record set
was readable and validated consistently. It is **not** mutation readiness or
current canonical confirmation. Use `operation-status` for fresh chain evidence.
The current production adapter remains cooperative close; zero rows for other
operation kinds do not claim those adapters are implemented.

The sole current operation record is now `morph.ckb_operation.v2`, with required
lifecycle evidence. Registration time, latest state-entry time and twelve bounded
state-entry counters are persisted with the status, exact intent and outbox in
one runtime transaction. A failed CAS cannot leave a phantom count. A duplicate
registration or unchanged observation adds no count. A depth/tip change within
one status class can update evidence without adding a new class entry. Counts
survive process restart, but are not an independent authority rollback detector.
Older v1 records and missing counters are rejected, never migrated or silently
counted as zero. Preserve old no-value test artifacts and regenerate development
acceptance stores with the current build; do not erase signed recovery artifacts
or signer journals to satisfy an exporter.

One exporter has **225 fixed series** (eight kind labels, twelve status labels):

| Metric | Type | Meaning |
| --- | --- | --- |
| `morph_operation_store_available` | gauge | One coherent, validated local snapshot completed within the observation budget |
| `morph_operation_records{kind}` | gauge | Retained registered exact transaction bodies |
| `morph_operation_broadcast_intents_total{kind}` | counter | Durable pre-send intents; a crash before the network syscall still counts, a confirmed transfer is not implied |
| `morph_operation_replacements_registered_total{kind}` | counter | Explicitly linked replacement bodies registered, not replacement winners or revoked approvals |
| `morph_operation_state_records{kind,state}` | gauge | Last persisted status class per retained operation |
| `morph_operation_state_entries_total{kind,state}` | counter | Entries into that status class; repeated polls/depth changes do not count |
| `morph_operation_oldest_unresolved_milliseconds{kind}` | gauge | Age from registration of the oldest body not last observed finalised or replaced at its required depth; zero when none |

Historical `finalised` entry counts remain after a reorg or RPC failure. The
current saved-state gauge moves when reconciliation records that new state.
Metrics alone cannot discover a reorg; even a saved finalised gauge may be stale.
These are lifecycle records, not settled-payment totals, observed network sends,
fee expenditure or a chain-finality proof. Rejected/operator-action bodies remain
unresolved for age reporting. A replacement observed below the configured depth
also remains unresolved. Counters are per retained store; a new development
store resets the series and is not an authorized recovery technique.

Labels are selected from fixed enums only; no operation/channel IDs, OutPoints,
paths, RPC URLs, raw errors, signatures or transaction bytes appear. On unavailable,
old-schema, invalid or expired evidence, availability is zero and all 224 remaining
series are `NaN`, so unavailable data cannot look like an empty healthy queue.
JSON returns nonzero with a null snapshot; metrics mode successfully exports this
unavailable state. No HTTP endpoint or new exposure/authentication boundary is added.

A five-second total wall/boot observation horizon includes integrity validation
and record reads. Global revision and reopened database identity must agree at
completion; a concurrent change invalidates the scrape instead of merging two
revisions. Future recorded timestamps fail closed. The command owns at most one
worker; blocked OS I/O cannot be forcibly cancelled, and late results are dropped.
This is a local collection budget, not a calibrated production alert threshold.

For unavailable data, preserve the store and inspect build/schema, file permissions,
I/O and concurrent writes. For rising RPC failure/reorg/operator-action entries,
run a fresh bounded status check and follow recovery instructions above. For old
unresolved work, inspect the exact operation and current retry/confirmation policy;
never reset counters or retry budgets. Deployment-specific age and failure-rate
alert thresholds still require measurements from the admitted profile.


### Persisted preflight consistency

Registration, reopen and read-only metrics share the same preflight metadata
validator: saved transaction size must equal the exact packed transaction size,
and estimated cycles must be positive. Reopen rejects an inconsistent receipt
without replacing the operation or granting broadcast permission. This check
validates stored metadata; it does not rerun CKB-VM or establish canonical input
liveness. Existing fresh canonical observation and exact-body authorization
requirements remain in force. See [record rejection evidence](../evidence/private-records-2026-11-10/README.md).
