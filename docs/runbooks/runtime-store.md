# Runtime database operations

The current Hub and Payment Gateway use `morph-runtime-store`. It commits a
projection revision, immutable recovery intent and outbox rows atomically.
Signer journals, wallet keystores and retired signing evidence are **not** in
this database. Never substitute a database backup for their authoritative files.

## Initialize current development state

Use a dedicated local Linux directory owned by the service user, mode `0700`.
Database and SQLite sidecars must be regular owner-owned `0600` files, not
symlinks or hard links. Missing directories are created privately. Existing
exposed directories/files are rejected rather than silently chmodded.

```sh
cargo run -p morph-cli -- hub serve \
  --state-path target/morph-hub/runtime/node.db \
  --pubkey <compressed-public-key> \
  --allow-unauthenticated-loopback
```

The unauthenticated flag is only for an explicitly local development instance.
Normal auth, request limits and scoped permissions continue to apply. The
Gateway's `--store` must likewise point into a private directory. Its existing
protected credentials derive the encryption key; the database does not contain
that key. Both private state and exact Gateway recovery intent bodies are
AES-256-GCM encrypted before SQLite receives them. Public outbox events carry
only the revision-committed event, without preimages, credentials or offers.

Old Hub JSON files and the previous Gateway encrypted-snapshot format are not
database inputs. Stop old development processes and choose a fresh path. Do not
rename old bytes to `.db`, add a compatibility reader, or delete a live SQLite
journal. Hub `/api/state-file` remains the explicitly reviewed **JSON projection
export**; the restore API still enforces identity and operational-state barriers.
It never replaces the runtime database, revision history or any signer journal.
Its pre-restore backup is a private JSON projection, not a live database copy.

## Validate without changing records

```sh
cargo run -p morph-cli -- runtime-store-validate target/morph-hub/runtime/node.db
```

For an encrypted store, `--storage-key-file <protected-file>` accepts exactly
32 bytes encoded as hex through the protected file loader. This is the **derived
storage key**, not a participant key or the Gateway credential root. Never pass
key bytes in argv or environment variables. Services can call `Store::read_only`
and `validate()` with their existing in-memory derived key without exporting it.

The command reports only schema version, revision, encryption mode, record and
history counts, and stored payload bytes. It checks the exact current SQL schema,
SQLite integrity, foreign keys, revision continuity, resource limits and every
payload's checksum/authentication. A missing path is an error, not an initializer.
An unknown schema is an error, not a migration request. A hot journal may require
the owning service to open/recover the database before read-only validation.

## Failures and recovery

| Result | Action |
| --- | --- |
| Revision conflict | Reload current state and reconcile the intended operation. Do not blindly change the expected revision on a different proposal. Hub currently requires restart/reload after another owner advances its projection. |
| Same operation ID / identical request | The store returns the original durable receipt even if newer commits exist. |
| Same operation ID / different bytes | Stop the conflicting request; no records change. |
| Busy | Retry with a bounded backoff; each database lock wait is at most 250 ms. Do not hold a transaction across RPC. |
| Full | Stop new mutations, preserve the database and reconcile capacity. Never silently discard recovery intents or unsent events. |
| Commit outcome uncertain | Reopen, validate, and replay the **same operation ID and exact transaction body**. Do not create a replacement payment or re-sign to compensate for a lost acknowledgement. |
| Corruption / wrong key | Check the protected credential source and filesystem health. Preserve evidence. Do not use an old signer snapshot as a repair. |
| Unsupported schema | For disposable unpublished development state, stop owners and initialize a separate fresh path. Preserve independent recovery packages and all signer authority. |

SQLite uses `journal_mode=DELETE`, `synchronous=EXTRA`, foreign keys, private
files and one bounded transaction. Tests cover process termination and injected
syscall failures. These are local filesystem tests, not power-loss hardware
certification or evidence that a network filesystem implements the same guarantees.
Use a local filesystem with working locking and synchronization.

Do not copy an actively changing database with `cp`. For offline backup, stop
**all** processes using the database, ensure the last owner closed successfully,
validate it read-only, and retain the private file and the correct credential
backup under the same confidentiality policy. If recovery left sidecars, let
SQLite recover them before taking a clean offline backup. Never remove a hot
journal to make a copy appear clean. Whole-store restore can roll back ordinary
runtime history and therefore needs external reconciliation; it does not confer
new signing authority.

## Bounds and outstanding integrations

- Maximum payload: 64 MiB; total request payload: 72 MiB; at most 256 changes.
- Maximum mutable records: 4,096; at most 16,384 rows in each retained immutable
  history family; total stored payload bytes: 256 MiB. SQLite also has a bounded
  page count (131,072 pages).
- Queries return at most 128 records. Event/intent/attempt cursors are the pair
  `(revision, id)`, so later inserts with lexically smaller IDs are not skipped.
- History has no deletion or acknowledgement shortcut. Consumer #34 archival seals old generations and carries exact unresolved jobs
  into new databases without deleting any history. Producer segmentation remains
  unfinished; reaching its bound still makes mutations fail closed.
- A generic outbox row is not a delivered webhook. A generic publication attempt
  is not a confirmed chain transaction. #30/#34/#36/#37/#41 integrate the common
  store with authenticated replay, durable payments, edges and canonical chain
  reconciliation. No automatic Fiber resend or provider-loss recovery is claimed.
- A database revision does not prove signer freshness. #55 remains explicit
  about cloned or rolled-back whole-authority storage.

Design and record ownership: [ADR 002](../adr/002-runtime-transactions.md).


## A replayed transaction is not a fresh execution grant

`Store::commit` returns the original receipt for an identical prior transaction.
That is correct for recovering a persisted result, but cannot grant two callers
permission to each perform an external side effect. `Store::commit_new` uses the
same transactional engine and rejects even an identical prior commit. Gateway
outgoing payments use that operation for the first durable send reservation;
racing callers reload and reconcile instead of sending again. Receipt shape and
SQL schema are unchanged. This distinction does not make external HTTP delivery
exactly-once or detect whole-store rollback.

See [Gateway payment retries](gateway-payment-retries.md) for the concrete API,
capacity and unknown-outcome rules.


## Event consumer ownership

The Delivery record family is consumer metadata, never signer authority. The
current `event-delivery` process opens a Hub, Gateway or watch source read-only and owns a separate
runtime database. Its cursor/jobs commit atomically; delivery attempts/acks do not
advance producer business revisions. Immutable history point lookup validates exact
source cursors. See [event delivery](event-delivery.md) for policy binding,
at-least-once semantics and the current unimplemented archival boundary.


Watch checkpoints use `Family::Watch`: cursor, private alert intent, explicit egress
permission and (for alerts only) typed public outbox are one transaction. JSON
cursor files are rejected. Publication-attempt files remain immutable, separately
retained evidence; local alert JSONL is a rebuildable display, not a source of
canonical observation or delivery acknowledgement. See the event runbook for
shared-channel projection repair and the remaining archival/capacity boundary.
