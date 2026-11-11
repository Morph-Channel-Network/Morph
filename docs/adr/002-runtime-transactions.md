# ADR 002: one bounded runtime transaction boundary

Status: implementation in progress for #29; 2026-11-10. This ADR does not close #29 or enable routed payments.

## Ownership and selected backend

Use a host-only `morph-runtime-store` crate backed by bundled SQLite. An in-memory SQLite connection exercises the identical transaction logic in tests. Runtime owners commit mutable records, an immutable recovery intent, immutable publication attempts and pending outbox events in **one database transaction** with a global expected revision. Exact retry returns the original receipt; reusing an operation ID for different bytes fails. There is no transaction spanning independently deployed services: a cross-service action must use durable intent plus authenticated replay/acknowledgement (#30/#34).

| Owner | Current records | New boundary / exclusion |
| --- | --- | --- |
| Hub | Public coordination projection, saved signed packages, events, funding collection | Runtime state and its outgoing intent/events commit together. Public exports remain projections, never a database import. |
| Payment Gateway | Encrypted challenges/preimages, offers/keys, receipts, payment observations | Preserve encryption; use the same transaction API. Secret records and recovery bodies must never become public events. |
| Payment/edge/publication services | Future durable sessions, edge observations and operation progress | Typed record families, immutable intent/attempt bodies; integrations remain owned by #36/#37/#41. |
| Bilateral/Factory/funding/child signer | Keys, reservations, approved digests, lineage, retired evidence | **Excluded.** Keep existing stable locks and reserve/fsync/sign/record/fsync order. Database revision is not trusted signer freshness. |
| Local wallet | Keystore and prepared/signed payment lifecycle | Remains separately owned by the wallet; no general-database key import. |

SQLite is chosen over another whole-file JSON store because CAS, indexed bounded pagination and atomic changes across record families are required. Rewriting independent encrypted snapshots cannot establish cross-record atomicity. The implementation uses rollback-journal mode with `synchronous=EXTRA` on a private local directory; this synchronizes the directory following journal deletion. Only short database transactions hold the writer lock. No network calls occur inside them. WAL is unnecessary for the current bounded workload and adds live-backup/checkpoint obligations; changing journal mode needs evidence and an ADR update.

## Durability and recovery contract

```mermaid
sequenceDiagram
    participant O as Runtime owner
    participant D as Runtime database
    participant N as External peer / chain
    O->>D: Commit(expected revision, operation ID, exact intent, writes, events)
    D->>D: BEGIN IMMEDIATE; compare revision; validate all bounds
    D->>D: Write records + immutable intent + outbox + attempts
    D->>D: Commit and synchronize
    D-->>O: Durable receipt(revision, operation ID)
    O->>N: Execute saved intent / deliver saved event
    Note over O,D: Crash before response: retry the identical transaction ID and bytes
    Note over O,N: External outcome reconciliation is #30 / #34 / #41
```

Do not acknowledge success before commit. Disk-full, busy, schema mismatch and corruption are typed errors with no SQL/payload interpolation. A commit I/O error has an uncertain outcome: reopen and retry the exact operation, never invent a different intent. A successful transaction means local durability under SQLite's filesystem/fsync assumptions, not power-loss certification or external finality.

The store has one explicit unpublished schema and rejects old snapshots. It has no automatic migration or permissive reader. Native storage requires owner-only files in a private directory. Encrypted stores authenticate payloads against the database identity, record kind, key and revision; SQLite/WAL/journal pages never receive plaintext private bodies. A restored complete, consistent database can still roll back runtime history. This cannot restore signer authority because signer journals are excluded; independent freshness remains #55.

Resource limits cover payloads, transaction counts/bytes, total stored payload bytes, retained intents/events/attempts and page sizes. Reaching a retained-history limit fails closed; silently deleting unsent events or recovery evidence is prohibited. Consumer archival now uses sealed generations: a successor is prepared, the old metadata CAS is sealed, unresolved jobs are copied exactly in bounded chunks, and only then is the successor activated. Nothing is pruned; acknowledged jobs and every attempt/intent remain in retained predecessor databases. This recovers bounded consumer working capacity without changing the producer cursor/identity or granting a new retry budget. Producer-history segmentation and safe disk reclamation still need separate policy and evidence.

## Verification required before closeout

- CAS and identical retry versus conflicting content across independent connections.
- Actual child-process termination before commit, after commit and before response, followed by recovery of the whole record/intent/outbox set.
- Actual disk-full and fsync failure, corrupted/truncated files and wrong encryption key; no private payload in errors.
- Read-only schema/integrity/payload validator and a drift test against the canonical SQL.
- Hub and Gateway integration tests preserving prior behavior, encryption and immutable signed recovery bytes.
- Documented initialization/reset and safe backup/recovery; no signer-store restore path.

References: [SQLite atomic commit](https://www.sqlite.org/atomiccommit.html), [synchronous settings](https://www.sqlite.org/pragma.html#pragma_synchronous), [WAL constraints](https://www.sqlite.org/wal.html), [rusqlite](https://docs.rs/rusqlite/0.41.1/rusqlite/).
