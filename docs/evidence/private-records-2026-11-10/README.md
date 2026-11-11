# Consumer and operation record recovery — 2026-11-10

This #43 checkpoint adds 20 event-consumer and 11 operation-record reopen cases
and fixes two classes of actual validation omissions exposed by them. Valid
private runtime transactions carry the damaged consumer payloads, so tests reach
the higher-level decoder rather than merely tripping SQLite/ciphertext integrity.
No production format, schema version, contract or signing domain is changed.

## Defects demonstrated before the fixes

| Boundary | Previously accepted inconsistent data | Fix |
| --- | --- | --- |
| Event consumer | Nonempty cursor ID with revision zero; saved job whose event source differs from the pinned source store | Enforce empty/zero cursor pairing and job source identity on read |
| Exact operation | Saved preflight byte size zero or cycles zero accepted on reopen, despite rejection at initial registration/metrics | One shared preflight validator used by registration, reopen and metrics |

The initial logs name all four accepted bad variants. These are recovery
consistency defects; the tests deliberately have owner-level transaction access
and do not demonstrate that an unprivileged caller can corrupt protected files.
A decoded source mismatch must not become a dispatchable job. A persisted
preflight receipt must satisfy the same basic metadata checks on restart as on
registration. Matching byte length and positive cycles is **not a new VM
execution**, independent preflight proof or canonical input observation.

## Rejection matrix

The event test `damaged_consumer_metadata_and_jobs_never_reopen_or_reset_source_cursor`
covers:

- Meta: malformed JSON, future/retired schema, extra field, missing required
  archive link, wrong source/target, sealed phase without successor, zero cursor
  revision with nonempty ID, and wrong retained count (10 cases).
- Jobs: malformed JSON, missing acknowledgement, unknown status, attempts/replay
  overflow, wrong identity, malformed event body, wrong source, acknowledgement
  on a pending job and acknowledged status without a valid acknowledgement
  (10 cases).

The operation test
`corrupt_operation_records_reject_reopen_without_rebroadcast_or_record_replacement`
covers malformed JSON, future/retired schema, extra field, missing tip/lifecycle,
changed identity, broadcast/counter inconsistency and invalid preflight size/cycles
(11 cases).

Every case uses an independent temporary database. Reopen must reject. Exact
on-disk bytes and stored record bytes/revision remain unchanged; consumer cases
also preserve the separate source database. No replacement/init transaction,
new event or reset is allowed. The generic runtime's checksummed/encrypted
transaction layer remains valid, distinguishing these from torn-file, wrong-key,
fsync and disk-full tests. Existing model/process-kill/archive/reorg suites are
rerun alongside these negatives; they exercise normal transitions and recovery.

## Commands and results

```sh
cargo test --locked -p morph-events --all-features
cargo test --locked -p morph-cli --all-features operation_runtime
cargo clippy --locked -p morph-events -p morph-cli --all-features --all-targets -- -D warnings
cargo fmt --all -- --check
git diff --check
```

- Event suite: **23 pass**, including real queue/archive process kills and model.
- Operation scope: **23 pass**, including observability, replacement, reorg,
  ambiguous broadcast, subprocess tests and model. Other CLI tests are filtered.
- Total: **46 test-harness entries pass** (including subprocess helper entries);
  the two new regressions contain the 31 record variants.
- Scoped Clippy, formatting and whitespace checks pass.
- 133 explicit source/config entries match before/after final verification.
  This is not whole-worktree freeze, new native-chain/VM evidence or final candidate
  qualification. No repeated mutation campaign is claimed for these host-only
  record checks; their required ordinary CI suites already run these regressions.

Logs and source hashes are retained with SHA256SUMS. No existing private database,
archive, journal or lockfile was deleted or migrated. This does not solve rollback
of an entire consistent authority or exhaust all semantically inconsistent record
relationships. Inline script-argument inventory and final #28/#44/#55 candidate
qualification remain; no issue closure or complete W1 claim is made here.
