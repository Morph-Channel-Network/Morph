# Pre-production Operator Runbooks

These runbooks govern the controlled-devnet
`morph-current-custody` candidate. They are executable procedures, not a
mainnet operations claim.

Read and rehearse all of the following before activation:

- [`operations.md`](operations.md): release verification, keys, package
  retention, watchtower startup, health, and routine shutdown;
- [`incident-response.md`](incident-response.md): alert triage, emergency stop,
  reorg recovery, evidence preservation, and restart approval;
- [`upgrade-and-migration.md`](upgrade-and-migration.md): pre-release resets,
  contract upgrades, and rollback;
- [`value-limits.md`](value-limits.md): authoring, reviewing, and applying the
  operator value-limit policy before any real-assets phase;
- [`current-watch-service.md`](current-watch-service.md): the shared scanner,
  bounded publication service and reorg recovery;
- [`current-publication-reliability.md`](current-publication-reliability.md):
  fee, eviction, retry and controlled-reorg development rehearsals;
- [`rehearsal-2026-08-15.md`](rehearsal-2026-08-15.md): historical evidence for
  the retired candidate; it does not qualify the current ELFs.

## Roles

| Role | Responsibility | Must not do |
| --- | --- | --- |
| Release owner | Approves commit, manifest, envelope, and activation window. | Raise caps without new evidence. |
| Factory operator | Creates packages and submits approved devnet transactions. | Use participant keys as fee-payer or Hub tokens. |
| Watchtower operator | Runs an independent RPC/config/key set and responds to alerts. | Share the Factory operator's host or mutable package store. |
| Incident commander | Freezes new risk, preserves evidence, coordinates recovery. | Delete state or redeploy before evidence capture. |

One person may rehearse multiple roles locally, but an activated pilot requires
an independently operated watchtower as declared by the policy envelope.

## Activation Gate

Activation is allowed only when all items are true:

1. `make ci` passes on the exact candidate commit.
2. `make release-readiness` matches all eight ELF hashes.
3. The deployment report contains those same CKB data hashes.
4. The envelope is unexpired and every intended value is below its cap.
5. The Factory has 2–16 participants and every member verifies its N-of-N initial package.
6. The independent watchtower health file is healthy and its cursor scan floor
   predates the Factory/channel creation block.
7. Stop, incident, and migration procedures have been rehearsed.

If any item is false, the decision is no-go.

- [Protected private-key file input](key-input.md): Linux safe-open, ownership/permission and bounded-format checks; file paths replace private-key argv and environment values.
