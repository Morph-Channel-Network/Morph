# Canonical shadow registry service

This is a diagnostic Morph-to-Fiber service. It can register, refresh, drain and
disable **non-forwarding** mirrors. It cannot prepare or route a payment, sign a
state, publish custody transactions or replace a participant's recovery package.
The supported hook and deployment procedure are in [ADR 004](../adr/004-fiber-shadow-hook.md).

## Commands

Build `morph-cli` with the `devnet` feature. Install the config and runtime database
in a private owner-controlled Linux directory. The current service is qualified
on controlled no-value CKB only; this is not a real-asset release.

```sh
morph-cli devnet --devnet-only shadow-service --config /private/morph-shadow/config.json run
morph-cli devnet --devnet-only shadow-service --config /private/morph-shadow/config.json readiness
morph-cli devnet --devnet-only shadow-service --config /private/morph-shadow/config.json metrics
```

`run --passes 1` performs a real bounded cycle and marks the worker stopped when
it returns. It is not a fake healthy daemon. Normal `run` continues until Ctrl-C,
a fatal storage error or a changed configuration. SIGKILL/crash health expires
without rewriting the file. Do not launch a replacement while the original worker
is still alive: the stable `STORE.worker.lock` allows exactly one owner. Never
unlink that sidecar. Signing-journal locks are brief and are released before RPC.

## Sole current configuration

The strict JSON schema name is `morph.shadow_service.v1`. Unknown or omitted
required fields are rejected. Paths must be absolute with no `.`/`..` components.
The config, credential and heartbeat readers reject exposed files, aliases and
special files; use a trusted private directory and regular owner-owned `0600`
files. Do not place runtime state under a shared-writable workspace ancestor.

| Field | Required meaning |
| --- | --- |
| `schema` | Exact current schema name above |
| `store` | Dedicated coordinator SQLite path; never a signer journal |
| `chain_rpc_url` | HTTP(S) CKB RPC without URL credentials/query/fragment; must match each confirmed session's guard |
| `contracts_dir` | Installed artifacts, absolute directory matching each session guard |
| `deployment_id` | Exact independently approved deployment identity, `0x` + 64 lowercase hex; not copied from a provider claim |
| `min_confirmations` | 1–1024; cannot weaken any source session's depth |
| `provider_rpc_url` | HTTPS, or loopback HTTP accepted by the adapter |
| `callback_endpoint` | Validated address retained as metadata; no payment callback is invoked |
| `bearer_token_file` | Explicit null for literal-loopback unauthenticated no-value use, otherwise protected token file |
| `policy` | Pinned `fiber_commit`, `patch_hash`, `ckb_genesis_hash`; see hook manifest |
| `sources` | 1–32 explicit current session/participant/asset/reservation mappings |
| `poll_ms` | 100–10000 |
| `observe_budget_ms` | 100–20000, total for a whole observation batch; each RPC client at most 10 seconds |
| `reconcile_budget_ms` | 100–20000, total for HTTP reconciliation, including capability work |
| `lease_ms` | At most 60000, greater than observe + reconcile + poll budgets |

Each source has `session`, two `participants` (Morph node ID and settlement-lock
mapping), one typed `asset`, and an explicitly nullable `reservation`. Use the
current Core Rust serialization. No RGB++ admission or implicit address-ownership
inference is accepted. Multiple assets may reference one session; duplicate
session/asset entries are rejected. The observer verifies every committed Vault,
not merely the selected asset. A busy, missing, stale, conflicting or invalid
source quarantines the **whole batch**. This is conservative isolation, not
independent per-channel availability.

Bearer bytes enter only through the protected file (maximum 16 KiB, one ASCII
token), never argv, a raw environment variable or a URL. The owner configuration
digest is immutably bound to the database. It does not silently accept new sources,
endpoints, policy or paths after restart. Token contents can rotate at the same
path with a worker restart. A source/deployment configuration change requires a
reviewed new setup; there is no live reload, automatic generation migration or
history-discard procedure. Preserve the prior store and its evidence.

## Cycle, failure and freshness

1. Capture each authoritative current session, its package and confirmed lineage.
2. Check actual live State/Vault cells, exact scripts/assets/OutPoints, network,
   installed deployment and confirmation depth. Historical parents may be spent.
   Every source must observe the same stable chain tip.
3. Recheck all session fingerprints. Prepared update/splice/close means draining.
4. Atomically persist the observation and its typed event. Failure invalidates
   previous desired observations; a remote list never creates local authority.
5. Fetch current provider state and capabilities. Persist exact operations before
   sending. After capability negotiation, recheck config, journals, lease and
   time before transmission. Old/unknown mirrors drain then disable first.
6. Persist strict replies as historical receipts. Timeout retains uncertain
   operations for exact reconciliation; it never invents a replacement approval.

Readiness is explicitly `local_registry`. It requires a fresh, running worker,
verified sources, converged provider state, matching config/database identity and
revision, wall and boot deadlines, and the same Linux boot identity. A previous
bounded healthy observation can remain visible during a later probe; startup
never inherits it. Five fixed gauges expose readiness, worker freshness, source
verification, provider reconciliation and `forwarding=0`. No paths, keys, channel
IDs or remote error payloads become metric labels.

The private `STORE.health.json` is a projection, not signing authority. A missing
hook, slow RPC, wrong deployment, changed source, clock regression or store error
must not produce affirmative readiness. An unavailable provider may retain an
old diagnostic row until communication recovers; that row remains non-forwarding.
Clock/fingerprint/CAS checks do not detect a complete consistent rollback of all
local authority storage (#55).

## Capacity and retained evidence

The current handler retains at most 128 edge identities, including retired ones.
The shared database also bounds intents/events/attempts. Each committed observer
refresh consumes history: capacity is finite and poll frequency matters. A full
store stops writes; never delete history, reset revisions or restore an old signer
snapshot to continue. Producer-history segmentation/long-duration capacity
qualification remains in the W1 storage/observability follow-up. A read-only
validator and backup rules are in [runtime-store](runtime-store.md).

## Reproduce the real no-value matrix

```sh
FIBER_CHECKOUT=/absolute/path/to/pinned/patched/fiber \
CKB_BIN=/absolute/path/to/ckb \
OUT_DIR=/tmp/morph-shadow-fresh-run \
bash scripts/devnet-shadow-service-e2e.sh
```

The script builds both binaries from pinned sources, starts dedicated CKB/Fiber
processes and uses real funding/activation/signing journals. It SIGKILLs Morph and
Fiber, waits out saved health, checks exact restart reconciliation, forces a busy
source, orphans actual activation, replays the exact transaction, refreshes chain
evidence without changing backend authority, and finishes through ordinary
unilateral publication/finalisation. It does not stop existing wallet nodes.
Fiber initialization performs expensive key encryption/decryption, so its bounded
startup wait is longer than the service's operational RPC budget.

[Recorded evidence](../evidence/shadow-service-2026-11-10/README.md) binds sources,
binaries, patch, genesis, deployment and sanitized logs. Its combined service
source is Root-origin XUDT backed by two Vaults. Existing Factory/splice canonical
observer matrices and coordinator fault tests remain separate evidence; do not
claim this run exercised their full cross-product or value forwarding.
