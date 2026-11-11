# ADR 006: durable exact CKB operations

Status: partial implementation of #41, with #51 as the first adapter; 2026-11-10.
This is a controlled-devnet checkpoint, not completion of either issue.

## Decision and ownership

Persist a fully authorized, fully VM-preflighted transaction before any broadcast.
The shared runtime owns exact replay identity, attempts and fresh canonical
observations. Each adapter still owns its protocol authorization, input geometry,
fee limits, dependencies and full VM preflight. Signer journals and private keys
stay outside this database. A saved runtime record cannot reserve a state number,
unfreeze an old context or authorize different transaction bytes.

The first adapter is bilateral cooperative close. The `Kind` vocabulary also names
funding, activation, splice, publication, finalisation, conditional resolution and
Factory operations; those names do **not** imply their callers are migrated.
Existing publishers remain their current implementations until integrated and
qualified. A new runtime is not a second protocol or a compatibility parser.

## Identity and atomic boundaries

The identity is CKB-personalized Blake2b-256 of `MORPH_CKB_OPERATION_V1\0` and the
canonical serialization of `(kind, genesis, context_id, raw_transaction_hash)`.
The private record additionally binds the full packed transaction **including
witnesses**, evidence digest, RPC endpoint, confirmation policy and explicit
replacement reference. Reusing an identity with different contents fails closed.
The close adapter's context ID is its channel ID; its evidence digest hashes the
complete signed target State encoding. It is not a claim of a funding-context ID.

One `morph-runtime-store` transaction commits the current projection, immutable
intent, immutable attempt and typed public outbox event. `commit_new` prevents a
replayed local commit receipt from granting another send. A per-operation stable
nonblocking OS lock coordinates processes; independent operations have separate
locks. The global database CAS can still conflict, requiring reload. Network I/O
never occurs inside a SQLite transaction.

```mermaid
sequenceDiagram
    participant A as Protocol adapter
    participant R as Operation runtime
    participant D as Private SQLite store
    participant N as Pinned CKB node
    A->>A: Authenticate exact body and full VM preflight
    A->>R: Register exact bytes and preflight receipt
    R->>D: Atomic record + intent + attempt + public event
    R->>N: Check genesis, tip, transaction and live inputs
    R->>D: Persist fresh observation
    R->>D: Persist BroadcastUnknown and increment attempts
    Note over D,N: Process may die here; outcome remains uncertain
    R->>N: Send only the saved transaction
    R->>N: Fresh canonical reconciliation, regardless of reply
    R->>D: Atomic observation and notification
    R-->>A: Observed status and depth, never inferred success
```

## Observation semantics

`finalised` means the **configured confirmation depth** was reached in the last
verified canonical observation. It is not irreversible finality. Even a previously
finalised record is rechecked after restart and every status request. The node's
returned send hash is not confirmation. The runtime checks genesis, actual
canonical block transaction/raw body, inclusion depth, and an unchanged tip around
the observation. An RPC/identity/proof failure clears reported depth to zero.

| Status | Meaning | Automatic send permission |
| --- | --- | --- |
| `ready` | Exact preflighted body is durable | None until live-input reconciliation |
| `broadcast_unknown` | Durable send intent exists; result is uncertain | None on restart |
| `pending` / `proposed` | Node reports pool progress | None |
| `committed` | Canonical inclusion below configured depth | None |
| `finalised` | Canonical inclusion at or above configured depth | None |
| `replaced` | A linked, independently authorized competitor consumed the same source in the canonical chain | None; winner depth is separate from this operation's zero confirmations |
| `unknown` | Not found, all exact inputs currently canonical/live | Adapter may revalidate and replay exact bytes |
| `reorged` | Previously included, now absent, all inputs live | Same exact replay rule |
| `rejected` | Rejected and not previously included | Operator/adapter review; no blind retry |
| `operator_action` | An exact source is unavailable/consumed | No rebase or new signature permission |
| `rpc_unavailable` | Chain view could not be verified | None; never retain stale success |

A spent source alone does not identify which operation won. Close now searches
the explicitly registered replacement family and verifies the actual canonical
transaction before attributing the winner. Unknown/unlinked source consumption
remains `operator_action`. Close retains its ordinary unilateral package; it never
resets either participant's journal to compensate for a race. Status wait returns
promptly for replaced/rejected/operator-action outcomes rather than waiting for
the lost transaction to reach a confirmation target.

Subscribers choose independent depths without changing the registered policy.
Polling releases operation ownership between observations. Identical status/tip
observations do not append history; a new depth/tip is new evidence. Events carry
`component=operation`, `evidence_level=local_record`, an operation subject and
evidence digest. They omit transaction bytes, signatures, paths and RPC URLs.
`operation_observed` is a notification to query current evidence, not a portable
proof of settlement. Outbox delivery remains at least once.

## Replacement and recovery boundaries

Offline export recovers the exact packed signed transaction without contacting
RPC or returning cached confirmation as success. It never changes the stored
observation or grants broadcast authority. A conflicting output file is preserved.
Close retries recreate the same immutable transaction/recovery artifacts and
return their paths even if inputs are already consumed by the canonical close.

| Operation | Changed-body authorization required before registration |
| --- | --- |
| Cooperative close | Both close participants approve the new raw body; fee wallet signs its group |
| Root funding | Exact creation/initial exits and each declared funding wallet |
| Splice | New creation, recovery and bridge approvals plus external wallet authorization |
| Publication/finalisation/conditional resolution | Existing protocol proof plus operation-specific fee/Sponsor review; no generic authority to alter payout or conditions |
| Factory | Applicable all-member or touched-member domain plus physical conservation review |

Only the first row is integrated here. Close accepts `--replaces-operation` after
the predecessor has been registered as a fully signed/preflighted operation.
Registration requires the same kind, channel, genesis, target evidence digest,
RPC, confirmation policy and exact input-zero State source. A changed body still
requires both fresh close authorizations and its wallet signature. Other kinds
cannot yet declare replacement links. Repeated submits must retain the same
reference; omitting or changing it cannot silently rewrite the operation.

A replacement declaration is **not revocation**, nor evidence that either body
was broadcast. If a source is unavailable, the runtime traverses only the declared
family (bounded by 64 records), checking each candidate against the pinned canonical
chain within the existing RPC budget. The winner can be an older ancestor or a
newer descendant. The losing operation has zero own confirmations; its `replaced`
status carries the winner's ID, exact hash, block and depth separately. This
observation is rechecked after reorg; unavailable proof clears it. Unlinked
transactions with matching channel metadata are not automatically called a
replacement. There is no arbitrary chain-wide spender search.

No generic RBF, fee selection, automatic re-signing, source rebasing or approval
revocation exists. Pending older transactions are not evicted by registration;
the chain's actual source consumption decides between their still-valid approvals.

## Bounds and remaining work

- At most 64 operation records, 64 inputs/outputs per body, 512 KiB packed signed
  transaction, 32 durable broadcasts per operation and a minimum one-second retry
  cadence. Clock rollback fails the cadence/observation-age checks closed.
- Each observation/send has a five-second total RPC budget; status wait is at
  most 60 seconds, with independent depths 1–1024 and 250 ms polling intervals.
  Store validation/locking and filesystem scheduling are separate local costs.
- The existing store's 16,384-row-per-history and payload/page limits still apply.
  There is no evidence deletion, producer generation rotation or unlimited queue.
- A saved transaction is not proof that the adapter's review remains fresh.
  Unknown/reorg replay goes through its live-input and VM preflight again.
- Shared Built/AwaitingSignature orchestration, all other adapters, default-build
  API/SDK/desktop access, supervised scheduling/shutdown, failover, producer
  retention and full crash/RPC-loss campaigns remain #41/#32/#35/#43 work.
- Whole-store rollback can restore old runtime history. The existing #55 signer
  freshness assumption remains; this database never becomes signing authority.

Operational commands: [exact operation runbook](../runbooks/ckb-operations.md).
Storage semantics: [ADR 002](002-runtime-transactions.md).
