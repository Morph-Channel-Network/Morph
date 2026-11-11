# Roadmap after 4.1.0

4.1.0 includes the common custody foundation, native Rust Hub/wallet,
asset-bound CKB/UDT conditions, exact cooperative close, durable runtime/signers,
controlled no-value admission and nonforwarding Fiber shadow service. These are
implemented capabilities, not unfinished consolidation milestones. See
[the release record and closed issues](releases/v4.1.0.md).

## Remaining work by boundary

| Work | Current base | What remains |
| --- | --- | --- |
| Routed Morph-backed payments | Typed conditional recovery and canonical diagnostic Fiber hook | Live forwarding, explicit clock/liquidity policy, MPP and provider-loss acceptance; Morph does not add its own routing |
| Close/operation product integration | Exact-body close CLI, durable approval family and canonical operation store | Additional API/SDK/desktop adapters, generic operation coordination and autonomous scheduling |
| Reliability | Bounded current watch, health, outbox/event delivery and signer supervision | Independent failure domains, pooled publication/failover, sustained adversarial and public-network measurements |
| Signer custody | Protected files, independent Linux signer and intact-journal crash recovery | Hardware/provider adapters and an independent trusted freshness boundary for whole-store rollback |
| Factory governance | N-of-N full consent and touched-member reduced claims | Member rotation/lost-key governance without confiscation; last shared carrier/floor still needs full consent |
| Asset admission | Exact Type accounting and a no-real-assets envelope | Qualify actual asset behavior, payout geometry, joint resource shape and production exposure |
| Deployment review | Exact historical executed evidence and source-bound release artifacts | Independent review/rebuild and production/mainnet sign-off; no such pass is inferred from publication |
| Native platforms/accessibility | Linux x86-64 GPUI client and native input evidence | Separate platform builds, OS accessibility and sustained device-level performance qualification |
| Resource research | Current dictionary/count/caching and immutable-verifier optimizations | Smaller repeated provenance fields; root/hash/signature/aggregate-Batch changes require independent design |

## One current model

No old State/Vault, Factory, splice, JSON or client compatibility implementation
is planned. Historical source/evidence remains traceable; disposable development
state is recreated after incompatible changes. Recovery never restores or
unfreezes an old signer authority. See [replacement](runbooks/upgrade-and-migration.md).

## Evidence and deployment

The existing `991f7e3` qualification passed the declared local no-value scope.
The owner requested that repeated acceptance be skipped for the 4.1.0 publication;
that is recorded separately from executed results. New runtime/contract changes
still need their applicable evidence; a version tag is not a substitute.
Mainnet and real assets require [readiness](mainnet-readiness.md), actual Type
behavior, operational evidence and reviewed exposure limits. The current
[envelope](preproduction-envelope.md) remains controlled devnet only.
