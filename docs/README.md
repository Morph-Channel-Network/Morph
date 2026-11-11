# Morph 4.1.0 documentation

Start with the [release highlights](releases/v4.1.0.md) and the
[native Hub guide](native-desktop.md). This index is for
the sole current implementation. Historical audit/evidence artifacts retain their
original commit and scope; they are not current setup instructions.

| Task | Authoritative documents |
| --- | --- |
| Understand the model | [Channels and Factory](multi-asset-channels.md), [implementation boundaries](implementation.md), [wire](multi-asset-wire.md) |
| Use the client and wallet | [Native desktop / Hub](native-desktop.md), [wallet runbook](runbooks/local-wallet.md), [native dependencies](native-gui-dependencies.md) |
| Fund, resize, close | [Initial funding](runbooks/initial-funding.md), [splice](multi-asset-splice.md), [cooperative close](runbooks/cooperative-close.md) |
| Use conditional CKB/UDT | [Conditions and resolution](conditional-batches.md), [ADR 007](adr/007-typed-conditional-settlement.md) |
| Operate Factory rights | [Factory capabilities](factory-multi-right.md), [admission](runbooks/experiment-admission.md), [value limits](runbooks/value-limits.md) |
| Integrate the API | [Hub mutations](hub-api-mutations.md), generated [Hub schemas](api/hub-types), `morph-sdk` and `morph-packages` |
| Operate runtime/signers | [Runtime store](runbooks/runtime-store.md), [key input](runbooks/key-input.md), [participant signer](runbooks/external-participant-signer.md), [supervision](runbooks/signer-supervision.md) |
| Observe and reconcile | [Watch](runbooks/current-watch-service.md), [events](runbooks/event-delivery.md), [readiness](runbooks/service-readiness.md), [CKB operations](runbooks/ckb-operations.md) |
| Connect Fiber | [Devnet integration](fiber-morph-devnet-runbook.md), [shadow service](runbooks/shadow-service.md), [Gateway integration](rgbpp-payment-gateway-fiber-integration-plan.md) |
| Review cost and bounds | [Resource/cost report](model-resource-optimization.md), [coverage](current-protocol-coverage.md), [boundary matrix](verification-boundary-matrix.md), [ADR 008](adr/008-bounded-cost-and-current-encoding.md) |
| Reproduce or replace development deployment | [Local qualification](runbooks/local-candidate-qualification.md), [verification campaigns](runbooks/verification-campaigns.md), [replacement/recovery](runbooks/upgrade-and-migration.md) |
| See deployment limits and future work | [Envelope](preproduction-envelope.md), [mainnet readiness](mainnet-readiness.md), [roadmap](roadmap.md) |

## Historical evidence and design decisions

- [Unified foundation migration](unified-protocol-migration.md) and [architecture decision](architecture-profile-strategy.md).
- [GPUI migration evidence](gpui-migration-status.md) and [W1 completion](w1-completion-2026-11-11.md).
- [Prior 4.0 alpha](releases/v4.0.0-alpha.1.md), [changelog](../CHANGELOG.md), audits and source-bound records under `evidence/`.
- Decisions under `adr/` preserve why authority, transactions, close, shadow and current encoding work as they do.

Superseded UI plans/reviews, old-envelope tutorials and interim W1 execution-order/progress documents
were consolidated into the current client guide, this index and the 4.1.0
release overview. Obsolete draft screenshots were removed; real native wallet
and current refinement evidence remain. Immutable captured evidence is not
rewritten to pretend it describes a later source.

The [closed-issue snapshot](releases/v4.1.0-closed-issues.json) retains issue-level delivery details.
