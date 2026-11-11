# Current verification boundary matrix

Reconciled against the working tree on 2026-11-10 for #43, with #32/#31/#55
interfaces. This inventory distinguishes mutation coverage, deterministic
regressions and actual process faults. A row naming a test means its source was
checked; only the linked dated evidence establishes an executed result. It is
not a clean-candidate or complete W1 certificate.

The authoritative public HTTP inventory is the closed registry in
`morph-hub-api/src/endpoints.rs` and `morph-payment-gateway/src/endpoints.rs`,
rendered into [Hub endpoints](api/hub-endpoints.md) and
[Gateway endpoints](api/gateway-endpoints.md). Those tables enumerate concrete
request/result types; this matrix groups verification boundaries instead of
maintaining another API schema. Domain validation remains distinct from serde
shape acceptance.

## Current decoder families

| Boundary / canonical owner | Current mutation coverage | Deterministic evidence and remaining gap |
| --- | --- | --- |
| State header, manifest, settlement, witness; Core + script-common `multi_asset` | `manifest`, `settlement`, `state-witness` | Host/script acceptance or implication plus exact roundtrip; VM owns authentic State/Vault selection and physical conservation |
| Bilateral cooperative close; script-common `multi_asset_close` | `close-frame` | Structural frame roundtrip; deliberately not valid close authority in this corpus. Real signatures/exact-body authorization are separate Core/VM/native close tests |
| Factory FS/FM/FR and compact rights proofs | `factory-state`, `factory-materialisation`, `factory-frame` | FS structural reconstruction; FM full/delegated consistency + signatures; FR paired-proof/noninterference. Physical body execution remains VM/native evidence |
| Splice `MORPHMS!`, flow framing and transaction envelope | `splice-frame`, `splice-flows`, plus SDK signed exports | Three signed frames; old-header commitments, flow conservation, bridge signature, host/script flow commitment and canonical reconstruction. Actual live State/input_type creation signatures/physical transaction execution remain VM/native evidence |
| Conditional Batch, Sponsor and current script argument codecs | `batch-resolution`: 1/8 transfers, both hash algorithms, fulfill/refund/mixed; `script-args`: StateType direct/child, Vault, Sponsor, Factory Type | Semantic resolution and independent payout accounting; canonical argument reconstruction. Sponsor parse is structural only. Factory Type uses the actual 44-byte parser/encoder. `current_inline_factory_and_batch_args_reject_malformed_shapes_before_witness_access` covers 11 Factory-reserve/Batch entry negatives in the real VM; existing Factory delegation and conditional finalisation/spend tests own valid-length authority and terms commitments. No alternate inline parser was added |
| SDK public document review, `inspection::inspect` | `sdk-document`, 22 canonical fixtures spanning all 10 current dispatch schemas | Includes ordinary/conditional recovery, conditional batch, root draft/collection/funding, proposal, splice draft/funding, Factory request/transition. Re-encoding through the actual typed DTO must preserve SDK review. Root/creation/exit availability is not inferred from a summary alone |
| SDK detached receipts, `inspection::inspect_signature` | `sdk-receipt`, 4 canonical receipts | Current SDK proposal and Factory receipt roles only; wrong/zero signatures and missing base rejected. This does **not** cover every signer-service receipt role |
| Hub HTTP DTOs and mutation headers | `hub-api`: 31 seeds covering every registered JSON/SSE root plus errors; `hub-mutation`; package cases through SDK | Raw concrete DTO decoding, stable encoding, strict duplicate/unknown fields and decimal negatives; readiness/page semantic checks. [Checkpoint](evidence/hub-api-fuzz-2026-11-10/README.md). Structural acceptance is not server authorization or restore eligibility; not every nested enum combination is enumerated |
| Gateway HTTP DTOs / payer proof / credential boundary | `gateway-api` (27 seeds covering registered JSON/query roots + errors), `gateway-receipt`, `gateway-authorization` | Raw typed decode, strict fields/duplicates, query bounds, current signed receipt/intent/outer binding with fixed external signer. [Checkpoint](evidence/gateway-api-fuzz-2026-11-10/README.md). Biscuit access, HTTP/URI extraction, opaque provider/proxy bytes and live payment remain separate boundaries |
| Typed public events and callback HMAC | `event-json`, `callback-auth` | Exact canonical event roundtrip, body/ID/MAC domain separation; HTTP oversized/bad-ack/redirect tests. Event-page cursor shapes are also checked by Hub/Gateway DTO targets; transport acceptance remains separate |
| External signer Request/Response and policy-bound review | `signer-request`, `signer-review`, `signer-response`, seven canonical role cases each | Fixed external policy/input resolver; raw envelope validation, attacker-recomputed public ID with full payload review, valid signature/context and roundtrip. Controlled evidence only; IPC/journal/whole-authority freshness remain separate. [Checkpoint](evidence/signer-fuzz-2026-11-10/README.md) |
| Runtime transaction JSON / SQLite schema | `store-commit`, `store-replay` | Atomic state+intent+outbox+attempts, CAS/retry, checked schema/permissions/encryption, corrupt/truncated and disk faults. Whole-store restore is not signer freshness |
| Gateway snapshot / outgoing ledger | Payment model and store/HTTP regressions | Encrypted current records, unknown outcomes, terminal immutability, display eviction and requirement conflicts; no alternate old-schema readers. Nine malformed/missing/unknown/future encrypted projection negatives now exercise the consumer decoder and prove no reinitialization/write. Existing runtime tests cover wrong-key/ciphertext identity. Final fault ledger must retain these distinctions from model-level semantic invariants |
| Event consumer jobs/meta/archive links | Delivery model + queue/archive/fault tests; 20 corrupt-record reopen cases | Source/cursor/count/schema/link shape, job identity/body/ack/limits reject without changing either store. Zero-revision cursor shape and job source checks added after failing regressions. [Checkpoint](evidence/private-records-2026-11-10/README.md). Archive handoff crash/checkpoint semantics remain separate tests |
| Operation v2 records / exact persisted transaction | Operation model + duplicate/replacement/reorg/export tests; 11 corrupt-record reopen cases | Schema/required fields/identity/counters and persisted preflight reject without replacing records. Registration/reopen/metrics now share the preflight validator. [Checkpoint](evidence/private-records-2026-11-10/README.md). This validates metadata, not a fresh VM run; one close adapter, not every future operation adapter |
| Factory/shadow/session/watch configuration, private journals and health snapshots | Targeted tests, not complete mutation corpus | Bounded file/JSON readers, explicit versions/policies, canonical refresh, boot/wall expiry and negative tests. Final inventory must distinguish config/health rejection from signing-authority rollback detection |

Hub caps request bodies at 1,048,576 bytes, request lines at 8 KiB and headers at
64 KiB. Gateway uses its actual `DefaultBodyLimit` of 1 MiB + 64 KiB. Signer requests
are at most 1 MiB with bounded framing/total deadlines. The fuzz tool's 1 MiB
maximum is its own experiment bound, not proof that every production body-size
limit was exercised. Endpoint transports and fuzz workers own different bounds.

## Deterministic models

All five model areas requested by #43 exist for current implemented boundaries.
They use independent reference state rather than calling the production transition
function to compute expected results. Fixed seeds do not explore all schedules.

| Area | Model / evidence |
| --- | --- |
| Runtime replay | `morph-xtask/src/fuzz/targets/replay.rs`; [runtime/edge checkpoint](evidence/runtime-replay-model-2026-11-10/README.md) |
| Edge revisions | `morph-fiber-adapter/src/shadow/tests/model.rs`; same checkpoint; single-context per trace |
| Payment attempts | `morph-payment-gateway/src/store/outgoing/tests/model.rs`; [lifecycle checkpoint](evidence/lifecycle-models-2026-11-10/README.md) |
| Outbox delivery | `morph-events/src/tests/model.rs`; same checkpoint; one job per trace, contention tested separately |
| Operation lifecycle | `morph-cli/src/operation_runtime/tests/model.rs`; same checkpoint; controlled RPC, with replacement/native checks separate |

## Durability and external-effect fault ledger

| Actual boundary | Source tests / verified property | Evidence qualification |
| --- | --- | --- |
| Runtime transaction before commit, committed before reply, acknowledged before kill | `runtime-store::tests::real_process_kill_before_commit_after_commit_and_after_acknowledgement` | Child processes; no partially acknowledged transaction; not simulated power loss |
| SQLite fsync EIO, ENOSPC, page limit, truncation/schema drift | `actual_fsync_eio_and_enospc_never_acknowledge_partial_commit`, `actual_sqlite_page_limit_causes_full_without_partial_cross_record_commit`, `validator_is_read_only_and_schema_drift_and_truncation_fail_closed` | Actual syscall/page-limit injection and current-schema rejection, not all filesystem failure modes |
| Root creation/exit reservation, received signature, persisted receipt | `multi_asset_funding_session/tests/funding_fault_tests.rs`, `real_host_kill_after_reserve_receipt_and_record_keeps_both_root_roles_monotonic` | Actual host subprocess kills; independent signer invocation; no reservation reset |
| Update/splice creation/recovery/bridge reservation and receipt | `multi_asset_session/tests/session_fault_tests.rs`, `real_host_kill_after_reserve_receipt_and_record_keeps_all_session_roles_monotonic` | Current four session roles; no empty-signature-list inference |
| Close reservation, receipt and record | `close_real_host_kill_at_reservation_receipt_and_record_retains_authority` | Seventh isolated role, separate exact close authorization |
| Journal temp write, fsync, rename, directory fsync | `actual_write_sync_rename_and_directory_failures_keep_root_roles_recoverable`, `actual_write_sync_rename_and_directory_failures_keep_session_roles_recoverable`, `close_actual_write_sync_rename_and_directory_failures_recover_exact_authority` | Injection must hit; canonical renamed bytes remain authority. No old snapshot restoration |
| Signer partial/truncated/oversized frames, disconnect after receiving, wrong target and total deadline | `morph-signer/src/ipc/tests.rs`: `separate_process_disconnect_after_receiving_is_an_unknown_outcome`, `inbound_oversize_zero_truncated_trailing_and_malformed_frames_do_not_escape`, `deadline_is_total_not_refreshed_by_each_partial_read`, `malformed_oversized_wrong_target_replies_and_silence_never_return_receipts` | Real socket/process boundary, separate from canonical payload authority checks |
| Exact broadcast intent before network effect | `killed_broadcaster_retains_exact_intent_and_restart_reconciles_instead_of_resending`; lost reply, replacement and reorg tests in `operation_runtime/tests.rs` | Actual broadcaster kill plus controlled canonical observations; native close replacement evidence remains separate |
| Queue enrollment, send, remote acceptance, local acknowledgement | `real_process_kills_enrollment_send_acceptance_and_local_ack_boundaries` | At-least-once delivery, stable bytes/ID and receiver deduplication; never exactly-once HTTP |
| Consumer generation/archive handoff | `real_process_kills_each_archive_handoff_boundary_are_resumable` | Every implemented handoff checkpoint; no cursor reset or evidence deletion |
| Gateway reservation / provider acceptance and lost reply / terminal receipt | `real_service_kills_reservation_provider_acceptance_and_terminal_reply_never_resend`, existing contention/reopen tests and payment model | Six actual HTTP-service SIGKILL/restart scenarios with encrypted SQLite; unchanged send count, immutable result/request, success and failure. [Evidence](evidence/gateway-process-kill-2026-11-10/README.md). Controlled Fiber server; test entry point rather than CLI bootstrap; no power-loss or whole-store-rollback claim |
| Shadow mirror/coordinator/provider restart | `shadow/tests.rs`, `coordinator/tests.rs`; [real service checkpoint](evidence/shadow-service-2026-11-10/README.md) | Separate controlled/provider-process tests and pinned actual Fiber/CKB observation; no forwarding claim |
| Whole consistent signing-authority rollback | Explicit retained #55 assumption | Not solved by any of these logs, hashes, encryption, process isolation or boot clocks; cannot be marked pass by a local replay model |

## Remaining order

1. The named current binary and public DTO target gaps above now have explicit
   coverage. Preserve distinctions from transport, private config and VM semantics.
2. Private-record and real-service kill checkpoints now have executed evidence.
   Map the final declared scope to those tests; add only genuinely missing cut
   points, not duplicate campaigns or invented future consumers.
3. The initial #44 plan/candidate/index validator and execution-receipt runner
   are implemented; see [the runbook](runbooks/integration-evidence.md). Bind
   actual final-plan gates and public exports next. Historical checkpoints are
   supporting evidence, not final fresh results.
4. Keep #28 physical geometry and #55 custody/freshness claims separate. Future #30
   or routed #40 features gain their own tests when implemented; this inventory
   does not silently make every future integration a W1 prerequisite.


Hub administrative restore remains separately guarded by actual server tests:
`public_archive_is_separate_exact_and_validated_before_restore`,
`state_restore_requires_current_confirmation_hash`,
`state_restore_cannot_inject_completed_flows`,
`state_restore_rejects_replacing_operational_state`,
`state_restore_rejects_pubkey_mismatch_without_commit`, and
`state_restore_rejects_network_mismatch_without_commit` in `morph-cli/src/hub.rs`.
Their sources were inspected for the Hub DTO checkpoint; that checkpoint does
not claim to rerun the CLI suite. Final candidate qualification must bind those
server tests independently of DTO-fuzz results.
