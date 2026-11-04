# Factory Runbook Rehearsal — 2026-08-15

Historical record: the wire lengths, commands and release baseline below
belong to the dated rehearsal. They are not current parser acceptance or a
current release gate. Use [current coverage](../current-protocol-coverage.md),
the [current devnet guide](../devnet.md), and the
[current reset runbook](upgrade-and-migration.md) for today's profile.

This is the repository-side rehearsal for the controlled-devnet
`factory-dynamic-n` candidate after the signed-withdrawal wire update. It is not
the independent multi-operator rehearsal required for a production claim.

## Candidate Boundary

| Item | Value |
| --- | --- |
| Implementation parent | `1cc830f` (`fix: bind splice withdrawal destinations`) |
| Audit baseline | `9ab9ec1`, `docs/swarm-audit-glm-2026-08-15.md` |
| Rust toolchain | 1.92.0 (repository-pinned) |
| Contract target | `riscv64imac-unknown-none-elf` |
| Network/value policy | Controlled local devnet; no real assets |
| Bilateral resize wire | `SpliceHeader` 485 bytes; transition body version 2 |
| Factory resize wire | `FactorySpliceHeader` 469 bytes; full/reduced body version 2 |

The final documentation/release-cleanup commit is identified by git history;
the protocol binaries and reviewed manifest originate from implementation
commit `1cc830f`.

## Executed Checks

| Procedure | Result |
| --- | --- |
| `make ci AUDIT='cargo audit --no-fetch'` | Passed using the cached RustSec database after the live fetch returned an upstream Git I/O error. |
| `make release-readiness` | Passed: seven ELF hashes/sizes, envelope, watch policy/config, and runbooks verified. |
| `make package-contract-release` twice | Passed; both archives had SHA-256 `792c2fdcd9cac72e0bc1007552bb434ce0a5b4e88e4f757e54e3305b2c253984`. |
| Packaging cleanup check | Passed after both runs; temporary `target/contract-release.*` staging directories are removed on exit. |
| `git diff --check` | Passed. |
| Local Markdown-link/reference audit | Passed for current-tree relative links; historical audit line references resolve through audited git history. |

## Rehearsed Decisions

- Any pre-`1cc830f` contract archive is stale because splice-out signatures did
  not bind the destination lock. It must not be deployed or accepted as current
  release evidence.
- Resize-out requires the signed participant withdrawal lock and an exact
  CKB/xUDT payout output. Resize-in requires a zero withdrawal target.
- Factory child creation delegates to the exact FactoryType code hash committed
  in the child StateType args. Operators must pin the audited code identity.
- Factories admit 2–16 signers. Unsupported multi-right/variable-depth reduced
  proof shapes fail closed or use the N-of-N conservative path.
- Mainnet, real assets, external xUDTs, and Hub-submitted chain actions remain
  outside the envelope.
- A cursor hash mismatch or uninitialised cursor hash emits
  `chain_reorg_detected`, clears orphanable context, and rescans from the
  configured floor.

## Remaining External Evidence

Before any scope beyond controlled devnet, obtain independent protocol and
script reviews, a second-operator watchtower rehearsal, repeated induced reorg
and fee-pressure runs, long-running service evidence, independent release
reproduction, and an explicit real-asset value policy.
