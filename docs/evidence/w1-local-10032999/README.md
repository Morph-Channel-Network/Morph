# W1 same-candidate local qualification — 2026-11-11

All nine required gates completed successfully on signed code commit [`1003299952a1ef0d3fba1f3900b49e2104c6623e`](https://github.com/Morph-Channel-Network/Morph/commit/1003299952a1ef0d3fba1f3900b49e2104c6623e). The later commit adding this directory contains documentation/public evidence only: it is not a second executed code candidate.

The authoritative closing scope is [docs/w1-acceptance.md](https://github.com/Morph-Channel-Network/Morph/blob/1003299952a1ef0d3fba1f3900b49e2104c6623e/docs/w1-acceptance.md), covering #28/#29/#31/#32/#35/#37/#43/#44/#51/#55. The profile is `w1-local-no-value`, with clean unchanged source, exactly bound schemas/artifacts and validated report semantics.

## Executed results

- Full CI passed, including **101 CKB-VM cases**, 360 CLI unit tests, 12 smoke-report unit tests (included in CLI), and 44 Python evidence-tool tests.
- Native matrix: **5 cases / 10 stateful scenarios / 145 assertions / 11 audit families**.
- Participant lifecycle: 22 completed role attempts, 66 service processes, 44 key-using processes and 44 verified fresh caller processes.
- Cooperative-close campaign: 16 completed role attempts, 48 service processes, 32 key-using processes and 32 verified fresh caller processes; two/eight-Type replacements and unilateral fallback.
- Three seeds (1, 17, 332043276360), 26 targets and 10,000 inputs per target: **780,000 mutation inputs**. This is bounded deterministic mutation testing, not exhaustive or coverage-guided verification.
- Fiber hook/auth: two selected tests passed; SQLite backup/restore: two selected tests passed. Other filtered Fiber tests are not counted as passed.
- Real Fiber/CKB/Morph shadow: restart, journal contention, spent custody, orphaned activation and exact replay passed; **forwarding=false** throughout.
- All three Factory child close origins passed with four-confirmation checks and immutable parent/child journals. Conditional fulfill/refund execute on mutually exclusive controlled branches. The retained final branch is the existing unilateral fallback, with its pending Batch preserved.

| Gate | Started (UTC) | Finished (UTC) | Exit |
| --- | --- | --- | ---: |
| ci | 2026-11-11T02:32:29+00:00 | 2026-11-11T02:38:05+00:00 | 0 |
| native | 2026-11-11T02:38:06+00:00 | 2026-11-11T02:45:44+00:00 | 0 |
| signer-lifecycle | 2026-11-11T02:45:45+00:00 | 2026-11-11T02:47:39+00:00 | 0 |
| cooperative-close | 2026-11-11T02:47:40+00:00 | 2026-11-11T02:49:36+00:00 | 0 |
| fuzz | 2026-11-11T02:49:37+00:00 | 2026-11-11T03:06:00+00:00 | 0 |
| shadow-service | 2026-11-11T03:06:01+00:00 | 2026-11-11T03:19:12+00:00 | 0 |
| contracts-package | 2026-11-11T03:19:13+00:00 | 2026-11-11T03:19:34+00:00 | 0 |
| desktop-package | 2026-11-11T03:19:35+00:00 | 2026-11-11T03:30:30+00:00 | 0 |
| qualification | 2026-11-11T03:30:32+00:00 | 2026-11-11T03:30:34+00:00 | 0 |

## Identities and artifacts

| Identity | Exact value |
| --- | --- |
| code commit | `1003299952a1ef0d3fba1f3900b49e2104c6623e` |
| Git tree | `fa69458ed2e3ea7ebc636701953d11c9aa7f15dc` |
| source SHA-256 | `10439fc8230f5d601c13c5175cd47af42855d19ea9b9004be1bd0423d115d474` |
| Cargo.lock SHA-256 | `179b0b9c561f4074efd1e157e261275291cc7e067f038f328c35f922cdf77d02` |
| contract manifest SHA-256 | `47060e4f7f5c79ad26a6051aaf22bf7eed4ae34dd75217147b20542e34bdf067` |
| contract bundle SHA-256 | `d6097bf712b2e8dd30e5d9517731241a2aef8b6163442a7f80e4091ccc8d4e21` |
| desktop binary SHA-256 | `55fdd5493a3883428e02fa3673c92a38012ca51e7480b429910cd4191f671ca6` |
| desktop bundle SHA-256 | `2a81394cd6997d85f2c147a520518eb4a0af5e27a7f7937172a780d029bbc670` |
| public integration archive SHA-256 | `3ebf60f806ff741cd35da20b9aade4cd0537f1b9f23bccd85eb61923fd5080d4` |

| Script | Bytes | CKB data hash |
| --- | ---: | --- |
| morph-state-lock | 12960 | `0xec66a96655a9bda524e2a55a6da2b90e9982f3b57088186134438a20a2ae45b4` |
| morph-state-type | 190856 | `0x8ca45c9bf6cfbae187fd6bd7c59e9e3a77a0ad0fb6a57766015f5210b4f47e14` |
| morph-factory-type | 224224 | `0x73f77e4980a6127b03353eac1961c3aa5bdc35fc71d2faf6658fbf85cf9f8799` |
| morph-factory-vault-lock | 94872 | `0x91e6104edf5b1474687acbe7ef1ec9f52e51e3bc10c9f51033e7dd182ad9dba4` |
| morph-vault-lock | 172360 | `0x202b85e0e47824bb25604de075146d45c7eddcd7ea03da5bfcbb2ca860543e19` |
| morph-batch-lock | 44160 | `0xb565ee1f9518a90aa2908e99418dbe9b8d563701349dd20bce33558a85145bf5` |
| morph-sponsor-lock | 16592 | `0x016cea922778eae65dcda0279b5e33f6aa76b965a6eac59b03d7918c3e2f5aa6` |
| morph-devnet-xudt | 13584 | `0x0aa0aefe66ef0eda5121d7c12b0856d0bff08fc204a8119c0afb192a3416cc05` |

The optimized desktop and contract bundles remain local artifacts; they were not uploaded as releases. Their exact bytes, manifest, source archives and required notices were checked by the qualification gate. [The machine index](integration/index.json), [runtime outcomes](integration/runtime-results.json), [artifact results](integration/artifact-results.json) and [native checkpoint](native/checkpoint.json) give the checked projections. The public archive contains the exact allowlisted native/integration records and their checksums. Private full reports and logs remain in the protected local run storage; they are not part of the archive.

## Reproduction

From a clean checkout of the code commit, with Rust 1.95.0, Linux native build dependencies, the CKB binary and pinned Fiber source available:

```bash
CKB_BIN=/absolute/path/to/ckb FIBER_SOURCE=/absolute/path/to/fiber \
  OUT_DIR=.local-evidence/fresh-w1 make qualify-local-candidate
```

Use a fresh output directory. The command runs all required gates and rejects changed source, missing coverage, altered reports or inconsistent artifact identities. Inspect `qualification.json`, `integration-validation.json` and `integration-public/index.json`. Local run receipts include actual commands and private log checksums; public replay references point to fixed projections.

## Boundaries

Controlled devnet, no real assets; no release/tag/main merge or deployment authorization. Independent review and public-network measurements were owner-excluded and remain explicitly deferred, never passed. Remote scheduled jobs were not claimed as executed. Live routing/provider-loss automation, new GUI flows, HSM vendor integrations and future endpoints are separate work. Intact restart durability does not detect complete consistent signer-authority rollback/clone; no internal hash chain, SQLite or process isolation claim supplies external freshness.

Failed earlier candidates were retained, corrected and superseded before this successful run; their results were not promoted. The Chinese [completion report](../../w1-completion-2026-11-11.md) explains the actual failures and fixes. The unchanged old historical evidence directories remain checkpoints, not evidence for this code identity.
