# GPUI / Rust migration acceptance record (d988c79)

> Historical acceptance record for `d988c79`, not a qualification of subsequent edits.
> Follow-up cleanup removed the retired SDK snapshots, dynamic camelCase adapter,
> unused generated package copies and duplicated node evidence. Current tests reuse
> canonical Rust package samples and a single current Gateway vector. The user
> explicitly requested no gates for that cleanup; the results below remain tied
> to their original commits, not to the subsequent unqualified cleanup and UI changes.

The frontend, internal clients and former JS/TS/Node test runners now use Rust. React/Vite, the TypeScript SDK, Node/Bruno execution, static serving and their installation outputs are retired. Existing shell node orchestration and Python evidence validators remain; neither executes a retired client runtime. See [native operations](native-desktop.md) and [dependency provenance](native-gui-dependencies.md).

Baseline: `e6469c3b4736d8ab4f62469f054f79aef71610f9`. Implementation: `371aae9`; qualification cache isolation: `31a5cf2`. This ledger and the final audit invocation correction follow those commits. No release, main merge, script deployment or real-asset admission is performed.

## Required gates

- [x] P0: one pinned GPUI family builds and passes the recorded native input/platform checks.
- [x] P1: shared DTOs and Rust clients reuse canonical protocol/package validators; independent expected vectors survive.
- [x] P2: Rust replaces SDK/Node regressions and all 15 selected Fiber scenario families, including real three-node Gateway payment, credentials and fair exchange.
- [x] P3: native read views retain capabilities, provenance, permissions, freshness and task lifecycle behavior.
- [x] P4: all 23 Hub workflows, package/root-funding review, file export and restore have native replacements with existing authorization/recovery boundaries.
- [x] P5: old implementation, static serving, build/CI and active documentation dependencies are removed; unrelated user materials are preserved.
- [x] P6: full local CI, clean-source native matrix, VM, supply-chain and exact desktop/contract artifact qualification pass. Full Fiber runtime cases pass; the final audit invocation defect and successful post-run verification are recorded below.

## Architecture and preserved behavior

Five new host crates bring the host workspace to ten: `morph-packages`, `morph-hub-api`, `morph-sdk`, `morph-desktop`, `morph-xtask`. CLI modules re-export the sole package implementation. The desktop acquires no channel key, state-number reservation or chain publication authority.

The native application has virtualized read lists and 23 typed workflows, explicit review/confirmation, scope/freshness gates, bounded background work, stale-connection rejection, native file dialogs and immutable owner-only exports. Ambiguous mutations require reconciliation and are never retried automatically. Local Hub projections, saved signatures and confirmed chain facts remain distinct.

All 13 protocol fixtures moved byte-for-byte to `fixtures/protocol`. Interoperability data preserves 29 initial vectors and 202 public calls captured while the retiring SDK's complete assertions passed. These overlap and are not advertised as 231 independent test functions. No retired implementation generates expected results during Rust tests. Dynamic JSON exports preserve u128 through `serde_json` arbitrary precision.

## Verified source and artifacts

`target/gpui-migration/clean-candidate-02/qualification.json` passes for clean source `31a5cf266a2b27aee86feec17dcd69bf5effe5bc`:

| Gate | Result |
| --- | --- |
| Full `make ci` | Passed: formatting, clippy, hygiene, supply chain, workspace, fixtures, native build, contracts and readiness |
| CLI / real Hub transport | 269 CLI tests plus the real-service native-client integration passed |
| Gateway | 31 library tests plus existing integration suites passed |
| SDK | 4 transport tests, 3 authorization tests, 2 independent vector suites passed |
| GPUI | 5 headless tests passed; native OS evidence is separate below |
| Evidence validators | 22 Python tests passed, including forged/dirty/unsafe native archive rejection |
| CKB-VM | 91 passed, 0 failed; all eight rebuilt ELF identities match the existing manifest |
| Clean native chain | 5 native cases, 10 derived scenarios, 118 evidence assertions, 83 unique transactions, 11 audit families |
| Desktop archive | 751 dependency records, 721 registry archives, 4,161 files and 2 exact MPL source archives verified |

The optimized desktop binary is about 36 MiB; its source/notices bundle is about 93 MiB. Qualified binary SHA256: `e7982f4c64e99ee561dda5fe2b6d528726317c33f1263028b90c03c26b6a113d`. The local package is not published. The contract release profile and wire boundary did not change.

The first candidate run passed CI but correctly failed source cleanliness because of a pre-existing untracked Python bytecode cache. The original cache was preserved. Generated caches are excluded from source inventories, qualification uses an isolated cache prefix, and candidate 02 reran the gates from a new clean signed commit. The failed record was not restamped.

## Real Fiber / Gateway acceptance

`target/gpui-migration/fiber-full-clean-01` executed from clean `31a5cf2` against the pinned external Fiber checkout:

- All 15 scenario families passed: **18 runtime instances**, **277 recorded request steps**, **584 checks**. The funding family runs independently for four mutation cases. Polling attempts, development block repetitions, restart and Gateway flows are not silently counted as additional source definitions; the corpus contains 268 definitions.
- External funding and owned-node restart passed; exact signed funding survived restart and the channel reached Closed.
- Real node1 → node2 → node3 x402 settlement, terminal signed receipts, Biscuit credential delivery and hash-locked encrypted result exchange passed. This proves a Fiber provider route, not Morph custody backing for that route.
- UDT, reconnection, cooperative/force closure, hold/cancel, periodic expiry and all four watchtower combinations passed with actual economic/state assertions.
- Morph's complete native matrix passed on Fiber's exact CKB genesis and RPC.

The original full command exited **1 at its final summary auditor**, after every runtime case had passed: that auditor omitted the mandatory stateful budget profile. No scenario failure was waived. Before changing tracked source, a candidate verifier added the explicit budget and audit profiles, retained all source/artifact guards and successfully rechecked the original run. The resulting audit covers **27 business flows and 22 security/recovery families**. The production script now uses those same arguments.

`target/gpui-migration/audit-replay/verification.json` records the original exit/failure, source commit, correction hash, verifier hash, input hashes and successful post-run audit. Raw scenario evidence retains its original source identity; it was not rewritten as a newer run. This is a successful post-run verification, not a claim that the original shell invocation returned zero. Runtime binaries and scenarios are unchanged by the invocation fix.

Periodic expiry checks both peers' zero in-flight balances, unchanged business balances, the same live channel and exact confirmed failed-removal TLC statuses. Current Fiber can retain terminal bookkeeping; an empty list is not substituted for these checks. Missing values, live Committed TLCs, wrong balances and closed/missing channels fail.

## Native platform evidence

GPUI Kit `=0.9.0` / GPUI pre `=0.3.11` is the sole supported family. Linux x86-64 is the tested target.

- Actual native X11 core-key delivery, UTF-8 clipboard, request review/confirmation and real Hub write passed. Automation does not claim physical keyboard delivery.
- The task-specific GNOME/Nautilus portal opened; cancellation returned and restored controls.
- The user separately confirmed actual Chinese IME, Enter confirmation and Esc composition cancellation as **正常** in the opened native window.
- The optimized Wayland binary opened, connected, navigated and opened/cancelled the native portal. This is separate from the debug-window physical IME report.

Headless input handlers, native events, physical IME and screenshots are distinct evidence classes. Other operating systems and full assistive-technology compatibility are not certified by these checks. Native dependency preparation uses system libraries or a local linker shim, never system library replacement.

## Supply chain and remaining boundaries

`make supply-chain` passes with no new advisory ignore. Only the existing rand 0.7 upstream waiver remains. All 26 exact vendored consumers have checksummed provenance and verified upstream archive reconstruction. Maintained timing/macros, SVG/fonts and zbus 6 platform dependencies replace the obsolete native graph. Unsupported alternate frontend backends are not selected.

MPL exceptions remain exact: option-ext 0.2.0 and macOS build-only cbindgen 0.28.0. Local bundles carry original notices and exact source archives. These bounded source patches require maintenance until compatible upstream releases replace them.

This migration does not implement Spore/RNA custody, change consensus formats, relax signer journals, certify independent watchtower failover or authorize real assets. Those protocol/product boundaries remain governed by their own plans and readiness gates.
