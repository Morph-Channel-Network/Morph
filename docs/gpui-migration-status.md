# GPUI / Rust migration execution ledger

Objective: replace the frontend, internal clients and former JS/TS/Node test tools with Rust, preserving existing protocol, recovery and service capabilities, then remove every active old implementation and dependency. The detailed contract is [the migration plan](gpui-rust-migration-plan.md).

Baseline: `e6469c3b4736d8ab4f62469f054f79aef71610f9`.

## Required gates

- [ ] P0: one exact native GPUI dependency family compiles with the pinned toolchain and passes real native input/platform checks.
- [x] P1: shared public DTOs and a thin Rust SDK reuse the canonical protocol/package validators; fixtures and independent expected vectors survive.
- [ ] P2: Rust controls replace SDK/Node regressions and all selected Fiber/Bruno scenario families, including real three-node Gateway payment, credentials and fair exchange.
- [ ] P3: complete native read views preserve model capabilities, record provenance, permissions, offline/stale/error and task lifecycle behavior.
- [ ] P4: all existing package, root-funding, write, export and restore workflows have native replacements with unchanged authorization/recovery boundaries.
- [ ] P5: React/Vite/TypeScript/Node/Bruno implementation, static serving, build/config/CI and active documentation dependencies are removed without deleting unrelated user materials.
- [ ] P6: full clean-source Rust/desktop/native/VM/supply-chain and artifact qualification passes; desktop packaging and platform evidence are recorded.

## Current evidence (implementation in progress)

- Registry GPUI Kit **=0.9.0** / GPUI **=0.3.11** compiles on Rust 1.95.0. Only native component/assets are selected. An actual X11 window opens and renders CJK text. Native X11 core-key delivery, UTF-8 clipboard paste, request review/confirmation and a real Hub write have passed. The system portal opened its task-specific GNOME/Nautilus chooser; closing it returned cancellation and restored controls. The user separately confirmed native Chinese IME, Enter confirmation and Esc composition cancellation as normal. That manual report is recorded independently of automated core-event/headless evidence.
- A local linker shim under `target/native-libs` uses the installed `libxkbcommon-x11.so.0`; the development linker name is absent on this machine. Qualification/CI still needs an explicit system dependency setup.
- `morph-packages` owns the former CLI public codecs and common artifact persistence; CLI files re-export that sole implementation and retain the existing test namespaces. Shared public Hub DTOs are in `morph-hub-api`, and typed bounded HTTP workflows in `morph-sdk`.
- All 13 protocol fixtures moved byte-for-byte to `fixtures/protocol`. Independent retired-SDK output is preserved under `fixtures/interop`: 29 initial vectors plus **202 public protocol calls captured while the complete retiring smoke assertions passed**. Rust validates their positive and negative behavior; it never executes the retired code to obtain expected output during tests.
- CLI regression: **271 passed**. Payment Gateway library regression: **31 passed**; its existing integration suites also passed. SDK: **4 transport tests + 3 gateway authorization tests + 2 vector suites passed**. Native GPUI: **5 tests passed**, including actual GPUI pointer/key dispatch, CJK composition via the public input handler, clipboard, retained drafts and disabled offline writes. These GPUI tests use the headless platform and do not establish native OS IME compatibility.
- The desktop implementation has read pages, virtual record lists, scope/freshness gates, 23 Hub workflow forms, explicit request review/confirmation, offline inspection, bounded worker dispatch, JSON file dialogs and private immutable export. These are **implemented, not yet fully accepted**. Mutation cancellation/transport uncertainty prevents automatic mutation retries. Service records retain their `local_operator_projection` / provenance boundaries.
- `morph-xtask gateway-fiber` now provides a Rust replacement for the former Node three-node Gateway flow: protected key-file loading, unpaid settlement rejection, exact route assertions, terminal receipts, Biscuit authorization, hash-locked AES-GCM exchange and payment indexes. It passed a real three-node Fiber route together with the **39-request** native router-pay suite. Exact source-bound final qualification remains open.

## Supply-chain qualification

`make supply-chain` passes with no new advisory ignore; the existing explicit rand 0.7 upstream waiver remains. **26** vendored dependencies have exact checksummed provenance and pass complete upstream archive reconstruction. Native timing, macro, SVG/font and D-Bus paths use maintained dependencies; the AT-SPI stack is ported to zbus 6.2.1. Native GPUI headless tests pass on that graph. See [native dependency provenance and redistribution](native-gui-dependencies.md).

MPL-2.0 is permitted only for `option-ext =0.2.0` and macOS build-only `cbindgen =0.28.0`, not globally. Exact upstream source archives and original license texts are retained under `vendor/redistribution` and `vendor/licenses/native-desktop`. Desktop packages must carry them; packaging qualification remains open.

SDK dynamic state-file exports use lossless `serde_json` arbitrary-precision numbers: a regression passes quantities above both JavaScript's exact-number limit and u64. Public protocol amounts remain decimal strings. No snapshot/journal authority or wire encoding changed.

The native Fiber runner now loads **268** source-bound request definitions across **15** scenario families through a closed Rust action/assertion vocabulary. The corpus/order, exact-integer refund, missing-value and mutation-no-retry negative tests pass. Real router-pay (39), external funding (22), owned-node restart, open/use/close (22), three-node transfer (23), reestablish (9), force shutdown (12) and Gateway routing have passed in development runs. Other scenario families and final clean-source qualification remain in progress. No retired runtime is invoked to execute these definitions.

## Current retirement and packaging

The React/Vite frontend, TypeScript SDK, Node regression sources and their installation/build outputs are deleted. Hub static serving and `--ui-dir` are removed; arbitrary file/root paths have a negative 404 test. Make/CI use Rust client and GPUI checks, and the new Rust source-surface gate passes with zero JS/TS/manifests. This is an implementation cutover under qualification, **not a claim that every live acceptance gate has finished**.

A separate host-only `desktop` profile produces an optimized Linux binary of about 36 MiB; contract release flags remain unchanged. Local packaging passes and includes the dependency closure's published source archives, exact patched/Git sources, original notices and both explicit MPL source archives. The initial bundle is deliberately marked `tracked_clean:false` until final qualification. No artifact is published.

Workspace tests (including the existing 19 Python evidence-validator tests), full clippy, supply-chain checks and **91 CKB-VM cases** pass on the current working tree. Final source-commit qualification still requires clean tracked inputs and will rerun the required gates.

## Remaining acceptance and retirement

Remaining work is the rest of the native Fiber scenario matrix and four malicious funding shapes; package/runtime/portal/IME evidence; final freshness/scope, GUI and exact-artifact verification; the final documentation/Vault report; and clean-source candidate qualification. The implementation is not yet declared complete, committed as a migration baseline or released.
