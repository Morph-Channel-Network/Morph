# Fiber/Morph Devnet Acceptance

This document defines the cross-repository devnet acceptance gate for running
Fiber and Morph against the same local CKB devnet.

For an operator-facing walkthrough of the commands, covered business flows,
evidence files, and failure handling, use
[`fiber-morph-devnet-runbook.md`](fiber-morph-devnet-runbook.md).

## Purpose

The gate tests coexistence of two separate systems:

- Fiber starts its normal three-node devnet stack.
- Morph runs the strict stateful channel and factory matrix against Fiber's CKB
  RPC endpoint.
- Fiber then runs channel and external-funding acceptance on the same running
  devnet.
- A fresh Fiber `router-pay` topology carries Morph Agent x402, Biscuit, and
  fair-exchange payments from node1 through node2 to node3.

This is deliberately stricter than a static compatibility document. It binds
Fiber's channel/external-funding evidence to Morph's bilateral, sponsor, splice,
factory, factory-splice, xUDT, watchtower, and negative-path stateful evidence.

## Commands

Preflight only:

```sh
make fiber-morph-devnet-preflight
```

Same-devnet coexistence gate:

```sh
make fiber-morph-devnet-acceptance
```

Full gate, including additional Fiber Bruno suites:

```sh
make fiber-morph-devnet-acceptance-full
```

Audit the latest completed run without rerunning devnet:

```sh
make fiber-morph-devnet-audit
```

Audit a specific run directory:

```sh
make fiber-morph-devnet-audit FIBER_MORPH_ACCEPTANCE_RUN=target/fiber-morph-devnet-acceptance/<run-id>
```

The script is also directly callable:

```sh
scripts/fiber-morph-devnet-acceptance.sh preflight
scripts/fiber-morph-devnet-acceptance.sh coexistence
scripts/fiber-morph-devnet-acceptance.sh full
scripts/fiber-morph-devnet-audit.sh target/fiber-morph-devnet-acceptance/<run-id>
```

## Dependency Resolution

The script expects sibling checkouts under the parent of this repository:

- `../fiber`
- `../ckb`
- `../ckb-cli`

If one is missing, the script clones the upstream Nervos checkout. It then
resolves or builds:

- `ckb`
- `ckb-cli`

Those binaries are exposed through a temporary `target/.../tool-bin` directory
so Fiber's existing dev scripts can keep calling `ckb` and `ckb-cli` from
`PATH`.

## Modes

### `preflight`

Checks tools, sibling repositories, CKB binaries, and records repo state. It
does not start devnet nodes.

### `coexistence`

The production coexistence gate:

1. requires a clean Morph worktree;
2. starts Fiber's three-node devnet with `e2e/external-funding-open`;
3. builds Morph RISC-V contracts;
4. runs `scripts/devnet-stateful-scenarios.sh` with
   `MORPH_CKB_RPC=http://127.0.0.1:8114`,
   `MORPH_DEVNET_AUDIT_PROFILE=docs/devnet-audit-profile.example.json`, and
   `MORPH_DEVNET_STATEFUL_BUDGET_PROFILE=docs/devnet-stateful-budget.example.json`,
   so Morph uses Fiber's CKB devnet while preserving the same audit and budget
   gates as `make devnet-stateful-e2e`;
5. runs Fiber's `e2e/external-funding-open` Bruno suite;
6. runs Fiber's required external-funding restart regression;
7. starts a fresh `e2e/router-pay` three-node topology and passes its Bruno
   suite;
8. runs two real Morph Agent payments over that route, covering x402 terminal
   settlement/Biscuit issuance and hash-locked fair exchange.

### `fiber`

Runs the strict Fiber suite set without Morph's stateful matrix. This is useful
when debugging Fiber-only business-flow coverage before paying the cost of the
full cross-repository run.

### `full`

Runs `coexistence`, then starts fresh Fiber devnets for the strict Fiber suite
set listed in `FIBER_BRUNO_SUITES`.

Default strict Fiber suites:

```text
e2e/open-use-close-a-channel
e2e/3-nodes-transfer
e2e/router-pay
e2e/reestablish
e2e/shutdown-force
e2e/hold-invoice-cancel-failure
e2e/period-check/force-close-expiry
e2e/udt
e2e/udt-router-pay
e2e/watchtower/force-close-after-open-channel
e2e/watchtower/force-close-with-pending-tlcs
e2e/watchtower/force-close-after-multiple-payments
e2e/watchtower/force-close-remote-with-pending-tlcs-and-stop-watchtower
```

The strict Fiber gate also runs every funding-transaction verification case:

```text
remove_change
modify_change
fund_from_peer
missing_inputs
```

## Evidence

Each run writes under:

```text
target/fiber-morph-devnet-acceptance/<run-id>/
```

Key files:

- `manifest.txt`: run parameters and final status;
- `repo-state.json`: Morph, Fiber, CKB, and ckb-cli checkout state;
- `acceptance-matrix.json`: required evidence families;
- `business-flow-audit.json`: machine-checked Morph/Fiber business-flow and
  security-family coverage;
- `summary.json`: top-level pass summary;
- `logs/`: Fiber stack logs, Morph stateful logs, Bruno logs, and build logs;
- `morph-stateful/evidence.json`: actual external RPC/genesis and current code/report binding;
- `fiber-coexistence-genesis.json`: independent observation of the same Fiber genesis;
- `morph-stateful/scenarios/`: strict current stateful ledger;
- `morph-stateful/scenarios/smoke/`: five actual current reports, recovery artifacts, captured ELFs and manifest.
- `morph-agent-fiber-e2e/`: Agent result, no-secret manifest, and encrypted
  payer/payee stores from the three-node route.

## Business-Flow And Security Audit

Every `coexistence`, `fiber`, and `full` run now executes
`scripts/fiber-morph-devnet-audit.sh` after writing the top-level summary. The
audit fails the run unless the completed artefacts prove the expected flow set.

Morph runs the sole `scripts/devnet-current-e2e.sh` with
`EXTERNAL_RPC_URL` set to Fiber's actual CKB RPC. It neither starts another
Morph chain nor stops the external node. The runner writes its strict stateful
ledger under `morph-stateful/scenarios/` and the five current cases, captured
ELFs and code manifest under `morph-stateful/scenarios/smoke/`:

- `bilateral_shared`: independent shared funding and whole-set settlement;
- `bilateral_splice`: asset removal/admission, withheld receipt recovery and terminal exits;
- `factory_custody_and_children`: current custody/rights operations, independent journals and full/reduced child exits;
- `watch_service_reorg`: actual current service publication and canonical rollback recovery;
- `maximum_asset_lifecycle`: eight-asset complete-set lifecycle.

The audit invokes the same current `devnet-stateful-assert` as the standalone
gate. It additionally validates exact case IDs/kinds, each real report,
318-byte recovery packages through the current Rust parser, and the independently
observed Fiber genesis against the runner's RPC/genesis evidence. Captured
artifact paths must stay inside the run. The retired physical implementation's
190-transaction and old proof-profile counters are not evidence thresholds.
Security families remain causal current stateful assertions rather than names
that make an unexecuted scenario count as covered.

For Fiber, `coexistence` requires:

- `e2e/external-funding-open`
- `e2e/external-funding-open/restart`
- `e2e/router-pay` as the real Morph Agent routing substrate
- Morph Agent x402/credential and fair-exchange payments over node1 -> node2 ->
  node3

The `full` gate additionally requires:

- `e2e/open-use-close-a-channel`
- `e2e/3-nodes-transfer`
- `e2e/router-pay`
- `e2e/reestablish`
- `e2e/shutdown-force`
- `e2e/hold-invoice-cancel-failure`
- `e2e/period-check/force-close-expiry`
- `e2e/udt`
- `e2e/udt-router-pay`
- `e2e/watchtower/force-close-after-open-channel`
- `e2e/watchtower/force-close-with-pending-tlcs`
- `e2e/watchtower/force-close-after-multiple-payments`
- `e2e/watchtower/force-close-remote-with-pending-tlcs-and-stop-watchtower`
- `e2e/funding-tx-verification/remove_change`
- `e2e/funding-tx-verification/modify_change`
- `e2e/funding-tx-verification/fund_from_peer`
- `e2e/funding-tx-verification/missing_inputs`

For Fiber, the audit does not merely trust each suite's JSON status. It also
checks the Bruno or restart log for named request evidence, including external
funding submission after restart, duplicate-payment rejection, reconnect
re-establishment, forced shutdown, cancelled hold-invoice failure decoding,
periodic expired-TLC cleanup, xUDT routing, watchtower settlement, and all four
funding-transaction verification cases. The period-check expiry suite also
requires stack-log evidence that both expired TLCs were removed with
`RemoveTlcFail` and both sides reached zero active TLCs; the dedicated
shutdown/watchtower suites provide the force-close evidence.

The coexistence gate treats Fiber's `e2e/external-funding-open` balance and
early-readiness checks as stale in this devnet profile when the upstream Bruno
collection fails only after the essential external-funding requests have
succeeded. In that case the harness still requires explicit `200 OK` evidence
for open, sign, submit, cooperative shutdown, closed-state capture, and shutdown
transaction inspection before it writes a passed evidence JSON. This exception
does not accept a failure of the external-funding flow itself.

The generated `business-flow-audit.json` records these named flows, their
evidence files, the Morph and Fiber security families, and the minimum evidence
floors for committed transactions, factory exits, factory splices, watchtower
alerts, expected failures, referenced artefacts, Fiber business flows, and
funding-transaction verification cases.

## Production Strictness

The coexistence and full gates are intentionally strict:

- Morph stateful acceptance requires committed transaction evidence;
- factory lifecycle, factory splice, extreme one-sided paths, and exact factory
  negative failures remain required;
- cycle, byte, and proof-profile budgets remain active;
- the underlying Morph stateful assertion enforces fresh artifacts against the
  current Morph commit;
- Fiber external funding must pass on the same CKB devnet where Morph deployed
  and exercised its scripts.

The tracked-clean-worktree requirement is intentional. The underlying Morph
`devnet-stateful-assert` gate checks artifact freshness against the current
commit, so every tracked production input must be reproducible from a commit.
Untracked operator files do not change the tested commit and therefore do not
invalidate a run; their presence is still captured in
`repo-state.json` as `morph.worktree_status` for audit context.

## Useful Environment Variables

```sh
FIBER_DIR=../fiber
CKB_SOURCE_DIR=../ckb
CKB_CLI_SOURCE_DIR=../ckb-cli
CKB_BIN=/absolute/path/to/ckb
CKB_CLI_BIN=/absolute/path/to/ckb-cli
FIBER_MORPH_ACCEPTANCE_MODE=coexistence
FIBER_TEST_ENV=debug
FIBER_BRUNO_SUITES="e2e/open-use-close-a-channel e2e/udt"
FIBER_FUNDING_TX_VERIFICATION_CASES="remove_change missing_inputs"
FIBER_CXXFLAGS="-include cstdint"
MORPH_FIBER_DEPLOYER_KEY_FILE=../fiber/tests/nodes/deployer/ckb/plain_key
MORPH_FIBER_ALICE_KEY_FILE=../fiber/tests/nodes/1/ckb/plain_key
MORPH_FIBER_BOB_KEY_FILE=../fiber/tests/nodes/2/ckb/plain_key
```

The current Morph phase builds and captures its intended ELFs through the sole
runner; it does not select an older prebuilt implementation.

`FIBER_BRUNO_SUITES` and `FIBER_FUNDING_TX_VERIFICATION_CASES` are useful for
local debugging. Production `fiber` and `full` audit runs expect the strict
default suite and case set above.

`FIBER_CXXFLAGS` defaults to `-include cstdint` so Fiber's locked
`ckb-librocksdb-sys 8.5.4` builds with current GCC and Clang releases. The
exact value is recorded in the run manifest and can be overridden for an
older toolchain.

The Morph stateful run reads the three public, devnet-only Fiber fixture keys
from the paths above. Their paths, never their contents, are recorded in the
manifest. Overrides must still be single-line 32-byte secp256k1 keys. No
default key exists for a production network.

## Current Boundary

This gate proves same-devnet coexistence, strict scenario compatibility, and
Morph Agent application flows over real Fiber multi-hop routing. The routed
channels in that Agent test are Fiber-native. It does not claim that Morph
Factory rights or materialised bilateral channels are already Fiber public
graph edges; that remains the external-edge hook in the integration plan.

## Current publication reliability rehearsal

`devnet-publication-reliability.sh` uses the same current funding/session,
transaction and watcher APIs, with a disposable independent CKB node. It
restores a genuine signed Settling/1 branch while retaining a newer signed
state-2 package, then tests two separate Sponsor budgets/operators. The
rehearsal retains actual fee-floor/cap rejection, bounded RBF floor learning,
unchanged-tip mempool eviction/retry, duplicate reconciliation, canonical
confirmation, induced rollback/republication, measured challenge-window
components and stopped-service health. It snapshots the CLI/ELFs used by the
run. See [the reliability runbook](runbooks/current-publication-reliability.md).

Fiber provider-route evidence is explicitly scoped: Agent manifests record
`proof_scope: "fiber_provider_route"` and `morph_custody_backing_proven: false`.
Actual x402/credential/fair-exchange traffic remains required, but it does not
prove a Morph-backed routed channel. Missing Fiber runtime/dependencies,
failed clean-source checks or unavailable RPCs must be reported as unexecuted
acceptance, not a passed cross-stack gate.
