# Experimental Fiber shadow hook

This directory carries the optional patch for Fiber revision
`a5faac7177a2a2ec086a2c6d0da1840ec9fe5703`. The patch includes its exact combined
Cargo lockfile. Its SHA-256 digest and toolchain are recorded in `manifest.json`.
Morph owns this patch; it has not been submitted upstream or released.

Read [ADR 004](../../docs/adr/004-fiber-shadow-hook.md) for the contract, authority
boundary, dependency decision and remaining #37 acceptance.

## Reproduce the targeted checks

Requirements: Linux, Rust 1.95.0, Cargo Nextest, Git, jq, rg, a C/C++ compiler and
the native build prerequisites for the pinned Fiber checkout. First compilation
also builds the upstream test dependencies, including RocksDB. Allow several
minutes. The production check here selects Fiber's SQLite backend.

From the Morph repository:

```sh
# Optional: use an existing clone as the source, without modifying its worktree.
FIBER_SOURCE=/path/to/fiber ./scripts/fiber-shadow-hook-check.sh
```

Without `FIBER_SOURCE`, the script clones the official Fiber repository. It creates
a fresh direct child of `Morph/target`, checks out the exact commit, checks and
applies the patch, and runs:

- The combined Fiber binary `cargo check`, with `sqlite,morph-shadow`.
- The native shadow RPC and separate Biscuit permission tests using Nextest.
- Fiber's SQLite backend tests after the rusqlite alignment.

It retains logs, the source-hash bracket and a machine-readable result under
`target/fiber-shadow-evidence`. It does not start a node, create a wallet, submit a
transaction, enable forwarding or qualify a clean release commit. The patch uses
relative path dependencies into this Morph source tree; applying it somewhere
else requires an explicitly reviewed dependency-layout change.

## Configure the optional module

Build Fiber with the `morph-shadow` feature and add `morph_shadow` to its explicit
RPC enabled-module list. Both `rpc.morph_shadow_policy` and
`rpc.morph_shadow_database` must be configured. Supplying those paths without
enabling the module is an error; enabling it in a binary without the feature is
also an error.

The policy is a strict JSON object containing:

| Field | Source |
| --- | --- |
| `fiber_commit` | Exact `fiber_revision` in this manifest |
| `patch_hash` | `0x` followed by this patch's SHA-256 digest |
| `ckb_genesis_hash` | Independently obtained canonical genesis hash for the selected no-value CKB network |

No example uses a fabricated live genesis. The patch compares the policy to the
initialized Fiber chain hash; the client also pins its own matching expectations.
The patch digest remains deployment metadata, not remote attestation. Capture
the actual executable and all consumed source identities in later chain acceptance.

Use a dedicated owner-only private database directory. The runtime store checks
permissions and trusted ancestry. It cannot be reopened under another policy.
Unauthenticated access is allowed only on literal loopback; other addresses need
Biscuit authentication. Issue `read("morph_shadow")` and/or
`write("morph_shadow")` capabilities separately from native graph/payment rights.
The existing hosted tenant allowlist is unchanged.

## Retry and capacity behavior

All six methods require one positional object. Register/update/drain/disable
persist an immutable revision-slot request and original reply with the mirror
mutation. Repeating that exact request reads the original reply after restart;
different contents conflict. A cached active receipt may precede a later disable:
it is historical evidence, not the current mirror state. Always list and reconcile
before making subsequent decisions.

There are at most 128 retained identities, including disabled edges. History is
not silently pruned. Exhaustion stops new work. Do not delete the database to
make a disputed request appear new or to bypass a retired epoch.

These mirrors are diagnostic only. `active`, `draining` and `disabled` all have
`forwarding=false`. Callback URLs are never invoked. Exact chain evidence,
expiry/reorg handling, a durable Morph-side orchestrator and real no-value
both-process recovery remain required for #37. Routed payments remain gated by
#38/#40 and the dependent payment/recovery implementation.
