# Resource-optimization candidate: `991f7e3`

All ten local controlled-devnet gates passed on signed implementation
[`991f7e30ab2f1225afbccd72862f60784a154196`](https://github.com/Morph-Channel-Network/Morph/commit/991f7e30ab2f1225afbccd72862f60784a154196).
The later commit adding this record contains documentation/evidence only and is
not another qualification of its own HEAD.

- Source tree SHA-256: `8ca5807393ff3d161678b2055b31dc2e122f69f55fa4c5dc46e8c5edc9175777`.
- Contract manifest SHA-256: `787b9f45bbd51940affc6236783b709efe5a3f76484639de2cf8794fabd07103`.
- Contract bundle SHA-256: `a07af25b9663ff224849542d83048f3d94cc284ecf36649d20932b2075e4cc33`.
- Native desktop bundle SHA-256: `517a958945be12863e041129720c2ef8e86151f8607bcd51b53ca92910e3475a`.
- Native desktop binary SHA-256: `4f7e6d5e7e717736db516b1a85cb6587ed88c8a6c97abf966536f7bcd85da0cc`.
- Eight relinked ELFs match that manifest; VM matrix **114 passed / 0 failed**.
- Native matrix: 5 actual cases, 10 derived stateful scenarios, 88 unique
  transactions (98 observations), 145 evidence assertions, 11 audit families.
- Three fixed fuzz seeds × 26 targets × 10,000 cases = **780,000** bounded
  mutation cases. This is host/parser/SDK/store testing, not 780,000 VM cases or
  coverage-guided proof.
- Independent candidate-side Python tool checks: **46 passed**.

| Required gate | Result |
| --- | --- |
| ci | Passed, exit 0 |
| native | Passed, exit 0 |
| signer-lifecycle | Passed, exit 0 |
| cooperative-close | Passed, exit 0 |
| typed-conditions | Passed, exit 0 |
| fuzz | Passed, exit 0 |
| shadow-service | Passed, exit 0 |
| contracts-package | Passed, exit 0 |
| desktop-package | Passed, exit 0 |
| qualification | Passed, exit 0 |

The exact [integration index](integration/index.json) binds source, toolchain,
schemas, runtime, artifacts and scoped gate receipts. [Runtime results](integration/runtime-results.json)
contain the redacted signer, conditional, fuzz and shadow projections. The
[native checkpoint](native/checkpoint.json), [transactions](native/transactions.json),
[acceptance](native/acceptance.json) and [qualification](qualification.json) retain
source identity and immutable hashes. Exported files are copied unchanged from
the validated exporter; private journals, signed packages, raw logs and tokens
remain in the private run directory.

## Actual-wallet conditional costs

The eight-asset / 64-condition native preflight reports **8,911,564 cycles /
14,449 bytes** for terminal settlement. Sixteen fulfill/refund-or-mixed claims
have maxima **1,831,294 cycles / 2,253 bytes**. All payouts were checked, the
first eight fulfillments lost their confirmation credit after controlled
rollback, replacement-branch resolutions were checked, exact retries did not
rebroadcast, participant journals stayed unchanged and no provider RPC was
used. Metrics are the native RPC preflight's `estimated_cycles`; successful
submission/canonical/payout evidence is recorded separately.

The earlier typed implementation checkpoint reported approximately 25.92M
cycles / 14,455 bytes. These real-wallet traces show a roughly 65.6% computation
reduction with only six bytes saved in that terminal shape. Do not infer a
matching fee reduction or apply maximum-Script VM byte savings to all wallets.
See [the complete resource comparison](../../model-resource-optimization.md).

## Reproduction and boundaries

From an isolated, clean checkout of the implementation source, supply a local
CKB development binary and the public Fiber source pinned by
`integrations/fiber-shadow/manifest.json`:

```sh
CKB_BIN=/path/to/ckb \
FIBER_SOURCE=/path/to/fiber FIBER_DIR=/path/to/fiber \
OUT_DIR=.local-evidence/reproduce make qualify-local-candidate
```

Use a fresh output directory. `FIBER_SOURCE` configures the integration plan;
`FIBER_DIR` also supplies the native matrix's public test-key fixtures. An initial
attempt with only the latter stopped at signer startup; its failed receipt was
retained and is not counted here. The final plan/run was frozen afresh and all
ten gates rerun on the same unchanged source.

No release/tag/main merge or real assets. Independent attestation and public
network measurements were excluded from this owner's local no-value profile;
none is claimed. Shadow evidence is diagnostic and nonforwarding, not live
routing. Future close GUI/HSM adapters retain the existing separate scope.
