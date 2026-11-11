# Value-Limit Policy Runbook

The value-limit policy restricts which value an operator admits. It is a
host-side control: passing it never authorises a transaction, approves an asset
script, or proves canonical chain inclusion. Run the native script/dependency,
source-cell, signature and VM checks as well.

## Policy and accounting

`ValueLimitPolicy` declares a maximum CKB capacity and one base-unit cap for
each admitted xUDT Type hash. Unlisted Types fail closed. Author a policy with
`print-value-limit-policy-fixture`, replace its test caps with reviewed limits,
and record the digest from `validate-value-limit-policy policy.json --json`.

A custody snapshot counts every Vault's reserve and business CKB, every Type's
token quantity, and its separate State carrier. Pending conditional CKB remains
part of the funded Vault: it is counted once, even though it is absent from the
already settled allocations. Publication fees and unrelated wallet change are
separate funding lanes.

For a splice or Factory transition, take the component-wise maximum of the
before and after snapshots. Do not add mutually exclusive whole states or
cancel one asset's increase against another asset's decrease. Factory children
and retained parent custody coexist, so add those bundles within the after
snapshot, including each independently funded child carrier. Parent carrier
refunds and wallet withdrawals are released value, not a second custody bundle.

## Current package surfaces

| Schema | Verification before extraction |
| --- | --- |
| `morph.multi_asset_recovery_package.v1` | Complete current State/Vault evidence, two participant signatures and exact OutPoint commitments |
| `morph.conditional_batch_package.v2` | Its complete signed current source package, bounded conditions, complete resolution witness, preimages and refund clock |
| `morph.multi_asset_root_funding.v1` | Signed initial exit and exact-transaction root creation authorisation |
| `morph.multi_asset_splice_funding.v1` | Required signed old recovery, new exit, creation and bridge authorisations, and the exact raw transaction |
| `morph.factory_transition_package.v1` | Exact transaction and its canonical current Factory transition frame, signatures and localised proofs |
| `morph.factory_request.v1` | Core-validated exact unsigned parent body and custody, complete target rights, and every supplied child delivery attestation; missing attestations remain visible during review |

These are offline evidence checks. Native Factory source ownership and the
physical input cells still require the separate authenticated source/RPC/VM
boundary. A Factory request is an explicit proposal review surface, not proof
of a signed transaction. Its policy subject also includes every typed value
right with a zero quantity, so an unlisted asset cannot enter through a dormant
claim. Parent signing still requires all child delivery attestations and the
native canonical-source, dependency, VM and durable-reservation gates. A
detached balance list is not a supported custody package.

Retired `morph.splice_package`, `morph.factory_splice_package` and
`morph.factory_reduced_splice_package` and the detached
`morph.factory_multi_asset_materialisation.v1` plan shapes are rejected. There is no old
schema conversion or fallback.

## Applying a policy

Check a current recovery package:

```sh
cargo run -p morph-cli -- value-limit-check \
  --policy policy.json \
  --package recovery.json
```

A splice bundle must carry an explicitly supplied old source:

```sh
cargo run -p morph-cli -- value-limit-check \
  --policy policy.json \
  --package splice-funding.json \
  --old-package old-recovery.json
```

The checker verifies that the bridge actually extends that signed source.
Omitting it, substituting a different context, or passing `--old-package` for a
non-splice schema fails. Never infer old holdings from the new distribution.

Explicit amounts remain useful while sizing a channel:

```sh
cargo run -p morph-cli -- value-limit-check \
  --policy policy.json \
  --ckb 200000000000 \
  --xudt 0x<32-byte-type-hash>:5000
```

Such a sizing check does not verify a package or establish funding authority.

## Failures and retained evidence

An over-limit or unlisted asset blocks new admission. Reduce the proposed
value or review a new policy and digest. A policy change cannot make an unsafe
asset script safe. A malformed or unauthorised package requires corrected
evidence, not a relaxed cap.

A later cap reduction must not erase an existing exit package. Data retention,
watch publication, canonical inclusion, source-script approval and recovery
remain independent obligations. The checker enforces policy only when callers
route the actual current package through it; it does not claim every RPC
submission automatically enforces that policy.

Tests in `value_limit::tests` exercise current signed recovery, conditional,
root and observed splice surfaces, per-Type rejection and old-source binding.
Factory tests exercise aggregate children/carriers and current transition
proofs. Run the repository gates after changing policy extraction or formats.
