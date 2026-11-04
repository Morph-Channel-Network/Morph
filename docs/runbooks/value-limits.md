# Value-Limit Policy Runbook

Audience: operators of controlled-devnet Morph Channel deployments preparing
for any future real-assets phase. The value-limit policy is the operator
control the roadmap requires before any real-assets claim; it is host-side
only and never weakens the on-chain script boundary.

## 1. What the policy controls

A `ValueLimitPolicy` declares:

- `max_channel_ckb_capacity`: the largest CKB capacity (base units) a channel
  vault may commit;
- `max_xudt_amounts`: one cap per admitted xUDT type (canonical `0x`-prefixed
  32-byte hex). **Any asset not listed is rejected outright** (fail closed).

Enforcement is additive: it can only reject, never authorise. The CKB scripts
remain the final boundary for every on-chain rule.

## 2. Authoring and reviewing a policy

1. Start from the fixture:
   `cargo run -p morph-cli -- print-value-limit-policy-fixture > policy.json`
2. Edit the caps to values justified by evidence (liquidity, insurance, or
   experiment budgets). Every cap must have a written rationale; a cap
   without a rationale is optimism, not policy.
3. Validate and record the digest:
   `cargo run -p morph-cli -- validate-value-limit-policy policy.json --json`
   The `digest` field is a deterministic commitment over the declared caps;
   record it in the deployment log and in every broadcast approval.
4. Store the policy file with the channel's other operator records; policy
   rotation follows the same review path (new file, new digest, new sign-off).

## 3. Applying the policy

Check a value-bearing package before signing or broadcasting it:

```sh
cargo run -p morph-cli -- value-limit-check \
  --policy policy.json \
  --package factory-splice-in.json
```

Supported package schemas are the value-bearing splice surfaces:
`morph.splice_package`, `morph.factory_splice_package`, and
`morph.factory_reduced_splice_package`. The subject is the peak committed
channel holding computed component-wise across the old and new vault
descriptors. Packages are fully decoded and validated before extraction;
unknown, incomplete, or digest-invalid packages fail closed. Withdrawals and
remaining settlement are partitions of those committed vault amounts, not
additional holdings, so they are not double-counted.

Ad-hoc checks (for example when sizing a new channel) use explicit amounts:

```sh
cargo run -p morph-cli -- value-limit-check \
  --policy policy.json \
  --ckb 200000000000 \
  --xudt 0x<32-byte-type-hash>:5000
```

## 4. Failure handling

The checker also accepts `morph.multi_asset_recovery_package.v1` packages.
It counts every Vault's reserve and business CKB plus the State carrier, and
checks each registered xUDT amount separately. Unlisted assets fail closed.
Retaining recovery evidence remains separate from permission to fund or
publish new value; a reduced operator cap must not erase existing exit data.

- `channel CKB capacity ... exceeds the policy cap` or
  `xUDT asset ... exceeds the policy cap`: do not broadcast. Reduce the
  package amounts or raise the cap through review.
- `xUDT asset ... is not admitted`: the asset is entirely outside the
  deployment's declared scope. Do not add it casually; adding an asset is a
  policy change with the same review weight as a cap raise.
- Digest mismatch in an approval: the policy file changed after review.
  Stop and re-review.

## 5. Boundaries

- The policy does not inspect witness validity, signatures, or script
  consensus; those checks remain with `validate-*-package` commands and the
  on-chain scripts. Run both.
- The policy applies to stored package files. Live RPC-submitted transactions
  are checked only if the operator routes them through package tooling first;
  keep publication flows package-based until that changes.
- CI evidence: `make fixture-checks` validates the policy fixture and applies
  it to the factory splice-in fixture on every run.
