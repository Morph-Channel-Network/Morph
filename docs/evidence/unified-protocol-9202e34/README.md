# Public local migration evidence

Protocol checkpoint: `9202e34162871f90380402bdd9d6432c46406c92`. This package preserves that
original run's source identity. A later PR commit may add publication tooling,
CI or documentation; it does not change which protocol checkpoint these local
results measured.

This is a whitelist export of retained local records, not an independent
attestation, a public-network finality proof or production approval.

## Recorded results

| Item | Local result |
| --- | ---: |
| Native acceptance cases | 5 |
| Derived stateful scenarios | 9 |
| Exact retained-artifact assertions | 65 |
| Passing audit categories | 11 |
| CKB-VM tests in supplied local CI stdout | 77 |
| Distinct transaction hashes observed as Committed | 74 |
| Total measured cycles | 344,443,484 |
| Maximum measured transaction cycles | 29,129,250 |
| Total transaction bytes | 1,091,034 |
| Maximum transaction bytes | 280,956 |
| Matching ELF CKB/SHA hashes and sizes | 8 |

The pre-build record says `git_dirty=false`, and the completed manifest says
`source_unchanged=true`. These are the original run's records, not a fresh
statement about the tree that exports or publishes this directory.

There are six resource groups: five native cases plus eight ELF deployment
transactions. Transactions are deduplicated by hash; group totals do not add a
second copy of deployment. The run deliberately exercises a chain rollback.
Committed status describes the observation at that step and does not assert
that every historical branch transaction is canonical at the final tip.

## Resource scopes

The source-commit default node profile has a 40,000,000-cycle native
transaction ceiling. Its byte and deployment-specific limits are exported in
`resource-budgets.json`. The separate 70,000,000-cycle joint-dimension CKB-VM
fixture ceiling is not this native-node ceiling, and is not a universal bound
for arbitrary wallet/asset scripts or all proof topologies.

Maximum-dimension VM fixture measurements are documented in
[`current-protocol-coverage.md`](https://github.com/Morph-Channel-Network/Morph/blob/9202e34162871f90380402bdd9d6432c46406c92/docs/current-protocol-coverage.md#measured-dimensional-limits).
Retained Factory floors, proof-data availability and signer rollback assumptions
remain material. Full external Fiber/Bruno traffic was not executed in this
migration checkpoint; no real-asset or mainnet admission is implied.

## Files and publication boundary

- `checkpoint.json`: original source identity, counts, public node genesis and
  captured CLI/ELF hashes; the CLI and ELFs are not copied into this directory.
- `contracts.json`: the canonical eight-script release manifest, with only its
  published manifest fields. Rebuilt ELF bytes must match it.
- `transactions.json`: public hashes, observed status, block number when
  recorded, cycle/byte measurements and resource groups.
- `acceptance.json`: all 65 allowlisted assertion expectations, matched
  again against the retained local artifacts during export, plus audit results.
- `publication-policy.json`: the actual bounded watch publication fee and
  challenge-window policy retained by this run.
- `source-artifacts.json`: exact hashes/sizes of source records, without copying
  their potentially private contents.
- `resource-budgets.json`: public default budget fields read from the actual
  source commit, rather than a later mutable working tree.
- `ci-results.json`: original local CI stdout hash/size and strictly allowlisted passing test/result lines. Freeform stdout is omitted.
- `SHA256SUMS`: checksums of every public file above, including this README.

Private journals, private initial-exit packages/signatures, raw witnesses,
signed unbroadcast transactions, keys, tokens and absolute home paths are
omitted. The hashes and filtered records make the local claim inspectable;
they do not independently establish the contents of withheld recovery data.

## Verify or reproduce

Verify the public package's own bytes:

```sh
sha256sum -c SHA256SUMS
```

On a clean checkout of the recorded source commit, run:

```sh
make ci
```

Run an isolated node using the public stock-dev-genesis funding fixture and
disposable participant scalars 2 and 3 from CI. This example supplies them to the child
process without printing key values or requiring a separate Fiber checkout:

```sh
python3 - <<'FIXTURE'
import os
import subprocess

env = os.environ.copy()
env["MORPH_DEVNET_PRIVATE_KEY"] = "d00c06bfd800d27397002dca6fb0993d5ba6399b4238b2f29ee9deb97593d2bc"
for scalar, name in ((2, "MORPH_ALICE_PRIVATE_KEY"), (3, "MORPH_BOB_PRIVATE_KEY")):
    env[name] = format(scalar, "064x")
env["CKB_BIN"] = "/path/to/ckb"
env["OUT_DIR"] = "target/current-protocol-e2e/reproduction"
subprocess.run(["bash", "scripts/devnet-current-e2e.sh"], env=env, check=True)
FIXTURE
```

The funding fixture is published in the [pinned CKB dev specification](https://github.com/nervosnetwork/ckb/blob/2592ddf0502cd4adfe886db893cccc866db3c60f/resource/specs/dev.toml); all three keys are public development test data. Use no
real funds. See the repository CI workflow for its pinned CKB download and the
same fixture setup. A fresh run has new transaction hashes and its own immutable
provenance; it must pass artifact, budget, audit-category and source-freshness
checks. The original checkpoint's private key files are not needed or published.

On a checkout containing the publication tool, export a completed run with:

```sh
python3 -B scripts/export-current-public-evidence.py --run-dir target/current-protocol-e2e/reproduction --source-commit FULL_RECORDED_COMMIT --ci-log target/reproduction-ci.log --output-dir target/current-public-evidence
```

`--source-commit` verifies the recorded full commit and cannot relabel it. Use a
fresh output directory. `--ci-log` is optional and never uploads raw stdout.
The original private run directory must not be uploaded as a substitute.
