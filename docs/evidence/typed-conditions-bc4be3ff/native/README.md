# Public local migration evidence

Protocol checkpoint: `bc4be3ff03cb4448f8e16dc95a832e4d6922ce71`. This package preserves that
original run's source identity. A later PR commit may add publication tooling,
CI or documentation; it does not change which protocol checkpoint these local
results measured.

This is a whitelist export of retained local records, not an independent
attestation, a public-network finality proof or production approval.

## Recorded results

| Item | Local result |
| --- | ---: |
| Native acceptance cases | 5 |
| Derived stateful scenarios | 10 |
| Exact retained-artifact assertions | 145 |
| Passing audit categories | 11 |
| CKB-VM tests in supplied local CI stdout | 110 |
| Distinct transaction hashes observed as Committed | 88 |
| Total measured cycles | 452,891,398 |
| Maximum measured transaction cycles | 46,887,765 |
| Total transaction bytes | 996,649 |
| Maximum transaction bytes | 231,812 |
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

The source-commit default node profile has a 55,000,000-cycle outer
transaction ceiling. Individual cases, named transactions and proof shapes
retain their explicit stricter limits, all exported in `resource-budgets.json`.
This does not assign the largest ceiling to every native operation.
The separate 70,000,000-cycle joint-dimension CKB-VM
fixture ceiling is not this native-node ceiling, and is not a universal bound
for arbitrary wallet/asset scripts or all proof topologies.

Maximum-dimension VM fixture measurements are documented in
[`current-protocol-coverage.md`](https://github.com/Morph-Channel-Network/Morph/blob/bc4be3ff03cb4448f8e16dc95a832e4d6922ce71/docs/current-protocol-coverage.md#measured-dimensional-limits).
Retained Factory floors, proof-data availability and signer rollback assumptions
remain material. Full external Fiber/Rust-scenario traffic was not executed in this
migration checkpoint; no real-asset or mainnet admission is implied.

## Files and publication boundary

- `checkpoint.json`: original source identity, counts, public node genesis and
  captured CLI/ELF hashes; the CLI and ELFs are not copied into this directory.
- `contracts.json`: the canonical eight-script release manifest, with only its
  published manifest fields. Rebuilt ELF bytes must match it.
- `transactions.json`: public hashes, observed status, block number when
  recorded, cycle/byte measurements and resource groups.
- `acceptance.json`: all 145 allowlisted assertion expectations, matched
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

Run an isolated node using the same public disposable fixture scalars 1, 2
and 3 as the CI workflow. This example supplies them directly to the child
process through protected files, without private-key argv/environment values or a separate Fiber checkout:

```sh
python3 - <<'FIXTURE'
import os
from pathlib import Path
import subprocess
import tempfile

env = os.environ.copy()
with tempfile.TemporaryDirectory(prefix="morph-public-fixtures-") as directory:
    for scalar, name in enumerate(("MORPH_DEVNET_PRIVATE_KEY_FILE", "MORPH_ALICE_PRIVATE_KEY_FILE", "MORPH_BOB_PRIVATE_KEY_FILE"), 1):
        path = Path(directory) / name
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as output:
            output.write(format(scalar, "064x") + "\n")
        env[name] = str(path)
    env["CKB_BIN"] = "/path/to/ckb"
    env["OUT_DIR"] = "target/current-protocol-e2e/reproduction"
    subprocess.run(["bash", "scripts/devnet-current-e2e.sh"], env=env, check=True)
FIXTURE
```

These scalars are public test data for a disposable development chain; use no
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
