# Candidate-bound integration evidence

`scripts/verify-integration-evidence.py` implements the first #44 index boundary.
It has one current format and no legacy aliases. It complements the native
public exporter and `verify-local-candidate.py`; it does not replace their
scenario assertions, artifact sanitization or release qualification.

The scope is always `controlled-devnet-no-real-assets`. The owner excluded
independent review and external/public-network measurement from this local
scope. Keep those exclusions explicit; never manufacture passed attestations.
No output authorizes a release, mainnet deployment or real assets.

## Three separate inputs

| Input | Purpose | Trust boundary |
| --- | --- | --- |
| Plan (`morph.integration_evidence_plan.v1`) | Required gates, exact command argv, configuration roles, fault/replay labels, schema labels and file bindings | Review before execution. The manifest cannot remove a required gate or redefine its command. This tool does not decide whether a plan covers every issue |
| Candidate (`morph.integration_candidate.v1`) | Commit, source digest, clean assertion, capture time, plan digest and artifact/schema bindings | Capture before gates. Validation independently recaptures current files and source. Neither a directory name nor a `latest` symlink is identity |
| Index (`morph.integration_evidence.v1`) | Time range and a result for every planned gate, including excluded/deferred ones | Compare with the plan, actual execution receipt, artifact bytes and replay locations. Metadata is not independent attestation |

A plan has exactly `schema`, `scope`, `bindings`, `schemas`, `gates`. Bindings
map short role names to repository-relative files. Required roles are
`cargo-lock` (`Cargo.lock`), `rust-toolchain` (`rust-toolchain.toml`),
`deployment-manifest`, and `elf-<name>` for all eight current scripts.
Capture recomputes both SHA-256 and CKB-personalized ELF data hashes and sizes,
checking every script against the deployment manifest. Add runtime/API/event
schema files, node/Fiber identities, configuration and public identity records
as explicit bindings in the final plan. Schema labels must each have a bound
file; their declared semantic meaning still requires review against that file.

Source inventory uses `current-stateful-ledger.py`: tracked files plus untracked
implementation paths, excluding generated target data. Capture refuses dirty
source; validation also refuses source, plan or bound-file changes. An output
under a tracked source path would itself change the candidate. Keep execution
outputs under an ignored target directory or outside the repository.

Each gate declaration has exactly:

- `required`: a Boolean; at least one gate must be required.
- `command`: exact argv array, not a shell command string.
- `configuration`: bound role names used by the command.
- `faults`: declared fault labels that a passing record must enumerate.
- `replay`: declared replay families that need concrete JSON locations.
- `exclusion`: empty for required gates; a nonempty reviewed scope rationale for
  optional gates. Optional does not mean silently absent.

## Execution and validation

After preparing and reviewing the plan, use the same plan for all commands:

```sh
python3 -B scripts/verify-integration-evidence.py --plan /path/to/plan.json \
  capture --output /path/to/candidate.json
python3 -B scripts/verify-integration-evidence.py --plan /path/to/plan.json \
  run --candidate /path/to/candidate.json --gate restart \
  --output target/integration-evidence/restart --timeout 3600
python3 -B scripts/verify-integration-evidence.py --plan /path/to/plan.json \
  validate --candidate /path/to/candidate.json \
  --manifest /path/to/index.json --reports target/integration-evidence
```

Paths and `restart` above illustrate the interface, not an executable final W1
plan or claimed result. A plan command is trusted executable configuration:
review it and do not put keys, tokens or other secrets in argv. The runner
executes argv directly without a shell, inherits the caller's environment and
exports none of that environment. It provides a total timeout and kills/reaps
the owned process group on timeout. It is an evidence wrapper, not a sandbox.

`run` creates a fresh directory (0700), one merged stdout/stderr `output.private.log` (0600), and a
current `execution.json`. The receipt contains gate/candidate/command/config
bindings, actual exit code, start/end seconds, timeout and before/after-source
result, and the merged-log hash. A failed execution retains its receipt and logs;
reusing a directory is rejected. Do not upload the raw logs automatically.
They can contain private output from the invoked command. Receipt JSON contains
no command arguments, raw output, private exits, preimages, keys or journal data.
Before/after hashes cannot prove that files never transiently changed during a
run; use an isolated clean checkout for final qualification.

Each index gate row has `status`, `candidate_sha256`, `command_sha256`,
`configuration` (role-to-hash map), `faults`, `replay`, `started_at`,
`finished_at`, `exit_code`, `reports` (relative-path-to-SHA-256 map), `execution`
(path to the indexed execution receipt, or null), and `reason`.
A replay maps its family to `{ "report": "relative.json", "pointer": "/path/0" }`.
The pointer must identify a nonempty value in a checksummed JSON report.
This checks existence and binding, not the semantic truth of an arbitrary
scenario result; the corresponding scenario verifier still owns that assertion.

A required gate must be `pass`, exit 0, with all declared faults/replays and a
matching execution receipt proving no reported timeout or source change.
`fail`, `skip`, `unsupported` and `deferred` never satisfy it. Non-pass rows need
a reason; nonexecuted rows cannot carry an execution receipt. Campaign times
must follow candidate capture and contain all gate times. Artifact reads reject
links, unsafe paths, duplicate JSON fields, unknown fields, oversized files and
changed hashes. Individual files are bounded at 16 MiB; aggregate report reads
at 64 MiB. Receipts and manifests remain local evidence, not unforgeable records:
an actor controlling the whole candidate and evidence can fabricate both.

## Output and remaining integration

The validation output is a small allowlisted summary: candidate/plan/index
hashes, finite gate states, artifact count and explicit false values for
independent attestation/deployment authorization. It does not copy arbitrary
reports, paths, commands, exclusion text or logs into a public bundle.

The existing `make qualify-local-candidate` now generates a reviewed-in-source
`current-local-no-value` plan through `local-integration-evidence.py`. It wraps
actual CI/native/signer/close/fuzz/shadow/package/qualification commands, checks the selected CKB binary
before and after, and executes the pinned Fiber hook and shadow service. Runtime, Hub/Gateway version,
event and signer labels are extracted from their actual current source owners;
changed/unrecognized source declarations fail rather than silently reusing labels.
The public archive includes allowlisted native reports and a limited integration
index with artifact hashes and resolvable replay references. It contains no raw
logs, commands or private runtime state. The source-bound existing native and
archive verifiers remain responsible for semantic assertions. See
[local candidate qualification](local-candidate-qualification.md) for the real
command and optional manual CI entry.

The profile covers the [declared W1 closing scope](../w1-acceptance.md).
`full_w1_qualified=true` is emitted only after the required receipts, actual
campaign semantics and final clean identity checks pass. The native gate includes
all three Factory-child closes and mutually exclusive conditional Batch forks;
separate signer and close gates exercise every current role and two/eight-Type
replacements. Three fixed fuzz seeds must cover the entire current inventory.
The public runtime projection retains only checked facts, counts and hashes.
Independent/public-network requirements canceled for this local scope remain
exclusions. New live routing, GUI/HSM and unexposed-endpoint features stay deferred.
Old scoped checkpoints do not become fresh evidence by inclusion in an index.

Tests use a temporary Git repository, synthetic nonexecutable ELF bytes and
real child processes for successful, failing, source-changing and timed-out
commands. Baseline wiring tests additionally check final assembly, private-marker
exclusion, changed packages/plan/results, archive allowlists/determinism and replay
locations. Their synthetic artifact fixtures are not native Morph acceptance.

The current profile additionally requires the `typed-conditions` gate: eight UDT
Types, eight conditions each, real-node fulfillments, a controlled rollback
with zero canonical credit, and eight refund/mixed resolutions. Both hash
algorithms, exact payout data, independent fee inputs and unchanged participant
journals are checked. `conditional_udt_qualified=true` is emitted only after
these semantics and the same candidate/artifact identities pass. Earlier W1
evidence remains historical; the base ordinary five-case matrix is preserved.
