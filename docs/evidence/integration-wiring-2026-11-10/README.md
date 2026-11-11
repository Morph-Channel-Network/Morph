# Local candidate integration wiring — 2026-11-10

This #44 checkpoint connects the execution/index foundation to the existing
`make qualify-local-candidate` workflow. It is explicitly the
`local-candidate-baseline` profile, with `full_w1_qualified=false`.

## Implemented

- Capture after preparing exact ELFs, preserving the pre-build source identity.
  Run actual CI, native acceptance, contract/desktop packaging and the existing
  semantic qualification verifier through the same candidate-bound runner.
- Preserve merged stdout/stderr ordering in one private log. Derive the existing
  CI receipt from its actual checked execution receipt; the established CI parser
  still sees the VM runner header before its test result.
- Bind the selected node executable/version hashes, explicitly pass that node to
  the fresh development-node command and recheck it before packaging. Verify the
  current Fiber pin/patch identity without claiming an actual Fiber runtime run.
- Extract current runtime/API/event/signer version labels from source owners;
  bind those files and the SQL/API schema implementation files. No alternate
  schema implementation or historical alias was introduced.
- Assemble a strict result for each declared gate, including explicit deferred
  shadow-service/conditional-close and owner-excluded external requirements.
- Reconstruct a public index and deterministic archive from fixed allowlists,
  actual checksums and resolvable replay references. Do not copy raw logs,
  commands, arbitrary files or active private state.
- Store default runs in ignored `.local-evidence/` outside Cargo's target cache.
  A manual `qualify_baseline` workflow input runs the larger path and uploads
  only the exact sanitized tarball. Ordinary PR native acceptance is retained.

The existing semantic verifier still checks source freshness, native assertions,
policy expiry, all archive/ELF identities and exact package contents. The index
wrapper does not replace those assertions with directory-name or status trust.

## Executed verification

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts/tests -p 'test_*.py'
bash -n scripts/qualify-local-candidate.sh
git diff --check
```

**42 Python tests pass**, including 11 integration-validator/real-runner tests
and 9 baseline wiring tests. Synthetic final-assembly tests use controlled source
capture/node identities to exercise actual assemblers/exporters/archive writers;
they do not execute a Morph native chain. Negatives reject changed package bytes,
weakened plans, substituted qualification identity, failed gate receipts, changed
public indices, even-checksummed extra private files and links. Archive tests
read actual tar bytes, check all member hashes/replay locations and reproduce
identical bytes on a second packaging pass.

The actual dirty working tree was probed through `qualify-local-candidate.sh`
with a fresh explicit output path. It returned exit 1 with
`commit tracked changes before qualification`; no run directory was created.
This is an expected rejection, not a clean-candidate acceptance result.
Workflow YAML parsed successfully; its upload path is the single sanitized
archive. No GitHub job was triggered. No full CI/native/VM campaign or rebuilt
ELF equivalence is claimed in this checkpoint. `source-identities.json` records
post-run hashes only, not a whole-repository before/after freeze.

Final W1 native shadow/conditional-close and other applicable fault/resource/
freshness gates still need their exact-candidate integration and execution.
This does not close #44 or the full W1 set; no commit, push or release occurred.
