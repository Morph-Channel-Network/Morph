# Local controlled-devnet candidate qualification

This workflow produces local evidence and an archive. It does not publish a
GitHub release, create a tag, merge main, or authorize real assets.

1. Finish the source, policy and vendor changes. Run `make ci` and inspect any
   changed ELF identities. Regenerate the reviewed contract manifest only for
   intentional code/build changes, then repeat the gate.
2. Freeze the exact candidate in an isolated clean checkout. A detached signed
   candidate commit may be prepared without advancing `dev`; advance/push the
   branch only after acceptance. Preserve configured signing.
3. Select a CKB development-node binary and public disposable fixture key files
   as documented in `devnet-current-e2e.sh`. Key material stays outside evidence.
4. Run from the clean candidate, using a fresh output path:

   ```sh
   CKB_BIN=/path/to/ckb FIBER_SOURCE=/path/to/public/fiber-source \
     OUT_DIR=.local-evidence/candidate-check \
     make qualify-local-candidate
   ```

The runner captures source identity before preparing the exact eight ELFs,
checks them against the reviewed deployment manifest, and binds a current
integration candidate before `make ci`. The same execution-receipt runner wraps
CI, the fresh isolated native node matrix, independent signing lifecycle, two/eight
Type close, three fixed long fuzz seeds, pinned Fiber hook and actual shadow service,
both package builders and the existing
qualification verifier. Each command has actual exit/timeout and before/after
source checks; `ci-receipt.json` is derived from its checked merged execution log. Source changes or a dirty tracked tree fail qualification.
The source digest also includes new implementation files and the vendor tree.
Local packaging produces the eight-ELF archive with the current envelope and
the optimized Linux native desktop bundle with its complete dependency source
and license inventory. Each run uses a fresh Python cache prefix; generated
bytecode is ignored as build output and is never an implementation source input.

`public-evidence/` contains only the existing allowlisted evidence projection;
no active signer journal, private child exit, secret preimage, private key or
bearer token is copied into it. Raw local logs and private native artifacts
remain local, outside that public projection. Do not upload the entire run.

`qualification.json` binds the source commit/tree digest, Cargo lock/compiler,
policy/manifest, actual ELF SHA-256 and CKB hashes, local bundle, complete CI,
native genesis and public report index. It verifies archive contents without
extracting them. The native archive additionally binds the exact built executable,
Cargo/vendor metadata, registry archive checksums, and both MPL source/notices.
Unexpected files, links, duplicates, changed bytes or policy,
incomplete coverage, stale source and expired policy windows are rejected. All
auxiliary watch/publication policy and configuration files in the archive must
also match the exact candidate, even if someone recomputes archive checksums. To repeat verification:

```sh
python3 -B scripts/verify-local-candidate.py \
  --public-evidence .local-evidence/candidate-check/public-evidence \
  --bundle .local-evidence/candidate-check/morph-current-custody.tar.gz \
  --desktop-bundle .local-evidence/candidate-check/morph-desktop-linux-x86_64.tar.gz \
  --ci-receipt .local-evidence/candidate-check/ci-receipt.json
```

The receipt is local execution evidence. It is not an independent attestation
and is not designed to prove honesty of an administrator who controls the
source, scripts and all stored evidence. The owner removed external-operator
and external-record prerequisites from #21 for this local no-value scope on
2026-11-06; missing external evidence is not marked passed. `release_admitted`
remains false. Broader deployment qualifications remain separate.


The W1 profile writes `integration-plan.json`, `integration-candidate.json`,
`integration-index.json` and `integration-validation.json`, plus an allowlisted
`integration-public/` projection. `morph-integration-evidence.tar.gz` deterministically
packages that projection with the existing public native evidence. Checksums cover
every member; replay references identify concrete bundled JSON locations. Raw gate
logs live in `gates/<gate>/output.private.log` and are never archive members.
`CARGO_TERM_COLOR=never` keeps the existing CI result parser's merged log unambiguous.

The default output is under ignored `.local-evidence/`, outside Cargo's cached
`target/`. It is private (umask 077). An explicit `target/` output remains possible
for local runs, but do not cache that run directory. The node binary is selected
before execution, hashed, explicitly passed to the owned fresh-node command and
checked again before packaging. `EXTERNAL_RPC_URL` is rejected in this baseline;
the separate native acceptance command still supports its documented external
node mode. Fiber pin/patch identity is verified, and the W1 profile executes both hook checks and a
fresh Fiber/CKB shadow run before recording it as passed.

In the existing **Current protocol native acceptance** GitHub workflow, manual
`workflow_dispatch` with `qualify_baseline=true` runs this larger path (180-minute
job budget). Ordinary PR/default runs keep the existing native-only path. The
manual path uploads only the exact sanitized integration archive, not the hidden
run directory; private output stays outside the Cargo cache. A workflow definition
is not evidence that GitHub has executed it.

The profile is `w1-local-no-value`; `full_w1_qualified=true` refers only to the
declared [W1 acceptance boundary](../w1-acceptance.md). Required scenarios cannot
be skipped. Independent review/public-network retain the owner's exclusions;
live routing, future GUI/HSM work and unexposed endpoints stay explicitly deferred.
The integration exporter verifies actual role counts, reports, fixed fuzz seeds,
process recovery and sentinel CI results before assembling the public bundle.
Raw private state/logs/corpora never enter that bundle. See the
[integration evidence boundary](integration-evidence.md).
