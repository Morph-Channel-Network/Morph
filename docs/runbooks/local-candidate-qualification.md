# Local controlled-devnet candidate qualification

This workflow produces local evidence and an archive. It does not publish a
GitHub release, create a tag, merge main, or authorize real assets.

1. Finish the source, policy and vendor changes. Run `make ci` and inspect any
   changed ELF identities. Regenerate the reviewed contract manifest only for
   intentional code/build changes, then repeat the gate.
2. Commit the exact candidate. A signed commit uses the repository's configured
   signing mechanism; do not disable it to bypass a missing unlock.
3. Select a CKB development-node binary and public disposable fixture key files
   as documented in `devnet-current-e2e.sh`. Key material stays outside evidence.
4. Run from the clean candidate, using a fresh output path:

   ```sh
   CKB_BIN=/path/to/ckb OUT_DIR=target/local-candidate/candidate-check \
     make qualify-local-candidate
   ```

The runner captures source identity before `make ci`. It binds the successful
command and complete log digest in `ci-receipt.json`, then runs a fresh isolated
native node matrix. Source changes or a dirty tracked tree fail qualification.
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
  --public-evidence target/local-candidate/candidate-check/public-evidence \
  --bundle target/local-candidate/candidate-check/morph-current-custody.tar.gz \
  --desktop-bundle target/local-candidate/candidate-check/morph-desktop-linux-x86_64.tar.gz \
  --ci-receipt target/local-candidate/candidate-check/ci-receipt.json
```

The receipt is local execution evidence. It is not an independent attestation
and is not designed to prove honesty of an administrator who controls the
source, scripts and all stored evidence. The owner removed external-operator
and external-record prerequisites from #21 for this local no-value scope on
2026-11-06; missing external evidence is not marked passed. `release_admitted`
remains false. Broader deployment qualifications remain separate.
