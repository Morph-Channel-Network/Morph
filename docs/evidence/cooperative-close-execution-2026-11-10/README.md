# Cooperative-close execution checkpoint

#51 now has a real close journal/isolated-signer/native execution path. This
checkpoint builds on the earlier 100-VM-test verifier/Core checkpoint; it does not
rerun or relabel that historical VM count as new evidence.

| Validation | Result |
| --- | --- |
| CLI all-features binary tests | 313 passed |
| Shared packages / signer crate tests | 4 + 10 passed |
| Close host process termination | 3 real SIGKILL cuts: reserved, received, recorded |
| Close filesystem failures | 8 actual syscall faults: write/ENOSPC, fsync/EIO, rename/EIO, directory-fsync/EIO at each of two saves |
| Other new close tests | Whole-session receipt budget, six wrong-role rejections, spent-source rejection, authorized export and retained recovery |
| Clippy | CLI/packages/signer all features/all targets; CLI default features/all targets passed |
| Formatting | Passed |
| Native signer harness | Two/eight-token channels, 16 total role attempts, 48 separate key-service processes, 32 verified fresh caller processes |
| Native artifact check | Eight captured ELFs match the current manifest |
| Native source stability | 4,106 recorded source/generated entries unchanged during the run |

The six close-specific Rust test functions include the subprocess entrypoint.
The three kill and eight I/O scenarios are variants inside those tests, not 11
additional Rust test functions. The 16 native role attempts comprise four root
exits, four root creations and eight close approvals (two parties × two fee
versions × two channel shapes). Each attempt uses an expiry-rejected service,
a service whose signed response is discarded, then a successful retry service.

## What the native chain establishes

Each shape starts with the ordinary public funding ceremony and same-path guarded
participant journals. The shared native builder infers payouts; private journals
reserve before external key use and retain both approved fee versions. The wallet
signs only its separate plain CKB input, after checking both close signatures.
Keyless submit preflights the exact complete witnesses before persisting them.
All State/Vault inputs become spent, and every actual output is read back from
the canonical chain and compared with the signed body.

| Shape | Fully signed bytes | Node dry-run cycles | Fee in shannons |
| --- | ---: | ---: | ---: |
| Two devnet token Types | 3,548 | 12,203,398 | 200,000 |
| Eight devnet token Types | 8,294 | 13,988,452 | 200,000 |

These include the actual CKB secp wallet but use the development xUDT contract.
They do not qualify arbitrary asset scripts, maximum script sizes or all admitted
exit geometries. The configured ordinary challenge interval was 64 blocks; direct
close consumes bound Active custody without publishing/waiting through Settling.

The node is then deliberately rolled back to the predecessor. The exact fully
signed close is replayed without participant keys. On a second rollback branch,
an already signed ordinary publication consumes the source first. Reusing close
is rejected, while the retained unilateral recovery completes normal delayed
finalisation. Both participant journal files remain byte-identical throughout
those chain operations. **The final canonical branch is the unilateral fallback**;
the cooperative inclusions in the earlier branches are intentionally orphaned.

`native-results.json` contains the transaction identities, observed confirmations,
resources and explicit checks. `native-verification.json` preserves the original
harness file hashes. Full private run files, source fingerprints and binary are
under `target/close-native-evidence/reorg-race/`. The first positive-only run under
`target/close-native-evidence/initial/` is superseded by this richer run.

Reproduce with:

```sh
SCENARIO=close CKB_BIN=/path/to/ckb \
  bash scripts/devnet-external-signer-e2e.sh
```

The original six-role lifecycle harness remains available with its default
`SCENARIO=lifecycle`. The new variant reuses its node/key/process machinery.

## Remaining work and scope

The native helper accepts one plain fee input and one owner change, although the
consensus boundary permits more general independently authorized fees. It does
not automatically replace a failed body or rebase onto a different source. An
already committed transaction has spent inputs and cannot be passed through this
live-input submit path again; callers must reconcile the exact transaction hash.
An autonomous durable operation lifecycle and acknowledgment-loss handling are
still #41 work. Close API/SDK/desktop orchestration, native conditional/child cases,
and final #28/#43/#44 qualification remain open. #51 is not closed.

The current 512 KiB whole-session limit now budgets both future receipts before
accepting a proposal; it does not promise 32 maximum-size Core proposals will fit.
No older approval is removed on exhaustion. Whole-store rollback remains the
explicit #55 freshness assumption, not something fixed by these fault tests.

This is a dirty-worktree, controlled no-value checkpoint. Documentation was
updated after the source-stable native run. The eight ELFs were captured and
checked, not rebuilt by this harness. No commit, push, release, independent audit
or issue closure is claimed. See [the operational runbook](../../runbooks/cooperative-close.md).
