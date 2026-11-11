# Declared close replacements and canonical winner attribution

This advances #41's first close adapter without changing contracts, signer domains
or revoking any prior approval. Close submit accepts `--replaces-operation` only
for an already registered fully signed/preflighted predecessor with the same
State source, target evidence, network, endpoint and confirmation policy.

Registering a newer fee version does not mark either operation replaced. Only
fresh canonical verification of a linked competitor produces `replaced`. The
competitor's ID/hash/block/depth are distinct from the losing operation's **zero
own confirmations**. A previously observed winner must be checked again; failed
canonical proof clears the attribution. Unknown/unlinked spenders remain
`operator_action`. Lookup is bounded to the 64-record declared family and shares
the existing total RPC deadline; it is not a chain-wide spender index.

## Executed checks

| Scope | Result |
| --- | --- |
| Full CLI binary, all features | **328 passed, 0 failed** |
| Operation tests included above | 15, including one subprocess entrypoint; four new replacement tests |
| Clippy | CLI all features/all targets and default features/all targets passed |
| fmt / diff whitespace | Passed |
| Native close acceptance | Two/eight devnet token Types passed |
| Source identity | 4,121 entries unchanged during native execution |
| Contract identity | All eight prebuilt ELFs match manifest; no contract rebuild this turn |
| Private operation stores | Two records and 36 intents/events/attempts each; validated read-only |
| Offline exports after node shutdown | Both approved versions for both shapes match original bytes; database hashes unchanged |

New tests reject changed context, genesis, evidence, endpoint, confirmation policy,
operation kind, source or missing predecessor. They verify old approval remains
usable immediately after a declaration; changed/omitted predecessor on retry
fails; a cached success field cannot establish a winner; forged canonical proof
invalidates attribution; reorg/live inputs make it recoverable; an ancestor can
win against descendants; and matching channel metadata without an explicit link
does not imply replacement.

An initial targeted test failed because its explicit `dead` mock RPC response
still overrode the restored live-cell fixture. Correcting the fixture's actual
response produced 15 passing targeted tests. The final full CLI run includes the
bounded graph traversal and passed all 328; no production check was weakened.

## Actual node branches

1. Register the older 100,000-shannon body without broadcasting. Register the
   independently authorized 200,000-shannon body with the predecessor link.
2. Publish the newer body and reach depth four. The older operation reports that
   exact winner, zero own confirmations and zero broadcasts. A repeated new
   submit still does not broadcast again.
3. Roll back once and replay the exact newer body; it again reaches depth four.
4. Roll back twice and publish the older body; it reaches depth four and the newer
   operation reports the older winner. This demonstrates actual spendability of
   the retained old approval, not merely an exportable signature file.
5. Roll back a third time and publish an ordinary retained state. Close now
   reports `operator_action`, not either cached winner. Unilateral finalisation
   succeeds and all signer journals remain byte-identical.

**The final canonical branch is ordinary unilateral fallback.** All cooperative
inclusions above were intentionally orphaned. These are controlled branches, not
multiple simultaneously canonical spends of one cell.

| Shape | Signed bytes per version | Newer-body VM cycles | Older-body VM cycles |
| --- | ---: | ---: | ---: |
| Two devnet token Types | 3,548 | 12,390,267 | 12,215,474 |
| Eight devnet token Types | 8,294 | 14,098,115 | 14,012,337 |

These are exact-body measurements with actual secp wallet fees and development
xUDT assets, not universal cost bounds. The runner repeats 16 role attempts,
48 service processes and 32 verified caller processes; these are not transaction
counts. Existing root/close signer-loss scenarios remain part of that harness.

Reproduce:

```sh
cargo test --locked -p morph-cli --all-features --bin morph-cli
cargo clippy --locked -p morph-cli --all-features --all-targets -- -D warnings
cargo clippy --locked -p morph-cli --all-targets -- -D warnings
SCENARIO=close CKB_BIN=/path/to/ckb bash scripts/devnet-external-signer-e2e.sh
```

Private originals: `target/close-native-evidence/replacement-qualified/`.
`native-results.json` is an allowlisted projection; raw signed bodies, private
databases and signer snapshots are not published here. `verification.json` binds
source hashes, run identities and scope. Documentation was updated after the run.

This dirty-worktree checkpoint does not complete other operation adapters,
autonomous scheduling, API/desktop integration, native conditional/child close,
full CI or final qualification. Whole-store rollback remains the explicit #55
assumption. No issue was closed and no commit, push, release or exposure expansion
was performed. The previous [runtime evidence](../operation-runtime-2026-11-10/README.md)
remains a historical checkpoint with its own counts and two-rollback scenario.
