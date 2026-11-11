# Watch isolation and scan-readiness checkpoint — 2026-11-10

The configured watcher now retains individual failures and proceeds to later
resources. Each channel gets a bounded RPC client; a busy cursor no longer waits
indefinitely. Saved recovery network and State/Vault script identities must match
the RPC genesis and current artifact set. Health has one current v2 schema,
per-resource start times, wall/boot expiry and a config/policy/location binding.
The keyless probe emits eight fixed gauges and redacted resource indices.

This is **scan coverage**. Sponsor availability, future fee headroom and challenge
margin are not proven by these observations; `protection_ready` remains false.
Health files cannot authorize publication, signing or journal restoration.

| Evidence | Result and scope |
| --- | --- |
| CLI all-features | 343 unit + 3 integration tests pass; native-event test remains ignored unless explicitly supplied native evidence |
| Final watch subset | 19 pass, including per-resource isolation, error redaction, freshness, changed config/policy and old-schema rejection |
| Network/deployment negative | Controlled RPC checks genesis and all three script identities; included in the 343 unit tests |
| Clippy | All-features/all-targets and default CLI pass |
| Native CKB | Unavailable first resource, real second channel Sponsor funding/canonical correction, reorg flow and terminal stop |
| Read-only CLI | Stopped health returns nonzero; metrics emits eight bounded gauges |
| Artifacts | Existing eight ELF manifest matches; no contract rebuild or new VM run |

`native-runner.sh` records the exact local subset runner, derived from the current
native pipeline; it stages existing contracts and invokes the real watch path in
`multi-asset-smoke --shared-funding --sponsor-publication --watch-publication
--watch-reorg`. It has this machine's repository path; change that path for a
different checkout and select a fresh no-value run directory. Actual invocation:

```sh
CKB_BIN=/home/arthur/RustRoverProjects/ckb/target/debug/ckb \
RPC_PORT=19794 P2P_PORT=19795 \
OUT_DIR=/tmp/morph-watch-readiness-native-20261110-final \
bash /tmp/morph-watch-readiness-native.sh
```

The process owned its private CKB node and stopped it on exit. Existing wallet
nodes and `target` were preserved. Fixture keys entered only through protected
files; raw databases, keys, recovery packages and complete transactions are not
copied here. `public-summary.json` contains allowlisted per-resource results and
public transaction identities only.

Native source provenance is captured before build and verified unchanged after
execution. Its helper also records the general current-runner hash; the exact
subset script and its own hash are included separately. The tree is dirty, not a
release candidate. After native acceptance, two host changes improved once/loop
CLI failure reporting and moved the health probe's clock read after its final
config check; final targeted tests and Clippy passed. Native service execution
did not include those two later command/report changes. `current-source.json`
records final relevant source hashes; `verification.json` binds the retained
native executable and states this scope explicitly.

Synthetic freshness tests are not a new process-kill/ten-minute expiry experiment.
The real service matrix verifies failed-resource isolation and actual correction,
not a positive long-lived scan-health claim. Sequential scheduling, live Sponsor
budget/readiness, RBF/Sponsor business metrics and measured challenge-margin alerts
remain #35 work. This checkpoint does not close #35, publish a release, provide an
independent audit or authorize real assets.
