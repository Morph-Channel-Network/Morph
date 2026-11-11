# Live participant key-policy observations — 2026-11-10

The participant key process now accepts a distinct read-only probe on its actual
private signing socket. Signing request/response encoding and authorization remain
unchanged. The fixed control frame cannot parse as a signing request. Peer UID,
private endpoint checks, bounded framing, half-close and a total monotonic I/O
budget are shared with the existing transport.

The CLI loads protected config independently, sends a fresh random challenge and
a domain-separated config digest, and rechecks config after the response. The
service compares its loaded policy with the requested digest and current file.
It does not sign, reserve a vote, inspect/mutate authority or contact RPC. Startup
already checks that the loaded key matches the configured public key. This is a
same-account trusted process observation, not cryptographic key-possession proof.

`participant-signer-readiness` names the `key_process_policy` scope only. Its
`responsive`/`policy_ready` booleans distinguish a timely negative policy response
from unavailable evidence. A two-second total horizon covers reads and exchange;
wall/boot time reject late results, backward time, reboot and suspend. JSON mode
returns nonzero unless policy-ready. Metrics mode exports two fixed gauges with
no labels; unavailable observations are zero. No readiness cache or second
signing authority is created. A successful probe does not verify journal, chain,
outbox or transaction-specific readiness.

| Verification | Result |
| --- | --- |
| `cargo test -p morph-cli --all-features` | 346 unit + 4 integration tests pass; native-event readback remains explicitly ignored without its separate devnet input |
| `cargo test -p morph-signer` | 13 pass, including existing signature receipt/unknown-outcome behavior |
| Actual CLI/key process | Live private listener; occupied queue times out; release recovers; policy change denies; SIGKILL is unavailable; reviewed restart recovers |
| No trial signing | Actual probes pass with absent journal and unavailable RPC; no authority file/sidecar is created |
| Negative transport | Wrong challenge/policy, signature-shaped response, invalid boolean, malformed control size and hangs reject |
| Freshness | Deterministic backward-wall/boot, reboot, suspend and elapsed-budget cases reject |
| Clippy | CLI/signer all-features/all-targets and default CLI all-targets pass |
| Formatting | Workspace formatting and diff whitespace checks pass |

The final test run follows the allocation correction requested by Clippy; no lint
suppression was added. `source-before.json` and `source-after.json` bind the eight
changed implementation/test/workflow files across final verification; they are
not a whole-worktree clean-source proof. `verification.json` records the built CLI
hash. Logs contain test outcomes, not key/config/payload files. Test-owned private
fixtures and service processes are removed by their guards; original wallet
nodes and `target` are preserved.

The scheduled fault campaign now includes signer transport and the actual CLI
readiness regression. The unpushed workflow has not been executed by GitHub.
No contract/ELF, public-network performance or final release qualification is
claimed. Remaining #35 work includes combining actual readiness dependencies,
complete lifecycle/payment/RBF/Sponsor metrics and calibrated alerts; other W1
acceptance and exact-candidate evidence remain open. No issue was closed and no
commit, push or release occurred in this checkpoint.

Operational semantics and actions: [external signer runbook](../../runbooks/external-participant-signer.md#read-only-key-process-policy-readiness).
