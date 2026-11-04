# Pre-production Operations

## 1. Verify the Candidate

Use a clean checkout of the exact reviewed commit. Do not reuse contract ELFs
from another worktree.

```sh
rustc --version
git status --short
make build-contracts
make release-readiness
make package-contract-release
```

The Rust release must be 1.92.0, the Git worktree must be clean, and the
manifest verifier must report eight matching scripts. Compare the deployment
report's `data_hash` values with
`release/factory-preproduction/contracts.json` before creating cells.

## 2. Handle Keys and Tokens

Use distinct keys for the fee payer, Alice, Bob, the watchtower sponsor, and
invoice signing. Never reuse a mainnet key or a key holding assets. Generate
and back up keys outside Morph; this repository does not provide a production
key-management system.

Before creating local secret files:

```sh
umask 077
install -d -m 0700 target/operator-secrets
```

Store one raw secret per file with mode 0600. Prefer CLI `--private-key-file`
or the documented `*_PRIVATE_KEY_FILE` variable. Do not pass secrets on a
command line, commit them, place them in watch configs, copy them into reports,
or paste them into incident tickets. Use scoped Hub tokens; rotate them by
restarting the Hub. The webhook HMAC secret must be different from every Hub
and signing secret.

Before and after a run, inspect generated reports for accidental secret
material. If exposure is suspected, follow the compromised-key procedure in
[`incident-response.md`](incident-response.md).

## 3. Retain Packages and Evidence

Keep participant-signed state/Factory packages on storage writable only by the
package owner. Give the watchtower a read-only replicated copy. Back up a new
package before using it to supersede, exit, or splice.

Retain:

- every signed state, conditional-batch, Factory, reduced-right, exit, and splice package;
- watch configuration, policy, cursor, health, and JSONL alerts;
- the deployment report and exact release bundle;
- smoke/stateful summaries and transaction hashes;
- the incident timeline for any warning or critical alert.

Keep packages until at least 30 days after finalisation and never less than
twice the configured challenge window. A splice starts a new funding context;
retain both pre- and post-splice packages, but publish only a package whose
funding context matches the live StateCell.

Test restoration into a separate directory. Validate restored packages with
the matching `validate-*package` command before trusting the backup. Never edit
a signed package in place.

## 4. Start and Monitor the Watchtower

Validate policy and configuration first:

```sh
cargo run -p morph-cli -- validate-watch-policy target/watch-policy.json
cargo run -p morph-cli -- validate-watch-config target/watch-config.json
cargo run -p morph-cli --features devnet -- devnet --devnet-only watch-config-once \
  --config target/watch-config.json \
  --private-key-file target/operator-secrets/watchtower.key \
  --json
```

Then run the supervised service:

```sh
cargo run -p morph-cli --features devnet -- devnet --devnet-only watch-config-service \
  --config target/watch-config.json \
  --private-key-file target/operator-secrets/watchtower.key \
  --health-file target/watchtower-health.json \
  --stop-file target/watchtower.stop \
  --json
```

The policy must require at least three-block detection depth. Each channel must
set `from_block` no later than its creation block. Alert JSONL and cursor files
must live on durable storage. Monitor health age, consecutive errors, RPC tip,
cursor progress, sponsor capacity, package freshness, and webhook delivery.

Treat `chain_reorg_detected`, repeated service errors, stale splice packages,
and any unexpected publication as pages. A reorg alert automatically resets
the cursor to `from_block`; the operator still must verify that the canonical
rescan finishes and that no orphaned publication is treated as final.

## 5. Routine Stop and Restart

Stop accepting new Factory/channel mutations first. Create the configured stop
file and wait for the service report to show `stopped_reason=stop_file`.
Preserve the health file, cursor, alerts, and package stores. Do not kill the
process during a write unless it is unsafe to let it continue.

On restart, verify the release manifest, RPC chain identity, envelope date,
package backup, cursor ownership, and health output. An uninitialised cursor without a
canonical block hash will deliberately trigger a critical rescan. Cursor JSON
requires its original `from_block` and contiguous scan heights; a changed origin
requires a fresh cursor. This reset policy does not apply to signer journals,
whose reservations must never be rolled back.
