# Current publication reliability rehearsal

This runs disposable no-value node acceptance for the current 318-byte State,
descriptor 6 and complete Vault set. It is local evidence, not a production
latency distribution or independent-operator qualification.

```sh
CKB_BIN=/absolute/path/to/ckb scripts/devnet-publication-reliability.sh
```

The script needs Cargo, curl, jq, Python 3, Perl, Git and sha256sum. It builds
the CLI and, by default, the current contracts. `BUILD_CONTRACTS=0` is available
when the intended current ELFs have already been built. The actual CLI and
all eight ELFs are copied into the fresh evidence directory and those copies
are used throughout. Do not reuse an existing evidence directory.

Default ports are 18414/18415; set `RPC_PORT`/`P2P_PORT` to unused local ports.
The node is stopped on exit. The default devnet keys come from sibling Fiber
fixture files; explicit hidden environment overrides are accepted. These are
disposable devnet funders. Watch publication uses only saved public recovery
and public Sponsor change identity. A separate operator key is used only for
its funding/change identity and the bounded configured service check; no
participant key is delivered to a watcher.

## Executed sequence

1. Deploy captured current scripts. Use native shared funding and independent
   participant journals to create, activate, publish two signed states and settle
   a real two-asset channel.
2. On this isolated node only, truncate to its genuine Settling/1 publication
   block. Retain the independently signed complete state-2 package. Assert the
   restored live cell has the actual current header and validate recovery with
   the sole current Rust parser.
3. Fund distinct state-2 SponsorCells/change identities for operators A/B and a
   deliberately insufficient cap. Retain separate package stores, cursors,
   profiles, alert files and durable attempt logs.
4. Prove cap rejection before pool mutation and actual below-floor rejection.
   Inject and measure detection delay. Publish without participant keys.
5. Clear the pool without changing the tip and prove restart retry of the same
   signed evidence; reconcile duplicate rebroadcast. Prove an insufficient
   cross-operator replacement is rejected, then learn the node's replacement
   floor and accept the second bounded attempt from the independent Sponsor.
6. Mine and reconcile canonical confirmations. Truncate before that publication,
   clear detached pool transactions and prove cursor reset/rescan and explicit
   republication onto a distinct canonical block. Compare the complete State
   and participant-signed witness evidence on both branches.
7. Run the current configured service for one idle pass and verify stopped,
   error-free, timestamped durable health. Assess the measured challenge-window
   components and reject fake State authority, wrong-network data and the
   insufficient one-sample production dataset.

The explicit synthetic rehearsal fee cap is 1,000,000,000 shannons and the
profile fee-rate cap is 400,000,000 shannons/KW. Current recovery witnesses and
recent-block estimates require more headroom than the retired smaller profile.
The cap remains enforced by both operator profile and Sponsor policy. Budget
exhaustion must fail; do not remove these checks to make a run pass.

## Review the result

The final report is
`target/devnet-publication-reliability/<run-id>/evidence/report.json`, also
linked by `latest` after success. Review actual attempt records: operator B's
first attempt must record `rbf_fee_too_low` and the learned node floor; the
second must be accepted and canonically confirmed. Reorg evidence must identify
a different canonical publication block, with unchanged participant evidence.
The service report/health, exact dataset digest, CLI/ELF/harness hashes and
working-tree fingerprint are recorded alongside the report.

A passed local report still rejects the production dataset gate. Production
requires fresh public-network samples, independent hosts/RPCs/operators,
external review, current release artifacts and approved real-asset limits.
