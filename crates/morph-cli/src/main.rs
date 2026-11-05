#![forbid(unsafe_code)]

use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;
#[cfg(feature = "devnet")]
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, ensure};
#[cfg(feature = "devnet")]
use ckb_types::H256;
use clap::{Parser, Subcommand, ValueEnum};
#[cfg(feature = "devnet")]
use devnet::{DeployContractsOptions, FundSponsorOptions};
use k256::ecdsa::SigningKey;
use morph_core::*;
#[cfg(feature = "devnet")]
use rpc::{CkbRpcClient, HeaderView};

mod canonical_fields;
#[cfg(any(feature = "devnet", test))]
mod channel_creation;
mod conditional_packages;
#[cfg_attr(not(feature = "devnet"), allow(dead_code))]
mod devnet;
#[cfg(feature = "devnet")]
mod devnet_dispatch;
mod factory_artifacts;
mod factory_child_origin;
mod factory_child_session;
mod factory_context;
mod factory_delivery;
#[cfg(test)]
#[path = "../../morph-core/tests/support/factory_journal.rs"]
mod factory_journal_fixture;
mod factory_packets;
#[cfg(any(feature = "devnet", test))]
mod factory_root_transaction;
mod factory_session;
#[cfg(any(feature = "devnet", test))]
mod factory_transaction;
mod factory_transition_packages;
#[cfg(test)]
mod fixture_exports;
#[cfg(any(feature = "devnet", test))]
mod funding_wallets;
mod hub;
mod multi_asset_funding;
mod multi_asset_funding_session;
mod multi_asset_packages;
#[cfg(any(feature = "devnet", test))]
mod multi_asset_root_transaction;
mod multi_asset_session;
mod multi_asset_session_chain;
mod multi_asset_signatures;
mod multi_asset_splice_transaction;
#[cfg(feature = "devnet")]
mod multi_asset_supervision;
mod persistence;
mod preproduction;
#[cfg_attr(not(feature = "devnet"), allow(dead_code))]
mod publication;
mod release;
#[cfg_attr(not(feature = "devnet"), allow(dead_code))]
mod rpc;
mod smoke_report;
mod stateful_report;
mod value_limit;
#[cfg_attr(not(feature = "devnet"), allow(dead_code))]
mod watch_alert;
#[cfg_attr(not(feature = "devnet"), allow(dead_code))]
mod watch_config;
mod watch_cursor;
#[cfg_attr(not(feature = "devnet"), allow(dead_code))]
mod watch_policy;

#[derive(Debug, Parser)]
#[command(name = "morph")]
#[command(about = "Morph Channel devnet and invariant tooling")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum InvoiceNetworkArg {
    Devnet,
    Testnet,
    Mainnet,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum InvoiceAssetArg {
    Ckb,
    Xudt,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Subcommand)]
enum Command {
    /// Inspect a current signed Factory transition; live source/code checks remain native obligations.
    InspectFactoryTransition {
        path: PathBuf,
        #[arg(long)]
        source: Option<PathBuf>,
    },
    /// Independently authorize a fixed Factory child's initial exit before parent funding.
    FactoryChildSession {
        #[arg(long)]
        session: PathBuf,
        #[command(subcommand)]
        command: factory_child_session::FactoryChildSessionCommand,
    },
    /// Private child recovery delivery and public possession attestations.
    FactoryChildDelivery {
        #[command(subcommand)]
        command: factory_delivery::DeliveryCommand,
    },
    InspectFactoryCustody {
        path: PathBuf,
    },
    /// Review and sign current Factory requests through one independent durable authority.
    FactorySession {
        #[arg(long)]
        session: PathBuf,
        #[command(subcommand)]
        command: factory_session::FactorySessionCommand,
    },
    /// Inspect one canonical current Factory request without reserving authority.
    InspectFactoryRequest {
        path: PathBuf,
    },
    /// Verify a public funding bundle and durably extract its exit before the binary.
    ImportRootFunding {
        bundle: PathBuf,
        #[arg(long)]
        store_dir: PathBuf,
    },
    /// Verify a complete splice export against the old context and retain its exit before the binary.
    ImportSpliceFunding {
        bundle: PathBuf,
        #[arg(long)]
        old_package: PathBuf,
        #[arg(long)]
        store_dir: PathBuf,
    },
    /// Independently collect an initial exit before authorising exact root funding.
    MultiAssetFundingSession {
        #[arg(long)]
        session: PathBuf,
        #[command(subcommand)]
        command: multi_asset_funding_session::FundingSessionCommand,
    },
    /// Negotiate signed multi-asset updates using a durable local signing journal.
    MultiAssetSession {
        #[arg(long)]
        session: PathBuf,
        #[command(subcommand)]
        command: multi_asset_session::SessionCommand,
    },
    /// Continuously verify registered signer contexts and persist local health/alerts.
    #[cfg(feature = "devnet")]
    MultiAssetSupervise {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        health_file: PathBuf,
        #[arg(long)]
        alert_file: PathBuf,
        #[arg(long)]
        cycles: Option<u64>,
    },
    /// Read supervision health; stale or unverified contexts return a failing exit status.
    #[cfg(feature = "devnet")]
    MultiAssetSupervisionHealth {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        health_file: PathBuf,
    },
    /// Validate current custody, signed recovery and update reservation fixtures.
    ValidateFixture,
    /// Print the current signed recovery package fixture.
    PrintFixture,
    /// Create a Morph-native invoice. This is not a Fiber or Lightning invoice.
    NewInvoice {
        /// Payee Morph node id as a 32-byte 0x-prefixed hex value.
        #[arg(long)]
        payee_node_id: String,
        /// Payee secp256k1 private key used to sign the invoice.
        #[arg(long)]
        payee_private_key: String,
        /// Amount in the asset's smallest unit. CKB amounts are shannons.
        #[arg(long)]
        amount: u128,
        /// Short human description.
        #[arg(long)]
        description: String,
        /// Morph network for the invoice.
        #[arg(long, value_enum, default_value = "devnet")]
        network: InvoiceNetworkArg,
        /// Invoice asset.
        #[arg(long, value_enum, default_value = "ckb")]
        asset: InvoiceAssetArg,
        /// xUDT type hash. Required when --asset xudt.
        #[arg(long)]
        xudt_type_hash: Option<String>,
        /// Optional channel hint as a 32-byte 0x-prefixed hex value.
        #[arg(long)]
        channel_id: Option<String>,
        /// 32-byte payment preimage. Mutually exclusive with --payment-hash.
        #[arg(long)]
        payment_preimage: Option<String>,
        /// 32-byte payment hash for a hold invoice. Mutually exclusive with --payment-preimage.
        #[arg(long)]
        payment_hash: Option<String>,
        /// Creation time. Defaults to the current Unix time.
        #[arg(long)]
        created_at_unix: Option<u64>,
        /// Expiry in seconds from creation time.
        #[arg(long, default_value_t = 3600)]
        expiry_secs: u64,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Decode and validate a Morph-native invoice.
    DecodeInvoice {
        /// Encoded Morph invoice.
        invoice: String,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Verify that a payment preimage settles a Morph-native invoice.
    SettleInvoice {
        /// Encoded Morph invoice.
        invoice: String,
        /// 32-byte payment preimage.
        #[arg(long)]
        payment_preimage: String,
        /// Verification time. Defaults to the current Unix time.
        #[arg(long)]
        now_unix: Option<u64>,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Run the Morph Hub API and static UI server.
    Hub {
        #[command(subcommand)]
        command: HubCommand,
    },
    /// Print the CKB data-hash manifest for built contract ELFs.
    PrintContractManifest {
        /// Directory containing the release-profile RISC-V contract ELFs.
        #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
        contracts_dir: PathBuf,
    },
    /// Verify built contract ELFs against the reviewed release manifest.
    VerifyContractManifest {
        /// Reviewed contract release manifest.
        #[arg(long, default_value = "release/factory-preproduction/contracts.json")]
        manifest: PathBuf,
        /// Directory containing the release-profile RISC-V contract ELFs.
        #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
        contracts_dir: PathBuf,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Validate the bounded Factory pre-production envelope.
    ValidatePreproductionEnvelope {
        /// Pre-production policy envelope to validate.
        #[arg(long, default_value = "release/factory-preproduction/envelope.json")]
        envelope: PathBuf,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Print a bounded CKB conditional-batch force-resolution package fixture.
    PrintConditionalBatchFixture,
    /// Print a complete signed two-xUDT recovery package fixture.
    PrintMultiAssetFixture,
    /// Print an operator value-limit policy fixture.
    PrintValueLimitPolicyFixture,
    /// Print a sample watchtower operator policy.
    PrintWatchPolicyFixture,
    /// Print a sample multi-channel watchtower config.
    PrintWatchConfigFixture,
    /// Validate a watchtower operator policy.
    ValidateWatchPolicy {
        /// Path to the watchtower policy JSON.
        path: std::path::PathBuf,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Validate a multi-channel watchtower config.
    ValidateWatchConfig {
        /// Path to the watchtower config JSON.
        path: std::path::PathBuf,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Validate a conditional-batch force-resolution package.
    ValidateConditionalBatchPackage {
        /// Path to the conditional-batch package JSON.
        path: std::path::PathBuf,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Validate complete multi-asset unilateral recovery evidence.
    ValidateMultiAssetPackage {
        path: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Validate and atomically retain a multi-asset recovery package.
    StoreMultiAssetPackage {
        path: PathBuf,
        #[arg(long)]
        store_dir: PathBuf,
    },
    /// Validate an operator value-limit policy file.
    ValidateValueLimitPolicy {
        /// Path to the value-limit policy JSON.
        path: std::path::PathBuf,
        /// Emit machine-readable JSON including the policy digest.
        #[arg(long)]
        json: bool,
    },
    /// Check a package or explicit amounts against an operator value-limit policy.
    ValueLimitCheck {
        /// Path to the value-limit policy JSON.
        #[arg(long)]
        policy: std::path::PathBuf,
        /// Current signed recovery, funding, conditional or Factory custody package.
        #[arg(long)]
        package: Option<std::path::PathBuf>,
        /// Exact signed source recovery required by a current splice funding bundle.
        #[arg(long, requires = "package")]
        old_package: Option<std::path::PathBuf>,
        /// Explicit CKB capacity to check, in base units.
        #[arg(long, conflicts_with = "package")]
        ckb: Option<u64>,
        /// Explicit xUDT amount to check, formatted as <type-hash>:<amount>.
        #[arg(
            long = "xudt",
            value_name = "TYPE_HASH:AMOUNT",
            conflicts_with = "package"
        )]
        xudt: Vec<String>,
    },
    /// Summarise a completed scripts/devnet-smoke.sh output directory.
    DevnetSmokeReport {
        /// Directory produced by scripts/devnet-smoke.sh.
        #[arg(
            long,
            default_value = "target/current-protocol-e2e/latest/scenarios/smoke"
        )]
        dir: std::path::PathBuf,
        /// Emit machine-readable JSON instead of Markdown.
        #[arg(long)]
        json: bool,
    },
    /// Assert that a completed devnet smoke directory covers required paths.
    DevnetSmokeAssert {
        /// Directory produced by scripts/devnet-smoke.sh.
        #[arg(
            long,
            default_value = "target/current-protocol-e2e/latest/scenarios/smoke"
        )]
        dir: std::path::PathBuf,
        /// Directory containing the built RISC-V contract binaries.
        #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
        contracts_dir: std::path::PathBuf,
        /// JSON file with absolute smoke budgets for totals and named transactions.
        #[arg(long)]
        budget_profile: Option<std::path::PathBuf>,
        /// Maximum allowed total estimated cycles across all recorded transactions.
        #[arg(long)]
        max_total_cycles: Option<u64>,
        /// Maximum allowed estimated cycles for any single recorded transaction.
        #[arg(long)]
        max_tx_cycles: Option<u64>,
        /// Maximum allowed total serialized bytes across all recorded transactions.
        #[arg(long)]
        max_total_bytes: Option<usize>,
        /// Maximum allowed serialized bytes for any single recorded transaction.
        #[arg(long)]
        max_tx_bytes: Option<usize>,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Compare two completed devnet smoke output directories.
    DevnetSmokeCompare {
        /// Baseline directory produced by scripts/devnet-smoke.sh.
        #[arg(long)]
        baseline: std::path::PathBuf,
        /// Candidate directory produced by scripts/devnet-smoke.sh.
        #[arg(long)]
        candidate: std::path::PathBuf,
        /// Fail if the candidate has added or missing transaction entries.
        #[arg(long)]
        fail_on_transaction_set_change: bool,
        /// Fail if any compared transaction status changed.
        #[arg(long)]
        fail_on_status_change: bool,
        /// Maximum allowed absolute total estimated-cycle delta.
        #[arg(long)]
        max_abs_total_cycle_delta: Option<u64>,
        /// Maximum allowed absolute per-transaction estimated-cycle delta.
        #[arg(long)]
        max_abs_tx_cycle_delta: Option<u64>,
        /// Maximum allowed absolute total transaction-size delta.
        #[arg(long)]
        max_abs_total_byte_delta: Option<u64>,
        /// Maximum allowed absolute per-transaction transaction-size delta.
        #[arg(long)]
        max_abs_tx_byte_delta: Option<u64>,
        /// Emit machine-readable JSON instead of Markdown.
        #[arg(long)]
        json: bool,
    },
    /// Summarise a completed scripts/devnet-stateful-scenarios.sh output directory.
    DevnetStatefulReport {
        /// Directory produced by scripts/devnet-stateful-scenarios.sh.
        #[arg(long, default_value = "target/current-protocol-e2e/latest/scenarios")]
        dir: std::path::PathBuf,
        /// JSON file defining generalized devnet audit family requirements.
        #[arg(long, default_value = "docs/devnet-audit-profile.example.json")]
        audit_profile: std::path::PathBuf,
        /// Emit machine-readable JSON instead of Markdown.
        #[arg(long)]
        json: bool,
    },
    /// Assert that a completed devnet stateful scenario directory covers required paths.
    DevnetStatefulAssert {
        /// Directory produced by scripts/devnet-stateful-scenarios.sh.
        #[arg(long, default_value = "target/current-protocol-e2e/latest/scenarios")]
        dir: std::path::PathBuf,
        /// JSON file with absolute stateful budgets for totals and named transactions.
        #[arg(long)]
        budget_profile: Option<std::path::PathBuf>,
        /// JSON file defining generalized devnet audit family requirements.
        #[arg(long, default_value = "docs/devnet-audit-profile.example.json")]
        audit_profile: std::path::PathBuf,
        /// Directory containing the built RISC-V contract binaries.
        #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
        contracts_dir: std::path::PathBuf,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Compare two completed devnet stateful scenario directories.
    DevnetStatefulCompare {
        /// Baseline directory produced by scripts/devnet-stateful-scenarios.sh.
        #[arg(long)]
        baseline: std::path::PathBuf,
        /// Candidate directory produced by scripts/devnet-stateful-scenarios.sh.
        #[arg(long)]
        candidate: std::path::PathBuf,
        /// Fail if scenario membership or underlying transaction status changed.
        #[arg(long)]
        fail_on_status_change: bool,
        /// JSON file defining generalized devnet audit family requirements.
        #[arg(long, default_value = "docs/devnet-audit-profile.example.json")]
        audit_profile: std::path::PathBuf,
        /// Emit machine-readable JSON instead of Markdown.
        #[arg(long)]
        json: bool,
    },
    /// Talk to a local CKB devnet node without relying on ckb-cli.
    #[cfg(feature = "devnet")]
    Devnet {
        /// Confirm this is a local/devnet-only operation, not a production-chain command.
        #[arg(long = "devnet-only", required = true)]
        _devnet_only: bool,
        /// CKB JSON-RPC endpoint.
        #[arg(long, env = "MORPH_CKB_RPC", default_value = "http://127.0.0.1:18114")]
        rpc_url: String,
        #[command(subcommand)]
        command: DevnetCommand,
    },
}

#[derive(Debug, Subcommand)]
enum HubCommand {
    /// Serve the Morph Hub API and production-built UI.
    Serve {
        /// Host and port for the hub server.
        #[arg(long, default_value = "127.0.0.1:4617")]
        listen: String,
        /// Durable hub state file.
        #[arg(long, default_value = "target/morph-hub/node-state.json")]
        state_path: PathBuf,
        /// Local Morph node identity as a 33-byte compressed secp256k1 pubkey, hex without 0x.
        #[arg(long)]
        pubkey: String,
        /// Local node secp256k1 private key used only to sign newly created invoices.
        #[arg(long, env = "MORPH_HUB_INVOICE_PRIVATE_KEY", hide_env_values = true)]
        invoice_private_key: Option<String>,
        /// Morph network.
        #[arg(long, value_enum, default_value = "devnet")]
        network: InvoiceNetworkArg,
        /// Optional CKB JSON-RPC URL for live chain health.
        #[arg(long)]
        ckb_rpc_url: Option<String>,
        /// Watchtower alert JSONL file to expose as devnet evidence in Morph Hub.
        #[arg(long)]
        watch_alert_file: Option<PathBuf>,
        /// Bearer token required for Morph Hub API requests. Visible in process listings; prefer file, stdin, or rotation. Prefix with read,write,restore,sign: to scope a token.
        #[arg(long, env = "MORPH_HUB_AUTH_TOKEN", hide_env_values = true)]
        auth_token: Option<String>,
        /// Read the Morph Hub auth token from this file.
        #[arg(long)]
        auth_token_file: Option<PathBuf>,
        /// Read the Morph Hub auth token from stdin.
        #[arg(long)]
        auth_token_stdin: bool,
        /// Generate a fresh random Morph Hub auth token at startup and print it once.
        #[arg(long)]
        rotate_auth_token_on_restart: bool,
        /// Explicitly allow unauthenticated API access on loopback for local development only.
        #[arg(long)]
        allow_unauthenticated_loopback: bool,
        /// Allow replacing the durable Hub state file through PUT /api/state-file.
        #[arg(long)]
        allow_state_restore: bool,
        /// Explicit CORS origin for direct browser API access, for example http://127.0.0.1:5173.
        #[arg(long, env = "MORPH_HUB_CORS_ORIGIN")]
        cors_origin: Option<String>,
        /// Directory containing the built Morph Hub UI.
        #[arg(long, default_value = "ui/morph-hub/dist")]
        ui_dir: PathBuf,
    },
}

#[cfg(feature = "devnet")]
#[derive(Debug, Subcommand)]
enum DevnetCommand {
    /// Native current Factory lifecycle with independent signer journals.
    Factory {
        #[command(subcommand)]
        command: devnet::factory_operator::FactoryCommand,
    },
    /// Scan canonical multi-asset State Cells and publish saved newer recovery evidence.
    MultiAssetWatch {
        #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
        contracts_dir: PathBuf,
        #[command(subcommand)]
        fee_authorization: devnet::multi_asset_operator::FeeAuthorization,
        #[arg(long)]
        fee_out_point: String,
        #[arg(long)]
        store_dir: PathBuf,
        #[arg(long)]
        channel_id: String,
        #[arg(long)]
        from_block: u64,
        #[arg(long)]
        cursor_file: PathBuf,
        #[arg(long)]
        alert_file: PathBuf,
        #[arg(long)]
        publication_profile: PathBuf,
        #[arg(long)]
        attempt_log: PathBuf,
        #[arg(long, default_value_t = 1)]
        detection_depth: u64,
        #[arg(long, default_value_t = 30)]
        timeout_secs: u64,
        #[arg(long, default_value_t = 1000)]
        poll_ms: u64,
        #[arg(long)]
        max_fee: u64,
        #[arg(long, default_value_t = 0)]
        mine_blocks: u64,
    },
    /// Recover activation, publish, or finalise the complete Vault set from saved evidence.
    MultiAssetTransact {
        #[arg(long, value_enum)]
        operation: devnet::multi_asset_operator::Operation,
        #[arg(long)]
        package: PathBuf,
        #[arg(long)]
        state_out_point: String,
        #[arg(long)]
        fee_out_point: String,
        #[command(subcommand)]
        fee_authorization: devnet::multi_asset_operator::FeeAuthorization,
        #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
        contracts_dir: PathBuf,
        #[arg(long, default_value = "target/multi-asset/packages")]
        store_dir: PathBuf,
        #[arg(long, default_value_t = 100_000_000)]
        fee: u64,
        #[arg(long)]
        max_fee: u64,
        #[arg(long, default_value_t = 0)]
        mine_blocks: u64,
        #[arg(long)]
        publication_profile: Option<PathBuf>,
        #[arg(long)]
        attempt_log: Option<PathBuf>,
        #[arg(long)]
        dry_run: bool,
    },
    /// Construct exact root funding with explicit per-wallet CKB/token/fee contributions.
    MultiAssetFundingPrepare {
        #[arg(long)]
        terms: PathBuf,
        #[arg(long)]
        max_fee: u64,
        #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
        contracts_dir: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Sign only the declared wallet's group after reviewing exact funding terms and exit.
    MultiAssetFundingWalletSign {
        #[arg(long)]
        terms: PathBuf,
        #[arg(long)]
        transaction: PathBuf,
        #[arg(long)]
        package: PathBuf,
        #[arg(long)]
        max_fee: u64,
        #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
        contracts_dir: PathBuf,
        #[arg(long, default_value = "target/multi-asset/packages")]
        store_dir: PathBuf,
        #[arg(long, env = "MORPH_DEVNET_PRIVATE_KEY", hide_env_values = true)]
        private_key: String,
    },
    /// Submit a fully signed epoch-0 funding transaction or replay its exact bytes.
    MultiAssetFundingSubmit {
        #[arg(long)]
        transaction: PathBuf,
        #[arg(long)]
        package: PathBuf,
        #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
        contracts_dir: PathBuf,
        #[arg(long, default_value = "target/multi-asset/packages")]
        store_dir: PathBuf,
        #[arg(long)]
        max_fee: u64,
        #[arg(long, default_value_t = 0)]
        mine_blocks: u64,
        #[arg(long)]
        dry_run: bool,
    },
    /// Construct an exact unsigned splice draft from explicit funding inputs and value terms.
    MultiAssetSplicePrepare {
        #[arg(long)]
        old_package: PathBuf,
        #[arg(long)]
        state_out_point: String,
        #[arg(long)]
        terms: PathBuf,
        #[arg(long = "external-input", required = true)]
        external_inputs: Vec<String>,
        #[arg(long)]
        change_pubkey: String,
        #[arg(long)]
        fee: u64,
        #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
        contracts_dir: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Verify live complete sets and code, then submit an exact signed splice body.
    MultiAssetSpliceSubmit {
        #[arg(long)]
        transaction: PathBuf,
        #[arg(long)]
        old_package: PathBuf,
        #[arg(long)]
        new_package: PathBuf,
        #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
        contracts_dir: PathBuf,
        #[arg(long, default_value = "target/multi-asset/packages")]
        store_dir: PathBuf,
        #[arg(long)]
        max_fee: u64,
        #[arg(long, default_value_t = 0)]
        mine_blocks: u64,
        #[arg(long)]
        dry_run: bool,
        #[command(subcommand)]
        fee_authorization: devnet::multi_asset_splice_operator::FeeAuthorization,
    },
    /// Exercise a complete multi-xUDT channel lifecycle on an isolated devnet.
    MultiAssetSmoke {
        #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
        contracts_dir: PathBuf,
        #[arg(long, env = "MORPH_DEVNET_PRIVATE_KEY", hide_env_values = true)]
        private_key: String,
        #[arg(long, env = "MORPH_ALICE_PRIVATE_KEY", hide_env_values = true)]
        alice_private_key: String,
        #[arg(long, env = "MORPH_BOB_PRIVATE_KEY", hide_env_values = true)]
        bob_private_key: String,
        #[arg(long, default_value_t = 2)]
        asset_count: usize,
        /// Fund assets from both participants and use a third fee/carrier wallet.
        #[arg(long)]
        shared_funding: bool,
        /// Orphan and replay this exact funding transaction on the isolated devnet.
        #[arg(long, requires = "shared_funding", conflicts_with_all = ["watch_publication", "splice_transitions"])]
        funding_reorg: bool,
        /// Exercise real 2-to-1 removal and 1-to-2 admission, including a withheld bridge receipt.
        #[arg(long, conflicts_with_all = ["watch_publication", "sponsor_publication"])]
        splice_transitions: bool,
        #[arg(long, default_value_t = 100_000_000)]
        fee: u64,
        #[arg(long, default_value_t = 4)]
        finalise_since: u64,
        #[arg(long, default_value_t = 4)]
        mine_blocks: u64,
        #[arg(long, default_value = "target/multi-asset-devnet/packages")]
        store_dir: PathBuf,
        #[arg(long)]
        publication_profile: Option<PathBuf>,
        #[arg(long, requires = "publication_profile")]
        watch_publication: bool,
        #[arg(long, requires = "watch_publication")]
        watch_reorg: bool,
        /// Use a separately funded, state-number-bound SponsorCell for every publication.
        #[arg(long)]
        sponsor_publication: bool,
        #[arg(long)]
        json: bool,
    },
    /// Print chain, node, and tip status.
    Check {
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Print a validated publication profile fixture.
    PublicationProfileFixture {
        /// Emit machine-readable JSON (the fixture is always JSON).
        #[arg(long)]
        json: bool,
    },
    /// Inspect the node fee estimator and transaction-pool policy.
    FeeMarket {
        /// Optional publication profile to validate against the node.
        #[arg(long)]
        profile: Option<PathBuf>,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Derive the compressed public key used for an operator sponsor-change lock.
    DeriveOperatorPubkey {
        /// Operator secp256k1 private key. The command prints only its public key.
        #[arg(long, env = "MORPH_DEVNET_PRIVATE_KEY", hide_env_values = true)]
        private_key: String,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Assess measured publication latency against a challenge-window profile.
    AssessChallengeWindow {
        /// Directory containing the exact built RISC-V contracts expected on chain.
        #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
        contracts_dir: PathBuf,
        /// Publication profile JSON.
        #[arg(long)]
        profile: PathBuf,
        /// Challenge-window measurement dataset JSON.
        #[arg(long)]
        dataset: PathBuf,
        /// Out-of-band SHA-256 digest of the exact dataset bytes. Required with --production.
        #[arg(long)]
        expected_dataset_sha256: Option<String>,
        /// Canonical live StateCell whose deployed finalise_since is assessed.
        /// Required with --production.
        #[arg(long)]
        state_out_point: Option<String>,
        /// Enforce production structural requirements. This remains fail-closed
        /// until trusted measurement-receipt verification is implemented.
        #[arg(long)]
        production: bool,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Truncate a local devnet to a previous tip for deterministic reorg tests.
    Truncate {
        /// Canonical block hash that should become the new tip.
        target_tip_hash: String,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Print the current canonical tip header.
    Tip {
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Wait until the node reaches at least the requested block number.
    WaitTip {
        /// Minimum canonical block number.
        min_number: u64,
        /// Maximum time to wait.
        #[arg(long, default_value_t = 60)]
        timeout_secs: u64,
        /// Poll interval in milliseconds.
        #[arg(long, default_value_t = 1_000)]
        poll_ms: u64,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Generate one or more dev blocks through CKB integration-test RPC.
    Mine {
        /// Number of blocks to generate.
        #[arg(long, default_value_t = 1)]
        blocks: u64,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Deploy the Morph contract binaries to local devnet.
    DeployContracts {
        /// Directory containing the built RISC-V contract binaries.
        #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
        contracts_dir: std::path::PathBuf,
        /// Secp256k1 private key that controls a funded local-devnet cell.
        #[arg(long, env = "MORPH_DEVNET_PRIVATE_KEY", hide_env_values = true)]
        private_key: String,
        /// Absolute fee to reserve for the deployment transaction, in shannons.
        #[arg(long, default_value_t = 100_000_000)]
        fee: u64,
        /// Mine this many blocks after broadcasting. Use 0 to only submit to tx-pool.
        #[arg(long, default_value_t = 4)]
        mine_blocks: u64,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Run one configured watchtower pass across multiple channels.
    WatchConfigOnce {
        /// Directory containing the built RISC-V contract binaries.
        #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
        contracts_dir: std::path::PathBuf,
        /// Secp256k1 private key that controls sponsor funding and change.
        #[arg(long, hide_env_values = true)]
        private_key: Option<String>,
        /// File containing the sponsor private key. Prefer this for watchtower processes.
        #[arg(long, env = "MORPH_DEVNET_PRIVATE_KEY_FILE", hide_env_values = true)]
        private_key_file: Option<PathBuf>,
        /// Watchtower config JSON path.
        #[arg(long)]
        config: std::path::PathBuf,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Run several configured watchtower passes, reusing persisted cursors.
    WatchConfigLoop {
        /// Directory containing the built RISC-V contract binaries.
        #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
        contracts_dir: std::path::PathBuf,
        /// Secp256k1 private key that controls sponsor funding and change.
        #[arg(long, hide_env_values = true)]
        private_key: Option<String>,
        /// File containing the sponsor private key. Prefer this for watchtower processes.
        #[arg(long, env = "MORPH_DEVNET_PRIVATE_KEY_FILE", hide_env_values = true)]
        private_key_file: Option<PathBuf>,
        /// Watchtower config JSON path.
        #[arg(long)]
        config: std::path::PathBuf,
        /// Number of passes to run.
        #[arg(long, default_value_t = 3)]
        passes: u64,
        /// Milliseconds to sleep between passes.
        #[arg(long, default_value_t = 1_000)]
        sleep_ms: u64,
        /// Return after the first pass that publishes any state.
        #[arg(long)]
        stop_after_publication: bool,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Run a supervised watchtower service with health output and error backoff.
    WatchConfigService {
        /// Directory containing the built RISC-V contract binaries.
        #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
        contracts_dir: std::path::PathBuf,
        /// Secp256k1 private key that controls sponsor funding and change.
        #[arg(long, hide_env_values = true)]
        private_key: Option<String>,
        /// File containing the sponsor private key. Prefer this for watchtower processes.
        #[arg(long, env = "MORPH_DEVNET_PRIVATE_KEY_FILE", hide_env_values = true)]
        private_key_file: Option<PathBuf>,
        /// Watchtower config JSON path.
        #[arg(long)]
        config: std::path::PathBuf,
        /// Maximum passes before returning. Omit to run until stopped or failed.
        #[arg(long)]
        max_passes: Option<u64>,
        /// Milliseconds to sleep after a successful pass.
        #[arg(long, default_value_t = 1_000)]
        sleep_ms: u64,
        /// Milliseconds to sleep after a failed pass.
        #[arg(long, default_value_t = 5_000)]
        error_backoff_ms: u64,
        /// Stop after this many consecutive failed passes.
        #[arg(long, default_value_t = 5)]
        max_consecutive_errors: u64,
        /// Return after the first pass that publishes any state.
        #[arg(long)]
        stop_after_publication: bool,
        /// Stop gracefully when this file exists.
        #[arg(long)]
        stop_file: Option<PathBuf>,
        /// JSON health file updated after start, pass, error, and stop events.
        #[arg(long)]
        health_file: Option<PathBuf>,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Create a fresh SponsorCell for an existing channel state.
    FundSponsor {
        /// Directory containing the built RISC-V contract binaries.
        #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
        contracts_dir: std::path::PathBuf,
        /// Secp256k1 private key funding the SponsorCell and receiving change.
        #[arg(long, env = "MORPH_DEVNET_PRIVATE_KEY", hide_env_values = true)]
        private_key: String,
        /// Compressed secp256k1 pubkey whose lock receives later SponsorCell change.
        #[arg(long)]
        sponsor_change_pubkey: Option<String>,
        /// StateCell out point whose channel id should be sponsored.
        #[arg(long)]
        state_out_point: String,
        /// Capacity placed under the sponsor lock, in shannons.
        #[arg(long, default_value_t = 50_000_000_000)]
        sponsor_capacity: u64,
        /// Lowest state number the SponsorCell may pay for.
        #[arg(long, default_value_t = devnet::DEFAULT_SPONSOR_MIN_STATE_NUMBER)]
        sponsor_min_state_number: u64,
        /// Highest state number the SponsorCell may pay for.
        #[arg(long, default_value_t = devnet::DEFAULT_SPONSOR_MAX_STATE_NUMBER)]
        sponsor_max_state_number: u64,
        /// Reject sponsor policies outside the bounded default state-number window.
        #[arg(long)]
        strict_sponsor_range: bool,
        /// Maximum fee this SponsorCell may pay in one publication transaction.
        #[arg(long)]
        sponsor_max_fee_per_tx: Option<u64>,
        /// Maximum total fee this SponsorCell may pay.
        #[arg(long)]
        sponsor_max_total_fee: Option<u64>,
        /// Absolute fee for the funding transaction, in shannons.
        #[arg(long, default_value_t = 100_000_000)]
        fee: u64,
        /// Mine this many blocks after broadcasting. Use 0 to only submit to tx-pool.
        #[arg(long, default_value_t = 4)]
        mine_blocks: u64,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::InspectFactoryTransition { path, source } => {
            println!(
                "{}",
                serde_json::to_string_pretty(&factory_transition_packages::inspect(
                    &path,
                    source.as_deref()
                )?)?
            );
            Ok(())
        }
        Command::FactoryChildSession { session, command } => {
            println!(
                "{}",
                serde_json::to_string_pretty(&factory_child_session::run(&session, command)?)?
            );
            Ok(())
        }
        Command::FactoryChildDelivery { command } => {
            println!(
                "{}",
                serde_json::to_string_pretty(&factory_delivery::run(command)?)?
            );
            Ok(())
        }
        Command::InspectFactoryCustody { path } => {
            println!(
                "{}",
                serde_json::to_string_pretty(&factory_packets::read_custody(&path)?.inspect()?)?
            );
            Ok(())
        }
        Command::FactorySession { session, command } => {
            println!(
                "{}",
                serde_json::to_string_pretty(&factory_session::run(&session, command)?)?
            );
            Ok(())
        }
        Command::InspectFactoryRequest { path } => {
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &factory_packets::read_for_delivery_review(&path)?.inspect()?
                )?
            );
            Ok(())
        }
        Command::ImportRootFunding { bundle, store_dir } => {
            let result = multi_asset_funding::import_root_funding(&bundle, &store_dir)?;
            println!("{}", serde_json::to_string_pretty(&result)?);
            Ok(())
        }
        Command::ImportSpliceFunding {
            bundle,
            old_package,
            store_dir,
        } => {
            let result = multi_asset_splice_transaction::import_splice_funding(
                &bundle,
                &old_package,
                &store_dir,
            )?;
            println!("{}", serde_json::to_string_pretty(&result)?);
            Ok(())
        }
        Command::MultiAssetFundingSession { session, command } => {
            let result = multi_asset_funding_session::run(&session, command)?;
            println!("{}", serde_json::to_string_pretty(&result)?);
            Ok(())
        }
        Command::MultiAssetSession { session, command } => {
            let result = multi_asset_session::run(&session, command)?;
            println!("{}", serde_json::to_string_pretty(&result)?);
            Ok(())
        }
        #[cfg(feature = "devnet")]
        Command::MultiAssetSupervise {
            config,
            health_file,
            alert_file,
            cycles,
        } => {
            let result = multi_asset_supervision::run(&config, &health_file, &alert_file, cycles)?;
            println!("{}", serde_json::to_string_pretty(&result)?);
            Ok(())
        }
        #[cfg(feature = "devnet")]
        Command::MultiAssetSupervisionHealth {
            config,
            health_file,
        } => {
            let result = multi_asset_supervision::health(&config, &health_file)?;
            println!("{}", serde_json::to_string_pretty(&result)?);
            ensure!(
                result.healthy,
                "signer supervision is stale or contains unverified contexts"
            );
            Ok(())
        }
        Command::ValidateFixture => validate_fixture(),
        Command::PrintFixture | Command::PrintMultiAssetFixture => print_fixture(),
        Command::NewInvoice {
            payee_node_id,
            payee_private_key,
            amount,
            description,
            network,
            asset,
            xudt_type_hash,
            channel_id,
            payment_preimage,
            payment_hash,
            created_at_unix,
            expiry_secs,
            json,
        } => new_invoice_command(NewInvoiceCommand {
            payee_node_id,
            payee_private_key,
            amount,
            description,
            network,
            asset,
            xudt_type_hash,
            channel_id,
            payment_preimage,
            payment_hash,
            created_at_unix,
            expiry_secs,
            json,
        }),
        Command::DecodeInvoice { invoice, json } => decode_invoice_command(&invoice, json),
        Command::SettleInvoice {
            invoice,
            payment_preimage,
            now_unix,
            json,
        } => settle_invoice_command(&invoice, &payment_preimage, now_unix, json),
        Command::Hub { command } => match command {
            HubCommand::Serve {
                listen,
                state_path,
                pubkey,
                invoice_private_key,
                network,
                ckb_rpc_url,
                watch_alert_file,
                auth_token,
                auth_token_file,
                auth_token_stdin,
                rotate_auth_token_on_restart,
                allow_unauthenticated_loopback,
                allow_state_restore,
                cors_origin,
                ui_dir,
            } => hub::serve(hub::HubServeOptions {
                listen,
                state_path,
                pubkey,
                invoice_private_key,
                network: morph_network(network),
                ckb_rpc_url,
                watch_alert_file,
                ui_dir,
                auth_token: resolve_hub_auth_token(
                    auth_token,
                    auth_token_file,
                    auth_token_stdin,
                    rotate_auth_token_on_restart,
                )?,
                allow_unauthenticated_loopback,
                allow_state_restore,
                cors_origin,
            }),
        },
        Command::PrintContractManifest { contracts_dir } => {
            let manifest = release::build_contract_manifest(&contracts_dir)?;
            println!("{}", serde_json::to_string_pretty(&manifest)?);
            Ok(())
        }
        Command::VerifyContractManifest {
            manifest,
            contracts_dir,
            json,
        } => {
            let verification = release::verify_contract_manifest(&manifest, &contracts_dir)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&verification)?);
            } else {
                println!(
                    "verified {} CKB contract ELFs for {} against {}",
                    verification.script_count,
                    verification.release_profile,
                    manifest.display()
                );
            }
            Ok(())
        }
        Command::ValidatePreproductionEnvelope { envelope, json } => {
            let verification = preproduction::verify_preproduction_envelope(&envelope)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&verification)?);
            } else {
                println!(
                    "verified {} for {:?}; real_assets_allowed={}",
                    verification.release_profile,
                    verification.approved_networks,
                    verification.real_assets_allowed
                );
            }
            Ok(())
        }
        Command::PrintConditionalBatchFixture => {
            let package = conditional_packages::fixture_package()?;
            println!("{}", serde_json::to_string_pretty(&package)?);
            Ok(())
        }
        Command::PrintValueLimitPolicyFixture => {
            let policy = value_limit::fixture_value_limit_policy()?;
            println!("{}", serde_json::to_string_pretty(&policy)?);
            Ok(())
        }
        Command::PrintWatchPolicyFixture => {
            let policy = watch_policy::fixture_policy();
            println!("{}", serde_json::to_string_pretty(&policy)?);
            Ok(())
        }
        Command::PrintWatchConfigFixture => {
            let config = watch_config::fixture_config();
            println!("{}", serde_json::to_string_pretty(&config)?);
            Ok(())
        }
        Command::ValidateWatchPolicy { path, json } => {
            let policy = watch_policy::read_watchtower_policy(&path)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&policy)?);
            } else {
                println!("watchtower policy ok");
                println!("schema={}", policy.schema);
                if let Some(channel_id) = &policy.channel_id {
                    println!("channel_id={channel_id}");
                }
                println!("min_detection_depth={}", policy.min_detection_depth);
                println!("max_fee={}", policy.max_fee);
                println!(
                    "max_auto_sponsor_capacity={}",
                    policy.max_auto_sponsor_capacity
                );
                println!("allow_explicit_sponsor={}", policy.allow_explicit_sponsor);
                println!(
                    "require_auto_fund_sponsor={}",
                    policy.require_auto_fund_sponsor
                );
                println!("allow_webhook_alerts={}", policy.allow_webhook_alerts);
            }
            Ok(())
        }
        Command::ValidateWatchConfig { path, json } => {
            let config = watch_config::read_watchtower_config(&path)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&config)?);
            } else {
                println!("watchtower config ok");
                println!("schema={}", config.schema);
                println!("channels={}", config.channels.len());
                for channel in &config.channels {
                    println!(
                        "channel={} from_block={}",
                        channel.channel_id, channel.from_block
                    );
                }
            }
            Ok(())
        }
        Command::ValidateConditionalBatchPackage { path, json } => {
            let package = conditional_packages::read_package(&path)?;
            let summary = package.validate()?;
            if json {
                println!("{}", serde_json::to_string_pretty(&summary)?);
            } else {
                println!("conditional batch package ok");
                println!("batch_id={}", summary.batch_id);
                println!("transfer_count={}", summary.transfer_count);
                println!("total_capacity={}", summary.total_capacity);
                println!("descriptor_commitment={}", summary.descriptor_commitment);
                println!("input_since={}", summary.input_since);
                println!(
                    "resolved_capacities={},{}",
                    summary.resolved_capacities[0], summary.resolved_capacities[1]
                );
            }
            Ok(())
        }
        Command::ValidateMultiAssetPackage { path, json } => {
            let summary = multi_asset_packages::read_package(&path)?.validate()?;
            if json {
                println!("{}", serde_json::to_string_pretty(&summary)?);
            } else {
                println!(
                    "multi-asset package ok: channel={} state={} vaults={}",
                    summary.channel_id, summary.state_number, summary.vault_count
                );
            }
            Ok(())
        }
        Command::StoreMultiAssetPackage { path, store_dir } => {
            let package = multi_asset_packages::read_package(&path)?;
            let stored_path = multi_asset_packages::write_package(&store_dir, &package)?;
            println!("{}", stored_path.display());
            Ok(())
        }
        Command::ValidateValueLimitPolicy { path, json } => {
            let policy = value_limit::read_value_limit_policy(&path)?;
            let digest = policy.digest()?;
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "schema": policy.schema,
                        "max_channel_ckb_capacity": policy.max_channel_ckb_capacity,
                        "max_xudt_amounts": policy.max_xudt_amounts,
                        "digest": format!("0x{}", hex::encode(digest)),
                    })
                );
            } else {
                println!("value-limit policy ok");
                println!(
                    "max_channel_ckb_capacity={}",
                    policy.max_channel_ckb_capacity
                );
                println!("admitted_xudt_assets={}", policy.max_xudt_amounts.len());
                println!("digest=0x{}", hex::encode(digest));
            }
            Ok(())
        }
        Command::ValueLimitCheck {
            policy: policy_path,
            package,
            old_package,
            ckb,
            xudt,
        } => {
            let policy = value_limit::read_value_limit_policy(&policy_path)?;
            let subject = match (&package, ckb) {
                (Some(package_path), None) if xudt.is_empty() => {
                    let (schema, subject) =
                        value_limit::extract_value_subject(package_path, old_package.as_deref())?;
                    println!("package_schema={schema}");
                    subject
                }
                (None, Some(ckb_capacity)) => {
                    let mut subject = morph_core::ValueSubject::default();
                    subject.add_ckb(u128::from(ckb_capacity))?;
                    for entry in &xudt {
                        let (type_hash, amount) = entry.split_once(':').ok_or_else(|| {
                            anyhow::anyhow!("xudt entries must be <type-hash>:<amount>")
                        })?;
                        let amount: u128 = amount.parse()?;
                        subject.add_xudt(type_hash, amount)?;
                    }
                    subject
                }
                _ => return Err(anyhow::anyhow!("pass exactly one of --package or --ckb")),
            };
            policy.enforce(&subject)?;
            println!("value-limit check ok");
            println!("ckb_capacity={}", subject.ckb_capacity);
            println!("xudt_assets={}", subject.xudt_amounts.len());
            Ok(())
        }
        Command::DevnetSmokeReport { dir, json } => {
            let summary = smoke_report::summarize_devnet_smoke(&dir)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&summary)?);
            } else {
                print!("{}", smoke_report::render_markdown(&summary));
            }
            Ok(())
        }
        Command::DevnetSmokeAssert {
            dir,
            contracts_dir,
            budget_profile,
            max_total_cycles,
            max_tx_cycles,
            max_total_bytes,
            max_tx_bytes,
            json,
        } => {
            let mut budget_limits = if let Some(path) = budget_profile {
                smoke_report::read_smoke_budget_profile(&path)?
            } else {
                smoke_report::DevnetSmokeBudgetLimits::default()
            };
            if max_total_cycles.is_some() {
                budget_limits.max_total_cycles = max_total_cycles;
            }
            if max_tx_cycles.is_some() {
                budget_limits.max_tx_cycles = max_tx_cycles;
            }
            if max_total_bytes.is_some() {
                budget_limits.max_total_bytes = max_total_bytes;
            }
            if max_tx_bytes.is_some() {
                budget_limits.max_tx_bytes = max_tx_bytes;
            }
            let report = if budget_limits.has_any_limit() {
                smoke_report::assert_default_devnet_smoke_with_budget(
                    &dir,
                    contracts_dir.as_path(),
                    Some(&budget_limits),
                )?
            } else {
                smoke_report::assert_default_devnet_smoke(&dir, contracts_dir.as_path())?
            };
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("devnet smoke assertions ok");
                println!("directory={}", report.directory);
                if let Some(git_commit) = &report.git_commit {
                    println!("git_commit={git_commit}");
                }
                if let Some(git_dirty) = &report.git_dirty {
                    println!("git_dirty={git_dirty}");
                }
                println!("transactions={}", report.transaction_count);
                println!("committed={}", report.committed_count);
                println!(
                    "expected_script_failures={}",
                    report.expected_script_failures
                );
                println!("deployed_scripts={}", report.deployed_scripts);
                println!(
                    "deployed_script_hashes_verified={}",
                    report.deployed_script_hashes_verified
                );
                println!("watchtower_alerts={}", report.watchtower_alerts);
                println!(
                    "watchtower_publication_alerts={}",
                    report.watchtower_publication_alerts
                );
                println!(
                    "watchtower_service_records={}",
                    report.watchtower_service_records
                );
                println!("cases={}", report.case_count);
                println!("factory_proofs={}", report.factory_proofs);
                println!("publication_attempts={}", report.publication_attempts);
                println!("sponsor_policies={}", report.sponsor_policies);
                if let Some(budget) = &report.budget {
                    println!("budget_total_cycles={}", budget.total_estimated_cycles);
                    println!("budget_max_tx_cycles={}", budget.max_estimated_cycles);
                    println!("budget_total_bytes={}", budget.total_tx_size_bytes);
                    println!("budget_max_tx_bytes={}", budget.max_tx_size_bytes);
                    for transaction in &budget.transactions {
                        println!(
                            "budget_tx={} {} cycles={} bytes={}",
                            transaction.check,
                            transaction.path,
                            transaction.estimated_cycles,
                            transaction.tx_size_bytes
                        );
                    }
                    for profile in &budget.proof_profiles {
                        println!(
                            "budget_proof={} operation={} siblings={} witness_len={} cycles={} bytes={}",
                            profile.check,
                            profile.operation,
                            profile.proof_siblings,
                            profile.witness_len,
                            profile.estimated_cycles,
                            profile.tx_size_bytes
                        );
                    }
                }
            }
            Ok(())
        }
        Command::DevnetSmokeCompare {
            baseline,
            candidate,
            fail_on_transaction_set_change,
            fail_on_status_change,
            max_abs_total_cycle_delta,
            max_abs_tx_cycle_delta,
            max_abs_total_byte_delta,
            max_abs_tx_byte_delta,
            json,
        } => {
            let comparison = smoke_report::compare_devnet_smoke(&baseline, &candidate)?;
            let limits = smoke_report::DevnetSmokeComparisonLimits {
                fail_on_transaction_set_change,
                fail_on_status_change,
                max_abs_total_cycle_delta,
                max_abs_tx_cycle_delta,
                max_abs_total_byte_delta,
                max_abs_tx_byte_delta,
            };
            if json {
                println!("{}", serde_json::to_string_pretty(&comparison)?);
            } else {
                print!("{}", smoke_report::render_comparison_markdown(&comparison));
            }
            smoke_report::assert_comparison_limits(&comparison, &limits)?;
            Ok(())
        }
        Command::DevnetStatefulReport {
            dir,
            audit_profile,
            json,
        } => {
            let audit_profile = stateful_report::read_audit_profile(&audit_profile)?;
            let summary =
                stateful_report::summarize_devnet_stateful_with_audit(&dir, Some(&audit_profile))?;
            if json {
                println!("{}", serde_json::to_string_pretty(&summary)?);
            } else {
                print!("{}", stateful_report::render_markdown(&summary));
            }
            Ok(())
        }
        Command::DevnetStatefulAssert {
            dir,
            budget_profile,
            audit_profile,
            contracts_dir,
            json,
        } => {
            let budget_limits = budget_profile
                .as_deref()
                .map(stateful_report::read_stateful_budget_profile)
                .transpose()?;
            let audit_profile = stateful_report::read_audit_profile(&audit_profile)?;
            let report = stateful_report::assert_default_devnet_stateful(
                &dir,
                stateful_report::DevnetStatefulAssertionOptions {
                    budget_limits: budget_limits.as_ref(),
                    audit_profile: Some(&audit_profile),
                    contracts_dir: contracts_dir.as_path(),
                },
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("devnet stateful assertions ok");
                println!("directory={}", report.directory);
                if let Some(git_commit) = &report.git_commit {
                    println!("git_commit={git_commit}");
                }
                if let Some(git_dirty) = &report.git_dirty {
                    println!("git_dirty={git_dirty}");
                }
                println!("scenarios={}", report.scenario_count);
                println!("required_scenarios={}", report.required_scenarios);
                println!("audit_families={}", report.audit_families);
                println!("audit_families_passed={}", report.audit_families_passed);
                println!("referenced_artifacts={}", report.referenced_artifacts);
                println!(
                    "required_committed_checks={}",
                    report.required_committed_checks
                );
                println!("expected_failures={}", report.expected_failures);
                if let Some(smoke) = &report.smoke {
                    println!("smoke_transactions={}", smoke.transaction_count);
                    println!("smoke_committed={}", smoke.committed_count);
                    println!(
                        "smoke_expected_script_failures={}",
                        smoke.expected_script_failures
                    );
                    if let Some(budget) = &smoke.budget {
                        println!("budget_total_cycles={}", budget.total_estimated_cycles);
                        println!("budget_max_tx_cycles={}", budget.max_estimated_cycles);
                        println!("budget_total_bytes={}", budget.total_tx_size_bytes);
                        println!("budget_max_tx_bytes={}", budget.max_tx_size_bytes);
                    }
                }
            }
            Ok(())
        }
        Command::DevnetStatefulCompare {
            baseline,
            candidate,
            fail_on_status_change,
            audit_profile,
            json,
        } => {
            let audit_profile = stateful_report::read_audit_profile(&audit_profile)?;
            let comparison = stateful_report::compare_devnet_stateful_with_audit(
                &baseline,
                &candidate,
                Some(&audit_profile),
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&comparison)?);
            } else {
                print!(
                    "{}",
                    stateful_report::render_comparison_markdown(&comparison)
                );
            }
            stateful_report::assert_stateful_comparison_limits(&comparison, fail_on_status_change)?;
            Ok(())
        }
        #[cfg(feature = "devnet")]
        Command::Devnet {
            _devnet_only: _,
            rpc_url,
            command,
        } => devnet_dispatch::run_devnet(&rpc_url, command),
    }
}

#[cfg(feature = "devnet")]
fn resolve_watchtower_private_key(
    _rpc_url: &str,
    private_key: Option<String>,
    private_key_file: Option<PathBuf>,
) -> Result<String> {
    ensure!(
        private_key.is_none() || private_key_file.is_none(),
        "pass either --private-key or --private-key-file, not both"
    );
    if let Some(private_key) = private_key {
        return canonical_private_key(&private_key, "--private-key");
    }
    if let Some(path) = private_key_file {
        let value = fs::read_to_string(&path)
            .with_context(|| format!("failed to read private key file {}", path.display()))?;
        return canonical_private_key(&value, &format!("private key file {}", path.display()));
    }
    anyhow::bail!("--private-key or --private-key-file is required")
}

fn resolve_hub_auth_token(
    auth_token: Option<String>,
    auth_token_file: Option<PathBuf>,
    auth_token_stdin: bool,
    rotate_on_restart: bool,
) -> Result<Option<String>> {
    let source_count = usize::from(auth_token.is_some())
        + usize::from(auth_token_file.is_some())
        + usize::from(auth_token_stdin)
        + usize::from(rotate_on_restart);
    ensure!(
        source_count <= 1,
        "pass only one of --auth-token, --auth-token-file, --auth-token-stdin, or --rotate-auth-token-on-restart"
    );
    if let Some(token) = auth_token {
        return Ok(Some(non_empty_secret(token, "--auth-token")?));
    }
    if let Some(path) = auth_token_file {
        let value = fs::read_to_string(&path)
            .with_context(|| format!("failed to read auth token file {}", path.display()))?;
        return Ok(Some(non_empty_secret(
            value,
            &format!("auth token file {}", path.display()),
        )?));
    }
    if auth_token_stdin {
        let mut value = String::new();
        io::stdin()
            .read_to_string(&mut value)
            .context("failed to read auth token from stdin")?;
        return Ok(Some(non_empty_secret(value, "stdin")?));
    }
    if rotate_on_restart {
        let token = generate_hub_auth_token()?;
        println!("morph_hub_auth_token={token}");
        return Ok(Some(token));
    }
    Ok(None)
}

fn generate_hub_auth_token() -> Result<String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes)
        .map_err(|err| anyhow::anyhow!("failed to generate Morph Hub auth token: {err}"))?;
    Ok(hex::encode(bytes))
}

fn non_empty_secret(value: String, source: &str) -> Result<String> {
    let trimmed = value.trim().to_string();
    ensure!(!trimmed.is_empty(), "{source} must not be empty");
    Ok(trimmed)
}

#[cfg(feature = "devnet")]
fn canonical_private_key(value: &str, source: &str) -> Result<String> {
    let mut parts = value.split_whitespace();
    let Some(first) = parts.next() else {
        anyhow::bail!("{source} is empty");
    };
    ensure!(
        parts.next().is_none(),
        "{source} must contain exactly one hex private key"
    );
    let raw = first.strip_prefix("0x").unwrap_or(first);
    ensure!(raw.len() == 64, "{source} must be 32 bytes");
    let decoded = hex::decode(raw).with_context(|| format!("{source} must be hex encoded"))?;
    ensure!(decoded.len() == 32, "{source} must be 32 bytes");
    SigningKey::from_slice(&decoded)
        .map_err(|err| anyhow::anyhow!("{source} is not a valid secp256k1 private key: {err:?}"))?;
    Ok(format!("0x{}", raw.to_ascii_lowercase()))
}

#[cfg(feature = "devnet")]
fn print_metrics(metrics: &devnet::TransactionMetrics) {
    println!("estimated_cycles={}", metrics.estimated_cycles);
    println!("tx_size_bytes={}", metrics.tx_size_bytes);
}

#[cfg(feature = "devnet")]
fn print_sponsor_policy(policy: &devnet::SponsorPolicyReport) {
    println!("sponsor_min_state_number={}", policy.min_state_number);
    println!("sponsor_max_state_number={}", policy.max_state_number);
    println!("sponsor_max_fee_per_tx={}", policy.max_fee_per_tx);
    println!("sponsor_max_total_fee={}", policy.max_total_fee);
    println!(
        "sponsor_publication_state_type_hash={}",
        policy.publication_state_type_hash
    );
    println!("sponsor_change_lock_hash={}", policy.change_lock_hash);
}

#[cfg(feature = "devnet")]
fn print_tip(tip: &HeaderView) -> Result<()> {
    println!("tip_number={}", tip.number_value()?);
    println!("tip_hash={}", tip.hash);
    println!("tip_parent_hash={}", tip.parent_hash);
    println!("tip_epoch={}", tip.epoch);
    println!("tip_timestamp={}", tip.timestamp_value()?);
    Ok(())
}

#[cfg(feature = "devnet")]
fn tip_json(tip: &HeaderView) -> Result<serde_json::Value> {
    Ok(serde_json::json!({
        "number": tip.number,
        "number_value": tip.number_value()?,
        "hash": tip.hash,
        "parent_hash": tip.parent_hash,
        "epoch": tip.epoch,
        "timestamp": tip.timestamp,
        "timestamp_value": tip.timestamp_value()?,
    }))
}

struct NewInvoiceCommand {
    payee_node_id: String,
    payee_private_key: String,
    amount: u128,
    description: String,
    network: InvoiceNetworkArg,
    asset: InvoiceAssetArg,
    xudt_type_hash: Option<String>,
    channel_id: Option<String>,
    payment_preimage: Option<String>,
    payment_hash: Option<String>,
    created_at_unix: Option<u64>,
    expiry_secs: u64,
    json: bool,
}

fn new_invoice_command(command: NewInvoiceCommand) -> Result<()> {
    ensure!(command.amount > 0, "--amount must be greater than zero");
    ensure!(
        command.expiry_secs > 0,
        "--expiry-secs must be greater than zero"
    );
    ensure!(
        command.payment_preimage.is_some() ^ command.payment_hash.is_some(),
        "set exactly one of --payment-preimage or --payment-hash"
    );

    let payee_node_id = parse_cli_bytes32("payee_node_id", &command.payee_node_id)?;
    let payee_signing_key = parse_cli_signing_key("payee_private_key", &command.payee_private_key)?;
    let channel_id = command
        .channel_id
        .as_deref()
        .map(|value| parse_cli_bytes32("channel_id", value))
        .transpose()?;
    let asset = parse_invoice_asset(command.asset, command.xudt_type_hash.as_deref())?;
    let payment_preimage = command
        .payment_preimage
        .as_deref()
        .map(|value| parse_cli_bytes32("payment_preimage", value))
        .transpose()?;
    let payment_hash = command
        .payment_hash
        .as_deref()
        .map(|value| parse_cli_bytes32("payment_hash", value))
        .transpose()?;
    let created_at_unix = command
        .created_at_unix
        .map(Ok)
        .unwrap_or_else(current_unix_time)?;
    let expires_at_unix = created_at_unix
        .checked_add(command.expiry_secs)
        .context("invoice expiry overflows u64")?;

    let invoice = MorphInvoice::new_signed(
        NewMorphInvoice {
            network: morph_network(command.network),
            payee_node_id,
            channel_id,
            asset,
            amount: command.amount,
            created_at_unix,
            expires_at_unix,
            payment_preimage,
            payment_hash,
            description: command.description,
        },
        &payee_signing_key,
    )?;
    print_invoice_result(&invoice, command.json)
}

fn decode_invoice_command(invoice: &str, json: bool) -> Result<()> {
    let invoice = MorphInvoice::decode(invoice)?;
    print_invoice_result(&invoice, json)
}

fn settle_invoice_command(
    invoice: &str,
    payment_preimage: &str,
    now_unix: Option<u64>,
    json: bool,
) -> Result<()> {
    let invoice = MorphInvoice::decode(invoice)?;
    let preimage = parse_cli_bytes32("payment_preimage", payment_preimage)?;
    let now_unix = now_unix.map(Ok).unwrap_or_else(current_unix_time)?;
    ensure!(
        !invoice.is_expired_at(now_unix),
        "invoice expired at {}",
        invoice.expires_at_unix
    );
    invoice.verify_preimage(&preimage)?;

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "status": "paid",
                "invoice_id": hex_prefixed_cli(&invoice.invoice_id),
                "payment_hash": hex_prefixed_cli(&invoice.payment_hash),
                "paid_at_unix": now_unix,
            }))?
        );
    } else {
        println!("status=paid");
        println!("invoice_id={}", hex_prefixed_cli(&invoice.invoice_id));
        println!("payment_hash={}", hex_prefixed_cli(&invoice.payment_hash));
        println!("paid_at_unix={now_unix}");
    }
    Ok(())
}

fn print_invoice_result(invoice: &MorphInvoice, json: bool) -> Result<()> {
    let encoded_invoice = invoice.encode();
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "encoded_invoice": encoded_invoice,
                "invoice_id": hex_prefixed_cli(&invoice.invoice_id),
                "network": invoice.network,
                "payee_node_id": hex_prefixed_cli(&invoice.payee_node_id),
                "payee_pubkey_sec1": hex::encode(&invoice.payee_pubkey_sec1),
                "channel_id": invoice.channel_id.map(|id| hex_prefixed_cli(&id)),
                "asset": invoice_asset_json(&invoice.asset),
                "amount": invoice.amount,
                "created_at_unix": invoice.created_at_unix,
                "expires_at_unix": invoice.expires_at_unix,
                "payment_hash": hex_prefixed_cli(&invoice.payment_hash),
                "description": invoice.description,
                "signature_scheme_id": invoice.signature_scheme_id,
                "payee_signature": hex_prefixed_cli(&invoice.payee_signature),
            }))?
        );
    } else {
        println!("invoice={encoded_invoice}");
        println!("invoice_id={}", hex_prefixed_cli(&invoice.invoice_id));
        println!(
            "payee_pubkey_sec1={}",
            hex::encode(&invoice.payee_pubkey_sec1)
        );
        println!("payment_hash={}", hex_prefixed_cli(&invoice.payment_hash));
        println!("amount={}", invoice.amount);
        println!("expires_at_unix={}", invoice.expires_at_unix);
    }
    Ok(())
}

fn invoice_asset_json(asset: &MorphAsset) -> serde_json::Value {
    match asset {
        MorphAsset::Ckb => serde_json::json!({ "kind": "ckb" }),
        MorphAsset::Xudt(type_hash) => {
            serde_json::json!({ "kind": "xudt", "type_hash": hex_prefixed_cli(type_hash) })
        }
    }
}

fn parse_invoice_asset(asset: InvoiceAssetArg, xudt_type_hash: Option<&str>) -> Result<MorphAsset> {
    match asset {
        InvoiceAssetArg::Ckb => {
            ensure!(
                xudt_type_hash.is_none(),
                "--xudt-type-hash is only valid with --asset xudt"
            );
            Ok(MorphAsset::Ckb)
        }
        InvoiceAssetArg::Xudt => Ok(MorphAsset::Xudt(parse_cli_bytes32(
            "xudt_type_hash",
            xudt_type_hash.context("--xudt-type-hash is required with --asset xudt")?,
        )?)),
    }
}

fn morph_network(network: InvoiceNetworkArg) -> MorphNetwork {
    match network {
        InvoiceNetworkArg::Devnet => MorphNetwork::Devnet,
        InvoiceNetworkArg::Testnet => MorphNetwork::Testnet,
        InvoiceNetworkArg::Mainnet => MorphNetwork::Mainnet,
    }
}

fn parse_cli_bytes32(label: &str, value: &str) -> Result<[u8; 32]> {
    let value = value.trim();
    ensure!(
        !value.is_empty(),
        "{label} must not be empty; pass a 32-byte 0x-prefixed hex value"
    );
    let hex = value
        .strip_prefix("0x")
        .ok_or_else(|| anyhow::anyhow!("{label} must be 0x-prefixed"))?;
    ensure!(hex.len() == 64, "{label} must be 32 bytes");
    let raw = hex::decode(hex).with_context(|| format!("{label} is not valid hex"))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}

fn parse_cli_signing_key(label: &str, value: &str) -> Result<SigningKey> {
    let value = value.trim();
    ensure!(
        !value.is_empty(),
        "{label} must not be empty; pass a 32-byte secp256k1 private key"
    );
    let raw_hex = value.strip_prefix("0x").unwrap_or(value);
    ensure!(raw_hex.len() == 64, "{label} must be 32 bytes");
    let raw = hex::decode(raw_hex).with_context(|| format!("{label} is not valid hex"))?;
    SigningKey::from_slice(&raw)
        .map_err(|err| anyhow::anyhow!("{label} is not a valid secp256k1 private key: {err:?}"))
}

fn hex_prefixed_cli(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

fn current_unix_time() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system time is before Unix epoch")?
        .as_secs())
}

fn validate_fixture() -> Result<()> {
    let package = multi_asset_packages::fixture_package()?;
    let recovery = package.recovery()?;
    recovery.validate()?;
    let mut backend = MultiAssetChannelBackend::new(
        recovery.clone(),
        recovery.authorization.signatures[0].pubkey_sec1.clone(),
    )?;
    let mut settlement = recovery.settlement.clone();
    settlement.payouts[0].values[0].amount = settlement.payouts[0].values[0]
        .amount
        .checked_sub(1)
        .context("fixture has no spendable token")?;
    settlement.payouts[0].values[1].amount = settlement.payouts[0].values[1]
        .amount
        .checked_add(1)
        .context("fixture amount overflow")?;
    let proposal = backend.propose(settlement)?;
    let reservation = backend.reserve_signature()?;
    ensure!(
        proposal.signing_digest()? == reservation.signing_digest,
        "fixture signing reservation differs from current proposal"
    );
    println!("fixture ok");
    println!("state_digest={}", hex::encode(reservation.signing_digest));
    Ok(())
}

fn print_fixture() -> Result<()> {
    println!(
        "{}",
        serde_json::to_string_pretty(&multi_asset_packages::fixture_package()?)?
    );
    Ok(())
}

#[cfg(test)]
mod cli_secret_tests {
    use super::*;
    use clap::CommandFactory;

    #[cfg(not(feature = "devnet"))]
    #[test]
    fn default_cli_hides_live_devnet_command() {
        let command = Cli::command();
        assert!(
            command
                .get_subcommands()
                .all(|command| command.get_name() != "devnet"),
            "default morph-cli build must not expose live devnet operators"
        );
    }

    #[cfg(feature = "devnet")]
    #[test]
    fn devnet_feature_requires_devnet_only_confirmation() {
        std::thread::Builder::new()
            .name("clap-metadata-devnet-confirmation".to_string())
            .stack_size(16 * 1024 * 1024)
            .spawn(|| {
                let command = Cli::command();
                let devnet = command
                    .get_subcommands()
                    .find(|command| command.get_name() == "devnet")
                    .expect("missing devnet command");
                let confirmation = devnet
                    .get_arguments()
                    .find(|arg| arg.get_long() == Some("devnet-only"))
                    .expect("missing --devnet-only confirmation flag");
                assert!(
                    confirmation.is_required_set(),
                    "--devnet-only must be required for live devnet operators"
                );
            })
            .expect("failed to spawn clap metadata test")
            .join()
            .expect("clap metadata test panicked");
    }

    #[cfg(feature = "devnet")]
    #[test]
    fn resolves_private_key_from_file() {
        let private_key = private_key_from_scalar(1);
        let path = std::env::temp_dir().join(format!(
            "morph-private-key-{}-{}.txt",
            std::process::id(),
            "file"
        ));
        fs::write(&path, format!("{private_key}\n")).unwrap();
        let resolved =
            resolve_watchtower_private_key("http://127.0.0.1:18114", None, Some(path.clone()))
                .unwrap();
        fs::remove_file(path).unwrap();
        assert_eq!(resolved, private_key);
    }

    #[cfg(feature = "devnet")]
    #[test]
    fn rejects_ambiguous_private_key_sources() {
        let private_key = private_key_from_scalar(2);
        let err = resolve_watchtower_private_key(
            "http://127.0.0.1:18114",
            Some(private_key),
            Some(PathBuf::from("key.txt")),
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("either --private-key or --private-key-file")
        );
    }

    #[cfg(feature = "devnet")]
    #[test]
    fn rejects_multi_token_private_key_file() {
        let private_key = private_key_from_scalar(3);
        let path = std::env::temp_dir().join(format!(
            "morph-private-key-{}-{}.txt",
            std::process::id(),
            "multi"
        ));
        fs::write(&path, format!("{private_key} extra\n")).unwrap();
        let err =
            resolve_watchtower_private_key("http://127.0.0.1:18114", None, Some(path.clone()))
                .unwrap_err();
        fs::remove_file(path).unwrap();
        assert!(err.to_string().contains("exactly one hex private key"));
    }

    #[cfg(feature = "devnet")]
    #[test]
    fn rejects_missing_watchtower_private_key() {
        let err = resolve_watchtower_private_key("http://127.0.0.1:18114", None, None).unwrap_err();
        assert!(err.to_string().contains("--private-key"), "got: {err}");
    }

    #[cfg(feature = "devnet")]
    #[test]
    fn watchtower_private_key_file_is_not_shadowed_by_devnet_key_env() {
        std::thread::Builder::new()
            .name("clap-metadata-watchtower-private-key".to_string())
            .stack_size(16 * 1024 * 1024)
            .spawn(|| {
                for subcommand in [
                    "watch-config-once",
                    "watch-config-loop",
                    "watch-config-service",
                ] {
                    let private_key = devnet_arg(subcommand, "private_key");
                    assert_eq!(private_key.get_env(), None, "{subcommand} private-key");

                    let private_key_file = devnet_arg(subcommand, "private_key_file");
                    assert_eq!(
                        private_key_file.get_env(),
                        Some(std::ffi::OsStr::new("MORPH_DEVNET_PRIVATE_KEY_FILE")),
                        "{subcommand} private-key-file"
                    );
                }
            })
            .expect("failed to spawn clap metadata test")
            .join()
            .expect("clap metadata test panicked");
    }

    #[test]
    fn resolves_hub_auth_token_from_file() {
        let path = std::env::temp_dir().join(format!(
            "morph-hub-auth-token-{}-{}.txt",
            std::process::id(),
            "file"
        ));
        fs::write(&path, "  secret-token\n").unwrap();
        let resolved = resolve_hub_auth_token(None, Some(path.clone()), false, false).unwrap();
        fs::remove_file(path).unwrap();
        assert_eq!(resolved.as_deref(), Some("secret-token"));
    }

    #[test]
    fn rejects_ambiguous_hub_auth_token_sources() {
        let err = resolve_hub_auth_token(
            Some("secret-token".to_string()),
            Some(PathBuf::from("token.txt")),
            false,
            false,
        )
        .unwrap_err();
        assert!(err.to_string().contains("pass only one of"));
    }

    #[test]
    fn rejects_empty_hub_auth_token_file() {
        let path = std::env::temp_dir().join(format!(
            "morph-hub-auth-token-{}-{}.txt",
            std::process::id(),
            "empty"
        ));
        fs::write(&path, "\n").unwrap();
        let err = resolve_hub_auth_token(None, Some(path.clone()), false, false).unwrap_err();
        fs::remove_file(path).unwrap();
        assert!(err.to_string().contains("must not be empty"));
    }

    #[test]
    fn rotates_hub_auth_token_on_restart() {
        let token = generate_hub_auth_token().unwrap();
        assert_eq!(token.len(), 64);
        assert!(hex::decode(token).is_ok());
    }

    #[cfg(feature = "devnet")]
    fn devnet_arg(subcommand: &str, arg_id: &str) -> clap::Arg {
        let command = Cli::command();
        let devnet = command
            .get_subcommands()
            .find(|command| command.get_name() == "devnet")
            .unwrap_or_else(|| panic!("missing devnet command"));
        let subcommand = devnet
            .get_subcommands()
            .find(|command| command.get_name() == subcommand)
            .unwrap_or_else(|| panic!("missing devnet subcommand {subcommand}"));
        subcommand
            .get_arguments()
            .find(|arg| arg.get_id() == arg_id)
            .cloned()
            .unwrap_or_else(|| panic!("missing argument {arg_id}"))
    }

    #[cfg(feature = "devnet")]
    fn private_key_from_scalar(value: u8) -> String {
        let mut bytes = [0u8; 32];
        bytes[31] = value;
        format!("0x{}", hex::encode(bytes))
    }
}
