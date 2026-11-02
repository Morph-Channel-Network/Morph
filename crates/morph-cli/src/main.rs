#![forbid(unsafe_code)]

use std::collections::BTreeSet;
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
use devnet::{
    ApplyFactoryReducedSpliceOptions, ApplyFactorySpliceOptions, ApplySpliceOptions,
    CompetingSpendSmokeOptions, DeployContractsOptions, DevnetSpliceAsset, DevnetSpliceKind,
    FactoryExitAuthorisation, FactoryExitChannelOptions, FactoryExitChannelTamper,
    FactoryMerkleUpdateSmokeOptions, FactoryReducedExitSmokeOptions,
    FactoryReducedRightsSmokeOptions, FactoryReducedXudtExitSmokeOptions,
    FactoryReducedXudtNegativeExitSmokeOptions, FactorySmokeOptions, FactorySpliceSmokeOptions,
    FactoryXudtNegativeSmokeOptions, FactoryXudtSmokeOptions, FactoryXudtSpliceSmokeOptions,
    FinaliseChannelOptions, FinaliseSinceNegativeSmokeOptions, FundSponsorOptions,
    OpenChannelOptions, OpenFactoryOptions, PublishLatestStatePackageOptions, PublishStateOptions,
    SaveFactoryMerkleUpdatePackageOptions, SaveFactoryReducedRightsPackageOptions,
    SaveFactoryReducedSplicePackageOptions, SaveFactorySplicePackageOptions,
    SaveFactoryStatePackageOptions, SaveSplicePackageOptions, SaveStatePackageOptions,
    SpliceNegativeSmokeOptions, SpliceSmokeOptions, SponsorBudgetNegativeSmokeOptions,
    SponsorPolicyNegativeSmokeOptions, SupersedeSmokeOptions, UpdateFactoryOptions,
    WatchLatestStatePackageOptions, XudtNegativeSmokeOptions, XudtSmokeOptions,
    XudtSpliceSmokeOptions,
};
use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::ecdsa::{Signature, SigningKey};
use morph_core::*;
#[cfg(feature = "devnet")]
use rpc::{CkbRpcClient, HeaderView};

mod conditional_packages;
#[cfg_attr(not(feature = "devnet"), allow(dead_code))]
mod devnet;
#[cfg(feature = "devnet")]
mod devnet_dispatch;
mod factory_packages;
mod hub;
mod multi_asset_funding;
mod multi_asset_funding_session;
mod multi_asset_packages;
#[cfg(any(feature = "devnet", test))]
mod multi_asset_root_transaction;
mod multi_asset_session;
mod multi_asset_session_chain;
mod multi_asset_splice_transaction;
#[cfg(feature = "devnet")]
mod multi_asset_supervision;
mod packages;
mod preproduction;
#[cfg_attr(not(feature = "devnet"), allow(dead_code))]
mod publication;
mod release;
#[cfg_attr(not(feature = "devnet"), allow(dead_code))]
mod rpc;
mod smoke_report;
mod splice_packages;
mod stateful_report;
mod value_limit;
#[cfg_attr(not(feature = "devnet"), allow(dead_code))]
mod watch_alert;
#[cfg_attr(not(feature = "devnet"), allow(dead_code))]
mod watch_config;
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
enum SpliceFixtureKindArg {
    SpliceIn,
    SpliceOut,
    XudtSpliceIn,
    XudtSpliceOut,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum FactorySpliceFixtureKindArg {
    SpliceIn,
    SpliceOut,
    XudtSpliceIn,
    XudtSpliceOut,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CkbSpliceKindArg {
    SpliceIn,
    SpliceOut,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum SpliceAssetArg {
    Ckb,
    Xudt,
}

#[cfg(feature = "devnet")]
#[derive(Debug, Clone, Copy, ValueEnum)]
enum FactoryExitAuthorisationArg {
    FullParticipants,
    ReducedReserveClaim,
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
    /// Validate the built-in bilateral-channel fixture.
    ValidateFixture,
    /// Print a JSON state header fixture and signing digest.
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
    /// Print a valid host-side factory non-interference package fixture.
    PrintFactoryFixture,
    /// Print a bounded CKB conditional-batch force-resolution package fixture.
    PrintConditionalBatchFixture,
    /// Print a complete signed two-xUDT recovery package fixture.
    PrintMultiAssetFixture,
    /// Print a conservative all-participant signed factory state package fixture.
    PrintFactoryStateFixture,
    /// Print a host-side authorised-participant signed factory state package fixture.
    PrintReducedFactoryStateFixture,
    /// Print an on-chain reduced-rights factory update package fixture.
    PrintFactoryReducedRightsFixture,
    /// Print a host-side reduced factory-exit package fixture.
    PrintFactoryReducedExitFixture,
    /// Print a host-side single-right sparse Merkle factory update package fixture.
    PrintFactoryMerkleUpdateFixture,
    /// Print a host-side multi-right compact sparse Merkle factory update package fixture.
    PrintFactoryMultiRightUpdateFixture,
    /// Print an operator value-limit policy fixture.
    PrintValueLimitPolicyFixture,
    /// Print a valid factory local-exit evidence package fixture.
    PrintFactoryLocalExitFixture,
    /// Print a valid conservative factory splice package fixture.
    PrintFactorySpliceFixture {
        /// Fixture shape to print.
        #[arg(long, value_enum, default_value = "splice-in")]
        kind: FactorySpliceFixtureKindArg,
    },
    /// Print a sparse-Merkle reduced factory splice package fixture.
    PrintFactoryReducedSpliceFixture {
        /// Fixture shape to print.
        #[arg(long, value_enum, default_value = "splice-in")]
        kind: FactorySpliceFixtureKindArg,
    },
    /// Print a valid bilateral splice package fixture.
    PrintSpliceFixture {
        /// Fixture shape to print.
        #[arg(long, value_enum, default_value = "splice-in")]
        kind: SpliceFixtureKindArg,
    },
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
    /// Validate a host-side factory non-interference package.
    ValidateFactoryPackage {
        /// Path to the factory update package JSON.
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
    /// Validate a conservative all-participant signed factory state package.
    ValidateFactoryStatePackage {
        /// Path to the factory state package JSON.
        path: std::path::PathBuf,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Validate an on-chain reduced-rights factory update package.
    ValidateFactoryReducedRightsPackage {
        /// Path to the factory reduced-rights package JSON.
        path: std::path::PathBuf,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Validate a host-side reduced factory-exit package.
    ValidateFactoryReducedExitPackage {
        /// Path to the factory reduced-exit package JSON.
        path: std::path::PathBuf,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Validate a host-side single-right sparse Merkle factory update package.
    ValidateFactoryMerkleUpdatePackage {
        /// Path to the factory Merkle update package JSON.
        path: std::path::PathBuf,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Validate a host-side multi-right compact sparse Merkle factory update package.
    ValidateFactoryMultiRightUpdatePackage {
        /// Path to the factory multi-right update package JSON.
        path: std::path::PathBuf,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
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
        /// Path to a value-bearing package JSON (bilateral or factory splice family).
        #[arg(long)]
        package: Option<std::path::PathBuf>,
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
    /// Validate a factory local-exit evidence package.
    ValidateFactoryLocalExitPackage {
        /// Path to the factory local-exit package JSON.
        path: std::path::PathBuf,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Validate a conservative factory splice package.
    ValidateFactorySplicePackage {
        /// Path to the factory splice package JSON.
        path: std::path::PathBuf,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Validate a sparse-Merkle reduced factory splice package.
    ValidateFactoryReducedSplicePackage {
        /// Path to the reduced factory splice package JSON.
        path: std::path::PathBuf,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Validate a bilateral splice package.
    ValidateSplicePackage {
        /// Path to the splice package JSON.
        path: std::path::PathBuf,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Summarise a completed scripts/devnet-smoke.sh output directory.
    DevnetSmokeReport {
        /// Directory produced by scripts/devnet-smoke.sh.
        #[arg(long, default_value = "target/devnet-smoke/latest")]
        dir: std::path::PathBuf,
        /// Emit machine-readable JSON instead of Markdown.
        #[arg(long)]
        json: bool,
    },
    /// Assert that a completed devnet smoke directory covers required paths.
    DevnetSmokeAssert {
        /// Directory produced by scripts/devnet-smoke.sh.
        #[arg(long, default_value = "target/devnet-smoke/latest")]
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
        #[arg(long, default_value = "target/devnet-stateful-e2e/latest/scenarios")]
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
        #[arg(long, default_value = "target/devnet-stateful-e2e/latest/scenarios")]
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
    /// Open a bilateral Morph channel on local devnet using deployed Morph scripts.
    OpenChannel {
        /// Directory containing the built RISC-V contract binaries.
        #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
        contracts_dir: std::path::PathBuf,
        /// Secp256k1 private key that controls a funded local-devnet cell.
        #[arg(long, env = "MORPH_DEVNET_PRIVATE_KEY", hide_env_values = true)]
        private_key: String,
        /// Devnet Alice channel key.
        #[arg(long, env = "MORPH_ALICE_PRIVATE_KEY", hide_env_values = true)]
        alice_private_key: String,
        /// Devnet Bob channel key.
        #[arg(long, env = "MORPH_BOB_PRIVATE_KEY", hide_env_values = true)]
        bob_private_key: String,
        /// Capacity placed under the channel vault lock, in shannons.
        #[arg(long, default_value_t = 20_000_000_000)]
        vault_capacity: u64,
        /// Alice's descriptor capacity, in shannons. Must be paired with --bob-capacity.
        #[arg(long)]
        alice_capacity: Option<u64>,
        /// Bob's descriptor capacity, in shannons. Must be paired with --alice-capacity.
        #[arg(long)]
        bob_capacity: Option<u64>,
        /// Capacity placed under the sponsor lock, in shannons.
        #[arg(long, default_value_t = 50_000_000_000)]
        sponsor_capacity: u64,
        /// Lowest state number the initial SponsorCell may pay for.
        #[arg(long, default_value_t = devnet::DEFAULT_SPONSOR_MIN_STATE_NUMBER)]
        sponsor_min_state_number: u64,
        /// Highest state number the initial SponsorCell may pay for.
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
        /// Absolute fee to reserve for the open-channel transaction, in shannons.
        #[arg(long, default_value_t = 100_000_000)]
        fee: u64,
        /// Relative block count required before finalisation.
        #[arg(long, default_value_t = 4)]
        finalise_since: u64,
        /// Mine this many blocks after broadcasting. Use 0 to only submit to tx-pool.
        #[arg(long, default_value_t = 4)]
        mine_blocks: u64,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Open a conservative 2-16 participant Morph factory state cell on local devnet.
    OpenFactory {
        /// Directory containing the built RISC-V contract binaries.
        #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
        contracts_dir: std::path::PathBuf,
        /// Secp256k1 private key that controls a funded local-devnet cell.
        #[arg(long, env = "MORPH_DEVNET_PRIVATE_KEY", hide_env_values = true)]
        private_key: String,
        /// Devnet Alice factory signing key.
        #[arg(long, env = "MORPH_ALICE_PRIVATE_KEY", hide_env_values = true)]
        alice_private_key: String,
        /// Devnet Bob factory signing key.
        #[arg(long, env = "MORPH_BOB_PRIVATE_KEY", hide_env_values = true)]
        bob_private_key: String,
        /// Additional factory signing key for participant 3 onward. Repeat up to 14 times.
        #[arg(long = "participant-private-key", hide_env_values = true)]
        additional_participant_private_keys: Vec<String>,
        /// Capacity placed under the FactoryStateCell, in shannons.
        #[arg(long, default_value_t = 50_000_000_000)]
        factory_capacity: u64,
        /// Reserve capacity placed under the FactoryVaultCell, in shannons.
        #[arg(long, default_value_t = 300_000_000_000)]
        factory_vault_capacity: u64,
        /// Optional devnet xUDT amount placed under the FactoryVaultCell.
        #[arg(long)]
        factory_vault_xudt_amount: Option<u128>,
        /// Optional 32-byte state root for the initial factory state.
        #[arg(long)]
        state_root: Option<String>,
        /// Optional 32-byte access-manifest root for the initial factory state.
        #[arg(long)]
        access_manifest_root: Option<String>,
        /// Optional 32-byte non-interference digest for the initial factory state.
        #[arg(long)]
        non_interference_digest: Option<String>,
        /// Absolute fee to reserve for the open-factory transaction, in shannons.
        #[arg(long, default_value_t = 100_000_000)]
        fee: u64,
        /// Mine this many blocks after broadcasting. Use 0 to only submit to tx-pool.
        #[arg(long, default_value_t = 4)]
        mine_blocks: u64,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Advance a Morph factory state cell using all-participant signatures.
    UpdateFactory {
        /// Directory containing the built RISC-V contract binaries.
        #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
        contracts_dir: std::path::PathBuf,
        /// Secp256k1 private key that pays the independent fee input.
        #[arg(long, env = "MORPH_DEVNET_PRIVATE_KEY", hide_env_values = true)]
        private_key: String,
        /// Devnet Alice factory signing key.
        #[arg(long, env = "MORPH_ALICE_PRIVATE_KEY", hide_env_values = true)]
        alice_private_key: String,
        /// Devnet Bob factory signing key.
        #[arg(long, env = "MORPH_BOB_PRIVATE_KEY", hide_env_values = true)]
        bob_private_key: String,
        /// Additional factory signing key for participant 3 onward. Repeat up to 14 times.
        #[arg(long = "participant-private-key", hide_env_values = true)]
        additional_participant_private_keys: Vec<String>,
        /// Current FactoryStateCell out point, formatted as <tx-hash>:<index>.
        #[arg(long)]
        factory_out_point: String,
        /// New update number. Defaults to old_update_number + 1.
        #[arg(long)]
        update_number: Option<u64>,
        /// Optional 32-byte replacement state root.
        #[arg(long)]
        state_root: Option<String>,
        /// Optional 32-byte replacement access-manifest root.
        #[arg(long)]
        access_manifest_root: Option<String>,
        /// Optional 32-byte replacement non-interference digest.
        #[arg(long)]
        non_interference_digest: Option<String>,
        /// Signed factory state package JSON. When set, Alice/Bob keys and root overrides are not used.
        #[arg(
            long,
            conflicts_with_all = [
                "update_number",
                "state_root",
                "access_manifest_root",
                "non_interference_digest"
            ]
        )]
        factory_state_package: Option<std::path::PathBuf>,
        /// Absolute fee paid by a normal owner cell, in shannons.
        #[arg(long, default_value_t = 100_000_000)]
        fee: u64,
        /// Mine this many blocks after broadcasting. Use 0 to only submit to tx-pool.
        #[arg(long, default_value_t = 4)]
        mine_blocks: u64,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Save a signed factory state package without broadcasting it.
    SaveFactoryStatePackage {
        /// Devnet Alice factory signing key.
        #[arg(long, env = "MORPH_ALICE_PRIVATE_KEY", hide_env_values = true)]
        alice_private_key: String,
        /// Devnet Bob factory signing key.
        #[arg(long, env = "MORPH_BOB_PRIVATE_KEY", hide_env_values = true)]
        bob_private_key: String,
        /// Additional factory signing key for participant 3 onward. Repeat up to 14 times.
        #[arg(long = "participant-private-key", hide_env_values = true)]
        additional_participant_private_keys: Vec<String>,
        /// Current FactoryStateCell out point, formatted as <tx-hash>:<index>.
        #[arg(long)]
        factory_out_point: String,
        /// New update number. Defaults to old_update_number + 1.
        #[arg(long)]
        update_number: Option<u64>,
        /// Optional 32-byte replacement state root.
        #[arg(long)]
        state_root: Option<String>,
        /// Optional 32-byte replacement access-manifest root.
        #[arg(long)]
        access_manifest_root: Option<String>,
        /// Optional 32-byte replacement non-interference digest.
        #[arg(long)]
        non_interference_digest: Option<String>,
        /// Directory where signed factory state packages are stored.
        #[arg(long, default_value = "target/morph-factory-state-packages")]
        store_dir: std::path::PathBuf,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Save a reduced-rights factory update package without broadcasting it.
    SaveFactoryReducedRightsPackage {
        /// Devnet Alice factory signing key. Alice is the touched participant in the bounded reduced-rights proof body.
        #[arg(long, env = "MORPH_ALICE_PRIVATE_KEY", hide_env_values = true)]
        alice_private_key: String,
        /// Devnet Bob factory key used to prove full factory membership. Bob does not sign the reduced update.
        #[arg(long, env = "MORPH_BOB_PRIVATE_KEY", hide_env_values = true)]
        bob_private_key: String,
        /// Additional membership key for participant 3 onward. Only Alice signs this update.
        #[arg(long = "participant-private-key", hide_env_values = true)]
        additional_participant_private_keys: Vec<String>,
        /// Current FactoryStateCell out point, formatted as <tx-hash>:<index>.
        #[arg(long)]
        factory_out_point: String,
        /// New update number. Defaults to old_update_number + 1.
        #[arg(long)]
        update_number: Option<u64>,
        /// New Alice balance quantity in the bounded rights fixture. Must be lower than 100.
        #[arg(long, default_value_t = 90)]
        touched_after_balance: u128,
        /// Directory where reduced-rights factory packages are stored.
        #[arg(long, default_value = "target/morph-factory-state-packages")]
        store_dir: std::path::PathBuf,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Save a conservative factory splice package from the live FactoryStateCell/FactoryVaultCell pair.
    SaveFactorySplicePackage {
        /// Devnet Alice factory signing key. Alice owns the touched reserve claim in the factory splice body.
        #[arg(long, env = "MORPH_ALICE_PRIVATE_KEY", hide_env_values = true)]
        alice_private_key: String,
        /// Devnet Bob factory signing key.
        #[arg(long, env = "MORPH_BOB_PRIVATE_KEY", hide_env_values = true)]
        bob_private_key: String,
        /// Additional factory signing key for participant 3 onward. Repeat up to 14 times.
        #[arg(long = "participant-private-key", hide_env_values = true)]
        additional_participant_private_keys: Vec<String>,
        /// Current FactoryStateCell out point, formatted as <tx-hash>:<index>.
        #[arg(long)]
        factory_out_point: String,
        /// Current FactoryVaultCell out point, formatted as <tx-hash>:<index>.
        #[arg(long)]
        factory_vault_out_point: String,
        /// Factory splice direction.
        #[arg(long, value_enum, default_value = "splice-in")]
        kind: CkbSpliceKindArg,
        /// Asset delta to encode in the factory splice package.
        #[arg(long, value_enum, default_value = "ckb")]
        asset: SpliceAssetArg,
        /// Net CKB amount added to or withdrawn from the factory vault, in shannons.
        #[arg(long, default_value_t = 1_000_000_000)]
        ckb_amount: u64,
        /// Net xUDT amount added to or withdrawn from the factory vault. Required with --asset xudt.
        #[arg(long)]
        xudt_amount: Option<u128>,
        /// New factory update number. Defaults to old_update_number + 1.
        #[arg(long)]
        update_number: Option<u64>,
        /// Directory where factory splice packages are stored.
        #[arg(long, default_value = "target/morph-factory-splice-packages")]
        store_dir: std::path::PathBuf,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Save a reduced sparse-Merkle factory splice package from the live FactoryStateCell/FactoryVaultCell pair.
    SaveFactoryReducedSplicePackage {
        /// Devnet Alice factory signing key. Alice owns the touched reserve claim in the reduced-splice body.
        #[arg(long, env = "MORPH_ALICE_PRIVATE_KEY", hide_env_values = true)]
        alice_private_key: String,
        /// Devnet Bob factory key used to prove full factory membership. Bob does not sign the reduced splice.
        #[arg(long, env = "MORPH_BOB_PRIVATE_KEY", hide_env_values = true)]
        bob_private_key: String,
        /// Additional membership key for participant 3 onward. Only Alice signs this splice.
        #[arg(long = "participant-private-key", hide_env_values = true)]
        additional_participant_private_keys: Vec<String>,
        /// Current FactoryStateCell out point, formatted as <tx-hash>:<index>.
        #[arg(long)]
        factory_out_point: String,
        /// Current FactoryVaultCell out point, formatted as <tx-hash>:<index>.
        #[arg(long)]
        factory_vault_out_point: String,
        /// Factory splice direction.
        #[arg(long, value_enum, default_value = "splice-in")]
        kind: CkbSpliceKindArg,
        /// Asset delta to encode in the reduced factory splice package.
        #[arg(long, value_enum, default_value = "ckb")]
        asset: SpliceAssetArg,
        /// Net CKB amount added to or withdrawn from the factory vault, in shannons.
        #[arg(long, default_value_t = 1_000_000_000)]
        ckb_amount: u64,
        /// Net xUDT amount added to or withdrawn from the factory vault. Required with --asset xudt.
        #[arg(long)]
        xudt_amount: Option<u128>,
        /// New factory update number. Defaults to old_update_number + 1.
        #[arg(long)]
        update_number: Option<u64>,
        /// Directory where reduced factory splice packages are stored.
        #[arg(long, default_value = "target/morph-factory-splice-packages")]
        store_dir: std::path::PathBuf,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Apply a validated conservative factory splice package.
    ApplyFactorySplice {
        /// Directory containing the built RISC-V contract binaries.
        #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
        contracts_dir: std::path::PathBuf,
        /// Secp256k1 private key that pays independent transaction fees.
        #[arg(long, env = "MORPH_DEVNET_PRIVATE_KEY", hide_env_values = true)]
        private_key: String,
        /// Current FactoryStateCell out point, formatted as <tx-hash>:<index>.
        #[arg(long)]
        factory_out_point: String,
        /// Current FactoryVaultCell out point, formatted as <tx-hash>:<index>.
        #[arg(long)]
        factory_vault_out_point: String,
        /// Signed factory splice package JSON.
        #[arg(long)]
        factory_splice_package: std::path::PathBuf,
        /// External owner-controlled xUDT input, formatted as <tx-hash>:<index>. Required for xUDT splice-in.
        #[arg(long)]
        xudt_input_out_point: Option<String>,
        /// Absolute transaction fee, in shannons.
        #[arg(long, default_value_t = 100_000_000)]
        fee: u64,
        /// Mine this many blocks after broadcasting. Use 0 to only submit to tx-pool.
        #[arg(long, default_value_t = 4)]
        mine_blocks: u64,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Apply a validated reduced sparse-Merkle factory splice package.
    ApplyFactoryReducedSplice {
        /// Directory containing the built RISC-V contract binaries.
        #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
        contracts_dir: std::path::PathBuf,
        /// Secp256k1 private key that pays independent transaction fees.
        #[arg(long, env = "MORPH_DEVNET_PRIVATE_KEY", hide_env_values = true)]
        private_key: String,
        /// Current FactoryStateCell out point, formatted as <tx-hash>:<index>.
        #[arg(long)]
        factory_out_point: String,
        /// Current FactoryVaultCell out point, formatted as <tx-hash>:<index>.
        #[arg(long)]
        factory_vault_out_point: String,
        /// Signed reduced factory splice package JSON.
        #[arg(long)]
        factory_reduced_splice_package: std::path::PathBuf,
        /// External owner-controlled xUDT input, formatted as <tx-hash>:<index>. Required for xUDT splice-in.
        #[arg(long)]
        xudt_input_out_point: Option<String>,
        /// Absolute transaction fee, in shannons.
        #[arg(long, default_value_t = 100_000_000)]
        fee: u64,
        /// Mine this many blocks after broadcasting. Use 0 to only submit to tx-pool.
        #[arg(long, default_value_t = 4)]
        mine_blocks: u64,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Save a sparse Merkle factory update package without broadcasting it.
    SaveFactoryMerkleUpdatePackage {
        /// Devnet Alice factory signing key. Alice is the touched participant in the single-right proof.
        #[arg(long, env = "MORPH_ALICE_PRIVATE_KEY", hide_env_values = true)]
        alice_private_key: String,
        /// Devnet Bob factory key used to prove full membership. Bob does not sign the Merkle update.
        #[arg(long, env = "MORPH_BOB_PRIVATE_KEY", hide_env_values = true)]
        bob_private_key: String,
        /// Additional membership key for participant 3 onward. Only Alice signs this update.
        #[arg(long = "participant-private-key", hide_env_values = true)]
        additional_participant_private_keys: Vec<String>,
        /// Current FactoryStateCell out point, formatted as <tx-hash>:<index>.
        #[arg(long)]
        factory_out_point: String,
        /// New factory update number. Defaults to old_update_number + 1.
        #[arg(long)]
        update_number: Option<u64>,
        /// New Alice balance quantity in the sparse Merkle fixture. Must be lower than 1000.
        #[arg(long, default_value_t = 900)]
        touched_after_balance: u128,
        /// Directory where sparse Merkle factory packages are stored.
        #[arg(long, default_value = "target/morph-factory-state-packages")]
        store_dir: std::path::PathBuf,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// List saved signed factory state packages.
    ListFactoryStatePackages {
        /// Directory where signed factory state packages are stored.
        #[arg(long, default_value = "target/morph-factory-state-packages")]
        store_dir: std::path::PathBuf,
        /// Optional factory id filter.
        #[arg(long)]
        factory_id: Option<String>,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Select the highest-numbered saved factory state package.
    LatestFactoryStatePackage {
        /// Directory where signed factory state packages are stored.
        #[arg(long, default_value = "target/morph-factory-state-packages")]
        store_dir: std::path::PathBuf,
        /// Factory id to select.
        #[arg(long)]
        factory_id: String,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Run open -> save package -> package update for a conservative factory.
    FactorySmoke {
        /// Directory containing the built RISC-V contract binaries.
        #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
        contracts_dir: std::path::PathBuf,
        /// Secp256k1 private key that controls funded local-devnet cells.
        #[arg(long, env = "MORPH_DEVNET_PRIVATE_KEY", hide_env_values = true)]
        private_key: String,
        /// Devnet Alice factory signing key.
        #[arg(long, env = "MORPH_ALICE_PRIVATE_KEY", hide_env_values = true)]
        alice_private_key: String,
        /// Devnet Bob factory signing key.
        #[arg(long, env = "MORPH_BOB_PRIVATE_KEY", hide_env_values = true)]
        bob_private_key: String,
        /// Capacity placed under the FactoryStateCell, in shannons.
        #[arg(long, default_value_t = 50_000_000_000)]
        factory_capacity: u64,
        /// Reserve capacity placed under the FactoryVaultCell, in shannons.
        #[arg(long, default_value_t = 300_000_000_000)]
        factory_vault_capacity: u64,
        /// Absolute fee paid by each transaction, in shannons.
        #[arg(long, default_value_t = 100_000_000)]
        fee: u64,
        /// Mine this many blocks after each broadcast. Use 0 to only submit to tx-pool.
        #[arg(long, default_value_t = 4)]
        mine_blocks: u64,
        /// Directory where signed factory state packages are stored.
        #[arg(long, default_value = "target/morph-factory-state-packages")]
        store_dir: std::path::PathBuf,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Run open -> save reduced-rights package -> package update for a bounded reduced factory proof.
    FactoryReducedRightsSmoke {
        /// Directory containing the built RISC-V contract binaries.
        #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
        contracts_dir: std::path::PathBuf,
        /// Secp256k1 private key that controls funded local-devnet cells.
        #[arg(long, env = "MORPH_DEVNET_PRIVATE_KEY", hide_env_values = true)]
        private_key: String,
        /// Devnet Alice factory signing key. Alice signs the reduced update.
        #[arg(long, env = "MORPH_ALICE_PRIVATE_KEY", hide_env_values = true)]
        alice_private_key: String,
        /// Devnet Bob factory key used to prove full membership.
        #[arg(long, env = "MORPH_BOB_PRIVATE_KEY", hide_env_values = true)]
        bob_private_key: String,
        /// Capacity placed under the FactoryStateCell, in shannons.
        #[arg(long, default_value_t = 50_000_000_000)]
        factory_capacity: u64,
        /// Reserve capacity placed under the FactoryVaultCell, in shannons.
        #[arg(long, default_value_t = 300_000_000_000)]
        factory_vault_capacity: u64,
        /// New Alice balance quantity in the bounded rights fixture. Must be lower than 100.
        #[arg(long, default_value_t = 90)]
        touched_after_balance: u128,
        /// Absolute fee paid by each transaction, in shannons.
        #[arg(long, default_value_t = 100_000_000)]
        fee: u64,
        /// Mine this many blocks after each broadcast. Use 0 to only submit to tx-pool.
        #[arg(long, default_value_t = 4)]
        mine_blocks: u64,
        /// Directory where reduced-rights factory packages are stored.
        #[arg(long, default_value = "target/morph-factory-state-packages")]
        store_dir: std::path::PathBuf,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Run open -> save factory splice package -> apply -> child exit for CKB reserve addition.
    FactorySpliceInSmoke {
        /// Directory containing the built RISC-V contract binaries.
        #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
        contracts_dir: std::path::PathBuf,
        /// Secp256k1 private key that controls funded local-devnet cells.
        #[arg(long, env = "MORPH_DEVNET_PRIVATE_KEY", hide_env_values = true)]
        private_key: String,
        /// Devnet Alice factory signing key.
        #[arg(long, env = "MORPH_ALICE_PRIVATE_KEY", hide_env_values = true)]
        alice_private_key: String,
        /// Devnet Bob factory signing key.
        #[arg(long, env = "MORPH_BOB_PRIVATE_KEY", hide_env_values = true)]
        bob_private_key: String,
        /// Capacity placed under the FactoryStateCell, in shannons.
        #[arg(long, default_value_t = 50_000_000_000)]
        factory_capacity: u64,
        /// Initial reserve capacity placed under the FactoryVaultCell, in shannons.
        #[arg(long, default_value_t = 300_000_000_000)]
        factory_vault_capacity: u64,
        /// CKB amount added to the factory vault, in shannons.
        #[arg(long, default_value_t = 1_000_000_000)]
        splice_amount: u64,
        /// Capacity released from the post-splice factory reserve into the child channel vault.
        #[arg(long, default_value_t = 20_000_000_000)]
        child_vault_capacity: u64,
        /// Alice's child-channel descriptor capacity. Must be paired with --bob-capacity.
        #[arg(long)]
        alice_capacity: Option<u64>,
        /// Bob's child-channel descriptor capacity. Must be paired with --alice-capacity.
        #[arg(long)]
        bob_capacity: Option<u64>,
        /// Capacity placed under the child channel sponsor lock.
        #[arg(long, default_value_t = 50_000_000_000)]
        sponsor_capacity: u64,
        /// Absolute fee paid by each transaction, in shannons.
        #[arg(long, default_value_t = 100_000_000)]
        fee: u64,
        /// Relative block count required before child-channel finalisation.
        #[arg(long, default_value_t = 4)]
        finalise_since: u64,
        /// Mine this many blocks after each broadcast. Use 0 to only submit to tx-pool.
        #[arg(long, default_value_t = 4)]
        mine_blocks: u64,
        /// Directory where factory splice packages are stored.
        #[arg(long, default_value = "target/morph-factory-splice-packages")]
        store_dir: std::path::PathBuf,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Run open -> save factory splice package -> apply -> child exit for CKB reserve withdrawal.
    FactorySpliceOutSmoke {
        /// Directory containing the built RISC-V contract binaries.
        #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
        contracts_dir: std::path::PathBuf,
        /// Secp256k1 private key that controls funded local-devnet cells.
        #[arg(long, env = "MORPH_DEVNET_PRIVATE_KEY", hide_env_values = true)]
        private_key: String,
        /// Devnet Alice factory signing key.
        #[arg(long, env = "MORPH_ALICE_PRIVATE_KEY", hide_env_values = true)]
        alice_private_key: String,
        /// Devnet Bob factory signing key.
        #[arg(long, env = "MORPH_BOB_PRIVATE_KEY", hide_env_values = true)]
        bob_private_key: String,
        /// Capacity placed under the FactoryStateCell, in shannons.
        #[arg(long, default_value_t = 50_000_000_000)]
        factory_capacity: u64,
        /// Initial reserve capacity placed under the FactoryVaultCell, in shannons.
        #[arg(long, default_value_t = 300_000_000_000)]
        factory_vault_capacity: u64,
        /// CKB amount withdrawn from the factory vault, in shannons.
        #[arg(long, default_value_t = 7_000_000_000)]
        splice_amount: u64,
        /// Capacity released from the post-splice factory reserve into the child channel vault.
        #[arg(long, default_value_t = 20_000_000_000)]
        child_vault_capacity: u64,
        /// Alice's child-channel descriptor capacity. Must be paired with --bob-capacity.
        #[arg(long)]
        alice_capacity: Option<u64>,
        /// Bob's child-channel descriptor capacity. Must be paired with --alice-capacity.
        #[arg(long)]
        bob_capacity: Option<u64>,
        /// Capacity placed under the child channel sponsor lock.
        #[arg(long, default_value_t = 50_000_000_000)]
        sponsor_capacity: u64,
        /// Absolute fee paid by each transaction, in shannons.
        #[arg(long, default_value_t = 100_000_000)]
        fee: u64,
        /// Relative block count required before child-channel finalisation.
        #[arg(long, default_value_t = 4)]
        finalise_since: u64,
        /// Mine this many blocks after each broadcast. Use 0 to only submit to tx-pool.
        #[arg(long, default_value_t = 4)]
        mine_blocks: u64,
        /// Directory where factory splice packages are stored.
        #[arg(long, default_value = "target/morph-factory-splice-packages")]
        store_dir: std::path::PathBuf,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Run open -> save reduced factory splice package -> apply -> child exit for CKB reserve addition.
    FactoryReducedSpliceInSmoke {
        /// Directory containing the built RISC-V contract binaries.
        #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
        contracts_dir: std::path::PathBuf,
        /// Secp256k1 private key that controls funded local-devnet cells.
        #[arg(long, env = "MORPH_DEVNET_PRIVATE_KEY", hide_env_values = true)]
        private_key: String,
        /// Devnet Alice factory signing key.
        #[arg(long, env = "MORPH_ALICE_PRIVATE_KEY", hide_env_values = true)]
        alice_private_key: String,
        /// Devnet Bob factory signing key.
        #[arg(long, env = "MORPH_BOB_PRIVATE_KEY", hide_env_values = true)]
        bob_private_key: String,
        /// Capacity placed under the FactoryStateCell, in shannons.
        #[arg(long, default_value_t = 50_000_000_000)]
        factory_capacity: u64,
        /// Initial reserve capacity placed under the FactoryVaultCell, in shannons.
        #[arg(long, default_value_t = 300_000_000_000)]
        factory_vault_capacity: u64,
        /// CKB amount added to the factory vault, in shannons.
        #[arg(long, default_value_t = 1_000_000_000)]
        splice_amount: u64,
        /// Capacity released from the post-splice factory reserve into the child channel vault.
        #[arg(long, default_value_t = 20_000_000_000)]
        child_vault_capacity: u64,
        /// Alice's child-channel descriptor capacity. Must be paired with --bob-capacity.
        #[arg(long)]
        alice_capacity: Option<u64>,
        /// Bob's child-channel descriptor capacity. Must be paired with --alice-capacity.
        #[arg(long)]
        bob_capacity: Option<u64>,
        /// Capacity placed under the child channel sponsor lock.
        #[arg(long, default_value_t = 50_000_000_000)]
        sponsor_capacity: u64,
        /// Absolute fee paid by each transaction, in shannons.
        #[arg(long, default_value_t = 100_000_000)]
        fee: u64,
        /// Relative block count required before child-channel finalisation.
        #[arg(long, default_value_t = 4)]
        finalise_since: u64,
        /// Mine this many blocks after each broadcast. Use 0 to only submit to tx-pool.
        #[arg(long, default_value_t = 4)]
        mine_blocks: u64,
        /// Directory where reduced factory splice packages are stored.
        #[arg(long, default_value = "target/morph-factory-splice-packages")]
        store_dir: std::path::PathBuf,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Run open -> save reduced factory splice package -> apply -> child exit for CKB reserve withdrawal.
    FactoryReducedSpliceOutSmoke {
        /// Directory containing the built RISC-V contract binaries.
        #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
        contracts_dir: std::path::PathBuf,
        /// Secp256k1 private key that controls funded local-devnet cells.
        #[arg(long, env = "MORPH_DEVNET_PRIVATE_KEY", hide_env_values = true)]
        private_key: String,
        /// Devnet Alice factory signing key.
        #[arg(long, env = "MORPH_ALICE_PRIVATE_KEY", hide_env_values = true)]
        alice_private_key: String,
        /// Devnet Bob factory signing key.
        #[arg(long, env = "MORPH_BOB_PRIVATE_KEY", hide_env_values = true)]
        bob_private_key: String,
        /// Capacity placed under the FactoryStateCell, in shannons.
        #[arg(long, default_value_t = 50_000_000_000)]
        factory_capacity: u64,
        /// Initial reserve capacity placed under the FactoryVaultCell, in shannons.
        #[arg(long, default_value_t = 300_000_000_000)]
        factory_vault_capacity: u64,
        /// CKB amount withdrawn from the factory vault, in shannons.
        #[arg(long, default_value_t = 7_000_000_000)]
        splice_amount: u64,
        /// Capacity released from the post-splice factory reserve into the child channel vault.
        #[arg(long, default_value_t = 20_000_000_000)]
        child_vault_capacity: u64,
        /// Alice's child-channel descriptor capacity. Must be paired with --bob-capacity.
        #[arg(long)]
        alice_capacity: Option<u64>,
        /// Bob's child-channel descriptor capacity. Must be paired with --alice-capacity.
        #[arg(long)]
        bob_capacity: Option<u64>,
        /// Capacity placed under the child channel sponsor lock.
        #[arg(long, default_value_t = 50_000_000_000)]
        sponsor_capacity: u64,
        /// Absolute fee paid by each transaction, in shannons.
        #[arg(long, default_value_t = 100_000_000)]
        fee: u64,
        /// Relative block count required before child-channel finalisation.
        #[arg(long, default_value_t = 4)]
        finalise_since: u64,
        /// Mine this many blocks after each broadcast. Use 0 to only submit to tx-pool.
        #[arg(long, default_value_t = 4)]
        mine_blocks: u64,
        /// Directory where reduced factory splice packages are stored.
        #[arg(long, default_value = "target/morph-factory-splice-packages")]
        store_dir: std::path::PathBuf,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Run open -> xUDT factory splice package -> apply -> typed child exit for reserve addition.
    FactoryXudtSpliceInSmoke {
        /// Directory containing the built RISC-V contract binaries.
        #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
        contracts_dir: std::path::PathBuf,
        /// Secp256k1 private key controlling devnet funding cells and xUDT mint authority.
        #[arg(long, env = "MORPH_DEVNET_PRIVATE_KEY", hide_env_values = true)]
        private_key: String,
        /// Devnet Alice factory/channel signing key.
        #[arg(long, env = "MORPH_ALICE_PRIVATE_KEY", hide_env_values = true)]
        alice_private_key: String,
        /// Devnet Bob factory/channel signing key.
        #[arg(long, env = "MORPH_BOB_PRIVATE_KEY", hide_env_values = true)]
        bob_private_key: String,
        /// Capacity placed under the FactoryStateCell, in shannons.
        #[arg(long, default_value_t = 50_000_000_000)]
        factory_capacity: u64,
        /// Reserve capacity placed under the FactoryVaultCell, in shannons.
        #[arg(long, default_value_t = 300_000_000_000)]
        factory_vault_capacity: u64,
        /// Net xUDT amount added to the factory vault.
        #[arg(long, default_value_t = 100_000u128)]
        splice_xudt_amount: u128,
        /// Capacity released from the post-splice factory reserve into the child xUDT vault.
        #[arg(long, default_value_t = 40_000_000_000)]
        child_vault_capacity: u64,
        /// Alice's child-channel descriptor capacity. Must be paired with --bob-capacity.
        #[arg(long)]
        alice_capacity: Option<u64>,
        /// Bob's child-channel descriptor capacity. Must be paired with --alice-capacity.
        #[arg(long)]
        bob_capacity: Option<u64>,
        /// Alice's initial xUDT reserve amount.
        #[arg(long, default_value_t = 600_000u128)]
        alice_xudt_amount: u128,
        /// Bob's initial xUDT reserve amount.
        #[arg(long, default_value_t = 400_000u128)]
        bob_xudt_amount: u128,
        /// Capacity placed under the child channel sponsor lock.
        #[arg(long, default_value_t = 50_000_000_000)]
        sponsor_capacity: u64,
        /// Absolute fee paid by each transaction, in shannons.
        #[arg(long, default_value_t = 100_000_000)]
        fee: u64,
        /// Relative block count required before child-channel finalisation.
        #[arg(long, default_value_t = 4)]
        finalise_since: u64,
        /// Mine this many blocks after each broadcast. Use 0 to only submit to tx-pool.
        #[arg(long, default_value_t = 4)]
        mine_blocks: u64,
        /// Directory where factory splice packages are stored.
        #[arg(long, default_value = "target/morph-factory-splice-packages")]
        store_dir: std::path::PathBuf,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Run open -> xUDT factory splice package -> apply -> typed child exit for reserve withdrawal.
    FactoryXudtSpliceOutSmoke {
        /// Directory containing the built RISC-V contract binaries.
        #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
        contracts_dir: std::path::PathBuf,
        /// Secp256k1 private key controlling devnet funding cells and xUDT mint authority.
        #[arg(long, env = "MORPH_DEVNET_PRIVATE_KEY", hide_env_values = true)]
        private_key: String,
        /// Devnet Alice factory/channel signing key.
        #[arg(long, env = "MORPH_ALICE_PRIVATE_KEY", hide_env_values = true)]
        alice_private_key: String,
        /// Devnet Bob factory/channel signing key.
        #[arg(long, env = "MORPH_BOB_PRIVATE_KEY", hide_env_values = true)]
        bob_private_key: String,
        /// Capacity placed under the FactoryStateCell, in shannons.
        #[arg(long, default_value_t = 50_000_000_000)]
        factory_capacity: u64,
        /// Reserve capacity placed under the FactoryVaultCell, in shannons.
        #[arg(long, default_value_t = 300_000_000_000)]
        factory_vault_capacity: u64,
        /// Net xUDT amount withdrawn from the factory vault.
        #[arg(long, default_value_t = 100_000u128)]
        splice_xudt_amount: u128,
        /// Capacity released from the post-splice factory reserve into the child xUDT vault.
        #[arg(long, default_value_t = 40_000_000_000)]
        child_vault_capacity: u64,
        /// Alice's child-channel descriptor capacity. Must be paired with --bob-capacity.
        #[arg(long)]
        alice_capacity: Option<u64>,
        /// Bob's child-channel descriptor capacity. Must be paired with --alice-capacity.
        #[arg(long)]
        bob_capacity: Option<u64>,
        /// Alice's initial xUDT reserve amount.
        #[arg(long, default_value_t = 600_000u128)]
        alice_xudt_amount: u128,
        /// Bob's initial xUDT reserve amount.
        #[arg(long, default_value_t = 400_000u128)]
        bob_xudt_amount: u128,
        /// Capacity placed under the child channel sponsor lock.
        #[arg(long, default_value_t = 50_000_000_000)]
        sponsor_capacity: u64,
        /// Absolute fee paid by each transaction, in shannons.
        #[arg(long, default_value_t = 100_000_000)]
        fee: u64,
        /// Relative block count required before child-channel finalisation.
        #[arg(long, default_value_t = 4)]
        finalise_since: u64,
        /// Mine this many blocks after each broadcast. Use 0 to only submit to tx-pool.
        #[arg(long, default_value_t = 4)]
        mine_blocks: u64,
        /// Directory where factory splice packages are stored.
        #[arg(long, default_value = "target/morph-factory-splice-packages")]
        store_dir: std::path::PathBuf,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Run open -> reduced xUDT factory splice package -> apply -> typed child exit for reserve addition.
    FactoryReducedXudtSpliceInSmoke {
        /// Directory containing the built RISC-V contract binaries.
        #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
        contracts_dir: std::path::PathBuf,
        /// Secp256k1 private key controlling devnet funding cells and xUDT mint authority.
        #[arg(long, env = "MORPH_DEVNET_PRIVATE_KEY", hide_env_values = true)]
        private_key: String,
        /// Devnet Alice factory/channel signing key.
        #[arg(long, env = "MORPH_ALICE_PRIVATE_KEY", hide_env_values = true)]
        alice_private_key: String,
        /// Devnet Bob factory/channel signing key.
        #[arg(long, env = "MORPH_BOB_PRIVATE_KEY", hide_env_values = true)]
        bob_private_key: String,
        /// Capacity placed under the FactoryStateCell, in shannons.
        #[arg(long, default_value_t = 50_000_000_000)]
        factory_capacity: u64,
        /// Reserve capacity placed under the FactoryVaultCell, in shannons.
        #[arg(long, default_value_t = 300_000_000_000)]
        factory_vault_capacity: u64,
        /// Net xUDT amount added to the factory vault.
        #[arg(long, default_value_t = 100_000u128)]
        splice_xudt_amount: u128,
        /// Capacity released from the post-splice factory reserve into the child xUDT vault.
        #[arg(long, default_value_t = 40_000_000_000)]
        child_vault_capacity: u64,
        /// Alice's child-channel descriptor capacity. Must be paired with --bob-capacity.
        #[arg(long)]
        alice_capacity: Option<u64>,
        /// Bob's child-channel descriptor capacity. Must be paired with --alice-capacity.
        #[arg(long)]
        bob_capacity: Option<u64>,
        /// Alice's initial xUDT reserve amount.
        #[arg(long, default_value_t = 600_000u128)]
        alice_xudt_amount: u128,
        /// Bob's initial xUDT reserve amount.
        #[arg(long, default_value_t = 400_000u128)]
        bob_xudt_amount: u128,
        /// Capacity placed under the child channel sponsor lock.
        #[arg(long, default_value_t = 50_000_000_000)]
        sponsor_capacity: u64,
        /// Absolute fee paid by each transaction, in shannons.
        #[arg(long, default_value_t = 100_000_000)]
        fee: u64,
        /// Relative block count required before child-channel finalisation.
        #[arg(long, default_value_t = 4)]
        finalise_since: u64,
        /// Mine this many blocks after each broadcast. Use 0 to only submit to tx-pool.
        #[arg(long, default_value_t = 4)]
        mine_blocks: u64,
        /// Directory where reduced factory splice packages are stored.
        #[arg(long, default_value = "target/morph-factory-splice-packages")]
        store_dir: std::path::PathBuf,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Run open -> reduced xUDT factory splice package -> apply -> typed child exit for reserve withdrawal.
    FactoryReducedXudtSpliceOutSmoke {
        /// Directory containing the built RISC-V contract binaries.
        #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
        contracts_dir: std::path::PathBuf,
        /// Secp256k1 private key controlling devnet funding cells and xUDT mint authority.
        #[arg(long, env = "MORPH_DEVNET_PRIVATE_KEY", hide_env_values = true)]
        private_key: String,
        /// Devnet Alice factory/channel signing key.
        #[arg(long, env = "MORPH_ALICE_PRIVATE_KEY", hide_env_values = true)]
        alice_private_key: String,
        /// Devnet Bob factory/channel signing key.
        #[arg(long, env = "MORPH_BOB_PRIVATE_KEY", hide_env_values = true)]
        bob_private_key: String,
        /// Capacity placed under the FactoryStateCell, in shannons.
        #[arg(long, default_value_t = 50_000_000_000)]
        factory_capacity: u64,
        /// Reserve capacity placed under the FactoryVaultCell, in shannons.
        #[arg(long, default_value_t = 300_000_000_000)]
        factory_vault_capacity: u64,
        /// Net xUDT amount withdrawn from the factory vault.
        #[arg(long, default_value_t = 100_000u128)]
        splice_xudt_amount: u128,
        /// Capacity released from the post-splice factory reserve into the child xUDT vault.
        #[arg(long, default_value_t = 40_000_000_000)]
        child_vault_capacity: u64,
        /// Alice's child-channel descriptor capacity. Must be paired with --bob-capacity.
        #[arg(long)]
        alice_capacity: Option<u64>,
        /// Bob's child-channel descriptor capacity. Must be paired with --alice-capacity.
        #[arg(long)]
        bob_capacity: Option<u64>,
        /// Alice's initial xUDT reserve amount.
        #[arg(long, default_value_t = 600_000u128)]
        alice_xudt_amount: u128,
        /// Bob's initial xUDT reserve amount.
        #[arg(long, default_value_t = 400_000u128)]
        bob_xudt_amount: u128,
        /// Capacity placed under the child channel sponsor lock.
        #[arg(long, default_value_t = 50_000_000_000)]
        sponsor_capacity: u64,
        /// Absolute fee paid by each transaction, in shannons.
        #[arg(long, default_value_t = 100_000_000)]
        fee: u64,
        /// Relative block count required before child-channel finalisation.
        #[arg(long, default_value_t = 4)]
        finalise_since: u64,
        /// Mine this many blocks after each broadcast. Use 0 to only submit to tx-pool.
        #[arg(long, default_value_t = 4)]
        mine_blocks: u64,
        /// Directory where reduced factory splice packages are stored.
        #[arg(long, default_value = "target/morph-factory-splice-packages")]
        store_dir: std::path::PathBuf,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Run open -> sparse Merkle package -> package update for a larger factory rights tree.
    FactoryMerkleUpdateSmoke {
        /// Directory containing the built RISC-V contract binaries.
        #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
        contracts_dir: std::path::PathBuf,
        /// Secp256k1 private key that controls funded local-devnet cells.
        #[arg(long, env = "MORPH_DEVNET_PRIVATE_KEY", hide_env_values = true)]
        private_key: String,
        /// Devnet Alice factory signing key. Alice signs the Merkle update.
        #[arg(long, env = "MORPH_ALICE_PRIVATE_KEY", hide_env_values = true)]
        alice_private_key: String,
        /// Devnet Bob factory key used to prove full membership.
        #[arg(long, env = "MORPH_BOB_PRIVATE_KEY", hide_env_values = true)]
        bob_private_key: String,
        /// Capacity placed under the FactoryStateCell, in shannons.
        #[arg(long, default_value_t = 50_000_000_000)]
        factory_capacity: u64,
        /// Reserve capacity placed under the FactoryVaultCell, in shannons.
        #[arg(long, default_value_t = 300_000_000_000)]
        factory_vault_capacity: u64,
        /// New Alice balance quantity in the sparse Merkle fixture. Must be lower than 1000.
        #[arg(long, default_value_t = 900)]
        touched_after_balance: u128,
        /// Absolute fee paid by each transaction, in shannons.
        #[arg(long, default_value_t = 100_000_000)]
        fee: u64,
        /// Mine this many blocks after each broadcast. Use 0 to only submit to tx-pool.
        #[arg(long, default_value_t = 4)]
        mine_blocks: u64,
        /// Directory where sparse Merkle factory packages are stored.
        #[arg(long, default_value = "target/morph-factory-state-packages")]
        store_dir: std::path::PathBuf,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Run open -> reduced reserve-claim exit -> publish/finalise child channel.
    FactoryReducedExitSmoke {
        /// Directory containing the built RISC-V contract binaries.
        #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
        contracts_dir: std::path::PathBuf,
        /// Secp256k1 private key that controls funded local-devnet cells.
        #[arg(long, env = "MORPH_DEVNET_PRIVATE_KEY", hide_env_values = true)]
        private_key: String,
        /// Devnet Alice factory/channel signing key. Alice signs the reduced exit.
        #[arg(long, env = "MORPH_ALICE_PRIVATE_KEY", hide_env_values = true)]
        alice_private_key: String,
        /// Devnet Bob factory/channel key used to prove full membership.
        #[arg(long, env = "MORPH_BOB_PRIVATE_KEY", hide_env_values = true)]
        bob_private_key: String,
        /// Capacity placed under the FactoryStateCell, in shannons.
        #[arg(long, default_value_t = 50_000_000_000)]
        factory_capacity: u64,
        /// Reserve capacity placed under the FactoryVaultCell, in shannons.
        #[arg(long, default_value_t = 300_000_000_000)]
        factory_vault_capacity: u64,
        /// Capacity released from the factory reserve into the child vault.
        #[arg(long, default_value_t = 20_000_000_000)]
        child_vault_capacity: u64,
        /// Alice's child-channel descriptor capacity. Must be paired with --bob-capacity.
        #[arg(long)]
        alice_capacity: Option<u64>,
        /// Bob's child-channel descriptor capacity. Must be paired with --alice-capacity.
        #[arg(long)]
        bob_capacity: Option<u64>,
        /// Capacity placed under the child channel sponsor lock.
        #[arg(long, default_value_t = 50_000_000_000)]
        sponsor_capacity: u64,
        /// Absolute fee paid by each transaction, in shannons.
        #[arg(long, default_value_t = 100_000_000)]
        fee: u64,
        /// Relative block count required before child-channel finalisation.
        #[arg(long, default_value_t = 4)]
        finalise_since: u64,
        /// Mine this many blocks after each broadcast. Use 0 to only submit to tx-pool.
        #[arg(long, default_value_t = 4)]
        mine_blocks: u64,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Run open -> reduced reserve-claim CKB+xUDT exit -> publish/finalise child channel.
    FactoryReducedXudtExitSmoke {
        /// Directory containing the built RISC-V contract binaries.
        #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
        contracts_dir: std::path::PathBuf,
        /// Secp256k1 private key that controls funded local-devnet cells.
        #[arg(long, env = "MORPH_DEVNET_PRIVATE_KEY", hide_env_values = true)]
        private_key: String,
        /// Devnet Alice factory/channel signing key. Alice signs the reduced exit.
        #[arg(long, env = "MORPH_ALICE_PRIVATE_KEY", hide_env_values = true)]
        alice_private_key: String,
        /// Devnet Bob factory/channel key used to prove full membership.
        #[arg(long, env = "MORPH_BOB_PRIVATE_KEY", hide_env_values = true)]
        bob_private_key: String,
        /// Capacity placed under the FactoryStateCell, in shannons.
        #[arg(long, default_value_t = 50_000_000_000)]
        factory_capacity: u64,
        /// Reserve capacity placed under the FactoryVaultCell, in shannons.
        #[arg(long, default_value_t = 300_000_000_000)]
        factory_vault_capacity: u64,
        /// Capacity released from the factory reserve into the child xUDT vault.
        #[arg(long, default_value_t = 40_000_000_000)]
        child_vault_capacity: u64,
        /// Alice's child-channel descriptor capacity. Must be paired with --bob-capacity.
        #[arg(long)]
        alice_capacity: Option<u64>,
        /// Bob's child-channel descriptor capacity. Must be paired with --alice-capacity.
        #[arg(long)]
        bob_capacity: Option<u64>,
        /// Alice's final xUDT settlement amount.
        #[arg(long, default_value_t = 600_000u128)]
        alice_xudt_amount: u128,
        /// Bob's final xUDT settlement amount.
        #[arg(long, default_value_t = 400_000u128)]
        bob_xudt_amount: u128,
        /// Extra xUDT kept in the factory vault change after the child vault release.
        #[arg(long, default_value_t = 0u128)]
        factory_vault_xudt_surplus: u128,
        /// Capacity placed under the child channel sponsor lock.
        #[arg(long, default_value_t = 50_000_000_000)]
        sponsor_capacity: u64,
        /// Absolute fee paid by each transaction, in shannons.
        #[arg(long, default_value_t = 100_000_000)]
        fee: u64,
        /// Relative block count required before child-channel finalisation.
        #[arg(long, default_value_t = 4)]
        finalise_since: u64,
        /// Mine this many blocks after each broadcast. Use 0 to only submit to tx-pool.
        #[arg(long, default_value_t = 4)]
        mine_blocks: u64,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Run reduced CKB+xUDT child-vault amount mismatch rejection smoke.
    FactoryReducedXudtNegativeExitSmoke {
        /// Directory containing the built RISC-V contract binaries.
        #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
        contracts_dir: std::path::PathBuf,
        /// Secp256k1 private key that controls funded local-devnet cells.
        #[arg(long, env = "MORPH_DEVNET_PRIVATE_KEY", hide_env_values = true)]
        private_key: String,
        /// Devnet Alice factory/channel signing key. Alice signs the reduced exit.
        #[arg(long, env = "MORPH_ALICE_PRIVATE_KEY", hide_env_values = true)]
        alice_private_key: String,
        /// Devnet Bob factory/channel key used to prove full membership.
        #[arg(long, env = "MORPH_BOB_PRIVATE_KEY", hide_env_values = true)]
        bob_private_key: String,
        /// Capacity placed under the FactoryStateCell, in shannons.
        #[arg(long, default_value_t = 50_000_000_000)]
        factory_capacity: u64,
        /// Reserve capacity placed under the FactoryVaultCell, in shannons.
        #[arg(long, default_value_t = 300_000_000_000)]
        factory_vault_capacity: u64,
        /// Capacity released from the factory reserve into the child xUDT vault.
        #[arg(long, default_value_t = 40_000_000_000)]
        child_vault_capacity: u64,
        /// Alice's child-channel descriptor capacity. Must be paired with --bob-capacity.
        #[arg(long)]
        alice_capacity: Option<u64>,
        /// Bob's child-channel descriptor capacity. Must be paired with --alice-capacity.
        #[arg(long)]
        bob_capacity: Option<u64>,
        /// Alice's final xUDT settlement amount.
        #[arg(long, default_value_t = 600_000u128)]
        alice_xudt_amount: u128,
        /// Bob's final xUDT settlement amount.
        #[arg(long, default_value_t = 400_000u128)]
        bob_xudt_amount: u128,
        /// Capacity placed under the child channel sponsor lock.
        #[arg(long, default_value_t = 50_000_000_000)]
        sponsor_capacity: u64,
        /// Absolute fee paid by each transaction, in shannons.
        #[arg(long, default_value_t = 100_000_000)]
        fee: u64,
        /// Relative block count required before child-channel finalisation.
        #[arg(long, default_value_t = 4)]
        finalise_since: u64,
        /// Mine this many blocks after accepted broadcasts. Use 0 to only submit to tx-pool.
        #[arg(long, default_value_t = 4)]
        mine_blocks: u64,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Run a conservative factory-local CKB+xUDT child-channel smoke.
    FactoryXudtSmoke {
        /// Directory containing the built RISC-V contract binaries.
        #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
        contracts_dir: std::path::PathBuf,
        /// Secp256k1 private key that controls funded local-devnet cells.
        #[arg(long, env = "MORPH_DEVNET_PRIVATE_KEY", hide_env_values = true)]
        private_key: String,
        /// Devnet Alice factory/channel signing key.
        #[arg(long, env = "MORPH_ALICE_PRIVATE_KEY", hide_env_values = true)]
        alice_private_key: String,
        /// Devnet Bob factory/channel signing key.
        #[arg(long, env = "MORPH_BOB_PRIVATE_KEY", hide_env_values = true)]
        bob_private_key: String,
        /// Capacity placed under the FactoryStateCell, in shannons.
        #[arg(long, default_value_t = 50_000_000_000)]
        factory_capacity: u64,
        /// Reserve capacity placed under the FactoryVaultCell, in shannons.
        #[arg(long, default_value_t = 300_000_000_000)]
        factory_vault_capacity: u64,
        /// Capacity released from the factory reserve into the child xUDT vault.
        #[arg(long, default_value_t = 40_000_000_000)]
        child_vault_capacity: u64,
        /// Alice's child-channel descriptor capacity. Must be paired with --bob-capacity.
        #[arg(long)]
        alice_capacity: Option<u64>,
        /// Bob's child-channel descriptor capacity. Must be paired with --alice-capacity.
        #[arg(long)]
        bob_capacity: Option<u64>,
        /// Alice's final xUDT settlement amount.
        #[arg(long, default_value_t = 600_000u128)]
        alice_xudt_amount: u128,
        /// Bob's final xUDT settlement amount.
        #[arg(long, default_value_t = 400_000u128)]
        bob_xudt_amount: u128,
        /// Capacity placed under the child channel sponsor lock.
        #[arg(long, default_value_t = 50_000_000_000)]
        sponsor_capacity: u64,
        /// Absolute fee paid by each transaction, in shannons.
        #[arg(long, default_value_t = 100_000_000)]
        fee: u64,
        /// Relative block count required before child-channel finalisation.
        #[arg(long, default_value_t = 4)]
        finalise_since: u64,
        /// Mine this many blocks after each broadcast. Use 0 to only submit to tx-pool.
        #[arg(long, default_value_t = 4)]
        mine_blocks: u64,
        /// Directory where signed factory state packages are stored.
        #[arg(long, default_value = "target/morph-factory-xudt-state-packages")]
        store_dir: std::path::PathBuf,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Prove devnet rejects a factory-local xUDT exit with a tampered child vault amount.
    FactoryXudtNegativeSmoke {
        /// Directory containing the built RISC-V contract binaries.
        #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
        contracts_dir: std::path::PathBuf,
        /// Secp256k1 private key that controls funded local-devnet cells.
        #[arg(long, env = "MORPH_DEVNET_PRIVATE_KEY", hide_env_values = true)]
        private_key: String,
        /// Devnet Alice factory/channel signing key.
        #[arg(long, env = "MORPH_ALICE_PRIVATE_KEY", hide_env_values = true)]
        alice_private_key: String,
        /// Devnet Bob factory/channel signing key.
        #[arg(long, env = "MORPH_BOB_PRIVATE_KEY", hide_env_values = true)]
        bob_private_key: String,
        /// Capacity placed under the FactoryStateCell, in shannons.
        #[arg(long, default_value_t = 50_000_000_000)]
        factory_capacity: u64,
        /// Reserve capacity placed under the FactoryVaultCell, in shannons.
        #[arg(long, default_value_t = 300_000_000_000)]
        factory_vault_capacity: u64,
        /// Capacity released from the factory reserve into the child xUDT vault.
        #[arg(long, default_value_t = 40_000_000_000)]
        child_vault_capacity: u64,
        /// Alice's child-channel descriptor capacity. Must be paired with --bob-capacity.
        #[arg(long)]
        alice_capacity: Option<u64>,
        /// Bob's child-channel descriptor capacity. Must be paired with --alice-capacity.
        #[arg(long)]
        bob_capacity: Option<u64>,
        /// Alice's final xUDT settlement amount.
        #[arg(long, default_value_t = 600_000u128)]
        alice_xudt_amount: u128,
        /// Bob's final xUDT settlement amount.
        #[arg(long, default_value_t = 400_000u128)]
        bob_xudt_amount: u128,
        /// Capacity placed under the child channel sponsor lock.
        #[arg(long, default_value_t = 50_000_000_000)]
        sponsor_capacity: u64,
        /// Absolute fee paid by each transaction, in shannons.
        #[arg(long, default_value_t = 100_000_000)]
        fee: u64,
        /// Relative block count required before child-channel finalisation.
        #[arg(long, default_value_t = 4)]
        finalise_since: u64,
        /// Mine this many blocks after each accepted broadcast. Use 0 to only submit to tx-pool.
        #[arg(long, default_value_t = 4)]
        mine_blocks: u64,
        /// Directory where signed factory state packages are stored.
        #[arg(
            long,
            default_value = "target/morph-factory-xudt-negative-state-packages"
        )]
        store_dir: std::path::PathBuf,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Materialise a bilateral child channel from a conservative factory reserve.
    FactoryExitChannel {
        /// Directory containing the built RISC-V contract binaries.
        #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
        contracts_dir: std::path::PathBuf,
        /// Secp256k1 private key that pays the independent fee input.
        #[arg(long, env = "MORPH_DEVNET_PRIVATE_KEY", hide_env_values = true)]
        private_key: String,
        /// Devnet Alice factory/channel signing key.
        #[arg(long, env = "MORPH_ALICE_PRIVATE_KEY", hide_env_values = true)]
        alice_private_key: String,
        /// Bob's factory/channel signing key. Required for full-participant authorisation.
        #[arg(
            long,
            env = "MORPH_BOB_PRIVATE_KEY",
            hide_env_values = true,
            conflicts_with = "bob_public_key"
        )]
        bob_private_key: Option<String>,
        /// Additional factory private key for participant 3 onward. Repeat up to 14 times.
        #[arg(
            long = "participant-private-key",
            hide_env_values = true,
            conflicts_with = "additional_participant_public_keys"
        )]
        additional_participant_private_keys: Vec<String>,
        /// Additional compressed public key for participant 3 onward. Sufficient for reduced-reserve-claim authorisation.
        #[arg(
            long = "participant-public-key",
            conflicts_with = "additional_participant_private_keys"
        )]
        additional_participant_public_keys: Vec<String>,
        /// Bob's compressed 33-byte public key. Sufficient for reduced-reserve-claim authorisation.
        #[arg(long, conflicts_with = "bob_private_key")]
        bob_public_key: Option<String>,
        /// Factory exit authorisation path.
        #[arg(long, value_enum, default_value = "full-participants")]
        authorisation: FactoryExitAuthorisationArg,
        /// Current FactoryStateCell out point, formatted as <tx-hash>:<index>.
        #[arg(long)]
        factory_out_point: String,
        /// Current FactoryVaultCell out point, formatted as <tx-hash>:<index>.
        #[arg(long)]
        factory_vault_out_point: String,
        /// New factory update number. Defaults to old_update_number + 1.
        #[arg(long)]
        update_number: Option<u64>,
        /// Capacity released from the factory reserve into the child channel vault.
        #[arg(long, default_value_t = 20_000_000_000)]
        vault_capacity: u64,
        /// Alice's child-channel descriptor capacity. Must be paired with --bob-capacity.
        #[arg(long)]
        alice_capacity: Option<u64>,
        /// Bob's child-channel descriptor capacity. Must be paired with --alice-capacity.
        #[arg(long)]
        bob_capacity: Option<u64>,
        /// Alice's child-channel xUDT amount when the FactoryVaultCell carries xUDT.
        #[arg(long)]
        alice_xudt_amount: Option<u128>,
        /// Bob's child-channel xUDT amount when the FactoryVaultCell carries xUDT.
        #[arg(long)]
        bob_xudt_amount: Option<u128>,
        /// Capacity placed under the child channel sponsor lock.
        #[arg(long, default_value_t = 50_000_000_000)]
        sponsor_capacity: u64,
        /// Absolute fee paid by a normal owner cell, in shannons.
        #[arg(long, default_value_t = 100_000_000)]
        fee: u64,
        /// Relative block count required before child-channel finalisation.
        #[arg(long, default_value_t = 4)]
        finalise_since: u64,
        /// Mine this many blocks after broadcasting. Use 0 to only submit to tx-pool.
        #[arg(long, default_value_t = 4)]
        mine_blocks: u64,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Publish a newer signed settling state, paid by a SponsorCell.
    PublishState {
        /// Directory containing the built RISC-V contract binaries.
        #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
        contracts_dir: std::path::PathBuf,
        /// Secp256k1 private key that controls the sponsor change lock.
        #[arg(long, env = "MORPH_DEVNET_PRIVATE_KEY", hide_env_values = true)]
        private_key: String,
        /// Devnet Alice channel signing key.
        #[arg(long, env = "MORPH_ALICE_PRIVATE_KEY", hide_env_values = true)]
        alice_private_key: String,
        /// Devnet Bob channel signing key.
        #[arg(long, env = "MORPH_BOB_PRIVATE_KEY", hide_env_values = true)]
        bob_private_key: String,
        /// Current StateCell out point, formatted as <tx-hash>:<index>.
        #[arg(long)]
        state_out_point: String,
        /// SponsorCell out point, formatted as <tx-hash>:<index>.
        #[arg(long)]
        sponsor_out_point: String,
        /// New state number. Defaults to old_state_number + 1.
        #[arg(long)]
        state_number: Option<u64>,
        /// Signed state package JSON. When set, Alice/Bob keys are not used.
        #[arg(long, conflicts_with = "state_number")]
        state_package: Option<std::path::PathBuf>,
        /// Absolute fee paid by the SponsorCell, in shannons.
        #[arg(long, default_value_t = 100_000_000)]
        fee: u64,
        /// Mine this many blocks after broadcasting. Use 0 to only submit to tx-pool.
        #[arg(long, default_value_t = 4)]
        mine_blocks: u64,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Save a signed splice package from the live StateCell/VaultCell pair.
    SaveSplicePackage {
        /// Devnet Alice channel signing key.
        #[arg(long, env = "MORPH_ALICE_PRIVATE_KEY", hide_env_values = true)]
        alice_private_key: String,
        /// Devnet Bob channel signing key.
        #[arg(long, env = "MORPH_BOB_PRIVATE_KEY", hide_env_values = true)]
        bob_private_key: String,
        /// Current active StateCell out point, formatted as <tx-hash>:<index>.
        #[arg(long)]
        state_out_point: String,
        /// Current VaultCell out point, formatted as <tx-hash>:<index>.
        #[arg(long)]
        vault_out_point: String,
        /// CKB splice direction.
        #[arg(long, value_enum, default_value = "splice-in")]
        kind: CkbSpliceKindArg,
        /// Asset delta to encode in the splice package.
        #[arg(long, value_enum, default_value = "ckb")]
        asset: SpliceAssetArg,
        /// Net CKB amount added to or withdrawn from the vault, in shannons.
        #[arg(long, default_value_t = 1_000_000_000)]
        ckb_amount: u64,
        /// Net xUDT amount added to or withdrawn from the vault. Required with --asset xudt.
        #[arg(long)]
        xudt_amount: Option<u128>,
        /// Signed CKB fee reserved inside a splice-in delta. Must be 0 for splice-out.
        #[arg(long, default_value_t = 0)]
        signed_fee: u64,
        /// Funding epoch of the current live StateCell.
        #[arg(long, default_value_t = 0)]
        old_funding_epoch: u64,
        /// Funding epoch assigned to the post-splice StateCell. Defaults to old + 1.
        #[arg(long)]
        new_funding_epoch: Option<u64>,
        /// Splice sequence number. Defaults to the post-splice funding epoch.
        #[arg(long)]
        splice_number: Option<u64>,
        /// Directory where signed splice packages are stored.
        #[arg(long, default_value = "target/morph-splice-packages")]
        store_dir: std::path::PathBuf,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Apply a validated splice package to the live StateCell/VaultCell pair.
    ApplySplice {
        /// Directory containing the built RISC-V contract binaries.
        #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
        contracts_dir: std::path::PathBuf,
        /// Secp256k1 private key that pays splice external CKB and transaction fees.
        #[arg(long, env = "MORPH_DEVNET_PRIVATE_KEY", hide_env_values = true)]
        private_key: String,
        /// Current active StateCell out point, formatted as <tx-hash>:<index>.
        #[arg(long)]
        state_out_point: String,
        /// Current VaultCell out point, formatted as <tx-hash>:<index>.
        #[arg(long)]
        vault_out_point: String,
        /// Signed splice package JSON.
        #[arg(long)]
        splice_package: std::path::PathBuf,
        /// External owner-controlled xUDT input, formatted as <tx-hash>:<index>. Required for xUDT splice-in.
        #[arg(long)]
        xudt_input_out_point: Option<String>,
        /// Absolute transaction fee, in shannons.
        #[arg(long, default_value_t = 100_000_000)]
        fee: u64,
        /// Mine this many blocks after broadcasting. Use 0 to only submit to tx-pool.
        #[arg(long, default_value_t = 4)]
        mine_blocks: u64,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Save a signed settling state package without broadcasting it.
    SaveStatePackage {
        /// Devnet Alice channel signing key.
        #[arg(long, env = "MORPH_ALICE_PRIVATE_KEY", hide_env_values = true)]
        alice_private_key: String,
        /// Devnet Bob channel signing key.
        #[arg(long, env = "MORPH_BOB_PRIVATE_KEY", hide_env_values = true)]
        bob_private_key: String,
        /// Current StateCell out point, formatted as <tx-hash>:<index>.
        #[arg(long)]
        state_out_point: String,
        /// New state number. Defaults to old_state_number + 1.
        #[arg(long)]
        state_number: Option<u64>,
        /// Directory where signed state packages are stored.
        #[arg(long, default_value = "target/morph-state-packages")]
        store_dir: std::path::PathBuf,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// List saved signed state packages.
    ListStatePackages {
        /// Directory where signed state packages are stored.
        #[arg(long, default_value = "target/morph-state-packages")]
        store_dir: std::path::PathBuf,
        /// Optional channel id filter.
        #[arg(long)]
        channel_id: Option<String>,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Select the highest-numbered saved state package for a channel.
    LatestStatePackage {
        /// Directory where signed state packages are stored.
        #[arg(long, default_value = "target/morph-state-packages")]
        store_dir: std::path::PathBuf,
        /// Channel id to select.
        #[arg(long)]
        channel_id: String,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Publish the highest-numbered saved state package for a channel.
    PublishLatestPackage {
        /// Directory containing the built RISC-V contract binaries.
        #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
        contracts_dir: std::path::PathBuf,
        /// Secp256k1 private key that controls the sponsor change lock.
        #[arg(long, env = "MORPH_DEVNET_PRIVATE_KEY", hide_env_values = true)]
        private_key: String,
        /// Current StateCell out point, formatted as <tx-hash>:<index>.
        #[arg(long)]
        state_out_point: String,
        /// SponsorCell out point, formatted as <tx-hash>:<index>.
        #[arg(long)]
        sponsor_out_point: String,
        /// Directory where signed state packages are stored.
        #[arg(long, default_value = "target/morph-state-packages")]
        store_dir: std::path::PathBuf,
        /// Channel id to select.
        #[arg(long)]
        channel_id: String,
        /// Absolute fee paid by the SponsorCell, in shannons.
        #[arg(long, default_value_t = 100_000_000)]
        fee: u64,
        /// Mine this many blocks after broadcasting. Use 0 to only submit to tx-pool.
        #[arg(long, default_value_t = 4)]
        mine_blocks: u64,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Scan confirmed blocks and publish the latest saved package when an older StateCell is seen.
    WatchLatestPackage {
        /// Directory containing the built RISC-V contract binaries.
        #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
        contracts_dir: std::path::PathBuf,
        /// Secp256k1 private key that controls the sponsor change lock.
        #[arg(long, hide_env_values = true)]
        private_key: Option<String>,
        /// File containing the sponsor private key. Prefer this for watchtower processes.
        #[arg(long, env = "MORPH_DEVNET_PRIVATE_KEY_FILE", hide_env_values = true)]
        private_key_file: Option<PathBuf>,
        /// SponsorCell out point, formatted as <tx-hash>:<index>.
        /// Required unless --auto-fund-sponsor is set.
        #[arg(long)]
        sponsor_out_point: Option<String>,
        /// Directory where signed state packages are stored.
        #[arg(long, default_value = "target/morph-state-packages")]
        store_dir: std::path::PathBuf,
        /// Channel id to watch.
        #[arg(long)]
        channel_id: String,
        /// First block number to scan.
        #[arg(long, default_value_t = 0)]
        from_block: u64,
        /// Cursor JSON path. Defaults to the state-package store for this channel.
        #[arg(long)]
        cursor_file: Option<std::path::PathBuf>,
        /// Optional watchtower policy JSON that bounds this run.
        #[arg(long)]
        watch_policy: Option<std::path::PathBuf>,
        /// Publication fee/RBF/window profile JSON.
        #[arg(long)]
        publication_profile: Option<std::path::PathBuf>,
        /// Durable JSONL publication-attempt log. Required with --publication-profile.
        #[arg(long)]
        publication_attempt_log: Option<std::path::PathBuf>,
        /// Optional JSONL alert sink for watchtower events.
        #[arg(long)]
        alert_file: Option<std::path::PathBuf>,
        /// Optional HTTP webhook URL for watchtower alerts.
        #[arg(long)]
        alert_webhook_url: Option<String>,
        /// Start from --from-block even when a saved cursor exists.
        #[arg(long)]
        ignore_cursor: bool,
        /// Required confirmation depth before a StateCell is actionable.
        #[arg(long, default_value_t = 1)]
        detection_depth: u64,
        /// Maximum time to poll before returning without publication.
        #[arg(long, default_value_t = 60)]
        timeout_secs: u64,
        /// Poll interval in milliseconds.
        #[arg(long, default_value_t = 1_000)]
        poll_ms: u64,
        /// Absolute fee paid by the SponsorCell, in shannons.
        #[arg(long, default_value_t = 100_000_000)]
        fee: u64,
        /// Mine this many blocks after broadcasting. Use 0 to only submit to tx-pool.
        #[arg(long, default_value_t = 4)]
        mine_blocks: u64,
        /// Create a narrowly scoped SponsorCell when an older StateCell is observed.
        #[arg(long)]
        auto_fund_sponsor: bool,
        /// Capacity placed under an automatically created SponsorCell, in shannons.
        #[arg(long, default_value_t = 50_000_000_000)]
        auto_sponsor_capacity: u64,
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
    /// Finalise a settling channel and release the vault according to the descriptor.
    FinaliseChannel {
        /// Directory containing the built RISC-V contract binaries.
        #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
        contracts_dir: std::path::PathBuf,
        /// Secp256k1 private key receiving the state-carrier refund.
        #[arg(long, env = "MORPH_DEVNET_PRIVATE_KEY", hide_env_values = true)]
        private_key: String,
        /// Devnet Alice settlement key.
        #[arg(long, env = "MORPH_ALICE_PRIVATE_KEY", hide_env_values = true)]
        alice_private_key: String,
        /// Devnet Bob settlement key.
        #[arg(long, env = "MORPH_BOB_PRIVATE_KEY", hide_env_values = true)]
        bob_private_key: String,
        /// Current settling StateCell out point, formatted as <tx-hash>:<index>.
        #[arg(long)]
        state_out_point: String,
        /// VaultCell out point, formatted as <tx-hash>:<index>.
        #[arg(long)]
        vault_out_point: String,
        /// Alice's descriptor capacity, in shannons. Must be paired with --bob-capacity.
        #[arg(long)]
        alice_capacity: Option<u64>,
        /// Bob's descriptor capacity, in shannons. Must be paired with --alice-capacity.
        #[arg(long)]
        bob_capacity: Option<u64>,
        /// Relative block count encoded onto the StateCell input.
        #[arg(long, default_value_t = 4)]
        finalise_since: u64,
        /// Absolute fee paid from the state-carrier refund, in shannons.
        #[arg(long, default_value_t = 100_000_000)]
        fee: u64,
        /// Mine this many blocks after broadcasting. Use 0 to only submit to tx-pool.
        #[arg(long, default_value_t = 4)]
        mine_blocks: u64,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Run open -> CKB splice-in -> sponsor top-up -> post-splice publish on devnet.
    SpliceInSmoke {
        /// Directory containing the built RISC-V contract binaries.
        #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
        contracts_dir: std::path::PathBuf,
        /// Secp256k1 private key controlling devnet funding cells.
        #[arg(long, env = "MORPH_DEVNET_PRIVATE_KEY", hide_env_values = true)]
        private_key: String,
        /// Devnet Alice channel key.
        #[arg(long, env = "MORPH_ALICE_PRIVATE_KEY", hide_env_values = true)]
        alice_private_key: String,
        /// Devnet Bob channel key.
        #[arg(long, env = "MORPH_BOB_PRIVATE_KEY", hide_env_values = true)]
        bob_private_key: String,
        /// Initial capacity placed under the channel vault lock, in shannons.
        #[arg(long, default_value_t = 20_000_000_000)]
        vault_capacity: u64,
        /// Net CKB amount added to the vault, in shannons.
        #[arg(long, default_value_t = 1_000_000_000)]
        splice_amount: u64,
        /// Alice's initial descriptor capacity, in shannons. Must be paired with --bob-capacity.
        #[arg(long)]
        alice_capacity: Option<u64>,
        /// Bob's initial descriptor capacity, in shannons. Must be paired with --alice-capacity.
        #[arg(long)]
        bob_capacity: Option<u64>,
        /// Capacity placed under each sponsor lock, in shannons.
        #[arg(long, default_value_t = 50_000_000_000)]
        sponsor_capacity: u64,
        /// Absolute fee used for each transaction, in shannons.
        #[arg(long, default_value_t = 100_000_000)]
        fee: u64,
        /// Relative block count used by channel scripts.
        #[arg(long, default_value_t = 4)]
        finalise_since: u64,
        /// Mine this many blocks after each broadcast. Use 0 to only submit to tx-pool.
        #[arg(long, default_value_t = 4)]
        mine_blocks: u64,
        /// Directory where signed splice packages are stored.
        #[arg(long, default_value = "target/morph-splice-packages")]
        store_dir: std::path::PathBuf,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Run open -> CKB splice-out -> sponsor top-up -> post-splice publish on devnet.
    SpliceOutSmoke {
        /// Directory containing the built RISC-V contract binaries.
        #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
        contracts_dir: std::path::PathBuf,
        /// Secp256k1 private key controlling devnet funding cells.
        #[arg(long, env = "MORPH_DEVNET_PRIVATE_KEY", hide_env_values = true)]
        private_key: String,
        /// Devnet Alice channel key.
        #[arg(long, env = "MORPH_ALICE_PRIVATE_KEY", hide_env_values = true)]
        alice_private_key: String,
        /// Devnet Bob channel key.
        #[arg(long, env = "MORPH_BOB_PRIVATE_KEY", hide_env_values = true)]
        bob_private_key: String,
        /// Initial capacity placed under the channel vault lock, in shannons.
        #[arg(long, default_value_t = 24_000_000_000)]
        vault_capacity: u64,
        /// Net CKB amount withdrawn from the vault, in shannons.
        #[arg(long, default_value_t = 7_000_000_000)]
        splice_amount: u64,
        /// Alice's initial descriptor capacity, in shannons. Must be paired with --bob-capacity.
        #[arg(long)]
        alice_capacity: Option<u64>,
        /// Bob's initial descriptor capacity, in shannons. Must be paired with --alice-capacity.
        #[arg(long)]
        bob_capacity: Option<u64>,
        /// Capacity placed under each sponsor lock, in shannons.
        #[arg(long, default_value_t = 50_000_000_000)]
        sponsor_capacity: u64,
        /// Absolute fee used for each transaction, in shannons.
        #[arg(long, default_value_t = 100_000_000)]
        fee: u64,
        /// Relative block count used by channel scripts.
        #[arg(long, default_value_t = 4)]
        finalise_since: u64,
        /// Mine this many blocks after each broadcast. Use 0 to only submit to tx-pool.
        #[arg(long, default_value_t = 4)]
        mine_blocks: u64,
        /// Directory where signed splice packages are stored.
        #[arg(long, default_value = "target/morph-splice-packages")]
        store_dir: std::path::PathBuf,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Run open -> xUDT splice-in -> sponsor top-up -> post-splice publish on devnet.
    XudtSpliceInSmoke {
        /// Directory containing the built RISC-V contract binaries.
        #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
        contracts_dir: std::path::PathBuf,
        /// Secp256k1 private key controlling devnet funding cells and xUDT mint authority.
        #[arg(long, env = "MORPH_DEVNET_PRIVATE_KEY", hide_env_values = true)]
        private_key: String,
        /// Devnet Alice channel key.
        #[arg(long, env = "MORPH_ALICE_PRIVATE_KEY", hide_env_values = true)]
        alice_private_key: String,
        /// Devnet Bob channel key.
        #[arg(long, env = "MORPH_BOB_PRIVATE_KEY", hide_env_values = true)]
        bob_private_key: String,
        /// Capacity placed under the xUDT vault lock, in shannons.
        #[arg(long, default_value_t = 40_000_000_000)]
        vault_capacity: u64,
        /// Net xUDT amount added to the vault.
        #[arg(long, default_value_t = 100_000u128)]
        splice_xudt_amount: u128,
        /// Alice's descriptor capacity, in shannons. Must be paired with --bob-capacity.
        #[arg(long)]
        alice_capacity: Option<u64>,
        /// Bob's descriptor capacity, in shannons. Must be paired with --alice-capacity.
        #[arg(long)]
        bob_capacity: Option<u64>,
        /// Alice's initial xUDT settlement amount.
        #[arg(long, default_value_t = 600_000u128)]
        alice_xudt_amount: u128,
        /// Bob's initial xUDT settlement amount.
        #[arg(long, default_value_t = 400_000u128)]
        bob_xudt_amount: u128,
        /// Capacity placed under each sponsor lock, in shannons.
        #[arg(long, default_value_t = 50_000_000_000)]
        sponsor_capacity: u64,
        /// Absolute fee used for each transaction, in shannons.
        #[arg(long, default_value_t = 100_000_000)]
        fee: u64,
        /// Relative block count used by channel scripts.
        #[arg(long, default_value_t = 4)]
        finalise_since: u64,
        /// Mine this many blocks after each broadcast. Use 0 to only submit to tx-pool.
        #[arg(long, default_value_t = 4)]
        mine_blocks: u64,
        /// Directory where signed splice packages are stored.
        #[arg(long, default_value = "target/morph-splice-packages")]
        store_dir: std::path::PathBuf,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Run open -> xUDT splice-out -> sponsor top-up -> post-splice publish on devnet.
    XudtSpliceOutSmoke {
        /// Directory containing the built RISC-V contract binaries.
        #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
        contracts_dir: std::path::PathBuf,
        /// Secp256k1 private key controlling devnet funding cells and xUDT mint authority.
        #[arg(long, env = "MORPH_DEVNET_PRIVATE_KEY", hide_env_values = true)]
        private_key: String,
        /// Devnet Alice channel key.
        #[arg(long, env = "MORPH_ALICE_PRIVATE_KEY", hide_env_values = true)]
        alice_private_key: String,
        /// Devnet Bob channel key.
        #[arg(long, env = "MORPH_BOB_PRIVATE_KEY", hide_env_values = true)]
        bob_private_key: String,
        /// Capacity placed under the xUDT vault lock, in shannons.
        #[arg(long, default_value_t = 40_000_000_000)]
        vault_capacity: u64,
        /// Net xUDT amount withdrawn from the vault.
        #[arg(long, default_value_t = 100_000u128)]
        splice_xudt_amount: u128,
        /// Alice's descriptor capacity, in shannons. Must be paired with --bob-capacity.
        #[arg(long)]
        alice_capacity: Option<u64>,
        /// Bob's descriptor capacity, in shannons. Must be paired with --alice-capacity.
        #[arg(long)]
        bob_capacity: Option<u64>,
        /// Alice's initial xUDT settlement amount.
        #[arg(long, default_value_t = 600_000u128)]
        alice_xudt_amount: u128,
        /// Bob's initial xUDT settlement amount.
        #[arg(long, default_value_t = 400_000u128)]
        bob_xudt_amount: u128,
        /// Capacity placed under each sponsor lock, in shannons.
        #[arg(long, default_value_t = 50_000_000_000)]
        sponsor_capacity: u64,
        /// Absolute fee used for each transaction, in shannons.
        #[arg(long, default_value_t = 100_000_000)]
        fee: u64,
        /// Relative block count used by channel scripts.
        #[arg(long, default_value_t = 4)]
        finalise_since: u64,
        /// Mine this many blocks after each broadcast. Use 0 to only submit to tx-pool.
        #[arg(long, default_value_t = 4)]
        mine_blocks: u64,
        /// Directory where signed splice packages are stored.
        #[arg(long, default_value = "target/morph-splice-packages")]
        store_dir: std::path::PathBuf,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Prove live devnet rejects malformed and mismatched splice packages.
    SpliceNegativeSmoke {
        /// Directory containing the built RISC-V contract binaries.
        #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
        contracts_dir: std::path::PathBuf,
        /// Secp256k1 private key controlling devnet funding cells and xUDT mint authority.
        #[arg(long, env = "MORPH_DEVNET_PRIVATE_KEY", hide_env_values = true)]
        private_key: String,
        /// Devnet Alice channel key.
        #[arg(long, env = "MORPH_ALICE_PRIVATE_KEY", hide_env_values = true)]
        alice_private_key: String,
        /// Devnet Bob channel key.
        #[arg(long, env = "MORPH_BOB_PRIVATE_KEY", hide_env_values = true)]
        bob_private_key: String,
        /// Initial capacity placed under both test vault locks, in shannons.
        #[arg(long, default_value_t = 40_000_000_000)]
        vault_capacity: u64,
        /// Net CKB amount used for splice-in/out negative packages, in shannons.
        #[arg(long, default_value_t = 1_000_000_000)]
        splice_amount: u64,
        /// Net xUDT amount used for xUDT splice-out tampering.
        #[arg(long, default_value_t = 100_000u128)]
        splice_xudt_amount: u128,
        /// Alice's descriptor capacity, in shannons. Must be paired with --bob-capacity.
        #[arg(long)]
        alice_capacity: Option<u64>,
        /// Bob's descriptor capacity, in shannons. Must be paired with --alice-capacity.
        #[arg(long)]
        bob_capacity: Option<u64>,
        /// Alice's initial xUDT settlement amount.
        #[arg(long, default_value_t = 600_000u128)]
        alice_xudt_amount: u128,
        /// Bob's initial xUDT settlement amount.
        #[arg(long, default_value_t = 400_000u128)]
        bob_xudt_amount: u128,
        /// Capacity placed under each sponsor lock, in shannons.
        #[arg(long, default_value_t = 50_000_000_000)]
        sponsor_capacity: u64,
        /// Absolute fee used for setup and rejected apply attempts, in shannons.
        #[arg(long, default_value_t = 100_000_000)]
        fee: u64,
        /// Relative block count used by channel scripts.
        #[arg(long, default_value_t = 4)]
        finalise_since: u64,
        /// Mine this many blocks after accepted setup broadcasts. Rejected attempts never mine.
        #[arg(long, default_value_t = 4)]
        mine_blocks: u64,
        /// Directory where signed and tampered splice packages are stored.
        #[arg(long, default_value = "target/morph-splice-packages")]
        store_dir: std::path::PathBuf,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Run open -> stale publish -> sponsor top-up -> supersede -> finalise on devnet.
    SupersedeSmoke {
        /// Directory containing the built RISC-V contract binaries.
        #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
        contracts_dir: std::path::PathBuf,
        /// Secp256k1 private key controlling devnet funding cells.
        #[arg(long, env = "MORPH_DEVNET_PRIVATE_KEY", hide_env_values = true)]
        private_key: String,
        /// Devnet Alice channel key.
        #[arg(long, env = "MORPH_ALICE_PRIVATE_KEY", hide_env_values = true)]
        alice_private_key: String,
        /// Devnet Bob channel key.
        #[arg(long, env = "MORPH_BOB_PRIVATE_KEY", hide_env_values = true)]
        bob_private_key: String,
        /// Capacity placed under the channel vault lock, in shannons.
        #[arg(long, default_value_t = 20_000_000_000)]
        vault_capacity: u64,
        /// Alice's descriptor capacity, in shannons. Must be paired with --bob-capacity.
        #[arg(long)]
        alice_capacity: Option<u64>,
        /// Bob's descriptor capacity, in shannons. Must be paired with --alice-capacity.
        #[arg(long)]
        bob_capacity: Option<u64>,
        /// Capacity placed under each sponsor lock, in shannons.
        #[arg(long, default_value_t = 50_000_000_000)]
        sponsor_capacity: u64,
        /// Absolute fee used for each transaction, in shannons.
        #[arg(long, default_value_t = 100_000_000)]
        fee: u64,
        /// Relative block count used by channel finalisation.
        #[arg(long, default_value_t = 4)]
        finalise_since: u64,
        /// Mine this many blocks after each broadcast. Use 0 to only submit to tx-pool.
        #[arg(long, default_value_t = 4)]
        mine_blocks: u64,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Prove live devnet rejects finalisation when the StateCell input since is too low.
    FinaliseSinceNegativeSmoke {
        /// Directory containing the built RISC-V contract binaries.
        #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
        contracts_dir: std::path::PathBuf,
        /// Secp256k1 private key controlling devnet funding cells.
        #[arg(long, env = "MORPH_DEVNET_PRIVATE_KEY", hide_env_values = true)]
        private_key: String,
        /// Devnet Alice channel key.
        #[arg(long, env = "MORPH_ALICE_PRIVATE_KEY", hide_env_values = true)]
        alice_private_key: String,
        /// Devnet Bob channel key.
        #[arg(long, env = "MORPH_BOB_PRIVATE_KEY", hide_env_values = true)]
        bob_private_key: String,
        /// Capacity placed under the channel vault lock, in shannons.
        #[arg(long, default_value_t = 20_000_000_000)]
        vault_capacity: u64,
        /// Alice's descriptor capacity, in shannons. Must be paired with --bob-capacity.
        #[arg(long)]
        alice_capacity: Option<u64>,
        /// Bob's descriptor capacity, in shannons. Must be paired with --alice-capacity.
        #[arg(long)]
        bob_capacity: Option<u64>,
        /// Capacity placed under each sponsor lock, in shannons.
        #[arg(long, default_value_t = 50_000_000_000)]
        sponsor_capacity: u64,
        /// Absolute fee used for each transaction, in shannons.
        #[arg(long, default_value_t = 100_000_000)]
        fee: u64,
        /// Relative block count required by channel finalisation.
        #[arg(long, default_value_t = 4)]
        finalise_since: u64,
        /// Mine this many blocks after each accepted broadcast. Use 0 to only submit to tx-pool.
        #[arg(long, default_value_t = 4)]
        mine_blocks: u64,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Run open -> publish -> finalise for a CKB+xUDT channel on devnet.
    XudtSmoke {
        /// Directory containing the built RISC-V contract binaries.
        #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
        contracts_dir: std::path::PathBuf,
        /// Secp256k1 private key controlling devnet funding cells and xUDT mint authority.
        #[arg(long, env = "MORPH_DEVNET_PRIVATE_KEY", hide_env_values = true)]
        private_key: String,
        /// Devnet Alice channel key.
        #[arg(long, env = "MORPH_ALICE_PRIVATE_KEY", hide_env_values = true)]
        alice_private_key: String,
        /// Devnet Bob channel key.
        #[arg(long, env = "MORPH_BOB_PRIVATE_KEY", hide_env_values = true)]
        bob_private_key: String,
        /// Capacity placed under the xUDT vault lock, in shannons.
        #[arg(long, default_value_t = 40_000_000_000)]
        vault_capacity: u64,
        /// Alice's descriptor capacity, in shannons. Must be paired with --bob-capacity.
        #[arg(long)]
        alice_capacity: Option<u64>,
        /// Bob's descriptor capacity, in shannons. Must be paired with --alice-capacity.
        #[arg(long)]
        bob_capacity: Option<u64>,
        /// Alice's final xUDT settlement amount.
        #[arg(long, default_value_t = 600_000u128)]
        alice_xudt_amount: u128,
        /// Bob's final xUDT settlement amount.
        #[arg(long, default_value_t = 400_000u128)]
        bob_xudt_amount: u128,
        /// Capacity placed under the sponsor lock, in shannons.
        #[arg(long, default_value_t = 50_000_000_000)]
        sponsor_capacity: u64,
        /// Absolute fee used for each transaction, in shannons.
        #[arg(long, default_value_t = 100_000_000)]
        fee: u64,
        /// Relative block count used by channel finalisation.
        #[arg(long, default_value_t = 4)]
        finalise_since: u64,
        /// Mine this many blocks after each broadcast. Use 0 to only submit to tx-pool.
        #[arg(long, default_value_t = 4)]
        mine_blocks: u64,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Prove live devnet rejects tampered CKB+xUDT vault settlement.
    XudtNegativeSmoke {
        /// Directory containing the built RISC-V contract binaries.
        #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
        contracts_dir: std::path::PathBuf,
        /// Secp256k1 private key controlling devnet funding cells and xUDT mint authority.
        #[arg(long, env = "MORPH_DEVNET_PRIVATE_KEY", hide_env_values = true)]
        private_key: String,
        /// Devnet Alice channel key.
        #[arg(long, env = "MORPH_ALICE_PRIVATE_KEY", hide_env_values = true)]
        alice_private_key: String,
        /// Devnet Bob channel key.
        #[arg(long, env = "MORPH_BOB_PRIVATE_KEY", hide_env_values = true)]
        bob_private_key: String,
        /// Capacity placed under the xUDT vault lock, in shannons.
        #[arg(long, default_value_t = 40_000_000_000)]
        vault_capacity: u64,
        /// Alice's descriptor capacity, in shannons. Must be paired with --bob-capacity.
        #[arg(long)]
        alice_capacity: Option<u64>,
        /// Bob's descriptor capacity, in shannons. Must be paired with --alice-capacity.
        #[arg(long)]
        bob_capacity: Option<u64>,
        /// Alice's final xUDT settlement amount.
        #[arg(long, default_value_t = 600_000u128)]
        alice_xudt_amount: u128,
        /// Bob's final xUDT settlement amount.
        #[arg(long, default_value_t = 400_000u128)]
        bob_xudt_amount: u128,
        /// Capacity placed under the sponsor lock, in shannons.
        #[arg(long, default_value_t = 50_000_000_000)]
        sponsor_capacity: u64,
        /// Absolute fee used for each transaction, in shannons.
        #[arg(long, default_value_t = 100_000_000)]
        fee: u64,
        /// Relative block count used by channel finalisation.
        #[arg(long, default_value_t = 4)]
        finalise_since: u64,
        /// Mine this many blocks after each accepted broadcast. Use 0 to only submit to tx-pool.
        #[arg(long, default_value_t = 4)]
        mine_blocks: u64,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Prove live devnet rejects a SponsorCell outside its state-number policy.
    SponsorPolicyNegativeSmoke {
        /// Directory containing the built RISC-V contract binaries.
        #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
        contracts_dir: std::path::PathBuf,
        /// Secp256k1 private key controlling devnet funding cells.
        #[arg(long, env = "MORPH_DEVNET_PRIVATE_KEY", hide_env_values = true)]
        private_key: String,
        /// Devnet Alice channel key.
        #[arg(long, env = "MORPH_ALICE_PRIVATE_KEY", hide_env_values = true)]
        alice_private_key: String,
        /// Devnet Bob channel key.
        #[arg(long, env = "MORPH_BOB_PRIVATE_KEY", hide_env_values = true)]
        bob_private_key: String,
        /// Capacity placed under the channel vault lock, in shannons.
        #[arg(long, default_value_t = 20_000_000_000)]
        vault_capacity: u64,
        /// Alice's descriptor capacity, in shannons. Must be paired with --bob-capacity.
        #[arg(long)]
        alice_capacity: Option<u64>,
        /// Bob's descriptor capacity, in shannons. Must be paired with --alice-capacity.
        #[arg(long)]
        bob_capacity: Option<u64>,
        /// Capacity placed under each sponsor lock, in shannons.
        #[arg(long, default_value_t = 50_000_000_000)]
        sponsor_capacity: u64,
        /// Absolute fee used for each transaction, in shannons.
        #[arg(long, default_value_t = 100_000_000)]
        fee: u64,
        /// Relative block count used by channel finalisation.
        #[arg(long, default_value_t = 4)]
        finalise_since: u64,
        /// Mine this many blocks after each broadcast. Use 0 to only submit to tx-pool.
        #[arg(long, default_value_t = 4)]
        mine_blocks: u64,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Prove live devnet rejects a SponsorCell whose fee cap is too low.
    SponsorBudgetNegativeSmoke {
        /// Directory containing the built RISC-V contract binaries.
        #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
        contracts_dir: std::path::PathBuf,
        /// Secp256k1 private key controlling devnet funding cells.
        #[arg(long, env = "MORPH_DEVNET_PRIVATE_KEY", hide_env_values = true)]
        private_key: String,
        /// Devnet Alice channel key.
        #[arg(long, env = "MORPH_ALICE_PRIVATE_KEY", hide_env_values = true)]
        alice_private_key: String,
        /// Devnet Bob channel key.
        #[arg(long, env = "MORPH_BOB_PRIVATE_KEY", hide_env_values = true)]
        bob_private_key: String,
        /// Capacity placed under the channel vault lock, in shannons.
        #[arg(long, default_value_t = 20_000_000_000)]
        vault_capacity: u64,
        /// Alice's descriptor capacity, in shannons. Must be paired with --bob-capacity.
        #[arg(long)]
        alice_capacity: Option<u64>,
        /// Bob's descriptor capacity, in shannons. Must be paired with --alice-capacity.
        #[arg(long)]
        bob_capacity: Option<u64>,
        /// Capacity placed under each sponsor lock, in shannons.
        #[arg(long, default_value_t = 50_000_000_000)]
        sponsor_capacity: u64,
        /// Absolute fee used for each transaction, in shannons.
        #[arg(long, default_value_t = 100_000_000)]
        fee: u64,
        /// Relative block count used by channel finalisation.
        #[arg(long, default_value_t = 4)]
        finalise_since: u64,
        /// Mine this many blocks after each accepted broadcast. Use 0 to only submit to tx-pool.
        #[arg(long, default_value_t = 4)]
        mine_blocks: u64,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Prove competing mempool spends do not replace a live StateCell update.
    CompetingSpendSmoke {
        /// Directory containing the built RISC-V contract binaries.
        #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
        contracts_dir: std::path::PathBuf,
        /// Secp256k1 private key controlling devnet funding cells.
        #[arg(long, env = "MORPH_DEVNET_PRIVATE_KEY", hide_env_values = true)]
        private_key: String,
        /// Devnet Alice channel key.
        #[arg(long, env = "MORPH_ALICE_PRIVATE_KEY", hide_env_values = true)]
        alice_private_key: String,
        /// Devnet Bob channel key.
        #[arg(long, env = "MORPH_BOB_PRIVATE_KEY", hide_env_values = true)]
        bob_private_key: String,
        /// Capacity placed under the channel vault lock, in shannons.
        #[arg(long, default_value_t = 20_000_000_000)]
        vault_capacity: u64,
        /// Alice's descriptor capacity, in shannons. Must be paired with --bob-capacity.
        #[arg(long)]
        alice_capacity: Option<u64>,
        /// Bob's descriptor capacity, in shannons. Must be paired with --alice-capacity.
        #[arg(long)]
        bob_capacity: Option<u64>,
        /// Capacity placed under each sponsor lock, in shannons.
        #[arg(long, default_value_t = 50_000_000_000)]
        sponsor_capacity: u64,
        /// Absolute fee used for each transaction, in shannons.
        #[arg(long, default_value_t = 100_000_000)]
        fee: u64,
        /// Relative block count used by channel finalisation.
        #[arg(long, default_value_t = 4)]
        finalise_since: u64,
        /// Mine this many blocks after each accepted broadcast. Must be greater than zero.
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
        Command::PrintFixture => print_fixture(),
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
        Command::PrintFactoryFixture => {
            let package = factory_packages::fixture_package()?;
            println!("{}", serde_json::to_string_pretty(&package)?);
            Ok(())
        }
        Command::PrintConditionalBatchFixture => {
            let package = conditional_packages::fixture_package()?;
            println!("{}", serde_json::to_string_pretty(&package)?);
            Ok(())
        }
        Command::PrintMultiAssetFixture => {
            println!(
                "{}",
                serde_json::to_string_pretty(&multi_asset_packages::fixture_package()?)?
            );
            Ok(())
        }
        Command::PrintFactoryStateFixture => {
            let package = factory_packages::fixture_state_package()?;
            println!("{}", serde_json::to_string_pretty(&package)?);
            Ok(())
        }
        Command::PrintReducedFactoryStateFixture => {
            let package = factory_packages::fixture_reduced_state_package()?;
            println!("{}", serde_json::to_string_pretty(&package)?);
            Ok(())
        }
        Command::PrintFactoryReducedRightsFixture => {
            let package = packages::fixture_factory_reduced_rights_package()?;
            println!("{}", serde_json::to_string_pretty(&package)?);
            Ok(())
        }
        Command::PrintFactoryReducedExitFixture => {
            let package = factory_packages::fixture_reduced_exit_package()?;
            println!("{}", serde_json::to_string_pretty(&package)?);
            Ok(())
        }
        Command::PrintFactoryMerkleUpdateFixture => {
            let package = factory_packages::fixture_merkle_update_package()?;
            println!("{}", serde_json::to_string_pretty(&package)?);
            Ok(())
        }
        Command::PrintFactoryMultiRightUpdateFixture => {
            let package = factory_packages::fixture_multi_right_update_package()?;
            println!("{}", serde_json::to_string_pretty(&package)?);
            Ok(())
        }
        Command::PrintValueLimitPolicyFixture => {
            let policy = value_limit::fixture_value_limit_policy()?;
            println!("{}", serde_json::to_string_pretty(&policy)?);
            Ok(())
        }
        Command::PrintFactoryLocalExitFixture => {
            let package = packages::fixture_factory_local_exit_package()?;
            println!("{}", serde_json::to_string_pretty(&package)?);
            Ok(())
        }
        Command::PrintFactorySpliceFixture { kind } => {
            let package = factory_packages::fixture_factory_splice_package_with_kind(match kind {
                FactorySpliceFixtureKindArg::SpliceIn => {
                    factory_packages::FixtureFactorySpliceKind::CkbSpliceIn
                }
                FactorySpliceFixtureKindArg::SpliceOut => {
                    factory_packages::FixtureFactorySpliceKind::CkbSpliceOut
                }
                FactorySpliceFixtureKindArg::XudtSpliceIn => {
                    factory_packages::FixtureFactorySpliceKind::XudtSpliceIn
                }
                FactorySpliceFixtureKindArg::XudtSpliceOut => {
                    factory_packages::FixtureFactorySpliceKind::XudtSpliceOut
                }
            })?;
            println!("{}", serde_json::to_string_pretty(&package)?);
            Ok(())
        }
        Command::PrintFactoryReducedSpliceFixture { kind } => {
            let package =
                factory_packages::fixture_factory_reduced_splice_package_with_kind(match kind {
                    FactorySpliceFixtureKindArg::SpliceIn => {
                        factory_packages::FixtureFactorySpliceKind::CkbSpliceIn
                    }
                    FactorySpliceFixtureKindArg::SpliceOut => {
                        factory_packages::FixtureFactorySpliceKind::CkbSpliceOut
                    }
                    FactorySpliceFixtureKindArg::XudtSpliceIn => {
                        factory_packages::FixtureFactorySpliceKind::XudtSpliceIn
                    }
                    FactorySpliceFixtureKindArg::XudtSpliceOut => {
                        factory_packages::FixtureFactorySpliceKind::XudtSpliceOut
                    }
                })?;
            println!("{}", serde_json::to_string_pretty(&package)?);
            Ok(())
        }
        Command::PrintSpliceFixture { kind } => {
            let package = splice_packages::fixture_package_with_kind(match kind {
                SpliceFixtureKindArg::SpliceIn => splice_packages::FixtureSpliceKind::SpliceIn,
                SpliceFixtureKindArg::SpliceOut => splice_packages::FixtureSpliceKind::SpliceOut,
                SpliceFixtureKindArg::XudtSpliceIn => {
                    splice_packages::FixtureSpliceKind::XudtSpliceIn
                }
                SpliceFixtureKindArg::XudtSpliceOut => {
                    splice_packages::FixtureSpliceKind::XudtSpliceOut
                }
            })?;
            println!("{}", serde_json::to_string_pretty(&package)?);
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
        Command::ValidateFactoryPackage { path, json } => {
            let package = factory_packages::read_factory_update_package(&path)?;
            let summary = package.summary()?;
            if json {
                println!("{}", serde_json::to_string_pretty(&summary)?);
            } else {
                println!("factory package ok");
                println!("factory_id={}", summary.factory_id);
                println!("update_number={}", summary.update_number);
                println!("state_root_before={}", summary.state_root_before);
                println!("state_root_after={}", summary.state_root_after);
                println!("touched_participants={}", summary.touched_participants);
                println!(
                    "authorised_participants={}",
                    summary.authorised_participants
                );
                println!("rights_before={}", summary.rights_before);
                println!("rights_after={}", summary.rights_after);
                println!(
                    "non_interference_digest={}",
                    summary.non_interference_digest
                );
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
        Command::ValidateFactoryStatePackage { path, json } => {
            let package = factory_packages::read_factory_state_package(&path)?;
            let summary = package.summary()?;
            if json {
                println!("{}", serde_json::to_string_pretty(&summary)?);
            } else {
                println!("factory state package ok");
                println!("factory_id={}", summary.factory_id);
                println!("update_number={}", summary.update_number);
                println!("state_root_before={}", summary.state_root_before);
                println!("state_root_after={}", summary.state_root_after);
                println!(
                    "non_interference_digest={}",
                    summary.non_interference_digest
                );
                println!("signature_mode={}", summary.signature_mode);
                println!("signature_threshold={}", summary.signature_threshold);
                println!("participants={}", summary.participants);
                println!("signatures={}", summary.signatures);
                println!("factory_state_digest={}", summary.factory_state_digest);
            }
            Ok(())
        }
        Command::ValidateFactoryReducedRightsPackage { path, json } => {
            let package = packages::read_factory_reduced_rights_package(&path)?;
            let summary = package.summary()?;
            if json {
                println!("{}", serde_json::to_string_pretty(&summary)?);
            } else {
                println!("factory reduced-rights package ok");
                println!("factory_id={}", summary.factory_id);
                println!("old_update_number={}", summary.old_update_number);
                println!("new_update_number={}", summary.new_update_number);
                println!("signing_digest={}", summary.signing_digest);
                println!("old_state_root={}", summary.old_state_root);
                println!("new_state_root={}", summary.new_state_root);
                println!(
                    "old_access_manifest_root={}",
                    summary.old_access_manifest_root
                );
                println!(
                    "new_access_manifest_root={}",
                    summary.new_access_manifest_root
                );
                println!(
                    "non_interference_digest={}",
                    summary.non_interference_digest
                );
                println!("witness_len={}", summary.witness_len);
            }
            Ok(())
        }
        Command::ValidateFactoryReducedExitPackage { path, json } => {
            let package = factory_packages::read_factory_reduced_exit_package(&path)?;
            let summary = package.summary()?;
            if json {
                println!("{}", serde_json::to_string_pretty(&summary)?);
            } else {
                println!("factory reduced-exit package ok");
                println!("factory_id={}", summary.factory_id);
                println!("update_number={}", summary.update_number);
                println!("participant={}", summary.participant);
                println!(
                    "reserve_claim_subchannel={}",
                    summary.reserve_claim_subchannel
                );
                if let Some(asset_type) = &summary.reserve_claim_asset_type {
                    println!("reserve_claim_asset_type={asset_type}");
                }
                println!("release_quantity={}", summary.release_quantity);
                println!("reserve_claim_before={}", summary.reserve_claim_before);
                println!("reserve_claim_after={}", summary.reserve_claim_after);
            }
            Ok(())
        }
        Command::ValidateFactoryMerkleUpdatePackage { path, json } => {
            let package = factory_packages::read_factory_merkle_update_package(&path)?;
            let summary = package.summary()?;
            if json {
                println!("{}", serde_json::to_string_pretty(&summary)?);
            } else {
                println!("factory Merkle update package ok");
                println!("factory_id={}", summary.factory_id);
                println!("update_number={}", summary.update_number);
                println!("state_root_before={}", summary.state_root_before);
                println!("state_root_after={}", summary.state_root_after);
                println!("touched_participants={}", summary.touched_participants);
                println!(
                    "authorised_participants={}",
                    summary.authorised_participants
                );
                println!("changed_participant={}", summary.changed_participant);
                println!("changed_kind={:?}", summary.changed_kind);
                println!("quantity_before={}", summary.quantity_before);
                println!("quantity_after={}", summary.quantity_after);
                println!("proof_siblings={}", summary.proof_siblings);
                println!(
                    "non_interference_digest={}",
                    summary.non_interference_digest
                );
            }
            Ok(())
        }
        Command::ValidateFactoryMultiRightUpdatePackage { path, json } => {
            let package = factory_packages::read_factory_multi_right_update_package(&path)?;
            let summary = package.summary()?;
            if json {
                println!("{}", serde_json::to_string_pretty(&summary)?);
            } else {
                println!("factory multi-right update package ok");
                println!("factory_id={}", summary.factory_id);
                println!("update_number={}", summary.update_number);
                println!("state_root_before={}", summary.state_root_before);
                println!("state_root_after={}", summary.state_root_after);
                println!("touched_participants={}", summary.touched_participants);
                println!(
                    "authorised_participants={}",
                    summary.authorised_participants
                );
                println!("changed_participant={}", summary.changed_participant);
                println!("right_count={}", summary.right_count);
                println!("asset_groups={}", summary.asset_groups);
                println!("proof_pairs_before={}", summary.proof_pairs_before);
                println!("proof_pairs_after={}", summary.proof_pairs_after);
                println!(
                    "non_interference_digest={}",
                    summary.non_interference_digest
                );
            }
            Ok(())
        }
        Command::ValidateFactoryLocalExitPackage { path, json } => {
            let package = packages::read_factory_local_exit_package(&path)?;
            let summary = package.summary()?;
            if json {
                println!("{}", serde_json::to_string_pretty(&summary)?);
            } else {
                println!("factory local-exit package ok");
                println!("factory_id={}", summary.factory_id);
                println!("update_number={}", summary.update_number);
                println!("factory_signing_digest={}", summary.factory_signing_digest);
                println!("exit_digest={}", summary.exit_digest);
                println!("child_channel_id={}", summary.child_channel_id);
                println!("child_state_number={}", summary.child_state_number);
                println!("child_phase={}", summary.child_phase);
                println!("descriptor_version={}", summary.descriptor_version);
                println!("state_output_index={}", summary.state_output_index);
                println!("vault_output_index={}", summary.vault_output_index);
            }
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
            ckb,
            xudt,
        } => {
            let policy = value_limit::read_value_limit_policy(&policy_path)?;
            let subject = match (&package, ckb) {
                (Some(package_path), None) if xudt.is_empty() => {
                    let (schema, subject) = value_limit::extract_value_subject(package_path)?;
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
        Command::ValidateFactorySplicePackage { path, json } => {
            let package = factory_packages::read_factory_splice_package(&path)?;
            let summary = package.summary()?;
            if json {
                println!("{}", serde_json::to_string_pretty(&summary)?);
            } else {
                println!("factory splice package ok");
                println!("factory_id={}", summary.factory_id);
                println!("kind={}", summary.kind);
                println!("old_update_number={}", summary.old_update_number);
                println!("new_update_number={}", summary.new_update_number);
                println!("old_state_root={}", summary.old_state_root);
                println!("new_state_root={}", summary.new_state_root);
                println!(
                    "old_access_manifest_root={}",
                    summary.old_access_manifest_root
                );
                println!(
                    "new_access_manifest_root={}",
                    summary.new_access_manifest_root
                );
                println!("signing_digest={}", summary.signing_digest);
                println!("vault_delta_commitment={}", summary.vault_delta_commitment);
                println!(
                    "non_interference_digest={}",
                    summary.non_interference_digest
                );
                println!(
                    "reserve_claim_participant={}",
                    summary.reserve_claim_participant
                );
                println!(
                    "reserve_claim_subchannel={}",
                    summary.reserve_claim_subchannel
                );
                println!("reserve_claim_asset={}", summary.reserve_claim_asset);
                println!("reserve_claim_before={}", summary.reserve_claim_before);
                println!("reserve_claim_after={}", summary.reserve_claim_after);
                println!("vault_old_amount={}", summary.vault_old_amount);
                println!("vault_new_amount={}", summary.vault_new_amount);
                println!("external_input={}", summary.external_input);
                println!("withdrawal={}", summary.withdrawal);
                println!("signature_threshold={}", summary.signature_threshold);
                println!("signatures={}", summary.signatures);
                println!("contract_witness_len={}", summary.contract_witness_len);
                println!("contract_witness_hex={}", summary.contract_witness_hex);
            }
            Ok(())
        }
        Command::ValidateFactoryReducedSplicePackage { path, json } => {
            let package = factory_packages::read_factory_reduced_splice_package(&path)?;
            let summary = package.summary()?;
            if json {
                println!("{}", serde_json::to_string_pretty(&summary)?);
            } else {
                println!("reduced factory splice package ok");
                println!("factory_id={}", summary.factory_id);
                println!("kind={}", summary.kind);
                println!("old_update_number={}", summary.old_update_number);
                println!("new_update_number={}", summary.new_update_number);
                println!("old_state_root={}", summary.old_state_root);
                println!("new_state_root={}", summary.new_state_root);
                println!(
                    "old_access_manifest_root={}",
                    summary.old_access_manifest_root
                );
                println!(
                    "new_access_manifest_root={}",
                    summary.new_access_manifest_root
                );
                println!("signing_digest={}", summary.signing_digest);
                println!("vault_delta_commitment={}", summary.vault_delta_commitment);
                println!(
                    "non_interference_digest={}",
                    summary.non_interference_digest
                );
                println!(
                    "reserve_claim_participant={}",
                    summary.reserve_claim_participant
                );
                println!(
                    "reserve_claim_subchannel={}",
                    summary.reserve_claim_subchannel
                );
                println!("reserve_claim_asset={}", summary.reserve_claim_asset);
                println!("reserve_claim_before={}", summary.reserve_claim_before);
                println!("reserve_claim_after={}", summary.reserve_claim_after);
                println!("vault_old_amount={}", summary.vault_old_amount);
                println!("vault_new_amount={}", summary.vault_new_amount);
                println!("external_input={}", summary.external_input);
                println!("withdrawal={}", summary.withdrawal);
                println!("participant_keys={}", summary.participant_keys);
                println!("signature_threshold={}", summary.signature_threshold);
                println!("signatures={}", summary.signatures);
                println!("proof_siblings={}", summary.proof_siblings);
                println!("contract_witness_len={}", summary.contract_witness_len);
                println!("contract_witness_hex={}", summary.contract_witness_hex);
            }
            Ok(())
        }
        Command::ValidateSplicePackage { path, json } => {
            let package = splice_packages::read_splice_package(&path)?;
            let summary = package.summary()?;
            if json {
                println!("{}", serde_json::to_string_pretty(&summary)?);
            } else {
                println!("splice package ok");
                println!("channel_id={}", summary.channel_id);
                println!("kind={}", summary.kind);
                println!("base_state_number={}", summary.base_state_number);
                println!("old_funding_epoch={}", summary.old_funding_epoch);
                println!("new_funding_epoch={}", summary.new_funding_epoch);
                println!("splice_number={}", summary.splice_number);
                println!("signing_digest={}", summary.signing_digest);
                println!("asset_delta_commitment={}", summary.asset_delta_commitment);
                println!("deltas={}", summary.deltas);
                println!("withdrawals={}", summary.withdrawals);
                println!(
                    "withdrawal_payout_policy={}",
                    summary.withdrawal_payout_policy
                );
                if let Some(pubkey) = &summary.withdrawal_participant_pubkey_sec1 {
                    println!("withdrawal_participant_pubkey_sec1={pubkey}");
                }
                println!(
                    "remaining_settlement_assets={}",
                    summary.remaining_settlement_assets
                );
                println!("contract_witness_len={}", summary.contract_witness_len);
                println!("contract_witness_hex={}", summary.contract_witness_hex);
                println!(
                    "current_state_header_hex={}",
                    summary.current_state_header_hex
                );
                println!("next_state_header_hex={}", summary.next_state_header_hex);
            }
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
                println!(
                    "factory_reduced_rights_updates={}",
                    report.factory_reduced_rights_updates
                );
                println!("factory_merkle_updates={}", report.factory_merkle_updates);
                println!("factory_proof_profiles={}", report.factory_proof_profiles);
                println!("factory_reduced_exits={}", report.factory_reduced_exits);
                println!("factory_local_exits={}", report.factory_local_exits);
                println!("factory_splices={}", report.factory_splices);
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
                            "budget_proof={} {} {} siblings={} witness_len={} cycles={} bytes={}",
                            profile.check,
                            profile.transaction_path,
                            profile.proof_kind,
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
fn print_factory_xudt_splice_smoke_report(report: &devnet::FactoryXudtSpliceSmokeReport) {
    println!("kind={}", report.kind);
    println!("factory_id={}", report.open.factory_id);
    println!(
        "xudt_type_hash={}",
        report.exit.xudt_type_hash.as_deref().unwrap_or_default()
    );
    println!("open_tx_hash={}", report.open.tx_hash);
    if let Some(external_xudt) = &report.external_xudt {
        println!("external_xudt_tx_hash={}", external_xudt.tx_hash);
        println!(
            "external_xudt_out_point={}:{}",
            external_xudt.cell_out_point.tx_hash, external_xudt.cell_out_point.index
        );
    }
    println!("package_path={}", report.package.path);
    println!("apply_tx_hash={}", report.apply.tx_hash);
    println!("apply_status={}", report.apply.status);
    println!(
        "factory_out_point={}:{}",
        report.apply.factory_out_point.tx_hash, report.apply.factory_out_point.index
    );
    println!(
        "factory_vault_out_point={}:{}",
        report.apply.factory_vault_out_point.tx_hash, report.apply.factory_vault_out_point.index
    );
    if let Some(out_point) = &report.apply.withdrawal_out_point {
        println!(
            "withdrawal_out_point={}:{}",
            out_point.tx_hash, out_point.index
        );
    }
    println!("contract_witness_len={}", report.apply.contract_witness_len);
    println!("exit_tx_hash={}", report.exit.tx_hash);
    println!("exit_status={}", report.exit.status);
    println!(
        "child_state_out_point={}:{}",
        report.exit.state_out_point.tx_hash, report.exit.state_out_point.index
    );
    println!(
        "child_vault_out_point={}:{}",
        report.exit.vault_out_point.tx_hash, report.exit.vault_out_point.index
    );
    println!(
        "child_xudt_amount={}",
        report.exit.child_xudt_amount.unwrap_or_default()
    );
    println!(
        "alice_xudt_amount={}",
        report.exit.alice_xudt_amount.unwrap_or_default()
    );
    println!(
        "bob_xudt_amount={}",
        report.exit.bob_xudt_amount.unwrap_or_default()
    );
    println!(
        "post_exit_factory_vault_out_point={}:{}",
        report.exit.factory_vault_out_point.tx_hash, report.exit.factory_vault_out_point.index
    );
    if let Some(amount) = report.exit.factory_vault_change_xudt_amount {
        println!("factory_vault_change_xudt_amount={amount}");
    }
    print_metrics(&report.open.metrics);
    if let Some(external_xudt) = &report.external_xudt {
        print_metrics(&external_xudt.metrics);
    }
    print_metrics(&report.apply.metrics);
    print_metrics(&report.exit.metrics);
    for hash in &report.apply.mined_blocks {
        println!("mined_block={hash}");
    }
    for hash in &report.exit.mined_blocks {
        println!("mined_block={hash}");
    }
}

#[cfg(feature = "devnet")]
fn print_factory_reduced_xudt_splice_smoke_report(
    report: &devnet::FactoryReducedXudtSpliceSmokeReport,
) {
    println!("kind={}", report.kind);
    println!("factory_id={}", report.open.factory_id);
    println!(
        "xudt_type_hash={}",
        report.exit.xudt_type_hash.as_deref().unwrap_or_default()
    );
    println!("open_tx_hash={}", report.open.tx_hash);
    if let Some(external_xudt) = &report.external_xudt {
        println!("external_xudt_tx_hash={}", external_xudt.tx_hash);
        println!(
            "external_xudt_out_point={}:{}",
            external_xudt.cell_out_point.tx_hash, external_xudt.cell_out_point.index
        );
    }
    println!("package_path={}", report.package.path);
    println!("proof_siblings={}", report.package.proof_siblings);
    println!("apply_tx_hash={}", report.apply.tx_hash);
    println!("apply_status={}", report.apply.status);
    println!(
        "factory_out_point={}:{}",
        report.apply.factory_out_point.tx_hash, report.apply.factory_out_point.index
    );
    println!(
        "factory_vault_out_point={}:{}",
        report.apply.factory_vault_out_point.tx_hash, report.apply.factory_vault_out_point.index
    );
    if let Some(out_point) = &report.apply.withdrawal_out_point {
        println!(
            "withdrawal_out_point={}:{}",
            out_point.tx_hash, out_point.index
        );
    }
    println!("contract_witness_len={}", report.apply.contract_witness_len);
    println!("exit_tx_hash={}", report.exit.tx_hash);
    println!("exit_status={}", report.exit.status);
    println!(
        "child_state_out_point={}:{}",
        report.exit.state_out_point.tx_hash, report.exit.state_out_point.index
    );
    println!(
        "child_vault_out_point={}:{}",
        report.exit.vault_out_point.tx_hash, report.exit.vault_out_point.index
    );
    println!(
        "child_xudt_amount={}",
        report.exit.child_xudt_amount.unwrap_or_default()
    );
    println!(
        "alice_xudt_amount={}",
        report.exit.alice_xudt_amount.unwrap_or_default()
    );
    println!(
        "bob_xudt_amount={}",
        report.exit.bob_xudt_amount.unwrap_or_default()
    );
    println!(
        "post_exit_factory_vault_out_point={}:{}",
        report.exit.factory_vault_out_point.tx_hash, report.exit.factory_vault_out_point.index
    );
    if let Some(amount) = report.exit.factory_vault_change_xudt_amount {
        println!("factory_vault_change_xudt_amount={amount}");
    }
    print_metrics(&report.open.metrics);
    if let Some(external_xudt) = &report.external_xudt {
        print_metrics(&external_xudt.metrics);
    }
    print_metrics(&report.apply.metrics);
    print_metrics(&report.exit.metrics);
    for hash in &report.apply.mined_blocks {
        println!("mined_block={hash}");
    }
    for hash in &report.exit.mined_blocks {
        println!("mined_block={hash}");
    }
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
    let fixture = Fixture::new()?;
    validate_state_transition(&fixture.old_state, &fixture.new_state, &fixture.transition)?;
    validate_partition_conservation(
        &fixture.transition.partition,
        &fixture.transition.asset_registry,
    )?;
    validate_sponsor_policy(&fixture.sponsor_policy, &fixture.sponsor_spend)?;
    validate_vault_spend(&fixture.vault_spend)?;
    println!("fixture ok");
    println!(
        "state_digest={}",
        hex::encode(fixture.new_state.header.signing_digest())
    );
    Ok(())
}

fn print_fixture() -> Result<()> {
    let fixture = Fixture::new()?;
    let value = serde_json::json!({
        "old_state": fixture.old_state,
        "new_state": fixture.new_state,
        "new_state_signing_digest": hex::encode(fixture.new_state.header.signing_digest()),
        "sponsor_policy": fixture.sponsor_policy,
        "sponsor_spend": fixture.sponsor_spend,
    });
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

struct Fixture {
    old_state: StateCell,
    new_state: StateCell,
    transition: StateTransitionContext,
    sponsor_policy: SponsorPolicy,
    sponsor_spend: SponsorSpend,
    vault_spend: VaultSpend,
}

impl Fixture {
    fn new() -> Result<Self> {
        let registry = AssetRegistry {
            xudt_types: BTreeSet::from([bytes32(42)]),
        };
        let partition = PartitionedTransaction {
            inputs: vec![
                ClassifiedCell::channel_reserve(1_000, 700),
                ClassifiedCell::business_ckb(1_500, 700, 800),
                ClassifiedCell::xudt(bytes32(42), 1_000, 700, 10),
                ClassifiedCell::state_carrier(10_000, 1_000),
                ClassifiedCell::sponsor(500, 100),
            ],
            outputs: vec![
                ClassifiedCell::channel_reserve(1_000, 700),
                ClassifiedCell::business_ckb(1_500, 700, 800),
                ClassifiedCell::xudt(bytes32(42), 1_000, 700, 10),
                ClassifiedCell::state_carrier(10_000, 1_000),
                ClassifiedCell::sponsor(400, 100),
            ],
            tx_fee: 100,
            authorised_reserve_refund: 0,
        };
        let mut old_state = StateCell {
            header: header(1, Phase::Active),
            capacity: 10_000,
            occupied_capacity: 1_000,
        };
        let mut new_state = StateCell {
            header: header(2, Phase::Settling),
            capacity: 10_000,
            occupied_capacity: 1_000,
        };
        let authorization = authorization_for(&mut new_state.header)?;
        old_state.header.participants_commitment = new_state.header.participants_commitment;
        let transition = StateTransitionContext {
            referenced_funding_anchor: bytes32(3),
            authorization,
            asset_registry: registry.clone(),
            partition: partition.clone(),
        };
        let sponsor_policy = SponsorPolicy {
            channel_id: bytes32(2),
            min_state_number: 1,
            max_state_number: 10,
            max_fee_per_tx: 200,
            max_total_fee: 1_000,
            already_spent: 100,
            publication_state_type_hash: bytes32(10),
            change_lock: bytes32(11),
        };
        let sponsor_spend = SponsorSpend {
            channel_id: bytes32(2),
            state_number: 2,
            fee: 100,
            publication_state_type_hash: bytes32(10),
            change_lock: bytes32(11),
            operation: ChannelOperation::Publish,
        };
        let vault_spend = VaultSpend {
            operation: ChannelOperation::Finalise,
            state_cell: new_state.clone(),
            signatures_or_phase_authorised: true,
            since_satisfied: true,
            expected_funding_anchor: bytes32(3),
            descriptor_outputs_match: true,
            asset_registry: registry,
            partition,
        };
        Ok(Self {
            old_state,
            new_state,
            transition,
            sponsor_policy,
            sponsor_spend,
            vault_spend,
        })
    }
}

fn signing_key(byte: u8) -> Result<SigningKey> {
    SigningKey::from_slice(&[byte; 32])
        .map_err(|err| anyhow::anyhow!("invalid built-in fixture signing key: {err:?}"))
}

fn pubkey(key: &SigningKey) -> Vec<u8> {
    key.verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .to_vec()
}

fn signature(key: &SigningKey, digest: &[u8; 32]) -> Result<Vec<u8>> {
    let sig: Signature = key
        .sign_prehash(digest)
        .map_err(|err| anyhow::anyhow!("failed to sign built-in fixture: {err:?}"))?;
    let signature_bytes = sig.to_bytes();
    let signature_slice: &[u8] = signature_bytes.as_ref();
    Ok(signature_slice.to_vec())
}

fn authorization_for(header: &mut StateHeader) -> Result<StateAuthorization> {
    let key0 = signing_key(1)?;
    let key1 = signing_key(2)?;
    let mut entries = [(pubkey(&key0), key0), (pubkey(&key1), key1)];
    entries.sort_by(|left, right| left.0.cmp(&right.0));

    let pubkeys = [entries[0].0.as_slice(), entries[1].0.as_slice()];
    header.participants_commitment = participants_commitment(2, &pubkeys);
    let digest = header.signing_digest();
    Ok(StateAuthorization {
        threshold: 2,
        signatures: entries
            .iter()
            .map(|(pubkey, key)| {
                Ok(ParticipantSignature {
                    pubkey_sec1: pubkey.clone(),
                    signature: signature(key, &digest)?,
                })
            })
            .collect::<Result<Vec<_>>>()?,
    })
}

fn header(n: u64, phase: Phase) -> StateHeader {
    StateHeader {
        protocol_version: 1,
        chain_id: bytes32(1),
        signature_scheme_id: 1,
        channel_id: bytes32(2),
        funding_epoch: 0,
        funding_anchor: bytes32(3),
        vault_set_commitment: bytes32(33),
        state_number: n,
        mode: Mode::BilateralPlain,
        phase,
        participants_commitment: bytes32(4),
        asset_registry_commitment: asset_registry_commitment(&AssetRegistry {
            xudt_types: BTreeSet::from([bytes32(42)]),
        }),
        settlement_descriptor_commitment: bytes32(6),
        descriptor_version: 1,
        vault_materialisation_root: bytes32(7),
        vault_outpoint_commitment: bytes32(34),
        challenge_policy_commitment: bytes32(8),
        state_layout_version: 1,
    }
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
                    "watch-latest-package",
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
