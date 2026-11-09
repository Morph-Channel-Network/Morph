mod desktop_bundle;
mod fiber_scenarios;
mod gateway_fiber;
mod hygiene;
use anyhow::Result;
use clap::{Parser, Subcommand};
#[derive(Parser)]
#[command(about = "Morph Rust acceptance tools; never starts a Node/JS runtime")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Stage a local native binary, source archives and complete dependency notices; never publishes.
    DesktopBundle {
        #[arg(long)]
        binary: std::path::PathBuf,
        #[arg(long)]
        output_dir: std::path::PathBuf,
    },
    /// Reject retired JS/TS source, dependency manifests and framework build inputs.
    VerifyRustClients {
        #[arg(long, default_value = ".")]
        root: std::path::PathBuf,
    },
    /// Check all native Fiber result rows against the exact typed request/assertion corpus.
    VerifyFiberEvidence {
        scenario: std::path::PathBuf,
        evidence: std::path::PathBuf,
    },
    #[cfg(target_os = "linux")]
    /// Restart an owned devnet node after signing external funding, then submit and close.
    FiberRestart {
        #[arg(long)]
        fiber_dir: std::path::PathBuf,
        #[arg(long)]
        stack_pid: u32,
        #[arg(long)]
        output: std::path::PathBuf,
        #[arg(long)]
        log: std::path::PathBuf,
        #[arg(long, env="MORPH_FIBER_EXTERNAL_PRIVATE_KEY_FILE", hide_env_values=true, value_parser=morph_key_input::secp256k1_file)]
        external_private_key_file: morph_key_input::SecretString,
    },
    /// Run a data-only native Fiber scenario; every RPC/semantic assertion is checked in Rust.
    FiberScenario {
        scenario: std::path::PathBuf,
        #[arg(long)]
        output: std::path::PathBuf,
        #[arg(long, env="MORPH_FIBER_EXTERNAL_PRIVATE_KEY_FILE", hide_env_values=true, value_parser=morph_key_input::secp256k1_file)]
        external_private_key_file: Option<morph_key_input::SecretString>,
    },
    /// Verify terminal payment, credential and encrypted data exchange over three real Fiber nodes.
    GatewayFiber {
        #[arg(long,env="MORPH_PAYMENT_GATEWAY_PAYER_PRIVATE_KEY_FILE",hide_env_values=true,value_parser=morph_key_input::secp256k1_file)]
        payer_private_key_file: morph_key_input::SecretString,
    },
    /// Stateless review of one public protocol document; no chain/signing authority.
    Inspect {
        document: std::path::PathBuf,
        #[arg(long)]
        base: Option<std::path::PathBuf>,
        #[arg(long)]
        receipt: Option<std::path::PathBuf>,
    },
}
#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().command {
        Command::DesktopBundle { binary, output_dir } => {
            desktop_bundle::stage(&binary, &output_dir)
        }
        Command::VerifyRustClients { root } => hygiene::verify(&root),
        Command::VerifyFiberEvidence { scenario, evidence } => {
            fiber_scenarios::verify(&scenario, &evidence)
        }
        #[cfg(target_os = "linux")]
        Command::FiberRestart {
            fiber_dir,
            stack_pid,
            output,
            log,
            external_private_key_file,
        } => {
            fiber_scenarios::restart(
                &fiber_dir,
                stack_pid,
                external_private_key_file,
                &output,
                &log,
            )
            .await
        }
        Command::FiberScenario {
            scenario,
            output,
            external_private_key_file,
        } => fiber_scenarios::run(&scenario, external_private_key_file, &output).await,
        Command::GatewayFiber {
            payer_private_key_file,
        } => gateway_fiber::run(&payer_private_key_file).await,
        Command::Inspect {
            document,
            base,
            receipt,
        } => {
            fn read(path: &std::path::Path) -> Result<serde_json::Value> {
                morph_sdk::packages::multi_asset_packages::read_bounded_json(path, 4 * 1024 * 1024)
            }
            let document = read(&document)?;
            let base = base.as_deref().map(read).transpose()?;
            let result = if let Some(receipt) = receipt {
                morph_sdk::inspection::inspect_signature(
                    &document,
                    base.as_ref(),
                    &read(&receipt)?,
                )?
            } else {
                morph_sdk::inspection::inspect(&document, base.as_ref())?
            };
            println!("{}", serde_json::to_string_pretty(&result)?);
            Ok(())
        }
    }
}
