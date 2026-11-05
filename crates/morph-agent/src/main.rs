#![forbid(unsafe_code)]

use std::{
    collections::BTreeSet,
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, Result, ensure};
use clap::{Parser, Subcommand};
use k256::ecdsa::{SigningKey, VerifyingKey};
use morph_agent::{
    AgentConfig, AgentService, AssetKind, CredentialService, DurableStore, FiberRpcClient,
    RgbppAsset, serve,
};
use morph_core::blake2b256;

const MAX_ASSET_CATALOG_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Parser)]
#[command(name = "morph-agent", about = "Morph-owned RGB++ Agent/Fiber sidecar")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
#[allow(clippy::large_enum_variant)] // Parsed once at process start; boxing every CLI field adds noise.
enum Command {
    /// Generate a Biscuit root key; retain its private output in a protected key file.
    GenerateKey,
    /// Generate a receipt-signing key; retain its private output in a protected key file.
    GenerateReceiptKey,
    /// Derive a Morph account ID from a compressed secp256k1 public key.
    AccountId {
        #[arg(long)]
        pubkey: String,
    },
    /// Run the x402 gateway/facilitator against an unmodified Fiber node.
    Serve {
        #[arg(long, default_value = "127.0.0.1:4620")]
        listen: SocketAddr,
        #[arg(long, default_value = "http://127.0.0.1:8227")]
        fiber_rpc: String,
        #[arg(long, env = "MORPH_AGENT_FIBER_BEARER_TOKEN", hide_env_values = true)]
        fiber_bearer_token: Option<String>,
        #[arg(long, default_value = "./morph-agent.db")]
        store: PathBuf,
        /// Bearer required by durable creation and operator routes. Mandatory for non-loopback listeners.
        #[arg(long, env = "MORPH_AGENT_API_BEARER_TOKEN", hide_env_values = true)]
        api_bearer_token: Option<String>,
        #[arg(long = "biscuit-private-key-file", env = "MORPH_AGENT_BISCUIT_PRIVATE_KEY_FILE", hide_env_values = true, value_name = "PATH", value_parser = morph_key_input::biscuit_file)]
        biscuit_private_key: morph_key_input::SecretString,
        /// secp256k1 key used to sign canonical terminal settlement receipts.
        #[arg(long = "receipt-private-key-file", env = "MORPH_AGENT_RECEIPT_PRIVATE_KEY_FILE", hide_env_values = true, value_name = "PATH", value_parser = morph_key_input::secp256k1_file)]
        receipt_private_key: morph_key_input::SecretString,
        #[arg(long)]
        payee: String,
        /// Morph identity allowed to sign outgoing `/v1/pay` requests.
        #[arg(long)]
        outgoing_payer: Option<String>,
        /// Maximum routing fee for one outgoing payment, in asset base units.
        /// Required when --outgoing-payer is set.
        #[arg(long)]
        outgoing_max_fee_amount: Option<u128>,
        /// Maximum outgoing Fiber payment timeout accepted from callers.
        #[arg(long, default_value_t = 60)]
        outgoing_payment_timeout_seconds: u64,
        #[arg(long, default_value = "Fibd")]
        currency: String,
        #[arg(long)]
        ckb_network_id: Option<String>,
        /// JSON array of configured CKB/RGB++ assets. Defaults to CKB only.
        #[arg(long)]
        asset_catalog: Option<PathBuf>,
        /// Operator-verified RGB++ proof commitment; repeat for multiple proofs.
        #[arg(long = "verified-rgbpp-proof-commitment")]
        verified_rgbpp_proof_commitments: Vec<String>,
        #[arg(long, default_value_t = 3600)]
        credential_ttl_seconds: u64,
        /// Fixed upstream used by the paid `/gateway/*` reverse proxy.
        #[arg(long)]
        upstream_base_url: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().command {
        Command::GenerateKey => {
            let service = CredentialService::generate();
            println!("private_key={}", service.private_key());
            println!("public_key={}", service.public_key());
        }
        Command::GenerateReceiptKey => {
            let key = loop {
                let candidate = morph_agent::random_byte32();
                if let Ok(key) = SigningKey::from_slice(&candidate) {
                    break key;
                }
            };
            println!("private_key=0x{}", hex::encode(key.to_bytes()));
            println!(
                "public_key=0x{}",
                hex::encode(key.verifying_key().to_sec1_point(true).as_bytes())
            );
        }
        Command::AccountId { pubkey } => {
            println!("account_id={}", account_id_from_public_key(&pubkey)?);
        }
        Command::Serve {
            listen,
            fiber_rpc,
            fiber_bearer_token,
            store,
            api_bearer_token,
            biscuit_private_key,
            receipt_private_key,
            payee,
            outgoing_payer,
            outgoing_max_fee_amount,
            outgoing_payment_timeout_seconds,
            currency,
            ckb_network_id,
            asset_catalog,
            verified_rgbpp_proof_commitments,
            credential_ttl_seconds,
            upstream_base_url,
        } => {
            ensure!(
                listen.ip().is_loopback() || api_bearer_token.is_some(),
                "--api-bearer-token is required for a non-loopback listener"
            );
            let credentials = CredentialService::from_private_key(&biscuit_private_key)
                .context("invalid Biscuit private-key file")?;
            let receipt_signing_key = parse_receipt_signing_key(&receipt_private_key)?;
            drop(biscuit_private_key);
            drop(receipt_private_key);
            let durable_store = Arc::new(
                DurableStore::open(store, credentials.store_key())
                    .context("failed to open encrypted Morph Agent store")?,
            );
            let assets = match asset_catalog {
                Some(path) => read_asset_catalog(&path)?,
                None => vec![RgbppAsset {
                    kind: AssetKind::Ckb,
                    ckb_network_id: ckb_network_id
                        .context("--ckb-network-id is required when --asset-catalog is absent")?,
                    type_script_hash: None,
                    type_script: None,
                    bitcoin_network: None,
                    binding_code_hash: None,
                    symbol: "CKB".to_string(),
                    decimals: 8,
                }],
            };
            let fiber = FiberRpcClient::new(&fiber_rpc, fiber_bearer_token)
                .context("invalid Fiber RPC configuration")?;
            let service = Arc::new(
                AgentService::new(
                    AgentConfig {
                        payee,
                        outgoing_payer,
                        outgoing_max_fee_amount,
                        outgoing_payment_timeout_seconds,
                        currency,
                        supported_assets: assets,
                        verified_rgbpp_proof_commitments: verified_rgbpp_proof_commitments
                            .into_iter()
                            .collect::<BTreeSet<_>>(),
                        default_credential_ttl_seconds: credential_ttl_seconds,
                        upstream_base_url,
                        api_bearer_token,
                    },
                    fiber,
                    durable_store,
                    credentials,
                    receipt_signing_key,
                )
                .context("invalid Morph Agent configuration")?,
            );
            let listener = tokio::net::TcpListener::bind(listen)
                .await
                .with_context(|| format!("failed to listen on {listen}"))?;
            serve(service, listener).await?;
        }
    }
    Ok(())
}

fn parse_receipt_signing_key(value: &str) -> Result<SigningKey> {
    let raw = zeroize::Zeroizing::new(
        hex::decode(value.strip_prefix("0x").unwrap_or(value))
            .context("receipt private-key file must be hexadecimal")?,
    );
    ensure!(raw.len() == 32, "receipt private-key file must be 32 bytes");
    SigningKey::from_slice(&raw).context("invalid receipt private-key file")
}

fn account_id_from_public_key(value: &str) -> Result<String> {
    let raw = hex::decode(value.strip_prefix("0x").unwrap_or(value))
        .context("compressed public key must be hexadecimal")?;
    ensure!(raw.len() == 33, "compressed public key must be 33 bytes");
    let key = VerifyingKey::from_sec1_bytes(&raw).context("invalid secp256k1 public key")?;
    ensure!(
        key.to_sec1_point(true).as_bytes() == raw,
        "public key must use canonical compressed SEC1 encoding"
    );
    Ok(format!("0x{}", hex::encode(blake2b256(&raw))))
}

fn read_asset_catalog(path: &Path) -> Result<Vec<RgbppAsset>> {
    let metadata = fs::metadata(path)
        .with_context(|| format!("failed to stat asset catalog {}", path.display()))?;
    ensure!(
        metadata.len() <= MAX_ASSET_CATALOG_BYTES,
        "asset catalog exceeds 1 MiB"
    );
    let bytes = fs::read(path)
        .with_context(|| format!("failed to read asset catalog {}", path.display()))?;
    let assets: Vec<RgbppAsset> =
        serde_json::from_slice(&bytes).context("asset catalog must be a JSON asset array")?;
    ensure!(!assets.is_empty(), "asset catalog must not be empty");
    Ok(assets)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_private_keys_only_accept_protected_file_paths() {
        use clap::CommandFactory;
        let command = Cli::command();
        let serve = command
            .get_subcommands()
            .find(|s| s.get_name() == "serve")
            .unwrap();
        let mut count = 0;
        for arg in serve.get_arguments() {
            if let Some(name) = arg.get_long()
                && name.contains("private-key")
            {
                assert!(name.ends_with("-file"));
                assert_eq!(
                    arg.get_value_parser().type_id(),
                    std::any::TypeId::of::<morph_key_input::SecretString>()
                );
                assert!(arg.get_all_aliases().unwrap_or_default().is_empty());
                count += 1;
            }
            if let Some(env) = arg.get_env() {
                assert!(!env.to_string_lossy().ends_with("PRIVATE_KEY"));
            }
        }
        assert_eq!(count, 2);
        for flag in ["--biscuit-private-key", "--receipt-private-key"] {
            for args in [
                vec![
                    "morph-agent".to_owned(),
                    "serve".into(),
                    flag.into(),
                    "SECRET_MUST_NOT_APPEAR".into(),
                ],
                vec![
                    "morph-agent".to_owned(),
                    "serve".into(),
                    format!("{flag}=SECRET_MUST_NOT_APPEAR"),
                ],
            ] {
                let error = Cli::try_parse_from(args).unwrap_err().to_string();
                assert!(!error.contains("SECRET_MUST_NOT_APPEAR"));
            }
        }
    }

    #[test]
    fn account_id_matches_the_typescript_sdk_vector() {
        assert_eq!(
            account_id_from_public_key(
                "0x02989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f"
            )
            .unwrap(),
            "0xc3884ddf5c0e66af9bd067147e948641917a9fd9df768dc299172e35a613a6e8"
        );
    }

    #[test]
    fn account_id_rejects_uncompressed_keys() {
        let key = SigningKey::from_slice(&[7; 32]).unwrap();
        let uncompressed = hex::encode(key.verifying_key().to_sec1_point(false).as_bytes());
        assert!(account_id_from_public_key(&uncompressed).is_err());
    }
}
