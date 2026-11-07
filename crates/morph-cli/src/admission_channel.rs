//! Exact bilateral experiment admission. Recovery exports and publication never
//! depend on this operator policy or its mutable files.
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use ckb_types::{core::Capacity, packed, prelude::*};
use morph_core::{
    Bytes32, MultiAssetRecoveryPackage, MultiAssetSettlementCapability, VaultAsset, blake2b256,
};
use serde::{Deserialize, Serialize};

use crate::admission::AdmissionConfig;
use crate::multi_asset_packages::read_bounded_json;
use crate::preproduction::PreproductionEnvelope;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Binding {
    config: PathBuf,
    config_hash: Bytes32,
    contracts: PathBuf,
}

fn config(path: &Path, contracts: &Path) -> Result<(AdmissionConfig, PreproductionEnvelope)> {
    let config = crate::admission::read_verified_config(path, contracts)?;
    let envelope = read_bounded_json(&config.envelope, 64 * 1024)?;
    Ok((config, envelope))
}

pub(crate) fn capacity(recovery: &MultiAssetRecoveryPackage) -> Result<u64> {
    recovery
        .manifest
        .vaults
        .iter()
        .try_fold(recovery.state_carrier_capacity, |sum, vault| {
            sum.checked_add(vault.value.capacity()?)
                .context("bilateral custody capacity overflow")
        })
}

fn validate(
    path: &Path,
    contracts: &Path,
    recovery: &MultiAssetRecoveryPackage,
    current_block: Option<u64>,
) -> Result<PreproductionEnvelope> {
    recovery.validate_contents()?;
    let (config, envelope) = config(path, contracts)?;
    ensure!(
        capacity(recovery)? <= envelope.channel.max_capacity_shannons,
        "bilateral custody including the State carrier exceeds experiment capacity"
    );
    ensure!(
        recovery.manifest.vaults.len() <= envelope.channel.max_vaults_per_state as usize,
        "bilateral Vault count exceeds experiment admission"
    );
    for (raw, name) in [
        (&recovery.scripts.state_type, "morph-state-type"),
        (&recovery.scripts.state_lock, "morph-state-lock"),
        (&recovery.scripts.vault_lock, "morph-vault-lock"),
    ] {
        let script = packed::Script::from_slice(raw)?;
        ensure!(
            script.hash_type().as_slice() == [2]
                && script.code_hash().as_slice()
                    == blake2b256(&std::fs::read(contracts.join(name))?),
            "bilateral authority must use the exact reviewed data1 ELF {name}"
        );
    }
    let issuer = blake2b256(&std::fs::read(contracts.join("morph-devnet-xudt"))?);
    let mut token_count = 0;
    for vault in &recovery.manifest.vaults {
        if let VaultAsset::Xudt(hash) = vault.asset {
            token_count += 1;
            ensure!(
                vault.value.amount <= envelope.xudt.max_units_per_type_per_channel,
                "bilateral token quantity exceeds experiment admission"
            );
            ensure!(
                config
                    .admitted_asset_types
                    .contains(&crate::multi_asset_packages::canonical_hex(&hash)),
                "bilateral token Type is not explicitly admitted, including zero quantities"
            );
            let entry = recovery
                .scripts
                .type_scripts
                .iter()
                .find(|entry| entry.type_hash == hash)
                .context("missing admitted token Type Script")?;
            let script = packed::Script::from_slice(&entry.script)?;
            ensure!(
                script.hash_type().as_slice() == [2] && script.code_hash().as_slice() == issuer,
                "bilateral token must use the exact reviewed devnet-only issuer"
            );
        }
    }
    ensure!(
        token_count <= envelope.xudt.max_asset_types_per_channel as usize,
        "bilateral asset count exceeds experiment admission"
    );
    validate_conditions(
        &recovery.settlement,
        &envelope,
        current_block,
        blake2b256(&std::fs::read(contracts.join("morph-batch-lock"))?),
    )?;
    Ok(envelope)
}

fn validate_conditions(
    settlement: &morph_core::MultiAssetSettlement,
    envelope: &PreproductionEnvelope,
    current_block: Option<u64>,
    expected_batch: Bytes32,
) -> Result<()> {
    if let MultiAssetSettlementCapability::CkbConditional {
        batch_code_hash,
        batch_hash_type,
        batch,
    } = &settlement.capability
    {
        batch.validate()?;
        ensure!(
            envelope.conditional_batch.enabled
                && envelope.conditional_batch.ckb_only
                && batch.transfers.len() <= envelope.conditional_batch.max_transfers as usize,
            "conditional capability exceeds experiment admission"
        );
        ensure!(
            *batch_hash_type == 2 && *batch_code_hash == expected_batch,
            "conditional capability must use the exact reviewed Batch lock"
        );
        if let Some(block) = current_block {
            let maximum = block
                .checked_add(envelope.conditional_batch.max_refund_block_delta)
                .context("conditional horizon overflow")?;
            ensure!(
                batch
                    .transfers
                    .iter()
                    .all(|transfer| transfer.refund_after_block > block
                        && transfer.refund_after_block <= maximum),
                "conditional refund horizon exceeds experiment admission"
            );
        }
    }
    Ok(())
}

/// Public policy for fixed-custody updates, shared by direct and Factory-origin
/// parties. It needs no parent's private ledger or admission configuration.
pub(crate) fn validate_conditional_horizon(
    settlement: &morph_core::MultiAssetSettlement,
    current_block: u64,
    contracts: &Path,
) -> Result<()> {
    if matches!(
        settlement.capability,
        MultiAssetSettlementCapability::Ordinary
    ) {
        return Ok(());
    }
    let envelope: PreproductionEnvelope = serde_json::from_str(include_str!(
        "../../../release/factory-preproduction/envelope.json"
    ))?;
    envelope.validate()?;
    let manifest: crate::release::ContractReleaseManifest = serde_json::from_str(include_str!(
        "../../../release/factory-preproduction/contracts.json"
    ))?;
    let artifact = manifest
        .scripts
        .iter()
        .find(|artifact| artifact.name == "morph-batch-lock")
        .context("public conditional policy has no Batch artifact")?;
    let expected = crate::canonical_fields::hash(&artifact.ckb_data_hash)?;
    ensure!(
        blake2b256(&std::fs::read(contracts.join("morph-batch-lock"))?) == expected,
        "public conditional policy Batch ELF changed"
    );
    validate_conditions(settlement, &envelope, Some(current_block), expected)
}

pub(crate) fn validate_recovery_shape(
    path: &Path,
    contracts: &Path,
    recovery: &MultiAssetRecoveryPackage,
) -> Result<()> {
    validate(path, contracts, recovery, None)?;
    Ok(())
}

#[cfg(feature = "devnet")]
pub(crate) fn validate_recovery_shape_at(
    path: &Path,
    contracts: &Path,
    recovery: &MultiAssetRecoveryPackage,
    current_block: u64,
) -> Result<()> {
    validate(path, contracts, recovery, Some(current_block))?;
    Ok(())
}

pub(crate) fn validate_outputs(transaction: &packed::Transaction) -> Result<()> {
    for (index, output) in transaction.raw().outputs().into_iter().enumerate() {
        let data = transaction
            .raw()
            .outputs_data()
            .get(index)
            .context("missing admitted output data")?
            .raw_data();
        ensure!(
            u64::from(output.capacity())
                >= output
                    .occupied_capacity(Capacity::bytes(data.len())?)?
                    .as_u64(),
            "admitted output is below occupied capacity"
        );
    }
    Ok(())
}

#[cfg(any(feature = "devnet", test))]
fn validate_fee(envelope: &PreproductionEnvelope, fee: u64) -> Result<()> {
    ensure!(
        fee > 0 && fee <= envelope.sponsor.max_fee_per_transaction_shannons,
        "actual bilateral transaction fee exceeds experiment admission"
    );
    Ok(())
}

#[cfg(feature = "devnet")]
pub(crate) fn reserve(
    rpc: &crate::rpc::CkbRpcClient,
    path: &Path,
    contracts: &Path,
    recovery: &MultiAssetRecoveryPackage,
    transaction: &packed::Transaction,
    fee: u64,
) -> Result<()> {
    let envelope = validate(
        path,
        contracts,
        recovery,
        Some(rpc.tip_header()?.number_value()?),
    )?;
    validate_fee(&envelope, fee)?;
    validate_outputs(transaction)?;
    crate::admission::reserve_bilateral(
        rpc,
        path,
        contracts,
        recovery.state.header.chain_id,
        recovery.state.header.channel_id,
        transaction.calc_tx_hash().unpack(),
        capacity(recovery)?,
    )
}

fn config_bytes(path: &Path) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(64 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 64 * 1024,
        "bilateral admission configuration exceeds byte limit"
    );
    Ok(bytes)
}

impl Binding {
    pub(crate) fn new(
        path: &Path,
        contracts: &Path,
        recovery: &MultiAssetRecoveryPackage,
        transaction: &packed::Transaction,
    ) -> Result<Self> {
        let binding = Self {
            config: path.canonicalize()?,
            config_hash: blake2b256(&config_bytes(path)?),
            contracts: contracts.canonicalize()?,
        };
        binding.require(recovery, transaction)?;
        Ok(binding)
    }
    pub(crate) fn require_fresh(
        &self,
        recovery: &MultiAssetRecoveryPackage,
        transaction: &packed::Transaction,
    ) -> Result<()> {
        self.require(recovery, transaction)?;
        let config = crate::admission::read_verified_config(&self.config, &self.contracts)?;
        let rpc = crate::rpc::CkbRpcClient::new_supervision(
            &config.rpc_url,
            std::time::Duration::from_secs(30),
        )?;
        validate(
            &self.config,
            &self.contracts,
            recovery,
            Some(rpc.tip_header()?.number_value()?),
        )?;
        crate::admission::reserve_bilateral(
            &rpc,
            &self.config,
            &self.contracts,
            recovery.state.header.chain_id,
            recovery.state.header.channel_id,
            transaction.calc_tx_hash().unpack(),
            capacity(recovery)?,
        )?;
        // A closure check may observe a newer or reorganized tip. The final
        // horizon check is immediately before the caller invokes its signer.
        validate(
            &self.config,
            &self.contracts,
            recovery,
            Some(rpc.tip_header()?.number_value()?),
        )?;
        self.require(recovery, transaction)
    }
    pub(crate) fn require(
        &self,
        recovery: &MultiAssetRecoveryPackage,
        transaction: &packed::Transaction,
    ) -> Result<()> {
        ensure!(
            self.config.is_absolute() && self.contracts.is_absolute(),
            "bilateral admission paths must be absolute"
        );
        ensure!(
            blake2b256(&config_bytes(&self.config)?) == self.config_hash,
            "bilateral admission configuration changed after journal review"
        );
        validate(&self.config, &self.contracts, recovery, None)?;
        validate_outputs(transaction)?;
        crate::admission::require_bilateral_reserved(
            &self.config,
            &self.contracts,
            recovery.state.header.chain_id,
            recovery.state.header.channel_id,
            transaction.calc_tx_hash().unpack(),
            capacity(recovery)?,
        )
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use k256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner};
    use morph_core::*;

    /// Small fail-fast JSON-RPC fixture. Every connection and request is bounded;
    /// unknown methods receive an immediate method-not-found response.
    pub(crate) struct MockRpc {
        pub(crate) url: String,
        tip: std::sync::Arc<std::sync::atomic::AtomicU64>,
        stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
        worker: Option<std::thread::JoinHandle<()>>,
    }
    impl MockRpc {
        pub(crate) fn start(genesis: Bytes32, tip: u64) -> Self {
            use std::io::{Read, Write};
            use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let tip = std::sync::Arc::new(AtomicU64::new(tip));
            let stop = std::sync::Arc::new(AtomicBool::new(false));
            let current = tip.clone();
            let stopping = stop.clone();
            let worker = std::thread::spawn(move || {
                for connection in listener.incoming() {
                    let Ok(mut stream) = connection else {
                        break;
                    };
                    if stopping.load(Ordering::Relaxed) {
                        break;
                    }
                    stream
                        .set_read_timeout(Some(std::time::Duration::from_millis(500)))
                        .unwrap();
                    stream
                        .set_write_timeout(Some(std::time::Duration::from_millis(500)))
                        .unwrap();
                    let response = (|| -> anyhow::Result<serde_json::Value> {
                        let mut request = Vec::new();
                        let header_end = loop {
                            if let Some(offset) =
                                request.windows(4).position(|value| value == b"\r\n\r\n")
                            {
                                break offset + 4;
                            }
                            ensure!(request.len() <= 16 * 1024, "mock RPC headers exceed bound");
                            let mut bytes = [0; 1024];
                            let count = stream.read(&mut bytes)?;
                            ensure!(count > 0, "mock RPC incomplete headers");
                            request.extend_from_slice(&bytes[..count]);
                        };
                        let headers = std::str::from_utf8(&request[..header_end])?;
                        let length = headers
                            .lines()
                            .find_map(|line| {
                                line.split_once(':')
                                    .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                                    .map(|(_, value)| value.trim().parse::<usize>())
                            })
                            .context("mock RPC missing length")??;
                        ensure!(length <= 64 * 1024, "mock RPC body exceeds bound");
                        while request.len() < header_end + length {
                            let mut bytes = [0; 1024];
                            let count = stream.read(&mut bytes)?;
                            ensure!(count > 0, "mock RPC incomplete body");
                            request.extend_from_slice(&bytes[..count]);
                        }
                        let body: serde_json::Value =
                            serde_json::from_slice(&request[header_end..header_end + length])?;
                        let result = match body["method"].as_str() {
                            Some("get_block_hash") if body["params"][0] == "0x0" => {
                                serde_json::json!(crate::multi_asset_packages::canonical_hex(
                                    &genesis
                                ))
                            }
                            Some("get_blockchain_info") => {
                                serde_json::json!({"chain":"ckb_dev","median_time":"0x0","epoch":"0x0","is_initial_block_download":false})
                            }
                            Some("get_tip_header") => {
                                serde_json::json!({"hash":crate::multi_asset_packages::canonical_hex(&[42;32]),"number":format!("0x{:x}", current.load(Ordering::Relaxed)),"parent_hash":crate::multi_asset_packages::canonical_hex(&[41;32]),"timestamp":"0x0","epoch":"0x0"})
                            }
                            Some("get_transaction") => {
                                serde_json::json!({"transaction":null,"cycles":null,"tx_status":{"status":"unknown","block_hash":null,"block_number":null,"tx_index":null,"reason":null}})
                            }
                            _ => {
                                return Ok(
                                    serde_json::json!({"jsonrpc":"2.0","id":body["id"],"error":{"code":-32601,"message":"bounded admission mock: unknown method"}}),
                                );
                            }
                        };
                        Ok(serde_json::json!({"jsonrpc":"2.0","id":body["id"],"result":result}))
                    })();
                    let body = serde_json::to_vec(&response.unwrap_or_else(|_| serde_json::json!({"jsonrpc":"2.0","id":1,"error":{"code":-32600,"message":"invalid bounded mock request"}}))).unwrap();
                    let header = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = stream.write_all(header.as_bytes());
                    let _ = stream.write_all(&body);
                }
            });
            Self {
                url: format!("http://{address}/"),
                tip,
                stop,
                worker: Some(worker),
            }
        }
        pub(crate) fn set_tip(&self, tip: u64) {
            self.tip.store(tip, std::sync::atomic::Ordering::Relaxed);
        }
    }
    impl Drop for MockRpc {
        fn drop(&mut self) {
            self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
            if let Ok(endpoint) = url::Url::parse(&self.url) {
                let _ = std::net::TcpStream::connect(("127.0.0.1", endpoint.port().unwrap()));
            }
            if let Some(worker) = self.worker.take() {
                worker.join().unwrap();
            }
        }
    }
    fn shared_rpc() -> &'static MockRpc {
        static RPC: std::sync::OnceLock<MockRpc> = std::sync::OnceLock::new();
        RPC.get_or_init(|| MockRpc::start([1; 32], 100))
    }

    pub(crate) fn root_draft(
        refund_after_block: Option<u64>,
        chain: Bytes32,
    ) -> crate::multi_asset_funding::RootFundingDraft {
        let (mut terms, _, cells, _) = crate::multi_asset_root_transaction::tests::fixture(0, true);
        let authority = crate::multi_asset_root_transaction::RootAuthorityHashes {
            state_type: blake2b256(&artifact("morph-state-type")),
            state_lock: blake2b256(&artifact("morph-state-lock")),
            vault_lock: blake2b256(&artifact("morph-vault-lock")),
        };
        if let Some(refund_after_block) = refund_after_block {
            let mut settlement = terms.creation(chain, authority).unwrap().settlement;
            settlement.payouts[0].values[0].business_ckb -= 1_000_000_000;
            let batch = ConditionalBatch {
                batch_id: [71; 32],
                application_context_commitment: [72; 32],
                participants: std::array::from_fn(|i| ConditionalParticipant {
                    settlement_lock_hash: settlement.participant_lock_hashes[i],
                    settled_capacity: settlement.payouts[0].values[i].capacity().unwrap(),
                }),
                transfers: vec![ConditionalTransferSpec {
                    transfer_id: [73; 32],
                    payer_lock_hash: settlement.participant_lock_hashes[0],
                    hash_algorithm: ConditionalHashAlgorithm::Sha256,
                    payment_hash: [74; 32],
                    amount: 1_000_000_000,
                    refund_after_block,
                }],
            };
            settlement.capability = MultiAssetSettlementCapability::CkbConditional {
                batch_code_hash: blake2b256(&artifact("morph-batch-lock")),
                batch_hash_type: 2,
                batch: Box::new(batch),
            };
            terms.descriptor_hex =
                crate::multi_asset_packages::canonical_hex(&settlement.encode().unwrap());
        }
        terms
            .build(chain, authority, &cells, 100_000_000)
            .unwrap()
            .draft
    }
    pub(crate) fn set_rpc(path: &Path, rpc_url: &str) {
        let mut config: AdmissionConfig = read_bounded_json(path, 64 * 1024).unwrap();
        config.rpc_url = rpc_url.to_string();
        std::fs::write(path, serde_json::to_vec(&config).unwrap()).unwrap();
    }

    pub(crate) fn artifact(name: &str) -> Vec<u8> {
        match name {
            "morph-state-type" => b"root-test-state-type".to_vec(),
            "morph-state-lock" => b"root-test-state-lock".to_vec(),
            "morph-vault-lock" => b"root-test-vault-lock".to_vec(),
            _ => format!("admission-test-{name}").into_bytes(),
        }
    }
    pub(crate) fn recovery(mut package: MultiAssetRecoveryPackage) -> MultiAssetRecoveryPackage {
        let replace_code = |raw: &[u8], name: &str| {
            packed::Script::from_slice(raw)
                .unwrap()
                .as_builder()
                .code_hash(blake2b256(&artifact(name)).pack())
                .build()
        };
        package.scripts.state_type = replace_code(&package.scripts.state_type, "morph-state-type")
            .as_slice()
            .to_vec();
        let state_type = blake2b256(&package.scripts.state_type);
        package.scripts.state_lock = replace_code(&package.scripts.state_lock, "morph-state-lock")
            .as_builder()
            .args(ckb_types::bytes::Bytes::from(state_type.to_vec()).pack())
            .build()
            .as_slice()
            .to_vec();
        let old_vault = packed::Script::from_slice(&package.scripts.vault_lock).unwrap();
        let old_args = old_vault.args().raw_data();
        let args = morph_script_common::multi_asset::MultiAssetVaultArgs::parse(&old_args).unwrap();
        let new_args = morph_script_common::multi_asset::encode_multi_asset_vault_args(
            &package.state.header.funding_anchor,
            args.finalise_since(),
            &state_type,
            &blake2b256(&package.scripts.state_lock),
        )
        .unwrap();
        package.scripts.vault_lock = replace_code(&package.scripts.vault_lock, "morph-vault-lock")
            .as_builder()
            .args(ckb_types::bytes::Bytes::from(new_args.to_vec()).pack())
            .build()
            .as_slice()
            .to_vec();
        for entry in &mut package.scripts.type_scripts {
            let old = entry.type_hash;
            let script = replace_code(&entry.script, "morph-devnet-xudt");
            let hash = script.calc_script_hash().unpack();
            entry.type_hash = hash;
            entry.script = script.as_slice().to_vec();
            for vault in &mut package.manifest.vaults {
                if vault.asset == VaultAsset::Xudt(old) {
                    vault.asset = VaultAsset::Xudt(hash);
                    vault.value.amount = 1000;
                }
            }
            for payout in &mut package.settlement.payouts {
                if payout.asset == VaultAsset::Xudt(old) {
                    payout.asset = VaultAsset::Xudt(hash);
                    payout.values[0].amount = 993;
                    payout.values[1].amount = 7;
                }
            }
        }
        package
            .scripts
            .type_scripts
            .sort_by_key(|entry| entry.type_hash);
        package
            .manifest
            .vaults
            .sort_by_key(|vault| vault.asset.clone());
        package
            .settlement
            .payouts
            .sort_by_key(|payout| payout.asset.clone());
        for vault in &mut package.manifest.vaults {
            vault.lock_hash = blake2b256(&package.scripts.vault_lock);
        }
        package.state.header.asset_registry_commitment =
            asset_registry_commitment(&package.manifest.registry().unwrap());
        package.state.header.settlement_descriptor_commitment =
            package.settlement.commitment().unwrap();
        package.state.vault_content_set_root = package.manifest.commitment().unwrap();
        package.state.vault_outpoint_set_root =
            multi_asset_outpoint_commitment(&package.manifest, &package.outpoints).unwrap();
        let digest = package.state.signing_digest().unwrap();
        package.authorization.signatures = [1u8, 2]
            .into_iter()
            .map(|seed| {
                let key = SigningKey::from_slice(&[seed; 32]).unwrap();
                let signature: Signature = key.sign_prehash(&digest).unwrap();
                ParticipantSignature {
                    pubkey_sec1: key.verifying_key().to_sec1_point(true).as_bytes().to_vec(),
                    signature: signature.to_bytes().to_vec(),
                }
            })
            .collect();
        package
            .authorization
            .signatures
            .sort_by(|a, b| a.pubkey_sec1.cmp(&b.pubkey_sec1));
        package.validate().unwrap();
        package
    }
    pub(crate) fn configuration(
        dir: &Path,
        recovery: &MultiAssetRecoveryPackage,
        transaction: &packed::Transaction,
    ) -> (PathBuf, PathBuf) {
        let contracts = dir.join("admission-contracts");
        std::fs::create_dir_all(&contracts).unwrap();
        for name in [
            "morph-state-type",
            "morph-state-lock",
            "morph-vault-lock",
            "morph-factory-type",
            "morph-factory-vault-lock",
            "morph-batch-lock",
            "morph-sponsor-lock",
            "morph-devnet-xudt",
        ] {
            std::fs::write(contracts.join(name), artifact(name)).unwrap();
        }
        let policy = dir.join("admission-policy");
        std::fs::create_dir_all(&policy).unwrap();
        let envelope = policy.join("envelope.json");
        std::fs::copy(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../release/factory-preproduction/envelope.json"),
            &envelope,
        )
        .unwrap();
        std::fs::write(
            policy.join("contracts.json"),
            serde_json::to_vec(&crate::release::build_contract_manifest(&contracts).unwrap())
                .unwrap(),
        )
        .unwrap();
        let identity =
            crate::preproduction::verify_admission_identity(&envelope, &contracts).unwrap();
        let config = AdmissionConfig {
            schema: "morph.factory_experiment_admission.v1".to_string(),
            envelope,
            ledger: dir.join("admission-ledger.json"),
            artifact_identity: crate::multi_asset_packages::canonical_hex(&identity),
            genesis_hash: crate::multi_asset_packages::canonical_hex(
                &recovery.state.header.chain_id,
            ),
            rpc_url: shared_rpc().url.clone(),
            no_real_assets: true,
            admitted_asset_types: recovery
                .scripts
                .type_scripts
                .iter()
                .map(|entry| crate::multi_asset_packages::canonical_hex(&entry.type_hash))
                .collect(),
        };
        let path = dir.join("admission-config.json");
        std::fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
        crate::admission::reserve_bilateral_for_test(
            &path,
            &contracts,
            recovery.state.header.chain_id,
            recovery.state.header.channel_id,
            transaction.calc_tx_hash().unpack(),
            capacity(recovery).unwrap(),
        )
        .unwrap();
        (path, contracts)
    }
    fn directory() -> PathBuf {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "morph-bilateral-admission-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }
    fn refresh(package: &mut MultiAssetRecoveryPackage) {
        package.state.header.asset_registry_commitment =
            asset_registry_commitment(&package.manifest.registry().unwrap());
        package.state.header.settlement_descriptor_commitment =
            package.settlement.commitment().unwrap();
        package.state.vault_content_set_root = package.manifest.commitment().unwrap();
        package.state.vault_outpoint_set_root =
            multi_asset_outpoint_commitment(&package.manifest, &package.outpoints).unwrap();
        package.validate_contents().unwrap();
    }
    #[test]
    fn admission_binds_exact_body_complete_artifacts_and_unchanged_configuration() {
        let dir = directory();
        let draft = crate::multi_asset_funding::tests::admitted_draft_fixture();
        let (_, package) = draft.evidence().unwrap();
        let transaction = draft.transaction().unwrap();
        let (config, contracts) = configuration(&dir, &package, &transaction);
        let binding = Binding::new(&config, &contracts, &package, &transaction).unwrap();
        let changed = transaction
            .clone()
            .as_builder()
            .raw(transaction.raw().as_builder().version(1u32).build())
            .build();
        assert!(
            binding
                .require(&package, &changed)
                .unwrap_err()
                .to_string()
                .contains("no durable")
        );
        let original = std::fs::read(&config).unwrap();
        let mut changed_config = original.clone();
        changed_config.push(b'\n');
        std::fs::write(&config, changed_config).unwrap();
        assert!(
            binding
                .require(&package, &transaction)
                .unwrap_err()
                .to_string()
                .contains("configuration changed")
        );
        std::fs::write(&config, original).unwrap();
        std::fs::write(
            contracts.join("morph-sponsor-lock"),
            b"changed-unrelated-ELF",
        )
        .unwrap();
        assert!(binding.require(&package, &transaction).is_err());
        std::fs::write(
            contracts.join("morph-sponsor-lock"),
            artifact("morph-sponsor-lock"),
        )
        .unwrap();
        std::fs::remove_file(dir.join("admission-ledger.json")).unwrap();
        assert!(
            binding
                .require(&package, &transaction)
                .unwrap_err()
                .to_string()
                .contains("ledger is missing")
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn admission_rejects_excess_custody_and_tokens_and_keeps_types_with_zero_participant_balances()
    {
        let dir = directory();
        let draft = crate::multi_asset_funding::tests::admitted_draft_fixture();
        let (_, package) = draft.evidence().unwrap();
        let (config, contracts) = configuration(&dir, &package, &draft.transaction().unwrap());
        let mut excess = package.clone();
        excess.manifest.vaults[0].value.reserve += 400_000_000_000;
        excess.settlement.payouts[0].values[0].reserve += 400_000_000_000;
        refresh(&mut excess);
        assert!(
            validate(&config, &contracts, &excess, None)
                .unwrap_err()
                .to_string()
                .contains("custody including")
        );
        let mut excess = package.clone();
        excess.manifest.vaults[0].value.amount = 1_000_000_000_001;
        excess.settlement.payouts[0].values[0].amount = 1_000_000_000_001;
        excess.settlement.payouts[0].values[1].amount = 0;
        refresh(&mut excess);
        assert!(
            validate(&config, &contracts, &excess, None)
                .unwrap_err()
                .to_string()
                .contains("token quantity")
        );
        let mut zero = package.clone();
        zero.settlement.payouts[0].values[0].amount = 0;
        zero.settlement.payouts[0].values[1].amount = zero.manifest.vaults[0].value.amount;
        refresh(&mut zero);
        validate(&config, &contracts, &zero, None).unwrap();
        let mut admission: AdmissionConfig = read_bounded_json(&config, 64 * 1024).unwrap();
        admission.admitted_asset_types.clear();
        std::fs::write(&config, serde_json::to_vec(&admission).unwrap()).unwrap();
        assert!(
            validate(&config, &contracts, &zero, None)
                .unwrap_err()
                .to_string()
                .contains("not explicitly admitted")
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn public_conditional_update_policy_rejects_new_long_or_mature_deadlines() {
        let envelope: PreproductionEnvelope = serde_json::from_str(include_str!(
            "../../../release/factory-preproduction/envelope.json"
        ))
        .unwrap();
        let mut settlement = crate::multi_asset_packages::fixture_package()
            .unwrap()
            .recovery()
            .unwrap()
            .settlement;
        let locks = settlement.participant_lock_hashes;
        let batch_hash = [7; 32];
        settlement.capability = MultiAssetSettlementCapability::CkbConditional {
            batch_code_hash: batch_hash,
            batch_hash_type: 2,
            batch: Box::new(ConditionalBatch {
                batch_id: [8; 32],
                application_context_commitment: [9; 32],
                participants: [
                    ConditionalParticipant {
                        settlement_lock_hash: locks[0],
                        settled_capacity: 1000,
                    },
                    ConditionalParticipant {
                        settlement_lock_hash: locks[1],
                        settled_capacity: 1000,
                    },
                ],
                transfers: vec![ConditionalTransferSpec {
                    transfer_id: [10; 32],
                    payer_lock_hash: locks[0],
                    hash_algorithm: ConditionalHashAlgorithm::CkbBlake2b,
                    payment_hash: [11; 32],
                    amount: 1,
                    refund_after_block: 2116,
                }],
            }),
        };
        validate_conditions(&settlement, &envelope, Some(100), batch_hash).unwrap();
        if let MultiAssetSettlementCapability::CkbConditional { batch, .. } =
            &mut settlement.capability
        {
            batch.transfers[0].refund_after_block = 2117;
        }
        assert!(
            validate_conditions(&settlement, &envelope, Some(100), batch_hash)
                .unwrap_err()
                .to_string()
                .contains("refund horizon")
        );
        // A late saved authorization remains valid protocol evidence. Admission
        // is applied only to a new proposal/signature, never package export.
        if let MultiAssetSettlementCapability::CkbConditional { batch, .. } =
            &mut settlement.capability
        {
            batch.transfers[0].refund_after_block = 100;
        }
        validate_conditions(&settlement, &envelope, None, batch_hash).unwrap();
        assert!(validate_conditions(&settlement, &envelope, Some(100), batch_hash).is_err());
        assert!(validate_conditions(&settlement, &envelope, None, [12; 32]).is_err());
    }
    #[test]
    fn allowlisted_type_still_requires_exact_reviewed_devnet_issuer_and_bounded_actual_fee() {
        let dir = directory();
        let draft = crate::multi_asset_funding::tests::admitted_draft_fixture();
        let (_, mut package) = draft.evidence().unwrap();
        let (config, contracts) = configuration(&dir, &package, &draft.transaction().unwrap());
        let old = package.scripts.type_scripts[0].type_hash;
        let script = packed::Script::from_slice(&package.scripts.type_scripts[0].script)
            .unwrap()
            .as_builder()
            .code_hash([99u8; 32].pack())
            .build();
        let hash = script.calc_script_hash().unpack();
        package.scripts.type_scripts[0].type_hash = hash;
        package.scripts.type_scripts[0].script = script.as_slice().to_vec();
        package
            .scripts
            .type_scripts
            .sort_by_key(|entry| entry.type_hash);
        for vault in &mut package.manifest.vaults {
            if vault.asset == VaultAsset::Xudt(old) {
                vault.asset = VaultAsset::Xudt(hash);
            }
        }
        for payout in &mut package.settlement.payouts {
            if payout.asset == VaultAsset::Xudt(old) {
                payout.asset = VaultAsset::Xudt(hash);
            }
        }
        package
            .manifest
            .vaults
            .sort_by_key(|vault| vault.asset.clone());
        package
            .settlement
            .payouts
            .sort_by_key(|payout| payout.asset.clone());
        refresh(&mut package);
        let mut admission: AdmissionConfig = read_bounded_json(&config, 64 * 1024).unwrap();
        admission.admitted_asset_types = package
            .scripts
            .type_scripts
            .iter()
            .map(|entry| crate::multi_asset_packages::canonical_hex(&entry.type_hash))
            .collect();
        std::fs::write(&config, serde_json::to_vec(&admission).unwrap()).unwrap();
        assert!(
            validate(&config, &contracts, &package, None)
                .unwrap_err()
                .to_string()
                .contains("reviewed devnet-only issuer")
        );
        let (_, envelope) = super::config(&config, &contracts).unwrap();
        validate_fee(&envelope, envelope.sponsor.max_fee_per_transaction_shannons).unwrap();
        assert!(validate_fee(&envelope, 0).is_err());
        assert!(
            validate_fee(
                &envelope,
                envelope.sponsor.max_fee_per_transaction_shannons + 1
            )
            .is_err()
        );
        let transaction = draft.transaction().unwrap();
        let mut outputs = transaction.raw().outputs().into_iter().collect::<Vec<_>>();
        outputs[0] = outputs[0].clone().as_builder().capacity(1u64).build();
        let underoccupied = transaction
            .clone()
            .as_builder()
            .raw(
                transaction
                    .raw()
                    .as_builder()
                    .outputs(outputs.pack())
                    .build(),
            )
            .build();
        assert!(validate_outputs(&underoccupied).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn fresh_admission_rechecks_delayed_and_reorganized_conditional_horizons() {
        for (refund, changed_tip) in [(200, 200), (2116, 99)] {
            let dir = directory();
            let mock = MockRpc::start([1; 32], 100);
            let draft = root_draft(Some(refund), [1; 32]);
            let (_, package) = draft.evidence().unwrap();
            let transaction = draft.transaction().unwrap();
            let (config, contracts) = configuration(&dir, &package, &transaction);
            set_rpc(&config, &mock.url);
            let binding = Binding::new(&config, &contracts, &package, &transaction).unwrap();
            binding.require_fresh(&package, &transaction).unwrap();
            mock.set_tip(changed_tip);
            // The old exact reservation alone remains readable, but cannot
            // grant a new signature against a now-invalid canonical horizon.
            binding.require(&package, &transaction).unwrap();
            assert!(
                binding
                    .require_fresh(&package, &transaction)
                    .unwrap_err()
                    .to_string()
                    .contains("refund horizon")
            );
            std::fs::remove_dir_all(dir).unwrap();
        }
    }
}
