//! One immutable initial-exit ceremony per Factory child party. Only the exact
//! public-parent-committed Settling/1 exit can be signed at this path; canonical
//! handoff replaces it with the ordinary bilateral journal at this same path.
use crate::factory_packets::{StoredFactoryRequest, read_for_delivery_review};
use crate::multi_asset_packages::{
    StoredMultiAssetPackage, canonical_hex, read_bounded_json, write_package,
};
use crate::multi_asset_signatures::{SignatureMessage, channel_signing_key, verify_participant};
use crate::persistence::{lock_private_path, write_private_atomic};
use anyhow::{Result, anyhow, ensure};
use clap::Subcommand;
use k256::ecdsa::{Signature, signature::hazmat::PrehashSigner};
use morph_core::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

const SCHEMA: &str = "morph.factory_child_session.v1";
const MAX_BYTES: usize = 8 * 1024 * 1024;
#[derive(Debug, Subcommand)]
pub(crate) enum FactoryChildSessionCommand {
    Init {
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        child_index: u16,
        #[arg(long)]
        local_pubkey: String,
        #[arg(long)]
        policy: PathBuf,
        #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
        contracts_dir: PathBuf,
    },
    Inspect,
    Sign {
        #[arg(long = "private-key-file", env = "MORPH_CHANNEL_PRIVATE_KEY_FILE", hide_env_values = true, value_name = "PATH", value_parser = morph_key_input::secp256k1_file)]
        private_key: morph_key_input::SecretString,
    },
    AddSignature {
        #[arg(long)]
        signature: PathBuf,
    },
    Export {
        #[arg(long)]
        store_dir: PathBuf,
    },
    #[cfg(feature = "devnet")]
    Confirm {
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        transaction: PathBuf,
        #[arg(long)]
        rpc_url: String,
        #[arg(long)]
        state_out_point: String,
        #[arg(long)]
        min_confirmations: u64,
        #[arg(long)]
        archive_dir: PathBuf,
        #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
        contracts_dir: PathBuf,
    },
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChildJournal {
    schema: String,
    request: StoredFactoryRequest,
    child_index: u16,
    local_pubkey: String,
    contracts_dir: PathBuf,
    policy: PathBuf,
    reserved: bool,
    signatures: Vec<ParticipantSignature>,
}
impl ChildJournal {
    fn request(&self) -> Result<FactorySigningRequest> {
        self.request.decode_for_delivery_review()
    }
    fn expected(&self) -> Result<MultiAssetRecoveryPackage> {
        Ok(self.request()?.expected_child_recovery(self.child_index)?)
    }
    fn participants(&self) -> Result<[String; 2]> {
        let expected = self.expected()?;
        ensure!(
            expected.authorization.signatures.len() == 2,
            "invalid expected child membership"
        );
        Ok(std::array::from_fn(|index| {
            canonical_hex(&expected.authorization.signatures[index].pubkey_sec1)
        }))
    }
    fn digest(&self) -> Result<Bytes32> {
        Ok(self.expected()?.state.signing_digest()?)
    }
    fn package(&self) -> Result<MultiAssetRecoveryPackage> {
        let mut package = self.expected()?;
        package.authorization.signatures = self.signatures.clone();
        self.request()?
            .verify_child_recovery(self.child_index, &package)?;
        Ok(package)
    }
    fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == SCHEMA && self.contracts_dir.is_absolute() && self.policy.is_absolute(),
            "invalid current Factory child journal/configuration"
        );
        let participants = self.participants()?;
        ensure!(
            participants.contains(&self.local_pubkey),
            "local child signer is not a committed participant"
        );
        ensure!(
            self.signatures.len() <= 2
                && self
                    .signatures
                    .windows(2)
                    .all(|pair| pair[0].pubkey_sec1 < pair[1].pubkey_sec1),
            "child signatures are not unique/canonical"
        );
        let digest = self.digest()?;
        for signature in &self.signatures {
            verify_participant(&digest, &participants, signature)?;
            if canonical_hex(&signature.pubkey_sec1) == self.local_pubkey {
                ensure!(
                    self.reserved,
                    "local child signature lacks its durable reservation"
                );
            }
        }
        Ok(())
    }
    fn admit(&self) -> Result<()> {
        self.validate()?;
        crate::factory_artifacts::validate_request_artifacts_for_review(
            &self.request()?,
            &self.contracts_dir,
        )?;
        let expected = self.expected()?;
        crate::value_limit::read_value_limit_policy(&self.policy)?.enforce(
            &ValueSubject::from_manifest(&expected.manifest, expected.state_carrier_capacity)?,
        )?;
        Ok(())
    }
    fn save(&self, path: &Path) -> Result<()> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)?;
        ensure!(
            bytes.len() <= MAX_BYTES,
            "Factory child journal exceeds byte bound"
        );
        write_private_atomic(path, &bytes)
    }
    fn record(&mut self, signature: ParticipantSignature) -> Result<()> {
        verify_participant(&self.digest()?, &self.participants()?, &signature)?;
        if canonical_hex(&signature.pubkey_sec1) == self.local_pubkey {
            ensure!(self.reserved, "local child signature is unreserved");
        }
        if let Some(existing) = self
            .signatures
            .iter()
            .find(|existing| existing.pubkey_sec1 == signature.pubkey_sec1)
        {
            ensure!(
                existing == &signature,
                "conflicting child signature receipt"
            );
        } else {
            self.signatures.push(signature);
            self.signatures
                .sort_by(|a, b| a.pubkey_sec1.cmp(&b.pubkey_sec1));
        }
        self.validate()
    }
    fn summary(&self) -> Result<Value> {
        self.validate()?;
        let request = self.request()?;
        let expected = self.expected()?;
        Ok(
            json!({"schema":"morph.factory_child_session_review.v1","request_id":canonical_hex(&request.request_id()?),"transaction_hash":canonical_hex(&request.transaction_hash()?),"child_index":self.child_index,"local_pubkey":self.local_pubkey,"reserved":self.reserved,"signature_count":self.signatures.len(),"signing_digest":canonical_hex(&self.digest()?),"channel_id":canonical_hex(&expected.state.header.channel_id),"state_number":"1","payouts":crate::multi_asset_session::payout_summary(&expected.settlement),"ready_for_delivery":self.signatures.len()==2}),
        )
    }
}
pub(crate) fn run(path: &Path, command: FactoryChildSessionCommand) -> Result<Value> {
    let _lock = lock_private_path(path)?;
    if let FactoryChildSessionCommand::Init {
        request,
        child_index,
        local_pubkey,
        policy,
        contracts_dir,
    } = command
    {
        ensure!(
            !path.exists(),
            "Factory child authority path already exists; never clone/reset it"
        );
        let request = read_for_delivery_review(&request)?;
        let local_pubkey = canonical_hex(&crate::canonical_fields::public(&local_pubkey)?);
        let journal = ChildJournal {
            schema: SCHEMA.to_string(),
            request,
            child_index,
            local_pubkey,
            contracts_dir: contracts_dir.canonicalize()?,
            policy: policy.canonicalize()?,
            reserved: false,
            signatures: vec![],
        };
        journal.admit()?;
        journal.save(path)?;
        return journal.summary();
    }
    let mut journal: ChildJournal = read_bounded_json(path, MAX_BYTES)?;
    journal.validate()?;
    match command {
        FactoryChildSessionCommand::Init { .. } => {
            Err(anyhow!("Factory child ceremony already initialized"))
        }
        FactoryChildSessionCommand::Inspect => journal.summary(),
        FactoryChildSessionCommand::Sign { private_key } => {
            journal.admit()?;
            let local = crate::canonical_fields::public(&journal.local_pubkey)?;
            let key = channel_signing_key(&private_key, &local)?;
            let digest = journal.digest()?;
            if let Some(signature) = journal
                .signatures
                .iter()
                .find(|signature| signature.pubkey_sec1 == local)
            {
                return Ok(serde_json::to_value(SignatureMessage::new(
                    &digest, signature,
                ))?);
            }
            journal.reserved = true;
            journal.save(path)?;
            journal.admit()?;
            let signature: Signature = key
                .sign_prehash(&digest)
                .map_err(|_| anyhow!("Factory child initial-exit signing failed"))?;
            let signature = ParticipantSignature {
                pubkey_sec1: local,
                signature: signature.to_bytes().to_vec(),
            };
            journal.record(signature.clone())?;
            journal.save(path)?;
            Ok(serde_json::to_value(SignatureMessage::new(
                &digest, &signature,
            ))?)
        }
        FactoryChildSessionCommand::AddSignature { signature } => {
            let message: SignatureMessage = read_bounded_json(&signature, 4096)?;
            journal.record(message.verify(&journal.digest()?, &journal.participants()?)?)?;
            journal.save(path)?;
            journal.summary()
        }
        FactoryChildSessionCommand::Export { store_dir } => {
            let request = journal.request()?;
            let raw = request.raw_transaction()?;
            let package = StoredMultiAssetPackage::from_recovery(
                &journal.package()?,
                &raw.cell_deps().into_iter().collect::<Vec<_>>(),
            )?;
            let package = write_package(&store_dir, &package)?;
            Ok(
                json!({"schema":"morph.factory_child_exit_export.v1","private_recovery":package,"child_index":journal.child_index,"request_id":canonical_hex(&request.request_id()?),"ready_for_delivery":true}),
            )
        }
        #[cfg(feature = "devnet")]
        FactoryChildSessionCommand::Confirm {
            request,
            transaction,
            rpc_url,
            state_out_point,
            min_confirmations,
            archive_dir,
            contracts_dir,
        } => {
            use ckb_types::{packed, prelude::*};
            use std::io::Read;
            let request = crate::factory_packets::read_request(&request)?;
            let complete = request.decode()?;
            ensure!(
                complete.request_id()? == journal.request()?.request_id()?,
                "confirmed Factory request differs from immutable child intent"
            );
            let initial = journal.package()?;
            complete.verify_child_recovery(journal.child_index, &initial)?;
            let mut bytes = vec![];
            std::fs::File::open(transaction)?
                .take(FACTORY_MAX_TRANSACTION_BYTES as u64 + 1)
                .read_to_end(&mut bytes)?;
            ensure!(
                bytes.len() <= FACTORY_MAX_TRANSACTION_BYTES,
                "Factory parent transaction exceeds byte bound"
            );
            let transaction = packed::Transaction::from_slice(&bytes)?;
            complete.verify_authorized_transaction(&transaction)?;
            let package = StoredMultiAssetPackage::from_recovery(
                &initial,
                &transaction
                    .raw()
                    .cell_deps()
                    .into_iter()
                    .collect::<Vec<_>>(),
            )?;
            let origin = crate::factory_child_origin::FactoryChildOrigin {
                schema: crate::factory_child_origin::SCHEMA.to_string(),
                request,
                transaction_hex: canonical_hex(transaction.as_slice()),
                child_index: journal.child_index,
                initial_recovery: package,
            };
            origin.decode()?;
            let archive = serde_json::to_vec(
                &json!({"schema":"morph.retired_factory_child_session.v1","session":journal}),
            )?;
            let archive_path = archive_dir.join(format!(
                "factory-child-{}.json",
                hex::encode(blake2b256(&archive))
            ));
            crate::persistence::write_private_immutable(&archive_path, &archive)?;
            let mut result = crate::multi_asset_session::confirm_factory_child(
                path,
                crate::multi_asset_session::FactoryChildHandoff {
                    origin,
                    local_pubkey: crate::canonical_fields::public(&journal.local_pubkey)?,
                    rpc_url: &rpc_url,
                    state_out_point: &state_out_point,
                    min_confirmations,
                    archive_dir: &archive_dir,
                    contracts_dir: &contracts_dir,
                },
            )?;
            result["initial_exit_archive"] = json!(archive_path.canonicalize()?);
            Ok(result)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::SigningKey;
    struct Directory(PathBuf);
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn directory() -> Directory {
        let path = std::env::temp_dir().join(format!(
            "morph-child-ceremony-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&path).unwrap();
        Directory(path)
    }
    #[test]
    fn independent_child_parties_reserve_before_sign_and_retain_complete_exit_before_parent_delivery()
     {
        let directory = directory();
        for name in [
            "morph-factory-type",
            "morph-factory-vault-lock",
            "morph-state-type",
            "morph-state-lock",
            "morph-vault-lock",
        ] {
            std::fs::write(directory.0.join(name), name.as_bytes()).unwrap();
        }
        let policy = directory.0.join("policy.json");
        std::fs::write(
            &policy,
            serde_json::to_vec(&ValueLimitPolicy {
                schema: VALUE_LIMIT_POLICY_SCHEMA.to_string(),
                created_unix_ms: 0,
                max_channel_ckb_capacity: 100_000_000_000,
                max_xudt_amounts: Default::default(),
            })
            .unwrap(),
        )
        .unwrap();
        let (terms, cells) =
            crate::factory_transaction::tests::native_child_fixture(Some(&directory.0));
        let request = terms.build(&cells, 1000).unwrap();
        let request_path = directory.0.join("public-request.json");
        std::fs::write(
            &request_path,
            serde_json::to_vec(&StoredFactoryRequest::from_delivery_review(&request).unwrap())
                .unwrap(),
        )
        .unwrap();
        let mut paths = vec![];
        let mut receipts = vec![];
        for seed in [1u8, 2] {
            let key = SigningKey::from_slice(&[seed; 32]).unwrap();
            let local_pubkey = canonical_hex(key.verifying_key().to_sec1_point(true).as_bytes());
            let path = directory.0.join(format!("party-{seed}.json"));
            run(
                &path,
                FactoryChildSessionCommand::Init {
                    request: request_path.clone(),
                    child_index: 0,
                    local_pubkey,
                    policy: policy.clone(),
                    contracts_dir: directory.0.clone(),
                },
            )
            .unwrap();
            let before = std::fs::read(&path).unwrap();
            assert!(
                run(
                    &path,
                    FactoryChildSessionCommand::Sign {
                        private_key: hex::encode([3; 32]).into()
                    }
                )
                .is_err()
            );
            assert_eq!(std::fs::read(&path).unwrap(), before);
            let signed = run(
                &path,
                FactoryChildSessionCommand::Sign {
                    private_key: hex::encode([seed; 32]).into(),
                },
            )
            .unwrap();
            let journal: ChildJournal = read_bounded_json(&path, MAX_BYTES).unwrap();
            journal.validate().unwrap();
            assert!(journal.reserved);
            assert_eq!(journal.signatures.len(), 1);
            let saved = std::fs::read(&path).unwrap();
            assert_eq!(
                run(
                    &path,
                    FactoryChildSessionCommand::Sign {
                        private_key: hex::encode([seed; 32]).into()
                    }
                )
                .unwrap(),
                signed
            );
            assert_eq!(std::fs::read(&path).unwrap(), saved);
            let exit_dir = directory.0.join(format!("exit-{seed}"));
            assert!(
                run(
                    &path,
                    FactoryChildSessionCommand::Export {
                        store_dir: exit_dir.clone()
                    }
                )
                .is_err()
            );
            assert!(!exit_dir.exists());
            let receipt = directory.0.join(format!("signature-{seed}.json"));
            std::fs::write(&receipt, serde_json::to_vec(&signed).unwrap()).unwrap();
            paths.push(path);
            receipts.push(receipt);
        }
        for (index, path) in paths.iter().enumerate() {
            run(
                path,
                FactoryChildSessionCommand::AddSignature {
                    signature: receipts[1 - index].clone(),
                },
            )
            .unwrap();
            let journal: ChildJournal = read_bounded_json(path, MAX_BYTES).unwrap();
            let recovery = journal.package().unwrap();
            request.verify_child_recovery(0, &recovery).unwrap();
            let exported = run(
                path,
                FactoryChildSessionCommand::Export {
                    store_dir: directory.0.join(format!("private-{index}")),
                },
            )
            .unwrap();
            let package = PathBuf::from(exported["private_recovery"].as_str().unwrap());
            assert_eq!(
                crate::multi_asset_packages::read_package(&package)
                    .unwrap()
                    .recovery()
                    .unwrap(),
                recovery
            );
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(
                    std::fs::metadata(&package).unwrap().permissions().mode() & 0o777,
                    0o600
                );
            }
            let mut tampered: Value =
                serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
            tampered["reserved"] = json!(false);
            let bad: ChildJournal = serde_json::from_value(tampered).unwrap();
            assert!(bad.validate().is_err());
        }
        let public = std::fs::read_to_string(request_path).unwrap();
        for path in &paths {
            let journal: ChildJournal = read_bounded_json(path, MAX_BYTES).unwrap();
            for signature in journal.signatures {
                assert!(!public.contains(&canonical_hex(&signature.signature)));
            }
        }
        std::fs::write(directory.0.join("morph-vault-lock"), b"changed artifact").unwrap();
        let before = std::fs::read(&paths[0]).unwrap();
        assert!(
            run(
                &paths[0],
                FactoryChildSessionCommand::Sign {
                    private_key: hex::encode([1; 32]).into()
                }
            )
            .is_err()
        );
        assert_eq!(std::fs::read(&paths[0]).unwrap(), before);
    }
}
