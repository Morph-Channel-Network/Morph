//! Independent initial funding ceremony. An immutable draft fixes both votes;
//! the complete initial exit must be durable before root creation can be signed.
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow, ensure};
use ckb_types::{bytes::Bytes, packed, prelude::*};
use clap::Subcommand;
use morph_core::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::multi_asset_funding::{RootFundingDraft, validate_root_funding};
use crate::multi_asset_packages::{
    StoredMultiAssetPackage, canonical_hex, decode_hex, write_package,
};
use crate::multi_asset_session::payout_summary;
use crate::multi_asset_signatures::{SIGNATURE_SCHEMA, SignatureMessage};
use crate::multi_asset_splice_transaction::{TransactionKind, write_transaction};
#[cfg(feature = "devnet")]
use crate::persistence::try_lock_private_path;
use crate::persistence::{lock_private_path, write_private_atomic};

const SCHEMA: &str = "morph.multi_asset_funding_session.v1";
const MAX_BYTES: u64 = 768 * 1024;

#[derive(Debug, Subcommand)]
pub enum FundingSessionCommand {
    /// Review an immutable public draft and initialise this signer's stable path.
    Init {
        #[arg(long)]
        admission_config: PathBuf,
        #[arg(long)]
        draft: PathBuf,
        #[arg(long)]
        local_pubkey: String,
        #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
        contracts_dir: PathBuf,
    },
    Inspect,
    /// Reserve durably before signing. Creation requires the complete initial exit.
    Sign {
        #[arg(long, value_enum)]
        target: FundingTarget,
        #[arg(long)]
        signer_config: PathBuf,
    },
    /// Development-only local participant signer (requires the devnet feature).
    SignLocal {
        #[arg(long, value_enum)]
        target: FundingTarget,
        #[arg(long = "private-key-file", env = "MORPH_CHANNEL_PRIVATE_KEY_FILE", hide_env_values = true, value_name = "PATH", value_parser = crate::participant_signer::development_key_file)]
        private_key: morph_key_input::SecretString,
    },
    AddSignature {
        #[arg(long, value_enum)]
        target: FundingTarget,
        #[arg(long)]
        signature: PathBuf,
    },
    /// Persist the full exit before exposing the Morph-authorised funding body.
    Export {
        #[arg(long)]
        store_dir: PathBuf,
    },
    /// Export the complete private exit without waiting for the peer's creation receipt.
    ExportRecovery {
        #[arg(long)]
        store_dir: PathBuf,
    },
    /// Switch this same path to a guarded operational session after chain confirmation.
    #[cfg(feature = "devnet")]
    Confirm {
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

pub use crate::multi_asset_funding::RootFundingTarget as FundingTarget;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FundingJournal {
    schema: String,
    draft: RootFundingDraft,
    local_pubkey: String,
    contracts_dir: PathBuf,
    admission: crate::admission_channel::Binding,
    exit_reserved: bool,
    creation_reserved: bool,
    exit_signatures: Vec<ParticipantSignature>,
    creation_signatures: Vec<ParticipantSignature>,
}
impl FundingJournal {
    fn external_payload(&self) -> Result<morph_packages::signer_protocol::Payload> {
        let mut collection =
            crate::multi_asset_funding::RootFundingCollection::new(self.draft.clone())?;
        let (creation, exit) = self.draft.digests()?;
        collection.creation_signatures = self
            .creation_signatures
            .iter()
            .map(|s| SignatureMessage::new(&creation, s))
            .collect();
        collection.exit_signatures = self
            .exit_signatures
            .iter()
            .map(|s| SignatureMessage::new(&exit, s))
            .collect();
        collection.validate()?;
        Ok(morph_packages::signer_protocol::Payload::Root {
            collection: Box::new(collection),
        })
    }
    fn digest(&self, target: FundingTarget) -> Result<Bytes32> {
        let (creation, exit) = self.draft.digests()?;
        Ok(match target {
            FundingTarget::Exit => exit,
            FundingTarget::Creation => creation,
        })
    }
    fn signatures(&self, target: FundingTarget) -> &[ParticipantSignature] {
        match target {
            FundingTarget::Exit => &self.exit_signatures,
            FundingTarget::Creation => &self.creation_signatures,
        }
    }
    fn reserved(&self, target: FundingTarget) -> bool {
        match target {
            FundingTarget::Exit => self.exit_reserved,
            FundingTarget::Creation => self.creation_reserved,
        }
    }
    fn eligible(&self, target: FundingTarget) -> Result<()> {
        if matches!(target, FundingTarget::Creation) {
            self.exit()?.validate()?;
        }
        Ok(())
    }
    fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == SCHEMA,
            "unsupported initial funding session schema"
        );
        self.draft.evidence()?;
        ensure!(
            self.contracts_dir.is_absolute(),
            "approved artifact path must be absolute"
        );
        ensure!(
            self.draft.participants.contains(&self.local_pubkey),
            "local key is not a root participant"
        );
        for target in [FundingTarget::Exit, FundingTarget::Creation] {
            let signatures = self.signatures(target);
            ensure!(signatures.len() <= 2, "too many root signatures");
            if self.reserved(target) || !signatures.is_empty() {
                self.eligible(target)?;
            }
            let mut previous: Option<&[u8]> = None;
            for signature in signatures {
                ensure!(
                    previous.is_none_or(|previous| previous < signature.pubkey_sec1.as_slice()),
                    "root signatures are not canonical"
                );
                if canonical_hex(&signature.pubkey_sec1) == self.local_pubkey {
                    ensure!(
                        self.reserved(target),
                        "local signature has no durable root reservation"
                    );
                }
                self.verify(target, signature)?;
                previous = Some(&signature.pubkey_sec1);
            }
        }
        Ok(())
    }
    fn verify_admission(&self) -> Result<()> {
        let (_, exit) = self.draft.evidence()?;
        self.admission.require(&exit, &self.draft.transaction()?)
    }
    fn verify_fresh_admission(&self) -> Result<()> {
        let (_, exit) = self.draft.evidence()?;
        self.admission
            .require_fresh(&exit, &self.draft.transaction()?)
    }
    fn verify_artifacts(&self) -> Result<()> {
        let (creation, _) = self.draft.evidence()?;
        for (script, name) in [
            (&creation.scripts.state_type, "morph-state-type"),
            (&creation.scripts.state_lock, "morph-state-lock"),
            (&creation.scripts.vault_lock, "morph-vault-lock"),
        ] {
            let script = packed::Script::from_slice(script)?;
            let binary = std::fs::read(self.contracts_dir.join(name))?;
            ensure!(
                script.hash_type().as_slice() == [2]
                    && script.code_hash().as_slice() == blake2b256(&binary),
                "root authority does not match approved data1 artifact {name}"
            );
        }
        Ok(())
    }
    fn verify(&self, target: FundingTarget, signature: &ParticipantSignature) -> Result<()> {
        crate::multi_asset_signatures::verify_participant(
            &self.digest(target)?,
            &self.draft.participants,
            signature,
        )
    }
    fn record(&mut self, target: FundingTarget, signature: ParticipantSignature) -> Result<()> {
        self.eligible(target)?;
        self.verify(target, &signature)?;
        if canonical_hex(&signature.pubkey_sec1) == self.local_pubkey {
            ensure!(
                self.reserved(target),
                "local signature has no durable root reservation"
            );
        }
        let signatures = match target {
            FundingTarget::Exit => &mut self.exit_signatures,
            FundingTarget::Creation => &mut self.creation_signatures,
        };
        if let Some(existing) = signatures
            .iter()
            .find(|existing| existing.pubkey_sec1 == signature.pubkey_sec1)
        {
            ensure!(existing == &signature, "conflicting root signature receipt");
        } else {
            signatures.push(signature);
            signatures.sort_by(|a, b| a.pubkey_sec1.cmp(&b.pubkey_sec1));
        }
        Ok(())
    }
    fn exit(&self) -> Result<MultiAssetRecoveryPackage> {
        let (_, mut exit) = self.draft.evidence()?;
        exit.authorization = StateAuthorization {
            threshold: 2,
            signatures: self.exit_signatures.clone(),
        };
        Ok(exit)
    }
    fn package(&self) -> Result<StoredMultiAssetPackage> {
        StoredMultiAssetPackage::from_recovery(
            &self.exit()?,
            &self
                .draft
                .transaction()?
                .raw()
                .cell_deps()
                .into_iter()
                .collect::<Vec<_>>(),
        )
    }
    fn transaction(&self) -> Result<packed::Transaction> {
        let tx = self.draft.transaction()?;
        let raw = tx
            .witnesses()
            .get(0)
            .ok_or_else(|| anyhow!("missing funding witness"))?
            .raw_data();
        let args = packed::WitnessArgs::from_slice(&raw)?
            .as_builder()
            .input_type(
                Some(Bytes::from(
                    encode_multi_asset_signatures(&StateAuthorization {
                        threshold: 2,
                        signatures: self.creation_signatures.clone(),
                    })?
                    .to_vec(),
                ))
                .pack(),
            )
            .build();
        let mut witnesses = tx.witnesses().into_iter().collect::<Vec<_>>();
        witnesses[0] = args.as_bytes().pack();
        let transaction = tx.as_builder().witnesses(witnesses.pack()).build();
        validate_root_funding(&self.exit()?, &transaction)?;
        Ok(transaction)
    }
    #[cfg(any(feature = "devnet", test))]
    fn eligible_for_handoff(&self) -> Result<()> {
        self.eligible(FundingTarget::Creation)?;
        ensure!(
            self.creation_reserved
                && self.creation_signatures.iter().any(|signature| {
                    canonical_hex(&signature.pubkey_sec1) == self.local_pubkey
                }),
            "canonical handoff requires the durable local creation approval"
        );
        Ok(())
    }
    fn summary(&self) -> Result<Value> {
        let (creation, exit) = self.draft.evidence()?;
        Ok(
            json!({"schema":self.schema,"local_pubkey":self.local_pubkey,
            "participants":self.draft.participants,"chain_id":canonical_hex(&creation.state.header.chain_id),"channel_id":canonical_hex(&creation.state.header.channel_id),
            "transaction_hash":canonical_hex(self.draft.transaction()?.calc_tx_hash().as_slice()),
            "funding_context_id":canonical_hex(&exit.state.funding_context_id()?),
            "creation_digest":canonical_hex(&self.digest(FundingTarget::Creation)?),
            "exit_digest":canonical_hex(&self.digest(FundingTarget::Exit)?),
            "exit_reserved":self.exit_reserved,"creation_reserved":self.creation_reserved,
            "exit_signature_count":self.exit_signatures.len(),"creation_signature_count":self.creation_signatures.len(),
            "recovery_available":self.exit_signatures.len()==2,
            "participant_lock_hashes":exit.settlement.participant_lock_hashes.map(|hash|canonical_hex(&hash)),
            "payouts":payout_summary(&exit.settlement),"state_carrier_capacity":exit.state_carrier_capacity.to_string(),
            "ready_to_export":self.exit_signatures.len()==2 && self.creation_signatures.len()==2}),
        )
    }
}

pub(crate) fn external_authority(
    bytes: &[u8],
    target: morph_packages::signer_protocol::Target,
    rpc: &crate::rpc::CkbRpcClient,
) -> Result<(morph_packages::signer_protocol::Payload, String)> {
    use morph_packages::signer_protocol::Target;
    let target = match target {
        Target::RootExit => FundingTarget::Exit,
        Target::RootCreation => FundingTarget::Creation,
        _ => return Err(anyhow!("not a root signing target")),
    };
    let journal: FundingJournal = serde_json::from_slice(bytes)?;
    journal.validate()?;
    journal.eligible(target)?;
    ensure!(
        journal.reserved(target),
        "external root signing requires an already persisted reservation"
    );
    journal.verify_artifacts()?;
    let (_, exit) = journal.draft.evidence()?;
    journal
        .admission
        .require_fresh_with_rpc(&exit, &journal.draft.transaction()?, rpc)?;
    Ok((journal.external_payload()?, journal.local_pubkey))
}

fn read(path: &Path) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(MAX_BYTES + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MAX_BYTES,
        "funding session exceeds byte limit"
    );
    Ok(bytes)
}
fn save(path: &Path, journal: &FundingJournal) -> Result<()> {
    journal.validate()?;
    let bytes = serde_json::to_vec(journal)?;
    ensure!(
        bytes.len() as u64 <= MAX_BYTES,
        "funding session exceeds byte limit"
    );
    write_private_atomic(path, &bytes)
}
fn message(digest: &Bytes32, signature: &ParticipantSignature) -> Result<Value> {
    Ok(serde_json::to_value(SignatureMessage::new(
        digest, signature,
    ))?)
}

pub fn run(path: &Path, command: FundingSessionCommand) -> Result<Value> {
    let _lock = lock_private_path(path)?;
    if let FundingSessionCommand::Init {
        draft,
        local_pubkey,
        contracts_dir,
        admission_config,
    } = command
    {
        ensure!(
            !path.exists(),
            "signing session already exists; never reset signing history"
        );
        let draft: RootFundingDraft = serde_json::from_slice(&read(&draft)?)?;
        let (_, exit) = draft.evidence()?;
        let admission = crate::admission_channel::Binding::new(
            &admission_config,
            &contracts_dir,
            &exit,
            &draft.transaction()?,
        )?;
        let local_pubkey = canonical_hex(&decode_hex(&local_pubkey, 33)?);
        let journal = FundingJournal {
            schema: SCHEMA.to_string(),
            draft,
            local_pubkey,
            contracts_dir: contracts_dir.canonicalize()?,
            admission,
            exit_reserved: false,
            creation_reserved: false,
            exit_signatures: vec![],
            creation_signatures: vec![],
        };
        journal.verify_artifacts()?;
        journal.verify_admission()?;
        save(path, &journal)?;
        return journal.summary();
    }
    let mut journal: FundingJournal = serde_json::from_slice(&read(path)?)?;
    journal.validate()?;
    match command {
        FundingSessionCommand::Init { .. } => Err(anyhow!("funding session already initialized")),
        FundingSessionCommand::Inspect => journal.summary(),
        command
        @ (FundingSessionCommand::Sign { .. } | FundingSessionCommand::SignLocal { .. }) => {
            let (target, signer) = match command {
                FundingSessionCommand::Sign {
                    target,
                    signer_config,
                } => (
                    target,
                    crate::participant_signer::Prepared::external(
                        &signer_config,
                        path,
                        &decode_hex(&journal.local_pubkey, 33)?,
                    )?,
                ),
                FundingSessionCommand::SignLocal {
                    target,
                    private_key,
                } => (
                    target,
                    crate::participant_signer::Prepared::local(
                        &private_key,
                        &decode_hex(&journal.local_pubkey, 33)?,
                    )?,
                ),
                _ => return Err(anyhow!("invalid signing command")),
            };
            journal.verify_artifacts()?;
            journal.verify_fresh_admission()?;
            let local = decode_hex(&journal.local_pubkey, 33)?;
            journal.eligible(target)?;
            let digest = journal.digest(target)?;
            if let Some(signature) = journal
                .signatures(target)
                .iter()
                .find(|sig| sig.pubkey_sec1 == local)
            {
                return message(&digest, signature);
            }
            match target {
                FundingTarget::Exit => journal.exit_reserved = true,
                FundingTarget::Creation => journal.creation_reserved = true,
            }
            save(path, &journal)?;
            #[cfg(all(test, target_os = "linux"))]
            crate::participant_signer::tests::checkpoint("reserved");
            journal.verify_artifacts()?;
            journal.verify_fresh_admission()?;
            let signing_target = match target {
                FundingTarget::Exit => morph_packages::signer_protocol::Target::RootExit,
                FundingTarget::Creation => morph_packages::signer_protocol::Target::RootCreation,
            };
            let signature = signer.sign(signing_target, &digest, || journal.external_payload())?;
            #[cfg(all(test, target_os = "linux"))]
            crate::participant_signer::tests::checkpoint("received");
            journal.record(target, signature.clone())?;
            save(path, &journal)?;
            #[cfg(all(test, target_os = "linux"))]
            crate::participant_signer::tests::checkpoint("recorded");
            journal.verify_artifacts()?;
            journal.verify_fresh_admission()?;
            message(&digest, &signature)
        }
        FundingSessionCommand::AddSignature { target, signature } => {
            let receipt: SignatureMessage = serde_json::from_slice(&read(&signature)?)?;
            ensure!(
                receipt.schema == SIGNATURE_SCHEMA
                    && decode_hex(&receipt.signing_digest, 32)?.as_slice()
                        == journal.digest(target)?,
                "signature is for another funding target"
            );
            journal.record(
                target,
                ParticipantSignature {
                    pubkey_sec1: decode_hex(&receipt.pubkey, 33)?,
                    signature: decode_hex(&receipt.signature, 64)?,
                },
            )?;
            save(path, &journal)?;
            journal.summary()
        }
        FundingSessionCommand::Export { store_dir } => {
            let transaction = journal.transaction()?;
            let package = write_package(&store_dir, &journal.package()?)?;
            let funding = write_transaction(
                &store_dir.join("funding-intents"),
                &transaction,
                TransactionKind::Root,
            )?;
            Ok(
                json!({"transaction":funding,"recovery_package":package,"transaction_hash":canonical_hex(transaction.calc_tx_hash().as_slice()),
                "requires_wallet_authorization":true}),
            )
        }
        FundingSessionCommand::ExportRecovery { store_dir } => {
            let package = write_package(&store_dir, &journal.package()?)?;
            Ok(json!({"recovery_package":package}))
        }
        #[cfg(feature = "devnet")]
        FundingSessionCommand::Confirm {
            rpc_url,
            state_out_point,
            min_confirmations,
            archive_dir,
            contracts_dir,
        } => {
            journal.verify_artifacts()?;
            journal.eligible_for_handoff()?;
            let package = journal.package()?;
            // The peer may have withheld its creation receipt after collecting
            // ours. The retained complete exit is sufficient to authenticate
            // canonical funding and activation: confirm_initial_funding reads
            // the actual transaction and verifies both creation signatures,
            // exact custody/context and dependencies before switching this path.
            // Seal all initial votes before replacing the active path. An
            // orphaned archive is harmless if RPC validation later fails.
            let bytes = serde_json::to_vec(
                &json!({"schema":"morph.multi_asset_retired_funding_session.v1","session":journal}),
            )?;
            let archive =
                archive_dir.join(format!("root-{}.json", hex::encode(blake2b256(&bytes))));
            let _archive_lock = try_lock_private_path(&archive)?;
            if archive.exists() {
                ensure!(
                    read(&archive)? == bytes,
                    "root archive contains different evidence"
                );
                File::open(&archive)?.sync_all()?;
            } else {
                write_private_atomic(&archive, &bytes)?;
            }
            let mut result = crate::multi_asset_session::confirm_initial_funding(
                path,
                package,
                decode_hex(&journal.local_pubkey, 33)?,
                &rpc_url,
                &state_out_point,
                min_confirmations,
                &contracts_dir,
            )?;
            result["initial_funding_archive"] = json!(archive.canonicalize()?);
            Ok(result)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct TempDir(PathBuf);
    impl TempDir {
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn tempdir() -> std::io::Result<TempDir> {
        let name = format!(
            "morph-initial-funding-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let path = std::env::temp_dir().join(name);
        std::fs::create_dir(&path)?;
        Ok(TempDir(path))
    }
    fn fixture() -> (TempDir, [PathBuf; 2], [String; 2], PathBuf) {
        fixture_with_draft(
            crate::multi_asset_funding::tests::admitted_draft_fixture(),
            None,
        )
    }
    fn fixture_with_draft(
        draft: RootFundingDraft,
        rpc_url: Option<&str>,
    ) -> (TempDir, [PathBuf; 2], [String; 2], PathBuf) {
        let dir = tempdir().unwrap();
        let file = dir.path().join("draft.json");
        std::fs::write(&file, serde_json::to_vec(&draft).unwrap()).unwrap();
        let (_, exit) = draft.evidence().unwrap();
        let (admission_config, artifacts) = crate::admission_channel::tests::configuration(
            dir.path(),
            &exit,
            &draft.transaction().unwrap(),
        );
        if let Some(rpc_url) = rpc_url {
            crate::admission_channel::tests::set_rpc(&admission_config, rpc_url);
        }
        let paths = [dir.path().join("alice.json"), dir.path().join("bob.json")];
        let secrets = [hex::encode([1; 32]), hex::encode([2; 32])];
        for (path, secret) in paths.iter().zip(&secrets) {
            let key = k256::ecdsa::SigningKey::from_slice(&hex::decode(secret).unwrap()).unwrap();
            run(
                path,
                FundingSessionCommand::Init {
                    admission_config: admission_config.clone(),
                    draft: file.clone(),
                    local_pubkey: canonical_hex(key.verifying_key().to_sec1_point(true).as_bytes()),
                    contracts_dir: artifacts.clone(),
                },
            )
            .unwrap();
        }
        (dir, paths, secrets, artifacts)
    }
    fn collect(
        paths: &[PathBuf; 2],
        keys: &[String; 2],
        dir: &Path,
        target: FundingTarget,
    ) -> [PathBuf; 2] {
        let receipts = [dir.join("receipt0.json"), dir.join("receipt1.json")];
        for i in 0..2 {
            let receipt = run(
                &paths[i],
                FundingSessionCommand::SignLocal {
                    target,
                    private_key: keys[i].clone().into(),
                },
            )
            .unwrap();
            let repeated = run(
                &paths[i],
                FundingSessionCommand::SignLocal {
                    target,
                    private_key: keys[i].clone().into(),
                },
            )
            .unwrap();
            assert_eq!(receipt, repeated);
            std::fs::write(&receipts[i], serde_json::to_vec(&receipt).unwrap()).unwrap();
        }
        for i in 0..2 {
            run(
                &paths[i],
                FundingSessionCommand::AddSignature {
                    target,
                    signature: receipts[1 - i].clone(),
                },
            )
            .unwrap();
        }
        receipts
    }
    #[cfg(target_os = "linux")]
    #[path = "funding_fault_tests.rs"]
    mod fault_tests;
    #[test]
    #[cfg(target_os = "linux")]
    fn external_root_signer_requires_reserved_authority_and_recovers_a_lost_real_signature() {
        use morph_packages::signer_protocol::Target;
        use std::io::{Read, Write};
        use std::os::unix::{fs::PermissionsExt, net::UnixStream};
        let draft = crate::multi_asset_funding::tests::admitted_draft_fixture();
        let (_, recovery) = draft.evidence().unwrap();
        let rpc =
            crate::admission_channel::tests::MockRpc::start(recovery.state.header.chain_id, 100);
        let transaction = draft.transaction().unwrap();
        let capacity = transaction
            .raw()
            .outputs()
            .into_iter()
            .map(|o| u64::from(o.capacity()))
            .sum::<u64>()
            + 1000;
        // Controlled live-cell fixture, not actual chain evidence. Each exact
        // input is explicitly installed; unknown/replaced inputs fail closed.
        for input in transaction.raw().inputs() {
            rpc.set_live_cell(
                &input.previous_output(),
                &transaction
                    .raw()
                    .outputs()
                    .get(0)
                    .unwrap()
                    .as_builder()
                    .capacity(capacity)
                    .build(),
            );
        }
        let (dir, paths, keys, _) = fixture_with_draft(draft, Some(&rpc.url));
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let (config, socket, key_file) = crate::participant_signer::tests::configuration(
            dir.path(),
            &paths[0],
            &rpc.url,
            &recovery,
            &[1; 32],
        );
        let original = read(&paths[0]).unwrap();
        let mut journal: FundingJournal = serde_json::from_slice(&original).unwrap();
        let request = crate::participant_signer::tests::request(
            &config,
            Target::RootExit,
            journal.external_payload().unwrap(),
        );
        let mut child = crate::participant_signer::tests::start(&config, &key_file, &socket);
        assert!(
            morph_signer::ipc::exchange(&socket, &request, std::time::Duration::from_secs(3))
                .is_err()
        );
        assert!(!child.0.wait().unwrap().success());
        assert_eq!(read(&paths[0]).unwrap(), original);

        // Persist the real reservation but deliberately lose the generated reply.
        journal.exit_reserved = true;
        save(&paths[0], &journal).unwrap();
        let reserved = read(&paths[0]).unwrap();
        let request = crate::participant_signer::tests::request(
            &config,
            Target::RootExit,
            journal.external_payload().unwrap(),
        );
        let mut child = crate::participant_signer::tests::start(&config, &key_file, &socket);
        let mut stream = UnixStream::connect(&socket).unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let bytes = request.encode().unwrap();
        stream
            .write_all(&(bytes.len() as u32).to_be_bytes())
            .unwrap();
        stream.write_all(&bytes).unwrap();
        stream.shutdown(std::net::Shutdown::Write).unwrap();
        let mut prefix = [0; 4];
        stream.read_exact(&mut prefix).unwrap();
        assert!(u32::from_be_bytes(prefix) > 0); // Service has actually signed.
        drop(stream); // Caller never records or uses any receipt bytes.
        let _ = child.0.wait().unwrap();
        assert_eq!(read(&paths[0]).unwrap(), reserved);
        assert!(
            serde_json::from_slice::<FundingJournal>(&reserved)
                .unwrap()
                .exit_signatures
                .is_empty()
        );

        // Restart both authority reader and key process; only the same reserved
        // target is signed, then the ordinary host path verifies/records/fsyncs.
        let mut child = crate::participant_signer::tests::start(&config, &key_file, &socket);
        let receipt = run(
            &paths[0],
            FundingSessionCommand::Sign {
                target: FundingTarget::Exit,
                signer_config: config.clone(),
            },
        )
        .unwrap();
        assert!(child.0.wait().unwrap().success());
        let saved: FundingJournal = serde_json::from_slice(&read(&paths[0]).unwrap()).unwrap();
        assert!(saved.exit_reserved && saved.exit_signatures.len() == 1);
        assert_eq!(
            receipt["signing_digest"],
            canonical_hex(&journal.digest(FundingTarget::Exit).unwrap())
        );
        // Cached receipt needs no new external process or additional key call.
        assert_eq!(
            run(
                &paths[0],
                FundingSessionCommand::Sign {
                    target: FundingTarget::Exit,
                    signer_config: config.clone()
                }
            )
            .unwrap(),
            receipt
        );
        collect(&paths, &keys, dir.path(), FundingTarget::Exit);
        let mut child = crate::participant_signer::tests::start(&config, &key_file, &socket);
        run(
            &paths[0],
            FundingSessionCommand::Sign {
                target: FundingTarget::Creation,
                signer_config: config,
            },
        )
        .unwrap();
        assert!(child.0.wait().unwrap().success());
        let saved: FundingJournal = serde_json::from_slice(&read(&paths[0]).unwrap()).unwrap();
        assert!(saved.creation_reserved && saved.creation_signatures.len() == 1);
    }

    #[test]
    fn initial_ceremony_requires_full_exit_before_creation_and_exports_exact_custody() {
        let (dir, paths, keys, _) = fixture();
        let before = read(&paths[0]).unwrap();
        assert!(
            run(
                &paths[0],
                FundingSessionCommand::SignLocal {
                    target: FundingTarget::Creation,
                    private_key: keys[0].clone().into()
                }
            )
            .is_err()
        );
        assert!(
            run(
                &paths[0],
                FundingSessionCommand::SignLocal {
                    target: FundingTarget::Exit,
                    private_key: keys[1].clone().into()
                }
            )
            .is_err()
        );
        assert_eq!(read(&paths[0]).unwrap(), before);
        let receipts = collect(&paths, &keys, dir.path(), FundingTarget::Exit);
        // Even a correctly signed exit receipt is rejected in the creation role.
        let before = read(&paths[0]).unwrap();
        assert!(
            run(
                &paths[0],
                FundingSessionCommand::AddSignature {
                    target: FundingTarget::Creation,
                    signature: receipts[1].clone()
                }
            )
            .is_err()
        );
        assert_eq!(read(&paths[0]).unwrap(), before);
        assert!(
            run(
                &paths[0],
                FundingSessionCommand::Export {
                    store_dir: dir.path().join("packages")
                }
            )
            .is_err()
        );
        collect(&paths, &keys, dir.path(), FundingTarget::Creation);
        let exported = run(
            &paths[0],
            FundingSessionCommand::Export {
                store_dir: dir.path().join("packages"),
            },
        )
        .unwrap();
        let peer = run(
            &paths[1],
            FundingSessionCommand::Export {
                store_dir: dir.path().join("packages"),
            },
        )
        .unwrap();
        assert_eq!(exported, peer);
        // Already signed evidence remains exportable after artifact loss.
        let journal: FundingJournal = serde_json::from_slice(&read(&paths[0]).unwrap()).unwrap();
        std::fs::remove_file(journal.contracts_dir.join("morph-state-type")).unwrap();
        let offline = run(
            &paths[0],
            FundingSessionCommand::Export {
                store_dir: dir.path().join("packages"),
            },
        )
        .unwrap();
        assert_eq!(offline, exported);
        assert!(
            run(
                &paths[0],
                FundingSessionCommand::SignLocal {
                    target: FundingTarget::Creation,
                    private_key: keys[0].clone().into()
                }
            )
            .is_err()
        );

        let package = crate::multi_asset_packages::read_package(Path::new(
            exported["recovery_package"].as_str().unwrap(),
        ))
        .unwrap();
        let tx = packed::Transaction::from_slice(
            &std::fs::read(exported["transaction"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        validate_root_funding(&package.recovery().unwrap(), &tx).unwrap();
        assert_eq!(package.recovery().unwrap().state.header.state_number, 1);
        let original: FundingJournal = serde_json::from_slice(&read(&paths[0]).unwrap()).unwrap();
        assert_eq!(
            tx.raw().as_slice(),
            original.draft.transaction().unwrap().raw().as_slice()
        );
        assert!(
            crate::multi_asset_session::run(
                &paths[0],
                crate::multi_asset_session::SessionCommand::Inspect
            )
            .is_err()
        );
        assert!(
            run(
                &paths[0],
                FundingSessionCommand::Init {
                    admission_config: dir.path().join("admission-config.json"),
                    draft: dir.path().join("draft.json"),
                    local_pubkey: original.local_pubkey.clone(),
                    contracts_dir: original.contracts_dir.clone()
                }
            )
            .is_err()
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&paths[0]).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
    #[test]
    fn initial_reservations_survive_restart_and_reject_forged_local_receipts_and_artifact_drift() {
        let (dir, paths, keys, artifacts) = fixture();
        // Simulate process death after the durable reservation and before crypto.
        let mut journal: FundingJournal =
            serde_json::from_slice(&read(&paths[0]).unwrap()).unwrap();
        journal.exit_reserved = true;
        save(&paths[0], &journal).unwrap();
        let receipt = run(
            &paths[0],
            FundingSessionCommand::SignLocal {
                target: FundingTarget::Exit,
                private_key: keys[0].clone().into(),
            },
        )
        .unwrap();
        assert_eq!(
            receipt["signing_digest"],
            canonical_hex(&journal.digest(FundingTarget::Exit).unwrap())
        );
        let mut journal: FundingJournal =
            serde_json::from_slice(&read(&paths[0]).unwrap()).unwrap();
        let saved = read(&paths[0]).unwrap();
        journal.exit_reserved = false;
        std::fs::write(&paths[0], serde_json::to_vec(&journal).unwrap()).unwrap();
        assert!(run(&paths[0], FundingSessionCommand::Inspect).is_err());
        std::fs::write(&paths[0], &saved).unwrap();
        std::fs::write(artifacts.join("morph-state-type"), b"unapproved upgrade").unwrap();
        assert!(
            run(
                &paths[0],
                FundingSessionCommand::SignLocal {
                    target: FundingTarget::Exit,
                    private_key: keys[0].clone().into()
                }
            )
            .is_err()
        );
        assert_eq!(read(&paths[0]).unwrap(), saved);
        std::fs::write(artifacts.join("morph-state-type"), b"root-test-state-type").unwrap();
        // A changed raw body gives both votes a new identity. Receipts cannot transfer.
        let mut draft = journal.draft.clone();
        let tx = draft.transaction().unwrap();
        let raw = tx
            .raw()
            .as_builder()
            .header_deps(vec![[81u8; 32].pack()].pack())
            .build();
        let tx = tx.as_builder().raw(raw).build();
        draft.transaction_hex = canonical_hex(tx.as_slice());
        journal.draft = draft;
        journal.exit_reserved = true;
        assert!(journal.validate().is_err());
        assert_eq!(read(&paths[0]).unwrap(), saved);
        // Unknown or absent persistence fields never reconstruct a reservation.
        let mut value: Value = serde_json::from_slice(&saved).unwrap();
        value.as_object_mut().unwrap().remove("creation_reserved");
        std::fs::write(&paths[0], serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(run(&paths[0], FundingSessionCommand::Inspect).is_err());
        let _ = dir;
    }
    #[test]
    fn incomplete_initial_exit_cannot_export_or_authorize_after_peer_loss() {
        let (dir, paths, keys, _) = fixture();
        run(
            &paths[0],
            FundingSessionCommand::SignLocal {
                target: FundingTarget::Exit,
                private_key: keys[0].clone().into(),
            },
        )
        .unwrap();
        // The peer disappears before supplying its exit authorization. The
        // locally persisted partial exit must not create a usable artifact or
        // reserve a creation vote, including after reopening the journal.
        std::fs::remove_file(&paths[1]).unwrap();
        let before = read(&paths[0]).unwrap();
        let store = dir.path().join("must-not-exist");
        for command in [
            FundingSessionCommand::ExportRecovery {
                store_dir: store.clone(),
            },
            FundingSessionCommand::Export {
                store_dir: store.clone(),
            },
            FundingSessionCommand::SignLocal {
                target: FundingTarget::Creation,
                private_key: keys[0].clone().into(),
            },
        ] {
            assert!(run(&paths[0], command).is_err());
            assert_eq!(read(&paths[0]).unwrap(), before);
            assert!(!store.exists());
        }
        let inspected = run(&paths[0], FundingSessionCommand::Inspect).unwrap();
        assert_eq!(inspected["exit_signature_count"], 1);
        assert_eq!(inspected["creation_reserved"], false);
        assert_eq!(inspected["recovery_available"], false);
    }
    #[test]
    fn retained_exit_survives_withheld_creation_receipt_and_requires_local_handoff_vote() {
        let (dir, paths, keys, artifacts) = fixture();
        collect(&paths, &keys, dir.path(), FundingTarget::Exit);
        let mut journal: FundingJournal =
            serde_json::from_slice(&read(&paths[0]).unwrap()).unwrap();
        assert!(journal.eligible_for_handoff().is_err());
        // A crash after reservation alone also cannot bootstrap a fresh
        // operational authority. Resume and record this same local vote first.
        journal.creation_reserved = true;
        save(&paths[0], &journal).unwrap();
        assert!(journal.eligible_for_handoff().is_err());
        let local = run(
            &paths[0],
            FundingSessionCommand::SignLocal {
                target: FundingTarget::Creation,
                private_key: keys[0].clone().into(),
            },
        )
        .unwrap();
        let peer = run(
            &paths[1],
            FundingSessionCommand::SignLocal {
                target: FundingTarget::Creation,
                private_key: keys[1].clone().into(),
            },
        )
        .unwrap();
        assert_ne!(local["pubkey"], peer["pubkey"]);
        // Both creation approvals now exist, but a coordinator can withhold
        // the peer receipt. No peer journal, receipt or local ELF is needed to
        // extract the complete exit already retained before our approval.
        std::fs::remove_file(&paths[1]).unwrap();
        std::fs::remove_dir_all(artifacts).unwrap();
        let before = read(&paths[0]).unwrap();
        let journal: FundingJournal = serde_json::from_slice(&before).unwrap();
        journal.eligible_for_handoff().unwrap();
        assert_eq!(journal.creation_signatures.len(), 1);
        let summary = run(&paths[0], FundingSessionCommand::Inspect).unwrap();
        assert_eq!(summary["recovery_available"], true);
        assert_eq!(summary["ready_to_export"], false);
        let store = dir.path().join("retained-recovery");
        let exported = run(
            &paths[0],
            FundingSessionCommand::ExportRecovery {
                store_dir: store.clone(),
            },
        )
        .unwrap();
        let path = Path::new(exported["recovery_package"].as_str().unwrap());
        let recovery = crate::multi_asset_packages::read_package(path)
            .unwrap()
            .recovery()
            .unwrap();
        recovery.validate().unwrap();
        assert_eq!(recovery.authorization.signatures.len(), 2);
        assert_eq!(recovery.state.header.state_number, 1);
        assert_eq!(
            recovery,
            journal.exit().unwrap(),
            "recovery must remain the exact originally retained allocation"
        );
        assert_eq!(read(&paths[0]).unwrap(), before);
        assert!(!store.join("funding-intents").exists());
        assert!(
            run(
                &paths[0],
                FundingSessionCommand::Export { store_dir: store }
            )
            .is_err()
        );
        assert_eq!(read(&paths[0]).unwrap(), before);
    }
    #[test]
    fn recovery_package_cannot_bypass_initial_funding_ceremony() {
        std::thread::Builder::new()
            .stack_size(16 * 1024 * 1024)
            .spawn(|| {
                use clap::Parser;
                for command in ["init", "bind-root"] {
                    assert!(
                        crate::Cli::try_parse_from([
                            "morph-cli",
                            "multi-asset-session",
                            "--session",
                            "signer.json",
                            command
                        ])
                        .is_err()
                    );
                }
            })
            .unwrap()
            .join()
            .unwrap();
    }
    #[test]
    fn root_draft_rejects_authority_membership_and_physical_replacement() {
        let draft = crate::multi_asset_funding::tests::admitted_draft_fixture();
        draft.evidence().unwrap();
        let mut duplicate = draft.clone();
        duplicate.participants[1] = duplicate.participants[0].clone();
        assert!(duplicate.evidence().is_err());
        let mut wrong = draft.clone();
        wrong.participants.reverse();
        assert!(wrong.evidence().is_err());
        let mut tx = draft.transaction().unwrap();
        let mut outputs = tx.raw().outputs().into_iter().collect::<Vec<_>>();
        outputs[2] = outputs[2]
            .clone()
            .as_builder()
            .capacity(u64::from(outputs[2].capacity()) - 1)
            .build();
        tx = tx
            .clone()
            .as_builder()
            .raw(tx.raw().as_builder().outputs(outputs.pack()).build())
            .build();
        let mut changed = draft;
        changed.transaction_hex = canonical_hex(tx.as_slice());
        assert!(changed.evidence().is_err());
    }
    #[test]
    fn changed_admission_stops_new_signatures_without_disabling_saved_exit_exports() {
        let (dir, paths, keys, _) = fixture();
        collect(&paths, &keys, dir.path(), FundingTarget::Exit);
        let configuration = dir.path().join("admission-config.json");
        let mut changed = std::fs::read(&configuration).unwrap();
        changed.push(b'\n');
        std::fs::write(&configuration, changed).unwrap();
        let before = read(&paths[0]).unwrap();
        let error = run(
            &paths[0],
            FundingSessionCommand::SignLocal {
                target: FundingTarget::Creation,
                private_key: keys[0].clone().into(),
            },
        )
        .unwrap_err();
        assert!(error.to_string().contains("configuration changed"));
        assert_eq!(read(&paths[0]).unwrap(), before);
        std::fs::remove_file(configuration).unwrap();
        let exported = run(
            &paths[0],
            FundingSessionCommand::ExportRecovery {
                store_dir: dir.path().join("recovery"),
            },
        )
        .unwrap();
        crate::multi_asset_packages::read_package(Path::new(
            exported["recovery_package"].as_str().unwrap(),
        ))
        .unwrap()
        .recovery()
        .unwrap()
        .validate()
        .unwrap();
    }
    #[test]
    fn delayed_conditional_funding_sign_rejects_before_reserving_and_keeps_saved_exit_exportable() {
        let mock = crate::admission_channel::tests::MockRpc::start([1; 32], 100);
        let draft = crate::admission_channel::tests::root_draft(Some(200), [1; 32]);
        let (dir, paths, keys, _) = fixture_with_draft(draft, Some(&mock.url));
        mock.set_tip(200);
        let before = read(&paths[0]).unwrap();
        let error = run(
            &paths[0],
            FundingSessionCommand::SignLocal {
                target: FundingTarget::Exit,
                private_key: keys[0].clone().into(),
            },
        )
        .unwrap_err();
        assert!(error.to_string().contains("refund horizon"));
        assert_eq!(read(&paths[0]).unwrap(), before);
        mock.set_tip(100);
        collect(&paths, &keys, dir.path(), FundingTarget::Exit);
        mock.set_tip(200);
        let before = read(&paths[0]).unwrap();
        let error = run(
            &paths[0],
            FundingSessionCommand::SignLocal {
                target: FundingTarget::Creation,
                private_key: keys[0].clone().into(),
            },
        )
        .unwrap_err();
        assert!(error.to_string().contains("refund horizon"));
        assert_eq!(read(&paths[0]).unwrap(), before);
        drop(mock);
        let exported = run(
            &paths[0],
            FundingSessionCommand::ExportRecovery {
                store_dir: dir.path().join("offline-exit"),
            },
        )
        .unwrap();
        crate::multi_asset_packages::read_package(Path::new(
            exported["recovery_package"].as_str().unwrap(),
        ))
        .unwrap()
        .recovery()
        .unwrap()
        .validate()
        .unwrap();
    }
}
