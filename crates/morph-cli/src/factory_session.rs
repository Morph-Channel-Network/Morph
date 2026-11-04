//! Independent Factory authority. Public packets are review data; only this
//! stable, locked journal can reserve a local participant's signing authority.
use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow, ensure};
use ckb_types::{bytes::Bytes, packed, prelude::*};
use clap::Subcommand;
#[cfg(feature = "devnet")]
use k256::ecdsa::{Signature, signature::hazmat::PrehashSigner};
use morph_core::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::canonical_fields::hash;
use crate::factory_packets::{FactorySignatureReceipt, StoredFactoryRequest, read_request};
use crate::multi_asset_packages::{canonical_hex, read_bounded_json};
use crate::persistence::{lock_private_path, write_private_atomic, write_private_immutable};

const SCHEMA: &str = "morph.factory_signer_session.v1";
const MAX_JOURNAL_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Subcommand)]
pub(crate) enum FactorySessionCommand {
    /// Create one participant's authority at a stable path for exact root terms.
    Init {
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        local_participant: String,
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        max_fee: u64,
        #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
        contracts_dir: PathBuf,
    },
    Inspect,
    /// Export current proof data for preparation, without copying signer authority.
    ExportContext {
        #[arg(long)]
        output: PathBuf,
    },
    Prepare {
        #[arg(long)]
        request: PathBuf,
    },
    /// Explicit alternative spend; the previous approval remains valid until spent.
    Replace {
        #[arg(long)]
        previous_request: String,
        #[arg(long)]
        request: PathBuf,
    },
    Cancel {
        #[arg(long)]
        request_id: String,
    },
    #[cfg(feature = "devnet")]
    Sign {
        #[arg(long)]
        rpc_url: String,
        #[arg(long)]
        request_id: String,
        #[arg(long, env = "MORPH_CHANNEL_PRIVATE_KEY", hide_env_values = true)]
        private_key: String,
    },
    AddSignature {
        #[arg(long)]
        request_id: String,
        #[arg(long)]
        signature: PathBuf,
    },
    /// Export a complete protocol authorization; wallet witnesses are separate.
    Export {
        #[arg(long)]
        request_id: String,
        #[arg(long)]
        store_dir: PathBuf,
    },
    #[cfg(feature = "devnet")]
    Confirm {
        #[arg(long)]
        rpc_url: String,
        #[arg(long)]
        request_id: String,
        /// Required for a retained successor; omit only for complete materialisation.
        #[arg(long)]
        state_out_point: Option<String>,
        #[arg(long)]
        min_confirmations: u64,
    },
    #[cfg(feature = "devnet")]
    Refresh {
        #[arg(long)]
        rpc_url: String,
        #[arg(long)]
        transaction_hash: String,
        #[arg(long)]
        state_out_point: String,
        #[arg(long)]
        min_confirmations: u64,
        /// Required only when a full-consent replacement changed the root data.
        #[arg(long)]
        full_request: Option<PathBuf>,
    },
    #[cfg(feature = "devnet")]
    Reconcile {
        #[arg(long)]
        rpc_url: String,
        #[arg(long)]
        context: PathBuf,
        #[arg(long)]
        min_confirmations: u64,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FactorySession {
    schema: String,
    journal: FactorySignerJournal,
    contracts_dir: PathBuf,
    policy: PathBuf,
    max_fee: u64,
}
impl FactorySession {
    fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == SCHEMA,
            "unsupported Factory signer journal schema"
        );
        ensure!(
            self.contracts_dir.is_absolute() && self.policy.is_absolute(),
            "Factory authority configuration must use absolute paths"
        );
        ensure!(self.max_fee > 0, "Factory maximum fee must be positive");
        self.journal.validate()?;
        Ok(())
    }
    fn save(&self, path: &Path) -> Result<()> {
        self.validate()?;
        let bytes = serde_json::to_vec_pretty(self)?;
        ensure!(
            bytes.len() <= MAX_JOURNAL_BYTES,
            "Factory journal exceeds its configured artifact bound"
        );
        write_private_atomic(path, &bytes)
    }
    fn admit(&self, request: &FactorySigningRequest) -> Result<()> {
        crate::value_limit::read_value_limit_policy(&self.policy)?
            .enforce(&ValueSubject::from_factory_request(request)?)?;
        crate::factory_artifacts::validate_request_artifacts(request, &self.contracts_dir)
    }
    fn inspect(&self) -> Result<Value> {
        self.validate()?;
        let active = self
            .journal
            .active_request_id()
            .map(|id| StoredFactoryRequest::from_core(self.journal.request(&id)?)?.inspect())
            .transpose()?;
        Ok(
            json!({"schema":"morph.factory_session_review.v1", "local_participant":canonical_hex(&self.journal.local_participant()),
            "current":self.journal.current().map(crate::factory_packets::StoredFactoryCustody::from_core).transpose()?,
            "active_request":active,"contracts_dir":self.contracts_dir,"policy":self.policy,
            "settlement_rule":"Only canonical source consumption settles Factory rights; replacement does not revoke earlier approvals."}),
        )
    }
}

pub(crate) fn authorized_transaction(
    request: &FactorySigningRequest,
    authorization: Vec<u8>,
) -> Result<packed::Transaction> {
    let first = match request.role {
        FactorySigningRole::RootFunding | FactorySigningRole::MetadataUpdate => {
            packed::WitnessArgs::new_builder()
                .input_type(Some(Bytes::from(authorization)).pack())
                .build()
        }
        FactorySigningRole::Materialisation | FactorySigningRole::Transition => {
            packed::WitnessArgs::new_builder()
                .output_type(Some(Bytes::from(authorization)).pack())
                .build()
        }
    };
    let raw = request.raw_transaction()?;
    let mut witnesses = vec![Bytes::new(); raw.inputs().len()];
    ensure!(!witnesses.is_empty(), "Factory request has no input");
    witnesses[0] = first.as_bytes();
    let tx = packed::Transaction::new_builder()
        .raw(raw)
        .witnesses(witnesses.pack())
        .build();
    request.verify_authorized_transaction(&tx)?;
    Ok(tx)
}

pub(crate) fn run(path: &Path, command: FactorySessionCommand) -> Result<Value> {
    let _lock = lock_private_path(path)?;
    if let FactorySessionCommand::Init {
        request,
        local_participant,
        policy,
        max_fee,
        contracts_dir,
    } = command
    {
        ensure!(!path.exists(), "Factory authority path already exists");
        let request = read_request(&request)?.decode()?;
        let journal = FactorySignerJournal::new_root(
            request.clone(),
            request.members()?,
            hash(&local_participant)?,
        )?;
        let session = FactorySession {
            schema: SCHEMA.to_string(),
            journal,
            contracts_dir: std::fs::canonicalize(contracts_dir)?,
            policy: std::fs::canonicalize(policy)?,
            max_fee,
        };
        session.admit(&request)?;
        session.save(path)?;
        return session.inspect();
    }
    let mut session: FactorySession = read_bounded_json(path, MAX_JOURNAL_BYTES)?;
    session.validate()?;
    match command {
        FactorySessionCommand::Init { .. } => unreachable_command(),
        FactorySessionCommand::Inspect => session.inspect(),
        FactorySessionCommand::ExportContext { output } => {
            let context =
                crate::factory_context::FactoryPreparationContext::from_journal(&session.journal)?;
            write_private_immutable(&output, &serde_json::to_vec_pretty(&context)?)?;
            Ok(
                json!({"schema":"morph.factory_context_export.v1","context":output,"signer_authority":false}),
            )
        }
        FactorySessionCommand::Prepare { request } => {
            let request = read_request(&request)?.decode()?;
            session.admit(&request)?;
            let id = session.journal.prepare_request(request)?;
            session.save(path)?;
            Ok(json!({"request_id":canonical_hex(&id),"prepared":true}))
        }
        FactorySessionCommand::Replace {
            previous_request,
            request,
        } => {
            let request = read_request(&request)?.decode()?;
            session.admit(&request)?;
            let id = session
                .journal
                .prepare_replacement(&hash(&previous_request)?, request)?;
            session.save(path)?;
            Ok(json!({"request_id":canonical_hex(&id),"previous_approval_remains_valid":true}))
        }
        FactorySessionCommand::Cancel { request_id } => {
            session.journal.cancel_request(&hash(&request_id)?)?;
            session.save(path)?;
            session.inspect()
        }
        #[cfg(feature = "devnet")]
        FactorySessionCommand::Sign {
            rpc_url,
            request_id,
            private_key,
        } => {
            let id = hash(&request_id)?;
            let request = session.journal.request(&id)?.clone();
            session.admit(&request)?;
            let member = session
                .journal
                .members()
                .iter()
                .find(|member| member.participant == session.journal.local_participant())
                .ok_or_else(|| anyhow!("local Factory member missing"))?;
            // Key matching precedes reservation; no signature can escape without
            // durable reservation and a complete live-chain authorization check.
            let key = crate::multi_asset_signatures::channel_signing_key(
                &private_key,
                &member.pubkey_sec1,
            )?;
            let public = member.pubkey_sec1.clone();
            let endpoint = crate::multi_asset_session_chain::rpc_endpoint(&rpc_url)?;
            let rpc = crate::rpc::CkbRpcClient::new(endpoint.as_str())?;
            let guard = crate::devnet::factory_operator::verify_request(
                &rpc,
                &request,
                &session.contracts_dir,
                session.max_fee,
            )?;
            let reservation = session.journal.reserve_signature(&id)?;
            session.save(path)?;
            crate::devnet::factory_operator::verify_checkpoint(&rpc, &guard)?;
            let signature: Signature = key
                .sign_prehash(&reservation.signing_digest)
                .map_err(|_| anyhow!("Factory signing failed"))?;
            let signature = FactoryParticipantSignature {
                participant: session.journal.local_participant(),
                pubkey_sec1: public,
                signature: signature.to_bytes().to_vec(),
            };
            session.journal.record_signature(&id, signature.clone())?;
            session.save(path)?;
            Ok(serde_json::to_value(FactorySignatureReceipt::new(
                &request, &signature,
            )?)?)
        }
        FactorySessionCommand::AddSignature {
            request_id,
            signature,
        } => {
            let id = hash(&request_id)?;
            let receipt: FactorySignatureReceipt = read_bounded_json(&signature, 4096)?;
            let signature = receipt.verify(session.journal.request(&id)?)?;
            session.journal.record_signature(&id, signature)?;
            session.save(path)?;
            session.inspect()
        }
        FactorySessionCommand::Export {
            request_id,
            store_dir,
        } => {
            let id = hash(&request_id)?;
            let request = session.journal.request(&id)?;
            let tx = authorized_transaction(request, session.journal.authorized_witness(&id)?)?;
            let packet = StoredFactoryRequest::from_core(request)?;
            let directory = store_dir.join(hex::encode(id));
            let packet_path = directory.join("request.json");
            let tx_path = directory.join("protocol-authorized.tx");
            write_private_immutable(&packet_path, &serde_json::to_vec_pretty(&packet)?)?;
            write_private_immutable(&tx_path, tx.as_slice())?;
            Ok(
                json!({"schema":"morph.factory_authorization_export.v1","request":packet_path,"transaction":tx_path,
                "request_id":canonical_hex(&id),"transaction_hash":canonical_hex(tx.calc_tx_hash().as_slice()),"broadcast":false}),
            )
        }
        #[cfg(feature = "devnet")]
        FactorySessionCommand::Confirm {
            rpc_url,
            request_id,
            state_out_point,
            min_confirmations,
        } => {
            let id = hash(&request_id)?;
            let request = session.journal.request(&id)?.clone();
            let endpoint = crate::multi_asset_session_chain::rpc_endpoint(&rpc_url)?;
            let rpc = crate::rpc::CkbRpcClient::new(endpoint.as_str())?;
            let (observed, signatures) = crate::devnet::factory_operator::confirm_request(
                &rpc,
                &request,
                state_out_point.as_deref(),
                min_confirmations,
                &session.contracts_dir,
            )?;
            for signature in signatures {
                session.journal.record_signature(&id, signature)?;
            }
            session.journal.confirm_request(&id, observed)?;
            session.save(path)?;
            session.inspect()
        }
        #[cfg(feature = "devnet")]
        FactorySessionCommand::Refresh {
            rpc_url,
            transaction_hash,
            state_out_point,
            min_confirmations,
            full_request,
        } => {
            let request = full_request
                .as_deref()
                .map(read_request)
                .transpose()?
                .map(|value| value.decode())
                .transpose()?;
            let endpoint = crate::multi_asset_session_chain::rpc_endpoint(&rpc_url)?;
            let rpc = crate::rpc::CkbRpcClient::new(endpoint.as_str())?;
            let (custody, rights) = crate::devnet::factory_operator::refresh_custody(
                &rpc,
                crate::devnet::factory_operator::RefreshOptions {
                    source: session
                        .journal
                        .current()
                        .ok_or_else(|| anyhow!("Factory has no current custody"))?,
                    rights: session
                        .journal
                        .current_rights()
                        .ok_or_else(|| anyhow!("Factory proof data missing"))?,
                    transaction_hash: &transaction_hash,
                    state_out_point: &state_out_point,
                    min_confirmations,
                    contracts_dir: &session.contracts_dir,
                    full_request: request.as_ref(),
                },
            )?;
            session.journal.observe_canonical(custody, rights)?;
            session.save(path)?;
            session.inspect()
        }
        #[cfg(feature = "devnet")]
        FactorySessionCommand::Reconcile {
            rpc_url,
            context,
            min_confirmations,
        } => {
            let context: crate::factory_context::FactoryPreparationContext =
                read_bounded_json(&context, 4 * 1024 * 1024)?;
            let (custody, members, rights) = context.decode()?;
            ensure!(
                members == session.journal.members(),
                "canonical context has another Factory membership"
            );
            let endpoint = crate::multi_asset_session_chain::rpc_endpoint(&rpc_url)?;
            let rpc = crate::rpc::CkbRpcClient::new(endpoint.as_str())?;
            let checkpoint = rpc.tip_header()?;
            crate::devnet::multi_asset_splice_operator::canonical_transaction(
                &rpc,
                custody.state_out_point.tx_hash.into(),
                min_confirmations,
            )?;
            crate::devnet::factory_operator::validate_live_custody(
                &rpc,
                &custody,
                &session.contracts_dir,
            )?;
            crate::devnet::factory_operator::verify_checkpoint(&rpc, &checkpoint)?;
            // This changes observed chain facts and keeps all earlier votes,
            // reservations and alternative approvals in the same journal.
            session.journal.observe_canonical(custody, rights)?;
            session.save(path)?;
            session.inspect()
        }
    }
}

fn unreachable_command() -> Result<Value> {
    Err(anyhow!("initial Factory command was already handled"))
}
