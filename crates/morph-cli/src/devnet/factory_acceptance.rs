//! Actual-node acceptance through public current Factory entry points.
//! Test keys are confined to this explicitly devnet-only harness.
use super::factory_operator::{
    self as operator, ActivateOptions, PrepareOptions, SubmitOptions, WalletSignOptions,
};
use super::*;
use crate::factory_packets::{FactoryMemberTerms, FactoryRightTerms, read_request};
use crate::factory_root_transaction::{FactoryReserveTerms, FactoryRootTerms};
use crate::factory_session::{FactorySessionCommand, run as session};
use crate::funding_wallets::{FundingInput, FundingWallet};
use crate::multi_asset_packages::{StoredMultiAssetCellDep, canonical_hex};
use morph_core::{VALUE_LIMIT_POLICY_SCHEMA, ValueLimitPolicy};
use serde_json::{Value, json};

#[derive(Debug, clap::Args)]
pub(crate) struct Options {
    #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
    pub contracts_dir: PathBuf,
    #[arg(long)]
    pub store_dir: PathBuf,
    #[arg(long, default_value_t = 100_000)]
    pub fee: u64,
    #[arg(long, default_value_t = 32)]
    pub mine_blocks: u64,
    /// Rehearse exact replay by truncating the first reduced update on this isolated devnet.
    #[arg(long)]
    pub reorg: bool,
    #[arg(long, env = "MORPH_DEVNET_PRIVATE_KEY", hide_env_values = true)]
    pub private_key: String,
    #[arg(long, env = "MORPH_ALICE_PRIVATE_KEY", hide_env_values = true)]
    pub alice_private_key: String,
    #[arg(long, env = "MORPH_BOB_PRIVATE_KEY", hide_env_values = true)]
    pub bob_private_key: String,
}

fn path_field(value: &Value, name: &str) -> Result<PathBuf> {
    Ok(PathBuf::from(
        value[name]
            .as_str()
            .ok_or_else(|| anyhow!("missing {name} path"))?,
    ))
}

pub(crate) fn run(rpc: &CkbRpcClient, options: Options) -> Result<Value> {
    ensure!(
        rpc.chain_info()?.chain.to_lowercase().contains("dev"),
        "Factory smoke requires isolated devnet"
    );
    ensure!(
        options.fee >= 2 && options.fee.is_multiple_of(2) && options.mine_blocks > 0,
        "Factory smoke requires an even positive fee and mining budget"
    );
    crate::persistence::create_private_directories(&options.store_dir)?;
    let directory = fs::canonicalize(&options.store_dir)?;
    let contracts_dir = fs::canonicalize(&options.contracts_dir)?;
    let owner =
        parse_privkey(&options.private_key).map_err(|_| anyhow!("invalid smoke funding key"))?;
    let alice =
        parse_privkey(&options.alice_private_key).map_err(|_| anyhow!("invalid Alice key"))?;
    let bob = parse_privkey(&options.bob_private_key).map_err(|_| anyhow!("invalid Bob key"))?;
    let owner_lock = secp256k1_lock(&owner)?;
    let members = [
        (&alice, &options.alice_private_key),
        (&bob, &options.bob_private_key),
    ];
    ensure!(
        secp256k1_lock(&alice)? != secp256k1_lock(&bob)?,
        "Factory members must be distinct"
    );
    let contracts =
        find_deployed_contracts(rpc, &contracts_dir, rpc.tip_header()?.number_value()?)?;
    let mut deps = contracts
        .iter()
        .map(|contract| contract.cell_dep.clone())
        .collect::<Vec<_>>();
    let secp = find_secp256k1_cell_dep(rpc)?;
    deps.push(secp.clone());
    deps.sort_by(|a, b| a.out_point().as_slice().cmp(b.out_point().as_slice()));
    let funding = find_largest_live_cell(rpc, &owner_lock, rpc.tip_header()?.number_value()?)?;
    let wallet_capacity = 60_000_000_000u64;
    let mut builder = TransactionBuilder::default()
        .cell_dep(secp)
        .input(CellInput::new(funding.out_point, 0));
    for (key, _) in members {
        builder = builder
            .output(
                CellOutput::new_builder()
                    .capacity(wallet_capacity)
                    .lock(secp256k1_lock(key)?)
                    .build(),
            )
            .output_data(Bytes::new().pack());
    }
    builder = builder
        .output(super::multi_asset::wallet_change(
            funding.capacity,
            2 * wallet_capacity,
            options.fee,
            &owner_lock,
        )?)
        .output_data(Bytes::new().pack());
    let funded = send_and_mine(
        rpc,
        super::multi_asset::sign_group(builder.build(), &owner, &[0])?,
        options.mine_blocks,
    )?;

    let participant_terms = members
        .iter()
        .enumerate()
        .map(|(index, (key, _))| -> Result<_> {
            Ok(FactoryMemberTerms {
                participant: canonical_hex(&[index as u8 + 1; 32]),
                pubkey: canonical_hex(&compressed_pubkey(key)?),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let mut funders = members
        .iter()
        .enumerate()
        .map(|(index, (key, _))| -> Result<_> {
            Ok(FundingWallet {
                pubkey: canonical_hex(&compressed_pubkey(key)?),
                inputs: vec![FundingInput {
                    tx_hash: funded.tx_hash.clone(),
                    index: index as u32,
                }],
                ckb_contribution: "45000000000".to_string(),
                fee_contribution: (options.fee / 2).to_string(),
                tokens: vec![],
            })
        })
        .collect::<Result<Vec<_>>>()?;
    funders.sort_by(|a, b| a.pubkey.cmp(&b.pubkey));
    let mut rights = participant_terms
        .iter()
        .map(|member| FactoryRightTerms {
            participant: member.participant.clone(),
            subchannel: canonical_hex(&[0; 32]),
            kind: morph_core::FactoryRightKind::ReserveClaim,
            asset_type: None,
            quantity: "13000000000".to_string(),
        })
        .collect::<Vec<_>>();
    // Precommit separate value rights so the native matrix can actually
    // publish the admitted one/four/ten-right ReducedRights shapes. Keep
    // the two primary ReserveClaims first for the later physical exits.
    for index in 0..10u8 {
        rights.push(FactoryRightTerms {
            participant: participant_terms[1].participant.clone(),
            subchannel: canonical_hex(&[64 + index; 32]),
            kind: morph_core::FactoryRightKind::SponsorBudgetClaim,
            asset_type: None,
            quantity: "100".to_string(),
        });
    }
    let terms = FactoryRootTerms {
        schema: "morph.factory_root_terms.v1".to_string(),
        members: participant_terms.clone(),
        rights,
        reserves: vec![FactoryReserveTerms {
            type_hash: None,
            reserve: "30000000000".to_string(),
            business_ckb: "10000000000".to_string(),
            amount: "0".to_string(),
        }],
        type_scripts_hex: vec![],
        state_carrier_capacity: "50000000000".to_string(),
        access_manifest_root: canonical_hex(&[71; 32]),
        challenge_policy_commitment: canonical_hex(&[72; 32]),
        cell_deps: deps
            .iter()
            .map(|dep| StoredMultiAssetCellDep {
                tx_hash: canonical_hex(dep.out_point().tx_hash().as_slice()),
                index: dep.out_point().index().unpack(),
                dep_type: if dep.dep_type().as_slice() == [0] {
                    "code"
                } else {
                    "dep_group"
                }
                .to_string(),
            })
            .collect(),
        funders,
    };
    let terms_path = directory.join("terms.json");
    crate::persistence::write_private_immutable(&terms_path, &serde_json::to_vec_pretty(&terms)?)?;
    let policy = ValueLimitPolicy {
        schema: VALUE_LIMIT_POLICY_SCHEMA.to_string(),
        created_unix_ms: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis()
            .try_into()?,
        max_channel_ckb_capacity: 1_000_000_000_000,
        max_xudt_amounts: Default::default(),
    };
    let policy_path = directory.join("policy.json");
    crate::persistence::write_private_immutable(
        &policy_path,
        &serde_json::to_vec_pretty(&policy)?,
    )?;
    let request_path = directory.join("root-request.json");
    let prepared = operator::prepare(
        rpc,
        PrepareOptions {
            terms: terms_path.clone(),
            contracts_dir: contracts_dir.clone(),
            policy: policy_path.clone(),
            max_fee: options.fee,
            output: request_path.clone(),
        },
    )?;
    let request = read_request(&request_path)?.decode()?;
    let request_id = canonical_hex(&request.request_id()?);
    let mut sessions = Vec::new();
    let mut receipts = Vec::new();
    for (index, (_, private)) in members.iter().enumerate() {
        let path = directory.join(format!("member-{index}.json"));
        session(
            &path,
            FactorySessionCommand::Init {
                request: request_path.clone(),
                local_participant: participant_terms[index].participant.clone(),
                policy: policy_path.clone(),
                max_fee: options.fee,
                contracts_dir: contracts_dir.clone(),
            },
        )?;
        // A wrong local key cannot reserve a number or mutate the journal.
        let before = fs::read(&path)?;
        let wrong = members[1 - index].1.clone();
        ensure!(
            session(
                &path,
                FactorySessionCommand::Sign {
                    rpc_url: rpc.endpoint().to_string(),
                    request_id: request_id.clone(),
                    private_key: wrong
                }
            )
            .is_err(),
            "wrong Factory key was accepted"
        );
        ensure!(
            fs::read(&path)? == before,
            "wrong Factory key changed signer authority"
        );
        let receipt = session(
            &path,
            FactorySessionCommand::Sign {
                rpc_url: rpc.endpoint().to_string(),
                request_id: request_id.clone(),
                private_key: (*private).clone(),
            },
        )?;
        let receipt_path = directory.join(format!("member-{index}-signature.json"));
        crate::persistence::write_private_immutable(
            &receipt_path,
            &serde_json::to_vec_pretty(&receipt)?,
        )?;
        sessions.push(path);
        receipts.push(receipt_path);
    }
    let partial_directory = directory.join("partial");
    ensure!(
        session(
            &sessions[0],
            FactorySessionCommand::Export {
                request_id: request_id.clone(),
                store_dir: partial_directory.clone()
            }
        )
        .is_err(),
        "partial Factory authorization exported"
    );
    ensure!(
        !partial_directory.exists(),
        "partial Factory authorization poisoned immutable export path"
    );
    for index in 0..2 {
        session(
            &sessions[index],
            FactorySessionCommand::AddSignature {
                request_id: request_id.clone(),
                signature: receipts[1 - index].clone(),
            },
        )?;
    }
    let export = session(
        &sessions[0],
        FactorySessionCommand::Export {
            request_id: request_id.clone(),
            store_dir: directory.join("exports"),
        },
    )?;
    let mut transaction = path_field(&export, "transaction")?;
    for (_, private) in members {
        let signed = operator::sign_wallet(
            rpc,
            WalletSignOptions {
                terms: terms_path.clone(),
                request: request_path.clone(),
                transaction,
                contracts_dir: contracts_dir.clone(),
                policy: policy_path.clone(),
                max_fee: options.fee,
                store_dir: directory.join("wallets"),
                private_key: private.clone(),
            },
        )?;
        transaction = path_field(&signed, "transaction")?;
    }
    let submitted = operator::submit(
        rpc,
        SubmitOptions {
            request: request_path.clone(),
            transaction: transaction.clone(),
            contracts_dir: contracts_dir.clone(),
            policy: policy_path.clone(),
            max_fee: options.fee,
            mine_blocks: options.mine_blocks,
            store_dir: directory.join("submitted"),
            dry_run: false,
        },
    )?;
    ensure!(
        submitted["report"]["status"] == "Committed",
        "Factory root did not commit"
    );
    let replay = operator::submit(
        rpc,
        SubmitOptions {
            request: request_path.clone(),
            transaction,
            contracts_dir: contracts_dir.clone(),
            policy: policy_path.clone(),
            max_fee: options.fee,
            mine_blocks: 0,
            store_dir: directory.join("submitted"),
            dry_run: false,
        },
    )?;
    ensure!(
        replay["canonical_replay"] == true,
        "exact committed Factory replay failed"
    );
    let fee_cell = find_largest_live_cell(rpc, &owner_lock, rpc.tip_header()?.number_value()?)?;
    let activated = operator::activate(
        rpc,
        ActivateOptions {
            request: request_path.clone(),
            fee_out_point: format_out_point(&fee_cell.out_point),
            contracts_dir: contracts_dir.clone(),
            store_dir: directory.join("activated"),
            fee: options.fee,
            max_fee: options.fee,
            mine_blocks: options.mine_blocks,
            private_key: options.private_key.clone(),
        },
    )?;
    let observed_point = activated["state_out_point"]
        .as_str()
        .ok_or_else(|| anyhow!("missing activated Factory State"))?;
    // Both original paths become operational; no second authority bootstrap.
    for path in &sessions {
        session(
            path,
            FactorySessionCommand::Confirm {
                rpc_url: rpc.endpoint().to_string(),
                request_id: request_id.clone(),
                state_out_point: Some(observed_point.to_string()),
                min_confirmations: 1,
            },
        )?;
    }

    let transitions = super::factory_transitions_acceptance::run(
        rpc,
        super::factory_transitions_acceptance::Context {
            options: &options,
            sessions: &sessions,
            cell_deps: &terms.cell_deps,
            policy: &policy_path,
        },
    )?;
    Ok(
        json!({"schema":"morph.current_factory_acceptance.v1","scope":"development node acceptance; not release approval",
        "prepared":prepared,"funded":report_json(&funded),"root":submitted,"activation":activated,"canonical_replay":replay,
        "independent_sessions":sessions,"wrong_key_preserves_journal":true,"partial_export_cannot_poison_path":true,"same_path_handoff":true,"transitions":transitions}),
    )
}

fn report_json(report: &SentTransactionReport) -> Value {
    json!({"tx_hash":report.tx_hash,"status":report.status,"metrics":report.metrics})
}
