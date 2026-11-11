//! Explicit canonical RPC data for host boundary tests; no CKB-VM execution.
use super::*;
use crate::admission_channel::tests::{MockRpc, artifact};
use ckb_types::{
    bytes::Bytes,
    core::{BlockBuilder, TransactionBuilder},
    prelude::*,
};
use morph_core::{MultiAssetSettlement, blake2b256};
use std::{os::unix::fs::PermissionsExt, time::Duration};

pub(super) struct Fixture {
    pub dir: tempfile::TempDir,
    pub paths: [PathBuf; 2],
    pub package: StoredMultiAssetPackage,
    pub rpc: MockRpc,
    pub state_point: ckb_types::packed::OutPoint,
}
fn live(
    rpc: &MockRpc,
    point: &ckb_types::packed::OutPoint,
    output: &ckb_types::packed::CellOutput,
    data: &[u8],
) {
    let point = serde_json::to_value(ckb_jsonrpc_types::OutPoint::from(point.clone())).unwrap();
    for with_data in [true, false] {
        let data = if with_data {
            json!({"content": canonical_hex(data), "hash": canonical_hex(&blake2b256(data))})
        } else {
            Value::Null
        };
        rpc.respond("get_live_cell", json!([point, with_data, false]), json!({
            "status": "live", "cell": {"output": ckb_jsonrpc_types::CellOutput::from(output.clone()), "data": data}
        }));
    }
}
pub(super) fn setup() -> Fixture {
    use crate::multi_asset_funding::{RootFundingCollection, RootFundingTarget};
    use crate::multi_asset_root_transaction::RootAuthorityHashes;
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let (mut terms, _, cells, _) = crate::multi_asset_root_transaction::tests::fixture(0, true);
    let wallet = b"canonical-test-participant-lock".to_vec();
    let rewrite = |raw: &str| {
        ckb_types::packed::Script::from_slice(&packages::decode_hex(raw, 1024).unwrap())
            .unwrap()
            .as_builder()
            .code_hash(blake2b256(&wallet).pack())
            .hash_type(2u8)
            .build()
    };
    let mut locks = terms.participant_locks_hex.each_ref().map(|s| rewrite(s));
    locks.sort_by_key(|s| s.calc_script_hash());
    terms.participant_locks_hex = locks.each_ref().map(|s| canonical_hex(s.as_slice()));
    terms.carrier_refund_lock_hex = terms.participant_locks_hex[0].clone();
    let mut settlement =
        MultiAssetSettlement::decode(&packages::decode_hex(&terms.descriptor_hex, 4096).unwrap())
            .unwrap();
    settlement.participant_lock_hashes = locks.each_ref().map(|s| s.calc_script_hash().unpack());
    settlement.carrier_refund_lock_hash = settlement.participant_lock_hashes[0];
    terms.descriptor_hex = canonical_hex(&settlement.encode().unwrap());
    let codes = [
        artifact("morph-state-type"),
        artifact("morph-state-lock"),
        artifact("morph-vault-lock"),
        wallet,
    ];
    terms.cell_deps = (0..4)
        .map(|i| packages::StoredMultiAssetCellDep {
            tx_hash: canonical_hex(&[100 + i; 32]),
            index: 0,
            dep_type: "code".into(),
        })
        .collect();
    let authority = RootAuthorityHashes {
        state_type: blake2b256(&codes[0]),
        state_lock: blake2b256(&codes[1]),
        vault_lock: blake2b256(&codes[2]),
    };
    let draft = terms
        .build([1; 32], authority, &cells, 100_000_000)
        .unwrap()
        .draft;
    let mut collection = RootFundingCollection::new(draft.clone()).unwrap();
    for target in [RootFundingTarget::Exit, RootFundingTarget::Creation] {
        for receipt in crate::multi_asset_funding::root_collection_tests::receipts(&draft, target) {
            collection.add(target, receipt).unwrap();
        }
    }
    let export = collection.export().unwrap();
    let package = export.recovery_package;
    let current = package.recovery().unwrap();
    let funding = ckb_types::packed::Transaction::from_slice(
        &packages::decode_hex(&export.transaction_hex, 256 * 1024).unwrap(),
    )
    .unwrap();
    let (config, contracts) =
        crate::admission_channel::tests::configuration(dir.path(), &current, &funding);
    let rpc = MockRpc::start([1; 32], 100);
    crate::admission_channel::tests::set_rpc(&config, &rpc.url);
    let mut active = current.state.clone();
    active.header.phase = morph_core::Phase::Active;
    active.header.state_number = 0;
    let state_output = funding.raw().outputs().get(0).unwrap();
    let state_tx = TransactionBuilder::default()
        .input(
            packed::CellInput::new_builder()
                .previous_output(
                    packed::OutPoint::new_builder()
                        .tx_hash(funding.calc_tx_hash())
                        .index(0u32)
                        .build(),
                )
                .build(),
        )
        .cell_deps(funding.raw().cell_deps().into_iter().collect::<Vec<_>>())
        .output(state_output.clone())
        .output_data(Bytes::from(active.encode().unwrap().to_vec()).pack())
        .build();
    let state_point = ckb_types::packed::OutPoint::new_builder()
        .tx_hash(state_tx.hash())
        .index(0u32)
        .build();
    let block = BlockBuilder::default()
        .number(100u64)
        .epoch(ckb_types::core::EpochNumberWithFraction::new(1, 0, 1000).full_value())
        .transactions(vec![funding.clone().into_view(), state_tx.clone()])
        .build();
    let view: ckb_jsonrpc_types::BlockView = block.clone().into();
    rpc.respond(
        "get_tip_header",
        json!([]),
        serde_json::to_value(&view.header).unwrap(),
    );
    rpc.respond(
        "get_block_by_number",
        json!(["0x64", "0x2", false]),
        serde_json::to_value(view).unwrap(),
    );
    for (index, tx) in [funding.clone().into_view(), state_tx.clone()]
        .iter()
        .enumerate()
    {
        rpc.respond("get_transaction", json!([canonical_hex(tx.hash().as_slice()), "0x2", null]), json!({
            "transaction": null, "cycles": null,
            "tx_status": {"status": "committed", "block_hash": canonical_hex(block.hash().as_slice()),
                "block_number": "0x64", "tx_index": format!("0x{index:x}"), "reason": null}
        }));
    }
    // The root State was consumed by activation; only its Vault outputs remain live.
    for (i, out) in funding.raw().outputs().into_iter().enumerate().skip(1) {
        let point = ckb_types::packed::OutPoint::new_builder()
            .tx_hash(funding.calc_tx_hash())
            .index(i as u32)
            .build();
        live(
            &rpc,
            &point,
            &out,
            &funding.raw().outputs_data().get(i).unwrap().raw_data(),
        );
    }
    live(&rpc, &state_point, &state_output, &active.encode().unwrap());
    for (dep, data) in funding.raw().cell_deps().into_iter().zip(&codes) {
        live(
            &rpc,
            &dep.out_point(),
            &ckb_types::packed::CellOutput::new_builder()
                .capacity(100_000_000_000u64)
                .build(),
            data,
        );
    }
    let paths = [dir.path().join("alice.json"), dir.path().join("bob.json")];
    for (path, key) in paths.iter().zip([1u8, 2]) {
        let pubkey = SigningKey::from_slice(&[key; 32])
            .unwrap()
            .verifying_key()
            .to_sec1_point(true)
            .as_bytes()
            .to_vec();
        confirm_initial_funding(
            path,
            package.clone(),
            pubkey,
            &rpc.url,
            &format!("{}:0", canonical_hex(state_point.tx_hash().as_slice())),
            1,
            &contracts,
        )
        .unwrap();
    }
    Fixture {
        dir,
        paths,
        package,
        rpc,
        state_point,
    }
}
#[test]
fn confirmed_rpc_fixture_passes_real_lineage_and_external_authority_checks() {
    let fixture = setup();
    let _keep = (&fixture.dir, &fixture.state_point);
    let alice = &fixture.paths[0];
    let mut settlement = fixture.package.recovery().unwrap().settlement;
    settlement.payouts[0].values[0].business_ckb -= 1;
    settlement.payouts[0].values[1].business_ckb += 1;
    super::super::run(
        alice,
        SessionCommand::Propose {
            descriptor_hex: canonical_hex(&settlement.encode().unwrap()),
        },
    )
    .unwrap();
    let mut session: StoredSession = serde_json::from_slice(&fs::read(alice).unwrap()).unwrap();
    SigningTarget::Update.reserve(&mut session.backend).unwrap();
    save(alice, &session).unwrap();
    let rpc =
        crate::rpc::CkbRpcClient::new_signer(&fixture.rpc.url, Duration::from_secs(5)).unwrap();
    external_authority(
        &fs::read(alice).unwrap(),
        morph_packages::signer_protocol::Target::Update,
        &rpc,
    )
    .unwrap();
}

impl Fixture {
    pub(super) fn prepare(&self, target: SigningTarget) {
        let current = self.package.recovery().unwrap();
        if matches!(target, SigningTarget::Update) {
            let mut settlement = current.settlement;
            settlement.payouts[0].values[0].business_ckb -= 1;
            settlement.payouts[0].values[1].business_ckb += 1;
            let proposal = super::super::run(
                &self.paths[0],
                SessionCommand::Propose {
                    descriptor_hex: canonical_hex(&settlement.encode().unwrap()),
                },
            )
            .unwrap();
            let file = self.dir.path().join("proposal.json");
            fs::write(&file, serde_json::to_vec(&proposal).unwrap()).unwrap();
            super::super::run(&self.paths[1], SessionCommand::Accept { proposal: file }).unwrap();
            return;
        }
        let deps = self
            .package
            .cell_deps
            .iter()
            .map(|dep| {
                packed::CellDep::new_builder()
                    .out_point(
                        packed::OutPoint::new_builder()
                            .tx_hash(digest(&dep.tx_hash).unwrap().pack())
                            .index(dep.index)
                            .build(),
                    )
                    .dep_type(0u8)
                    .build()
            })
            .collect();
        let draft = crate::multi_asset_splice_transaction::fixture_draft_at(
            &current,
            MultiAssetOutPoint {
                tx_hash: self.state_point.tx_hash().unpack(),
                index: 0,
            },
            deps,
        );
        let future = draft
            .proposal(&current)
            .unwrap()
            .initial_recovery_contents(&current)
            .unwrap();
        let (config, contracts) = crate::admission_channel::tests::configuration(
            self.dir.path(),
            &future,
            &draft.transaction().unwrap(),
        );
        crate::admission_channel::tests::set_rpc(&config, &self.rpc.url);
        let file = self.dir.path().join("splice-draft.json");
        fs::write(&file, serde_json::to_vec(&draft).unwrap()).unwrap();
        for path in &self.paths {
            super::super::run(
                path,
                SessionCommand::PrepareSplice {
                    admission_config: config.clone(),
                    contracts_dir: contracts.clone(),
                    draft: file.clone(),
                },
            )
            .unwrap();
        }
        if matches!(
            target,
            SigningTarget::SpliceRecovery | SigningTarget::SpliceBridge
        ) {
            self.collect(SigningTarget::SpliceCreation);
        }
        if matches!(target, SigningTarget::SpliceBridge) {
            self.collect(SigningTarget::SpliceRecovery);
        }
    }
    fn collect(&self, target: SigningTarget) {
        let receipts = self
            .paths
            .iter()
            .enumerate()
            .map(|(i, path)| {
                let signed = super::super::run(
                    path,
                    SessionCommand::SignLocal {
                        target,
                        private_key: hex::encode([i as u8 + 1; 32]).into(),
                    },
                )
                .unwrap();
                let file = self.dir.path().join(format!("{target:?}-{i}.json"));
                fs::write(&file, serde_json::to_vec(&signed).unwrap()).unwrap();
                file
            })
            .collect::<Vec<_>>();
        for (path, receipt) in self.paths.iter().zip(receipts.iter().rev()) {
            super::super::run(
                path,
                SessionCommand::AddSignature {
                    target,
                    signature: receipt.clone(),
                },
            )
            .unwrap();
        }
    }
}

#[test]
fn external_review_rechecks_canonical_status_live_vaults_and_dependency_data() {
    for failure in ["orphan", "spent-vault", "missing-dependency"] {
        let f = setup();
        f.prepare(SigningTarget::Update);
        let mut session: StoredSession =
            serde_json::from_slice(&fs::read(&f.paths[0]).unwrap()).unwrap();
        SigningTarget::Update.reserve(&mut session.backend).unwrap();
        save(&f.paths[0], &session).unwrap();
        let saved = fs::read(&f.paths[0]).unwrap();
        match failure {
            "orphan" => f.rpc.respond("get_transaction", json!([canonical_hex(f.state_point.tx_hash().as_slice()), "0x2", null]),
                json!({"transaction":null, "cycles":null, "tx_status":{"status":"unknown","block_hash":null,"block_number":null,"tx_index":null,"reason":null}})),
            "spent-vault" => f.rpc.respond("get_live_cell", json!([{"tx_hash": canonical_hex(&f.package.recovery().unwrap().outpoints[0].tx_hash), "index":"0x1"}, true, false]), json!({"status":"dead","cell":null})),
            "missing-dependency" => f.rpc.respond("get_live_cell", json!([{"tx_hash":canonical_hex(&[100;32]),"index":"0x0"}, true, false]), json!({"status":"unknown","cell":null})),
            _ => unreachable!(),
        }
        let rpc = crate::rpc::CkbRpcClient::new_signer(&f.rpc.url, Duration::from_secs(5)).unwrap();
        assert!(
            external_authority(
                &saved,
                morph_packages::signer_protocol::Target::Update,
                &rpc
            )
            .is_err(),
            "{failure}"
        );
        assert_eq!(fs::read(&f.paths[0]).unwrap(), saved);
    }
}
