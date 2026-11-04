//! Current Factory root construction. Wallet ownership, contribution and
//! change accounting use the same implementation as bilateral funding.
use anyhow::{Context, Result, anyhow, ensure};
use ckb_types::{bytes::Bytes, core::Capacity, packed, prelude::*};
use morph_core::*;
use morph_script_common::factory_multi_asset as wire;
use serde::{Deserialize, Serialize};

use crate::canonical_fields::{decimal_u64, decimal_u128, hash};
use crate::funding_wallets::{
    FundingCell, FundingCustody, FundingWallet, build_wallet_funding, funding_points,
};
use crate::multi_asset_packages::{
    StoredMultiAssetCellDep, canonical_hex, decode_dependency_records, decode_hex,
};
use crate::persistence::required_option;

use crate::factory_packets::{FactoryMemberTerms, FactoryRightTerms};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FactoryReserveTerms {
    #[serde(deserialize_with = "required_option")]
    pub type_hash: Option<String>,
    pub reserve: String,
    pub business_ckb: String,
    pub amount: String,
}

impl FactoryReserveTerms {
    pub(crate) fn decode(&self, lock_hash: Bytes32) -> Result<MultiAssetVault> {
        Ok(MultiAssetVault {
            asset: match self.type_hash.as_deref() {
                Some(value) => VaultAsset::Xudt(hash(value)?),
                None => VaultAsset::Ckb,
            },
            lock_hash,
            value: MultiAssetValue {
                reserve: decimal_u64(&self.reserve)?,
                business_ckb: decimal_u64(&self.business_ckb)?,
                amount: decimal_u128(&self.amount)?,
            },
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FactoryRootTerms {
    pub schema: String,
    pub members: Vec<FactoryMemberTerms>,
    /// Full initial tree data is retained privately for independent proofs.
    pub rights: Vec<FactoryRightTerms>,
    pub reserves: Vec<FactoryReserveTerms>,
    pub type_scripts_hex: Vec<String>,
    pub state_carrier_capacity: String,
    pub access_manifest_root: String,
    pub challenge_policy_commitment: String,
    pub cell_deps: Vec<StoredMultiAssetCellDep>,
    pub funders: Vec<FundingWallet>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct FactoryAuthorityHashes {
    pub factory_type: Bytes32,
    pub state_lock: Bytes32,
    pub vault_lock: Bytes32,
}

pub(crate) struct FactoryRootCreation {
    pub header: wire::FactoryMultiAssetHeaderFields,
    pub manifest: MultiAssetManifest,
    pub members: Vec<FactoryParticipantKey>,
    pub rights: Vec<FactoryRight>,
    pub state_type: packed::Script,
    pub state_lock: packed::Script,
    pub vault_lock: packed::Script,
    pub type_scripts: Vec<MultiAssetTypeScript>,
    pub carrier: u64,
}

pub(crate) struct PreparedFactoryRoot {
    pub creation: FactoryRootCreation,
    pub transaction: packed::Transaction,
    pub fee: u64,
}

impl PreparedFactoryRoot {
    pub(crate) fn signing_request(&self) -> Result<FactorySigningRequest> {
        let placeholders = self
            .creation
            .members
            .iter()
            .map(|member| FactoryParticipantSignature {
                participant: member.participant,
                pubkey_sec1: member.pubkey_sec1.clone(),
                signature: vec![0; 64],
            })
            .collect::<Vec<_>>();
        let witness = encode_factory_multi_asset_state_witness(
            wire::FACTORY_STATE_WITNESS_ROOT,
            &self.creation.manifest,
            &[],
            &placeholders,
        )?;
        let request = FactorySigningRequest {
            role: FactorySigningRole::RootFunding,
            source: None,
            target: Some(self.predicted_custody()?),
            transaction: self.transaction.raw().as_slice().to_vec(),
            witness,
            target_rights: self.creation.rights.clone(),
            deliveries: vec![],
        };
        request.validate(&self.creation.members)?;
        Ok(request)
    }

    /// Predicted bound evidence is review material until canonical activation.
    /// The journal handoff independently checks its actual live State OutPoint.
    pub(crate) fn predicted_custody(&self) -> Result<FactoryCustody> {
        let tx_hash: Bytes32 = self.transaction.calc_tx_hash().unpack();
        let vault_outpoints = (0..self.creation.manifest.vaults.len())
            .map(|i| MultiAssetOutPoint {
                tx_hash,
                index: i as u32 + 1,
            })
            .collect::<Vec<_>>();
        let mut header = self.creation.header;
        header.outpoint_root =
            multi_asset_outpoint_commitment(&self.creation.manifest, &vault_outpoints)?;
        let custody = FactoryCustody {
            header: header
                .encode()
                .map_err(|error| anyhow!("invalid predicted Factory header: {error:?}"))?
                .to_vec(),
            state_out_point: MultiAssetOutPoint { tx_hash, index: 0 },
            manifest: self.creation.manifest.clone(),
            vault_outpoints,
            state_type: self.creation.state_type.as_slice().to_vec(),
            state_lock: self.creation.state_lock.as_slice().to_vec(),
            vault_lock: self.creation.vault_lock.as_slice().to_vec(),
            type_scripts: self.creation.type_scripts.clone(),
            state_carrier_capacity: self.creation.carrier,
        };
        custody.validate()?;
        Ok(custody)
    }
}

const FACTORY_INITIAL_ALLOCATION_DOMAIN: &[u8] = b"CKB_MORPH_FACTORY_INITIAL_ALLOCATION_V1";

fn data1(code: Bytes32, args: &[u8]) -> packed::Script {
    packed::Script::new_builder()
        .code_hash(code.pack())
        .hash_type(2u8)
        .args(args.pack())
        .build()
}

impl FactoryRootTerms {
    pub(crate) fn points(&self) -> Result<Vec<packed::OutPoint>> {
        ensure!(
            self.schema == "morph.factory_root_terms.v1",
            "unsupported Factory root terms schema"
        );
        funding_points(&self.funders)
    }

    pub(crate) fn creation(
        &self,
        chain_id: Bytes32,
        authority: FactoryAuthorityHashes,
    ) -> Result<FactoryRootCreation> {
        let points = self.points()?;
        ensure!(
            chain_id != [0; 32]
                && [
                    authority.factory_type,
                    authority.state_lock,
                    authority.vault_lock
                ]
                .iter()
                .all(|hash| *hash != [0; 32]),
            "incomplete Factory deployment identity"
        );
        ensure!(
            (2..=16).contains(&self.members.len())
                && self.rights.len() <= FACTORY_MAX_RIGHTS_SNAPSHOT,
            "Factory member/right count exceeds current bounds"
        );
        let members = self
            .members
            .iter()
            .map(FactoryMemberTerms::decode)
            .collect::<Result<Vec<_>>>()?;
        let membership = factory_membership_commitment(&members)?;
        let first_input = packed::CellInput::new_builder()
            .previous_output(points[0].clone())
            .build();
        let factory_id = blake2b256(&[first_input.as_slice(), &0u64.to_le_bytes()].concat());
        let state_type = data1(
            authority.factory_type,
            &wire::encode_factory_multi_asset_type_args(&factory_id)
                .map_err(|error| anyhow!("invalid Factory Type identity: {error:?}"))?,
        );
        let type_hash: Bytes32 = state_type.calc_script_hash().unpack();
        let state_lock = data1(authority.state_lock, &type_hash);
        let vault_lock = data1(
            authority.vault_lock,
            &[factory_id.as_slice(), type_hash.as_slice()].concat(),
        );
        ensure!(
            (1..=8).contains(&self.reserves.len()) && self.type_scripts_hex.len() <= 8,
            "Factory Vault set exceeds current bounds"
        );
        let manifest = MultiAssetManifest {
            vaults: self
                .reserves
                .iter()
                .map(|entry| entry.decode(vault_lock.calc_script_hash().unpack()))
                .collect::<Result<Vec<_>>>()?,
        };
        manifest.encode()?;
        let type_scripts = self
            .type_scripts_hex
            .iter()
            .map(|value| {
                let script = decode_hex(
                    value,
                    morph_script_common::multi_asset::MULTI_ASSET_MAX_SCRIPT_LEN,
                )?;
                packed::Script::from_slice(&script)?;
                Ok(MultiAssetTypeScript {
                    type_hash: blake2b256(&script),
                    script,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let registry = manifest.registry()?;
        ensure!(
            type_scripts
                .iter()
                .map(|entry| &entry.type_hash)
                .eq(registry.xudt_types.iter()),
            "Factory Type Scripts differ from canonical custody registry"
        );
        let rights = self
            .rights
            .iter()
            .map(FactoryRightTerms::decode)
            .collect::<Result<Vec<_>>>()?;
        validate_factory_initial_rights(&members, &manifest, &rights)?;
        let state_root = factory_right_sparse_root(&rights)?;
        let access = hash(&self.access_manifest_root)?;
        let challenge = hash(&self.challenge_policy_commitment)?;
        ensure!(
            access != [0; 32] && challenge != [0; 32],
            "Factory policy commitments must be explicit and nonzero"
        );
        let carrier = decimal_u64(&self.state_carrier_capacity)?;
        let state_output = packed::CellOutput::new_builder()
            .lock(state_lock.clone())
            .type_(Some(state_type.clone()).pack())
            .build();
        ensure!(
            carrier
                >= state_output
                    .occupied_capacity(Capacity::bytes(
                        wire::FACTORY_MULTI_ASSET_STATE_HEADER_LEN
                    )?)?
                    .as_u64(),
            "Factory State carrier is below occupied capacity"
        );
        let locality = blake2b256(
            &[
                FACTORY_INITIAL_ALLOCATION_DOMAIN,
                factory_id.as_slice(),
                state_root.as_slice(),
                membership.as_slice(),
            ]
            .concat(),
        );
        let header = wire::FactoryMultiAssetHeaderFields {
            chain_id,
            factory_id,
            update_number: 0,
            state_root,
            participants_commitment: membership,
            access_manifest_root: access,
            non_interference_digest: locality,
            challenge_policy_commitment: challenge,
            content_root: manifest.commitment()?,
            outpoint_root: [0; 32],
            vault_count: manifest.vaults.len() as u16,
        };
        header
            .encode()
            .map_err(|error| anyhow!("invalid Factory header: {error:?}"))?;
        Ok(FactoryRootCreation {
            header,
            manifest,
            members,
            rights,
            state_type,
            state_lock,
            vault_lock,
            type_scripts,
            carrier,
        })
    }

    pub(crate) fn build(
        &self,
        chain_id: Bytes32,
        authority: FactoryAuthorityHashes,
        cells: &[FundingCell],
        max_fee: u64,
    ) -> Result<PreparedFactoryRoot> {
        let creation = self.creation(chain_id, authority)?;
        let mut vaults = Vec::new();
        for vault in &creation.manifest.vaults {
            let ty = match vault.asset {
                VaultAsset::Ckb => None,
                VaultAsset::Xudt(hash) => Some(packed::Script::from_slice(
                    &creation
                        .type_scripts
                        .iter()
                        .find(|entry| entry.type_hash == hash)
                        .context("missing Factory Type Script")?
                        .script,
                )?),
            };
            let occupied = morph_script_common::multi_asset::multi_asset_occupied_capacity(
                creation.vault_lock.as_slice(),
                ty.as_ref().map(Entity::as_slice),
                if ty.is_some() { 16 } else { 0 },
            )
            .map_err(|error| anyhow!("invalid Factory occupied capacity: {error:?}"))?;
            ensure!(
                occupied <= vault.value.reserve,
                "Factory reserve does not fund its Vault's occupied capacity"
            );
            let output = packed::CellOutput::new_builder()
                .capacity(vault.value.capacity()?)
                .lock(creation.vault_lock.clone())
                .type_(ty.clone().pack())
                .build();
            vaults.push((
                output,
                if ty.is_some() {
                    Bytes::from(vault.value.amount.to_le_bytes().to_vec())
                } else {
                    Bytes::new()
                },
            ));
        }
        let (transaction, fee) = build_wallet_funding(
            &self.funders,
            cells,
            FundingCustody {
                state: (
                    packed::CellOutput::new_builder()
                        .capacity(creation.carrier)
                        .lock(creation.state_lock.clone())
                        .type_(Some(creation.state_type.clone()).pack())
                        .build(),
                    Bytes::from(
                        creation
                            .header
                            .encode()
                            .map_err(|error| anyhow!("invalid Factory header: {error:?}"))?
                            .to_vec(),
                    ),
                ),
                vaults,
                type_scripts: creation.type_scripts.clone(),
            },
            decode_dependency_records(&self.cell_deps)?,
            packed::WitnessArgs::default(),
            max_fee,
        )?;
        Ok(PreparedFactoryRoot {
            creation,
            transaction,
            fee,
        })
    }

    pub(crate) fn review(&self, prepared: &PreparedFactoryRoot) -> Result<serde_json::Value> {
        let creation = &prepared.creation;
        Ok(
            serde_json::json!({"schema":"morph.factory_root_review.v1","factory_id":canonical_hex(&creation.header.factory_id),"transaction_hash":canonical_hex(prepared.transaction.calc_tx_hash().as_slice()),"member_count":creation.members.len(),"rights_count":creation.rights.len(),"state_root":canonical_hex(&creation.header.state_root),"state_carrier_capacity":creation.carrier.to_string(),"fee":prepared.fee.to_string(),"reserves":self.reserves,"funders":self.funders}),
        )
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use k256::ecdsa::SigningKey;

    pub(crate) fn fixture() -> (FactoryRootTerms, FactoryAuthorityHashes, Vec<FundingCell>) {
        let (bilateral, _, cells, _) = crate::multi_asset_root_transaction::tests::fixture(0, true);
        let members = (1u8..=2)
            .map(|id| FactoryMemberTerms {
                participant: canonical_hex(&[id; 32]),
                pubkey: canonical_hex(
                    SigningKey::from_slice(&[id; 32])
                        .unwrap()
                        .verifying_key()
                        .to_encoded_point(true)
                        .as_bytes(),
                ),
            })
            .collect::<Vec<_>>();
        let rights = members
            .iter()
            .map(|member| FactoryRightTerms {
                participant: member.participant.clone(),
                subchannel: canonical_hex(&[19; 32]),
                kind: FactoryRightKind::ReserveClaim,
                asset_type: None,
                quantity: "13000000000".to_string(),
            })
            .collect();
        let mut terms = FactoryRootTerms {
            schema: "morph.factory_root_terms.v1".to_string(),
            members,
            rights,
            reserves: vec![FactoryReserveTerms {
                type_hash: None,
                reserve: "30000000000".to_string(),
                business_ckb: "10000000000".to_string(),
                amount: "0".to_string(),
            }],
            type_scripts_hex: vec![],
            state_carrier_capacity: "50000000000".to_string(),
            access_manifest_root: canonical_hex(&[22; 32]),
            challenge_policy_commitment: canonical_hex(&[23; 32]),
            cell_deps: bilateral.cell_deps,
            funders: bilateral.funders,
        };
        terms.funders[0].ckb_contribution = "45000000000".to_string();
        terms.funders[1].ckb_contribution = "45000000000".to_string();
        (
            terms,
            FactoryAuthorityHashes {
                factory_type: [31; 32],
                state_lock: [32; 32],
                vault_lock: [33; 32],
            },
            cells,
        )
    }

    pub(crate) fn signer_fixture() -> serde_json::Value {
        let (terms, authority, cells) = fixture();
        let prepared = terms
            .build([41; 32], authority, &cells, 100_000_000)
            .unwrap();
        serde_json::json!({"request":prepared.signing_request().unwrap(), "members":prepared.creation.members,
            "terms":terms, "review":terms.review(&prepared).unwrap()})
    }

    #[test]
    fn factory_root_uses_current_header_and_shared_exact_wallet_budgets() {
        let (terms, authority, cells) = fixture();
        let prepared = terms
            .build([41; 32], authority, &cells, 100_000_000)
            .unwrap();
        assert_eq!(prepared.fee, 100_000_000);
        let raw = prepared.transaction.raw();
        assert_eq!(
            raw.outputs_data().get(0).unwrap().raw_data().len(),
            wire::FACTORY_MULTI_ASSET_STATE_HEADER_LEN
        );
        assert_eq!(
            raw.outputs().get(0).unwrap().capacity().as_slice(),
            50_000_000_000u64.to_le_bytes()
        );
        assert_eq!(
            raw.outputs().get(1).unwrap().lock().as_slice(),
            prepared.creation.vault_lock.as_slice()
        );
        assert_eq!(
            prepared.creation.header.state_root,
            factory_right_sparse_root(&prepared.creation.rights).unwrap()
        );
        let predicted = prepared.predicted_custody().unwrap();
        assert_eq!(
            predicted.vault_outpoints[0].tx_hash.as_slice(),
            prepared.transaction.calc_tx_hash().as_slice()
        );
        assert!(predicted.state().unwrap().vaults_are_bound());
        let request = prepared.signing_request().unwrap();
        assert_eq!(request.members().unwrap(), prepared.creation.members);
        assert_eq!(
            request.signing_digest().unwrap(),
            wire::FactoryMultiAssetStateHeader::parse(&prepared.creation.header.encode().unwrap(),)
                .unwrap()
                .root_funding_signing_digest(&request.transaction_hash().unwrap())
                .unwrap()
        );
        let mut wrong_role = request;
        wrong_role.role = FactorySigningRole::MetadataUpdate;
        assert!(wrong_role.validate(&prepared.creation.members).is_err());
        assert_eq!(terms.review(&prepared).unwrap()["member_count"], 2);
        let mut invalid = terms.clone();
        invalid.funders[0].ckb_contribution = "45000000001".to_string();
        assert!(
            invalid
                .build([41; 32], authority, &cells, 100_000_000)
                .is_err()
        );
    }

    #[test]
    fn factory_root_rejects_unbacked_convertible_rights_and_wrong_membership() {
        let (mut terms, authority, _) = fixture();
        terms.rights[0].quantity = "40000000001".to_string();
        assert!(terms.creation([41; 32], authority).is_err());
        terms.rights[0].quantity = "13000000000".to_string();
        terms.rights[0].participant = canonical_hex(&[99; 32]);
        assert!(terms.creation([41; 32], authority).is_err());
        let (mut terms, _, _) = fixture();
        terms.members.swap(0, 1);
        assert!(terms.creation([41; 32], authority).is_err());
    }

    #[test]
    fn factory_root_public_terms_require_canonical_decimal_and_explicit_asset_fields() {
        let (terms, authority, _) = fixture();
        let mut value = serde_json::to_value(&terms).unwrap();
        value["reserves"][0]
            .as_object_mut()
            .unwrap()
            .remove("type_hash");
        assert!(serde_json::from_value::<FactoryRootTerms>(value).is_err());
        let mut terms = terms;
        terms.reserves[0].business_ckb = "010000000000".to_string();
        assert!(terms.creation([41; 32], authority).is_err());
    }
}
