//! External participant-signer review contract. This module owns no key, journal,
//! IPC or signing capability. Validating a request never grants a signing vote.
use crate::{
    capability_summary::CapabilitySummary,
    multi_asset_funding::RootFundingCollection,
    multi_asset_packages::{
        StoredMultiAssetPackage, canonical_hex, capability_summary, decode_hex,
    },
    multi_asset_signatures::SignatureMessage,
    multi_asset_splice_transaction::SpliceDraft,
    proposal::ProposalMessage,
    public_encoding::decimal,
    summaries::{PayoutSummary, payout_summary},
};
use anyhow::{Result, anyhow, ensure};
use ckb_types::{packed, prelude::*};
use morph_core::{
    Bytes32, MultiAssetChannelBackend, MultiAssetOutPoint, MultiAssetRecoveryPackage,
    MultiAssetSettlement, MultiAssetState, ParticipantSignature, StateAuthorization, blake2b256,
};
use serde::{Deserialize, Serialize};

pub const VERSION: &str = "morph.participant_signer.v1";
pub const MAX_REQUEST_BYTES: usize = 1024 * 1024;
pub const MAX_RESPONSE_BYTES: usize = 4096;
const REQUEST_DOMAIN: &[u8] = b"MORPH_EXTERNAL_PARTICIPANT_REQUEST_V1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Target {
    RootExit,
    RootCreation,
    Update,
    SpliceCreation,
    SpliceRecovery,
    SpliceBridge,
    CooperativeClose,
}
impl Target {
    pub fn domain(self) -> &'static [u8] {
        match self {
            Self::RootCreation => morph_core::hash::MULTI_ASSET_ROOT_FUNDING_DOMAIN,
            Self::SpliceBridge => morph_core::hash::MULTI_ASSET_SPLICE_DOMAIN,
            Self::CooperativeClose => morph_core::hash::MULTI_ASSET_CLOSE_DOMAIN,
            _ => morph_core::hash::MULTI_ASSET_STATE_DOMAIN,
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Payload {
    CooperativeClose {
        current: Box<StoredMultiAssetPackage>,
        draft: crate::multi_asset_close::CloseDraft,
    },
    Root {
        collection: Box<RootFundingCollection>,
    },
    Update {
        current: Box<StoredMultiAssetPackage>,
        proposal: ProposalMessage,
    },
    Splice {
        current: Box<StoredMultiAssetPackage>,
        draft: SpliceDraft,
        creation_receipts: Vec<SignatureMessage>,
        recovery_receipts: Vec<SignatureMessage>,
    },
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodeIdentity {
    pub code_hash: String,
    pub hash_type: u8,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Deployment {
    pub state_type: CodeIdentity,
    pub state_lock: CodeIdentity,
    pub vault_lock: CodeIdentity,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutputReview {
    pub index: u32,
    pub capacity: String,
    pub lock_hash: String,
    #[serde(deserialize_with = "required_option")]
    pub type_hash: Option<String>,
    pub data_hash: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransactionReview {
    pub transaction_hash: String,
    pub inputs: Vec<String>,
    pub input_capacity: String,
    pub output_capacity: String,
    pub fee: String,
    pub outputs: Vec<OutputReview>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Review {
    pub target: Target,
    pub domain: String,
    pub chain_id: String,
    pub channel_id: String,
    pub funding_context_id: String,
    #[serde(with = "decimal")]
    pub funding_epoch: u64,
    #[serde(with = "decimal")]
    pub state_number: u64,
    pub signing_digest: String,
    pub deployment: Deployment,
    pub participants: [String; 2],
    pub payout_locks: [String; 2],
    pub carrier_refund_lock_hash: String,
    pub payouts: Vec<PayoutSummary>,
    pub capability: CapabilitySummary,
    pub state_carrier_capacity: String,
    #[serde(deserialize_with = "required_option")]
    pub transaction: Option<TransactionReview>,
}
fn required_option<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> std::result::Result<Option<T>, D::Error> {
    Option::<T>::deserialize(deserializer)
}
/// Installed trust/policy inputs, supplied out-of-band by the signer operator.
/// Caller JSON never chooses an allowed key, deployment, target or network.
pub struct Policy {
    pub expected_pubkey: String,
    pub network_genesis: Bytes32,
    pub chain_id: Bytes32,
    pub deployments: Vec<Deployment>,
    pub targets: Vec<Target>,
    pub max_request_lifetime_secs: u64,
}
/// Implementations must independently resolve the exact inputs on their pinned
/// canonical chain, fail on missing/spent cells and return values in input order.
/// Never implement this by trusting capacities supplied in caller JSON.
pub trait InputResolver {
    fn resolve_live(&self, inputs: &[MultiAssetOutPoint]) -> Result<ResolvedInputs>;
}
pub struct ResolvedInputs {
    pub genesis_hash: Bytes32,
    pub capacities: Vec<u64>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub version: String,
    pub request_id: String,
    pub expected_pubkey: String,
    pub network_genesis: String,
    #[serde(with = "decimal")]
    pub expires_at_unix: u64,
    pub review: Review,
    pub payload: Payload,
}
impl std::fmt::Debug for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignerRequest")
            .field("target", &self.review.target)
            .finish_non_exhaustive()
    }
}
impl Request {
    pub fn prepare(
        payload: Payload,
        target: Target,
        expires_at_unix: u64,
        policy: &Policy,
        resolver: &dyn InputResolver,
        now: u64,
    ) -> Result<Self> {
        let review = review(&payload, target, policy, resolver)?;
        let mut request = Self {
            version: VERSION.into(),
            request_id: String::new(),
            expected_pubkey: policy.expected_pubkey.clone(),
            network_genesis: canonical_hex(&policy.network_genesis),
            expires_at_unix,
            review,
            payload,
        };
        request.request_id = request.identity()?;
        request.validate(policy, resolver, now)?;
        Ok(request)
    }
    /// Strict bounded decoding only. The signer must call validate before any
    /// durable reservation or key use; this method does not validate authority.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() <= MAX_REQUEST_BYTES,
            "signer request exceeds byte limit"
        );
        serde_json::from_slice(bytes).map_err(|_| anyhow!("invalid signer request encoding"))
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        let bytes = serde_json::to_vec(self)?;
        ensure!(
            bytes.len() <= MAX_REQUEST_BYTES,
            "signer request exceeds byte limit"
        );
        Ok(bytes)
    }
    fn identity(&self) -> Result<String> {
        let mut value = serde_json::to_value(self)?;
        value["request_id"] = serde_json::Value::String(String::new());
        value.sort_all_objects();
        let bytes = serde_json::to_vec(&value)?;
        ensure!(
            bytes.len() <= MAX_REQUEST_BYTES,
            "signer request exceeds byte limit"
        );
        let mut raw = Vec::with_capacity(REQUEST_DOMAIN.len() + bytes.len());
        raw.extend_from_slice(REQUEST_DOMAIN);
        raw.extend_from_slice(&bytes);
        Ok(canonical_hex(&blake2b256(&raw)))
    }
    /// Cheap rejection before journal/chain I/O. This is not full payload
    /// validation and never grants permission to use a key.
    pub fn validate_envelope(&self, policy: &Policy, now: u64) -> Result<()> {
        ensure!(
            self.version == VERSION && self.request_id == self.identity()?,
            "signer request identity/version mismatch"
        );
        ensure!(
            self.expected_pubkey == policy.expected_pubkey
                && self.network_genesis == canonical_hex(&policy.network_genesis),
            "signer policy identity mismatch"
        );
        ensure!(
            self.expires_at_unix > now
                && self.expires_at_unix - now <= policy.max_request_lifetime_secs,
            "signer request expired or exceeds deadline policy"
        );
        ensure!(
            policy.targets.contains(&self.review.target)
                && policy.deployments.contains(&self.review.deployment),
            "signer role/deployment not permitted"
        );
        Ok(())
    }
    pub fn validate(&self, policy: &Policy, resolver: &dyn InputResolver, now: u64) -> Result<()> {
        self.validate_envelope(policy, now)?;
        ensure!(
            self.review == review(&self.payload, self.review.target, policy, resolver)?,
            "signer request summary does not match canonical payload"
        );
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    pub version: String,
    pub request_id: String,
    pub target: Target,
    pub receipt: SignatureMessage,
}
impl std::fmt::Debug for Response {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignerResponse")
            .field("target", &self.target)
            .finish_non_exhaustive()
    }
}
impl Response {
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() <= MAX_RESPONSE_BYTES,
            "signer response exceeds byte limit"
        );
        serde_json::from_slice(bytes).map_err(|_| anyhow!("invalid signer response encoding"))
    }

    /// Verify before recording in the caller's already-reserved journal. A late
    /// valid signature remains authority; transport expiry cannot revoke it.
    pub fn verify(&self, request: &Request) -> Result<ParticipantSignature> {
        ensure!(
            request.version == VERSION && request.request_id == request.identity()?,
            "invalid original signer request"
        );
        ensure!(
            self.version == VERSION
                && self.request_id == request.request_id
                && self.target == request.review.target
                && self.receipt.pubkey == request.expected_pubkey,
            "signer response context/key mismatch"
        );
        let digest: Bytes32 = decode_hex(&request.review.signing_digest, 32)?
            .try_into()
            .map_err(|_| anyhow!("invalid signer digest"))?;
        self.receipt.verify(&digest, &request.review.participants)
    }
}
fn deployment(package: &MultiAssetRecoveryPackage) -> Result<Deployment> {
    fn identity(bytes: &[u8]) -> Result<CodeIdentity> {
        let script = packed::Script::from_slice(bytes)?;
        Ok(CodeIdentity {
            code_hash: canonical_hex(script.code_hash().as_slice()),
            hash_type: u8::from(script.hash_type()),
        })
    }
    Ok(Deployment {
        state_type: identity(&package.scripts.state_type)?,
        state_lock: identity(&package.scripts.state_lock)?,
        vault_lock: identity(&package.scripts.vault_lock)?,
    })
}
fn receipts(
    digest: &Bytes32,
    participants: &[String; 2],
    receipts: &[SignatureMessage],
) -> Result<StateAuthorization> {
    ensure!(
        receipts.len() <= 2 && receipts.windows(2).all(|p| p[0].pubkey < p[1].pubkey),
        "unordered or duplicate signer receipts"
    );
    Ok(StateAuthorization {
        threshold: 2,
        signatures: receipts
            .iter()
            .map(|r| r.verify(digest, participants))
            .collect::<Result<_>>()?,
    })
}
fn transaction(
    tx: &packed::Transaction,
    policy: &Policy,
    resolver: &dyn InputResolver,
) -> Result<TransactionReview> {
    let raw = tx.raw();
    ensure!(
        (1..=64).contains(&raw.inputs().len()) && (1..=64).contains(&raw.outputs().len()),
        "signer transaction cell bound exceeded"
    );
    ensure!(
        raw.outputs().len() == raw.outputs_data().len(),
        "transaction output/data mismatch"
    );
    let inputs = raw
        .inputs()
        .into_iter()
        .map(|i| MultiAssetOutPoint {
            tx_hash: i.previous_output().tx_hash().unpack(),
            index: u32::from(i.previous_output().index()),
        })
        .collect::<Vec<_>>();
    let facts = resolver.resolve_live(&inputs)?;
    ensure!(
        facts.genesis_hash == policy.network_genesis && facts.capacities.len() == inputs.len(),
        "resolved input network/count mismatch"
    );
    let input_capacity = facts.capacities.iter().try_fold(0u64, |sum, value| {
        sum.checked_add(*value)
            .ok_or_else(|| anyhow!("input capacity overflow"))
    })?;
    let mut output_capacity = 0u64;
    let mut outputs = Vec::new();
    for (index, (output, data)) in raw
        .outputs()
        .into_iter()
        .zip(raw.outputs_data())
        .enumerate()
    {
        let capacity = u64::from(output.capacity());
        output_capacity = output_capacity
            .checked_add(capacity)
            .ok_or_else(|| anyhow!("output capacity overflow"))?;
        outputs.push(OutputReview {
            index: index as u32,
            capacity: capacity.to_string(),
            lock_hash: canonical_hex(output.lock().calc_script_hash().as_slice()),
            type_hash: output
                .type_()
                .to_opt()
                .map(|script| canonical_hex(script.calc_script_hash().as_slice())),
            data_hash: canonical_hex(&blake2b256(&data.raw_data())),
        });
    }
    let fee = input_capacity
        .checked_sub(output_capacity)
        .ok_or_else(|| anyhow!("transaction output exceeds resolved input capacity"))?;
    Ok(TransactionReview {
        transaction_hash: canonical_hex(tx.calc_tx_hash().as_slice()),
        inputs: inputs
            .iter()
            .map(|p| format!("{}:{}", canonical_hex(&p.tx_hash), p.index))
            .collect(),
        input_capacity: input_capacity.to_string(),
        output_capacity: output_capacity.to_string(),
        fee: fee.to_string(),
        outputs,
    })
}
fn review(
    payload: &Payload,
    target: Target,
    policy: &Policy,
    resolver: &dyn InputResolver,
) -> Result<Review> {
    ensure!(
        policy.targets.contains(&target),
        "signing target is not permitted"
    );
    crate::canonical_fields::public(&policy.expected_pubkey)?;
    let (package, state, settlement, participants, digest, physical): (
        MultiAssetRecoveryPackage,
        MultiAssetState,
        MultiAssetSettlement,
        [String; 2],
        Bytes32,
        Option<packed::Transaction>,
    ) = match (payload, target) {
        (Payload::CooperativeClose { current, draft }, Target::CooperativeClose) => {
            let package = current.recovery()?;
            let proposal = draft.proposal(&package)?;
            let digest = proposal.signing_digest(&package)?;
            let tx = packed::Transaction::new_builder()
                .raw(proposal.raw_transaction()?)
                .build();
            (
                package.clone(),
                package.state.clone(),
                package.settlement.clone(),
                current.validate()?.signer_pubkeys,
                digest,
                Some(tx),
            )
        }
        (Payload::Root { collection }, Target::RootExit | Target::RootCreation) => {
            collection.validate()?;
            let (creation, exit) = collection.draft.evidence()?;
            let digest = if target == Target::RootCreation {
                collection.initial_exit()?.validate()?;
                collection.draft.digests()?.0
            } else {
                collection.draft.digests()?.1
            };
            let selected = if target == Target::RootCreation {
                creation
            } else {
                exit
            };
            (
                selected.clone(),
                selected.state.clone(),
                selected.settlement.clone(),
                collection.draft.participants.clone(),
                digest,
                Some(collection.draft.transaction()?),
            )
        }
        (Payload::Update { current, proposal }, Target::Update) => {
            let package = current.recovery()?;
            let decoded = proposal.proposal(&package)?;
            let mut validator = MultiAssetChannelBackend::new(
                package.clone(),
                crate::canonical_fields::public(&policy.expected_pubkey)?,
            )?;
            validator.accept_proposal(decoded.clone())?;
            let digest = decoded.signing_digest()?;
            (
                package,
                decoded.state,
                decoded.settlement,
                current.validate()?.signer_pubkeys,
                digest,
                None,
            )
        }
        (
            Payload::Splice {
                current,
                draft,
                creation_receipts,
                recovery_receipts,
            },
            Target::SpliceCreation | Target::SpliceRecovery | Target::SpliceBridge,
        ) => {
            let package = current.recovery()?;
            let keys = current.validate()?.signer_pubkeys;
            let mut plan = draft.proposal(&package)?;
            plan.new_state_authorization =
                receipts(&plan.new_state.signing_digest()?, &keys, creation_receipts)?;
            plan.initial_recovery_authorization = receipts(
                &plan
                    .initial_recovery_contents(&package)?
                    .state
                    .signing_digest()?,
                &keys,
                recovery_receipts,
            )?;
            let mut validator = MultiAssetChannelBackend::new(
                package.clone(),
                crate::canonical_fields::public(&policy.expected_pubkey)?,
            )?;
            validator.prepare_splice(plan.clone())?;
            let recovery = plan.initial_recovery_contents(&package)?;
            let (state, digest) = match target {
                Target::SpliceCreation => {
                    (plan.new_state.clone(), plan.new_state.signing_digest()?)
                }
                Target::SpliceRecovery => {
                    (recovery.state.clone(), recovery.state.signing_digest()?)
                }
                Target::SpliceBridge => (package.state.clone(), plan.signing_digest(&package)?),
                _ => return Err(anyhow!("invalid splice target")),
            };
            // The review describes resulting custody and payouts even for the
            // old-context bridge. Its signing context still comes from `state`.
            (
                recovery,
                state,
                plan.new_settlement,
                keys,
                digest,
                Some(draft.transaction()?),
            )
        }
        _ => return Err(anyhow!("payload cannot authorize this signing target")),
    };
    ensure!(
        participants.contains(&policy.expected_pubkey),
        "signer is not a participant"
    );
    ensure!(
        state.header.chain_id == policy.chain_id,
        "signed chain identity differs from policy"
    );
    let deployment = deployment(&package)?;
    ensure!(
        policy.deployments.contains(&deployment),
        "deployment is not permitted"
    );
    let capability_state = if target == Target::SpliceBridge {
        &package.state
    } else {
        &state
    };
    let capability = capability_summary(&settlement, capability_state)?;
    Ok(Review {
        target,
        domain: canonical_hex(target.domain()),
        chain_id: canonical_hex(&state.header.chain_id),
        channel_id: canonical_hex(&state.header.channel_id),
        funding_context_id: canonical_hex(&state.funding_context_id()?),
        funding_epoch: state.header.funding_epoch,
        state_number: state.header.state_number,
        signing_digest: canonical_hex(&digest),
        deployment,
        participants,
        payout_locks: settlement
            .participant_lock_hashes
            .map(|h| canonical_hex(&h)),
        carrier_refund_lock_hash: canonical_hex(&settlement.carrier_refund_lock_hash),
        payouts: payout_summary(&settlement),
        capability,
        state_carrier_capacity: package.state_carrier_capacity.to_string(),
        transaction: physical
            .as_ref()
            .map(|tx| transaction(tx, policy, resolver))
            .transpose()?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner};
    use serde_json::{Value, json};
    struct Resolver {
        genesis: Bytes32,
        points: Vec<MultiAssetOutPoint>,
        capacities: Vec<u64>,
    }
    impl InputResolver for Resolver {
        fn resolve_live(&self, inputs: &[MultiAssetOutPoint]) -> Result<ResolvedInputs> {
            ensure!(inputs == self.points, "wrong input resolution request");
            Ok(ResolvedInputs {
                genesis_hash: self.genesis,
                capacities: self.capacities.clone(),
            })
        }
    }
    fn fixture(name: &str) -> Value {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/protocol");
        serde_json::from_slice(&std::fs::read(root.join(format!("{name}.json"))).unwrap()).unwrap()
    }
    fn cases() -> Vec<(Payload, Target, Policy, Resolver, SignatureMessage)> {
        let root = fixture("multi-asset-root");
        let splice = fixture("multi-asset-splice");
        let update = fixture("multi-asset-update");
        let base: StoredMultiAssetPackage = serde_json::from_value(fixture("multi-asset")).unwrap();
        let mut cases = Vec::new();
        for target in [
            Target::RootExit,
            Target::RootCreation,
            Target::Update,
            Target::SpliceCreation,
            Target::SpliceRecovery,
            Target::SpliceBridge,
        ] {
            let (payload, package, tx, receipt) = match target {
                Target::RootExit | Target::RootCreation => {
                    let collection: RootFundingCollection =
                        serde_json::from_value(root["collection"].clone()).unwrap();
                    let (_, package) = collection.draft.evidence().unwrap();
                    let tx = collection.draft.transaction().unwrap();
                    let receipt = serde_json::from_value(
                        root[if target == Target::RootExit {
                            "exit_receipts"
                        } else {
                            "creation_receipts"
                        }][0]
                            .clone(),
                    )
                    .unwrap();
                    (
                        Payload::Root {
                            collection: Box::new(collection),
                        },
                        package,
                        Some(tx),
                        receipt,
                    )
                }
                Target::Update => {
                    let proposal = serde_json::from_value(update["proposal"].clone()).unwrap();
                    let receipt = serde_json::from_value(update["signature"].clone()).unwrap();
                    (
                        Payload::Update {
                            current: Box::new(base.clone()),
                            proposal,
                        },
                        base.recovery().unwrap(),
                        None,
                        receipt,
                    )
                }
                _ => {
                    let current: StoredMultiAssetPackage =
                        serde_json::from_value(splice["current"].clone()).unwrap();
                    let package = current.recovery().unwrap();
                    let draft: SpliceDraft =
                        serde_json::from_value(splice["draft"].clone()).unwrap();
                    let tx = draft.transaction().unwrap();
                    let receipt = serde_json::from_value(
                        splice[match target {
                            Target::SpliceCreation => "creation_receipts",
                            Target::SpliceRecovery => "recovery_receipts",
                            _ => "bridge_receipts",
                        }][0]
                            .clone(),
                    )
                    .unwrap();
                    (
                        Payload::Splice {
                            current: Box::new(current),
                            draft,
                            creation_receipts: serde_json::from_value(
                                splice["creation_receipts"].clone(),
                            )
                            .unwrap(),
                            recovery_receipts: serde_json::from_value(
                                splice["recovery_receipts"].clone(),
                            )
                            .unwrap(),
                        },
                        package,
                        Some(tx),
                        receipt,
                    )
                }
            };
            let receipt: SignatureMessage = receipt;
            let policy = Policy {
                expected_pubkey: receipt.pubkey.clone(),
                network_genesis: [91; 32],
                chain_id: package.state.header.chain_id,
                deployments: vec![deployment(&package).unwrap()],
                targets: vec![target],
                max_request_lifetime_secs: 60,
            };
            let (points, capacities) = tx
                .as_ref()
                .map(|tx| {
                    let points = tx
                        .raw()
                        .inputs()
                        .into_iter()
                        .map(|input| MultiAssetOutPoint {
                            tx_hash: input.previous_output().tx_hash().unpack(),
                            index: u32::from(input.previous_output().index()),
                        })
                        .collect::<Vec<_>>();
                    let total = tx
                        .raw()
                        .outputs()
                        .into_iter()
                        .map(|o| u64::from(o.capacity()))
                        .sum::<u64>();
                    let mut capacities = vec![0; points.len()];
                    capacities[0] = total + 1000;
                    (points, capacities)
                })
                .unwrap_or_default();
            cases.push((
                payload,
                target,
                policy,
                Resolver {
                    genesis: [91; 32],
                    points,
                    capacities,
                },
                receipt,
            ));
        }
        cases
    }
    #[test]
    fn all_six_targets_rederive_the_existing_exact_digest_and_verify_original_receipts() {
        for (payload, target, policy, resolver, receipt) in cases() {
            let request = Request::prepare(payload, target, 150, &policy, &resolver, 100).unwrap();
            assert_eq!(
                request.review.signing_digest, receipt.signing_digest,
                "{target:?}"
            );
            assert_eq!(request.review.domain, canonical_hex(target.domain()));
            if let Some(tx) = &request.review.transaction {
                assert_eq!(tx.fee, "1000");
                assert_eq!(tx.inputs.len(), resolver.points.len());
            }
            let encoded = request.encode().unwrap();
            let decoded = Request::decode(&encoded).unwrap();
            decoded.validate(&policy, &resolver, 101).unwrap();
            let response = Response {
                version: VERSION.into(),
                request_id: request.request_id.clone(),
                target,
                receipt,
            };
            response.verify(&request).unwrap();
            Response::decode(&serde_json::to_vec(&response).unwrap())
                .unwrap()
                .verify(&request)
                .unwrap();
            assert!(!format!("{request:?}").contains("transaction_hex"));
            assert!(!format!("{response:?}").contains(&response.receipt.signature));
            // The canonical verifier also rejects the alternate high-s encoding
            // of a valid ECDSA signature; transport does not normalize it.
            let mut high = response.clone();
            let mut bytes = decode_hex(&high.receipt.signature, 64).unwrap();
            let order =
                hex::decode("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
                    .unwrap();
            let mut borrow = false;
            for index in (0..32).rev() {
                let (value, first) = order[index].overflowing_sub(bytes[32 + index]);
                let (value, second) = value.overflowing_sub(u8::from(borrow));
                bytes[32 + index] = value;
                borrow = first || second;
            }
            high.receipt.signature = canonical_hex(&bytes);
            assert!(high.verify(&request).is_err());
            let mut missing = serde_json::to_value(&request).unwrap();
            missing["review"]
                .as_object_mut()
                .unwrap()
                .remove("transaction");
            assert!(Request::decode(&serde_json::to_vec(&missing).unwrap()).is_err());
        }
    }
    #[test]
    fn summaries_policy_context_and_deadlines_cannot_substitute_for_payload_validation() {
        for (payload, target, mut policy, mut resolver, receipt) in cases() {
            let request = Request::prepare(payload, target, 150, &policy, &resolver, 100).unwrap();
            assert!(request.validate(&policy, &resolver, 150).is_err());
            let mut bad = request.clone();
            bad.expires_at_unix = 161;
            bad.request_id = bad.identity().unwrap();
            assert!(bad.validate(&policy, &resolver, 100).is_err());
            let mut bad = request.clone();
            bad.review.payouts[0].allocations[0].amount = "0".into();
            bad.review.carrier_refund_lock_hash = canonical_hex(&[99; 32]);
            bad.request_id = bad.identity().unwrap();
            assert!(bad.validate(&policy, &resolver, 100).is_err());
            let mut bad = request.clone();
            bad.review.domain = canonical_hex(b"wallet");
            bad.request_id = bad.identity().unwrap();
            assert!(bad.validate(&policy, &resolver, 100).is_err());
            let mut bad = request.clone();
            bad.review.funding_context_id = canonical_hex(&[99; 32]);
            bad.request_id = bad.identity().unwrap();
            assert!(bad.validate(&policy, &resolver, 100).is_err());
            policy.chain_id = [99; 32];
            assert!(request.validate(&policy, &resolver, 100).is_err());
            policy.chain_id = crate::canonical_fields::hash(&request.review.chain_id).unwrap();
            policy.targets.clear();
            assert!(request.validate(&policy, &resolver, 100).is_err());
            policy.targets.push(target);
            policy.deployments.clear();
            assert!(request.validate(&policy, &resolver, 100).is_err());
            policy.deployments.push(request.review.deployment.clone());
            if request.review.transaction.is_some() {
                resolver.genesis = [99; 32];
                assert!(request.validate(&policy, &resolver, 100).is_err());
                resolver.genesis = policy.network_genesis;
                resolver.capacities.pop();
                assert!(request.validate(&policy, &resolver, 100).is_err());
            }
            let response = Response {
                version: VERSION.into(),
                request_id: request.request_id.clone(),
                target,
                receipt,
            };
            let mut bad = response.clone();
            bad.request_id = canonical_hex(&[99; 32]);
            assert!(bad.verify(&request).is_err());
            let mut bad = response.clone();
            bad.target = if target == Target::Update {
                Target::RootExit
            } else {
                Target::Update
            };
            assert!(bad.verify(&request).is_err());
            let key = SigningKey::from_slice(&[99; 32]).unwrap();
            let digest = crate::canonical_fields::hash(&request.review.signing_digest).unwrap();
            let signature: Signature = key.sign_prehash(&digest).unwrap();
            let mut bad = response;
            bad.receipt = SignatureMessage::new(
                &digest,
                &ParticipantSignature {
                    pubkey_sec1: key.verifying_key().to_sec1_point(true).as_bytes().to_vec(),
                    signature: signature.to_bytes().to_vec(),
                },
            );
            assert!(bad.verify(&request).is_err());
        }
    }
    #[test]
    fn changing_any_frozen_physical_body_invalidates_the_existing_review_and_receipts() {
        for (payload, target, policy, resolver, _) in cases() {
            if target == Target::Update {
                continue;
            }
            let request = Request::prepare(payload, target, 150, &policy, &resolver, 100).unwrap();
            for change in 0..4 {
                let mut changed = request.clone();
                let (Payload::Root { .. } | Payload::Splice { .. }) = &changed.payload else {
                    unreachable!()
                };
                let transaction_hex = match &mut changed.payload {
                    Payload::Root { collection } => &mut collection.draft.transaction_hex,
                    Payload::Splice { draft, .. } => &mut draft.transaction_hex,
                    _ => unreachable!(),
                };
                let tx = packed::Transaction::from_slice(
                    &decode_hex(transaction_hex, MAX_REQUEST_BYTES).unwrap(),
                )
                .unwrap();
                let raw = tx.raw();
                let changed_raw = match change {
                    0 => {
                        let mut outputs = raw.outputs().into_iter().collect::<Vec<_>>();
                        let capacity = u64::from(outputs[0].capacity()) + 1;
                        outputs[0] = outputs[0].clone().as_builder().capacity(capacity).build();
                        raw.as_builder().outputs(outputs).build()
                    }
                    1 => {
                        let mut inputs = raw.inputs().into_iter().collect::<Vec<_>>();
                        let point = inputs[0]
                            .previous_output()
                            .as_builder()
                            .tx_hash([99; 32].pack())
                            .build();
                        inputs[0] = inputs[0]
                            .clone()
                            .as_builder()
                            .previous_output(point)
                            .build();
                        raw.as_builder().inputs(inputs).build()
                    }
                    2 => {
                        let mut deps = raw.cell_deps().into_iter().collect::<Vec<_>>();
                        let point = deps[0]
                            .out_point()
                            .as_builder()
                            .tx_hash([99; 32].pack())
                            .build();
                        deps[0] = deps[0].clone().as_builder().out_point(point).build();
                        raw.as_builder().cell_deps(deps).build()
                    }
                    _ => {
                        let mut outputs = raw.outputs().into_iter().collect::<Vec<_>>();
                        let lock = outputs[0]
                            .lock()
                            .as_builder()
                            .code_hash([99; 32].pack())
                            .build();
                        outputs[0] = outputs[0].clone().as_builder().lock(lock).build();
                        raw.as_builder().outputs(outputs).build()
                    }
                };
                *transaction_hex =
                    canonical_hex(tx.as_builder().raw(changed_raw).build().as_slice());
                // Even if the caller rehashes the request ID, canonical body
                // validation and review derivation must reject the substitution.
                changed.request_id = changed.identity().unwrap();
                assert!(
                    changed.validate(&policy, &resolver, 100).is_err(),
                    "{target:?}: {change}"
                );
            }
        }
    }

    #[test]
    fn creation_and_bridge_require_complete_future_exits_and_role_shapes_are_closed() {
        for (payload, target, policy, resolver, _) in cases() {
            if target == Target::RootCreation {
                let Payload::Root { mut collection } = payload else {
                    unreachable!()
                };
                collection.exit_signatures.pop();
                collection.creation_signatures.clear();
                assert!(
                    Request::prepare(
                        Payload::Root { collection },
                        target,
                        150,
                        &policy,
                        &resolver,
                        100
                    )
                    .is_err()
                );
            } else if target == Target::SpliceBridge {
                let Payload::Splice {
                    current,
                    draft,
                    creation_receipts,
                    mut recovery_receipts,
                } = payload
                else {
                    unreachable!()
                };
                recovery_receipts.pop();
                assert!(
                    Request::prepare(
                        Payload::Splice {
                            current,
                            draft,
                            creation_receipts,
                            recovery_receipts
                        },
                        target,
                        150,
                        &policy,
                        &resolver,
                        100
                    )
                    .is_err()
                );
            } else {
                let request =
                    Request::prepare(payload, target, 150, &policy, &resolver, 100).unwrap();
                let mut value = serde_json::to_value(&request).unwrap();
                value["review"]["target"] = json!("wallet_fee");
                assert!(Request::decode(&serde_json::to_vec(&value).unwrap()).is_err());
                let mut value = serde_json::to_value(&request).unwrap();
                value["transaction_hex"] = json!("replacement");
                assert!(Request::decode(&serde_json::to_vec(&value).unwrap()).is_err());
            }
        }
        assert!(Request::decode(&vec![b' '; MAX_REQUEST_BYTES + 1]).is_err());
        assert!(Response::decode(&vec![b' '; MAX_RESPONSE_BYTES + 1]).is_err());
    }
}
