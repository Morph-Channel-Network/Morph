//! A child's receipt is issued only after its complete valid exit is durable.
//! Parent requests contain public attestations, never the private exit package.
use crate::factory_packets::{
    StoredFactoryDelivery, StoredFactoryRequest, read_for_delivery_review,
};
use crate::multi_asset_packages::{canonical_hex, read_bounded_json, read_package, write_package};
use crate::persistence::write_private_immutable;
use anyhow::{Result, ensure};
use clap::Subcommand;
use morph_core::FactoryChildDeliveryReceipt;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

#[derive(Debug, Subcommand)]
pub(crate) enum DeliveryCommand {
    /// Retain this child's full exit before attesting possession to its parent.
    Receive {
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        child_index: u16,
        #[arg(long)]
        package: PathBuf,
        #[arg(long)]
        local_pubkey: String,
        #[arg(long)]
        store_dir: PathBuf,
        #[arg(long)]
        receipt: PathBuf,
        #[arg(long, env = "MORPH_CHANNEL_PRIVATE_KEY", hide_env_values = true)]
        private_key: String,
    },
    /// Add one verified public possession receipt to the exact parent request.
    Attach {
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        receipt: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeliveryReceipt {
    schema: String,
    request_id: String,
    transaction_hash: String,
    delivery: StoredFactoryDelivery,
}

pub(crate) fn run(command: DeliveryCommand) -> Result<Value> {
    match command {
        DeliveryCommand::Receive {
            request,
            child_index,
            package,
            local_pubkey,
            store_dir,
            receipt,
            private_key,
        } => {
            let request = read_for_delivery_review(&request)?.decode_for_delivery_review()?;
            let package = read_package(&package)?;
            let recovery = package.recovery()?;
            // A valid exit for another parent/child is not this delivery.
            // Reject it before writing anything into the recipient's store.
            request.verify_child_recovery(child_index, &recovery)?;
            let expected = crate::canonical_fields::public(&local_pubkey)?;
            ensure!(
                recovery
                    .authorization
                    .signatures
                    .iter()
                    .any(|signature| signature.pubkey_sec1 == expected),
                "delivery key is not a child participant"
            );
            let key = crate::multi_asset_signatures::channel_signing_key(&private_key, &expected)?;
            // The only child signing API rechecks complete private evidence
            // against the exact public parent intent before invoking this key.
            let saved = write_package(&store_dir, &package)?;
            let delivery =
                FactoryChildDeliveryReceipt::new_signed(&request, child_index, &recovery, &key)?;
            let message = DeliveryReceipt {
                schema: "morph.factory_child_delivery.v1".to_string(),
                request_id: canonical_hex(&request.request_id()?),
                transaction_hash: canonical_hex(&request.transaction_hash()?),
                delivery: StoredFactoryDelivery::from_core(&delivery),
            };
            write_private_immutable(&receipt, &serde_json::to_vec_pretty(&message)?)?;
            Ok(
                json!({"schema":"morph.factory_child_delivery_saved.v1","private_recovery":saved,"public_receipt":receipt,"child_index":child_index,
                "request_id":message.request_id,"transaction_hash":message.transaction_hash}),
            )
        }
        DeliveryCommand::Attach {
            request,
            receipt,
            output,
        } => attach(&request, &receipt, &output),
    }
}

fn attach(request_path: &Path, receipt_path: &Path, output: &Path) -> Result<Value> {
    let mut request = read_for_delivery_review(request_path)?.decode_for_delivery_review()?;
    let message: DeliveryReceipt = read_bounded_json(receipt_path, 4096)?;
    ensure!(
        message.schema == "morph.factory_child_delivery.v1"
            && message.request_id == canonical_hex(&request.request_id()?)
            && message.transaction_hash == canonical_hex(&request.transaction_hash()?),
        "delivery receipt belongs to another parent request"
    );
    let delivery = message.delivery.decode()?;
    delivery.verify(&request)?;
    if let Some(existing) = request.deliveries.iter().find(|existing| {
        existing.child_index == delivery.child_index && existing.pubkey_sec1 == delivery.pubkey_sec1
    }) {
        ensure!(existing == &delivery, "conflicting child delivery receipt");
    } else {
        request.deliveries.push(delivery);
        request
            .deliveries
            .sort_by(|a, b| (a.child_index, &a.pubkey_sec1).cmp(&(b.child_index, &b.pubkey_sec1)));
    }
    let stored = StoredFactoryRequest::from_delivery_review(&request)?;
    write_private_immutable(output, &serde_json::to_vec_pretty(&stored)?)?;
    stored.inspect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::factory_packets::read_request;
    use crate::multi_asset_packages::StoredMultiAssetPackage;
    use ckb_types::{packed, prelude::*};
    use k256::ecdsa::SigningKey;

    #[test]
    fn failed_private_persistence_or_acknowledgement_keeps_parent_unsigned_and_retryable() {
        let (request, members, rights, children) =
            crate::factory_journal_fixture::reduced_child_request();
        let dir = std::env::temp_dir().join(format!(
            "morph-factory-delivery-fault-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let request_path = dir.join("request.json");
        std::fs::write(
            &request_path,
            serde_json::to_vec(&StoredFactoryRequest::from_delivery_review(&request).unwrap())
                .unwrap(),
        )
        .unwrap();
        let raw = request.raw_transaction().unwrap();
        let private = StoredMultiAssetPackage::from_recovery(
            &children[0],
            &raw.cell_deps().into_iter().collect::<Vec<_>>(),
        )
        .unwrap();
        let input = dir.join("private-input.json");
        std::fs::write(&input, serde_json::to_vec(&private).unwrap()).unwrap();
        let key = SigningKey::from_slice(&[1; 32]).unwrap();
        let receive = |package: &Path, store: &Path, receipt: &Path| DeliveryCommand::Receive {
            request: request_path.clone(),
            child_index: 0,
            package: package.to_path_buf(),
            local_pubkey: canonical_hex(key.verifying_key().to_encoded_point(true).as_bytes()),
            store_dir: store.to_path_buf(),
            receipt: receipt.to_path_buf(),
            private_key: hex::encode([1; 32]),
        };
        // A complete but foreign exit is rejected before store creation.
        let foreign = dir.join("foreign.json");
        let other = crate::multi_asset_packages::fixture_package().unwrap();
        other.recovery().unwrap().validate().unwrap();
        std::fs::write(&foreign, serde_json::to_vec(&other).unwrap()).unwrap();
        let rejected_store = dir.join("foreign-store");
        let rejected_receipt = dir.join("foreign-receipt.json");
        assert!(run(receive(&foreign, &rejected_store, &rejected_receipt)).is_err());
        assert!(!rejected_store.exists() && !rejected_receipt.exists());

        // Storage failure cannot issue even the first possession receipt.
        let blocker = dir.join("not-a-directory");
        std::fs::write(&blocker, b"injected storage failure").unwrap();
        let receipt = dir.join("receipt.json");
        assert!(run(receive(&input, &blocker.join("private"), &receipt)).is_err());
        assert!(!receipt.exists());

        // Acknowledgement failure occurs only after the complete exit is
        // retained. A disconnected participant can retry without the peer.
        let store = dir.join("private-store");
        assert!(run(receive(&input, &store, &blocker.join("receipt.json"))).is_err());
        let saved = write_package(&store, &private).unwrap();
        request
            .verify_child_recovery(0, &read_package(&saved).unwrap().recovery().unwrap())
            .unwrap();
        let mut journal = morph_core::FactorySignerJournal::from_confirmed(
            request.source.clone().unwrap(),
            rights,
            members.clone(),
            members[0].participant,
        )
        .unwrap();
        assert_eq!(
            journal.prepare_request(request.clone()),
            Err(morph_core::FactoryBackendError::InvalidDelivery)
        );
        assert!(journal.active_request_id().is_none());
        run(receive(&input, &store, &receipt)).unwrap();
        let partial_path = dir.join("one-receipt.json");
        attach(&request_path, &receipt, &partial_path).unwrap();
        let partial = read_for_delivery_review(&partial_path)
            .unwrap()
            .decode_for_delivery_review()
            .unwrap();
        assert_eq!(partial.missing_delivery_receipts().unwrap().len(), 1);
        assert_eq!(
            journal.prepare_request(partial),
            Err(morph_core::FactoryBackendError::InvalidDelivery)
        );
        assert!(journal.active_request_id().is_none());
        assert_eq!(read_package(&saved).unwrap(), private);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn native_child_delivery_persists_private_exit_then_attaches_exact_public_receipts() {
        let (request, _, _, children) = crate::factory_journal_fixture::reduced_child_request();
        let packet = StoredFactoryRequest::from_delivery_review(&request).unwrap();
        let dir = std::env::temp_dir().join(format!(
            "morph-factory-delivery-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let request_path = dir.join("request.json");
        std::fs::write(&request_path, serde_json::to_vec(&packet).unwrap()).unwrap();
        assert!(read_request(&request_path).is_err());
        let raw = packed::RawTransaction::from_slice(&request.transaction).unwrap();
        let deps = raw.cell_deps().into_iter().collect::<Vec<_>>();
        let private = StoredMultiAssetPackage::from_recovery(&children[0], &deps).unwrap();
        let package_path = dir.join("private-input.json");
        std::fs::write(&package_path, serde_json::to_vec(&private).unwrap()).unwrap();
        let mut current = request_path;
        let mut first_receipt = None;
        for seed in 1u8..=2 {
            let key = SigningKey::from_slice(&[seed; 32]).unwrap();
            let receipt = dir.join(format!("receipt-{seed}.json"));
            let received = run(DeliveryCommand::Receive {
                request: current.clone(),
                child_index: 0,
                package: package_path.clone(),
                local_pubkey: canonical_hex(key.verifying_key().to_encoded_point(true).as_bytes()),
                store_dir: dir.join(format!("child-{seed}")),
                receipt: receipt.clone(),
                private_key: hex::encode([seed; 32]),
            })
            .unwrap();
            let stored = PathBuf::from(received["private_recovery"].as_str().unwrap());
            assert_eq!(read_package(&stored).unwrap(), private);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(
                    std::fs::metadata(&stored).unwrap().permissions().mode() & 0o777,
                    0o600
                );
            }
            let public = std::fs::read_to_string(&receipt).unwrap();
            assert!(!public.contains("signature_witness_hex"));
            assert!(!public.contains("recovery_package"));
            for signature in &children[0].authorization.signatures {
                assert!(!public.contains(&canonical_hex(&signature.signature)));
            }
            let message: DeliveryReceipt = serde_json::from_str(&public).unwrap();
            assert_eq!(
                message.request_id,
                canonical_hex(&request.request_id().unwrap())
            );
            let mut wrong: serde_json::Value = serde_json::from_str(&public).unwrap();
            wrong["request_id"] = json!(canonical_hex(&[91; 32]));
            let wrong_path = dir.join(format!("wrong-{seed}.json"));
            std::fs::write(&wrong_path, serde_json::to_vec(&wrong).unwrap()).unwrap();
            let rejected = dir.join(format!("rejected-{seed}.json"));
            assert!(attach(&current, &wrong_path, &rejected).is_err());
            assert!(!rejected.exists());
            let output = dir.join(format!("request-{seed}.json"));
            let summary = attach(&current, &receipt, &output).unwrap();
            assert_eq!(
                summary["missing_deliveries"].as_array().unwrap().len(),
                usize::from(2 - seed)
            );
            current = output;
            if first_receipt.is_none() {
                first_receipt = Some(receipt);
            }
        }
        let complete = read_request(&current).unwrap().decode().unwrap();
        assert_eq!(complete.deliveries.len(), 2);
        // Retrying the same attestation is idempotent, without replacing a
        // different one or publishing a private exit in the parent packet.
        let retry = dir.join("request-retry.json");
        attach(&current, &first_receipt.unwrap(), &retry).unwrap();
        assert_eq!(read_request(&retry).unwrap().decode().unwrap(), complete);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
