//! Approved local ELF identities for the one current custody family.
use anyhow::{Result, ensure};
use ckb_types::{packed, prelude::*};
use morph_core::{FactoryCustody, FactorySigningRequest, blake2b256};
use std::path::Path;

pub(crate) fn validate_custody_artifacts(custody: &FactoryCustody, directory: &Path) -> Result<()> {
    custody.validate()?;
    for (bytes, name) in [
        (&custody.state_type, "morph-factory-type"),
        (&custody.state_lock, "morph-state-lock"),
        (&custody.vault_lock, "morph-factory-vault-lock"),
    ] {
        let script = packed::Script::from_slice(bytes)?;
        ensure!(
            script.hash_type().as_slice() == [2]
                && script.code_hash().as_slice()
                    == blake2b256(&std::fs::read(directory.join(name))?),
            "Factory authority differs from approved data1 artifact {name}"
        );
    }
    Ok(())
}
pub(crate) fn validate_request_artifacts(
    request: &FactorySigningRequest,
    directory: &Path,
) -> Result<()> {
    request.validate(&request.members()?)?;
    validate_request_artifacts_for_review(request, directory)
}
pub(crate) fn validate_request_artifacts_for_review(
    request: &FactorySigningRequest,
    directory: &Path,
) -> Result<()> {
    request.validate_for_review(&request.members()?)?;
    for custody in request.source.iter().chain(&request.target) {
        validate_custody_artifacts(custody, directory)?;
    }
    for index in 0..request.child_count()? {
        let child = request.public_child(index)?;
        for (position, name) in [
            (4, "morph-state-type"),
            (5, "morph-state-lock"),
            (3, "morph-vault-lock"),
        ] {
            let script = packed::Script::from_slice(
                child
                    .evidence
                    .scripts()
                    .script(position)
                    .map_err(|error| anyhow::anyhow!("invalid child scripts: {error:?}"))?,
            )?;
            ensure!(
                script.hash_type().as_slice() == [2]
                    && script.code_hash().as_slice()
                        == blake2b256(&std::fs::read(directory.join(name))?),
                "Factory child {index} authority differs from approved data1 artifact {name}"
            );
        }
        if let Some(batch) = child
            .evidence
            .descriptor()
            .conditional()
            .map_err(|error| anyhow::anyhow!("invalid child capability: {error:?}"))?
        {
            ensure!(
                batch.hash_type() == 2
                    && batch.code_hash()
                        == blake2b256(&std::fs::read(directory.join("morph-batch-lock"))?),
                "Factory child {index} conditional executor differs from approved data1 Batch artifact"
            );
        }
    }
    Ok(())
}
