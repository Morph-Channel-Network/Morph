//! Read-only canonical Factory proof context. This artifact is never signer authority.
use crate::factory_packets::{FactoryMemberTerms, FactoryRightTerms, StoredFactoryCustody};
use anyhow::{Context, Result, ensure};
use morph_core::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FactoryPreparationContext {
    pub schema: String,
    pub custody: StoredFactoryCustody,
    pub members: Vec<FactoryMemberTerms>,
    pub rights: Vec<FactoryRightTerms>,
}
impl FactoryPreparationContext {
    pub(crate) fn from_journal(journal: &FactorySignerJournal) -> Result<Self> {
        journal.validate()?;
        let value = Self {
            schema: "morph.factory_preparation_context.v1".to_string(),
            custody: StoredFactoryCustody::from_core(
                journal
                    .current()
                    .context("Factory has no confirmed current custody")?,
            )?,
            members: journal
                .members()
                .iter()
                .map(FactoryMemberTerms::from_core)
                .collect(),
            rights: journal
                .current_rights()
                .context("Factory has no current proof data")?
                .iter()
                .map(FactoryRightTerms::from_core)
                .collect(),
        };
        value.decode()?;
        Ok(value)
    }
    pub(crate) fn decode(
        &self,
    ) -> Result<(
        FactoryCustody,
        Vec<FactoryParticipantKey>,
        Vec<FactoryRight>,
    )> {
        ensure!(
            self.schema == "morph.factory_preparation_context.v1",
            "unsupported Factory context schema"
        );
        let custody = self.custody.decode()?;
        let members = self
            .members
            .iter()
            .map(FactoryMemberTerms::decode)
            .collect::<Result<Vec<_>>>()?;
        let rights = self
            .rights
            .iter()
            .map(FactoryRightTerms::decode)
            .collect::<Result<Vec<_>>>()?;
        ensure!(
            factory_membership_commitment(&members)? == custody.state()?.participants_commitment(),
            "Factory context membership mismatch"
        );
        validate_factory_initial_rights(&members, &custody.manifest, &rights)?;
        ensure!(
            factory_right_sparse_root(&rights)? == custody.state()?.state_root(),
            "Factory context proof data mismatch"
        );
        Ok((custody, members, rights))
    }
}
