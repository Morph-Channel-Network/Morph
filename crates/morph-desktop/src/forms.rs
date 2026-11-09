//! Declarative native forms; requests are decoded into the shared typed API at dispatch.
use crate::i18n::{Language, Text};
use anyhow::{Result, anyhow, ensure};
use morph_sdk::hub::HubOperation;
use serde_json::{Map, Value};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy)]
pub enum Kind {
    Text,
    Optional,
    Number,
    Pubkeys,
    Secret,
}
#[derive(Debug, Clone, Copy)]
pub struct Field {
    pub key: &'static str,
    pub label: Text,
    pub kind: Kind,
    pub default: &'static str,
}
#[derive(Debug, Clone, Copy)]
pub struct Form {
    pub operation: HubOperation,
    pub label: Text,
    pub fields: &'static [Field],
    pub needs_id: bool,
    pub document: bool,
}
const fn field(key: &'static str, label: Text, kind: Kind, default: &'static str) -> Field {
    Field {
        key,
        label,
        kind,
        default,
    }
}
const PEER: &[Field] = &[
    field("pubkey", Text::PeerPublicKey66Hex, Kind::Text, ""),
    field("alias", Text::Alias, Kind::Text, ""),
];
const INVOICE: &[Field] = &[
    field("amount", Text::AmountIntegerBaseUnits, Kind::Text, ""),
    field("description", Text::Description, Kind::Text, ""),
    field(
        "payment_preimage",
        Text::PaymentPreimageSetPreimageORHash,
        Kind::Secret,
        "",
    ),
    field(
        "payment_hash",
        Text::PaymentHashOptional,
        Kind::Optional,
        "",
    ),
    field("expiry_secs", Text::ExpirySeconds, Kind::Number, "3600"),
    field("channel_id", Text::ChannelIdOptional, Kind::Optional, ""),
];
const CHANNEL: &[Field] = &[
    field("channel_id", Text::ChannelId, Kind::Text, ""),
    field(
        "counterparty_pubkey",
        Text::CounterpartyPublicKey,
        Kind::Text,
        "",
    ),
    field(
        "counterparty_alias",
        Text::CounterpartyAliasOptional,
        Kind::Optional,
        "",
    ),
    field("funding_context_id", Text::FundingContextId, Kind::Text, ""),
    field("local", Text::LocalBaseUnits, Kind::Text, "0"),
    field("remote", Text::RemoteBaseUnits, Kind::Text, "0"),
    field("pending", Text::PendingBaseUnits, Kind::Optional, "0"),
    field(
        "sponsor_budget",
        Text::SponsorBudgetShannons,
        Kind::Number,
        "1000000",
    ),
];
const CHILD: &[Field] = &[
    field("child_channel_id", Text::ChildChannelId, Kind::Text, ""),
    field(
        "counterparty_pubkey",
        Text::CounterpartyPublicKey,
        Kind::Text,
        "",
    ),
    field(
        "counterparty_alias",
        Text::CounterpartyAliasOptional,
        Kind::Optional,
        "",
    ),
    field("funding_context_id", Text::FundingContextId, Kind::Text, ""),
    field("local", Text::LocalBaseUnits, Kind::Text, "0"),
    field("remote", Text::RemoteBaseUnits, Kind::Text, "0"),
    field("pending", Text::PendingBaseUnits, Kind::Optional, "0"),
    field(
        "sponsor_budget",
        Text::SponsorBudgetShannons,
        Kind::Number,
        "1000000",
    ),
];
const FACTORY: &[Field] = &[
    field("factory_id", Text::FactoryId, Kind::Text, ""),
    field(
        "participant_pubkeys",
        Text::MemberPublicKeysCommaOrNewline,
        Kind::Pubkeys,
        "",
    ),
    field("reserve", Text::ReserveBaseUnits, Kind::Text, "0"),
];
macro_rules! form {
    ($op:ident,$label:expr,$fields:expr,$id:expr,$doc:expr) => {
        Form {
            operation: HubOperation::$op,
            label: $label,
            fields: $fields,
            needs_id: $id,
            document: $doc,
        }
    };
}
pub const FORMS: &[Form] = &[
    form!(Peer, Text::AddPeerRecord, PEER, false, false),
    form!(CreateInvoice, Text::CreateInvoice, INVOICE, false, false),
    form!(
        DecodeInvoice,
        Text::ImportInvoice,
        &[field(
            "encoded_invoice",
            Text::MorphBech32mInvoice,
            Kind::Text,
            ""
        )],
        false,
        false
    ),
    form!(
        SettleInvoice,
        Text::SettleInvoice,
        &[field(
            "payment_preimage",
            Text::PaymentPreimage,
            Kind::Secret,
            ""
        )],
        true,
        false
    ),
    form!(ReceiveInvoice, Text::MarkReceived, &[], true, false),
    form!(OpenChannel, Text::AddChannelRecord, CHANNEL, false, false),
    form!(
        SpliceChannel,
        Text::RecordSplice,
        &[
            field("new_funding_epoch", Text::NewFundingEpoch, Kind::Number, ""),
            field(
                "new_funding_context_id",
                Text::NewFundingContextId,
                Kind::Text,
                ""
            )
        ],
        true,
        false
    ),
    form!(
        PublishChannel,
        Text::RecordPublishedState,
        &[
            field("funding_context_id", Text::FundingContextId, Kind::Text, ""),
            field("state_number", Text::StateNumber, Kind::Number, "")
        ],
        true,
        false
    ),
    form!(FinaliseChannel, Text::RecordFinalisation, &[], true, false),
    form!(OpenFactory, Text::AddFactoryRecord, FACTORY, false, false),
    form!(
        AdvanceFactory,
        Text::AdvanceFactoryRecord,
        &[field(
            "new_update_number",
            Text::NewUpdateNumber,
            Kind::Number,
            ""
        )],
        true,
        false
    ),
    form!(
        MaterialiseChild,
        Text::RecordChildChannel,
        CHILD,
        true,
        false
    ),
    form!(
        ImportRecovery,
        Text::ImportRecoveryPackage,
        &[],
        false,
        true
    ),
    form!(
        ExportRecovery,
        Text::ExportRecoveryPackage,
        &[],
        true,
        false
    ),
    form!(ImportBatch, Text::ImportConditionalBatch, &[], false, true),
    form!(ImportRoot, Text::ImportFundingDraft, &[], false, true),
    form!(InspectRoot, Text::ReviewFundingCeremony, &[], true, false),
    form!(RootExitSignature, Text::CollectExitReceipt, &[], true, true),
    form!(
        RootCreationSignature,
        Text::CollectCreationReceipt,
        &[],
        true,
        true
    ),
    form!(ExportRoot, Text::ExportCompleteFunding, &[], true, false),
    form!(ExportState, Text::ExportWorkspace, &[], false, false),
    form!(
        PreviewRestore,
        Text::PreviewWorkspaceRestore,
        &[],
        false,
        true
    ),
    form!(Restore, Text::RestorePreviewedWorkspace, &[], false, true),
];
pub fn payload(form: &Form, fields: &BTreeMap<String, String>, token_asset: &str) -> Result<Value> {
    let mut value = Map::new();
    for field in form.fields {
        let raw = fields
            .get(field.key)
            .map(String::as_str)
            .unwrap_or("")
            .trim();
        let item = match field.kind {
            Kind::Optional | Kind::Secret if raw.is_empty() => Value::Null,
            Kind::Number => {
                let n = raw.parse::<u64>().map_err(|_| {
                    anyhow!(
                        "{} must be an unsigned integer",
                        Language::English.t(field.label)
                    )
                })?;
                ensure!(
                    n.to_string() == raw,
                    "{} must be canonical decimal",
                    Language::English.t(field.label)
                );
                Value::from(n)
            }
            Kind::Pubkeys => {
                let keys = raw
                    .split([',', '\n'])
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(|s| Value::String(s.to_owned()))
                    .collect::<Vec<_>>();
                ensure!(!keys.is_empty(), "member keys are required");
                Value::Array(keys)
            }
            _ => {
                ensure!(
                    !raw.is_empty(),
                    "{} is required",
                    Language::English.t(field.label)
                );
                Value::String(raw.to_owned())
            }
        };
        value.insert(field.key.into(), item);
    }
    if matches!(
        form.operation,
        HubOperation::CreateInvoice
            | HubOperation::OpenChannel
            | HubOperation::OpenFactory
            | HubOperation::MaterialiseChild
    ) {
        let asset = if token_asset.trim().is_empty() {
            serde_json::json!({"kind":"ckb"})
        } else {
            let hash = token_asset.trim();
            ensure!(
                hash.len() == 66
                    && hash.starts_with("0x")
                    && hash[2..]
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                "Type hash must be canonical 0x + 64 lowercase hex"
            );
            serde_json::json!({"kind":"xudt","type_hash":hash})
        };
        value.insert("asset".into(), asset);
    }
    Ok(Value::Object(value))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn amount_stays_decimal_string_and_epoch_is_checked_u64() {
        let form = FORMS
            .iter()
            .find(|f| f.operation == HubOperation::OpenChannel)
            .unwrap();
        let mut fields = form
            .fields
            .iter()
            .map(|f| {
                (
                    f.key.to_owned(),
                    if f.default.is_empty() {
                        "text".into()
                    } else {
                        f.default.into()
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();
        let amount = "170141183460469231731687303715884105727";
        fields.insert("local".into(), amount.into());
        assert_eq!(payload(form, &fields, "").unwrap()["local"], amount);
        fields.insert("sponsor_budget".into(), "18446744073709551616".into());
        assert!(payload(form, &fields, "").is_err());
    }
    #[test]
    fn sole_operation_catalog_preserves_all_public_hub_workflows() {
        assert_eq!(FORMS.len(), 23);
        for (i, form) in FORMS.iter().enumerate() {
            assert!(
                !FORMS[..i]
                    .iter()
                    .any(|other| other.operation == form.operation)
            );
        }
    }
}
