//! Declarative native forms; requests are decoded into the shared typed API at dispatch.
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
    pub label: &'static str,
    pub kind: Kind,
    pub default: &'static str,
}
#[derive(Debug, Clone, Copy)]
pub struct Form {
    pub operation: HubOperation,
    pub label: &'static str,
    pub fields: &'static [Field],
    pub needs_id: bool,
    pub document: bool,
}
const fn field(key: &'static str, label: &'static str, kind: Kind, default: &'static str) -> Field {
    Field {
        key,
        label,
        kind,
        default,
    }
}
const PEER: &[Field] = &[
    field("pubkey", "Peer public key (66 hex)", Kind::Text, ""),
    field("alias", "Alias", Kind::Text, ""),
];
const INVOICE: &[Field] = &[
    field("amount", "Amount (integer base units)", Kind::Text, ""),
    field("description", "Description", Kind::Text, ""),
    field(
        "payment_preimage",
        "Payment preimage (set preimage OR hash)",
        Kind::Secret,
        "",
    ),
    field(
        "payment_hash",
        "Payment hash (optional)",
        Kind::Optional,
        "",
    ),
    field("expiry_secs", "Expiry (seconds)", Kind::Number, "3600"),
    field("channel_id", "Channel id (optional)", Kind::Optional, ""),
];
const CHANNEL: &[Field] = &[
    field("channel_id", "Channel id", Kind::Text, ""),
    field(
        "counterparty_pubkey",
        "Counterparty public key",
        Kind::Text,
        "",
    ),
    field(
        "counterparty_alias",
        "Counterparty alias (optional)",
        Kind::Optional,
        "",
    ),
    field("funding_context_id", "Funding context id", Kind::Text, ""),
    field("local", "Local base units", Kind::Text, "0"),
    field("remote", "Remote base units", Kind::Text, "0"),
    field("pending", "Pending base units", Kind::Optional, "0"),
    field(
        "sponsor_budget",
        "Sponsor budget (shannons)",
        Kind::Number,
        "1000000",
    ),
];
const CHILD: &[Field] = &[
    field("child_channel_id", "Child channel id", Kind::Text, ""),
    field(
        "counterparty_pubkey",
        "Counterparty public key",
        Kind::Text,
        "",
    ),
    field(
        "counterparty_alias",
        "Counterparty alias (optional)",
        Kind::Optional,
        "",
    ),
    field("funding_context_id", "Funding context id", Kind::Text, ""),
    field("local", "Local base units", Kind::Text, "0"),
    field("remote", "Remote base units", Kind::Text, "0"),
    field("pending", "Pending base units", Kind::Optional, "0"),
    field(
        "sponsor_budget",
        "Sponsor budget (shannons)",
        Kind::Number,
        "1000000",
    ),
];
const FACTORY: &[Field] = &[
    field("factory_id", "Factory id", Kind::Text, ""),
    field(
        "participant_pubkeys",
        "Member public keys (comma or newline separated)",
        Kind::Pubkeys,
        "",
    ),
    field("reserve", "Reserve base units", Kind::Text, "0"),
];
macro_rules! form {
    ($op:ident,$label:literal,$fields:expr,$id:expr,$doc:expr) => {
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
    form!(Peer, "Connect peer", PEER, false, false),
    form!(CreateInvoice, "Create invoice", INVOICE, false, false),
    form!(
        DecodeInvoice,
        "Decode / receive invoice",
        &[field(
            "encoded_invoice",
            "Morph Bech32m invoice",
            Kind::Text,
            ""
        )],
        false,
        false
    ),
    form!(
        SettleInvoice,
        "Settle invoice",
        &[field(
            "payment_preimage",
            "Payment preimage",
            Kind::Secret,
            ""
        )],
        true,
        false
    ),
    form!(ReceiveInvoice, "Mark invoice received", &[], true, false),
    form!(OpenChannel, "Record channel", CHANNEL, false, false),
    form!(
        SpliceChannel,
        "Record splice",
        &[
            field("new_funding_epoch", "New funding epoch", Kind::Number, ""),
            field(
                "new_funding_context_id",
                "New funding context id",
                Kind::Text,
                ""
            )
        ],
        true,
        false
    ),
    form!(
        PublishChannel,
        "Record published state",
        &[
            field("funding_context_id", "Funding context id", Kind::Text, ""),
            field("state_number", "State number", Kind::Number, "")
        ],
        true,
        false
    ),
    form!(FinaliseChannel, "Record finalisation", &[], true, false),
    form!(OpenFactory, "Record Factory", FACTORY, false, false),
    form!(
        AdvanceFactory,
        "Advance Factory record",
        &[field(
            "new_update_number",
            "New update number",
            Kind::Number,
            ""
        )],
        true,
        false
    ),
    form!(MaterialiseChild, "Record Factory child", CHILD, true, false),
    form!(ImportRecovery, "Import recovery package", &[], false, true),
    form!(ExportRecovery, "Export recovery package", &[], true, false),
    form!(ImportBatch, "Import conditional Batch", &[], false, true),
    form!(ImportRoot, "Import root funding draft", &[], false, true),
    form!(InspectRoot, "Review root collection", &[], true, false),
    form!(
        RootExitSignature,
        "Collect root exit receipt",
        &[],
        true,
        true
    ),
    form!(
        RootCreationSignature,
        "Collect root creation receipt",
        &[],
        true,
        true
    ),
    form!(ExportRoot, "Export complete root funding", &[], true, false),
    form!(ExportState, "Export Hub state file", &[], false, false),
    form!(
        PreviewRestore,
        "Preview bootstrap restore",
        &[],
        false,
        true
    ),
    form!(
        Restore,
        "Restore previewed bootstrap state",
        &[],
        false,
        true
    ),
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
                let n = raw
                    .parse::<u64>()
                    .map_err(|_| anyhow!("{} must be an unsigned integer", field.label))?;
                ensure!(
                    n.to_string() == raw,
                    "{} must be canonical decimal",
                    field.label
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
                ensure!(!raw.is_empty(), "{} is required", field.label);
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
