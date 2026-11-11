//! Immediate form feedback only. Canonical SDK and server validation remain authoritative.
use crate::{forms, presentation as p, *};

impl Desktop {
    pub(crate) fn draft_issues(
        &self,
        key: &DraftKey,
        cx: &Context<Self>,
    ) -> BTreeMap<&'static str, String> {
        let mut issues = BTreeMap::new();
        let Some(draft) = self.drafts.get(key) else {
            return issues;
        };
        let form = forms::FORMS[key.form];
        if form.needs_id && !canonical_id(draft.id.read(cx).value().trim()) {
            issues.insert("resource", self.t(Text::ChooseAnObjectOrEnter0x).into());
        }
        let asset = draft.asset.read(cx).value();
        let ckb = asset.trim().is_empty();
        if workspace::uses_asset(form.operation) && !ckb && !canonical_id(asset.trim()) {
            issues.insert("asset", self.t(Text::TypeHashRequires0x64Lowercase).into());
        }
        for (name, input) in &draft.fields {
            let Some(meta) = form.fields.iter().find(|f| f.key == *name) else {
                continue;
            };
            let value = input.read(cx).value();
            let value = value.trim();
            let optional = matches!(meta.kind, forms::Kind::Optional)
                || (matches!(*name, "payment_preimage" | "description")
                    && form.operation == HubOperation::CreateInvoice);
            let issue = if value.is_empty() {
                (!optional).then_some(self.t(Text::ThisFieldIsRequired))
            } else if workspace::amount_field(name) {
                let valid = if ckb && draft.ckb_units {
                    p::decimal_to_shannons(value).is_ok()
                } else {
                    canonical_integer::<u128>(value)
                };
                (!valid).then_some(if ckb && draft.ckb_units {
                    self.t(Text::UseANonnegativeCKBAmountWith)
                } else {
                    self.t(Text::UseAnUnsignedIntegerInBase)
                })
            } else if matches!(meta.kind, forms::Kind::Number) {
                (!canonical_integer::<u64>(value))
                    .then_some(self.t(Text::UseACanonicalUnsigned64Bit))
            } else if matches!(*name, "pubkey" | "counterparty_pubkey") {
                (!compressed_key_shape(value))
                    .then_some(self.t(Text::Use66HexCharactersStartingWith))
            } else if matches!(meta.kind, forms::Kind::Pubkeys) {
                let keys = value
                    .split([',', '\n'])
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .collect::<Vec<_>>();
                (!(2..=16).contains(&keys.len()) || keys.iter().any(|k| !compressed_key_shape(k)))
                    .then_some(self.t(Text::Enter216CompressedPublicKeys))
            } else {
                None
            };
            if let Some(message) = issue {
                issues.insert(*name, message.into());
            }
        }
        if form.operation == HubOperation::CreateInvoice {
            let supplied = |name| {
                draft
                    .fields
                    .iter()
                    .find(|(k, _)| *k == name)
                    .is_some_and(|(_, e)| !e.read(cx).value().trim().is_empty())
            };
            if !supplied("payment_preimage") && !supplied("payment_hash") {
                let message = self.t(Text::SupplyExactlyOnePaymentPreimageOr);
                issues.insert("payment_preimage", message.into());
                issues.insert("payment_hash", message.into());
            }
        }
        issues
    }
}
fn compressed_key_shape(value: &str) -> bool {
    value.len() == 66
        && (value.starts_with("02") || value.starts_with("03"))
        && value.bytes().all(|b| b.is_ascii_hexdigit())
}
fn canonical_integer<T: std::str::FromStr + ToString>(value: &str) -> bool {
    value.parse::<T>().is_ok_and(|n| n.to_string() == value)
}
