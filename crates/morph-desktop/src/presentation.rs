//! Human-facing copy and exact amount presentation. No wire or signer authority.
use anyhow::{Result, ensure};
use morph_sdk::{api::AssetView, hub::HubOperation};
use serde_json::Value;

use crate::i18n::{Language, Text};
pub fn short(value: &str) -> String {
    if value.len() > 24 && value.is_ascii() {
        format!("{}…{}", &value[..10], &value[value.len() - 6..])
    } else {
        value.to_owned()
    }
}
pub fn grouped(value: &str) -> String {
    let mut result = String::new();
    for (i, c) in value.chars().enumerate() {
        if i > 0 && (value.len() - i).is_multiple_of(3) {
            result.push(',');
        }
        result.push(c);
    }
    result
}
pub fn ckb_decimal(raw: &str) -> String {
    let Ok(value) = raw.parse::<u128>() else {
        return raw.to_owned();
    };
    let fraction = format!("{:08}", value % 100_000_000);
    let fraction = fraction.trim_end_matches('0');
    if fraction.is_empty() {
        (value / 100_000_000).to_string()
    } else {
        format!("{}.{}", value / 100_000_000, fraction)
    }
}
pub fn decimal_to_shannons(raw: &str) -> Result<String> {
    let raw = raw.trim();
    let mut parts = raw.split('.');
    let whole = parts.next().unwrap_or("");
    let fraction = parts.next().unwrap_or("");
    ensure!(
        parts.next().is_none()
            && !whole.is_empty()
            && whole.bytes().all(|c| c.is_ascii_digit())
            && fraction.bytes().all(|c| c.is_ascii_digit())
            && fraction.len() <= 8,
        "CKB amount requires a nonnegative decimal with at most 8 fractional digits"
    );
    let whole = whole.parse::<u128>()?;
    let fraction = if fraction.is_empty() {
        0
    } else {
        fraction.parse::<u128>()? * 10_u128.pow(8 - fraction.len() as u32)
    };
    Ok(whole
        .checked_mul(100_000_000)
        .and_then(|n| n.checked_add(fraction))
        .ok_or_else(|| anyhow::anyhow!("CKB amount exceeds u128"))?
        .to_string())
}
pub fn amount(raw: &str, ckb: bool, lang: Language) -> String {
    if ckb {
        let value = ckb_decimal(raw);
        let (whole, fraction) = value.split_once('.').unwrap_or((&value, ""));
        format!(
            "{}{} CKB",
            grouped(whole),
            if fraction.is_empty() {
                String::new()
            } else {
                format!(".{fraction}")
            }
        )
    } else {
        format!(
            "{} {}",
            if raw.bytes().all(|b| b.is_ascii_digit()) {
                grouped(raw)
            } else {
                raw.to_owned()
            },
            lang.t(Text::BaseUnits)
        )
    }
}
pub fn asset_name(asset: &AssetView) -> String {
    match asset {
        AssetView::Ckb => "CKB".into(),
        AssetView::Xudt { type_hash } => format!("xUDT · {}", short(type_hash)),
    }
}
pub fn json_asset(value: &Value, lang: Language) -> (String, bool) {
    if value["kind"] == "ckb" || value.is_null() {
        ("CKB".into(), true)
    } else {
        (
            format!(
                "xUDT · {}",
                short(
                    value["type_hash"]
                        .as_str()
                        .unwrap_or(lang.t(Text::UnknownType))
                )
            ),
            false,
        )
    }
}
pub fn field_label(_key: &str, message: Text, lang: Language) -> &'static str {
    lang.t(message)
}
pub fn operation_title(op: HubOperation, lang: Language) -> &'static str {
    crate::forms::FORMS
        .iter()
        .find(|f| f.operation == op)
        .map_or(lang.t(Text::Task), |f| lang.t(f.label))
}
pub fn operation_help(op: HubOperation, lang: Language) -> &'static str {
    use HubOperation::*;
    match op {
        ImportRoot | InspectRoot | RootExitSignature | RootCreationSignature | ExportRoot => {
            lang.t(Text::ReviewExactTermsCollectTheTwo)
        }
        ImportRecovery | ExportRecovery | ImportBatch => {
            lang.t(Text::CanonicalSignaturesAndPackageContentsAre)
        }
        PreviewRestore | Restore => lang.t(Text::RestoreABootstrapHubWorkspaceAfter),
        ExportState => lang.t(Text::ExportTheCurrentHubWorkspaceTo),
        CreateInvoice | SettleInvoice => lang.t(Text::UseTheHubSCurrentInvoice),
        _ => lang.t(Text::UpdateALocalHubRecordThis),
    }
}
pub fn human_state(value: &str, lang: Language) -> String {
    let key = value.to_ascii_lowercase();
    let label = match key.as_str() {
        "active" => Text::Active,
        "settling" => Text::Settling,
        "finalised" | "finalized" => Text::Finalised,
        "open" | "pending" => Text::Pending,
        "paid" | "settled" => Text::Settled,
        "received" => Text::Received,
        "cancelled" | "canceled" => Text::Cancelled,
        "expired" => Text::Expired,
        "info" => Text::Info,
        "warning" => Text::Warning,
        "critical" => Text::Critical,
        _ => return value.to_owned(),
    };
    lang.t(label).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ckb_conversion_is_exact_and_bounded() {
        assert_eq!(decimal_to_shannons("1.00000001").unwrap(), "100000001");
        assert_eq!(ckb_decimal("100000001"), "1.00000001");
        for s in ["-1", "1e8", "1.000000001", "1.2.3", "."] {
            assert!(decimal_to_shannons(s).is_err())
        }
        assert!(decimal_to_shannons(&u128::MAX.to_string()).is_err());
    }
}

pub fn scope_name(scope: morph_sdk::api::AuthScope, l: Language) -> &'static str {
    use morph_sdk::api::AuthScope::*;
    match scope {
        Read => l.t(Text::Read),
        Write => l.t(Text::Write),
        Restore => l.t(Text::Restore),
        Sign => l.t(Text::InvoiceSigning),
    }
}
pub fn view_hash(text: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    text.hash(&mut h);
    h.finish()
}

pub fn event_name(value: &str, l: Language) -> String {
    let known = match value {
        "peer_connected" => l.t(Text::PeerRecordAdded),
        "invoice_created" => l.t(Text::InvoiceCreated),
        "invoice_received" => l.t(Text::InvoiceReceived),
        "invoice_paid" | "invoice_settled" => l.t(Text::InvoiceSettled),
        "channel_opened" => l.t(Text::ChannelRecordAdded),
        "channel_spliced" => l.t(Text::SpliceRecorded),
        "channel_published" | "state_published" => l.t(Text::PublicationRecorded),
        "channel_finalised" => l.t(Text::FinalisationRecorded),
        "factory_created" | "factory_opened" => l.t(Text::FactoryRecordAdded),
        "factory_advanced" => l.t(Text::FactoryRecordAdvanced),
        "factory_child_materialised" => l.t(Text::ChildChannelRecorded),
        "root_funding_proposed" => l.t(Text::FundingDraftSaved),
        "root_funding_signature_received" => l.t(Text::FundingReceiptSaved),
        "multi_asset_recovery_imported" => l.t(Text::RecoveryEvidenceImported),
        "conditional_batch_imported" => l.t(Text::ConditionalEvidenceImported),
        "state_restored" => l.t(Text::WorkspaceRestored),
        _ => return format!("{} · {value}", l.t(Text::ServiceEvent)),
    };
    known.into()
}

/// A projection sum, not wallet liquidity. Never add unlike assets or duplicate records.
pub fn local_ckb_total<'a>(
    channels: impl IntoIterator<Item = (&'a str, &'a [morph_sdk::api::BalanceView])>,
) -> Option<u128> {
    let mut seen = std::collections::HashSet::new();
    let mut total = 0_u128;
    for (id, balances) in channels {
        if !seen.insert(id) {
            return None;
        }
        let mut ckb = balances
            .iter()
            .filter(|b| matches!(b.asset, AssetView::Ckb));
        if let Some(balance) = ckb.next() {
            if ckb.next().is_some() {
                return None;
            }
            total = total.checked_add(balance.local.parse::<u128>().ok()?)?;
        }
    }
    Some(total)
}
/// Approximate geometry only. Exact quantities are always rendered separately.
pub fn allocation_shares(local: &str, remote: &str, pending: &str) -> Option<[f32; 3]> {
    let values = [local, remote, pending].map(str::parse::<u128>);
    let [Ok(local), Ok(remote), Ok(pending)] = values else {
        return None;
    };
    let total = local.checked_add(remote)?.checked_add(pending)?;
    if total == 0 {
        return None;
    }
    Some([local, remote, pending].map(|value| (value as f64 / total as f64) as f32))
}
#[cfg(test)]
mod projection_tests {
    use super::*;
    use morph_sdk::api::BalanceView;
    fn balance(asset: AssetView, local: &str) -> BalanceView {
        BalanceView {
            asset,
            local: local.into(),
            remote: "0".into(),
            pending: "0".into(),
        }
    }
    #[test]
    fn projection_never_sums_tokens_duplicates_or_overflows() {
        let valid = vec![
            balance(AssetView::Ckb, "123456789"),
            balance(
                AssetView::Xudt {
                    type_hash: "token".into(),
                },
                "999",
            ),
        ];
        assert_eq!(local_ckb_total([("a", valid.as_slice())]), Some(123456789));
        assert_eq!(
            local_ckb_total([("a", valid.as_slice()), ("a", valid.as_slice())]),
            None
        );
        let duplicate = vec![balance(AssetView::Ckb, "1"), balance(AssetView::Ckb, "1")];
        assert_eq!(local_ckb_total([("a", duplicate.as_slice())]), None);
        let huge = vec![balance(AssetView::Ckb, &u128::MAX.to_string())];
        assert_eq!(
            local_ckb_total([("a", huge.as_slice()), ("b", valid.as_slice())]),
            None
        );
        let bad = vec![balance(AssetView::Ckb, "invalid")];
        assert_eq!(local_ckb_total([("a", bad.as_slice())]), None);
    }
    #[test]
    fn distribution_handles_zero_invalid_and_overflow_without_fictitious_shares() {
        assert_eq!(allocation_shares("0", "0", "0"), None);
        assert_eq!(allocation_shares("invalid", "0", "0"), None);
        assert_eq!(allocation_shares(&u128::MAX.to_string(), "1", "0"), None);
        assert_eq!(allocation_shares("2", "1", "1"), Some([0.5, 0.25, 0.25]));
    }
}

pub fn network_name(value: &str, l: Language) -> String {
    match value.to_ascii_lowercase().as_str() {
        "devnet" => l.t(Text::NetworkDevnet).into(),
        "testnet" => l.t(Text::NetworkTestnet).into(),
        "mainnet" => l.t(Text::NetworkMainnet).into(),
        _ => value.into(),
    }
}
