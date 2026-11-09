use morph_sdk::api::{AuthScope, HubView};
use serde::Serialize;
use serde_json::Value;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Page {
    Overview,
    Channels,
    Factories,
    Invoices,
    Peers,
    Recovery,
    Watch,
    Events,
    Model,
    Actions,
    Inspector,
    Search,
}
#[derive(Clone)]
pub struct Row {
    pub title: String,
    pub subtitle: String,
    pub document: Value,
}
fn record<T: Serialize>(title: String, subtitle: String, item: &T) -> Row {
    Row {
        title,
        subtitle,
        document: serde_json::to_value(item).unwrap_or(Value::Null),
    }
}
pub fn rows(state: &HubView, page: Page) -> Vec<Row> {
    match page {
        Page::Channels => state
            .channels
            .iter()
            .map(|v| {
                record(
                    state
                        .peers
                        .iter()
                        .find(|peer| peer.pubkey == v.counterparty_pubkey)
                        .map(|peer| peer.alias.clone())
                        .unwrap_or_default(),
                    format!("{} · {}", v.provenance.label, v.provenance.message),
                    v,
                )
            })
            .collect(),
        Page::Factories => state
            .factories
            .iter()
            .map(|v| {
                record(
                    format!(
                        "{} · {} members · update {}",
                        v.factory_id,
                        v.participant_pubkeys.len(),
                        v.update_number
                    ),
                    format!(
                        "{} · {} child records",
                        v.provenance.label,
                        v.materialised_child_channels.len()
                    ),
                    v,
                )
            })
            .collect(),
        Page::Invoices => {
            let mut invoices = state.invoices.iter().collect::<Vec<_>>();
            invoices.sort_by_key(|v| std::cmp::Reverse(v.created_at_unix));
            invoices
                .into_iter()
                .map(|v| {
                    record(
                        format!("{} · {} · {}", v.amount, v.status, v.description),
                        format!("{} · {}", v.invoice_id, v.provenance.label),
                        v,
                    )
                })
                .collect()
        }
        Page::Peers => state
            .peers
            .iter()
            .map(|v| {
                record(
                    v.alias.clone(),
                    format!("{} · {}", v.pubkey, v.provenance.label),
                    v,
                )
            })
            .collect(),
        Page::Recovery => {
            let mut rows = state
                .multi_asset_packages
                .iter()
                .map(|v| {
                    record(
                        format!("Recovery · {} · state {}", v.channel_id, v.state_number),
                        format!(
                            "Saved signed evidence · {} Vaults · {}",
                            v.vault_count, v.package_id
                        ),
                        v,
                    )
                })
                .collect::<Vec<_>>();
            rows.extend(state.root_fundings.iter().map(|v| {
                record(
                    format!("Root · {}", v.root.channel_id),
                    format!(
                        "Exit receipts {} / 2 · Creation {} / 2 · Export ready {}",
                        v.exit_signature_count, v.creation_signature_count, v.ready_to_export
                    ),
                    v,
                )
            }));
            rows.extend(state.conditional_batches.iter().map(|v| {
                record(
                    "Conditional Batch recovery".into(),
                    "Saved force-resolution evidence; source must be registered".into(),
                    v,
                )
            }));
            rows
        }
        Page::Watch => state
            .watchtower
            .alerts
            .iter()
            .rev()
            .map(|v| {
                record(
                    format!("{:?} · {:?}", v.severity, v.event),
                    v.message.clone(),
                    v,
                )
            })
            .collect(),
        Page::Events => state
            .events
            .iter()
            .rev()
            .map(|v| {
                record(
                    format!("#{} · {:?} · {}", v.id, v.severity, v.event),
                    v.message.clone(),
                    v,
                )
            })
            .collect(),
        Page::Model => vec![
            record(
                "Capability boundary".into(),
                state.model.hub_role.clone(),
                &state.model,
            ),
            record(
                "API permissions".into(),
                state.security.auth_mode.clone(),
                &state.security,
            ),
            record(
                "Record provenance".into(),
                state.provenance.message.clone(),
                &state.provenance,
            ),
            record(
                "Watch service".into(),
                state.watchtower.provenance.message.clone(),
                &state.watchtower,
            ),
        ],
        _ => vec![],
    }
}
pub fn matches(row: &Row, tokens: &[String]) -> bool {
    let text = format!("{} {} {}", row.title, row.subtitle, row.document).to_lowercase();
    tokens.iter().all(|q| text.contains(q))
}
#[cfg(test)]
pub fn filter(rows: Vec<Row>, query: &str) -> Vec<Row> {
    let tokens = query
        .split_whitespace()
        .map(str::to_lowercase)
        .collect::<Vec<_>>();
    rows.into_iter().filter(|r| matches(r, &tokens)).collect()
}
pub fn can_operate(state: Option<&HubView>, checked: Option<Instant>, scope: AuthScope) -> bool {
    checked.is_some_and(|t| t.elapsed() < Duration::from_secs(15))
        && state
            .is_some_and(|s| !s.security.auth_required || s.security.auth_scopes.contains(&scope))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn all_search_tokens_match_full_precision_hidden_record_fields() {
        let row = Row {
            title: "xUDT record".into(),
            subtitle: "not chain verified".into(),
            document: serde_json::json!({"amount":"170141183460469231731687303715884105727","type_hash":"0xabcd"}),
        };
        assert_eq!(
            filter(
                vec![row.clone()],
                "XUDT 170141183460469231731687303715884105727 abcd"
            )
            .len(),
            1
        );
        assert!(filter(vec![row], "chain missing").is_empty());
    }
}

#[cfg(test)]
mod permissions {
    use super::*;
    #[test]
    fn explicit_unauthenticated_loopback_keeps_existing_service_semantics_but_stale_never_writes() {
        let mut state: HubView = serde_json::from_str(include_str!(
            "../../../fixtures/hub/unauthenticated-loopback.json"
        ))
        .unwrap();
        assert!(!state.security.auth_required);
        assert!(state.security.auth_scopes.is_empty());
        assert!(can_operate(
            Some(&state),
            Some(Instant::now()),
            AuthScope::Write
        ));
        assert!(!can_operate(
            Some(&state),
            Some(Instant::now() - Duration::from_secs(16)),
            AuthScope::Write
        ));
        state.security.auth_required = true;
        assert!(!can_operate(
            Some(&state),
            Some(Instant::now()),
            AuthScope::Write
        ));
        state.security.auth_scopes = vec![AuthScope::Read];
        assert!(!can_operate(
            Some(&state),
            Some(Instant::now()),
            AuthScope::Write
        ));
        assert!(can_operate(
            Some(&state),
            Some(Instant::now()),
            AuthScope::Read
        ));
    }
}
