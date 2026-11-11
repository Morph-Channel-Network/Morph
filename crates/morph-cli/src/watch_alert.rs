#[cfg(test)]
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(all(test, unix))]
use std::os::unix::fs::PermissionsExt;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

const WATCH_ALERT_SCHEMA: &str = "morph.watchtower_alert";

pub use morph_hub_api::{WatchAlertEvent, WatchAlertSeverity};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatchtowerAlert {
    pub schema: String,
    pub created_unix_ms: u64,
    pub channel_id: String,
    pub severity: WatchAlertSeverity,
    pub event: WatchAlertEvent,
    pub message: String,
    pub selected_state_number: u64,
    pub observed_state_number: Option<u64>,
    pub observed_out_point: Option<String>,
    pub publication_tx_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selected_funding_anchor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_funding_anchor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selected_funding_context_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_funding_context_id: Option<String>,
    pub scanned_to_block: u64,
    pub next_from_block: u64,
}

impl WatchtowerAlert {
    pub fn new(
        channel_id: String,
        severity: WatchAlertSeverity,
        event: WatchAlertEvent,
        message: String,
        selected_state_number: u64,
        scanned_to_block: u64,
        next_from_block: u64,
    ) -> Result<Self> {
        Ok(Self {
            schema: WATCH_ALERT_SCHEMA.to_string(),
            created_unix_ms: now_unix_ms()?,
            channel_id,
            severity,
            event,
            message,
            selected_state_number,
            observed_state_number: None,
            observed_out_point: None,
            publication_tx_hash: None,
            selected_funding_anchor: None,
            observed_funding_anchor: None,
            selected_funding_context_id: None,
            observed_funding_context_id: None,
            scanned_to_block,
            next_from_block,
        })
    }

    pub fn with_observed(mut self, state_number: u64, out_point: String) -> Self {
        self.observed_state_number = Some(state_number);
        self.observed_out_point = Some(out_point);
        self
    }

    pub fn with_publication(mut self, tx_hash: String) -> Self {
        self.publication_tx_hash = Some(tx_hash);
        self
    }

    pub fn with_funding_anchors(mut self, selected: String, observed: String) -> Self {
        self.selected_funding_anchor = Some(selected);
        self.observed_funding_anchor = Some(observed);
        self
    }

    pub fn with_optional_funding_contexts(
        mut self,
        selected: Option<String>,
        observed: Option<String>,
    ) -> Self {
        self.selected_funding_context_id = selected;
        self.observed_funding_context_id = observed;
        self
    }
}

pub fn append_watchtower_alert(path: &Path, alert: &WatchtowerAlert) -> Result<()> {
    let _lock = crate::persistence::try_lock_private_path(path)?
        .context("watch alert projection is busy")?;
    crate::persistence::append_private_jsonl(path, alert)
}

fn now_unix_ms() -> Result<u64> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before UNIX_EPOCH")?;
    Ok(duration.as_millis() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn channel_id(seed: u8) -> String {
        let hex = (0..32)
            .map(|offset| format!("{:02x}", seed.wrapping_add(offset)))
            .collect::<String>();
        format!("0x{hex}")
    }

    #[test]
    fn appends_jsonl_alerts() {
        let path =
            std::env::temp_dir().join(format!("morph-watch-alert-{}.jsonl", std::process::id()));
        let _ = fs::remove_file(&path);

        let alert = WatchtowerAlert::new(
            channel_id(1),
            WatchAlertSeverity::Warning,
            WatchAlertEvent::OlderStateDetected,
            "older state detected".to_string(),
            2,
            10,
            11,
        )
        .unwrap()
        .with_observed(1, "0xabc:0".to_string());

        append_watchtower_alert(&path, &alert).unwrap();
        append_watchtower_alert(&path, &alert).unwrap();

        let contents = fs::read_to_string(&path).unwrap();
        let lines: Vec<_> = contents.lines().collect();
        assert_eq!(lines.len(), 2);
        let decoded: WatchtowerAlert = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(decoded.event, WatchAlertEvent::OlderStateDetected);

        #[cfg(unix)]
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        for (invalid, reason) in [
            ("{\"schema\":\"another_stream\"}\n", "another schema"),
            (
                "{\"schema\":\"morph.watchtower_alert\"}",
                "incomplete record",
            ),
        ] {
            fs::write(&path, invalid).unwrap();
            #[cfg(unix)]
            {
                fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
                assert!(
                    append_watchtower_alert(&path, &alert)
                        .unwrap_err()
                        .to_string()
                        .contains("0600")
                );
                assert_eq!(fs::read_to_string(&path).unwrap(), invalid);
                assert_eq!(
                    fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                    0o644
                );
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            }
            assert!(
                append_watchtower_alert(&path, &alert)
                    .unwrap_err()
                    .to_string()
                    .contains(reason)
            );
            assert_eq!(fs::read_to_string(&path).unwrap(), invalid);
            #[cfg(unix)]
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }

        let _ = fs::remove_file(path);
    }

    #[test]
    fn appends_alert_without_parent_directory() {
        let path = std::path::PathBuf::from(format!(
            "morph-watch-alert-local-{}.jsonl",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);

        let alert = WatchtowerAlert::new(
            channel_id(2),
            WatchAlertSeverity::Info,
            WatchAlertEvent::ScanIdle,
            "scan idle".to_string(),
            2,
            10,
            11,
        )
        .unwrap();

        append_watchtower_alert(&path, &alert).unwrap();
        assert!(path.exists());

        let _ = fs::remove_file(&path);
        // Test owns this temporary stream and all append handles have closed.
        let _ = fs::remove_file(format!("{}.lock", path.display()));
    }

    #[test]
    fn serializes_critical_reorg_alert_for_operator_clients() {
        let alert = WatchtowerAlert::new(
            channel_id(3),
            WatchAlertSeverity::Critical,
            WatchAlertEvent::ChainReorgDetected,
            "canonical cursor hash changed".to_string(),
            7,
            42,
            10,
        )
        .unwrap();

        let value = serde_json::to_value(alert).unwrap();
        assert_eq!(value["severity"], "critical");
        assert_eq!(value["event"], "chain_reorg_detected");
    }
}
