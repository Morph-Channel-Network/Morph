//! Canonical scan progress shared by the sole current watch implementation.
use crate::canonical_fields::canonical_hex32;
use crate::persistence::required_option;
#[cfg(any(feature = "devnet", test))]
use crate::watch_runtime;
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
#[cfg(test)]
use std::fs;
#[cfg(any(feature = "devnet", test))]
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
const WATCH_CURSOR_SCHEMA: &str = "morph.watch_cursor";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WatchCursor {
    pub schema: String,
    pub channel_id: String,
    pub from_block: u64,
    pub next_block: u64,
    pub scanned_to_block: u64,
    #[serde(deserialize_with = "required_option")]
    pub scanned_to_block_hash: Option<String>,
    #[serde(deserialize_with = "required_option")]
    pub current_funding_anchor: Option<String>,
    #[serde(deserialize_with = "required_option")]
    pub current_funding_context_id: Option<String>,
    #[serde(deserialize_with = "required_option")]
    pub last_observed_state_number: Option<u64>,
    #[serde(deserialize_with = "required_option")]
    pub last_observed_out_point: Option<String>,
    pub updated_unix_ms: u64,
}

impl WatchCursor {
    pub fn new(
        channel_id: &str,
        from_block: u64,
        next_block: u64,
        scanned_to_block: u64,
    ) -> Result<Self> {
        let cursor = Self {
            schema: WATCH_CURSOR_SCHEMA.to_string(),
            channel_id: canonical_hex32(channel_id)?,
            from_block,
            next_block,
            scanned_to_block,
            scanned_to_block_hash: None,
            current_funding_anchor: None,
            current_funding_context_id: None,
            last_observed_state_number: None,
            last_observed_out_point: None,
            updated_unix_ms: now_unix_ms()?,
        };
        cursor.validate()?;
        Ok(cursor)
    }

    pub fn with_observed_context_state(
        mut self,
        funding_anchor: &str,
        funding_context_id: &str,
        state_number: u64,
        out_point: &str,
    ) -> Result<Self> {
        self.current_funding_anchor = Some(canonical_hex32(funding_anchor)?);
        self.current_funding_context_id = Some(canonical_hex32(funding_context_id)?);
        self.last_observed_state_number = Some(state_number);
        self.last_observed_out_point = Some(out_point.to_string());
        self.validate()?;
        Ok(self)
    }

    pub fn with_scanned_block_hash(mut self, block_hash: &str) -> Result<Self> {
        self.scanned_to_block_hash = Some(canonical_hex32(block_hash)?);
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == WATCH_CURSOR_SCHEMA,
            "unsupported watch cursor schema {}",
            self.schema
        );
        let canonical_channel_id = canonical_hex32(&self.channel_id)?;
        ensure!(
            self.channel_id == canonical_channel_id,
            "watch cursor channel_id must be canonical"
        );
        if let Some(block_hash) = &self.scanned_to_block_hash {
            ensure!(
                *block_hash == canonical_hex32(block_hash)?,
                "watch cursor scanned_to_block_hash must be canonical"
            );
        }
        let has_observation = self.current_funding_context_id.is_some();
        ensure!(
            self.current_funding_anchor.is_some() == has_observation
                && self.last_observed_state_number.is_some() == has_observation
                && self.last_observed_out_point.is_some() == has_observation,
            "watch cursor observation requires funding context, anchor, state number and OutPoint together"
        );
        if let Some(anchor) = &self.current_funding_anchor {
            ensure!(
                *anchor == canonical_hex32(anchor)?,
                "watch cursor current_funding_anchor must be canonical"
            );
        }
        if let Some(context_id) = &self.current_funding_context_id {
            ensure!(
                *context_id == canonical_hex32(context_id)?,
                "watch cursor current_funding_context_id must be canonical"
            );
        }
        ensure!(
            self.next_block >= self.from_block
                && self.scanned_to_block >= self.from_block.saturating_sub(1),
            "watch cursor precedes its scan origin"
        );
        ensure!(
            self.scanned_to_block.checked_add(1) == Some(self.next_block)
                || (self.scanned_to_block == 0 && self.next_block == 0),
            "watch cursor next_block must immediately follow scanned_to_block"
        );
        Ok(())
    }
}

#[cfg(any(feature = "devnet", test))]
pub fn default_watch_cursor_path(dir: &Path, channel_id: &str) -> Result<PathBuf> {
    let channel = canonical_hex32(channel_id)?;
    Ok(dir.join(format!(
        "watch-cursor-{}.db",
        channel.trim_start_matches("0x")
    )))
}

#[cfg(any(feature = "devnet", test))]
pub fn read_watch_cursor(path: &Path) -> Result<Option<WatchCursor>> {
    watch_runtime::read(path)
}

#[cfg(test)]
pub fn write_watch_cursor(path: &Path, cursor: &WatchCursor) -> Result<()> {
    cursor.validate()?;
    watch_runtime::commit(path, cursor, None, false, None)
}

fn now_unix_ms() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .try_into()?)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn temp_dir(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "morph-{label}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&path).unwrap();
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        path
    }
    #[test]
    fn writes_and_reads_watch_cursor() {
        let dir = temp_dir("cursor");
        let channel_id = format!("0x{}", "11".repeat(32));
        let funding_anchor = format!("0x{}", "22".repeat(32));
        let funding_context_id = format!("0x{}", "23".repeat(32));
        let path = default_watch_cursor_path(&dir, &channel_id).unwrap();
        let cursor = WatchCursor::new(&channel_id, 40, 43, 42)
            .unwrap()
            .with_scanned_block_hash(&format!("0x{}", "24".repeat(32)))
            .unwrap()
            .with_observed_context_state(&funding_anchor, &funding_context_id, 7, "0xabc:0")
            .unwrap();

        assert!(read_watch_cursor(&path).unwrap().is_none());
        write_watch_cursor(&path, &cursor).unwrap();

        let loaded = read_watch_cursor(&path).unwrap().unwrap();
        assert_eq!(loaded.channel_id, channel_id);
        assert_eq!(loaded.from_block, 40);
        assert_eq!(loaded.next_block, 43);
        let mut gap = loaded.clone();
        gap.next_block += 1;
        assert!(gap.validate().is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        assert_eq!(loaded.scanned_to_block, 42);
        assert_eq!(
            loaded.scanned_to_block_hash.as_deref(),
            Some(format!("0x{}", "24".repeat(32)).as_str())
        );
        assert_eq!(
            loaded.current_funding_anchor.as_deref(),
            Some(funding_anchor.as_str())
        );
        assert_eq!(
            loaded.current_funding_context_id.as_deref(),
            Some(funding_context_id.as_str())
        );
        assert_eq!(loaded.last_observed_state_number, Some(7));
        assert_eq!(loaded.last_observed_out_point.as_deref(), Some("0xabc:0"));
        let mut anchor_only = loaded.clone();
        anchor_only.current_funding_context_id = None;
        assert!(anchor_only.validate().is_err());
        let encoded = serde_json::to_value(&loaded).unwrap();
        for field in [
            "from_block",
            "current_funding_context_id",
            "scanned_to_block_hash",
        ] {
            let mut incomplete = encoded.clone();
            incomplete.as_object_mut().unwrap().remove(field);
            assert!(serde_json::from_value::<WatchCursor>(incomplete).is_err());
        }

        fs::remove_dir_all(dir).unwrap();
    }
}
