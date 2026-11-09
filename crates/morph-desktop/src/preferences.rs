//! Device-only UI preferences. No endpoint, credential, package or signing authority is stored.
use crate::i18n::Language;
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{Read, Write},
    path::PathBuf,
    sync::mpsc::{self, Receiver, SyncSender},
};
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Preferences {
    pub language: Language,
    pub scale_percent: u16,
    pub reduced_motion: bool,
}
impl Preferences {
    pub fn valid(&self) -> bool {
        (90..=150).contains(&self.scale_percent) && self.scale_percent.is_multiple_of(10)
    }
    pub fn scale(self) -> f32 {
        self.scale_percent as f32 / 100.
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    schema: String,
    preferences: Preferences,
}
pub enum Event {
    Loaded(Result<Option<Preferences>, String>),
    Saved(u64, Result<(), String>),
}
pub struct Store {
    sender: SyncSender<(u64, Preferences)>,
    pub events: Receiver<Event>,
}
impl Store {
    pub fn start() -> Result<Self> {
        let path = preference_path();
        let (sender, pending) = mpsc::sync_channel::<(u64, Preferences)>(1);
        let (out, events) = mpsc::sync_channel(2);
        std::thread::Builder::new()
            .name("morph-ui-preferences".into())
            .spawn(move || {
                let loaded = path.as_ref().map_or_else(|| Ok(None), |p| load(p));
                if out
                    .send(Event::Loaded(loaded.map_err(|e| e.to_string())))
                    .is_err()
                {
                    return;
                }
                while let Ok((revision, preferences)) = pending.recv() {
                    let result = path
                        .as_ref()
                        .ok_or_else(|| anyhow::anyhow!("no absolute user configuration directory"))
                        .and_then(|p| save(p, preferences, revision))
                        .map_err(|e| e.to_string());
                    if out.send(Event::Saved(revision, result)).is_err() {
                        break;
                    }
                }
            })?;
        Ok(Self { sender, events })
    }
    pub fn save(&self, revision: u64, preferences: Preferences) -> bool {
        self.sender.try_send((revision, preferences)).is_ok()
    }
}
fn preference_path() -> Option<PathBuf> {
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| {
            std::env::var_os("HOME")
                .map(PathBuf::from)
                .filter(|p| p.is_absolute())
                .map(|p| p.join(".config"))
        })
        .map(|p| p.join("morph/desktop-preferences.json"))
}
fn load(path: &std::path::Path) -> Result<Option<Preferences>> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW);
    }
    let file = match options.open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    ensure!(
        file.metadata()?.is_file(),
        "UI preferences must be a regular file"
    );
    let mut data = Vec::new();
    file.take(4097).read_to_end(&mut data)?;
    ensure!(data.len() <= 4096, "UI preferences exceed 4 KiB");
    let p: Document = serde_json::from_slice(&data)?;
    ensure!(
        p.schema == "morph.desktop_preferences.v2",
        "unsupported UI preference schema"
    );
    ensure!(p.preferences.valid(), "invalid UI scale");
    Ok(Some(p.preferences))
}
fn save(path: &std::path::Path, preferences: Preferences, revision: u64) -> Result<()> {
    ensure!(preferences.valid(), "invalid UI scale");
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("UI preferences require a parent"))?;
    fs::create_dir_all(parent)?;
    let temporary = parent.join(format!(
        ".desktop-preferences.{}.{}.tmp",
        std::process::id(),
        revision
    ));
    let result = (|| -> Result<()> {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary)?;
        file.write_all(&serde_json::to_vec(&Document {
            schema: "morph.desktop_preferences.v2".into(),
            preferences,
        })?)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, path)?;
        fs::File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn current_preferences_round_trip_and_reject_old_or_invalid_shapes() {
        let path = std::env::temp_dir().join(format!(
            "morph-motion-preferences-{}.json",
            std::process::id()
        ));
        let value = Preferences {
            language: Language::Chinese,
            scale_percent: 150,
            reduced_motion: true,
        };
        save(&path, value, 1).unwrap();
        assert_eq!(load(&path).unwrap(), Some(value));
        let mut invalid = value;
        invalid.scale_percent = 151;
        assert!(save(&path, invalid, 2).is_err());
        assert_eq!(load(&path).unwrap(), Some(value));
        fs::write(
            &path,
            r#"{"schema":"morph.desktop_preferences.v1","language":"en"}"#,
        )
        .unwrap();
        assert!(load(&path).is_err());
        fs::write(&path,r#"{"schema":"morph.desktop_preferences.v2","preferences":{"language":"en","scale_percent":100}}"#).unwrap();
        assert!(load(&path).is_err());
        fs::remove_file(path).unwrap();
    }
}
