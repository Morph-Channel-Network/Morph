//! One bounded background worker. RPC and filesystem work never run on the GPUI thread.
use anyhow::{Result, anyhow, ensure};
use morph_sdk::{
    HubClient,
    hub::{HubOperation, HubReply},
};
use serde_json::Value;
use std::{
    io::Read,
    path::PathBuf,
    sync::mpsc::{self, Receiver, SyncSender},
};

pub enum Work {
    Connect {
        endpoint: String,
        token: String,
    },
    Disconnect,
    Refresh,
    Execute {
        expected_revision: Option<u64>,
        operation: HubOperation,
        id: String,
        body: Value,
    },
    Inspect {
        document: Value,
        base: Option<Value>,
        receipt: Option<Value>,
    },
    Open {
        path: PathBuf,
    },
    Save {
        path: PathBuf,
        document: Value,
    },
}
pub struct Job {
    pub id: u64,
    pub generation: u64,
    pub work: Work,
}
pub enum Reply {
    Hub(Box<HubReply>),
    Document(Value),
    Opened(Value, u64),
    Saved,
}
pub struct Completion {
    pub review: Option<Value>,
    pub id: u64,
    pub generation: u64,
    pub result: Result<Reply>,
}
pub struct Worker {
    pub send: SyncSender<Job>,
    pub receive: Receiver<Completion>,
}
impl Worker {
    pub fn start() -> Result<Self> {
        Self::start_named("morph-desktop-network")
    }
    pub fn start_files() -> Result<Self> {
        Self::start_named("morph-desktop-files")
    }
    fn start_named(name: &str) -> Result<Self> {
        let (send, queue) = mpsc::sync_channel::<Job>(1);
        let (out, receive) = mpsc::sync_channel(2);
        std::thread::Builder::new()
            .name(name.into())
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build();
                let mut client: Option<HubClient> = None;
                while let Ok(job) = queue.recv() {
                    let result = (|| -> Result<Reply> {
                        match job.work {
                            Work::Connect { endpoint, token } => {
                                client = None;
                                let mut next = HubClient::new(&endpoint)?;
                                if !token.is_empty() {
                                    next = next.with_token(token)?;
                                }
                                let state = runtime
                                    .as_ref()
                                    .map_err(|_| anyhow!("network runtime unavailable"))?
                                    .block_on(next.state())?;
                                client = Some(next);
                                Ok(Reply::Hub(Box::new(HubReply::State(Box::new(state)))))
                            }
                            Work::Disconnect => {
                                client = None;
                                Ok(Reply::Saved)
                            }
                            Work::Refresh => {
                                let client = client
                                    .as_ref()
                                    .ok_or_else(|| anyhow!("Connect to a Hub first"))?;
                                let state = runtime
                                    .as_ref()
                                    .map_err(|_| anyhow!("network runtime unavailable"))?
                                    .block_on(client.state())?;
                                Ok(Reply::Hub(Box::new(HubReply::State(Box::new(state)))))
                            }
                            Work::Execute {
                                expected_revision,
                                operation,
                                id,
                                body,
                            } => {
                                let client = client
                                    .as_ref()
                                    .ok_or_else(|| anyhow!("Connect to a Hub first"))?;
                                let client = if operation.mutates() {
                                    client.clone().with_expected_revision(
                                        expected_revision.ok_or_else(|| {
                                            anyhow!(
                                                "Review the current Hub state before confirming"
                                            )
                                        })?,
                                    )?
                                } else {
                                    client.clone()
                                };
                                Ok(Reply::Hub(Box::new(
                                    runtime
                                        .as_ref()
                                        .map_err(|_| anyhow!("network runtime unavailable"))?
                                        .block_on(client.execute(operation, &id, &body))?,
                                )))
                            }
                            Work::Inspect {
                                document,
                                base,
                                receipt,
                            } => {
                                let review = if let Some(receipt) = receipt {
                                    morph_sdk::inspection::inspect_signature(
                                        &document,
                                        base.as_ref(),
                                        &receipt,
                                    )?
                                } else {
                                    morph_sdk::inspection::inspect(&document, base.as_ref())?
                                };
                                Ok(Reply::Document(review))
                            }
                            Work::Open { path } => {
                                let (value, bytes) = read_document(&path)?;
                                Ok(Reply::Opened(value, bytes))
                            }

                            Work::Save { path, document } => {
                                let bytes = serde_json::to_vec_pretty(&document)?;
                                morph_packages::persistence::write_private_immutable(
                                    &path, &bytes,
                                )?;
                                Ok(Reply::Saved)
                            }
                        }
                    })();
                    let mut review = None;
                    let result = result.and_then(|reply| {
                        if let Reply::Hub(hub) = &reply
                            && let HubReply::Document(document) = hub.as_ref()
                            && matches!(
                                document["schema"].as_str(),
                                Some(
                                    "morph.multi_asset_recovery_package.v1"
                                        | "morph.multi_asset_root_funding.v1"
                                        | "morph.multi_asset_root_collection.v1"
                                )
                            )
                        {
                            review = Some(morph_sdk::inspection::inspect(document, None)?);
                        }
                        Ok(reply)
                    });
                    if out
                        .send(Completion {
                            review,
                            id: job.id,
                            generation: job.generation,
                            result,
                        })
                        .is_err()
                    {
                        break;
                    }
                }
            })?;
        Ok(Self { send, receive })
    }
}

fn read_document(path: &std::path::Path) -> Result<(Value, u64)> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(path)?;
        let metadata = file.metadata()?;
        ensure!(metadata.is_file(), "document must be a regular file");
        ensure!(metadata.len() <= 4 * 1024 * 1024, "document exceeds 4 MiB");
        let mut data = Vec::new();
        (&mut file)
            .take(4 * 1024 * 1024 + 1)
            .read_to_end(&mut data)?;
        ensure!(data.len() <= 4 * 1024 * 1024, "document exceeds 4 MiB");
        Ok((serde_json::from_slice(&data)?, data.len() as u64))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        anyhow::bail!("native document input requires the qualified Unix platform")
    }
}
