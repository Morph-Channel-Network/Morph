use anyhow::{Result, anyhow, ensure};
use morph_key_input::SecretString;
use morph_wallet::{
    address::Network,
    rpc::Chain,
    service::{AssetManifest, Quote, Settings, Submission, Wallet, WalletView},
};
use std::{
    io::Read,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, SyncSender},
    },
    time::{Duration, Instant},
};

pub enum Command {
    Create {
        name: String,
        password: SecretString,
        key_file: Option<PathBuf>,
    },
    Restore {
        path: PathBuf,
        password: SecretString,
    },
    Unlock(SecretString),
    Lock,
    ChangePassword {
        current: SecretString,
        next: SecretString,
    },
    Backup(PathBuf),
    Configure {
        network: Network,
        rpc: String,
        indexer: String,
    },
    InspectAssets(PathBuf),
    AdmitAssets(AssetManifest),
    PaymentSecret(Option<String>),
    Refresh,
    Prepare {
        recipient: String,
        asset: Option<String>,
        amount: String,
    },
    Submit(String),
    History(Option<String>),
    Status(String),
    Resend(String),
}
pub enum Reply {
    View(Box<WalletView>),
    Quote(Box<Quote>),
    Submitted(Submission),
    History(serde_json::Value),
    Status(String, serde_json::Value),
    Saved,
    Secret(SecretString),
    Assets(AssetManifest),
}
pub struct Update {
    pub completed: bool,
    pub result: Result<Reply>,
    pub view: Option<Box<WalletView>>,
}
pub struct Worker {
    pub visible: Arc<AtomicBool>,
    pub send: SyncSender<Command>,
    pub receive: Receiver<Update>,
}
fn directory() -> Result<PathBuf> {
    let root = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| {
            std::env::var_os("HOME")
                .map(PathBuf::from)
                .filter(|p| p.is_absolute())
                .map(|p| p.join(".config"))
        })
        .ok_or_else(|| anyhow!("wallet.configuration_directory_missing"))?;
    Ok(root.join("morph/wallet"))
}
impl Worker {
    pub fn start() -> Result<Self> {
        let visible = Arc::new(AtomicBool::new(false));
        let observing = visible.clone();
        let (send, commands) = mpsc::sync_channel(1);
        let (out, receive) = mpsc::sync_channel(2);
        std::thread::Builder::new()
            .name("morph-local-wallet".into())
            .spawn(move || {
                let opened = directory().and_then(|p| Wallet::open(&p));
                let mut wallet = match opened {
                    Ok(w) => w,
                    Err(e) => {
                        let _ = out.send(Update {
                            completed: false,
                            result: Err(e),
                            view: None,
                        });
                        return;
                    }
                };
                if out
                    .send(Update {
                        completed: false,
                        result: wallet.view().map(|v| Reply::View(Box::new(v))),
                        view: None,
                    })
                    .is_err()
                {
                    return;
                }
                let mut last_check = Instant::now() - Duration::from_secs(20);
                loop {
                    let command = match commands.recv_timeout(Duration::from_secs(1)) {
                        Ok(c) => c,
                        Err(mpsc::RecvTimeoutError::Timeout) => {
                            if wallet.auto_lock()
                                && out
                                    .send(Update {
                                        completed: false,
                                        result: wallet.view().map(|v| Reply::View(Box::new(v))),
                                        view: None,
                                    })
                                    .is_err()
                            {
                                break;
                            }
                            if observing.load(Ordering::Relaxed)
                                && last_check.elapsed() >= Duration::from_secs(20)
                                && wallet.can_observe()
                            {
                                let result = wallet.refresh().map(|v| Reply::View(Box::new(v)));
                                last_check = Instant::now();
                                if out
                                    .send(Update {
                                        completed: false,
                                        result,
                                        view: wallet.view().ok().map(Box::new),
                                    })
                                    .is_err()
                                {
                                    break;
                                }
                            }
                            continue;
                        }
                        Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    };
                    let result = (|| -> Result<Reply> {
                        match command {
                            Command::Create {
                                name,
                                password,
                                key_file,
                            } => {
                                if let Some(path) = key_file {
                                    wallet.import_key(&name, &password, &path)?;
                                } else {
                                    wallet.create(&name, &password)?;
                                }
                            }
                            Command::Restore { path, password } => {
                                use std::os::unix::fs::OpenOptionsExt;
                                let file = std::fs::OpenOptions::new()
                                    .read(true)
                                    .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                                    .open(path)?;
                                ensure!(
                                    file.metadata()?.is_file()
                                        && file.metadata()?.len() <= 4 * 1024 * 1024,
                                    "wallet.invalid_keystore"
                                );
                                let mut bytes = Vec::new();
                                file.take(4 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
                                wallet.restore(&bytes, &password)?;
                            }
                            Command::Unlock(password) => wallet.unlock(&password)?,
                            Command::Lock => wallet.lock(),
                            Command::ChangePassword { current, next } => {
                                wallet.change_password(&current, &next)?
                            }
                            Command::Backup(path) => {
                                morph_wallet::storage::export_encrypted(&path, &wallet.backup()?)?;
                                return Ok(Reply::Saved);
                            }
                            Command::Configure {
                                network,
                                rpc,
                                indexer,
                            } => {
                                let chain = Chain::discover(network, rpc, indexer)?;
                                let assets = wallet
                                    .view()?
                                    .settings
                                    .filter(|s| s.chain.genesis_hash == chain.genesis_hash)
                                    .map_or_else(Vec::new, |s| s.assets);
                                wallet.configure(Settings { chain, assets })?;
                                wallet.refresh()?;
                            }
                            Command::InspectAssets(path) => {
                                use std::os::unix::fs::OpenOptionsExt;
                                let file = std::fs::OpenOptions::new()
                                    .read(true)
                                    .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                                    .open(path)?;
                                ensure!(
                                    file.metadata()?.is_file() && file.metadata()?.len() <= 65536,
                                    "wallet.invalid_asset"
                                );
                                let mut bytes = Vec::new();
                                file.take(65537).read_to_end(&mut bytes)?;
                                ensure!(bytes.len() <= 65536, "wallet.invalid_asset");
                                let manifest: AssetManifest = serde_json::from_slice(&bytes)?;
                                ensure!(manifest.assets.len() <= 32, "wallet.asset_limit");
                                return Ok(Reply::Assets(manifest));
                            }
                            Command::AdmitAssets(manifest) => wallet.admit_assets(manifest)?,
                            Command::PaymentSecret(hash) => {
                                return wallet.payment_secret(hash.as_deref()).map(Reply::Secret);
                            }
                            Command::Refresh => {
                                return wallet.refresh().map(|v| Reply::View(Box::new(v)));
                            }
                            Command::Prepare {
                                recipient,
                                asset,
                                amount,
                            } => {
                                return wallet
                                    .prepare_estimated(&recipient, asset.as_deref(), &amount)
                                    .map(|v| Reply::Quote(Box::new(v)));
                            }
                            Command::Submit(id) => {
                                return wallet.submit_reviewed(&id).map(Reply::Submitted);
                            }
                            Command::History(cursor) => {
                                return wallet.history(cursor.as_deref()).map(Reply::History);
                            }
                            Command::Status(hash) => {
                                return wallet.status(&hash).map(|v| Reply::Status(hash, v));
                            }
                            Command::Resend(hash) => {
                                return wallet.resend_exact(&hash).map(Reply::Submitted);
                            }
                        }
                        wallet.view().map(|v| Reply::View(Box::new(v)))
                    })();
                    last_check = Instant::now();
                    if out
                        .send(Update {
                            completed: true,
                            result,
                            view: wallet.view().ok().map(Box::new),
                        })
                        .is_err()
                    {
                        break;
                    }
                }
            })?;
        Ok(Self {
            send,
            receive,
            visible,
        })
    }
}
