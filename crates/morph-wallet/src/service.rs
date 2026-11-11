//! Stateful local wallet backend. Run on its own bounded worker, never the UI or Hub thread.
use crate::{
    address::{self, Network},
    keystore::{EncryptedSecret, Keystore, UnlockedKey},
    rpc::{Balance, Chain, NetworkConfig, Snapshot},
    storage::Storage,
    transaction::{self, PreparedTransfer, Token, Transfer, TransferSummary},
};
use anyhow::{Result, anyhow, ensure};
use ckb_types::{packed, prelude::*};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::BTreeSet,
    path::Path,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Asset {
    pub symbol: String,
    pub decimals: u8,
    pub script: ckb_jsonrpc_types::Script,
    pub dependency: ckb_jsonrpc_types::CellDep,
}
impl Asset {
    pub fn hash(&self) -> String {
        let script: packed::Script = self.script.clone().into();
        format!("{:#x}", script.calc_script_hash())
    }
    fn token(&self) -> Token {
        Token {
            script: self.script.clone().into(),
            dep: self.dependency.clone().into(),
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    pub chain: NetworkConfig,
    pub assets: Vec<Asset>,
}
impl Settings {
    fn validate(&self) -> Result<()> {
        self.chain.validate_identity()?;
        let _ = Chain::new(self.chain.clone())?;
        ensure!(self.assets.len() <= 32, "wallet.asset_limit");
        let mut seen = BTreeSet::new();
        for asset in &self.assets {
            ensure!(
                !asset.symbol.trim().is_empty()
                    && asset.symbol.len() <= 24
                    && !asset.symbol.chars().any(char::is_control)
                    && asset.decimals <= 38
                    && seen.insert(asset.hash()),
                "wallet.invalid_asset"
            );
        }
        Ok(())
    }
}
/// Importable, network-bound asset definitions. The UI reviews these before admission.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssetManifest {
    pub genesis_hash: String,
    pub assets: Vec<Asset>,
}
#[derive(Clone, Debug, Serialize)]
pub struct WalletView {
    pub exists: bool,
    pub unlocked: bool,
    pub name: String,
    pub public_key: String,
    pub address: String,
    pub settings: Option<Settings>,
    pub balance: Option<Balance>,
    pub local_transactions: Vec<SavedTransaction>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SavedTransaction {
    pub genesis_hash: String,
    pub transaction_hash: String,
    pub signed_transaction: String,
    pub inputs: Vec<String>,
    pub created_at: u64,
}
#[derive(Clone, Debug, Serialize)]
pub struct Quote {
    pub id: String,
    pub recipient: String,
    pub asset: String,
    pub summary: TransferSummary,
    pub display_amount: String,
    pub fee_rate: u64,
}
#[derive(Clone, Debug, Serialize)]
pub struct Submission {
    pub transaction_hash: String,
    pub accepted: bool,
    pub diagnostic: Option<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Backup {
    schema: String,
    keystore: Keystore,
    settings: Option<Settings>,
    invoice_secrets: Vec<EncryptedSecret>,
    transactions: Vec<SavedTransaction>,
}
pub struct Wallet {
    storage: Storage,
    key: Option<UnlockedKey>,
    store: Option<Keystore>,
    settings: Option<Settings>,
    snapshot: Option<Snapshot>,
    quote: Option<(Quote, PreparedTransfer, Instant)>,
    last_use: Instant,
}
impl Wallet {
    pub fn open(root: &Path) -> Result<Self> {
        let storage = Storage::open(root)?;
        let store = if storage.exists("wallet.json")? {
            let s: Keystore = serde_json::from_slice(&storage.read("wallet.json")?)?;
            s.validate()?;
            Some(s)
        } else {
            None
        };
        let settings: Option<Settings> = if storage.exists("network.json")? {
            Some(serde_json::from_slice(&storage.read("network.json")?)?)
        } else {
            None
        };
        if let Some(settings) = &settings {
            settings.validate()?;
        }
        Ok(Self {
            storage,
            key: None,
            store,
            settings,
            snapshot: None,
            quote: None,
            last_use: Instant::now(),
        })
    }
    pub fn create(&mut self, name: &str, password: &str) -> Result<()> {
        ensure!(self.store.is_none(), "wallet.already_exists");
        let key = UnlockedKey::generate()?;
        self.install(name, password, key)
    }
    pub fn import_key(&mut self, name: &str, password: &str, path: &Path) -> Result<()> {
        ensure!(self.store.is_none(), "wallet.already_exists");
        self.install(name, password, UnlockedKey::import_file(path)?)
    }
    fn install(&mut self, name: &str, password: &str, key: UnlockedKey) -> Result<()> {
        let store = Keystore::seal(name, &key, password)?;
        self.storage
            .create("wallet.json", &serde_json::to_vec(&store)?)?;
        self.store = Some(store);
        self.key = Some(key);
        self.last_use = Instant::now();
        Ok(())
    }
    pub fn restore(&mut self, encrypted: &[u8], password: &str) -> Result<()> {
        ensure!(
            self.store.is_none() && encrypted.len() <= 4 * 1024 * 1024,
            "wallet.restore_unavailable"
        );
        let backup: Backup = serde_json::from_slice(encrypted)?;
        ensure!(
            backup.schema == "morph.local_wallet_backup.v1"
                && backup.invoice_secrets.len() + backup.transactions.len() <= 9998,
            "wallet.unsupported_keystore"
        );
        if let Some(settings) = &backup.settings {
            settings.validate()?;
        }
        let key = backup.keystore.unlock(password)?;
        let mut records = Vec::new();
        for secret in &backup.invoice_secrets {
            let _clear = key.invoice_secret(secret)?;
            records.push((
                format!("invoice-{}.json", &secret.payment_hash[2..]),
                serde_json::to_vec(secret)?,
            ));
        }
        for tx in &backup.transactions {
            let packed =
                packed::Transaction::from_slice(&hex::decode(&tx.signed_transaction)?)?.into_view();
            ensure!(
                tx.transaction_hash == format!("{:#x}", packed.hash())
                    && tx.inputs
                        == packed
                            .inputs()
                            .into_iter()
                            .map(|i| hex::encode(i.previous_output().as_slice()))
                            .collect::<Vec<_>>(),
                "wallet.corrupt_history"
            );
            records.push((
                format!("tx-{}.json", &tx.transaction_hash[2..]),
                serde_json::to_vec(tx)?,
            ));
        }
        // Validate everything before writing. The keystore is installed last; an interrupted restore
        // can resume only if already-written immutable evidence matches byte-for-byte.
        if let Some(settings) = &backup.settings {
            records.push(("network.json".into(), serde_json::to_vec(settings)?));
        }
        for (name, bytes) in records {
            if self.storage.exists(&name)? {
                ensure!(
                    self.storage.read(&name)? == bytes,
                    "wallet.restore_conflict"
                );
            } else {
                self.storage.create(&name, &bytes)?;
            }
        }
        self.storage
            .create("wallet.json", &serde_json::to_vec(&backup.keystore)?)?;
        self.store = Some(backup.keystore);
        self.key = Some(key);
        self.settings = backup.settings;
        self.last_use = Instant::now();
        Ok(())
    }
    pub fn unlock(&mut self, password: &str) -> Result<()> {
        self.lock();
        self.key = Some(
            self.store
                .as_ref()
                .ok_or_else(|| anyhow!("wallet.not_created"))?
                .unlock(password)?,
        );
        self.last_use = Instant::now();
        Ok(())
    }
    pub fn lock(&mut self) {
        self.key = None;
        self.quote = None;
    }
    pub fn auto_lock(&mut self) -> bool {
        if self.key.is_some() && self.last_use.elapsed() >= Duration::from_secs(300) {
            self.lock();
            true
        } else {
            false
        }
    }
    pub fn change_password(&mut self, current: &str, next: &str) -> Result<()> {
        let old = self
            .store
            .as_ref()
            .ok_or_else(|| anyhow!("wallet.not_created"))?;
        let key = old.unlock(current)?;
        let next = Keystore::seal(&old.name, &key, next)?;
        self.storage
            .replace("wallet.json", &serde_json::to_vec(&next)?)?;
        self.store = Some(next);
        self.lock();
        Ok(())
    }
    /// Ciphertext backup only. Never export the unencrypted scalar through a view or JSON result.
    pub fn backup(&self) -> Result<Vec<u8>> {
        let mut invoice_secrets = Vec::new();
        let mut transactions = Vec::new();
        for name in self.storage.names()? {
            if name.starts_with("invoice-") && name.ends_with(".json") {
                invoice_secrets.push(serde_json::from_slice(&self.storage.read(&name)?)?);
            }
            if name.starts_with("tx-") && name.ends_with(".json") {
                transactions.push(serde_json::from_slice(&self.storage.read(&name)?)?);
            }
        }
        let bytes = serde_json::to_vec_pretty(&Backup {
            schema: "morph.local_wallet_backup.v1".into(),
            keystore: self
                .store
                .clone()
                .ok_or_else(|| anyhow!("wallet.not_created"))?,
            settings: self.settings.clone(),
            invoice_secrets,
            transactions,
        })?;
        ensure!(bytes.len() <= 4 * 1024 * 1024, "wallet.file_too_large");
        Ok(bytes)
    }
    pub fn payment_secret(&mut self, hash: Option<&str>) -> Result<morph_key_input::SecretString> {
        self.auto_lock();
        let key = self.key.as_ref().ok_or_else(|| anyhow!("wallet.locked"))?;
        let clear = if let Some(hash) = hash {
            ensure!(
                hash.len() == 66
                    && hash.starts_with("0x")
                    && hash[2..].bytes().all(|b| b.is_ascii_hexdigit()),
                "wallet.invalid_secret"
            );
            let sealed: EncryptedSecret = serde_json::from_slice(
                &self.storage.read(&format!("invoice-{}.json", &hash[2..]))?,
            )?;
            ensure!(sealed.payment_hash == hash, "wallet.invalid_secret");
            key.invoice_secret(&sealed)?
        } else {
            let (sealed, clear) = key.new_invoice_secret()?;
            self.storage.create(
                &format!("invoice-{}.json", &sealed.payment_hash[2..]),
                &serde_json::to_vec(&sealed)?,
            )?;
            clear
        };
        self.last_use = Instant::now();
        Ok(clear)
    }
    pub fn configure(&mut self, settings: Settings) -> Result<()> {
        settings.validate()?;
        let chain = Chain::new(settings.chain.clone())?;
        chain.verify_network()?;
        self.storage
            .replace("network.json", &serde_json::to_vec(&settings)?)?;
        self.settings = Some(settings);
        self.snapshot = None;
        self.quote = None;
        Ok(())
    }
    pub fn admit_assets(&mut self, manifest: AssetManifest) -> Result<()> {
        let mut settings = self
            .settings
            .clone()
            .ok_or_else(|| anyhow!("wallet.network_not_configured"))?;
        ensure!(
            manifest.genesis_hash == settings.chain.genesis_hash,
            "wallet.network_mismatch"
        );
        ensure!(!manifest.assets.is_empty(), "wallet.invalid_asset");
        for asset in manifest.assets {
            // Never silently replace decimals or a deployment for an already admitted identity.
            if let Some(existing) = settings.assets.iter().find(|a| a.hash() == asset.hash()) {
                ensure!(
                    serde_json::to_value(existing)? == serde_json::to_value(&asset)?,
                    "wallet.asset_definition_conflict"
                );
            } else {
                settings.assets.push(asset);
            }
        }
        self.configure(settings)
    }
    pub fn prepare_estimated(
        &mut self,
        recipient: &str,
        asset: Option<&str>,
        amount: &str,
    ) -> Result<Quote> {
        let rate = self.chain()?.fee_rate()?;
        self.prepare(recipient, asset, amount, rate, 100_000)
    }
    fn chain(&self) -> Result<Chain> {
        Chain::new(
            self.settings
                .as_ref()
                .ok_or_else(|| anyhow!("wallet.network_not_configured"))?
                .chain
                .clone(),
        )
    }
    fn owner(&self) -> Result<packed::Script> {
        let store = self
            .store
            .as_ref()
            .ok_or_else(|| anyhow!("wallet.not_created"))?;
        morph_packages::multi_asset_funding::funding_wallet_lock(&hex::decode(&store.public_key)?)
    }
    pub fn view(&mut self) -> Result<WalletView> {
        self.auto_lock();
        let (name, public_key, address) = if let Some(store) = &self.store {
            let network = self
                .settings
                .as_ref()
                .map_or(Network::Devnet, |v| v.chain.network);
            (
                store.name.clone(),
                store.public_key.clone(),
                address::encode(&self.owner()?, network)?,
            )
        } else {
            (String::new(), String::new(), String::new())
        };
        Ok(WalletView {
            exists: self.store.is_some(),
            unlocked: self.key.is_some(),
            name,
            public_key,
            address,
            settings: self.settings.clone(),
            balance: self.snapshot.as_ref().map(|s| s.balance.clone()),
            local_transactions: self.saved()?,
        })
    }
    pub fn can_observe(&self) -> bool {
        self.store.is_some() && self.settings.is_some() && self.quote.is_none()
    }
    pub fn refresh(&mut self) -> Result<WalletView> {
        self.quote = None;
        self.snapshot = None; // A failed refresh must not leave an old balance marked spendable.
        self.snapshot = Some(self.chain()?.snapshot(&self.owner()?, &self.reserved()?)?);
        self.view()
    }
    pub fn prepare(
        &mut self,
        recipient: &str,
        asset_hash: Option<&str>,
        amount: &str,
        fee_rate: u64,
        max_fee: u64,
    ) -> Result<Quote> {
        self.auto_lock();
        ensure!(self.key.is_some(), "wallet.locked");
        self.quote = None;
        self.refresh()?;
        let settings = self
            .settings
            .as_ref()
            .ok_or_else(|| anyhow!("wallet.network_not_configured"))?;
        let token = if let Some(hash) = asset_hash {
            Some(
                settings
                    .assets
                    .iter()
                    .find(|a| a.hash() == hash)
                    .ok_or_else(|| anyhow!("wallet.asset_not_admitted"))?,
            )
        } else {
            None
        };
        let display_amount = amount.to_owned();
        let amount = decimal_amount(amount, token.map_or(8, |a| a.decimals))?;
        let recipient_lock = address::decode(recipient, settings.chain.network)?;
        let snapshot = self
            .snapshot
            .as_ref()
            .ok_or_else(|| anyhow!("wallet.not_synced"))?;
        let prepared = transaction::prepare(
            &self.owner()?,
            snapshot.secp_dep.clone(),
            &snapshot.coins,
            &self.reserved()?,
            &Transfer {
                recipient: recipient_lock,
                amount,
                token: token.map(Asset::token),
                fee_rate,
                max_fee,
            },
        )?;
        let mut nonce = [0u8; 16];
        getrandom::fill(&mut nonce).map_err(|_| anyhow!("wallet.random_unavailable"))?;
        let quote = Quote {
            id: hex::encode(nonce),
            recipient: recipient.to_owned(),
            asset: token.map_or_else(|| "CKB".into(), |a| a.symbol.clone()),
            summary: prepared.summary().clone(),
            display_amount,
            fee_rate,
        };
        self.quote = Some((quote.clone(), prepared, Instant::now()));
        self.last_use = Instant::now();
        Ok(quote)
    }
    pub fn submit_reviewed(&mut self, quote_id: &str) -> Result<Submission> {
        self.auto_lock();
        ensure!(self.key.is_some(), "wallet.locked");
        let (quote, prepared, created) = self
            .quote
            .take()
            .ok_or_else(|| anyhow!("wallet.review_required"))?;
        ensure!(
            quote.id == quote_id && created.elapsed() < Duration::from_secs(90),
            "wallet.review_expired"
        );
        let chain = self.chain()?;
        chain.verify_inputs(&prepared)?;
        let key = self.key.as_ref().ok_or_else(|| anyhow!("wallet.locked"))?;
        let tx = prepared.sign(key)?;
        chain.preflight(&tx)?;
        let hash = format!("{:#x}", tx.hash());
        let saved = SavedTransaction {
            genesis_hash: chain.config.genesis_hash.clone(),
            transaction_hash: hash.clone(),
            signed_transaction: hex::encode(tx.data().as_slice()),
            inputs: prepared
                .coins()
                .iter()
                .map(|c| hex::encode(c.out_point.as_slice()))
                .collect(),
            created_at: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        };
        let filename = format!("tx-{}.json", &hash[2..]);
        self.storage
            .create(&filename, &serde_json::to_vec(&saved)?)?;
        self.last_use = Instant::now();
        self.snapshot = None;
        // Every failure after durable signature publication is tracked as unresolved, not retried.
        match chain.submit(&tx) {
            Ok(_) => Ok(Submission {
                transaction_hash: hash,
                accepted: true,
                diagnostic: None,
            }),
            Err(e) => Ok(Submission {
                transaction_hash: hash,
                accepted: false,
                diagnostic: Some(e.to_string()),
            }),
        }
    }
    pub fn resend_exact(&self, hash: &str) -> Result<Submission> {
        let saved = self
            .saved()?
            .into_iter()
            .find(|v| v.transaction_hash == hash)
            .ok_or_else(|| anyhow!("wallet.transaction_not_found"))?;
        let chain = self.chain()?;
        ensure!(
            saved.genesis_hash == chain.config.genesis_hash,
            "wallet.network_mismatch"
        );
        let packed = packed::Transaction::from_slice(&hex::decode(saved.signed_transaction)?)?;
        let tx = packed.into_view();
        ensure!(
            format!("{:#x}", tx.hash()) == hash,
            "wallet.corrupt_history"
        );
        match chain.submit(&tx) {
            Ok(_) => Ok(Submission {
                transaction_hash: hash.into(),
                accepted: true,
                diagnostic: None,
            }),
            Err(e) => Ok(Submission {
                transaction_hash: hash.into(),
                accepted: false,
                diagnostic: Some(e.to_string()),
            }),
        }
    }
    pub fn status(&self, hash: &str) -> Result<Value> {
        self.chain()?.inspect_transaction(hash, &self.owner()?)
    }
    pub fn history(&self, cursor: Option<&str>) -> Result<Value> {
        self.chain()?.history(&self.owner()?, cursor)
    }
    fn saved(&self) -> Result<Vec<SavedTransaction>> {
        let mut values = Vec::new();
        for name in self.storage.names()? {
            if name.starts_with("tx-") && name.ends_with(".json") {
                let record: SavedTransaction = serde_json::from_slice(&self.storage.read(&name)?)?;
                if self
                    .settings
                    .as_ref()
                    .is_none_or(|s| s.chain.genesis_hash == record.genesis_hash)
                {
                    values.push(record);
                }
            }
        }
        values.sort_by_key(|v| std::cmp::Reverse(v.created_at));
        Ok(values)
    }
    fn reserved(&self) -> Result<BTreeSet<Vec<u8>>> {
        self.saved()?
            .into_iter()
            .flat_map(|v| v.inputs)
            .map(|s| hex::decode(s).map_err(Into::into))
            .collect()
    }
}
/// Display decimals never pass through floating point, including u128-max token balances.
pub fn decimal_amount(text: &str, decimals: u8) -> Result<u128> {
    ensure!(
        decimals <= 38 && !text.is_empty() && text.len() <= 80 && text.trim() == text,
        "wallet.amount_format"
    );
    let mut parts = text.split('.');
    let whole = parts
        .next()
        .ok_or_else(|| anyhow!("wallet.amount_format"))?;
    let fraction = parts.next().unwrap_or("");
    ensure!(
        parts.next().is_none()
            && !whole.is_empty()
            && whole.bytes().all(|b| b.is_ascii_digit())
            && fraction.bytes().all(|b| b.is_ascii_digit())
            && fraction.len() <= decimals as usize,
        "wallet.amount_format"
    );
    let whole = whole.parse::<u128>()?;
    let fraction = if fraction.is_empty() {
        0
    } else {
        fraction.parse::<u128>()?
    };
    whole
        .checked_mul(10u128.pow(decimals as u32))
        .and_then(|v| {
            v.checked_add(
                fraction
                    * 10u128
                        .pow(decimals as u32 - text.split('.').nth(1).unwrap_or("").len() as u32),
            )
        })
        .ok_or_else(|| anyhow!("wallet.amount_overflow"))
}
pub fn display_amount(raw: &str, decimals: u8) -> Result<String> {
    ensure!(decimals <= 38, "wallet.invalid_asset");
    let value = raw.parse::<u128>()?;
    let unit = 10u128.pow(decimals as u32);
    let whole = value / unit;
    let rest = value % unit;
    if rest == 0 {
        return Ok(whole.to_string());
    }
    Ok(format!(
        "{whole}.{}",
        format!("{rest:0width$}", width = decimals as usize).trim_end_matches('0')
    ))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn backup_restores_encrypted_payment_authority_and_password_rotation_preserves_it() {
        let mut id = [0u8; 8];
        getrandom::fill(&mut id).unwrap();
        let root = std::env::temp_dir().join(format!("morph-wallet-backup-{}", hex::encode(id)));
        let mut wallet = Wallet::open(&root.join("source")).unwrap();
        wallet.create("测试钱包", "initial test password").unwrap();
        let clear = wallet.payment_secret(None).unwrap();
        let hash = format!(
            "0x{}",
            hex::encode(morph_core::blake2b256(
                &hex::decode(clear.trim_start_matches("0x")).unwrap()
            ))
        );
        let old = wallet.backup().unwrap();
        assert!(!String::from_utf8_lossy(&old).contains(&*clear));
        wallet
            .change_password("initial test password", "rotated test password")
            .unwrap();
        assert!(!wallet.view().unwrap().unlocked);
        assert!(wallet.unlock("initial test password").is_err());
        wallet.unlock("rotated test password").unwrap();
        assert_eq!(&*wallet.payment_secret(Some(&hash)).unwrap(), &*clear);
        wallet.last_use = Instant::now() - Duration::from_secs(301);
        assert!(wallet.auto_lock());
        assert!(wallet.payment_secret(Some(&hash)).is_err());
        let backup = wallet.backup().unwrap();
        let mut damaged: Value = serde_json::from_slice(&backup).unwrap();
        damaged["invoice_secrets"][0]["ciphertext"] = Value::String("00".repeat(48));
        let mut restored = Wallet::open(&root.join("restore")).unwrap();
        let mut bad_network: Value = serde_json::from_slice(&backup).unwrap();
        bad_network["settings"] = serde_json::to_value(Settings {
            chain: NetworkConfig {
                network: Network::Mainnet,
                rpc_url: "http://127.0.0.1:18314".into(),
                indexer_url: "http://127.0.0.1:18314".into(),
                genesis_hash: format!("0x{}", "11".repeat(32)),
            },
            assets: vec![],
        })
        .unwrap();
        assert!(
            restored
                .restore(
                    &serde_json::to_vec(&bad_network).unwrap(),
                    "rotated test password"
                )
                .is_err()
        );
        assert!(!restored.storage.exists("wallet.json").unwrap());
        assert!(!restored.storage.exists("network.json").unwrap());
        assert!(
            restored
                .restore(
                    &serde_json::to_vec(&damaged).unwrap(),
                    "rotated test password"
                )
                .is_err()
        );
        assert!(!restored.view().unwrap().exists);
        restored.restore(&backup, "rotated test password").unwrap();
        assert_eq!(&*restored.payment_secret(Some(&hash)).unwrap(), &*clear);
        assert!(restored.restore(&old, "initial test password").is_err());
        drop(wallet);
        drop(restored);
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn human_amounts_preserve_precision_and_reject_overflow() {
        assert_eq!(decimal_amount("1.00000001", 8).unwrap(), 100000001);
        assert_eq!(
            decimal_amount(&u128::MAX.to_string(), 0).unwrap(),
            u128::MAX
        );
        for bad in ["-1", "1e8", ".1", "1.000000001", " 1", "1..2"] {
            assert!(decimal_amount(bad, 8).is_err());
        }
        assert!(decimal_amount(&u128::MAX.to_string(), 8).is_err());
    }
}
