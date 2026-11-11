//! Local wallet UI: intent first, exact transaction review second. No channel journal authority.
mod worker;
use crate::{
    design as d,
    i18n::{Language, Text},
    presentation as p,
};
use gpui_kit::TestSupportExt;
use gpui_kit::{
    assets::IconName,
    component::{
        Disableable, Selectable, Sizable,
        button::{Button, ButtonVariants},
        input::{Input, InputEvent, InputState},
    },
    *,
};
use morph_key_input::SecretString;
use morph_wallet::{
    address::Network,
    service::{AssetManifest, Quote, Submission, WalletView, display_amount},
};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};
use worker::{Command, Reply, Worker};

#[derive(Clone, Copy, PartialEq)]
enum Screen {
    Home,
    Send,
    Receive,
    History,
    Settings,
}
#[derive(Clone, Copy, PartialEq, Debug)]
enum ConnectionPreset {
    Public,
    Local,
    Custom,
}
impl ConnectionPreset {
    fn endpoint(self, network: Network) -> Option<&'static str> {
        match (self, network) {
            (Self::Public, Network::Testnet) => Some("https://testnet.ckb.dev/"),
            (Self::Public, Network::Mainnet) => Some("https://mainnet.ckb.dev/"),
            (Self::Local, Network::Devnet) => Some("http://127.0.0.1:18114"),
            (Self::Local, _) => Some("http://127.0.0.1:8114"),
            _ => None,
        }
    }
    fn detect(network: Network, rpc: &str, indexer: &str) -> Self {
        if rpc.trim_end_matches('/') == indexer.trim_end_matches('/') || indexer.is_empty() {
            for preset in [Self::Public, Self::Local] {
                if preset
                    .endpoint(network)
                    .is_some_and(|url| url.trim_end_matches('/') == rpc.trim_end_matches('/'))
                {
                    return preset;
                }
            }
        }
        Self::Custom
    }
}
pub struct WalletPane {
    language: Language,
    screen: Screen,
    animate: bool,
    worker: Option<Worker>,
    state: Option<WalletView>,
    busy: bool,
    dialog: bool,
    error: Option<String>,
    details: bool,
    balance_details: bool,
    unlock_requested: bool,
    saved: bool,
    copied: bool,
    quote: Option<Quote>,
    submission: Option<Submission>,
    history: Option<serde_json::Value>,
    status: Option<(String, serde_json::Value)>,
    asset_manifest: Option<AssetManifest>,
    secret_target: Option<crate::workspace::DraftKey>,
    secret_delivery: Option<(crate::workspace::DraftKey, Result<SecretString, String>)>,
    name: Entity<InputState>,
    password: Entity<InputState>,
    repeat: Entity<InputState>,
    new_password: Entity<InputState>,
    recipient: Entity<InputState>,
    amount: Entity<InputState>,
    rpc: Entity<InputState>,
    indexer: Entity<InputState>,
    network: Network,
    connection_preset: ConnectionPreset,
    security_open: bool,
    asset: Option<String>,
    key_file: Option<PathBuf>,
    backup_file: Option<PathBuf>,
    _poll: Option<Task<()>>,
    _subscriptions: Vec<Subscription>,
}
impl WalletPane {
    fn t(&self, key: Text) -> &'static str {
        self.language.t(key)
    }
    fn input(
        value: &str,
        label: Text,
        secret: bool,
        language: Language,
        w: &mut Window,
        cx: &mut Context<Self>,
    ) -> Entity<InputState> {
        cx.new(|cx| {
            let mut s = InputState::new(w, cx)
                .placeholder(language.t(label))
                .masked(secret);
            s.set_value(value, w, cx);
            s
        })
    }
    pub fn new(language: Language, w: &mut Window, cx: &mut Context<Self>) -> Self {
        let started = if cfg!(test) {
            Ok(None)
        } else {
            Worker::start().map(Some)
        };
        let (worker, error) = match started {
            Ok(w) => (w, None),
            Err(e) => (None, Some(e.to_string())),
        };
        let configured_rpc = std::env::var("MORPH_CKB_RPC")
            .ok()
            .filter(|v| !v.trim().is_empty());
        let network = if configured_rpc.is_some() {
            Network::Devnet
        } else {
            Network::Testnet
        };
        let endpoint = configured_rpc
            .as_deref()
            .unwrap_or("https://testnet.ckb.dev/");
        let mut v = Self {
            language,
            screen: Screen::Home,
            animate: false,
            worker,
            state: None,
            busy: false,
            dialog: false,
            error,
            details: false,
            balance_details: false,
            unlock_requested: false,
            saved: false,
            copied: false,
            quote: None,
            submission: None,
            history: None,
            status: None,
            asset_manifest: None,
            secret_target: None,
            secret_delivery: None,
            name: Self::input("Morph", Text::WalletName, false, language, w, cx),
            password: Self::input("", Text::WalletPassword, true, language, w, cx),
            repeat: Self::input("", Text::WalletPasswordAgain, true, language, w, cx),
            new_password: Self::input("", Text::WalletNewPassword, true, language, w, cx),
            recipient: Self::input("", Text::WalletRecipient, false, language, w, cx),
            amount: Self::input("", Text::WalletAmount, false, language, w, cx),
            rpc: Self::input(endpoint, Text::WalletRPC, false, language, w, cx),
            indexer: Self::input("", Text::WalletIndexer, false, language, w, cx),
            network,
            connection_preset: ConnectionPreset::detect(network, endpoint, ""),
            security_open: false,
            asset: None,
            key_file: None,
            backup_file: None,
            _poll: None,
            _subscriptions: Vec::new(),
        };
        for input in [&v.recipient, &v.amount] {
            v._subscriptions
                .push(cx.subscribe_in(input, w, |this, _, event, _, cx| {
                    if matches!(event, InputEvent::Change) {
                        this.quote = None;
                        this.submission = None;
                        cx.notify();
                    }
                }));
        }
        v._poll = Some(cx.spawn_in(w, async move |this, cx| {
            loop {
                cx.background_executor()
                    .timer(Duration::from_millis(150))
                    .await;
                if this.update_in(cx, |this, w, cx| this.poll(w, cx)).is_err() {
                    break;
                }
            }
        }));
        v
    }
    pub fn set_visible(&self, visible: bool) {
        if let Some(worker) = &self.worker {
            worker
                .visible
                .store(visible, std::sync::atomic::Ordering::Relaxed);
        }
    }
    pub fn set_motion(&mut self, enabled: bool, cx: &mut Context<Self>) {
        if self.animate != enabled {
            self.animate = enabled;
            cx.notify();
        }
    }
    pub fn refresh_from_shortcut(&mut self, cx: &mut Context<Self>) {
        if self.state.as_ref().is_some_and(|s| s.settings.is_some()) {
            self.send(Command::Refresh, cx);
        }
    }
    pub fn request_payment_secret(
        &mut self,
        target: crate::workspace::DraftKey,
        hash: Option<String>,
        cx: &mut Context<Self>,
    ) -> bool {
        if self.secret_target.as_ref() == Some(&target) {
            return true;
        }
        if self.busy
            || self.secret_target.is_some()
            || self.secret_delivery.is_some()
            || !self.state.as_ref().is_some_and(|s| s.unlocked)
        {
            return false;
        }
        self.send(Command::PaymentSecret(hash), cx);
        if self.busy {
            self.secret_target = Some(target);
            true
        } else {
            false
        }
    }
    pub fn take_secret_delivery(
        &mut self,
    ) -> Option<(crate::workspace::DraftKey, Result<SecretString, String>)> {
        self.secret_delivery.take()
    }
    pub fn language(&mut self, language: Language, w: &mut Window, cx: &mut Context<Self>) {
        if self.language == language {
            return;
        }
        self.language = language;
        for (input, label) in [
            (&self.name, Text::WalletName),
            (&self.password, Text::WalletPassword),
            (&self.repeat, Text::WalletPasswordAgain),
            (&self.new_password, Text::WalletNewPassword),
            (&self.recipient, Text::WalletRecipient),
            (&self.amount, Text::WalletAmount),
            (&self.rpc, Text::WalletRPC),
            (&self.indexer, Text::WalletIndexer),
        ] {
            input.update(cx, |v, cx| v.set_placeholder(language.t(label), w, cx));
        }
        cx.notify();
    }
    fn send(&mut self, command: Command, cx: &mut Context<Self>) {
        if self.busy {
            return;
        }
        if matches!(
            command,
            Command::Refresh | Command::Prepare { .. } | Command::Configure { .. }
        ) {
            if let Some(state) = &mut self.state {
                state.balance = None;
            }
            self.quote = None;
        }
        self.error = None;
        self.details = false;
        self.saved = false;
        if self
            .worker
            .as_ref()
            .is_some_and(|v| v.send.try_send(command).is_ok())
        {
            self.busy = true;
        } else {
            self.error = Some("wallet.worker_unavailable".into());
        }
        cx.notify();
    }
    fn poll(&mut self, w: &mut Window, cx: &mut Context<Self>) {
        let reply = match self.worker.as_ref().map(|v| v.receive.try_recv()) {
            Some(Ok(reply)) => Some(reply),
            Some(Err(std::sync::mpsc::TryRecvError::Disconnected)) => {
                self.worker = None;
                self.busy = false;
                self.quote = None;
                if let Some(state) = &mut self.state {
                    state.unlocked = false;
                    state.balance = None;
                }
                if let Some(target) = self.secret_target.take() {
                    self.secret_delivery = Some((target, Err("wallet.worker_unavailable".into())));
                }
                if self.error.is_none() {
                    self.error = Some("wallet.worker_unavailable".into());
                }
                cx.notify();
                None
            }
            _ => None,
        };
        let Some(reply) = reply else {
            return;
        };
        if reply.completed {
            self.busy = false;
        }
        if let Some(state) = reply.view {
            self.apply_view(*state, w, cx);
        }
        match reply.result {
            Ok(Reply::View(state)) => self.apply_view(*state, w, cx),
            Ok(Reply::Quote(quote)) => self.quote = Some(*quote),
            Ok(Reply::Submitted(value)) => {
                self.quote = None;
                self.submission = Some(value);
                if let Some(s) = &mut self.state {
                    s.balance = None;
                }
            }
            Ok(Reply::Secret(secret)) => {
                if let Some(target) = self.secret_target.take() {
                    self.secret_delivery = Some((target, Ok(secret)));
                }
            }
            Ok(Reply::Saved) => self.saved = true,
            Ok(Reply::History(value)) => {
                let mut next = value;
                if let Some(mut previous) = self.history.take()
                    && let (Some(old), Some(new)) = (
                        previous["objects"].as_array_mut(),
                        next["objects"].as_array(),
                    )
                {
                    for row in new {
                        if old.len() < 200 && !old.iter().any(|v| v["tx_hash"] == row["tx_hash"]) {
                            old.push(row.clone());
                        }
                    }
                    next["objects"] = serde_json::Value::Array(old.clone());
                }
                self.history = Some(next);
            }
            Ok(Reply::Status(hash, value)) => self.status = Some((hash, value)),
            Ok(Reply::Assets(manifest)) => self.asset_manifest = Some(manifest),
            Err(error) => {
                if reply.completed {
                    if let Some(target) = self.secret_target.take() {
                        self.secret_delivery = Some((target, Err(error.to_string())));
                    }
                    self.quote = None;
                }
                self.error = Some(error.to_string());
            }
        }
        cx.notify();
    }
    fn apply_view(&mut self, state: WalletView, w: &mut Window, cx: &mut Context<Self>) {
        if state.unlocked {
            self.unlock_requested = false;
        }
        if let Some(settings) = &state.settings {
            let changed = self
                .state
                .as_ref()
                .and_then(|v| v.settings.as_ref())
                .is_none_or(|old| {
                    old.chain.genesis_hash != settings.chain.genesis_hash
                        || old.chain.rpc_url != settings.chain.rpc_url
                        || old.chain.indexer_url != settings.chain.indexer_url
                });
            if changed {
                self.network = settings.chain.network;
                self.connection_preset = ConnectionPreset::detect(
                    self.network,
                    &settings.chain.rpc_url,
                    &settings.chain.indexer_url,
                );
                self.rpc
                    .update(cx, |v, cx| v.set_value(&settings.chain.rpc_url, w, cx));
                self.indexer
                    .update(cx, |v, cx| v.set_value(&settings.chain.indexer_url, w, cx));
                self.history = None;
                self.status = None;
                self.asset = None;
                self.submission = None;
            }
        }
        if !state.unlocked {
            self.quote = None;
        }
        self.state = Some(state);
    }
    fn pick_assets(&mut self, cx: &mut Context<Self>) {
        if self.busy || self.dialog {
            return;
        }
        self.dialog = true;
        let paths = cx.prompt_for_paths(PathPromptOptions {
            files: true,
            directories: false,
            multiple: false,
            prompt: Some(self.t(Text::WalletImportAssets).into()),
        });
        cx.spawn(async move |this, cx| {
            let result = paths.await;
            let _ = this.update(cx, |this, cx| {
                this.dialog = false;
                match result {
                    Ok(Ok(Some(paths))) => {
                        if let Some(path) = paths.into_iter().next() {
                            this.send(Command::InspectAssets(path), cx);
                        }
                    }
                    Ok(Err(e)) => this.error = Some(e.to_string()),
                    _ => {}
                }
                cx.notify();
            });
        })
        .detach();
    }
    fn take_password(&mut self, w: &mut Window, cx: &mut Context<Self>) -> SecretString {
        let value = SecretString::new(self.password.read(cx).value().to_string());
        // Replace the entire input entity so its undo history cannot recover the submitted value.
        self.password = Self::input("", Text::WalletPassword, true, self.language, w, cx);
        self.repeat = Self::input("", Text::WalletPasswordAgain, true, self.language, w, cx);
        value
    }
    fn field(&self, id: &'static str, key: Text, input: &Entity<InputState>) -> Div {
        let control = Input::new(input).id(id).disabled(self.busy);
        let control = if id.contains("password") {
            control.mask_toggle()
        } else {
            control
        };
        div()
            .flex()
            .flex_col()
            .gap_2()
            .child(d::caption(self.t(key)))
            .child(control)
    }
    fn pick_file(&mut self, backup: bool, cx: &mut Context<Self>) {
        if self.busy || self.dialog {
            return;
        }
        self.dialog = true;
        let paths = cx.prompt_for_paths(PathPromptOptions {
            files: true,
            directories: false,
            multiple: false,
            prompt: Some(
                self.t(if backup {
                    Text::WalletRestore
                } else {
                    Text::WalletImportKey
                })
                .into(),
            ),
        });
        cx.spawn(async move |this, cx| {
            let result = paths.await;
            let _ = this.update(cx, |this, cx| {
                this.dialog = false;
                match result {
                    Ok(Ok(Some(paths))) => {
                        if let Some(path) = paths.into_iter().next() {
                            if backup {
                                this.backup_file = Some(path);
                                this.key_file = None;
                            } else {
                                this.key_file = Some(path);
                                this.backup_file = None;
                            }
                        }
                    }
                    Ok(Err(e)) => this.error = Some(e.to_string()),
                    _ => {}
                }
                cx.notify();
            });
        })
        .detach();
    }
    fn backup(&mut self, cx: &mut Context<Self>) {
        if self.busy || self.dialog {
            return;
        }
        self.dialog = true;
        let path = cx.prompt_for_new_path(Path::new("."), Some("morph-wallet.encrypted.json"));
        cx.spawn(async move |this, cx| {
            let result = path.await;
            let _ = this.update(cx, |this, cx| {
                this.dialog = false;
                match result {
                    Ok(Ok(Some(path))) => this.send(Command::Backup(path), cx),
                    Ok(Err(e)) => this.error = Some(e.to_string()),
                    _ => {}
                }
                cx.notify();
            });
        })
        .detach();
    }
    fn setup(&self, cx: &mut Context<Self>) -> Div {
        let restored = self.backup_file.is_some();
        let mut card = d::panel()
            .flex()
            .flex_col()
            .gap_5()
            .max_w(px(720.))
            .child(
                div()
                    .text_2xl()
                    .font_weight(FontWeight::SEMIBOLD)
                    .child(self.t(Text::WalletWelcome)),
            )
            .child(d::caption(self.t(Text::WalletWelcomeHelp)))
            .child(d::caption(self.t(Text::WalletPasswordHelp)));
        if !restored {
            card = card.child(self.field("wallet-name", Text::WalletName, &self.name));
        }
        card = card.child(self.field("wallet-password", Text::WalletPassword, &self.password));
        if !restored {
            card = card.child(self.field(
                "wallet-password-again",
                Text::WalletPasswordAgain,
                &self.repeat,
            ));
        }
        if let Some(path) = self.key_file.as_ref().or(self.backup_file.as_ref()) {
            card = card.child(d::caption(format!(
                "{} · {}",
                self.t(if restored {
                    Text::WalletBackupSelected
                } else {
                    Text::WalletKeySelected
                }),
                path.file_name().unwrap_or_default().to_string_lossy()
            )));
        }
        if self.key_file.is_some() || self.backup_file.is_some() {
            card = card.child(
                Button::new("wallet-reset-setup")
                    .ghost()
                    .label(self.t(Text::WalletStartNew))
                    .disabled(self.busy)
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.key_file = None;
                        this.backup_file = None;
                        cx.notify();
                    })),
            );
        }
        card.child(
            div()
                .flex()
                .flex_wrap()
                .gap_3()
                .child(
                    Button::new("wallet-create")
                        .primary()
                        .label(self.t(if restored {
                            Text::WalletRestoreConfirm
                        } else {
                            Text::WalletCreate
                        }))
                        .disabled(self.busy || self.dialog)
                        .on_click(cx.listener(|this, _, w, cx| {
                            if this.backup_file.is_none()
                                && (this.password.read(cx).value().len() < 12
                                    || this.password.read(cx).value()
                                        != this.repeat.read(cx).value())
                            {
                                this.error = Some(this.t(Text::WalletPasswordMismatch).into());
                                cx.notify();
                                return;
                            }
                            let password = this.take_password(w, cx);
                            if let Some(path) = this.backup_file.clone() {
                                this.send(Command::Restore { path, password }, cx);
                            } else {
                                this.send(
                                    Command::Create {
                                        name: this.name.read(cx).value().to_string(),
                                        password,
                                        key_file: this.key_file.clone(),
                                    },
                                    cx,
                                );
                            }
                        })),
                )
                .child(
                    Button::new("wallet-import-key")
                        .ghost()
                        .label(self.t(Text::WalletImportKey))
                        .disabled(self.busy || self.dialog)
                        .on_click(cx.listener(|this, _, _, cx| this.pick_file(false, cx))),
                )
                .child(
                    Button::new("wallet-restore-file")
                        .ghost()
                        .label(self.t(Text::WalletRestore))
                        .disabled(self.busy || self.dialog)
                        .on_click(cx.listener(|this, _, _, cx| this.pick_file(true, cx))),
                ),
        )
    }
    fn unlock_bar(&self, cx: &mut Context<Self>) -> Div {
        d::panel()
            .flex()
            .flex_wrap()
            .items_center()
            .gap_3()
            .child(d::caption(self.t(Text::WalletLocked)))
            .child(
                div().w(px(260.)).child(
                    Input::new(&self.password)
                        .id("wallet-unlock-password")
                        .disabled(self.busy),
                ),
            )
            .child(
                Button::new("wallet-unlock")
                    .primary()
                    .label(self.t(Text::WalletUnlock))
                    .disabled(self.busy)
                    .on_click(cx.listener(|this, _, w, cx| {
                        let pass = this.take_password(w, cx);
                        this.send(Command::Unlock(pass), cx);
                    })),
            )
    }
    fn home(&self, state: &WalletView, wide: bool, cx: &mut Context<Self>) -> Div {
        let mut view = div().flex().flex_col().gap_4();
        let balance = state.balance.as_ref();
        if state.settings.is_none() {
            view = view.child(
                d::panel()
                    .flex()
                    .flex_col()
                    .gap_3()
                    .child(div().text_xl().child(self.t(Text::WalletReadyToConnect)))
                    .child(d::caption(self.t(Text::WalletConnectHelp)))
                    .child(
                        Button::new("wallet-onboarding-connect")
                            .self_start()
                            .primary()
                            .label(self.t(Text::WalletConnect))
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.screen = Screen::Settings;
                                cx.notify();
                            })),
                    ),
            );
        }
        let balance_card = d::panel()
            .flex_1()
            .min_w_0()
            .flex()
            .flex_col()
            .gap_4()
            .child(d::caption(self.t(Text::WalletAvailable)))
            .child(
                div()
                    .text_size(rems(2.8))
                    .font_weight(FontWeight::SEMIBOLD)
                    .child(balance.map_or_else(
                        || "—".into(),
                        |b| p::amount(&b.available_plain_capacity, true, self.language),
                    )),
            )
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .gap_3()
                    .child(
                        Button::new("wallet-home-send")
                            .primary()
                            .icon(IconName::ArrowUpRight)
                            .label(self.t(Text::WalletSend))
                            .disabled(self.busy || state.settings.is_none())
                            .on_click(cx.listener(|this, _, w, cx| {
                                this.screen = Screen::Send;
                                this.submission = None;
                                w.focus(&this.recipient.read(cx).focus_handle(cx), cx);
                                cx.notify();
                            })),
                    )
                    .child(
                        Button::new("wallet-home-receive")
                            .icon(IconName::ArrowDownLeft)
                            .label(self.t(Text::WalletReceive))
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.screen = Screen::Receive;
                                cx.notify();
                            })),
                    )
                    .child(
                        Button::new("wallet-home-sync")
                            .ghost()
                            .icon(IconName::RefreshCw)
                            .label(self.t(Text::WalletSync))
                            .disabled(self.busy || state.settings.is_none())
                            .on_click(
                                cx.listener(|this, _, _, cx| this.send(Command::Refresh, cx)),
                            ),
                    ),
            );
        if wide && state.settings.is_some() {
            let address = state.address.clone();
            view = view.child(
                div().flex().gap_4().child(balance_card).child(
                    d::panel()
                        .w(px(240.))
                        .flex_shrink_0()
                        .flex()
                        .flex_col()
                        .gap_3()
                        .items_center()
                        .child(d::caption(self.t(Text::WalletReceive)))
                        .child(qr(&state.address, 152.))
                        .child(
                            Button::new("wallet-quick-copy")
                                .ghost()
                                .small()
                                .icon(if self.copied {
                                    IconName::Check
                                } else {
                                    IconName::Copy
                                })
                                .label(if self.copied {
                                    self.t(Text::Copied).to_owned()
                                } else {
                                    p::short(&address)
                                })
                                .tooltip(self.t(Text::WalletOwnAddress))
                                .on_click(cx.listener(move |this, _, _, cx| {
                                    cx.write_to_clipboard(ClipboardItem::new_string(
                                        address.clone(),
                                    ));
                                    this.copied = true;
                                    cx.notify();
                                })),
                        ),
                ),
            );
        } else {
            view = view.child(balance_card);
        }
        if let Some(b) = balance {
            view = view.child(
                Button::new("wallet-balance-details")
                    .ghost()
                    .self_start()
                    .icon(if self.balance_details {
                        IconName::ChevronDown
                    } else {
                        IconName::ChevronRight
                    })
                    .label(self.t(Text::WalletBalanceDetails))
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.balance_details = !this.balance_details;
                        cx.notify();
                    })),
            );
            if b.reserved_capacity != "0" {
                view = view.child(d::caption(format!(
                    "{} · {}",
                    self.t(Text::WalletHeld),
                    p::amount(&b.reserved_capacity, true, self.language)
                )));
            }
            if self.balance_details {
                let mut card = d::panel().flex().flex_col().gap_3();
                for (key, value) in [
                    (Text::WalletTotal, &b.total_capacity),
                    (Text::WalletOccupied, &b.occupied_capacity),
                    (Text::WalletHeld, &b.reserved_capacity),
                    (Text::WalletImmature, &b.immature_capacity),
                ] {
                    card = card.child(fact(self.t(key), p::amount(value, true, self.language)));
                }
                card = card.child(d::caption(format!(
                    "{} {} · {}",
                    self.t(Text::WalletObservedAt),
                    b.tip_number,
                    p::short(&b.tip_hash)
                )));
                card = card.child(d::caption(self.t(Text::WalletSyncHelp)));
                if b.reserved_capacity != "0" {
                    card = card.child(d::caption(self.t(Text::WalletHeldHelp)));
                }
                view = view.child(card);
            }
            if !b.token_quantities.is_empty() {
                let mut card = d::panel()
                    .flex()
                    .flex_col()
                    .gap_3()
                    .child(self.t(Text::WalletAssets));
                for (hash, quantity) in &b.token_quantities {
                    let asset = state
                        .settings
                        .as_ref()
                        .and_then(|s| s.assets.iter().find(|a| a.hash() == *hash));
                    card = card.child(fact(
                        asset.map_or(self.t(Text::WalletTokenRaw), |a| a.symbol.as_str()),
                        format!(
                            "{} · {}",
                            asset
                                .and_then(|a| display_amount(quantity, a.decimals).ok())
                                .unwrap_or_else(|| quantity.clone()),
                            p::short(hash)
                        ),
                    ));
                }
                view = view.child(card);
            }
        } else {
            view = view.child(d::caption(self.t(Text::WalletNotSynced)));
        }
        view
    }

    fn receive(&self, state: &WalletView, cx: &mut Context<Self>) -> Div {
        if state.settings.is_none() {
            return d::panel().child(self.t(Text::WalletNetworkRequired));
        }
        let value = state.address.clone();
        d::panel()
            .flex()
            .flex_col()
            .gap_5()
            .items_center()
            .py_8()
            .child(div().text_xl().child(self.t(Text::WalletOwnAddress)))
            .child(qr(&state.address, 240.))
            .child(
                div()
                    .id("wallet-address")
                    .w_full()
                    .min_w_0()
                    .overflow_x_scroll()
                    .text_sm()
                    .child(value.clone()),
            )
            .child(
                Button::new("wallet-copy-address")
                    .icon(if self.copied {
                        IconName::Check
                    } else {
                        IconName::Copy
                    })
                    .label(self.t(if self.copied {
                        Text::Copied
                    } else {
                        Text::Copy
                    }))
                    .on_click(cx.listener(move |this, _, _, cx| {
                        cx.write_to_clipboard(ClipboardItem::new_string(value.clone()));
                        this.copied = true;
                        cx.notify();
                    })),
            )
    }
    fn send_form(&self, state: &WalletView, cx: &mut Context<Self>) -> Div {
        let mut panel = d::panel().flex().flex_col().gap_5().max_w(px(900.));
        if let Some(submission) = &self.submission {
            let hash = submission.transaction_hash.clone();
            return panel
                .child(div().text_xl().child(self.t(if submission.accepted {
                    Text::WalletSubmitted
                } else {
                    Text::WalletUncertain
                })))
                .child(d::caption(hash.clone()))
                .child(
                    Button::new("wallet-submission-status")
                        .label(self.t(Text::WalletCheckStatus))
                        .disabled(self.busy)
                        .on_click(cx.listener(move |this, _, _, cx| {
                            this.send(Command::Status(hash.clone()), cx)
                        })),
                )
                .child(
                    Button::new("wallet-new-payment")
                        .ghost()
                        .label(self.t(Text::WalletStartPayment))
                        .disabled(self.busy)
                        .on_click(cx.listener(|this, _, w, cx| {
                            this.submission = None;
                            this.quote = None;
                            this.status = None;
                            this.amount.update(cx, |v, cx| v.set_value("", w, cx));
                            cx.notify();
                        })),
                );
        }
        if let Some(quote) = &self.quote {
            let id = quote.id.clone();
            return panel
                .child(div().text_xl().child(self.t(Text::WalletReview)))
                .child(d::caption(self.t(Text::WalletReviewHelp)))
                .child(fact(self.t(Text::WalletRecipient), quote.recipient.clone()))
                .child(fact(
                    self.t(Text::WalletAmount),
                    format!("{} {}", quote.display_amount, quote.asset),
                ))
                .child(fact(
                    self.t(Text::WalletRecipientType),
                    quote
                        .summary
                        .token_type_hash
                        .clone()
                        .unwrap_or_else(|| "CKB".into()),
                ))
                .child(fact(
                    self.t(Text::WalletFee),
                    p::amount(&quote.summary.fee, true, self.language),
                ))
                .child(fact(
                    self.t(Text::WalletRecipientCapacity),
                    p::amount(&quote.summary.recipient_capacity, true, self.language),
                ))
                .child(fact(
                    self.t(Text::WalletFeeRate),
                    quote.fee_rate.to_string(),
                ))
                .child(fact(
                    self.t(Text::WalletChange),
                    p::amount(&quote.summary.change_capacity, true, self.language),
                ))
                .child(
                    div()
                        .flex()
                        .flex_wrap()
                        .gap_3()
                        .child(
                            Button::new("wallet-confirm-send")
                                .primary()
                                .label(self.t(Text::WalletConfirm))
                                .disabled(self.busy || !state.unlocked)
                                .on_click(cx.listener(move |this, _, _, cx| {
                                    this.send(Command::Submit(id.clone()), cx)
                                })),
                        )
                        .child(
                            Button::new("wallet-edit-payment")
                                .label(self.t(Text::EditDraft))
                                .disabled(self.busy)
                                .on_click(cx.listener(|this, _, _, cx| {
                                    this.quote = None;
                                    cx.notify();
                                })),
                        ),
                );
        }
        let mut assets = div().flex().flex_wrap().gap_2().child(
            Button::new("wallet-asset-ckb")
                .label("CKB")
                .selected(self.asset.is_none())
                .disabled(self.busy)
                .on_click(cx.listener(|this, _, _, cx| {
                    this.asset = None;
                    this.quote = None;
                    cx.notify();
                })),
        );
        if let Some(settings) = &state.settings {
            for (i, asset) in settings.assets.iter().enumerate() {
                let hash = asset.hash();
                assets = assets.child(
                    Button::new(("wallet-asset", i))
                        .label(asset.symbol.clone())
                        .selected(self.asset.as_ref() == Some(&hash))
                        .disabled(self.busy)
                        .on_click(cx.listener(move |this, _, _, cx| {
                            this.asset = Some(hash.clone());
                            this.quote = None;
                            cx.notify();
                        })),
                );
            }
        }
        panel = panel
            .child(self.field("wallet-recipient", Text::WalletRecipient, &self.recipient))
            .child(assets)
            .child(self.field("wallet-amount", Text::WalletAmount, &self.amount));
        panel.child(
            Button::new("wallet-prepare-payment")
                .primary()
                .label(self.t(Text::WalletReview))
                .disabled(self.busy || !state.unlocked || state.settings.is_none())
                .on_click(cx.listener(|this, _, _, cx| {
                    this.send(
                        Command::Prepare {
                            recipient: this.recipient.read(cx).value().trim().to_owned(),
                            asset: this.asset.clone(),
                            amount: this.amount.read(cx).value().to_string(),
                        },
                        cx,
                    )
                })),
        )
    }
    fn choose_connection(
        &mut self,
        network: Network,
        mut preset: ConnectionPreset,
        w: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if network == Network::Devnet && preset == ConnectionPreset::Public {
            preset = ConnectionPreset::Local;
        }
        self.network = network;
        self.connection_preset = preset;
        if let Some(endpoint) = preset.endpoint(network) {
            self.rpc.update(cx, |v, cx| v.set_value(endpoint, w, cx));
            self.indexer.update(cx, |v, cx| v.set_value("", w, cx));
        }
        self.quote = None;
        cx.notify();
    }
    fn settings(&self, cx: &mut Context<Self>) -> Div {
        let mut networks = div().flex().flex_wrap().gap_2();
        for (i, network, label) in [
            (0_usize, Network::Testnet, Text::NetworkTestnet),
            (1, Network::Mainnet, Text::NetworkMainnet),
            (2, Network::Devnet, Text::NetworkDevnet),
        ] {
            networks = networks.child(
                Button::new(("wallet-network", i))
                    .label(self.t(label))
                    .selected(self.network == network)
                    .disabled(self.busy)
                    .on_click(cx.listener(move |this, _, w, cx| {
                        this.choose_connection(network, this.connection_preset, w, cx)
                    })),
            );
        }
        let mut presets = div().flex().flex_wrap().gap_2();
        for (i, preset, label) in [
            (0_usize, ConnectionPreset::Public, Text::WalletPublicNode),
            (1, ConnectionPreset::Local, Text::WalletLocalNode),
            (2, ConnectionPreset::Custom, Text::WalletCustomNode),
        ] {
            if preset == ConnectionPreset::Public && self.network == Network::Devnet {
                continue;
            }
            presets = presets.child(
                Button::new(("wallet-preset", i))
                    .label(self.t(label))
                    .selected(self.connection_preset == preset)
                    .disabled(self.busy)
                    .on_click(cx.listener(move |this, _, w, cx| {
                        this.choose_connection(this.network, preset, w, cx)
                    })),
            );
        }
        let mut connection = d::panel()
            .flex()
            .flex_col()
            .gap_4()
            .child(
                div()
                    .text_lg()
                    .font_weight(FontWeight::MEDIUM)
                    .child(self.t(Text::WalletNetwork)),
            )
            .child(networks)
            .child(presets);
        if self.connection_preset == ConnectionPreset::Custom {
            connection = connection
                .child(self.field("wallet-rpc", Text::WalletRPC, &self.rpc))
                .child(self.field("wallet-indexer", Text::WalletIndexer, &self.indexer))
                .child(d::caption(self.t(Text::WalletEndpointHelp)));
        } else {
            connection = connection
                .child(d::caption(self.rpc.read(cx).value().to_string()))
                .child(d::caption(self.t(
                    if self.connection_preset == ConnectionPreset::Public {
                        Text::WalletPublicHelp
                    } else {
                        Text::WalletLocalHelp
                    },
                )));
        }
        connection = connection.child(
            Button::new("wallet-connect-node")
                .primary()
                .self_start()
                .label(self.t(Text::WalletConnectionPreview))
                .disabled(self.busy)
                .on_click(cx.listener(|this, _, _, cx| {
                    let rpc = this.rpc.read(cx).value().trim().to_owned();
                    let indexer = this.indexer.read(cx).value().trim().to_owned();
                    this.send(
                        Command::Configure {
                            network: this.network,
                            indexer: if indexer.is_empty() {
                                rpc.clone()
                            } else {
                                indexer
                            },
                            rpc,
                        },
                        cx,
                    );
                })),
        );
        let mut security = d::panel()
            .flex()
            .flex_col()
            .gap_4()
            .child(
                div()
                    .text_lg()
                    .font_weight(FontWeight::MEDIUM)
                    .child(self.t(Text::WalletSecurity)),
            )
            .child(d::caption(self.t(Text::WalletBackupHelp)))
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .gap_2()
                    .child(
                        Button::new("wallet-backup")
                            .icon(IconName::Download)
                            .label(self.t(Text::WalletBackup))
                            .disabled(self.busy || self.dialog)
                            .on_click(cx.listener(|this, _, _, cx| this.backup(cx))),
                    )
                    .child(
                        Button::new("wallet-password-disclosure")
                            .ghost()
                            .label(self.t(Text::WalletChangePassword))
                            .icon(if self.security_open {
                                IconName::ChevronDown
                            } else {
                                IconName::ChevronRight
                            })
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.security_open = !this.security_open;
                                cx.notify();
                            })),
                    ),
            );
        if self.saved {
            security = security.child(d::status(self.t(Text::WalletSaved), d::Tone::Good));
        }
        if self.security_open {
            security = security
                .child(self.field(
                    "wallet-current-password",
                    Text::WalletPassword,
                    &self.password,
                ))
                .child(self.field(
                    "wallet-new-password",
                    Text::WalletNewPassword,
                    &self.new_password,
                ))
                .child(self.field(
                    "wallet-new-password-again",
                    Text::WalletNewPasswordAgain,
                    &self.repeat,
                ))
                .child(
                    Button::new("wallet-change-password")
                        .label(self.t(Text::WalletChangePassword))
                        .disabled(self.busy)
                        .on_click(cx.listener(|this, _, w, cx| {
                            if this.new_password.read(cx).value() != this.repeat.read(cx).value() {
                                this.error = Some("wallet.password_mismatch".into());
                                cx.notify();
                                return;
                            }
                            let current = this.take_password(w, cx);
                            let next =
                                SecretString::new(this.new_password.read(cx).value().to_string());
                            this.new_password = Self::input(
                                "",
                                Text::WalletNewPassword,
                                true,
                                this.language,
                                w,
                                cx,
                            );
                            this.send(Command::ChangePassword { current, next }, cx);
                        })),
                );
        }
        div()
            .flex()
            .flex_col()
            .gap_5()
            .child(connection)
            .child(security)
            .child(
                d::panel()
                    .flex()
                    .items_center()
                    .flex_wrap()
                    .gap_3()
                    .child(div().flex_1().child(self.t(Text::WalletAssetManagement)))
                    .child(
                        Button::new("wallet-import-assets")
                            .label(self.t(Text::WalletImportAssets))
                            .disabled(
                                self.busy
                                    || self.dialog
                                    || self.state.as_ref().is_none_or(|s| s.settings.is_none()),
                            )
                            .on_click(cx.listener(|this, _, _, cx| this.pick_assets(cx))),
                    ),
            )
    }

    fn transactions(&self, state: &WalletView, cx: &mut Context<Self>) -> Div {
        let mut view = d::panel().flex().flex_col().gap_4().child(
            Button::new("wallet-fetch-history")
                .ghost()
                .self_start()
                .icon(IconName::RefreshCw)
                .label(self.t(Text::WalletFetchHistory))
                .disabled(self.busy || state.settings.is_none())
                .on_click(cx.listener(|this, _, _, cx| {
                    this.history = None;
                    this.send(Command::History(None), cx)
                })),
        );
        let mut hashes = state
            .local_transactions
            .iter()
            .map(|t| t.transaction_hash.clone())
            .collect::<Vec<_>>();
        if let Some(rows) = self.history.as_ref().and_then(|v| v["objects"].as_array()) {
            for row in rows {
                if let Some(hash) = row["tx_hash"].as_str()
                    && !hashes.iter().any(|v| v == hash)
                {
                    hashes.push(hash.to_owned());
                }
            }
        }
        if hashes.is_empty() {
            view = view.child(d::caption(self.t(Text::WalletNoTransactions)));
        }
        for (i, hash) in hashes.iter().take(200).enumerate() {
            let exact = hash.clone();
            let resend = hash.clone();
            let local = state
                .local_transactions
                .iter()
                .any(|t| t.transaction_hash == *hash);
            let observed = self
                .history
                .as_ref()
                .and_then(|h| h["objects"].as_array())
                .and_then(|rows| rows.iter().find(|row| row["tx_hash"] == *hash));
            let mut row = div()
                .flex()
                .flex_wrap()
                .gap_3()
                .items_center()
                .child(div().flex_1().min_w_0().child(p::short(hash)))
                .child(
                    Button::new(("wallet-tx-status", i))
                        .label(self.t(Text::WalletCheckStatus))
                        .disabled(self.busy)
                        .on_click(cx.listener(move |this, _, _, cx| {
                            this.send(Command::Status(exact.clone()), cx)
                        })),
                );
            if local
                && observed.is_none_or(|v| v["tx_status"]["status"] != "committed")
                && !self
                    .status
                    .as_ref()
                    .is_some_and(|(h, v)| h == hash && v["tx_status"]["status"] == "committed")
            {
                row = row.child(
                    Button::new(("wallet-tx-resend", i))
                        .ghost()
                        .label(self.t(Text::WalletResend))
                        .disabled(self.busy)
                        .on_click(cx.listener(move |this, _, _, cx| {
                            this.send(Command::Resend(resend.clone()), cx)
                        })),
                );
            }
            view = view.child(d::rule()).child(row);
            if let Some(observed) = observed {
                view = view.child(self.transaction_changes(observed, state));
            }
        }
        if let Some(history) = &self.history
            && let Some(cursor) = history["last_cursor"]
                .as_str()
                .filter(|_| hashes.len() < 200 && history["has_more"] == true)
        {
            let cursor = cursor.to_owned();
            view = view.child(
                Button::new("wallet-more-history")
                    .ghost()
                    .label(self.t(Text::WalletMoreHistory))
                    .disabled(self.busy)
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.send(Command::History(Some(cursor.clone())), cx)
                    })),
            );
        }
        view
    }
    fn transaction_changes(&self, source: &serde_json::Value, state: &WalletView) -> Div {
        let mut view = div().flex().flex_col().gap_2();
        if let Some(changes) = source["wallet_changes"].as_array() {
            for change in changes {
                let hash = change["asset"].as_str().unwrap_or("");
                let raw = change["amount"].as_str().unwrap_or("");
                let positive = change["direction"] == "credit";
                let amount = if hash == "CKB" {
                    p::amount(raw, true, self.language)
                } else if let Some(asset) = state
                    .settings
                    .as_ref()
                    .and_then(|s| s.assets.iter().find(|a| a.hash() == hash))
                {
                    format!(
                        "{} {} · {}",
                        display_amount(raw, asset.decimals).unwrap_or_else(|_| raw.into()),
                        asset.symbol,
                        p::short(hash)
                    )
                } else {
                    format!(
                        "{raw} · {} · {}",
                        self.t(Text::WalletTokenRaw),
                        p::short(hash)
                    )
                };
                view = view.child(
                    div()
                        .font_weight(FontWeight::MEDIUM)
                        .text_color(rgb(if positive {
                            d::Tone::Good.color()
                        } else {
                            d::TEXT
                        }))
                        .child(format!("{} {amount}", if positive { "+" } else { "−" })),
                );
            }
            if changes.is_empty() {
                view = view.child(d::caption(self.t(Text::WalletNoNetChange)));
            }
        }
        if source["wallet_unsupported_assets"]
            .as_array()
            .is_some_and(|v| !v.is_empty())
        {
            view = view.child(d::caption(self.t(Text::WalletUnknownAssetEffects)));
        }
        view
    }
    fn open_screen(&mut self, screen: Screen, cx: &mut Context<Self>) {
        self.screen = screen;
        self.copied = false;
        self.status = None;
        if screen == Screen::History
            && self.history.is_none()
            && self.worker.is_some()
            && !self.busy
            && self.state.as_ref().is_some_and(|s| s.settings.is_some())
        {
            self.send(Command::History(None), cx);
        }
        cx.notify();
    }
}
impl Render for WalletPane {
    fn render(&mut self, w: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let mut view = div()
            .id("wallet-scroll")
            .test_support()
            .min_w_0()
            .flex_1()
            .min_h_0()
            .overflow_y_scroll()
            .flex()
            .flex_col()
            .gap_5();
        if let Some(error) = &self.error {
            let key = if error.contains("password_mismatch") {
                Text::WalletPasswordMismatch
            } else if error.contains("password_length") {
                Text::WalletErrorPasswordLength
            } else if error.contains("wallet.locked") {
                Text::WalletErrorLocked
            } else if error.contains("amount_") || error.contains("zero_amount") {
                Text::WalletErrorAmount
            } else if error.contains("asset_") || error.contains("invalid_asset") {
                Text::WalletErrorAsset
            } else if error.contains("fee_") {
                Text::WalletErrorFee
            } else if error.contains("unlock_failed") {
                Text::WalletErrorUnlock
            } else if error.contains("insufficient") || error.contains("below_occupied") {
                Text::WalletErrorFunds
            } else if error.contains("address_") {
                Text::WalletErrorAddress
            } else if error.contains("network_")
                || error.contains("rpc_")
                || error.contains("indexer_")
            {
                Text::WalletErrorNetwork
            } else if error.contains("review_") || error.contains("input_") {
                Text::WalletErrorReview
            } else if error.contains("already_open") {
                Text::WalletErrorOpen
            } else {
                Text::WalletError
            };
            let mut card = d::panel()
                .flex()
                .flex_col()
                .gap_2()
                .child(
                    d::caption(crate::i18n::message_key(error).map_or(self.t(key), |k| self.t(k)))
                        .text_color(rgb(d::WARNING)),
                )
                .child(
                    Button::new("wallet-error-details")
                        .ghost()
                        .small()
                        .label(self.t(if self.details {
                            Text::HideDiagnostic
                        } else {
                            Text::OriginalDiagnostic
                        }))
                        .on_click(cx.listener(|this, _, _, cx| {
                            this.details = !this.details;
                            cx.notify();
                        })),
                );
            if self.details {
                card = card.child(d::caption(error.clone()));
            }
            view = view.child(card);
        }
        if self.busy {
            view = view.child(d::caption(self.t(Text::WalletBusy)));
        }

        let Some(state) = self.state.clone() else {
            return if self.error.is_some() {
                view
            } else {
                view.child(d::caption(self.t(Text::WalletBusy)))
            };
        };
        if !state.exists {
            return view.child(d::workbench(self.setup(cx), 680.));
        }
        let mut header = div()
            .flex()
            .flex_wrap()
            .gap_3()
            .items_center()
            .child(d::title(self.t(Text::Wallet)).flex_1())
            .child(d::caption(state.name.clone()));
        if let Some(settings) = &state.settings {
            let key = match settings.chain.network {
                Network::Mainnet => Text::NetworkMainnet,
                Network::Testnet => Text::NetworkTestnet,
                Network::Devnet => Text::NetworkDevnet,
            };
            header = header.child(d::status(self.t(key), d::Tone::Neutral));
        }
        if state.unlocked {
            header = header.child(
                Button::new("wallet-lock")
                    .ghost()
                    .icon(IconName::Lock)
                    .label(self.t(Text::WalletLock))
                    .disabled(self.busy)
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.quote = None;
                        this.send(Command::Lock, cx);
                    })),
            );
        } else {
            header = header.child(
                Button::new("wallet-request-unlock")
                    .ghost()
                    .icon(IconName::Lock)
                    .label(self.t(Text::WalletUnlock))
                    .disabled(self.busy)
                    .on_click(cx.listener(|this, _, w, cx| {
                        this.unlock_requested = true;
                        w.focus(&this.password.read(cx).focus_handle(cx), cx);
                        cx.notify();
                    })),
            );
        }
        view = view.child(header);
        let handles = w
            .use_keyed_state(
                (ElementId::Name("wallet-tabs".into()), "focus"),
                cx,
                |_, cx| (0..5).map(|_| cx.focus_handle()).collect::<Vec<_>>(),
            )
            .read(cx)
            .clone();
        let mut buttons = Vec::new();
        for (i, screen, label) in [
            (0_usize, Screen::Home, Text::WalletAssets),
            (1, Screen::Send, Text::WalletSend),
            (2, Screen::Receive, Text::WalletReceive),
            (3, Screen::History, Text::WalletHistory),
            (4, Screen::Settings, Text::Settings),
        ] {
            let focus = handles[i].clone();
            let keys = handles.clone();
            let button = Button::new(("wallet-tabs", i))
                .ghost()
                .label(self.t(label))
                .accessibility_label(self.t(if screen == Screen::Settings {
                    Text::WalletNetwork
                } else {
                    label
                }))
                .selected(self.screen == screen)
                .disabled(self.busy)
                .track_focus(&focus)
                .on_click(cx.listener(move |this, _, w, cx| {
                    w.focus(&focus, cx);
                    this.open_screen(screen, cx);
                }))
                .on_key_down(cx.listener(move |this, event: &KeyDownEvent, w, cx| {
                    if this.busy
                        || event.keystroke.modifiers.control
                        || event.keystroke.modifiers.alt
                        || event.keystroke.modifiers.platform
                    {
                        return;
                    }
                    let next = match event.keystroke.key.as_str() {
                        "left" => (i + 4) % 5,
                        "right" => (i + 1) % 5,
                        "home" => 0,
                        "end" => 4,
                        _ => return,
                    };
                    cx.stop_propagation();
                    w.focus(&keys[next], cx);
                    let screen = [
                        Screen::Home,
                        Screen::Send,
                        Screen::Receive,
                        Screen::History,
                        Screen::Settings,
                    ][next];
                    this.open_screen(screen, cx);
                }));
            buttons.push((button, self.screen == screen));
        }
        view = view.child(
            div().flex().child(
                crate::motion::rail("wallet-tab-rail", buttons, false, self.animate, w, cx)
                    .rounded(px(12.))
                    .bg(rgb(d::SIDEBAR)),
            ),
        );
        if !state.unlocked && (self.unlock_requested || self.screen == Screen::Send) {
            view = view.child(d::workbench(self.unlock_bar(cx), 720.));
        }
        if let Some((hash, status)) = &self.status {
            let key = match status["tx_status"]["status"].as_str().unwrap_or("unknown") {
                "committed" => Text::WalletConfirmed,
                "pending" => Text::WalletPending,
                "proposed" => Text::WalletProposed,
                "rejected" => Text::WalletRejected,
                _ => Text::WalletUnknown,
            };
            let mut card = d::panel()
                .flex()
                .flex_col()
                .gap_3()
                .child(d::badge(self.t(key), d::Tone::Info))
                .child(fact(self.t(Text::WalletTransaction), hash.clone()))
                .child(self.transaction_changes(status, &state))
                .child(d::caption(self.t(Text::WalletNetChangeHelp)));
            if let Some(fee) = status["wallet_fee"].as_str() {
                card = card.child(fact(
                    self.t(Text::WalletFee),
                    p::amount(fee, true, self.language),
                ));
            }
            let exact = hash.clone();
            card = card.child(
                Button::new("wallet-copy-transaction")
                    .ghost()
                    .self_start()
                    .icon(IconName::Copy)
                    .label(self.t(Text::Copy))
                    .on_click(cx.listener(move |_, _, _, cx| {
                        cx.write_to_clipboard(ClipboardItem::new_string(exact.clone()))
                    })),
            );
            view = view.child(card);
        }
        if let Some(manifest) = self.asset_manifest.clone() {
            let mut card = d::panel()
                .flex()
                .flex_col()
                .gap_3()
                .child(div().text_xl().child(self.t(Text::WalletAssetReview)))
                .child(d::caption(self.t(Text::WalletAssetReviewHelp)))
                .child(fact(
                    self.t(Text::WalletNetwork),
                    manifest.genesis_hash.clone(),
                ));
            for asset in &manifest.assets {
                card = card.child(fact(
                    &asset.symbol,
                    format!(
                        "{} · {} {}",
                        asset.hash(),
                        self.t(Text::WalletDecimals),
                        asset.decimals
                    ),
                ));
            }
            card = card
                .child(
                    Button::new("wallet-admit-assets")
                        .primary()
                        .label(self.t(Text::WalletAdmitAssets))
                        .disabled(self.busy)
                        .on_click(cx.listener(move |this, _, _, cx| {
                            this.asset_manifest = None;
                            this.send(Command::AdmitAssets(manifest.clone()), cx);
                        })),
                )
                .child(
                    Button::new("wallet-cancel-assets")
                        .ghost()
                        .label(self.t(Text::KeepEditing))
                        .disabled(self.busy)
                        .on_click(cx.listener(|this, _, _, cx| {
                            this.asset_manifest = None;
                            cx.notify();
                        })),
                );
            view = view.child(card);
        }
        let content = match self.screen {
            Screen::Home => self.home(
                &state,
                w.viewport_size().width > px(1200.) && w.rem_size() <= px(19.2),
                cx,
            ),
            Screen::Send => self.send_form(&state, cx),
            Screen::Receive => self.receive(&state, cx),
            Screen::History => self.transactions(&state, cx),
            Screen::Settings => self.settings(cx),
        };
        let width = match self.screen {
            Screen::Home => 960.,
            Screen::History => 1100.,
            _ => 720.,
        };
        view.child(d::workbench(content, width))
    }
}
fn fact(label: &str, value: String) -> Div {
    div()
        .flex()
        .flex_col()
        .gap_2()
        .child(d::caption(label.to_owned()))
        .child(
            div()
                .id(SharedString::from(format!("wallet-fact-{label}")))
                .min_w_0()
                .max_w_full()
                .overflow_x_scroll()
                .child(value),
        )
}
fn qr(value: &str, pixels: f32) -> AnyElement {
    let Ok(code) = qrcode::QrCode::new(value.as_bytes()) else {
        return div().into_any_element();
    };
    let width = code.width();
    let colors = code.to_colors();
    canvas(
        |bounds, _, _| bounds,
        move |bounds, _, w, _| {
            w.paint_quad(fill(bounds, rgb(0xffffff)));
            let step = f32::from(bounds.size.width) / (width + 8) as f32;
            for y in 0..width {
                for x in 0..width {
                    if colors[y * width + x] == qrcode::Color::Dark {
                        w.paint_quad(fill(
                            Bounds::new(
                                bounds.origin
                                    + point(px((x + 4) as f32 * step), px((y + 4) as f32 * step)),
                                size(px(step), px(step)),
                            ),
                            rgb(0x050505),
                        ));
                    }
                }
            }
        },
    )
    .size(px(pixels))
    .into_any_element()
}

#[cfg(test)]
mod tests;
