mod assets;
mod design;
mod forms;
mod i18n;
#[cfg(test)]
mod interaction_tests;
mod localization;
mod model;
mod motion;
mod preferences;
mod presentation;
mod validation;
mod views;
mod wallet;
mod worker;
mod workspace;

use gpui_kit::component::{
    Theme, ThemeMode,
    input::{InputEvent, InputState, TextareaState},
};
use gpui_kit::{
    App, AppContext, Bounds, ClipboardItem, Context, Entity, FocusHandle, Focusable, IntoElement,
    ParentElement, PathPromptOptions, Render, Subscription, Task, Window, WindowBounds,
    WindowOptions, px, size,
};
use i18n::{Language, Text};
use model::Page;
use morph_sdk::{
    api::HubView,
    hub::{HubOperation, HubReply},
};
use presentation::operation_title;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};
use worker::{Completion, Job, Reply, Work, Worker};
use workspace::*;

struct Notice {
    created: Instant,
    tone: design::Tone,
    title: String,
    detail: String,
}
struct Desktop {
    wallet: Option<Entity<wallet::WalletPane>>,
    language: Language,
    scale_percent: u16,
    appearance_settings: bool,
    reduced_motion: bool,
    motion_generation: usize,
    page_enter_started: Instant,
    task_signal: Entity<motion::TaskSignal>,
    aurora: Entity<motion::Aurora>,
    preferences: Option<preferences::Store>,
    locale_revision: u64,
    preference_dirty: bool,
    preference_failed: bool,
    endpoint: Entity<InputState>,
    token: Entity<InputState>,
    search: Entity<InputState>,
    focus: FocusHandle,
    inspector: [Entity<TextareaState>; 3],
    inspector_files: [Option<FileInfo>; 3],
    output: Entity<TextareaState>,
    page: Page,
    active: Option<DraftKey>,
    task_domain: Option<usize>,
    task_search: Entity<InputState>,
    copied: Option<(u64, Instant)>,
    drafts: BTreeMap<DraftKey, Draft>,
    selected: Option<Record>,
    selection_missing: bool,
    rows: Arc<Vec<Record>>,
    state: Option<HubView>,
    result: Option<Value>,
    result_review: Option<Value>,
    result_target: ResultTarget,
    inspector_revision: u64,
    inspector_advanced: bool,
    inspector_error: Option<String>,
    activity_search: Entity<InputState>,
    activity_filter: ActivityFilter,
    result_title: String,
    result_source: String,
    result_private: bool,
    result_checked: bool,
    technical: bool,
    raw_details: bool,
    worker: Option<Worker>,
    files_worker: Option<Worker>,
    network_jobs: BTreeMap<u64, Pending>,
    file_jobs: BTreeMap<u64, Pending>,
    next_job: u64,
    generation: u64,
    file_generation: u64,
    connected: bool,
    connected_endpoint: String,
    connection_error: Option<String>,
    last_checked: Option<Instant>,
    last_attempt: Instant,
    last_paint: Instant,
    retry_after: Option<Instant>,
    activities: Vec<Activity>,
    next_activity: u64,
    selected_activity: Option<u64>,
    hub_activity: bool,
    notice: Option<Notice>,
    prepared: Option<Prepared>,
    unknown_context: Option<(String, String)>,
    reconcile_ready: bool,
    dialog_pending: bool,
    _subscriptions: Vec<Subscription>,
    _poll: Option<Task<()>>,
}
impl Desktop {
    fn t(&self, text: Text) -> &'static str {
        self.language.t(text)
    }
    fn input(
        value: &str,
        placeholder: &str,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Entity<InputState> {
        cx.new(|cx| {
            let mut s = InputState::new(window, cx).placeholder(placeholder.to_owned());
            s.set_value(value.to_owned(), window, cx);
            s
        })
    }
    fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        let language = Language::system();
        window.set_rem_size(px(design::BASE_FONT_SIZE));
        gpui_kit::component::set_locale(language.code());
        design::language_font(language, cx);
        let endpoint = Self::input("http://127.0.0.1:4617", "http://127.0.0.1:4617", window, cx);
        let token = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder(language.t(Text::AccessToken))
                .masked(true)
        });
        let search = Self::input("", language.t(Text::SearchRecords), window, cx);
        let search_subscription = cx.subscribe_in(&search, window, |this, _, e, _, cx| {
            if matches!(e, InputEvent::Change) {
                this.rebuild();
                cx.notify()
            }
        });
        let activity_search = Self::input("", language.t(Text::SearchTasks), window, cx);
        let activity_subscription = cx.subscribe_in(&activity_search, window, |_, _, e, _, cx| {
            if matches!(e, InputEvent::Change) {
                cx.notify();
            }
        });
        let task_search = Self::input("", language.t(Text::SearchWorkflows), window, cx);
        let task_search_subscription = cx.subscribe_in(&task_search, window, |_, _, e, _, cx| {
            if matches!(e, InputEvent::Change) {
                cx.notify();
            }
        });
        let worker = Worker::start();
        let files = Worker::start_files();
        let notice = worker
            .as_ref()
            .err()
            .or_else(|| files.as_ref().err())
            .map(|e| Notice {
                created: Instant::now(),
                tone: design::Tone::Danger,
                title: language.t(Text::WorkerUnavailable).into(),
                detail: e.to_string(),
            });
        let mut v = Self {
            wallet: None,
            language,
            scale_percent: 100,
            appearance_settings: false,
            reduced_motion: false,
            motion_generation: 0,
            page_enter_started: Instant::now(),
            task_signal: cx.new(|_| motion::TaskSignal::default()),
            aurora: cx.new(|_| motion::Aurora::default()),
            preferences: if cfg!(test) {
                None
            } else {
                preferences::Store::start().ok()
            },
            locale_revision: 0,
            preference_dirty: false,
            preference_failed: false,
            endpoint,
            token,
            search,
            focus: cx.focus_handle(),
            inspector: std::array::from_fn(|i| {
                cx.new(|cx| {
                    TextareaState::new(window, cx)
                        .soft_wrap(false)
                        .placeholder(match i {
                            0 => language.t(Text::MainDocument),
                            1 => language.t(Text::SignedBaseRecovery),
                            _ => language.t(Text::DetachedReceipt),
                        })
                        .rows(5)
                })
            }),
            inspector_files: std::array::from_fn(|_| None),
            output: cx.new(|cx| TextareaState::new(window, cx).soft_wrap(false).rows(12)),
            page: Page::Overview,
            active: None,
            task_domain: None,
            task_search,
            copied: None,
            drafts: BTreeMap::new(),
            selected: None,
            selection_missing: false,
            rows: Arc::new(Vec::new()),
            state: None,
            result: None,
            result_review: None,
            result_target: ResultTarget::None,
            inspector_revision: 0,
            inspector_advanced: false,
            inspector_error: None,
            activity_search,
            activity_filter: ActivityFilter::All,
            result_title: String::new(),
            result_source: String::new(),
            result_private: false,
            result_checked: false,
            technical: false,
            raw_details: false,
            worker: worker.ok(),
            files_worker: files.ok(),
            network_jobs: BTreeMap::new(),
            file_jobs: BTreeMap::new(),
            next_job: 0,
            generation: 0,
            file_generation: 0,
            connected: false,
            connected_endpoint: String::new(),
            connection_error: None,
            last_checked: None,
            last_attempt: Instant::now(),
            last_paint: Instant::now(),
            retry_after: None,
            activities: Vec::new(),
            next_activity: 0,
            selected_activity: None,
            hub_activity: false,
            notice,
            prepared: None,
            unknown_context: None,
            reconcile_ready: false,
            dialog_pending: false,
            _subscriptions: vec![
                search_subscription,
                activity_subscription,
                task_search_subscription,
            ],
            _poll: None,
        };
        for (slot, input) in v.inspector.clone().into_iter().enumerate() {
            let subscription = cx.subscribe_in(&input, window, move |this, _, event, _, cx| {
                if matches!(event, InputEvent::Change) {
                    this.inspector_revision = this.inspector_revision.saturating_add(1);
                    this.inspector_error = None;
                    if this.inspector_files[slot].as_ref().is_some_and(|f| {
                        f.view_hash
                            != presentation::view_hash(&this.inspector[slot].read(cx).value())
                    }) {
                        this.inspector_files[slot] = None;
                    }
                    cx.notify();
                }
            });
            v._subscriptions.push(subscription);
        }
        v._poll = Some(cx.spawn_in(window, async move |this, cx| {
            loop {
                cx.background_executor()
                    .timer(Duration::from_millis(150))
                    .await;
                if this
                    .update_in(cx, |this, window, cx| this.poll(window, cx))
                    .is_err()
                {
                    break;
                }
            }
        }));
        v
    }
    fn inform(
        &mut self,
        tone: design::Tone,
        title: impl Into<String>,
        detail: impl Into<String>,
        cx: &mut Context<Self>,
    ) {
        self.notice = Some(Notice {
            created: Instant::now(),
            tone,
            title: title.into(),
            detail: detail.into(),
        });
        cx.notify()
    }
    fn state_revision(&self) -> u64 {
        self.state.as_ref().map_or(0, |s| s.revision)
    }
    fn event_id(&self) -> u64 {
        self.state
            .as_ref()
            .and_then(|s| s.events.last())
            .map_or(0, |e| e.id)
    }
    fn foreground_busy(&self) -> bool {
        self.network_jobs.values().any(|p| !p.background)
    }
    fn file_busy(&self) -> bool {
        !self.file_jobs.is_empty()
    }
    fn pending(&self, kind: JobKind, background: bool) -> Pending {
        Pending {
            kind,
            activity: None,
            background,
            draft: if matches!(kind, JobKind::Execute(_)) && self.page == Page::Actions {
                self.active.clone()
            } else {
                None
            },
            candidate: None,
            previous_roots: self
                .state
                .as_ref()
                .map(|s| {
                    s.root_fundings
                        .iter()
                        .map(|r| r.root.transaction_hash.clone())
                        .collect()
                })
                .unwrap_or_default(),
            target: None,
            inspector_revision: None,
            draft_revision: None,
            follow_up: None,
            connection_generation: self.generation,
            file_name: String::new(),
            endpoint: self.connected_endpoint.clone(),
            origin_node: self
                .state
                .as_ref()
                .map(|s| s.pubkey.clone())
                .unwrap_or_default(),
        }
    }
    fn record_activity(&mut self, title: String, resource: String, origin: String) -> u64 {
        self.next_activity = self.next_activity.saturating_add(1);
        if self.activities.len() >= 200
            && let Some(i) = self
                .activities
                .iter()
                .position(|e| !matches!(e.status, Status::Running | Status::Unknown))
        {
            self.activities.remove(i);
        }
        self.activities.push(Activity {
            id: self.next_activity,
            title,
            resource,
            status: Status::Running,
            detail: String::new(),
            started: Instant::now(),
            elapsed: None,
            output: None,
            review: None,
            output_private: false,
            output_checked: false,
            origin,
        });
        self.next_activity
    }
    fn finish_activity(
        &mut self,
        id: Option<u64>,
        status: Status,
        detail: String,
        output: Option<Value>,
    ) {
        if let Some(id) = id
            && let Some(entry) = self.activities.iter_mut().find(|e| e.id == id)
        {
            entry.status = status;
            entry.elapsed = Some(entry.started.elapsed());
            entry.detail = detail;
            entry.output = output;
        }
        let mut kept = 0;
        for entry in self.activities.iter_mut().rev() {
            if entry.output.is_some() {
                kept += 1;
                if kept > 8 {
                    entry.output = None
                }
            }
        }
    }
    fn enqueue(
        &mut self,
        work: Work,
        mut pending: Pending,
        local: bool,
        cx: &mut Context<Self>,
    ) -> bool {
        let Some(id) = self.next_job.checked_add(1) else {
            return false;
        };
        self.next_job = id;
        let generation = if local {
            self.file_generation
        } else {
            self.generation
        };
        if let Work::Execute {
            operation,
            id,
            body,
            ..
        } = &work
        {
            let target = match operation {
                HubOperation::Peer => Some((
                    Page::Peers,
                    body["pubkey"].as_str().unwrap_or("").to_ascii_lowercase(),
                )),
                HubOperation::OpenChannel => Some((
                    Page::Channels,
                    body["channel_id"].as_str().unwrap_or("").into(),
                )),
                HubOperation::OpenFactory => Some((
                    Page::Factories,
                    body["factory_id"].as_str().unwrap_or("").into(),
                )),
                HubOperation::MaterialiseChild => Some((
                    Page::Channels,
                    body["child_channel_id"].as_str().unwrap_or("").into(),
                )),
                HubOperation::SpliceChannel
                | HubOperation::PublishChannel
                | HubOperation::FinaliseChannel => Some((Page::Channels, id.clone())),
                HubOperation::AdvanceFactory => Some((Page::Factories, id.clone())),
                HubOperation::ReceiveInvoice | HubOperation::SettleInvoice => {
                    Some((Page::Invoices, id.clone()))
                }
                HubOperation::CreateInvoice | HubOperation::DecodeInvoice => {
                    Some((Page::Invoices, String::new()))
                }
                HubOperation::ImportRecovery | HubOperation::ImportBatch => {
                    Some((Page::Recovery, String::new()))
                }
                _ => None,
            };
            pending.follow_up = target;
        }
        let worker = if local {
            self.files_worker.as_ref()
        } else {
            self.worker.as_ref()
        };
        if worker.is_none_or(|w| {
            w.send
                .try_send(Job {
                    id,
                    generation,
                    work,
                })
                .is_err()
        }) {
            self.inform(
                design::Tone::Warning,
                self.t(Text::WorkerBusy),
                self.t(Text::WaitForTheCurrentTaskThen),
                cx,
            );
            return false;
        }
        if !pending.background {
            let title = match pending.kind {
                JobKind::Connect => self.t(Text::ConnectWorkspace).to_owned(),
                JobKind::Disconnect => self.t(Text::DisconnectWorkspace).into(),
                JobKind::Refresh => self.t(Text::RefreshWorkspace).into(),
                JobKind::Execute(op) => operation_title(op, self.language).into(),
                JobKind::Inspect => self.t(Text::ReviewEvidenceOffline).into(),
                JobKind::Open => self.t(Text::OpenEvidenceFile).into(),
                JobKind::Save => self.t(Text::SavePrivateOriginal).into(),
            };
            let resource = pending
                .draft
                .as_ref()
                .map(|k| k.resource.clone())
                .unwrap_or_else(|| pending.file_name.clone());
            pending.activity =
                Some(self.record_activity(title, resource, pending.endpoint.clone()));
        }
        if local {
            self.file_jobs.insert(id, pending);
        } else {
            self.last_attempt = Instant::now();
            self.network_jobs.insert(id, pending);
        }
        cx.notify();
        true
    }
    fn connect(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.foreground_busy() {
            return;
        }
        self.stop_network(cx);
        self.generation = self.generation.saturating_add(1);
        self.connected = false;
        self.state = None;
        self.last_checked = None;
        self.prepared = None;
        self.reconcile_ready = false;
        self.connection_error = None;
        for draft in self.drafts.values_mut() {
            draft.restore = None;
            draft.review_stale = true;
        }
        let endpoint = self.endpoint.read(cx).value().trim().to_owned();
        let token = self.token.read(cx).value().to_string();
        let mut p = self.pending(JobKind::Connect, false);
        p.endpoint = endpoint.clone();
        if self.enqueue(Work::Connect { endpoint, token }, p, false, cx) {
            self.token.update(cx, |v, cx| v.set_value("", window, cx));
        }
    }
    fn refresh(&mut self, manual: bool, cx: &mut Context<Self>) {
        if manual && self.page == Page::Wallet {
            if let Some(wallet) = self.wallet.clone() {
                wallet.update(cx, |v, cx| v.refresh_from_shortcut(cx));
            }
            return;
        }
        if !self.connected || self.foreground_busy() || (!manual && !self.network_jobs.is_empty()) {
            return;
        }
        let p = self.pending(JobKind::Refresh, !manual);
        self.enqueue(Work::Refresh, p, false, cx);
    }
    fn stop_network(&mut self, cx: &mut Context<Self>) {
        if self.network_jobs.is_empty() {
            return;
        }
        self.generation = self.generation.saturating_add(1);
        self.prepared = None;
        self.last_checked = None;
        let jobs = std::mem::take(&mut self.network_jobs);
        for (_, p) in jobs {
            let unknown = matches!(p.kind,JobKind::Execute(op) if op.mutates());
            let detail = if unknown {
                self.unknown_context = Some((p.endpoint.clone(), p.origin_node.clone()));
                self.reconcile_ready = false;
                self.t(Text::StoppedWaitingTheServerMayHave)
            } else {
                self.t(Text::StoppedWaitingThisDoesNotRoll)
            };
            self.finish_activity(
                p.activity,
                if unknown {
                    Status::Unknown
                } else {
                    Status::Stopped
                },
                detail.into(),
                None,
            );
        }
        cx.notify()
    }
    fn disconnect(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.token.update(cx, |v, cx| v.set_value("", window, cx));
        self.connection_error = None;
        for draft in self.drafts.values_mut() {
            draft.restore = None;
            draft.review_stale = true;
        }
        self.stop_network(cx);
        self.generation = self.generation.saturating_add(1);
        self.connected = false;
        self.last_checked = None;
        self.state = None;
        self.selected = None;
        self.rows = Arc::new(Vec::new());
        self.prepared = None;
        let p = self.pending(JobKind::Disconnect, true);
        self.enqueue(Work::Disconnect, p, false, cx);
    }
    fn document_changed(&mut self, key: &DraftKey, slot: usize, cx: &mut Context<Self>) {
        if let Some(d) = self.drafts.get_mut(key) {
            d.document_revision = d.document_revision.saturating_add(1);
        }
        if let Some(d) = self.drafts.get_mut(key)
            && d.files[slot].as_ref().is_some_and(|f| {
                f.view_hash != presentation::view_hash(&d.documents[slot].read(cx).value())
            })
        {
            d.files[slot] = None;
        }
        self.invalidate_draft(key, cx)
    }
    fn invalidate_draft(&mut self, key: &DraftKey, cx: &mut Context<Self>) {
        if self.result_target == ResultTarget::Draft(key.clone()) {
            self.result_target = ResultTarget::None;
        }
        let had_review = self.prepared.as_ref().is_some_and(|p| &p.key == key);
        if had_review {
            self.prepared = None
        }
        if let Some(d) = self.drafts.get_mut(key) {
            d.error = None;
            d.discard_pending = false;
            d.checked_review = None;
            if d.restore.as_ref().is_some_and(|p| {
                serde_json::from_str::<Value>(&d.documents[0].read(cx).value())
                    .ok()
                    .as_ref()
                    != Some(&p.candidate)
            }) {
                d.restore = None
            }
            d.review_stale |= had_review;
        }
        cx.notify()
    }
    fn invalidate_reviews(&mut self, cx: &mut Context<Self>) {
        if let Some(p) = self.prepared.take()
            && let Some(d) = self.drafts.get_mut(&p.key)
        {
            d.review_stale = true;
        }
        let event_id = self.event_id();
        for d in self.drafts.values_mut() {
            if d.restore.as_ref().is_some_and(|p| p.event_id != event_id) {
                d.restore = None;
            }
        }
        cx.notify()
    }
    fn rebuild(&mut self) {
        let Some(s) = self.state.as_ref() else {
            self.rows = Arc::new(Vec::new());
            return;
        };
        let pages: Vec<Page> = if self.page == Page::Search {
            vec![
                Page::Channels,
                Page::Factories,
                Page::Invoices,
                Page::Recovery,
                Page::Peers,
                Page::Watch,
                Page::Events,
            ]
        } else {
            vec![self.page]
        };
        self.rows = Arc::new(
            pages
                .into_iter()
                .flat_map(|page| {
                    model::rows(s, page)
                        .into_iter()
                        .map(move |row| Record { page, row })
                })
                .collect(),
        );
    }
    fn filtered_records(&self, cx: &Context<Self>) -> Arc<Vec<Record>> {
        let tokens = self
            .search
            .read(cx)
            .value()
            .split_whitespace()
            .map(str::to_lowercase)
            .collect::<Vec<_>>();
        if tokens.is_empty() {
            return Arc::clone(&self.rows);
        }
        Arc::new(
            self.rows
                .iter()
                .filter(|r| {
                    let visible = format!(
                        "{} {}",
                        views::record_title(r, self.language),
                        views::record_subtitle(r, self.language)
                    )
                    .to_lowercase();
                    tokens.iter().all(|t| {
                        visible.contains(t) || model::matches(&r.row, std::slice::from_ref(t))
                    })
                })
                .cloned()
                .collect(),
        )
    }
    fn navigate(&mut self, page: Page, window: &mut Window, cx: &mut Context<Self>) {
        if self.page != page || self.selected.is_some() || self.technical {
            self.motion_generation = self.motion_generation.wrapping_add(1);
            self.page_enter_started = Instant::now();
        }
        self.page = page;
        self.selected = None;
        self.selection_missing = false;
        self.selected_activity = None;
        self.technical = false;
        self.raw_details = false;
        self.prepared = None;
        self.search.update(cx, |v, cx| v.set_value("", window, cx));
        self.rebuild();
        cx.notify()
    }
    fn pick_record(&mut self, record: Record, window: &mut Window, cx: &mut Context<Self>) {
        self.motion_generation = self.motion_generation.wrapping_add(1);
        self.page_enter_started = Instant::now();
        self.selected = Some(record.clone());
        self.selected_activity = None;
        self.selection_missing = false;
        self.technical = false;
        self.raw_details = false;
        self.show_result(
            record.row.document.clone(),
            record.row.title.clone(),
            record.source(self.language).into(),
            record.is_batch(),
            window,
            cx,
        );
        self.result_target = ResultTarget::Record(record.page, record.id());
    }
    fn request_draft_secret(
        &mut self,
        key: &DraftKey,
        hash: Option<String>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let Some(draft) = self.drafts.get(key) else {
            return;
        };
        if draft
            .fields
            .iter()
            .find(|(k, _)| *k == "payment_preimage")
            .is_none_or(|(_, v)| !v.read(cx).value().is_empty())
        {
            return;
        }
        if draft
            .fields
            .iter()
            .any(|(k, v)| *k == "payment_hash" && !v.read(cx).value().is_empty())
        {
            return;
        }
        let wallet = self
            .wallet
            .get_or_insert_with(|| {
                cx.new(|cx| crate::wallet::WalletPane::new(self.language, window, cx))
            })
            .clone();
        let requested = wallet.update(cx, |v, cx| v.request_payment_secret(key.clone(), hash, cx));
        if !requested {
            let message = self.t(Text::InvoiceWalletRequired).to_owned();
            if let Some(d) = self.drafts.get_mut(key) {
                d.error = Some(message);
            }
        }
    }
    fn start_task(
        &mut self,
        op: HubOperation,
        resource: String,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let Some(form) = forms::FORMS.iter().position(|f| f.operation == op) else {
            return;
        };
        let key = DraftKey { form, resource };
        if !self.drafts.contains_key(&key) {
            if self.drafts.len() >= 32 {
                self.inform(
                    design::Tone::Warning,
                    self.t(Text::DraftLimitReached),
                    self.t(Text::OpenASavedDraftFromThe),
                    cx,
                );
                return;
            }
            let d = Draft::new(&key, self.language, window, cx);
            self.drafts.insert(key.clone(), d);
        }
        self.motion_generation = self.motion_generation.wrapping_add(1);
        self.page_enter_started = Instant::now();
        self.active = Some(key.clone());
        let draft = &self.drafts[&key];
        let focus = if forms::FORMS[form].needs_id && key.resource.is_empty() {
            if draft.advanced_id {
                &draft.id
            } else {
                &draft.target_search
            }
        } else if let Some((_, input)) = draft.fields.first() {
            input
        } else {
            &draft.id
        };
        if !forms::FORMS[form].document || forms::FORMS[form].needs_id {
            window.focus(&focus.read(cx).focus_handle(cx), cx);
        }
        if op == HubOperation::CreateInvoice {
            self.request_draft_secret(&key, None, window, cx);
        }
        self.page = Page::Actions;
        self.prepared = None;
        self.selected_activity = None;
        self.technical = false;
        self.raw_details = false;
        self.result = None;
        cx.notify()
    }
    fn start_for_record(
        &mut self,
        op: HubOperation,
        record: Record,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let Some(form) = forms::FORMS.iter().position(|f| f.operation == op) else {
            return;
        };
        let expected = DraftKey {
            form,
            resource: record.id(),
        };
        let existing = self.drafts.contains_key(&expected);
        self.start_task(op, expected.resource.clone(), window, cx);
        let Some(key) = self.active.clone().filter(|k| k == &expected) else {
            return;
        };
        if existing {
            return;
        }
        if op == HubOperation::SettleInvoice
            && let Some(hash) = record.row.document["invoice"]["payment_hash"]
                .as_str()
                .or(record.row.document["payment_hash"].as_str())
        {
            self.request_draft_secret(&key, Some(hash.to_owned()), window, cx);
        }
        let Some(d) = self.drafts.get(&key) else {
            return;
        };
        if op == HubOperation::CreateInvoice && record.page == Page::Channels {
            if let Some((_, field)) = d.fields.iter().find(|(k, _)| *k == "channel_id") {
                let id = record.id();
                field.update(cx, |v, cx| v.set_value(id, window, cx));
            }
            if let Some(asset) = record.row.document["balances"]
                .as_array()
                .filter(|v| v.len() == 1)
                .and_then(|v| v.first())
                .and_then(|v| v.get("asset"))
                && let Some(hash) = asset["type_hash"].as_str()
            {
                d.asset
                    .update(cx, |v, cx| v.set_value(hash.to_owned(), window, cx));
            }
        }
    }
    fn discard_active(&mut self, cx: &mut Context<Self>) {
        if let Some(k) = self.active.take() {
            self.drafts.remove(&k);
        }
        self.prepared = None;
        cx.notify()
    }
    fn block_reason(&self, op: HubOperation) -> Option<String> {
        if !self.connected {
            return Some(self.t(Text::ConnectToAWorkspaceFirst).into());
        }
        if self.foreground_busy() {
            return Some(self.t(Text::AnotherNetworkTaskIsStillRunning).into());
        }
        if op.mutates()
            && let Some(until) = self.retry_after
            && until > Instant::now()
        {
            return Some(format!(
                "{} {} {}",
                self.t(Text::TheServiceAskedYouToWait),
                until.duration_since(Instant::now()).as_secs() + 1,
                self.t(Text::Seconds)
            ));
        }
        if self.unknown_context.is_some() && op.mutates() {
            return Some(self.t(Text::AWriteOutcomeNeedsReviewRefresh).into());
        }
        if self
            .last_checked
            .is_none_or(|time| time.elapsed() >= Duration::from_secs(15))
        {
            return Some(self.t(Text::RefreshTheWorkspaceBeforeContinuing).into());
        }
        if let Some(state) = &self.state
            && state.security.auth_required
            && !state.security.auth_scopes.contains(&op.required_scope())
        {
            return Some(format!(
                "{}: {}",
                self.t(Text::MissingPermission),
                presentation::scope_name(op.required_scope(), self.language)
            ));
        }
        if !model::can_operate(self.state.as_ref(), self.last_checked, op.required_scope()) {
            return Some(self.t(Text::TheWorkspaceIsNotReadyFor).into());
        }
        if let Some(s) = &self.state {
            if op == HubOperation::CreateInvoice && !s.security.invoice_signing_enabled {
                return Some(self.t(Text::InvoiceSigningIsDisabledOnThis).into());
            }
            if matches!(op, HubOperation::PreviewRestore | HubOperation::Restore)
                && !s.security.state_restore_enabled
            {
                return Some(self.t(Text::TheServerHasDisabledWorkspaceRestore).into());
            }
        }
        None
    }
    fn draft_payload(&self, key: &DraftKey, cx: &Context<Self>) -> anyhow::Result<(String, Value)> {
        let d = self
            .drafts
            .get(key)
            .ok_or_else(|| anyhow::anyhow!("{}", self.t(Text::DraftUnavailable)))?;
        let form = &forms::FORMS[key.form];
        let id = d.id.read(cx).value().trim().to_owned();
        if form.needs_id {
            anyhow::ensure!(
                canonical_id(&id),
                "{}",
                self.t(Text::ObjectIDRequiresCanonical0x64)
            );
        }
        let body = if form.operation == HubOperation::Restore {
            let plan = d
                .restore
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("{}", self.t(Text::PreviewCandidateAgain)))?;
            let current: Value = serde_json::from_str(&d.documents[0].read(cx).value())?;
            anyhow::ensure!(
                plan.preview.allowed
                    && plan.candidate == current
                    && plan.event_id == self.event_id()
                    && plan.generation == self.generation
                    && plan.endpoint == self.connected_endpoint,
                "{}",
                self.t(Text::RestorePreviewExpired)
            );
            json!({"state":plan.candidate,"confirmation_hash":plan.preview.confirmation_hash})
        } else if form.document {
            let raw = d.documents[0].read(cx).value();
            anyhow::ensure!(
                raw.len() <= 4 * 1024 * 1024,
                "{}",
                self.t(Text::DocumentSizeLimit)
            );
            serde_json::from_str(&raw)?
        } else {
            let mut values = BTreeMap::new();
            let ckb = d.asset.read(cx).value().trim().is_empty();
            for (name, input) in &d.fields {
                let raw = input.read(cx).value().trim().to_owned();
                let val = if workspace::amount_field(name) && !raw.is_empty() {
                    if ckb && d.ckb_units {
                        presentation::decimal_to_shannons(&raw)?
                    } else {
                        let n = raw.parse::<u128>()?;
                        anyhow::ensure!(
                            n.to_string() == raw,
                            "{}",
                            self.t(Text::CanonicalAmountRequired)
                        );
                        raw
                    }
                } else {
                    raw
                };
                values.insert(name.to_string(), val);
            }
            forms::payload(form, &values, &d.asset.read(cx).value())?
        };
        if matches!(
            form.operation,
            HubOperation::RootExitSignature | HubOperation::RootCreationSignature
        ) && let Some(root) = self.state.as_ref().and_then(|s| {
            s.root_fundings
                .iter()
                .find(|r| r.root.transaction_hash == id)
        }) {
            let expected = if form.operation == HubOperation::RootExitSignature {
                &root.root.exit_digest
            } else {
                &root.root.creation_digest
            };
            anyhow::ensure!(
                body["signing_digest"].as_str() == Some(expected.as_str()),
                "{}",
                self.t(Text::ReceiptDigestDoesNotMatchThis)
            );
            anyhow::ensure!(
                body["pubkey"].as_str().is_some_and(|key| root
                    .root
                    .participants
                    .iter()
                    .any(|p| p == key)),
                "{}",
                self.t(Text::ReceiptSignerIsNotAParticipant)
            );
        }
        Ok((id, body))
    }
    fn prepare(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(key) = self.active.clone() else {
            return;
        };
        let op = forms::FORMS[key.form].operation;
        if let Some(reason) = self.block_reason(op) {
            if let Some(d) = self.drafts.get_mut(&key) {
                d.error = Some(reason)
            }
            cx.notify();
            return;
        }
        if let Some(d) = self.drafts.get_mut(&key) {
            d.validation_attempted = true;
        }
        if op == HubOperation::CreateInvoice
            && self.drafts.get(&key).is_some_and(|d| {
                d.fields
                    .iter()
                    .filter(|(k, _)| matches!(*k, "payment_preimage" | "payment_hash"))
                    .all(|(_, v)| v.read(cx).value().is_empty())
            })
        {
            self.request_draft_secret(&key, None, window, cx);
            cx.notify();
            return;
        }
        let issues = self.draft_issues(&key, cx);
        if !issues.is_empty() {
            let first = if issues.contains_key("resource") {
                Some("resource")
            } else if issues.contains_key("asset") {
                Some("asset")
            } else {
                forms::FORMS[key.form]
                    .fields
                    .iter()
                    .find(|f| issues.contains_key(f.key))
                    .map(|f| f.key)
            };
            let message = self
                .t(Text::CheckTheHighlightedFieldsBeforeReviewing)
                .to_owned();
            if let Some(d) = self.drafts.get_mut(&key) {
                d.error = Some(message);
                if first.is_some_and(|name| {
                    matches!(name, "payment_hash" | "expiry_secs" | "channel_id")
                }) {
                    d.advanced_fields = true;
                }
                let input = match first {
                    Some("asset") => Some(d.asset.clone()),
                    Some("resource") => Some(d.id.clone()),
                    Some(name) => d
                        .fields
                        .iter()
                        .find(|(k, _)| *k == name)
                        .map(|(_, e)| e.clone()),
                    None if issues.contains_key("asset") => Some(d.asset.clone()),
                    None if issues.contains_key("resource") => Some(d.id.clone()),
                    _ => None,
                };
                if let Some(input) = input {
                    window.focus(&input.read(cx).focus_handle(cx), cx);
                }
                if let Some(anchor) = first.and_then(|key| d.anchors.get(key)) {
                    anchor.scroll_to(window, cx);
                }
            }
            cx.notify();
            return;
        }
        match self.draft_payload(&key, cx) {
            Ok((id, body)) => {
                if matches!(
                    op,
                    HubOperation::ImportRecovery
                        | HubOperation::ImportRoot
                        | HubOperation::ImportBatch
                ) {
                    let mut pending = self.pending(JobKind::Inspect, false);
                    pending.draft = Some(key.clone());
                    pending.candidate = Some(body.clone());
                    self.enqueue(
                        Work::Inspect {
                            document: body,
                            base: None,
                            receipt: None,
                        },
                        pending,
                        true,
                        cx,
                    );
                    return;
                }
                if !op.mutates() {
                    let mut p = self.pending(JobKind::Execute(op), false);
                    if op == HubOperation::PreviewRestore {
                        p.candidate = Some(body.clone())
                    }
                    self.enqueue(
                        Work::Execute {
                            expected_revision: None,
                            operation: op,
                            id,
                            body,
                        },
                        p,
                        false,
                        cx,
                    );
                    return;
                }
                self.prepared = Some(Prepared {
                    revision: self.state_revision(),
                    operation: op,
                    id,
                    body,
                    event_id: self.event_id(),
                    generation: self.generation,
                    key: key.clone(),
                    endpoint: self.connected_endpoint.clone(),
                });
                if let Some(d) = self.drafts.get_mut(&key) {
                    d.review_stale = false;
                    d.error = None
                }
                self.technical = false;
                cx.notify();
            }
            Err(e) => {
                if let Some(d) = self.drafts.get_mut(&key) {
                    d.error = Some(e.to_string())
                }
                cx.notify()
            }
        }
        let _ = window;
    }
    fn confirm(&mut self, cx: &mut Context<Self>) {
        let Some(p) = self.prepared.take() else {
            return;
        };
        if self.active.as_ref() != Some(&p.key)
            || self.block_reason(p.operation).is_some()
            || p.revision != self.state_revision()
            || p.event_id != self.event_id()
            || p.generation != self.generation
            || p.endpoint != self.connected_endpoint
            || self.draft_payload(&p.key, cx).ok() != Some((p.id.clone(), p.body.clone()))
        {
            let error = self
                .t(Text::TheDraftPermissionOrWorkspaceChanged)
                .to_owned();
            if let Some(d) = self.drafts.get_mut(&p.key) {
                d.review_stale = true;
                d.error = Some(error)
            }
            cx.notify();
            return;
        }
        let pending = self.pending(JobKind::Execute(p.operation), false);
        self.enqueue(
            Work::Execute {
                expected_revision: Some(p.revision),
                operation: p.operation,
                id: p.id,
                body: p.body,
            },
            pending,
            false,
            cx,
        );
    }
    fn show_result(
        &mut self,
        value: Value,
        title: String,
        source: String,
        private: bool,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.result = Some(value);
        self.result_review = None;
        self.result_target = ResultTarget::None;
        self.result_title = title;
        self.result_source = source;
        self.result_private = private;
        self.result_checked = false;
        self.raw_details = false;
        self.update_output(window, cx);
        let _ = window;
        cx.notify()
    }
    fn update_output(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let mut doc = self.result.clone().unwrap_or(Value::Null);
        if !self.raw_details {
            redact(&mut doc, self.language)
        }
        let text = serde_json::to_string_pretty(&doc).unwrap_or_default();
        self.output
            .update(cx, |v, cx| v.set_value(text, window, cx));
    }
    fn inspect(&mut self, cx: &mut Context<Self>) {
        let parsed = (|| -> anyhow::Result<Work> {
            let mut docs = Vec::new();
            for e in &self.inspector {
                let text = e.read(cx).value();
                anyhow::ensure!(
                    text.len() <= 4 * 1024 * 1024,
                    "{}",
                    self.t(Text::DocumentSizeLimit)
                );
                docs.push(if text.trim().is_empty() {
                    None
                } else {
                    Some(serde_json::from_str::<Value>(&text)?)
                });
            }
            Ok(Work::Inspect {
                document: docs[0]
                    .take()
                    .ok_or_else(|| anyhow::anyhow!("{}", self.t(Text::LoadDocumentFirst)))?,
                base: docs[1].take(),
                receipt: docs[2].take(),
            })
        })();
        match parsed {
            Ok(work) => {
                let mut p = self.pending(JobKind::Inspect, false);
                p.inspector_revision = Some(self.inspector_revision);
                self.enqueue(work, p, true, cx);
            }
            Err(e) => {
                self.inspector_error = Some(e.to_string());
                cx.notify();
            }
        }
    }
    fn open_file(&mut self, target: DocumentTarget, cx: &mut Context<Self>) {
        if self.file_busy() || self.dialog_pending {
            return;
        }
        let inspector_revision =
            matches!(&target, DocumentTarget::Inspector(_)).then_some(self.inspector_revision);
        let draft_revision = match &target {
            DocumentTarget::Draft(key, _) => self
                .drafts
                .get(key)
                .map(|d| (d.documents[0].entity_id(), d.document_revision)),
            _ => None,
        };
        self.dialog_pending = true;
        cx.notify();
        let paths = cx.prompt_for_paths(PathPromptOptions {
            files: true,
            directories: false,
            multiple: false,
            prompt: Some(self.t(Text::OpenMorphEvidence).into()),
        });
        cx.spawn(async move |this, cx| {
            let result = paths.await;
            let _ = this.update(cx, |this, cx| {
                this.dialog_pending = false;
                match result {
                    Ok(Ok(Some(paths))) => {
                        if let Some(path) = paths.into_iter().next() {
                            let mut p = this.pending(JobKind::Open, false);
                            p.target = Some(target);
                            p.inspector_revision = inspector_revision;
                            p.draft_revision = draft_revision;
                            p.file_name = path
                                .file_name()
                                .map(|v| v.to_string_lossy().into_owned())
                                .unwrap_or_default();
                            this.enqueue(Work::Open { path }, p, true, cx);
                        }
                    }
                    Ok(Err(e)) => this.inform(
                        design::Tone::Warning,
                        this.t(Text::FileChooserUnavailable),
                        e.to_string(),
                        cx,
                    ),
                    _ => cx.notify(),
                }
            });
        })
        .detach();
    }
    fn save_file(&mut self, cx: &mut Context<Self>) {
        if self.file_busy() || self.dialog_pending {
            return;
        }
        let Some(document) = self.result.clone() else {
            return;
        };
        self.dialog_pending = true;
        cx.notify();
        let path = cx.prompt_for_new_path(Path::new("."), Some("morph-evidence.json"));
        cx.spawn(async move |this, cx| {
            let result = path.await;
            let _ = this.update(cx, |this, cx| {
                this.dialog_pending = false;
                match result {
                    Ok(Ok(Some(path))) => {
                        let mut p = this.pending(JobKind::Save, false);
                        p.file_name = path
                            .file_name()
                            .map(|v| v.to_string_lossy().into_owned())
                            .unwrap_or_default();
                        this.enqueue(Work::Save { path, document }, p, true, cx);
                    }
                    Ok(Err(e)) => this.inform(
                        design::Tone::Warning,
                        this.t(Text::FileChooserUnavailable),
                        e.to_string(),
                        cx,
                    ),
                    _ => cx.notify(),
                }
            });
        })
        .detach();
    }
    fn poll(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.poll_preferences(window, cx);
        let delivery = self
            .wallet
            .clone()
            .and_then(|wallet| wallet.update(cx, |v, _| v.take_secret_delivery()));
        if let Some((key, result)) = delivery
            && let Some(draft) = self.drafts.get_mut(&key)
        {
            match result {
                Ok(secret) => {
                    if let Some((_, field)) =
                        draft.fields.iter().find(|(k, _)| *k == "payment_preimage")
                    {
                        field.update(cx, |v, cx| v.set_value(&*secret, window, cx));
                    }
                    draft.error = None;
                }
                Err(error) => draft.error = Some(error),
            }
            cx.notify();
        }
        if self
            .copied
            .is_some_and(|(_, at)| at.elapsed() >= Duration::from_secs(2))
        {
            self.copied = None;
            cx.notify();
        }
        if self.notice.as_ref().is_some_and(|n| {
            n.tone == design::Tone::Good && n.created.elapsed() > Duration::from_secs(8)
        }) {
            self.notice = None;
            cx.notify();
        }
        // Repaint at the freshness boundary, not every second to animate a timestamp.
        if self.connected
            && self.last_checked.is_some_and(|checked| {
                self.last_paint.saturating_duration_since(checked) < Duration::from_secs(15)
                    && checked.elapsed() >= Duration::from_secs(15)
            })
        {
            self.last_paint = Instant::now();
            cx.notify();
        }
        for local in [false, true] {
            for _ in 0..4 {
                let recv = {
                    let w = if local {
                        self.files_worker.as_ref()
                    } else {
                        self.worker.as_ref()
                    };
                    w.map(|w| w.receive.try_recv())
                };
                match recv {
                    Some(Ok(done)) => self.complete(done, local, window, cx),
                    Some(Err(std::sync::mpsc::TryRecvError::Disconnected)) => {
                        self.worker_lost(local, cx);
                        break;
                    }
                    _ => break,
                }
            }
        }
        if self.connected
            && self.worker.is_some()
            && self.network_jobs.is_empty()
            && self.unknown_context.is_none()
            && !self.dialog_pending
            && self.last_attempt.elapsed() >= Duration::from_secs(5)
        {
            self.refresh(false, cx)
        }
    }
    fn worker_lost(&mut self, local: bool, cx: &mut Context<Self>) {
        if local {
            self.files_worker = None;
            for (_, p) in std::mem::take(&mut self.file_jobs) {
                self.finish_activity(
                    p.activity,
                    Status::Failed,
                    self.t(Text::FileWorkerStopped).into(),
                    None,
                )
            }
        } else {
            self.stop_network(cx);
            self.worker = None;
            self.last_checked = None;
            self.connection_error = Some(self.t(Text::NetworkWorkerStopped).into());
        }
        cx.notify()
    }
    fn complete(
        &mut self,
        done: Completion,
        local: bool,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let review = done.review.clone();
        let p = if local {
            self.file_jobs.remove(&done.id)
        } else {
            self.network_jobs.remove(&done.id)
        };
        let Some(p) = p else { return };
        if done.generation
            != if local {
                self.file_generation
            } else {
                self.generation
            }
        {
            return;
        }
        match done.result {
            Err(e) => {
                let unknown = matches!(p.kind, JobKind::Execute(op) if op.mutates())
                    && e.downcast_ref::<morph_sdk::HubClientError>()
                        .is_some_and(|e| {
                            matches!(e, morph_sdk::HubClientError::OutcomeUnknown { .. })
                        });
                if unknown {
                    self.unknown_context = Some((p.endpoint.clone(), p.origin_node.clone()));
                    self.reconcile_ready = false;
                }
                let transport = e
                    .downcast_ref::<morph_sdk::HubClientError>()
                    .is_some_and(|err| match err {
                        morph_sdk::HubClientError::Transport
                        | morph_sdk::HubClientError::InvalidResponse
                        | morph_sdk::HubClientError::OutcomeUnknown { .. } => true,
                        morph_sdk::HubClientError::Api { status, .. } => {
                            matches!(*status, 401 | 403 | 500..=599)
                        }
                        _ => false,
                    });
                if !local && (transport || p.kind == JobKind::Connect) {
                    self.last_checked = None;
                    self.connection_error = Some(e.to_string());
                }
                if let Some(morph_sdk::HubClientError::Api {
                    retry_after_seconds: Some(seconds),
                    ..
                }) = e.downcast_ref::<morph_sdk::HubClientError>()
                {
                    self.retry_after = Instant::now().checked_add(Duration::from_secs(*seconds));
                }
                if local
                    && p.kind == JobKind::Inspect
                    && p.inspector_revision == Some(self.inspector_revision)
                {
                    self.inspector_error = Some(e.to_string());
                }
                if let Some(k) = &p.draft
                    && let Some(d) = self.drafts.get_mut(k)
                {
                    d.error = Some(e.to_string());
                }
                if !local {
                    self.prepared = None;
                }
                self.finish_activity(
                    p.activity,
                    if unknown {
                        Status::Unknown
                    } else {
                        Status::Failed
                    },
                    e.to_string(),
                    None,
                );
                if !p.background {
                    self.inform(
                        if unknown {
                            design::Tone::Warning
                        } else {
                            design::Tone::Danger
                        },
                        if unknown {
                            self.t(Text::OutcomeNeedsReview)
                        } else {
                            self.t(Text::TaskNotCompleted)
                        },
                        e.to_string(),
                        cx,
                    )
                }
            }
            Ok(reply) => match reply {
                Reply::Hub(reply) => match *reply {
                    HubReply::State(state) => {
                        if p.kind == JobKind::Connect {
                            self.connected_endpoint = p.endpoint.clone()
                        }
                        let changed = self.state_revision() != state.revision;
                        self.state = Some(*state);
                        self.connected = true;
                        self.connection_error = None;
                        self.last_checked = Some(Instant::now());
                        if changed {
                            self.invalidate_reviews(cx)
                        }
                        self.rebuild();
                        self.refresh_selected(window, cx);
                        if p.kind == JobKind::Refresh
                            && !p.background
                            && self.unknown_context.as_ref().is_some_and(|(ep, node)| {
                                ep == &self.connected_endpoint
                                    && self
                                        .state
                                        .as_ref()
                                        .is_some_and(|s| node.is_empty() || node == &s.pubkey)
                            })
                        {
                            self.reconcile_ready = true
                        }
                        let detail = match p.kind {
                            JobKind::Execute(op) => {
                                presentation::operation_help(op, self.language).to_owned()
                            }
                            _ => self
                                .t(Text::WorkspaceRecordsRefreshedChainObservationsAre)
                                .into(),
                        };
                        self.finish_activity(p.activity, Status::Done, detail.clone(), None);
                        if !p.background {
                            self.inform(design::Tone::Good, self.t(Text::Completed), detail, cx)
                        }
                        if let JobKind::Execute(op) = p.kind {
                            self.after_mutation(op, &p, window, cx)
                        }
                    }
                    HubReply::Document(value) => {
                        if p.kind == JobKind::Execute(HubOperation::PreviewRestore)
                            && let (Some(key), Some(candidate)) =
                                (p.draft.as_ref(), p.candidate.as_ref())
                            && let Ok(preview) = serde_json::from_value::<
                                morph_sdk::api::RestorePreview,
                            >(value.clone())
                        {
                            let plan = RestorePlan {
                                candidate: candidate.clone(),
                                preview,
                                event_id: self.event_id(),
                                generation: self.generation,
                                endpoint: self.connected_endpoint.clone(),
                            };
                            if let Some(d) = self.drafts.get_mut(key) {
                                d.restore = Some(plan)
                            }
                        }
                        let title = if let JobKind::Execute(op) = p.kind {
                            operation_title(op, self.language)
                        } else {
                            self.t(Text::DocumentReceived)
                        }
                        .to_owned();
                        let private = matches!(
                            p.kind,
                            JobKind::Execute(
                                HubOperation::ExportRecovery
                                    | HubOperation::ExportRoot
                                    | HubOperation::ExportState
                                    | HubOperation::InspectRoot
                            )
                        );
                        self.finish_activity(
                            p.activity,
                            Status::Done,
                            self.t(Text::CheckedByTheCanonicalRustClient).into(),
                            Some(value.clone()),
                        );
                        if let Some(id) = p.activity
                            && let Some(entry) = self.activities.iter_mut().find(|e| e.id == id)
                        {
                            entry.review = review.clone();
                            entry.output_private = private;
                            entry.output_checked = review.is_some();
                        }
                        if self.page == Page::Actions && self.active == p.draft {
                            self.show_result(
                                value,
                                title,
                                if p.kind == JobKind::Execute(HubOperation::ExportState) {
                                    self.t(Text::HubWorkspaceSnapshot)
                                } else {
                                    self.t(Text::CheckedContentsChainStatusSeparate)
                                }
                                .into(),
                                private,
                                window,
                                cx,
                            );
                            self.result_checked = review.is_some();
                            self.result_review = review;
                            if let Some(key) = p.draft.clone() {
                                self.result_target = ResultTarget::Draft(key);
                            }
                        }
                    }
                },
                Reply::Document(value) => {
                    if let (Some(key), Some(candidate)) = (p.draft.as_ref(), p.candidate.as_ref()) {
                        let op = forms::FORMS[key.form].operation;
                        let live = p.connection_generation == self.generation
                            && self.active.as_ref() == Some(key)
                            && self.page == Page::Actions
                            && self.connected_endpoint == p.endpoint
                            && self
                                .state
                                .as_ref()
                                .is_some_and(|s| s.pubkey == p.origin_node)
                            && self.block_reason(op).is_none();
                        if live
                            && let Ok((id, body)) = self.draft_payload(key, cx)
                            && &body == candidate
                        {
                            if let Some(d) = self.drafts.get_mut(key) {
                                d.checked_review = Some(value.clone());
                                d.review_stale = false;
                                d.error = None;
                            }
                            self.prepared = Some(Prepared {
                                revision: self.state_revision(),
                                operation: op,
                                id,
                                body,
                                event_id: self.event_id(),
                                generation: self.generation,
                                key: key.clone(),
                                endpoint: self.connected_endpoint.clone(),
                            });
                        }
                    }
                    self.finish_activity(
                        p.activity,
                        Status::Done,
                        self.t(Text::OfflineContentVerificationCompletedNoChain)
                            .into(),
                        Some(value.clone()),
                    );
                    if let Some(entry) = p
                        .activity
                        .and_then(|id| self.activities.iter_mut().find(|e| e.id == id))
                    {
                        entry.output_checked = true;
                    }
                    if self.page == Page::Inspector
                        && p.inspector_revision == Some(self.inspector_revision)
                    {
                        self.show_result(
                            value,
                            self.t(Text::EvidenceReview).into(),
                            self.t(Text::CheckedContents).into(),
                            false,
                            window,
                            cx,
                        );
                        self.result_checked = true;
                        self.result_target = ResultTarget::Inspector(self.inspector_revision);
                    }
                    self.inform(
                        design::Tone::Good,
                        self.t(Text::ContentsChecked),
                        self.t(Text::SignatureContentChecksAndCanonicalChain),
                        cx,
                    );
                }
                Reply::Opened(value, bytes) => {
                    let unchanged = match p.target.as_ref() {
                        Some(DocumentTarget::Inspector(_)) => {
                            p.inspector_revision == Some(self.inspector_revision)
                        }
                        Some(DocumentTarget::Draft(key, _)) => {
                            self.drafts.get(key).is_some_and(|d| {
                                p.draft_revision
                                    == Some((d.documents[0].entity_id(), d.document_revision))
                            })
                        }
                        None => false,
                    };
                    if !unchanged {
                        self.finish_activity(
                            p.activity,
                            Status::Done,
                            self.t(Text::TheInputChangedWhileThisFile).into(),
                            Some(value),
                        );
                        if let Some(entry) = p
                            .activity
                            .and_then(|id| self.activities.iter_mut().find(|e| e.id == id))
                        {
                            entry.output_private = true;
                        }
                        self.inform(
                            design::Tone::Warning,
                            self.t(Text::EditsPreserved),
                            self.t(Text::TheLateFileDidNotReplace),
                            cx,
                        );
                        return;
                    }
                    let text = serde_json::to_string_pretty(&value).unwrap_or_default();
                    let info = FileInfo {
                        view_hash: presentation::view_hash(&text),
                        name: p.file_name.clone(),
                        bytes,
                        schema: value["schema"].as_str().unwrap_or("JSON").to_owned(),
                    };
                    match p.target.as_ref() {
                        Some(DocumentTarget::Inspector(i)) => {
                            if let Some(input) = self.inspector.get(*i) {
                                input.update(cx, |v, cx| v.set_value(text, window, cx));
                                self.inspector_files[*i] = Some(info)
                            }
                        }
                        Some(DocumentTarget::Draft(key, i)) => {
                            self.invalidate_draft(key, cx);
                            if let Some(d) = self.drafts.get_mut(key) {
                                d.documents[*i].update(cx, |v, cx| v.set_value(text, window, cx));
                                d.files[*i] = Some(info)
                            }
                        }
                        _ => {}
                    }
                    self.finish_activity(
                        p.activity,
                        Status::Done,
                        self.t(Text::FileLoadedReviewItsContentBefore).into(),
                        None,
                    );
                }
                Reply::Saved => {
                    self.finish_activity(
                        p.activity,
                        Status::Done,
                        if p.kind == JobKind::Save {
                            format!("{} · {}", self.t(Text::NewPrivateFileSaved), p.file_name)
                        } else {
                            self.t(Text::Disconnected).into()
                        },
                        None,
                    );
                    if p.kind == JobKind::Save {
                        self.inform(
                            design::Tone::Good,
                            self.t(Text::PrivateCopySaved),
                            self.t(Text::ExistingFilesWereNotOverwrittenKeep),
                            cx,
                        )
                    }
                }
            },
        }
        cx.notify()
    }
    fn refresh_selected(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if let (Some(selected), Some(state)) = (&self.selected, &self.state) {
            let id = selected.id();
            let record = model::rows(state, selected.page)
                .into_iter()
                .map(|row| Record {
                    page: selected.page,
                    row,
                })
                .find(|r| r.id() == id);
            if let Some(record) = record {
                if self.result_target == ResultTarget::Record(record.page, record.id())
                    && self.result.as_ref() != Some(&record.row.document)
                {
                    self.result = Some(record.row.document.clone());
                    self.update_output(window, cx);
                }
                self.selected = Some(record);
                self.selection_missing = false
            } else {
                self.selection_missing = true
            }
        }
    }
    fn after_mutation(
        &mut self,
        op: HubOperation,
        p: &Pending,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if op == HubOperation::Restore {
            self.drafts.clear();
            self.active = None;
            self.prepared = None;
            self.navigate(Page::Overview, window, cx);
            return;
        }
        if self.page == Page::Actions
            && self.active == p.draft
            && let Some((page, id)) = &p.follow_up
        {
            let page = *page;
            let id = id.clone();
            self.active = None;
            self.navigate(page, window, cx);
            if !id.is_empty() {
                self.select_record_by_id(page, &id, window, cx);
            }
            return;
        }
        if matches!(
            op,
            HubOperation::ImportRoot
                | HubOperation::RootExitSignature
                | HubOperation::RootCreationSignature
        ) && self.page == Page::Actions
            && self.active == p.draft
        {
            let root = self
                .state
                .as_ref()
                .and_then(|s| {
                    s.root_fundings.iter().find(|r| {
                        if op == HubOperation::ImportRoot {
                            !p.previous_roots.contains(&r.root.transaction_hash)
                        } else {
                            p.draft
                                .as_ref()
                                .is_some_and(|k| k.resource == r.root.transaction_hash)
                        }
                    })
                })
                .map(|r| r.root.transaction_hash.clone());
            if let Some(id) = root
                && let Some(s) = &self.state
                && let Some(row) = model::rows(s, Page::Recovery)
                    .into_iter()
                    .find(|r| r.document["transaction_hash"] == id)
            {
                self.page = Page::Recovery;
                self.rebuild();
                self.pick_record(
                    Record {
                        page: Page::Recovery,
                        row,
                    },
                    window,
                    cx,
                );
            }
            if op != HubOperation::ImportRoot
                && let Some(k) = &p.draft
                && let Some(d) = self.drafts.get_mut(k)
            {
                d.documents[0].update(cx, |v, cx| v.set_value("", window, cx));
                d.files[0] = None;
            }
        }
    }
    fn continue_restore(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(plan) = self
            .active
            .as_ref()
            .and_then(|k| self.drafts.get(k))
            .and_then(|d| d.restore.clone())
        else {
            return;
        };
        if !plan.preview.allowed {
            return;
        }
        self.start_task(HubOperation::Restore, String::new(), window, cx);
        if let Some(k) = &self.active
            && forms::FORMS[k.form].operation == HubOperation::Restore
            && let Some(d) = self.drafts.get_mut(k)
        {
            d.documents[0].update(cx, |v, cx| {
                v.set_value(
                    serde_json::to_string_pretty(&plan.candidate).unwrap_or_default(),
                    window,
                    cx,
                )
            });
            d.restore = Some(plan);
        }
    }
    fn acknowledge_reconciliation(&mut self, cx: &mut Context<Self>) {
        if !self.reconcile_ready {
            return;
        }
        if let Some((ep, _)) = self.unknown_context.take() {
            for e in &mut self.activities {
                if e.status == Status::Unknown && e.origin == ep {
                    e.status = Status::Reviewed;
                    e.detail = self
                        .language
                        .t(Text::OperatorRefreshedAndReviewedTheCurrent)
                        .into()
                }
            }
        }
        self.reconcile_ready = false;
        cx.notify()
    }
    fn select_activity(&mut self, id: u64, window: &mut Window, cx: &mut Context<Self>) {
        self.selected_activity = Some(id);
        if let Some((doc, title, private, review, checked)) =
            self.activities.iter().find(|e| e.id == id).and_then(|e| {
                e.output.clone().map(|v| {
                    (
                        v,
                        e.title.clone(),
                        e.output_private,
                        e.review.clone(),
                        e.output_checked,
                    )
                })
            })
        {
            self.show_result(
                doc,
                title,
                self.t(Text::SavedTaskResult).into(),
                private,
                window,
                cx,
            );
            self.result_review = review;
            self.result_checked = checked;
            self.result_target = ResultTarget::Activity(id);
        }
        cx.notify()
    }
}
fn canonical_id(s: &str) -> bool {
    s.len() == 66
        && s.starts_with("0x")
        && s[2..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn redact(value: &mut Value, language: Language) {
    match value {
        Value::Object(fields) => {
            for (key, v) in fields {
                if key.contains("preimage")
                    || key == "signature"
                    || key.ends_with("witness_hex")
                    || key == "transaction_hex"
                {
                    *v = Value::String(language.t(Text::PrivateEvidenceHidden).into())
                } else {
                    redact(v, language)
                }
            }
        }
        Value::Array(values) => {
            for v in values {
                redact(v, language)
            }
        }
        _ => {}
    }
}
impl Render for Desktop {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        self.render_workspace(window, cx)
    }
}
fn main() {
    gpui_kit::application()
        .with_assets(assets::Assets)
        .run(|cx: &mut App| {
            gpui_kit::init(cx);
            Theme::change(ThemeMode::Dark, None, cx);
            design::install(cx);
            views::install_shortcuts(cx);
            let options = WindowOptions {
                window_bounds: Some(WindowBounds::Windowed(Bounds::centered(
                    None,
                    size(px(1440.), px(960.)),
                    cx,
                ))),
                window_min_size: Some(size(px(780.), px(580.))),
                app_id: Some("network.morph.workspace".into()),
                ..Default::default()
            };
            if let Err(e) = gpui_kit::open_window(options, cx, |window, cx| {
                window.set_window_title(Language::system().t(Text::MorphWorkspace));
                window.activate_window();
                cx.new(|cx| Desktop::new(window, cx))
            }) {
                eprintln!("Cannot open Morph desktop: {e}");
                cx.quit()
            }
        })
}

#[cfg(test)]
mod ui_tests {
    use super::*;
    use gpui_kit::{ElementInputHandler, InputHandler, TestAppContext, test::TestWindowExt};
    #[gpui_kit::test]
    fn maximum_text_scale_keeps_settings_controls_reachable_in_minimum_window(
        cx: &mut TestAppContext,
    ) {
        let (handle, view) = cx.update(|cx| {
            gpui_kit::init(cx);
            design::install(cx);
            gpui_kit::open_window(
                WindowOptions {
                    window_bounds: Some(WindowBounds::Windowed(Bounds::new(
                        Default::default(),
                        size(px(780.), px(580.)),
                    ))),
                    ..Default::default()
                },
                cx,
                |w, cx| cx.new(|cx| Desktop::new(w, cx)),
            )
            .unwrap()
        });
        cx.update_window(handle, |_, w, cx| {
            view.update(cx, |v, cx| {
                v.change_scale(50, w, cx);
                v.appearance_settings = true;
                v.set_reduced_motion(true, cx);
                v.navigate(Page::Model, w, cx);
            });
            w.render_frame(cx);
            let before = w.find("larger-text").bounds();
            for _ in 0..10 {
                let center = w.find("larger-text").bounds().center();
                if center.y > px(90.) && center.y < px(550.) {
                    break;
                }
                w.scroll(
                    "settings-scroll",
                    gpui_kit::ScrollDelta::Pixels(gpui_kit::point(px(0.), px(-100.))),
                    cx,
                );
            }
            let after = w.find("larger-text").bounds();
            assert!(
                after.top() < before.top(),
                "large settings must actually scroll"
            );
            assert!(after.center().y > px(90.) && after.center().y < px(550.));
            assert!(after.left() >= px(114.) && after.right() <= px(780.));
        })
        .unwrap();
    }
    #[gpui_kit::test]
    fn task_tiles_render_and_success_notice_does_not_move_content(cx: &mut TestAppContext) {
        let (handle, view) = cx.update(|cx| {
            gpui_kit::init(cx);
            design::install(cx);
            gpui_kit::open_window(
                WindowOptions {
                    window_bounds: Some(WindowBounds::Windowed(Bounds::new(
                        Default::default(),
                        size(px(1320.), px(880.)),
                    ))),
                    ..Default::default()
                },
                cx,
                |w, cx| cx.new(|cx| Desktop::new(w, cx)),
            )
            .unwrap()
        });
        cx.update_window(handle, |_, w, cx| {
            view.update(cx, |v, cx| {
                v.set_reduced_motion(true, cx);
                v.navigate(Page::Actions, w, cx);
            });
            w.render_frame(cx);
            let before = w.find(("task-area", 0_usize)).bounds();
            view.update(cx, |v, cx| {
                v.notice = Some(Notice {
                    created: Instant::now(),
                    tone: design::Tone::Good,
                    title: "Saved".into(),
                    detail: "Finished".into(),
                });
                cx.notify();
            });
            w.render_frame(cx);
            assert_eq!(before, w.find(("task-area", 0_usize)).bounds());
            w.click(("task-area", 0_usize), cx);
            assert_eq!(view.read(cx).task_domain, Some(0));
        })
        .unwrap();
    }
    #[gpui_kit::test]
    fn native_input_and_drafts_are_isolated_by_task_context(cx: &mut TestAppContext) {
        let (handle, view) = cx.update(|cx| {
            gpui_kit::init(cx);
            gpui_kit::open_window(WindowOptions::default(), cx, |window, cx| {
                cx.new(|cx| Desktop::new(window, cx))
            })
            .unwrap()
        });
        cx.update_window(handle, |_, window, cx| {
            view.update(cx, |this, cx| this.navigate(Page::Model, window, cx));
            window.render_frame(cx);
            window.click("endpoint", cx);
            window.press("ctrl-a", cx);
            let bounds = window.find("endpoint").bounds();
            let input = view.read(cx).endpoint.clone();
            let mut handler = ElementInputHandler::new(bounds, input.clone());
            handler.replace_and_mark_text_in_range(None, "zhong", Some(5..5), window, cx);
            handler.replace_text_in_range(None, "中文", window, cx);
            assert!(input.read(cx).value().contains("中文"));
            cx.write_to_clipboard(ClipboardItem::new_string("粘贴".into()));
            window.press("ctrl-v", cx);
            assert!(input.read(cx).value().contains("粘贴"));
            view.update(cx, |this, cx| {
                this.start_task(HubOperation::Peer, "context-a".into(), window, cx)
            });
            window.render_frame(cx);
            window.click("pubkey", cx);
            window.input("draft-a", cx);
            view.update(cx, |this, cx| {
                this.start_task(HubOperation::Peer, "context-b".into(), window, cx)
            });
            window.render_frame(cx);
            let b = view.read(cx).active.clone().unwrap();
            assert!(
                view.read(cx).drafts[&b].fields[0]
                    .1
                    .read(cx)
                    .value()
                    .is_empty()
            );
            view.update(cx, |this, cx| {
                this.start_task(HubOperation::Peer, "context-a".into(), window, cx)
            });
            window.render_frame(cx);
            let a = view.read(cx).active.clone().unwrap();
            assert!(
                view.read(cx).drafts[&a].fields[0]
                    .1
                    .read(cx)
                    .value()
                    .contains("draft-a")
            );
            let field = view.read(cx).drafts[&a].fields[0].1.clone();
            let id = field.entity_id();
            view.update(cx, |this, cx| {
                this.change_scale(50, window, cx);
                assert_eq!(this.scale_percent, 150);
                this.change_scale(10, window, cx);
                assert_eq!(this.scale_percent, 150);
                this.set_language(Language::Chinese, window, cx);
                this.set_reduced_motion(true, cx);
            });
            window.render_frame(cx);
            assert_eq!(field.entity_id(), id);
            assert!(field.read(cx).value().contains("draft-a"));
            assert_eq!(window.rem_size(), px(24.));
            view.update(cx, |this, cx| {
                this.change_scale(-100, window, cx);
                assert_eq!(this.scale_percent, 90);
                this.change_scale(0, window, cx);
                assert_eq!(this.scale_percent, 100);
            });
            window.click("review-action", cx);
            assert!(view.read(cx).prepared.is_none());
        })
        .unwrap();
    }
}
