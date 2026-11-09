mod forms;
mod model;
mod worker;

use gpui_kit::component::{
    Disableable, Selectable, Theme, ThemeMode,
    button::{Button, ButtonVariants},
    input::{Input, InputEvent, InputState, Textarea, TextareaState},
};
use gpui_kit::{
    App, AppContext, ClipboardItem, Context, Entity, InteractiveElement, IntoElement,
    ParentElement, PathPromptOptions, Render, StatefulInteractiveElement, Styled, Subscription,
    Task, Window, WindowOptions, div, px, rgb, uniform_list,
};
use model::{Page, Row};
use morph_sdk::{
    api::HubView,
    hub::{HubOperation, HubReply},
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};
use worker::{Job, Reply, Work, Worker};

type FieldInputs = Vec<(&'static str, Entity<InputState>)>;
struct Prepared {
    operation: HubOperation,
    id: String,
    body: Value,
    event_id: u64,
}
struct Desktop {
    endpoint: Entity<InputState>,
    token: Entity<InputState>,
    search: Entity<InputState>,
    id: Entity<InputState>,
    asset: Entity<InputState>,
    fields: FieldInputs,
    documents: [Entity<TextareaState>; 3],
    output: Entity<TextareaState>,
    page: Page,
    form: usize,
    state: Option<HubView>,
    rows: Arc<Vec<Row>>,
    result: Option<Value>,
    worker: Option<Worker>,
    busy: bool,
    dialog_pending: bool,
    connected: bool,
    generation: u64,
    last_checked: Option<Instant>,
    last_attempt: Instant,
    message: String,
    prepared: Option<Prepared>,
    uncertain: bool,
    mutating: bool,
    _subscriptions: Vec<Subscription>,
    _poll: Option<Task<()>>,
}
impl Desktop {
    fn input(
        value: &str,
        placeholder: &str,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Entity<InputState> {
        cx.new(|cx| {
            let mut state = InputState::new(window, cx).placeholder(placeholder.to_owned());
            state.set_value(value.to_owned(), window, cx);
            state
        })
    }
    fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        let endpoint = Self::input("http://127.0.0.1:4617", "Hub endpoint", window, cx);
        let token = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("Bearer token · memory only")
                .masked(true)
        });
        let search = Self::input("", "Search all fields", window, cx);
        let id = Self::input("", "Resource id: 0x + 64 lowercase hex", window, cx);
        let asset = Self::input("", "Blank = CKB; otherwise xUDT Type hash", window, cx);
        let documents =
            std::array::from_fn(|_| cx.new(|cx| TextareaState::new(window, cx).rows(6)));
        let output = cx.new(|cx| TextareaState::new(window, cx).rows(10));
        let search_subscription = cx.subscribe_in(&search, window, |this, _, event, _, cx| {
            if matches!(event, InputEvent::Change) {
                this.rebuild(cx);
                cx.notify()
            }
        });
        let worker = Worker::start();
        let message = worker
            .as_ref()
            .err()
            .map(|e| format!("Worker unavailable: {e}"))
            .unwrap_or_else(|| "Connect to a Hub, or inspect public evidence offline.".into());
        let mut view = Self {
            endpoint,
            token,
            search,
            id,
            asset,
            fields: vec![],
            documents,
            output,
            page: Page::Overview,
            form: 0,
            state: None,
            rows: Arc::new(vec![]),
            result: None,
            worker: worker.ok(),
            busy: false,
            dialog_pending: false,
            connected: false,
            generation: 0,
            last_checked: None,
            last_attempt: Instant::now(),
            message,
            prepared: None,
            uncertain: false,
            mutating: false,
            _subscriptions: vec![search_subscription],
            _poll: None,
        };
        view.select_form(0, window, cx);
        view._poll = Some(cx.spawn_in(window, async move |this, cx| {
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
        view
    }
    fn select_form(&mut self, index: usize, window: &mut Window, cx: &mut Context<Self>) {
        self.form = index;
        self.prepared = None;
        self.fields = forms::FORMS[index]
            .fields
            .iter()
            .map(|f| {
                let input = Self::input(f.default, f.label, window, cx);
                if matches!(f.kind, forms::Kind::Secret) {
                    input.update(cx, |state, cx| state.set_masked(true, window, cx));
                }
                (f.key, input)
            })
            .collect();
        cx.notify();
    }
    fn show_result(&mut self, value: Value, window: &mut Window, cx: &mut Context<Self>) {
        let text = serde_json::to_string_pretty(&value)
            .unwrap_or_else(|e| format!("Formatting failed: {e}"));
        self.output
            .update(cx, |input, cx| input.set_value(text, window, cx));
        self.result = Some(value);
        cx.notify();
    }
    fn rebuild(&mut self, cx: &mut Context<Self>) {
        self.rows = Arc::new(
            self.state
                .as_ref()
                .map(|s| model::filter(model::rows(s, self.page), &self.search.read(cx).value()))
                .unwrap_or_default(),
        );
    }
    fn send(&mut self, work: Work, cx: &mut Context<Self>) {
        if self.busy {
            self.message = "An operation is already running.".into();
            return;
        }
        self.mutating = matches!(&work,Work::Execute{operation,..} if operation.mutates());
        match self
            .worker
            .as_ref()
            .ok_or_else(|| "Background worker unavailable".to_owned())
            .and_then(|worker| {
                worker
                    .send
                    .try_send(Job {
                        generation: self.generation,
                        work,
                    })
                    .map_err(|_| "Background worker busy or stopped".into())
            }) {
            Ok(()) => {
                self.busy = true;
                self.message = "Working…".into();
                self.last_attempt = Instant::now()
            }
            Err(error) => self.message = error,
        }
        cx.notify();
    }
    fn connect(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.busy {
            return;
        }
        self.generation = self.generation.saturating_add(1);
        self.connected = false;
        self.last_checked = None;
        self.state = None;
        self.prepared = None;
        self.uncertain = false;
        let endpoint = self.endpoint.read(cx).value().to_string();
        let token = self.token.read(cx).value().to_string();
        self.token
            .update(cx, |input, cx| input.set_value("", window, cx));
        self.send(Work::Connect { endpoint, token }, cx);
    }
    fn cancel(&mut self, cx: &mut Context<Self>) {
        if !self.busy {
            return;
        }
        self.generation = self.generation.saturating_add(1);
        self.busy = false;
        self.prepared = None;
        self.last_checked = None;
        self.uncertain = self.mutating;
        self.message = if self.mutating {
            "Stopped waiting. Mutation outcome unknown: refresh and reconcile before retrying."
        } else {
            "Stopped waiting; late read results will be ignored."
        }
        .into();
        cx.notify();
    }
    fn disconnect(&mut self, cx: &mut Context<Self>) {
        if self.busy {
            self.cancel(cx)
        } else {
            self.generation = self.generation.saturating_add(1)
        }
        self.connected = false;
        self.state = None;
        self.rows = Arc::new(Vec::new());
        self.last_checked = None;
        self.prepared = None;
        self.send(Work::Disconnect, cx);
    }
    fn poll(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let completion = self
            .worker
            .as_ref()
            .and_then(|worker| worker.receive.try_recv().ok());
        if let Some(done) = completion
            && done.generation == self.generation
        {
            self.busy = false;
            match done.result {
                Ok(Reply::Hub(reply)) => match *reply {
                    HubReply::State(state) => {
                        self.state = Some(*state);
                        self.connected = true;
                        self.last_checked = Some(Instant::now());
                        self.message =
                            "Hub refreshed · local projection; see provenance for each record."
                                .into();
                        self.uncertain = false;
                        self.rebuild(cx)
                    }
                    HubReply::Document(value) => {
                        self.show_result(value, window, cx);
                        self.message =
                            "Validated document received. Save a private copy to retain it.".into()
                    }
                },
                Ok(Reply::Document(value)) => {
                    self.show_result(value, window, cx);
                    self.message =
                        "Public terms checked offline. Canonical chain / VM checks remain separate."
                            .into()
                }
                Ok(Reply::Opened(slot, value)) => {
                    let text = serde_json::to_string_pretty(&value).unwrap_or_default();
                    if let Some(document) = self.documents.get(slot) {
                        document.update(cx, |input, cx| input.set_value(text, window, cx));
                    }
                    self.prepared = None;
                    self.message = "Document loaded; review before import or inspection.".into()
                }
                Ok(Reply::Saved) => self.message = "Completed.".into(),
                Err(error) => {
                    self.uncertain = error
                        .downcast_ref::<morph_sdk::HubClientError>()
                        .is_some_and(|e| matches!(e, morph_sdk::HubClientError::OutcomeUnknown));
                    self.message = error.to_string();
                    self.last_checked = None;
                    self.prepared = None;
                }
            }
            cx.notify();
        }
        if self.connected
            && !self.busy
            && !self.dialog_pending
            && !self.uncertain
            && self.last_attempt.elapsed() >= Duration::from_secs(5)
        {
            self.send(Work::Refresh, cx)
        }
    }
    fn allowed(&self, operation: HubOperation) -> bool {
        if self.busy
            || self.uncertain
            || !model::can_operate(
                self.state.as_ref(),
                self.last_checked,
                operation.required_scope(),
            )
        {
            return false;
        }
        self.state.as_ref().is_some_and(|state| match operation {
            HubOperation::CreateInvoice => state.security.invoice_signing_enabled,
            HubOperation::PreviewRestore | HubOperation::Restore => {
                state.security.state_restore_enabled
            }
            _ => true,
        })
    }
    fn draft(&self, cx: &Context<Self>) -> anyhow::Result<(String, Value)> {
        let form = &forms::FORMS[self.form];
        let id = self.id.read(cx).value().trim().to_owned();
        if form.needs_id {
            anyhow::ensure!(
                id.len() == 66
                    && id.starts_with("0x")
                    && id[2..]
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                "Resource id must be canonical lowercase 32-byte hex"
            );
        }
        let body = if form.document {
            let value = self.documents[0].read(cx).value();
            anyhow::ensure!(value.len() <= 4 * 1024 * 1024, "document exceeds 4 MiB");
            serde_json::from_str(&value)?
        } else {
            let fields = self
                .fields
                .iter()
                .map(|(key, entity)| (key.to_string(), entity.read(cx).value().to_string()))
                .collect::<BTreeMap<_, _>>();
            forms::payload(form, &fields, &self.asset.read(cx).value())?
        };
        Ok((id, body))
    }
    fn prepare(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let op = forms::FORMS[self.form].operation;
        if !self.allowed(op) {
            self.message = "Fresh Hub state and the required API scope are needed.".into();
            return;
        }
        match self.draft(cx) {
            Ok((id, body)) => {
                if !op.mutates() {
                    self.send(
                        Work::Execute {
                            operation: op,
                            id,
                            body,
                        },
                        cx,
                    );
                    return;
                }
                let event_id = self
                    .state
                    .as_ref()
                    .and_then(|s| s.events.last())
                    .map_or(0, |e| e.id);
                let mut safe = body.clone();
                redact(&mut safe);
                self.show_result(json!({"review":forms::FORMS[self.form].label,"resource_id":id,"request":safe,"scope":"Hub local projection / evidence store; this does not broadcast a transaction"}),window,cx);
                self.prepared = Some(Prepared {
                    operation: op,
                    id,
                    body,
                    event_id,
                });
                self.message="Review the exact request, then confirm. Editing the form or changing Hub state invalidates confirmation.".into();
            }
            Err(error) => self.message = error.to_string(),
        }
        cx.notify();
    }
    fn confirm(&mut self, cx: &mut Context<Self>) {
        let Some(prepared) = self.prepared.take() else {
            return;
        };
        let event_id = self
            .state
            .as_ref()
            .and_then(|s| s.events.last())
            .map_or(0, |e| e.id);
        if !self.allowed(prepared.operation)
            || forms::FORMS[self.form].operation != prepared.operation
            || self.draft(cx).ok() != Some((prepared.id.clone(), prepared.body.clone()))
            || prepared.event_id != event_id
        {
            self.message = "Draft, permissions or live state changed. Review again.".into();
            cx.notify();
            return;
        }
        self.send(
            Work::Execute {
                operation: prepared.operation,
                id: prepared.id,
                body: prepared.body,
            },
            cx,
        );
    }
    fn inspect(&mut self, cx: &mut Context<Self>) {
        let parsed = (|| -> anyhow::Result<_> {
            let mut values = Vec::new();
            for field in &self.documents {
                let text = field.read(cx).value();
                anyhow::ensure!(text.len() <= 4 * 1024 * 1024, "document exceeds 4 MiB");
                values.push(if text.trim().is_empty() {
                    None
                } else {
                    Some(serde_json::from_str::<Value>(&text)?)
                });
            }
            let document = values[0]
                .take()
                .ok_or_else(|| anyhow::anyhow!("Load public evidence first"))?;
            Ok(Work::Inspect {
                document,
                base: values[1].take(),
                receipt: values[2].take(),
            })
        })();
        match parsed {
            Ok(work) => self.send(work, cx),
            Err(error) => {
                self.message = error.to_string();
                cx.notify()
            }
        }
    }
    fn open_file(&mut self, slot: usize, cx: &mut Context<Self>) {
        if self.busy || self.dialog_pending {
            return;
        }
        self.dialog_pending = true;
        self.message = "Choose JSON evidence in the native file dialog.".into();
        cx.notify();
        let paths = cx.prompt_for_paths(PathPromptOptions {
            files: true,
            directories: false,
            multiple: false,
            prompt: Some("Open Morph JSON evidence".into()),
        });
        cx.spawn(async move |this, cx| {
            let result = paths.await;
            let _ = this.update(cx, |this, cx| {
                this.dialog_pending = false;
                match result {
                    Ok(Ok(Some(paths))) => {
                        if let Some(path) = paths.into_iter().next() {
                            this.send(Work::Open { path, slot }, cx)
                        } else {
                            this.message = "No file selected.".into()
                        }
                    }
                    Ok(Err(error)) => this.message = format!("File dialog: {error}"),
                    _ => this.message = "File selection cancelled.".into(),
                }
                cx.notify();
            });
        })
        .detach();
    }
    fn save_file(&mut self, cx: &mut Context<Self>) {
        let Some(document) = self.result.clone() else {
            return;
        };
        if self.busy || self.dialog_pending {
            return;
        }
        self.dialog_pending = true;
        self.message = "Choose a new private JSON file in the native save dialog.".into();
        cx.notify();
        let path = cx.prompt_for_new_path(Path::new("."), Some("morph-evidence.json"));
        cx.spawn(async move |this, cx| {
            let result = path.await;
            let _ = this.update(cx, |this, cx| {
                this.dialog_pending = false;
                match result {
                    Ok(Ok(Some(path))) => this.send(Work::Save { path, document }, cx),
                    Ok(Err(error)) => this.message = format!("Save dialog: {error}"),
                    _ => this.message = "Save cancelled.".into(),
                }
                cx.notify();
            });
        })
        .detach();
    }
    fn navigation(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        let mut panel = div()
            .w(px(215.))
            .h_full()
            .text_color(rgb(0xe4edf7))
            .flex()
            .flex_col()
            .gap_2()
            .p_4()
            .bg(rgb(0x172233))
            .child(div().text_2xl().child("Morph Hub"))
            .child(div().text_sm().child("Native operator console"));
        for &(page, label) in model::PAGES {
            panel = panel.child(
                Button::new(label)
                    .label(label)
                    .selected(self.page == page)
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.page = page;
                        this.rebuild(cx);
                        cx.notify()
                    })),
            );
        }
        panel
            .child(div().flex_1())
            .child("Rust · GPUI")
            .child("No channel signing authority")
    }
    fn records(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        let rows = Arc::clone(&self.rows);
        let view = cx.entity().downgrade();
        div()
            .flex_1()
            .min_h_0()
            .flex()
            .flex_col()
            .gap_3()
            .child(Input::new(&self.search).id("record-search"))
            .child(format!(
                "{} matching records · select to inspect full fields and provenance",
                rows.len()
            ))
            .child(
                uniform_list("records", rows.len(), move |range, _, _| {
                    range
                        .map(|i| {
                            let row = rows[i].clone();
                            let view = view.clone();
                            div()
                                .id(("record", i))
                                .h(px(80.))
                                .p_3()
                                .border_b_1()
                                .border_color(rgb(0x344155))
                                .cursor_pointer()
                                .overflow_hidden()
                                .child(row.title.clone())
                                .child(
                                    div()
                                        .text_sm()
                                        .text_color(rgb(0xb7c6d9))
                                        .child(row.subtitle.clone()),
                                )
                                .on_click(move |_, window, cx| {
                                    let _ = view.update(cx, |this, cx| {
                                        this.show_result(row.document.clone(), window, cx)
                                    });
                                })
                        })
                        .collect::<Vec<_>>()
                })
                .flex_1()
                .min_h_0(),
            )
    }
    fn overview(&self) -> impl IntoElement {
        let mut body = div()
            .flex()
            .flex_col()
            .gap_4()
            .child(div().text_2xl().child("Operator overview"));
        if let Some(state) = &self.state {
            body = body
                .child(format!("{} · {}", state.network, state.pubkey))
                .child(format!(
                    "RPC: {} · tip {}",
                    state.rpc.status,
                    state
                        .rpc
                        .tip_height
                        .map_or("unknown".into(), |h| h.to_string())
                ))
                .child(state.provenance.message.clone())
                .child(format!(
                    "{} channels · {} factories · {} invoices · {} peers",
                    state.channels.len(),
                    state.factories.len(),
                    state.invoices.len(),
                    state.peers.len()
                ))
                .child(format!(
                    "{} saved recovery packages · {} root ceremonies",
                    state.multi_asset_package_count,
                    state.root_fundings.len()
                ))
                .child(format!(
                    "Watchtower: {} · {} alerts",
                    if state.watchtower.configured {
                        "configured"
                    } else {
                        "not configured"
                    },
                    state.watchtower.alerts.len()
                ))
                .child(format!("Missing flows: {}", state.missing_flows.join(", ")))
                .child("Amounts remain integer base units; token Types are never summed together.");
        } else {
            body = body
                .child("Connect to the headless Hub API to read local operator records.")
                .child("Offline inspection works without a Hub or node.")
        }
        body
    }
    fn operation_form(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        let form = forms::FORMS[self.form];
        let allowed = self.allowed(form.operation);
        let mut choices = div().w(px(235.)).flex().flex_col().gap_2();
        for (i, f) in forms::FORMS.iter().enumerate() {
            choices = choices.child(
                Button::new(("operation", i))
                    .label(f.label)
                    .selected(i == self.form)
                    .on_click(
                        cx.listener(move |this, _, window, cx| this.select_form(i, window, cx)),
                    ),
            );
        }
        let mut fields=div().flex_1().min_w_0().flex().flex_col().gap_3().child(div().text_xl().child(form.label)).child("These operations update the Hub projection or saved evidence. Native funding/signing/broadcast remains in the operator ceremony.");
        if form.needs_id {
            fields = fields
                .child("Resource id")
                .child(Input::new(&self.id).id("resource-id"));
        }
        for (key, field) in &self.fields {
            fields = fields.child(*key).child(Input::new(field).id(*key));
        }
        if matches!(
            form.operation,
            HubOperation::CreateInvoice
                | HubOperation::OpenChannel
                | HubOperation::OpenFactory
                | HubOperation::MaterialiseChild
        ) {
            fields = fields
                .child("Asset Type (blank = CKB)")
                .child(Input::new(&self.asset).id("asset-type"));
        }
        if form.document {
            fields = fields
                .child(
                    Button::new("open-operation-json")
                        .label("Open JSON file")
                        .disabled(self.busy || self.dialog_pending)
                        .on_click(cx.listener(|this, _, _, cx| this.open_file(0, cx))),
                )
                .child(Textarea::new(&self.documents[0]).h(px(230.)));
        }
        fields = fields
            .child(format!(
                "Required scope: {:?}",
                form.operation.required_scope()
            ))
            .child(
                Button::new("review-action")
                    .primary()
                    .label(if form.operation.mutates() {
                        "Review request"
                    } else {
                        "Fetch / preview"
                    })
                    .disabled(!allowed)
                    .on_click(cx.listener(|this, _, window, cx| this.prepare(window, cx))),
            );
        if self.prepared.is_some() {
            fields = fields.child(
                Button::new("confirm-action")
                    .label("Confirm reviewed request")
                    .disabled(!allowed)
                    .on_click(cx.listener(|this, _, _, cx| this.confirm(cx))),
            );
        }
        div()
            .id("form-scroll")
            .flex_1()
            .min_h_0()
            .overflow_y_scroll()
            .flex()
            .gap_4()
            .child(choices)
            .child(fields)
    }
    fn inspector(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        let mut view=div().id("inspector-scroll").flex_1().min_h_0().overflow_y_scroll().flex().flex_col().gap_3().child(div().text_xl().child("Offline evidence review")).child("Stateless public review uses canonical Core validation. It does not reserve signatures, publish, or recover a missing signer journal.");
        for (i, label) in [
            "Public document / proposal / Factory request",
            "Signed base recovery (proposal or splice)",
            "Detached signature receipt (optional)",
        ]
        .iter()
        .enumerate()
        {
            view = view
                .child(*label)
                .child(
                    Button::new(("open-document", i))
                        .label("Open JSON")
                        .disabled(self.busy || self.dialog_pending)
                        .on_click(cx.listener(move |this, _, _, cx| this.open_file(i, cx))),
                )
                .child(Textarea::new(&self.documents[i]).h(px(145.)));
        }
        view.child(
            Button::new("inspect-evidence")
                .primary()
                .label("Inspect exact public evidence")
                .disabled(self.busy || self.dialog_pending)
                .on_click(cx.listener(|this, _, _, cx| this.inspect(cx))),
        )
    }
}
fn redact(value: &mut Value) {
    match value {
        Value::Object(fields) => {
            for (key, value) in fields {
                if key.contains("preimage") || key == "signature" {
                    *value = Value::String("[redacted for request review]".into())
                } else {
                    redact(value)
                }
            }
        }
        Value::Array(values) => {
            for value in values {
                redact(value)
            }
        }
        _ => {}
    }
}
impl Render for Desktop {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let freshness = self
            .last_checked
            .map(|t| format!("Last verified {}s ago", t.elapsed().as_secs()))
            .unwrap_or_else(|| "Offline / stale · writes disabled".into());
        let mut content = div()
            .h_full()
            .flex_1()
            .min_w_0()
            .flex()
            .flex_col()
            .gap_3()
            .p_5()
            .bg(rgb(0x101a29))
            .text_color(rgb(0xe4edf7));
        content = content.child(
            div()
                .flex()
                .gap_3()
                .child(Input::new(&self.endpoint).id("endpoint"))
                .child(Input::new(&self.token).id("hub-token"))
                .child(
                    Button::new("connect")
                        .primary()
                        .label("Connect")
                        .disabled(self.busy || self.dialog_pending)
                        .on_click(cx.listener(|this, _, window, cx| this.connect(window, cx))),
                )
                .child(
                    Button::new("refresh")
                        .label("Refresh")
                        .disabled(self.busy || !self.connected)
                        .on_click(cx.listener(|this, _, _, cx| this.send(Work::Refresh, cx))),
                )
                .child(
                    Button::new("disconnect")
                        .label("Disconnect")
                        .disabled(!self.connected)
                        .on_click(cx.listener(|this, _, _, cx| this.disconnect(cx))),
                )
                .child(
                    Button::new("cancel-task")
                        .label("Stop waiting")
                        .disabled(!self.busy)
                        .on_click(cx.listener(|this, _, _, cx| this.cancel(cx))),
                ),
        );
        content = content.child(format!("{freshness} · {}", self.message));
        let body = match self.page {
            Page::Overview => self.overview().into_any_element(),
            Page::Actions => self.operation_form(cx).into_any_element(),
            Page::Inspector => self.inspector(cx).into_any_element(),
            _ => self.records(cx).into_any_element(),
        };
        content=content.child(div().flex_1().min_h_0().flex().gap_4().child(div().flex_1().min_w_0().flex().flex_col().child(body)).child(div().w(px(460.)).flex().flex_col().gap_2().child("Selected record / verified output").child(Textarea::new(&self.output).readonly(true).h(px(440.))).child(Button::new("copy-result").label("Copy output").disabled(self.result.is_none()).on_click(cx.listener(|this,_,_,cx|{if let Some(value)=&this.result&& let Ok(text)=serde_json::to_string_pretty(value){cx.write_to_clipboard(ClipboardItem::new_string(text));this.message="Output copied. Recovery exports may contain private evidence.".into();cx.notify()}}))).child(Button::new("save-result").label("Save private JSON copy").disabled(self.busy||self.dialog_pending||self.result.is_none()).on_click(cx.listener(|this,_,_,cx|this.save_file(cx))))));
        div()
            .size_full()
            .flex()
            .child(self.navigation(cx))
            .child(content)
    }
}
fn main() {
    gpui_kit::application()
        .with_assets(gpui_kit::assets::Assets)
        .run(|cx: &mut App| {
            gpui_kit::init(cx);
            Theme::change(ThemeMode::Dark, None, cx);
            if let Err(error) = gpui_kit::open_window(WindowOptions::default(), cx, |window, cx| {
                window.set_window_title("Morph Hub");
                window.activate_window();
                cx.new(|cx| Desktop::new(window, cx))
            }) {
                eprintln!("Cannot open Morph native desktop: {error}");
                cx.quit();
            }
        });
}

#[cfg(test)]
mod ui_tests {
    use super::{Desktop, Page};
    use gpui_kit::{
        AppContext, ClipboardItem, ElementInputHandler, InputHandler, TestAppContext,
        WindowOptions, test::TestWindowExt,
    };
    #[gpui_kit::test]
    fn input_retains_composition_clipboard_and_navigation(cx: &mut TestAppContext) {
        let (handle, view) = cx.update(|cx| {
            gpui_kit::init(cx);
            gpui_kit::open_window(WindowOptions::default(), cx, |window, cx| {
                cx.new(|cx| Desktop::new(window, cx))
            })
            .unwrap()
        });
        cx.update_window(handle, |_, window, cx| {
            window.render_frame(cx);
            window.click("endpoint", cx);
            window.press("ctrl-a", cx);
            window.input("http://127.0.0.1:4617", cx);
            let bounds = window.find("endpoint").bounds();
            let mut handler = ElementInputHandler::new(bounds, view.read(cx).endpoint.clone());
            handler.replace_and_mark_text_in_range(None, "zhong", Some(5..5), window, cx);
            handler.replace_text_in_range(None, "中文", window, cx);
            assert!(view.read(cx).endpoint.read(cx).value().contains("中文"));
            cx.write_to_clipboard(ClipboardItem::new_string("粘贴".into()));
            window.press("ctrl-v", cx);
            assert!(view.read(cx).endpoint.read(cx).value().contains("粘贴"));
            window.click("Offline inspector", cx);
        })
        .unwrap();
        cx.update_window(handle, |_, window, cx| {
            window.render_frame(cx);
            assert_eq!(view.read(cx).page, Page::Inspector);
            window.click("Operations", cx);
        })
        .unwrap();
        cx.update_window(handle, |_, window, cx| {
            window.render_frame(cx);
            assert_eq!(view.read(cx).page, Page::Actions);
            // A disconnected client cannot mutate the Hub through a click.
            window.click("review-action", cx);
            assert!(view.read(cx).prepared.is_none());
            window.click("pubkey", cx);
            window.input("draft-key", cx);
            window.click("Model & permissions", cx);
            window.click("Operations", cx);
            assert!(
                view.read(cx).fields[0]
                    .1
                    .read(cx)
                    .value()
                    .contains("draft-key")
            );
        })
        .unwrap();
    }
}
