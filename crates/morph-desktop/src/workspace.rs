//! Ephemeral UI tasks and drafts. None of these objects is signer authority.
use crate::{
    Desktop,
    i18n::{Language, Text},
    model::{Page, Row},
};
use gpui_kit::component::input::{InputEvent, InputState, TextareaState};
use gpui_kit::{AppContext, Context, Entity, Subscription, Window};
use morph_sdk::{api::RestorePreview, hub::HubOperation};
use serde_json::Value;
use std::time::Instant;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct DraftKey {
    pub form: usize,
    pub resource: String,
}
#[derive(Clone)]
pub struct RestorePlan {
    pub candidate: Value,
    pub preview: RestorePreview,
    pub event_id: u64,
    pub generation: u64,
    pub endpoint: String,
}
#[derive(Clone)]
pub struct FileInfo {
    pub name: String,
    pub bytes: u64,
    pub schema: String,
    pub view_hash: u64,
}
pub struct Draft {
    pub scroll: gpui_kit::ScrollHandle,
    pub anchors: std::collections::BTreeMap<&'static str, gpui_kit::ScrollAnchor>,
    pub id: Entity<InputState>,
    pub asset: Entity<InputState>,
    pub fields: Vec<(&'static str, Entity<InputState>)>,
    pub documents: [Entity<TextareaState>; 1],
    pub files: [Option<FileInfo>; 1],
    pub ckb_units: bool,
    pub advanced_id: bool,
    pub advanced_fields: bool,
    pub target_search: Entity<InputState>,
    pub target_page: usize,
    pub discard_pending: bool,
    pub validation_attempted: bool,
    pub document_revision: u64,
    pub show_document: bool,
    pub restore: Option<RestorePlan>,
    pub checked_review: Option<Value>,
    pub error: Option<String>,
    pub review_stale: bool,
    pub _subscriptions: Vec<Subscription>,
}
impl Draft {
    pub fn new(
        key: &DraftKey,
        language: Language,
        window: &mut Window,
        cx: &mut Context<Desktop>,
    ) -> Self {
        let form = crate::forms::FORMS[key.form];
        let id = Desktop::input(&key.resource, "0x…", window, cx);
        let asset = Desktop::input("", language.t(Text::AssetHashPlaceholder), window, cx);
        let target_search = Desktop::input("", language.t(Text::SearchObjects), window, cx);
        let fields = form
            .fields
            .iter()
            .map(|f| {
                let e = Desktop::input(f.default, language.t(f.label), window, cx);
                if matches!(f.kind, crate::forms::Kind::Secret) {
                    e.update(cx, |v, cx| v.set_masked(true, window, cx));
                }
                (f.key, e)
            })
            .collect::<Vec<_>>();
        let documents = std::array::from_fn(|_| {
            cx.new(|cx| {
                TextareaState::new(window, cx)
                    .soft_wrap(false)
                    .placeholder(language.t(Text::PasteCurrentJSON))
                    .rows(6)
            })
        });
        let search_key = key.clone();
        let mut subscriptions =
            vec![
                cx.subscribe_in(&target_search, window, move |this, _, event, _, cx| {
                    if matches!(event, InputEvent::Change) {
                        if let Some(d) = this.drafts.get_mut(&search_key) {
                            d.target_page = 0;
                        }
                        cx.notify();
                    }
                }),
            ];
        for input in [&id, &asset]
            .into_iter()
            .chain(fields.iter().map(|(_, e)| e))
        {
            let key = key.clone();
            subscriptions.push(
                cx.subscribe_in(input, window, move |this, _, event, _, cx| {
                    if matches!(event, InputEvent::Change) {
                        this.invalidate_draft(&key, cx)
                    }
                }),
            );
        }
        for (slot, input) in documents.iter().enumerate() {
            let key = key.clone();
            subscriptions.push(
                cx.subscribe_in(input, window, move |this, _, event, _, cx| {
                    if matches!(event, InputEvent::Change) {
                        this.document_changed(&key, slot, cx)
                    }
                }),
            );
        }
        let scroll = gpui_kit::ScrollHandle::new();
        let anchors = ["resource", "asset"]
            .into_iter()
            .chain(form.fields.iter().map(|f| f.key))
            .map(|name| (name, gpui_kit::ScrollAnchor::for_handle(scroll.clone())))
            .collect();
        Self {
            scroll,
            anchors,
            id,
            asset,
            fields,
            documents,
            files: std::array::from_fn(|_| None),
            ckb_units: true,
            advanced_id: false,
            advanced_fields: false,
            target_search,
            target_page: 0,
            discard_pending: false,
            validation_attempted: false,
            document_revision: 0,
            show_document: false,
            restore: None,
            checked_review: None,
            error: None,
            review_stale: false,
            _subscriptions: subscriptions,
        }
    }
}
#[derive(Clone)]
pub struct Record {
    pub page: Page,
    pub row: Row,
}
impl Record {
    pub fn id(&self) -> String {
        let v = &self.row.document;
        if self.page == Page::Watch {
            return format!(
                "{}:{}:{}",
                v["channel_id"], v["created_unix_ms"], v["event"]
            );
        }
        if self.is_batch() {
            return format!(
                "batch:{}",
                v["source_package"]["header_hex"]
                    .as_str()
                    .unwrap_or("missing")
            );
        }
        let key = match self.page {
            Page::Channels => "channel_id",
            Page::Factories => "factory_id",
            Page::Invoices => "invoice_id",
            Page::Peers => "pubkey",
            Page::Recovery if v.get("transaction_hash").is_some() => "transaction_hash",
            Page::Recovery if v.get("package_id").is_some() => "package_id",
            Page::Watch => "channel_id",
            _ => "id",
        };
        v[key]
            .as_str()
            .map(str::to_owned)
            .unwrap_or_else(|| v[key].to_string())
    }
    pub fn is_root(&self) -> bool {
        self.page == Page::Recovery && self.row.document.get("transaction_hash").is_some()
    }
    pub fn is_batch(&self) -> bool {
        self.page == Page::Recovery
            && self.row.document["schema"] == "morph.conditional_batch_package.v2"
    }
    pub fn is_recovery(&self) -> bool {
        self.page == Page::Recovery && self.row.document.get("package_id").is_some()
    }
    pub fn source(&self, lang: Language) -> &'static str {
        if self.is_root() {
            lang.t(Text::FundingTerms)
        } else if self.is_recovery() {
            lang.t(Text::SavedSignedPackage)
        } else if self.is_batch() {
            lang.t(Text::SavedConditionalEvidence)
        } else if self.page == Page::Watch {
            lang.t(Text::ObserverReport)
        } else {
            lang.t(Text::LocalHubRecord)
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Running,
    Done,
    Failed,
    Unknown,
    Stopped,
    Reviewed,
}
impl Status {
    pub fn label(self, l: Language) -> &'static str {
        match self {
            Self::Running => l.t(Text::InProgress),
            Self::Done => l.t(Text::Completed),
            Self::Failed => l.t(Text::NotCompleted),
            Self::Unknown => l.t(Text::OutcomeUnknown),
            Self::Stopped => l.t(Text::StoppedWaiting),
            Self::Reviewed => l.t(Text::ReviewedAfterRefresh),
        }
    }
}
pub struct Activity {
    pub id: u64,
    pub title: String,
    pub resource: String,
    pub status: Status,
    pub detail: String,
    pub started: Instant,
    pub elapsed: Option<std::time::Duration>,
    pub output: Option<Value>,
    pub origin: String,
    pub review: Option<Value>,
    pub output_private: bool,
    pub output_checked: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JobKind {
    Connect,
    Disconnect,
    Refresh,
    Execute(HubOperation),
    Inspect,
    Open,
    Save,
}
pub struct Pending {
    pub kind: JobKind,
    pub activity: Option<u64>,
    pub background: bool,
    pub draft: Option<DraftKey>,
    pub candidate: Option<Value>,
    pub previous_roots: Vec<String>,
    pub target: Option<DocumentTarget>,
    pub file_name: String,
    pub endpoint: String,
    pub origin_node: String,
    pub inspector_revision: Option<u64>,
    pub draft_revision: Option<(gpui_kit::EntityId, u64)>,
    pub follow_up: Option<(Page, String)>,
    pub connection_generation: u64,
}
#[derive(Clone)]
pub enum DocumentTarget {
    Inspector(usize),
    Draft(DraftKey, usize),
}
pub struct Prepared {
    pub revision: u64,
    pub operation: HubOperation,
    pub id: String,
    pub body: Value,
    pub event_id: u64,
    pub generation: u64,
    pub key: DraftKey,
    pub endpoint: String,
}
#[derive(Clone, Copy)]
pub enum Domain {
    Payments,
    Evidence,
    Funding,
    Workspace,
    Peers,
}
impl Domain {
    pub const ALL: [Self; 5] = [
        Self::Payments,
        Self::Evidence,
        Self::Funding,
        Self::Peers,
        Self::Workspace,
    ];
    pub fn label(self, l: Language) -> &'static str {
        match self {
            Self::Payments => l.t(Text::PaymentsInvoices),
            Self::Evidence => l.t(Text::EvidenceRecovery),
            Self::Funding => l.t(Text::FundingCeremony),
            Self::Workspace => l.t(Text::WorkspaceRestore),
            Self::Peers => l.t(Text::Peers),
        }
    }
    pub fn contains(self, op: HubOperation) -> bool {
        use HubOperation::*;
        match self {
            Self::Payments => matches!(
                op,
                CreateInvoice | DecodeInvoice | SettleInvoice | ReceiveInvoice
            ),
            Self::Evidence => matches!(op, ImportRecovery | ExportRecovery | ImportBatch),
            Self::Funding => matches!(
                op,
                ImportRoot | InspectRoot | RootExitSignature | RootCreationSignature | ExportRoot
            ),
            Self::Workspace => matches!(
                op,
                ExportState
                    | PreviewRestore
                    | Restore
                    | OpenChannel
                    | SpliceChannel
                    | PublishChannel
                    | FinaliseChannel
                    | OpenFactory
                    | AdvanceFactory
                    | MaterialiseChild
            ),
            Self::Peers => op == Peer,
        }
    }
}
pub fn amount_field(key: &str) -> bool {
    matches!(key, "local" | "remote" | "pending" | "amount" | "reserve")
}
pub fn uses_asset(op: HubOperation) -> bool {
    matches!(
        op,
        HubOperation::CreateInvoice
            | HubOperation::OpenChannel
            | HubOperation::OpenFactory
            | HubOperation::MaterialiseChild
    )
}
pub fn resource_page(op: HubOperation) -> Option<Page> {
    use HubOperation::*;
    match op {
        SpliceChannel | PublishChannel | FinaliseChannel => Some(Page::Channels),
        AdvanceFactory | MaterialiseChild => Some(Page::Factories),
        SettleInvoice | ReceiveInvoice => Some(Page::Invoices),
        ExportRecovery | InspectRoot | RootExitSignature | RootCreationSignature | ExportRoot => {
            Some(Page::Recovery)
        }
        _ => None,
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum ResultTarget {
    None,
    Inspector(u64),
    Draft(DraftKey),
    Record(Page, String),
    Activity(u64),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActivityFilter {
    All,
    Attention,
    Running,
    Completed,
}
impl ActivityFilter {
    pub const ALL: [Self; 4] = [Self::All, Self::Attention, Self::Running, Self::Completed];
    pub fn label(self, l: Language) -> &'static str {
        match self {
            Self::All => l.t(Text::All),
            Self::Attention => l.t(Text::NeedsAttention),
            Self::Running => l.t(Text::InProgress),
            Self::Completed => l.t(Text::Completed),
        }
    }
    pub fn matches(self, status: Status) -> bool {
        match self {
            Self::All => true,
            Self::Attention => matches!(status, Status::Failed | Status::Unknown | Status::Stopped),
            Self::Running => status == Status::Running,
            Self::Completed => matches!(status, Status::Done | Status::Reviewed),
        }
    }
}
