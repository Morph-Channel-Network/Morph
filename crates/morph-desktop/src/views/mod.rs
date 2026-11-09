//! Native workspace shell and task-oriented pages. The API/authority layer is unchanged.
use crate::design::{self as d, Tone};
use crate::i18n::{Language, Text};
use crate::presentation as p;
use crate::*;
use gpui_kit::assets::IconName;
use gpui_kit::component::{
    Disableable, Icon, Selectable, Sizable,
    button::{Button, ButtonVariants},
    input::{Input, Textarea},
};
use gpui_kit::{
    AnyElement, Div, Focusable, FontWeight, InteractiveElement, StatefulInteractiveElement, Styled,
    div, img, linear_color_stop, linear_gradient, rgb, uniform_list,
};

gpui_kit::actions!(
    morph_workspace,
    [
        FocusSearch,
        GoHome,
        GoChannels,
        GoFactories,
        RefreshWorkspace,
        OpenTasks,
        CloseDetails,
        IncreaseText,
        DecreaseText,
        ResetText
    ]
);
pub(crate) fn install_shortcuts(cx: &mut App) {
    cx.bind_keys([
        gpui_kit::KeyBinding::new("ctrl-=", IncreaseText, Some("MorphWorkspace")),
        gpui_kit::KeyBinding::new("ctrl-+", IncreaseText, Some("MorphWorkspace")),
        gpui_kit::KeyBinding::new("ctrl--", DecreaseText, Some("MorphWorkspace")),
        gpui_kit::KeyBinding::new("ctrl-0", ResetText, Some("MorphWorkspace")),
        gpui_kit::KeyBinding::new("ctrl-k", FocusSearch, Some("MorphWorkspace")),
        gpui_kit::KeyBinding::new("ctrl-1", GoHome, Some("MorphWorkspace")),
        gpui_kit::KeyBinding::new("ctrl-2", GoChannels, Some("MorphWorkspace")),
        gpui_kit::KeyBinding::new("ctrl-3", GoFactories, Some("MorphWorkspace")),
        gpui_kit::KeyBinding::new("ctrl-r", RefreshWorkspace, Some("MorphWorkspace")),
        gpui_kit::KeyBinding::new("ctrl-n", OpenTasks, Some("MorphWorkspace")),
        gpui_kit::KeyBinding::new("alt-left", CloseDetails, Some("MorphWorkspace")),
    ]);
}
fn page_name(page: Page, l: Language) -> &'static str {
    match page {
        Page::Overview => l.t(Text::Overview),
        Page::Channels => l.t(Text::Channels2),
        Page::Factories => l.t(Text::Factory),
        Page::Invoices => l.t(Text::PaymentsInvoices),
        Page::Recovery => l.t(Text::EvidenceFunding),
        Page::Events => l.t(Text::Activity),
        Page::Peers => l.t(Text::Peers),
        Page::Watch => l.t(Text::Watchtower),
        Page::Model => l.t(Text::Settings),
        Page::Actions => l.t(Text::Tasks2),
        Page::Inspector => l.t(Text::EvidenceTools),
        Page::Search => l.t(Text::SearchWorkspace),
    }
}
fn page_icon(page: Page) -> IconName {
    match page {
        Page::Overview => IconName::LayoutDashboard,
        Page::Channels => IconName::ArrowLeftRight,
        Page::Factories => IconName::Layers,
        Page::Invoices => IconName::Wallet,
        Page::Recovery => IconName::FolderOpen,
        Page::Events => IconName::Activity,
        Page::Watch => IconName::Shield,
        Page::Model => IconName::Settings,
        Page::Inspector => IconName::FileSearch,
        Page::Peers => IconName::Users,
        Page::Actions => IconName::Plus,
        Page::Search => IconName::Search,
    }
}
fn status_tone(status: Status) -> Tone {
    match status {
        Status::Running => Tone::Info,
        Status::Done | Status::Reviewed => Tone::Good,
        Status::Failed => Tone::Danger,
        Status::Unknown => Tone::Warning,
        Status::Stopped => Tone::Neutral,
    }
}
pub(crate) fn record_title(r: &Record, l: Language) -> String {
    let v = &r.row.document;
    match r.page {
        Page::Channels => format!(
            "{} · {}",
            if r.row.title.trim().is_empty() {
                l.t(Text::Channel)
            } else {
                &r.row.title
            },
            p::short(v["channel_id"].as_str().unwrap_or(""))
        ),
        Page::Factories => format!(
            "{} · {}",
            l.t(Text::Factory),
            p::short(v["factory_id"].as_str().unwrap_or(""))
        ),
        Page::Invoices => v["description"]
            .as_str()
            .filter(|s| !s.is_empty())
            .unwrap_or(l.t(Text::Invoice))
            .to_owned(),
        Page::Peers => v["alias"]
            .as_str()
            .filter(|v| !v.trim().is_empty())
            .unwrap_or(l.t(Text::Peer))
            .to_owned(),
        Page::Recovery if r.is_root() => {
            format!("{} · {}", l.t(Text::FundingCeremony), p::short(&r.id()))
        }
        Page::Recovery if r.is_recovery() => format!(
            "{} · {}",
            l.t(Text::Recovery),
            p::short(v["channel_id"].as_str().unwrap_or(""))
        ),
        Page::Recovery if r.is_batch() => l.t(Text::ConditionalSettlementEvidence).into(),
        Page::Watch => watch_label(v["event"].as_str().unwrap_or(""), l).to_owned(),
        Page::Events => format!(
            "#{} · {}",
            v["id"],
            p::event_name(v["event"].as_str().unwrap_or(""), l)
        ),
        _ => r.row.title.clone(),
    }
}
pub(crate) fn record_subtitle(r: &Record, l: Language) -> String {
    let v = &r.row.document;
    match r.page {
        Page::Channels => format!(
            "{} · {} {} · {} {}",
            p::human_state(v["phase"].as_str().unwrap_or(""), l),
            l.t(Text::FundingEpoch),
            v["funding_epoch"],
            l.t(Text::State),
            v["state_number"]
        ),
        Page::Factories => format!(
            "{} {} · {} {}",
            v["participant_pubkeys"].as_array().map_or(0, Vec::len),
            l.t(Text::Members),
            l.t(Text::Update),
            v["update_number"]
        ),
        Page::Invoices => {
            let (asset, ckb) = p::json_asset(&v["asset"], l);
            format!(
                "{} · {} · {}",
                p::amount(v["amount"].as_str().unwrap_or("0"), ckb, l),
                asset,
                p::human_state(v["status"].as_str().unwrap_or(""), l)
            )
        }
        Page::Recovery if r.is_root() => format!(
            "{} {} / 2 · {} {} / 2",
            l.t(Text::Exits),
            v["exit_signature_count"],
            l.t(Text::Creation2),
            v["creation_signature_count"]
        ),
        Page::Recovery if r.is_recovery() => format!(
            "{} {} · {} {}",
            l.t(Text::State),
            v["state_number"].as_str().unwrap_or(""),
            l.t(Text::VaultCount),
            v["vault_count"]
        ),
        _ => r.row.subtitle.clone(),
    }
}
fn title_row(title: &str, description: &str) -> Div {
    div()
        .flex()
        .flex_col()
        .gap_2()
        .pb_4()
        .child(d::title(title.to_owned()))
        .child(d::caption(description.to_owned()))
}
fn empty_state(icon: IconName, title: &str, description: &str) -> Div {
    d::panel()
        .flex()
        .flex_col()
        .gap_4()
        .items_center()
        .justify_center()
        .py_12()
        .child(Icon::new(icon).size(px(30.)).text_color(rgb(d::DIM)))
        .child(
            div()
                .text_lg()
                .font_weight(FontWeight::SEMIBOLD)
                .child(title.to_owned()),
        )
        .child(d::caption(description.to_owned()))
}

mod activity;
mod evidence;
mod overview;
mod records;
mod settings;
mod shell;
mod tasks;
mod tools;

fn form_requires_target(op: HubOperation) -> bool {
    workspace::resource_page(op).is_some()
}

fn watch_label(event: &str, l: Language) -> &str {
    match event {
        "chain_reorg_detected" => l.t(Text::ChainReorganisationObserved),
        "recovery_data_invalid" => l.t(Text::RecoveryEvidenceNeedsAttention),
        "publication_failed" => l.t(Text::PublicationFailed),
        "older_state_detected" => l.t(Text::OlderStateObserved),
        "publication_submitted" => l.t(Text::PublicationSubmitted),
        "splice_detected" => l.t(Text::SpliceObserved),
        "splice_package_stale" => l.t(Text::SavedSpliceEvidenceIsStale),
        "splice_publication_submitted" => l.t(Text::SplicePublicationSubmitted),
        "scan_idle" => l.t(Text::ScanCompleted),
        _ => event,
    }
}

fn record_balance_hint(r: &Record, l: Language) -> Option<String> {
    let balances = r
        .row
        .document
        .get("balances")
        .or_else(|| r.row.document.get("reserve_balances"))?
        .as_array()?;
    let first = balances.first()?;
    let (asset, ckb) = p::json_asset(&first["asset"], l);
    let local = p::amount(first["local"].as_str()?, ckb, l);
    let remote = p::amount(first["remote"].as_str()?, ckb, l);
    Some(format!(
        "{} · {} {} · {} {}{}",
        asset,
        l.t(Text::Local2),
        local,
        l.t(Text::Remote2),
        remote,
        if balances.len() > 1 {
            format!(" · +{} {}", balances.len() - 1, l.t(Text::AssetTypes))
        } else {
            String::new()
        }
    ))
}
