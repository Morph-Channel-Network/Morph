//! Native input and layout contracts; no node, signer, or real funds.
use super::*;
use gpui_kit::{TestAppContext, test::TestWindowExt};

#[gpui_kit::test]
fn navigation_keeps_its_own_bounds_across_pages_languages_and_scales(cx: &mut TestAppContext) {
    for (width, height) in [(780., 580.), (1440., 960.)] {
        let (handle, view) = cx.update(|cx| {
            gpui_kit::init(cx);
            design::install(cx);
            gpui_kit::open_window(
                WindowOptions {
                    window_bounds: Some(WindowBounds::Windowed(Bounds::new(
                        Default::default(),
                        size(px(width), px(height)),
                    ))),
                    ..Default::default()
                },
                cx,
                |w, cx| cx.new(|cx| Desktop::new(w, cx)),
            )
            .unwrap()
        });
        cx.update_window(handle, |_, w, cx| {
            for lang in [Language::English, Language::Chinese] {
                for percent in [90, 100, 150] {
                    view.update(cx, |v, cx| {
                        v.change_scale(0, w, cx);
                        v.change_scale(percent - 100, w, cx);
                        v.set_language(lang, w, cx);
                        v.set_reduced_motion(true, cx);
                        v.navigate(Page::Overview, w, cx);
                    });
                    w.render_frame(cx);
                    let original = (0_usize..7)
                        .map(|i| w.find(("nav", i)).bounds())
                        .collect::<Vec<_>>();
                    let logo = w.find("brand-mark").bounds();
                    let sidebar = w.find("navigation-scroll").bounds();
                    assert!(logo.left() >= sidebar.left() && logo.right() <= sidebar.right());
                    assert!(
                        logo.size.width >= px(48.),
                        "brand remains readable at minimum scale"
                    );
                    let content = w.find("page-surface").bounds();
                    for page in [
                        Page::Wallet,
                        Page::Channels,
                        Page::Factories,
                        Page::Invoices,
                        Page::Recovery,
                        Page::Events,
                        Page::Watch,
                        Page::Model,
                        Page::Inspector,
                        Page::Actions,
                        Page::Search,
                        Page::Overview,
                    ] {
                        view.update(cx, |v, cx| v.navigate(page, w, cx));
                        w.render_frame(cx);
                        assert_eq!(
                            content,
                            w.find("page-surface").bounds(),
                            "page frame shifted: {page:?} {lang:?} {percent}%"
                        );
                        for (i, bounds) in original.iter().enumerate() {
                            assert_eq!(
                                *bounds,
                                w.find(("nav", i)).bounds(),
                                "selection moved a navigation hitbox"
                            );
                        }
                    }
                }
            }
        })
        .unwrap();
    }
}

#[gpui_kit::test]
fn settings_segments_support_keyboard_and_task_search_opens_only_a_draft(cx: &mut TestAppContext) {
    let (handle, view) = cx.update(|cx| {
        gpui_kit::init(cx);
        design::install(cx);
        views::install_shortcuts(cx);
        gpui_kit::open_window(WindowOptions::default(), cx, |w, cx| {
            cx.new(|cx| Desktop::new(w, cx))
        })
        .unwrap()
    });
    cx.update_window(handle, |_, w, cx| {
        view.update(cx, |v, cx| {
            v.set_language(Language::English, w, cx);
            v.set_reduced_motion(true, cx);
            v.navigate(Page::Model, w, cx);
        });
        w.render_frame(cx);
        w.click(("settings-tabs", 0_usize), cx);
        let before = w.find(("settings-tabs", 1_usize)).bounds();
        w.press("right", cx);
        assert!(view.read(cx).appearance_settings);
        assert_eq!(before, w.find(("settings-tabs", 1_usize)).bounds());
        w.press("home", cx);
        assert!(!view.read(cx).appearance_settings);
        w.press("end", cx);
        assert!(view.read(cx).appearance_settings);
        w.press("ctrl-n", cx);
        assert_eq!(view.read(cx).page, Page::Actions);
        assert!(
            view.read(cx)
                .task_search
                .read(cx)
                .focus_handle(cx)
                .is_focused(w)
        );
        w.input("invoice", cx);
        let i = forms::FORMS
            .iter()
            .position(|f| f.operation == HubOperation::CreateInvoice)
            .unwrap();
        w.click(("workflow-match", i), cx);
        let key = view.read(cx).active.clone().unwrap();
        assert_eq!(key.form, i);
        assert!(view.read(cx).prepared.is_none());
        assert!(view.read(cx).network_jobs.is_empty());
        let first = &view.read(cx).drafts[&key].fields[0].1;
        assert!(first.read(cx).focus_handle(cx).is_focused(w));
        view.update(cx, |v, cx| v.set_language(Language::Chinese, w, cx));
        assert_eq!(view.read(cx).active.as_ref(), Some(&key));
    })
    .unwrap();
}

#[test]
fn translated_diagnostics_keep_user_values_and_exact_evidence_intact() {
    let l = Language::Chinese;
    assert_eq!(
        i18n::diagnostic_summary("HTTP 401: private backend detail", l),
        l.t(Text::ErrorUnauthorized)
    );
    assert_eq!(
        i18n::stored_copy("New private file saved · 我的 wallet.json", l),
        format!("{} · 我的 wallet.json", l.t(Text::NewPrivateFileSaved))
    );
    let mut evidence = serde_json::json!({"amount":"340282366920938463463374607431768211455","signature":"private","alias":"Invoice created by morph-core"});
    redact(&mut evidence, l);
    assert_eq!(
        evidence["amount"],
        "340282366920938463463374607431768211455"
    );
    assert_eq!(evidence["alias"], "Invoice created by morph-core");
    assert_eq!(evidence["signature"], l.t(Text::PrivateEvidenceHidden));
}

#[test]
fn every_application_message_is_in_the_live_language_catalog() {
    let source = include_str!("i18n.rs");
    let body = source
        .split("pub enum Text {")
        .nth(1)
        .unwrap()
        .split('}')
        .next()
        .unwrap();
    let expected = body
        .lines()
        .map(str::trim)
        .filter_map(|s| s.strip_suffix(','))
        .map(str::to_owned)
        .collect::<std::collections::BTreeSet<_>>();
    let catalog = Text::ALL
        .iter()
        .map(|key| format!("{key:?}"))
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(expected, catalog);
    assert_eq!(catalog.len(), Text::ALL.len());
    for key in Text::ALL {
        assert!(!Language::English.t(*key).trim().is_empty());
        assert!(!Language::Chinese.t(*key).trim().is_empty());
    }
}

#[gpui_kit::test]
fn review_scrolls_to_the_invalid_field_at_large_type_without_submitting(cx: &mut TestAppContext) {
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
            v.set_reduced_motion(true, cx);
            v.change_scale(0, w, cx);
            v.change_scale(50, w, cx);
            v.state = Some(
                serde_json::from_str(include_str!(
                    "../../../fixtures/hub/unauthenticated-loopback.json"
                ))
                .unwrap(),
            );
            v.connected = true;
            v.last_checked = Some(Instant::now());
            v.start_task(HubOperation::OpenChannel, String::new(), w, cx);
            let draft = &v.drafts[v.active.as_ref().unwrap()];
            for (name, input) in &draft.fields {
                let value = match *name {
                    "channel_id" | "funding_context_id" => format!("0x{}", "11".repeat(32)),
                    "counterparty_pubkey" => format!("02{}", "22".repeat(32)),
                    "sponsor_budget" => "invalid".into(),
                    "local" | "remote" | "pending" => "0".into(),
                    _ => String::new(),
                };
                input.update(cx, |i, cx| i.set_value(value, w, cx));
            }
        });
        w.render_frame(cx);
        let key = view.read(cx).active.clone().unwrap();
        let index = view.read(cx).drafts[&key]
            .fields
            .iter()
            .position(|(name, _)| *name == "sponsor_budget")
            .unwrap();
        let before = w.find(("field-container", index)).bounds();
        assert!(before.top() > w.find("task-edit-scroll").bounds().bottom());
        w.click("review-action", cx);
        w.simulate_next_frame(cx);
        w.render_frame(cx);
        let draft = &view.read(cx).drafts[&key];
        let input = &draft.fields[index].1;
        assert!(input.read(cx).focus_handle(cx).is_focused(w));
        let after = w.find(("field-container", index)).bounds();
        let viewport = w.find("task-edit-scroll").bounds();
        assert!(
            after.top() >= viewport.top() && after.bottom() <= viewport.bottom(),
            "invalid field is clipped: {after:?} in {viewport:?}"
        );
        assert!(view.read(cx).prepared.is_none());
        assert!(view.read(cx).network_jobs.is_empty());
    })
    .unwrap();
}
