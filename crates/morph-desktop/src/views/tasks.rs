use super::*;
use gpui_kit::TestSupportExt;

impl Desktop {
    pub(super) fn render_tasks(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
        wide: bool,
    ) -> AnyElement {
        if let Some(key) = self.active.clone() {
            return self
                .render_task_editor(key, window, cx, wide)
                .into_any_element();
        }
        let mut view = div()
            .id("catalog-scroll")
            .flex_1()
            .min_h_0()
            .overflow_y_scroll()
            .flex()
            .flex_col()
            .gap_5()
            .child(title_row(
                self.t(Text::StartWithATask),
                self.t(Text::ChooseAWorkflowObjectSpecificActions),
            ));
        view = view.child(
            Input::new(&self.task_search)
                .id("workflow-search")
                .cleanable(true),
        );
        let query = self.task_search.read(cx).value().trim().to_lowercase();
        if !query.is_empty() {
            let matches = forms::FORMS
                .iter()
                .enumerate()
                .filter(|(_, form)| {
                    let text = format!(
                        "{} {}",
                        operation_title(form.operation, self.language),
                        p::operation_help(form.operation, self.language)
                    )
                    .to_lowercase();
                    query.split_whitespace().all(|part| text.contains(part))
                })
                .collect::<Vec<_>>();
            if matches.is_empty() {
                view = view.child(empty_state(
                    IconName::Search,
                    self.t(Text::NoMatchingWorkflows),
                    self.t(Text::SearchWorkflows),
                ));
            }
            for (i, form) in matches {
                let op = form.operation;
                view = view.child(
                    Button::new(("workflow-match", i))
                        .ghost()
                        .h_auto()
                        .p_4()
                        .justify_start()
                        .bg(rgb(d::PANEL))
                        .rounded_lg()
                        .border_1()
                        .border_color(rgb(d::BORDER))
                        .accessibility_label(operation_title(op, self.language))
                        .child(
                            div()
                                .flex()
                                .flex_col()
                                .gap_2()
                                .whitespace_normal()
                                .items_start()
                                .child(
                                    div()
                                        .font_weight(FontWeight::SEMIBOLD)
                                        .child(operation_title(op, self.language)),
                                )
                                .child(d::caption(p::operation_help(op, self.language))),
                        )
                        .on_click(cx.listener(move |this, _, window, cx| {
                            this.start_task(op, String::new(), window, cx)
                        })),
                );
            }
            return view.into_any_element();
        }
        if !self.drafts.is_empty() {
            let mut card = d::panel()
                .flex()
                .flex_col()
                .gap_3()
                .child(div().text_lg().child(self.t(Text::YourDrafts)));
            let keys = self.drafts.keys().cloned().collect::<Vec<_>>();
            for (i, key) in keys.into_iter().enumerate() {
                let title = format!(
                    "{}  {}",
                    operation_title(forms::FORMS[key.form].operation, self.language),
                    p::short(&key.resource)
                );
                card = card.child(
                    Button::new(("resume-draft", i))
                        .label(title)
                        .justify_start()
                        .on_click(cx.listener(move |this, _, _, cx| {
                            this.active = Some(key.clone());
                            this.prepared = None;
                            cx.notify()
                        })),
                );
            }
            view = view.child(card);
        }
        if let Some(index) = self.task_domain {
            let domain = Domain::ALL[index];
            view = view.child(
                Button::new("back-task-domains")
                    .icon(IconName::ArrowLeft)
                    .ghost()
                    .label(self.t(Text::AllTaskAreas))
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.task_domain = None;
                        cx.notify()
                    })),
            );
            let mut card = d::panel()
                .flex()
                .flex_col()
                .gap_4()
                .child(
                    div()
                        .text_lg()
                        .font_weight(FontWeight::SEMIBOLD)
                        .child(domain.label(self.language)),
                )
                .child(d::caption(domain_description(domain, self.language)));
            for (i, form) in forms::FORMS
                .iter()
                .enumerate()
                .filter(|(_, f)| domain.contains(f.operation))
            {
                let op = form.operation;
                card = card.child(d::rule()).child(
                    div()
                        .flex()
                        .gap_4()
                        .items_center()
                        .child(
                            div()
                                .flex_1()
                                .min_w_0()
                                .child(operation_title(op, self.language)),
                        )
                        .child(
                            Button::new(("catalog-task", i))
                                .icon(IconName::ArrowRight)
                                .label(self.t(Text::Start))
                                .accessibility_label(operation_title(op, self.language))
                                .on_click(cx.listener(move |this, _, window, cx| {
                                    this.start_task(op, String::new(), window, cx)
                                })),
                        ),
                );
            }
            view = view.child(card);
        } else {
            let animated = self.motion_enabled(window, cx);
            for chunk in (0..Domain::ALL.len())
                .collect::<Vec<_>>()
                .chunks(if wide { 3 } else { 2 })
            {
                let mut row = div().flex().gap_4();
                for index in chunk {
                    let index = *index;
                    let domain = Domain::ALL[index];
                    let icon = match domain {
                        Domain::Payments => IconName::Wallet,
                        Domain::Evidence => IconName::FolderOpen,
                        Domain::Funding => IconName::FileCheck,
                        Domain::Peers => IconName::Users,
                        Domain::Workspace => IconName::Settings,
                    };
                    let tile = Button::new(("task-area", index))
                        .ghost()
                        .accessibility_label(domain.label(self.language))
                        .h_auto()
                        .min_h(px(130. * self.scale()))
                        .p_5()
                        .rounded(px(14.))
                        .flex_1()
                        .min_w_0()
                        .border_1()
                        .border_color(rgb(d::BORDER))
                        .bg(rgb(d::PANEL))
                        .child(
                            div()
                                .w_full()
                                .whitespace_normal()
                                .flex()
                                .flex_col()
                                .items_start()
                                .gap_3()
                                .child(
                                    div()
                                        .w_full()
                                        .flex()
                                        .justify_between()
                                        .items_center()
                                        .child(d::icon_tile(icon))
                                        .child(
                                            Icon::new(IconName::ArrowUpRight)
                                                .text_color(rgb(d::DIM)),
                                        ),
                                )
                                .child(
                                    div()
                                        .font_weight(FontWeight::MEDIUM)
                                        .child(domain.label(self.language)),
                                )
                                .child(d::caption(domain_description(domain, self.language))),
                        )
                        .on_click(cx.listener(move |this, _, _, cx| {
                            this.motion_generation = this.motion_generation.wrapping_add(1);
                            this.page_enter_started = Instant::now();
                            this.task_domain = Some(index);
                            cx.notify()
                        }));
                    row = row.child(div().flex_1().min_w_0().child(crate::motion::interactive(
                        tile.w_full(),
                        ("task-area", index),
                        animated,
                        window,
                        cx,
                    )));
                }
                for _ in chunk.len()..if wide { 3 } else { 2 } {
                    row = row.child(div().flex_1());
                }
                view = view.child(row);
            }
        }
        view.into_any_element()
    }

    pub(super) fn render_task_editor(
        &mut self,
        key: DraftKey,
        window: &mut Window,
        cx: &mut Context<Self>,
        wide: bool,
    ) -> Div {
        let form = forms::FORMS[key.form];
        let op = form.operation;
        let discard_pending = self.drafts.get(&key).is_some_and(|d| d.discard_pending);
        let discard_key = key.clone();
        let head = div()
            .flex()
            .flex_wrap()
            .gap_3()
            .items_center()
            .pb_4()
            .child(
                Button::new("retain-draft")
                    .icon(IconName::ArrowLeft)
                    .ghost()
                    .label(self.t(Text::KeepDraftBack))
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.active = None;
                        this.prepared = None;
                        cx.notify()
                    })),
            )
            .child(div().flex_1())
            .child(
                Button::new("discard-draft")
                    .icon(IconName::Trash)
                    .ghost()
                    .label(if discard_pending {
                        self.t(Text::ConfirmDiscard)
                    } else {
                        self.t(Text::DiscardDraft)
                    })
                    .on_click(cx.listener(move |this, _, _, cx| {
                        if discard_pending {
                            this.discard_active(cx)
                        } else if let Some(d) = this.drafts.get_mut(&discard_key) {
                            d.discard_pending = true;
                            cx.notify();
                        }
                    })),
            );
        let mut view = div().flex_1().min_h_0().flex().flex_col().child(head);
        if discard_pending {
            let cancel_key = key.clone();
            view = view.child(
                div()
                    .mb_4()
                    .flex()
                    .flex_wrap()
                    .gap_3()
                    .items_center()
                    .child(d::caption(self.t(Text::DiscardRemovesThisInMemoryDraft)).flex_1())
                    .child(
                        Button::new("keep-draft-instead")
                            .small()
                            .label(self.t(Text::KeepEditing))
                            .on_click(cx.listener(move |this, _, _, cx| {
                                if let Some(d) = this.drafts.get_mut(&cancel_key) {
                                    d.discard_pending = false;
                                }
                                cx.notify();
                            })),
                    ),
            );
        }
        let review = self.prepared.as_ref().is_some_and(|p| p.key == key);
        if review {
            let contents = self.render_review(&key, window, cx);
            return view
                .child(
                    div()
                        .id("task-review-scroll")
                        .flex_1()
                        .min_h_0()
                        .overflow_y_scroll()
                        .child(d::workbench(contents, 760. * self.scale())),
                )
                .child(d::workbench(
                    self.render_task_footer(&key, true, cx),
                    760. * self.scale(),
                ));
        }
        if self.result.is_some() && self.result_target == ResultTarget::Draft(key.clone()) {
            return view
                .child(
                    div()
                        .id("completed-task-scroll")
                        .flex_1()
                        .min_h_0()
                        .overflow_y_scroll()
                        .child(self.render_result_card(cx)),
                )
                .child(
                    div().pt_4().child(
                        Button::new("edit-completed-task")
                            .icon(IconName::ArrowLeft)
                            .label(self.t(Text::BackToInputs))
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.result_target = ResultTarget::None;
                                this.prepared = None;
                                cx.notify();
                            })),
                    ),
                );
        }
        let Some(draft) = self.drafts.get(&key) else {
            return view;
        };
        let scroll = draft.scroll.clone();
        let anchors = draft.anchors.clone();
        let id = draft.id.clone();
        let asset = draft.asset.clone();
        let fields = draft.fields.clone();
        let ckb_units = draft.ckb_units;
        let advanced_id = draft.advanced_id;
        let advanced_fields = draft.advanced_fields;
        let show_document = draft.show_document;
        let document = draft.documents[0].clone();
        let file = draft.files[0].clone();
        let plan = draft.restore.clone();
        let error = draft.error.clone();
        let review_stale = draft.review_stale;
        let issues = if draft.validation_attempted {
            self.draft_issues(&key, cx)
        } else {
            BTreeMap::new()
        };
        let mut editor = d::panel()
            .flex_1()
            .min_w_0()
            .flex()
            .flex_col()
            .gap_4()
            .child(title_row(
                operation_title(op, self.language),
                p::operation_help(op, self.language),
            ));
        if review_stale {
            editor = editor.child(d::badge(
                self.t(Text::DraftChangedReviewAgain),
                Tone::Warning,
            ));
        }
        if let Some(error) = error {
            editor = editor.child(self.diagnostic("draft-error", error, window, cx));
        }
        if form.needs_id {
            if !key.resource.is_empty() {
                editor = editor
                    .child(self.copyable_fact(
                        700,
                        self.t(Text::BoundObject),
                        key.resource.clone(),
                        cx,
                    ))
                    .child(
                        Button::new("change-task-object")
                            .ghost()
                            .small()
                            .label(self.t(Text::ChooseAnotherObject))
                            .on_click(cx.listener(move |this, _, window, cx| {
                                this.start_task(op, String::new(), window, cx)
                            })),
                    );
            } else {
                if !advanced_id {
                    editor = editor.child(self.render_resource_picker(op, cx));
                }
                if advanced_id {
                    editor = editor.child(d::caption(self.t(Text::ExactObjectID))).child(
                        div()
                            .id("resource-anchor")
                            .anchor_scroll(anchors.get("resource").cloned())
                            .child(Input::new(&id).id("resource-id")),
                    );
                    if let Some(issue) = issues.get("resource") {
                        editor = editor.child(d::caption(issue.clone()).text_color(rgb(d::DANGER)));
                    }
                }
                let k = key.clone();
                editor = editor.child(
                    Button::new("toggle-manual-id")
                        .ghost()
                        .small()
                        .label(if advanced_id {
                            self.t(Text::HideManualIDInput)
                        } else {
                            self.t(Text::AdvancedEnterAnObjectID)
                        })
                        .on_click(cx.listener(move |this, _, _, cx| {
                            if let Some(d) = this.drafts.get_mut(&k) {
                                d.advanced_id = !d.advanced_id
                            }
                            this.prepared = None;
                            cx.notify()
                        })),
                );
            }
        }
        if form.needs_id && key.resource.is_empty() && !advanced_id {
            return view
                .child(
                    div()
                        .id("task-target-scroll")
                        .flex_1()
                        .min_h_0()
                        .overflow_y_scroll()
                        .child(editor),
                )
                .child(self.render_task_footer(&key, false, cx));
        }
        if op == HubOperation::Restore && plan.is_none() {
            return view
                .child(empty_state(
                    IconName::ShieldAlert,
                    self.t(Text::AnExactRestorePreviewIsRequired),
                    self.t(Text::PreviewTheCandidateWorkspaceBeforeConfirming),
                ))
                .child(
                    Button::new("start-restore-preview")
                        .label(self.t(Text::PreviewAWorkspace))
                        .on_click(cx.listener(|this, _, window, cx| {
                            this.start_task(HubOperation::PreviewRestore, String::new(), window, cx)
                        })),
                );
        }
        if workspace::uses_asset(op) {
            let ckb = asset.read(cx).value().trim().is_empty();
            let ka = key.clone();
            let kb = key.clone();
            editor = editor
                .child(
                    div()
                        .font_weight(FontWeight::MEDIUM)
                        .child(self.t(Text::AssetUnits)),
                )
                .child(
                    div()
                        .flex()
                        .gap_2()
                        .child(
                            Button::new("choose-ckb")
                                .label("CKB")
                                .selected(ckb)
                                .on_click(cx.listener(move |this, _, window, cx| {
                                    if let Some(d) = this.drafts.get(&ka) {
                                        d.asset.update(cx, |v, cx| v.set_value("", window, cx));
                                    }
                                })),
                        )
                        .child(
                            Button::new("choose-xudt")
                                .label("xUDT")
                                .selected(!ckb)
                                .on_click(cx.listener(move |this, _, window, cx| {
                                    if let Some(d) = this.drafts.get(&kb)
                                        && d.asset.read(cx).value().is_empty()
                                    {
                                        d.asset.update(cx, |v, cx| v.set_value("0x", window, cx));
                                    }
                                })),
                        ),
                );
            if !ckb {
                editor = editor
                    .child(d::caption(
                        self.t(Text::CanonicalTypeHashUnknownTokenPrecision),
                    ))
                    .child(
                        div()
                            .id("asset-anchor")
                            .anchor_scroll(anchors.get("asset").cloned())
                            .child(Input::new(&asset).id("asset-type")),
                    );
                if let Some(issue) = issues.get("asset") {
                    editor = editor.child(d::caption(issue.clone()).text_color(rgb(d::DANGER)));
                }
                let known = self.known_assets();
                if !known.is_empty() {
                    let mut chips = div().flex().flex_wrap().gap_2();
                    for (i, hash) in known.into_iter().enumerate() {
                        let key = key.clone();
                        chips = chips.child(
                            Button::new(("known-type", i))
                                .small()
                                .label(p::short(&hash))
                                .tooltip(hash.clone())
                                .on_click(cx.listener(move |this, _, window, cx| {
                                    if let Some(d) = this.drafts.get(&key) {
                                        d.asset.update(cx, |v, cx| {
                                            v.set_value(hash.clone(), window, cx)
                                        });
                                    }
                                })),
                        );
                    }
                    editor = editor.child(chips);
                }
            } else {
                let k = key.clone();
                editor = editor.child(
                    Button::new("amount-unit-toggle")
                        .ghost()
                        .small()
                        .label(if ckb_units {
                            self.t(Text::InputCKBSwitchToShannons)
                        } else {
                            self.t(Text::InputShannonsSwitchToCKB)
                        })
                        .on_click(cx.listener(move |this, _, window, cx| {
                            this.toggle_amount_units(&k, window, cx)
                        })),
                );
            }
        }
        if op == HubOperation::CreateInvoice {
            editor = editor.child(d::caption(self.t(Text::InvoiceAutomatic)));
            let saved = fields
                .iter()
                .any(|(k, v)| *k == "payment_preimage" && !v.read(cx).value().is_empty());
            editor = editor.child(d::caption(self.t(if saved {
                Text::InvoiceSecretSaved
            } else {
                Text::InvoiceWalletRequired
            })));
            if !saved {
                editor = editor.child(
                    Button::new("invoice-open-wallet")
                        .label(self.t(Text::OpenLocalWallet))
                        .on_click(cx.listener(|this, _, w, cx| this.navigate(Page::Wallet, w, cx))),
                );
            }
            let toggle_key = key.clone();
            editor = editor.child(
                Button::new("task-advanced-options")
                    .ghost()
                    .small()
                    .label(self.t(if advanced_fields {
                        Text::HideAdvancedOptions
                    } else {
                        Text::AdvancedOptions
                    }))
                    .on_click(cx.listener(move |this, _, _, cx| {
                        if let Some(d) = this.drafts.get_mut(&toggle_key) {
                            d.advanced_fields = !d.advanced_fields;
                        }
                        cx.notify();
                    })),
            );
        }
        for (field_index, (name, input)) in fields.iter().enumerate() {
            if op == HubOperation::CreateInvoice
                && matches!(
                    *name,
                    "payment_preimage" | "payment_hash" | "expiry_secs" | "channel_id"
                )
                && !advanced_fields
            {
                continue;
            }
            if op == HubOperation::CreateInvoice && *name == "payment_preimage" {
                continue;
            }
            let meta = form.fields.iter().find(|f| f.key == *name);
            let fallback = meta.map_or(Text::Task, |m| m.label);
            let label = p::field_label(name, fallback, self.language);
            let mut field = div()
                .flex()
                .flex_col()
                .gap_2()
                .child(div().font_weight(FontWeight::MEDIUM).child(label))
                .child(Input::new(input).id(*name));
            if let Some(issue) = issues.get(name) {
                field = field.child(d::caption(issue.clone()).text_color(rgb(d::DANGER)));
            }
            let raw = input.read(cx).value();
            if workspace::amount_field(name) {
                let ckb = asset.read(cx).value().trim().is_empty();
                let helper = if ckb && ckb_units {
                    match p::decimal_to_shannons(&raw) {
                        Ok(base) => format!("{} shannons", base),
                        Err(_) => self.t(Text::UseANonnegativeDecimalUpTo).into(),
                    }
                } else if ckb {
                    p::amount(&raw, true, self.language)
                } else {
                    self.t(Text::IntegerBaseUnitsTokenPrecisionIs).into()
                };
                field = field.child(d::caption(helper));
            } else if *name == "sponsor_budget" {
                field = field.child(d::caption(p::amount(&raw, true, self.language)));
            } else if op == HubOperation::CreateInvoice && *name == "payment_hash" {
                field = field.child(d::caption(self.t(Text::InvoiceSecretModeHelp)));
            } else if *name == "payment_preimage" {
                field = field.child(d::caption(self.t(Text::KeptInMemoryForInvoiceCreation)));
            }
            if *name == "counterparty_pubkey"
                && let Some(state) = &self.state
            {
                let mut peers = div().flex().flex_wrap().gap_2();
                for (i, peer) in state.peers.iter().take(24).enumerate() {
                    let v = serde_json::to_value(peer).unwrap_or_default();
                    if let Some(pubkey) = v["pubkey"].as_str() {
                        let public = pubkey.to_owned();
                        let alias = v["alias"].as_str().unwrap_or("").to_owned();
                        let k = key.clone();
                        peers = peers.child(
                            Button::new(("known-peer", i))
                                .small()
                                .label(if alias.is_empty() {
                                    p::short(&public)
                                } else {
                                    alias.clone()
                                })
                                .on_click(cx.listener(move |this, _, w, cx| {
                                    if let Some(d) = this.drafts.get(&k) {
                                        for (name, input) in &d.fields {
                                            if *name == "counterparty_pubkey" {
                                                input.update(cx, |v, cx| {
                                                    v.set_value(public.clone(), w, cx)
                                                });
                                            } else if *name == "counterparty_alias" {
                                                input.update(cx, |v, cx| {
                                                    v.set_value(alias.clone(), w, cx)
                                                });
                                            }
                                        }
                                    }
                                })),
                        );
                    }
                }
                field = field.child(peers);
            }
            if op == HubOperation::CreateInvoice
                && *name == "channel_id"
                && let Some(state) = &self.state
            {
                let mut channels = div().flex().flex_wrap().gap_2();
                for (i, channel) in state.channels.iter().take(24).enumerate() {
                    let v = serde_json::to_value(channel).unwrap_or_default();
                    if let Some(id) = v["channel_id"].as_str() {
                        let value = id.to_owned();
                        let target = input.clone();
                        channels = channels.child(
                            Button::new(("invoice-channel", i))
                                .small()
                                .label(p::short(id))
                                .on_click(move |_, w, cx| {
                                    target.update(cx, |v, cx| v.set_value(value.clone(), w, cx));
                                }),
                        );
                    }
                }
                field = field.child(channels);
            }
            editor = editor.child(
                div()
                    .id(("field-container", field_index))
                    .anchor_scroll(anchors.get(name).cloned())
                    .child(field)
                    .test_support(),
            );
        }
        if form.document && op != HubOperation::Restore {
            let target = DocumentTarget::Draft(key.clone(), 0);
            let k = key.clone();
            let mut filecard = div()
                .border_1()
                .border_color(rgb(d::BORDER))
                .rounded_lg()
                .p_4()
                .flex()
                .flex_col()
                .gap_3()
                .child(div().font_weight(FontWeight::MEDIUM).child(
                    if op == HubOperation::PreviewRestore {
                        self.t(Text::CandidateWorkspace)
                    } else {
                        self.t(Text::EvidenceDocument)
                    },
                ));
            if let Some(info) = file {
                filecard = filecard
                    .child(div().child(info.name))
                    .child(d::caption(format!(
                        "{} · {} {}",
                        info.schema,
                        info.bytes,
                        self.t(Text::Bytes)
                    )))
                    .child(d::badge(self.t(Text::LoadedNotYetSubmitted), Tone::Neutral));
            } else {
                filecard = filecard.child(d::caption(self.t(Text::ChooseAJSONFileOrPaste)));
            }
            let clear_key = key.clone();
            filecard = filecard.child(
                div()
                    .flex()
                    .flex_wrap()
                    .gap_3()
                    .child(
                        Button::new("open-operation-json")
                            .icon(IconName::FolderOpen)
                            .label(self.t(Text::ChooseJSONFile))
                            .disabled(self.file_busy() || self.dialog_pending)
                            .on_click(cx.listener(move |this, _, _, cx| {
                                this.open_file(target.clone(), cx)
                            })),
                    )
                    .child(
                        Button::new("paste-operation-json")
                            .ghost()
                            .label(if show_document {
                                self.t(Text::HideEditor)
                            } else {
                                self.t(Text::PasteEditJSON)
                            })
                            .on_click(cx.listener(move |this, _, _, cx| {
                                if let Some(d) = this.drafts.get_mut(&k) {
                                    d.show_document = !d.show_document
                                }
                                cx.notify()
                            })),
                    ),
            );
            if !document.read(cx).value().is_empty() {
                filecard = filecard.child(
                    Button::new("clear-operation-document")
                        .ghost()
                        .small()
                        .icon(IconName::X)
                        .label(self.t(Text::RemoveDocument))
                        .on_click(cx.listener(move |this, _, window, cx| {
                            if let Some(d) = this.drafts.get(&clear_key) {
                                d.documents[0].update(cx, |v, cx| v.set_value("", window, cx));
                            }
                            if let Some(d) = this.drafts.get_mut(&clear_key) {
                                d.files[0] = None;
                            }
                            this.invalidate_draft(&clear_key, cx);
                        })),
                );
            }
            if show_document {
                filecard = filecard.child(
                    Textarea::new(&document)
                        .font_family("monospace")
                        .text_size(gpui_kit::rems(13. / 14.))
                        .h(px(230.)),
                );
            }
            editor = editor.child(filecard);
        }
        if let Some(plan) = plan {
            editor = editor.child(self.render_restore_preview(&plan, window, cx));
        }
        let inline_read = !op.mutates() && !form.document;
        if inline_read {
            editor = editor.child(self.render_task_footer(&key, false, cx));
        }
        let body = d::workbench(editor, 760. * self.scale());
        let _ = wide;
        let _ = window;
        view = view.child(
            div()
                .id("task-edit-scroll")
                .track_scroll(&scroll)
                .flex_1()
                .min_h_0()
                .overflow_y_scroll()
                .child(body)
                .test_support(),
        );
        if inline_read {
            view
        } else {
            view.child(d::workbench(
                self.render_task_footer(&key, false, cx),
                760. * self.scale(),
            ))
        }
    }

    pub(super) fn render_task_footer(
        &mut self,
        key: &DraftKey,
        review: bool,
        cx: &mut Context<Self>,
    ) -> Div {
        let op = forms::FORMS[key.form].operation;
        let reason = self.block_reason(op);
        let missing = form_requires_target(op)
            && key.resource.is_empty()
            && self.drafts.get(key).is_some_and(|d| !d.advanced_id);
        let mut footer = div()
            .flex_wrap()
            .pt_4()
            .mt_3()
            .border_t_1()
            .border_color(rgb(d::BORDER))
            .flex()
            .items_center()
            .gap_4()
            .child(
                d::caption(reason.clone().unwrap_or_else(|| {
                    if review {
                        self.t(Text::ConfirmTheExactActionShownAbove).into()
                    } else if missing {
                        self.t(Text::ChooseAnObjectToContinue).into()
                    } else {
                        self.t(Text::YourDraftStaysInMemoryUntil).into()
                    }
                }))
                .flex_1(),
            );
        if self.foreground_busy() {
            footer = footer.child(
                Button::new("stop-current-task")
                    .label(self.t(Text::StopWaiting))
                    .on_click(cx.listener(|this, _, _, cx| this.stop_network(cx))),
            );
        }
        if review {
            footer = footer
                .child(
                    Button::new("edit-reviewed-draft")
                        .label(self.t(Text::EditDraft))
                        .on_click(cx.listener(|this, _, _, cx| {
                            this.prepared = None;
                            cx.notify()
                        })),
                )
                .child(
                    Button::new("confirm-action")
                        .primary()
                        .label(self.t(Text::ConfirmThisAction))
                        .disabled(reason.is_some())
                        .on_click(cx.listener(|this, _, _, cx| this.confirm(cx))),
                );
        } else {
            footer = footer.child(
                Button::new("review-action")
                    .primary()
                    .loading(self.foreground_busy())
                    .label(if op.mutates() {
                        self.t(Text::ReviewAction)
                    } else if op == HubOperation::PreviewRestore {
                        self.t(Text::GenerateExactPreview)
                    } else {
                        self.t(Text::ReadPrepareExport)
                    })
                    .disabled(reason.is_some() || missing)
                    .on_click(cx.listener(|this, _, window, cx| this.prepare(window, cx))),
            );
        }
        footer
    }

    pub(super) fn render_resource_picker(
        &mut self,
        op: HubOperation,
        cx: &mut Context<Self>,
    ) -> Div {
        let mut card = div()
            .rounded_lg()
            .border_1()
            .border_color(rgb(d::BORDER))
            .p_4()
            .flex()
            .flex_col()
            .gap_3()
            .child(
                div()
                    .font_weight(FontWeight::MEDIUM)
                    .child(self.t(Text::ChooseTheObjectForThisTask)),
            );
        let Some(key) = self.active.clone() else {
            return card;
        };
        let Some(draft) = self.drafts.get(&key) else {
            return card;
        };
        let search = draft.target_search.clone();
        let query = search.read(cx).value();
        let tokens = query
            .split_whitespace()
            .map(str::to_lowercase)
            .collect::<Vec<_>>();
        let page = draft.target_page;
        let records = workspace::resource_page(op)
            .and_then(|page| {
                self.state.as_ref().map(|s| {
                    model::rows(s, page)
                        .into_iter()
                        .map(|row| Record { page, row })
                        .filter(|r| {
                            if op == HubOperation::ExportRecovery {
                                r.is_recovery()
                            } else if matches!(
                                op,
                                HubOperation::InspectRoot
                                    | HubOperation::RootExitSignature
                                    | HubOperation::RootCreationSignature
                                    | HubOperation::ExportRoot
                            ) {
                                r.is_root()
                            } else {
                                true
                            }
                        })
                        .collect::<Vec<_>>()
                })
            })
            .unwrap_or_default();
        if records.is_empty() {
            return card.child(d::caption(self.t(Text::NoMatchingObjectIsRegisteredImport)));
        }
        let matching = records
            .into_iter()
            .filter(|r| {
                let text = format!(
                    "{} {} {}",
                    record_title(r, self.language),
                    record_subtitle(r, self.language),
                    r.row.document
                )
                .to_lowercase();
                tokens.iter().all(|t| text.contains(t))
            })
            .collect::<Vec<_>>();
        let count = matching.len();
        let page_count = count.div_ceil(8).max(1);
        let page = page.min(page_count - 1);
        card = card
            .child(Input::new(&search).id("task-target-search").cleanable(true))
            .child(d::caption(format!(
                "{} {} · {} / {}",
                count,
                self.t(Text::Matches),
                page + 1,
                page_count
            )));
        if matching.is_empty() {
            card = card.child(d::caption(self.t(Text::NoMatchTryAnAliasID)));
        }
        for (i, r) in matching.into_iter().skip(page * 8).take(8).enumerate() {
            let title = record_title(&r, self.language);
            card = card.child(
                Button::new(("select-task-resource", i))
                    .accessibility_label(title.clone())
                    .child(
                        div()
                            .w_full()
                            .text_ellipsis()
                            .whitespace_nowrap()
                            .child(title),
                    )
                    .justify_start()
                    .on_click(cx.listener(move |this, _, window, cx| {
                        this.start_for_record(op, r.clone(), window, cx)
                    })),
            );
        }
        if page_count > 1 {
            let previous = key.clone();
            let next = key.clone();
            card = card.child(
                div()
                    .flex()
                    .gap_3()
                    .child(
                        Button::new("target-previous")
                            .label(self.t(Text::Previous))
                            .disabled(page == 0)
                            .on_click(cx.listener(move |this, _, _, cx| {
                                if let Some(d) = this.drafts.get_mut(&previous) {
                                    d.target_page = page.saturating_sub(1);
                                }
                                cx.notify();
                            })),
                    )
                    .child(
                        Button::new("target-next")
                            .label(self.t(Text::Next))
                            .disabled(page + 1 >= page_count)
                            .on_click(cx.listener(move |this, _, _, cx| {
                                if let Some(d) = this.drafts.get_mut(&next) {
                                    d.target_page = page + 1;
                                }
                                cx.notify();
                            })),
                    ),
            );
        }
        card
    }

    pub(super) fn known_assets(&self) -> Vec<String> {
        let Some(s) = &self.state else {
            return Vec::new();
        };
        let mut types = std::collections::BTreeSet::new();
        for b in s
            .channels
            .iter()
            .flat_map(|c| &c.balances)
            .chain(s.factories.iter().flat_map(|f| &f.reserve_balances))
        {
            if let morph_sdk::api::AssetView::Xudt { type_hash } = &b.asset {
                types.insert(type_hash.clone());
            }
        }
        for i in &s.invoices {
            if let morph_sdk::api::AssetView::Xudt { type_hash } = &i.asset {
                types.insert(type_hash.clone());
            }
        }
        types.into_iter().collect()
    }

    pub(super) fn toggle_amount_units(
        &mut self,
        key: &DraftKey,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let Some(d) = self.drafts.get(key) else {
            return;
        };
        let to_base = d.ckb_units;
        let fields = d
            .fields
            .iter()
            .filter(|(k, _)| workspace::amount_field(k))
            .map(|(_, e)| {
                let text = e.read(cx).value();
                let next = if text.trim().is_empty() {
                    Ok(String::new())
                } else if to_base {
                    p::decimal_to_shannons(&text)
                } else {
                    let raw = text.trim();
                    raw.parse::<u128>()
                        .map_err(anyhow::Error::from)
                        .map(|_| p::ckb_decimal(raw))
                };
                (e.clone(), next)
            })
            .collect::<Vec<_>>();
        if fields.iter().any(|(_, r)| r.is_err()) {
            self.inform(
                Tone::Warning,
                self.t(Text::FinishTheAmountFirst),
                self.t(Text::TheUnitCannotChangeWhileAn),
                cx,
            );
            return;
        }
        for (e, value) in fields {
            if let Ok(value) = value {
                e.update(cx, |v, cx| v.set_value(value, window, cx));
            }
        }
        if let Some(d) = self.drafts.get_mut(key) {
            d.ckb_units = !to_base;
        }
        self.invalidate_draft(key, cx)
    }

    pub(super) fn render_review(
        &mut self,
        key: &DraftKey,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Div {
        let Some(prepared) = self.prepared.as_ref() else {
            return d::panel();
        };
        let op = prepared.operation;
        let id = prepared.id.clone();
        let body = prepared.body.clone();
        let endpoint = prepared.endpoint.clone();
        let mut card = d::panel()
            .flex()
            .flex_col()
            .gap_4()
            .child(d::badge(self.t(Text::Label2ReviewExactAction), Tone::Info))
            .child(d::title(operation_title(op, self.language)))
            .child(d::caption(p::operation_help(op, self.language)))
            .child(d::key_value(self.t(Text::Workspace), endpoint));
        if !id.is_empty() {
            card = card.child(self.copyable_fact(800, self.t(Text::Object), id, cx));
        }
        if op == HubOperation::Restore {
            if let Some(plan) = self
                .drafts
                .get(key)
                .and_then(|d| d.restore.as_ref())
                .cloned()
            {
                card = card.child(self.render_restore_preview(&plan, window, cx));
            }
        } else if forms::FORMS[key.form].document {
            card = card
                .child(d::key_value(
                    self.t(Text::DocumentFormat),
                    body["schema"].as_str().unwrap_or("JSON").to_owned(),
                ))
                .child(d::key_value(
                    self.t(Text::EncodedSize),
                    format!(
                        "{} {}",
                        serde_json::to_vec(&body).map_or(0, |v| v.len()),
                        self.t(Text::Bytes)
                    ),
                ))
                .child(d::caption(self.t(Text::TheClientAndServiceValidateThe)));
        } else {
            let (_, ckb) = p::json_asset(&body["asset"], self.language);
            for (i, f) in forms::FORMS[key.form].fields.iter().enumerate() {
                let val = &body[f.key];
                if op == HubOperation::CreateInvoice
                    && (matches!(f.key, "payment_preimage" | "payment_hash")
                        || val.is_null()
                        || val.as_str() == Some(""))
                {
                    continue;
                }
                let text = if matches!(f.kind, forms::Kind::Secret) {
                    if val.is_null() {
                        self.t(Text::NotSupplied).into()
                    } else {
                        self.t(Text::SuppliedHidden).into()
                    }
                } else if workspace::amount_field(f.key) {
                    p::amount(val.as_str().unwrap_or("0"), ckb, self.language)
                } else {
                    val.as_str()
                        .map(str::to_owned)
                        .unwrap_or_else(|| val.to_string())
                };
                card = card.child(self.copyable_fact(
                    810 + i,
                    p::field_label(f.key, f.label, self.language),
                    text,
                    cx,
                ));
            }
            if workspace::uses_asset(op) {
                card = card.child(d::key_value(
                    self.t(Text::Asset),
                    p::json_asset(&body["asset"], self.language).0,
                ));
            }
        }
        if forms::FORMS[key.form].document {
            for (i, (field, label)) in [
                ("pubkey", Text::ReceiptSigner),
                ("signing_digest", Text::RoleDigest),
                ("request_id", Text::RequestID),
            ]
            .into_iter()
            .enumerate()
            {
                if let Some(value) = body[field].as_str() {
                    card = card.child(self.copyable_fact(
                        850 + i,
                        self.t(label),
                        value.to_owned(),
                        cx,
                    ));
                }
            }
            if let Some(summary) = self.drafts.get(key).and_then(|d| d.checked_review.clone()) {
                card = card.child(d::badge(
                    self.t(Text::CanonicalContentChecksPassed),
                    Tone::Good,
                ));
                card = card.child(self.render_checked_terms(&summary, cx));
                let summary = summary.get("summary").unwrap_or(&summary);
                for (i, (field, label)) in [
                    ("channel_id", Text::Channel),
                    ("transaction_hash", Text::ExactTransaction),
                    ("funding_context_id", Text::FundingContext),
                ]
                .into_iter()
                .enumerate()
                {
                    if let Some(value) = summary[field].as_str() {
                        card = card.child(self.copyable_fact(
                            860 + i,
                            self.t(label),
                            value.to_owned(),
                            cx,
                        ));
                    }
                }
            }
        }
        card.child(d::rule()).child(d::caption(
            self.t(Text::InputPermissionsConnectionAndTheLast),
        ))
    }

    pub(super) fn render_restore_preview(
        &mut self,
        plan: &RestorePlan,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Div {
        let mut card = div()
            .rounded_lg()
            .border_1()
            .border_color(rgb(if plan.preview.allowed {
                d::BORDER
            } else {
                d::WARNING
            }))
            .p_4()
            .flex()
            .flex_col()
            .gap_3()
            .child(
                div()
                    .font_weight(FontWeight::SEMIBOLD)
                    .child(self.t(Text::ExactRestorePreview)),
            )
            .child(d::badge(
                if plan.preview.allowed {
                    self.t(Text::ServerPermitsThisCandidate)
                } else {
                    self.t(Text::RestoreIsBlocked)
                },
                if plan.preview.allowed {
                    Tone::Info
                } else {
                    Tone::Warning
                },
            ));
        let current = &plan.preview.current;
        let candidate = &plan.preview.candidate;
        for (label, before, after) in [
            (Text::Channels2, current.channels, candidate.channels),
            (Text::Factories, current.factories, candidate.factories),
            (
                Text::RecoveryPackages,
                current.multi_asset_packages,
                candidate.multi_asset_packages,
            ),
            (
                Text::FundingCeremonies,
                current.root_fundings,
                candidate.root_fundings,
            ),
            (Text::Invoices, current.invoices, candidate.invoices),
            (Text::Events, current.events, candidate.events),
        ] {
            card = card.child(d::key_value(self.t(label), format!("{before} → {after}")));
        }
        for (i, warning) in plan.preview.warnings.iter().enumerate() {
            card = card.child(self.service_message(
                ("restore-warning", i),
                warning.clone(),
                window,
                cx,
            ));
        }
        let op = self.active.as_ref().map(|k| forms::FORMS[k.form].operation);
        if op == Some(HubOperation::PreviewRestore) {
            card = card.child(
                Button::new("continue-restore")
                    .label(self.t(Text::ContinueToRestoreReview))
                    .disabled(!plan.preview.allowed)
                    .on_click(cx.listener(|this, _, window, cx| this.continue_restore(window, cx))),
            );
        }
        card
    }
}

fn domain_description(domain: Domain, l: Language) -> &'static str {
    match domain {
        Domain::Payments => l.t(Text::CreateImportAndTrackInvoices),
        Domain::Evidence => l.t(Text::ReviewAndPrivatelyExportEvidence),
        Domain::Funding => l.t(Text::ExactTermsSignatureRolesAndExport),
        Domain::Peers => l.t(Text::PublicIdentitiesAndDisplayNames),
        Domain::Workspace => l.t(Text::PrivateExportAndPreviewedRestore),
    }
}
