use super::*;

impl Desktop {
    pub(super) fn primary_action(page: Page) -> Option<HubOperation> {
        match page {
            Page::Channels => Some(HubOperation::OpenChannel),
            Page::Factories => Some(HubOperation::OpenFactory),
            Page::Invoices => Some(HubOperation::CreateInvoice),
            Page::Recovery => Some(HubOperation::ImportRecovery),
            Page::Peers => Some(HubOperation::Peer),
            _ => None,
        }
    }

    pub(super) fn render_records(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> Div {
        let label = page_name(self.page, self.language);
        let records = self.filtered_records(cx);
        let mut header = div()
            .flex()
            .items_start()
            .gap_4()
            .child(title_row(label, self.t(Text::SelectARecordToViewIts)).flex_1());
        if let Some(op) = Self::primary_action(self.page) {
            header = header.child(
                Button::new("primary-record-action")
                    .icon(IconName::Plus)
                    .primary()
                    .label(operation_title(op, self.language))
                    .on_click(cx.listener(move |this, _, window, cx| {
                        this.start_task(op, String::new(), window, cx)
                    })),
            );
        }
        let mut view = div()
            .flex_1()
            .min_h_0()
            .flex()
            .flex_col()
            .gap_4()
            .child(header);
        if self.page == Page::Watch {
            if let Some(s) = &self.state {
                view = view.child(
                    d::panel()
                        .flex()
                        .gap_4()
                        .items_center()
                        .child(d::badge(
                            if s.watchtower.configured {
                                self.t(Text::Configured)
                            } else {
                                self.t(Text::NotConfigured)
                            },
                            if s.watchtower.last_error.is_some() {
                                Tone::Warning
                            } else {
                                Tone::Neutral
                            },
                        ))
                        .child(d::caption(s.watchtower.last_error.clone().unwrap_or_else(
                            || {
                                self.t(Text::ObserverReportsAreSeparateFromIndependent)
                                    .into()
                            },
                        ))),
                );
            }
        }
        if self.page == Page::Events {
            view = view.child(self.activity_tabs(cx));
        }
        view = view.child(
            div()
                .flex()
                .gap_3()
                .items_center()
                .child(Input::new(&self.search).id("record-search"))
                .child(d::caption(format!(
                    "{} · {}",
                    self.t(Text::Results),
                    records.len()
                ))),
        );
        if records.is_empty() {
            return view.child(empty_state(
                page_icon(self.page),
                if self.connected {
                    self.t(Text::NoMatchingRecords)
                } else {
                    self.t(Text::ConnectToSeeYourRecords)
                },
                self.t(Text::TryADifferentSearchImportEvidence),
            ));
        }
        let scale = self.scale();
        let weak = cx.entity().downgrade();
        let lang = self.language;
        view.child(
            uniform_list("workspace-records", records.len(), move |range, _, _| {
                range
                    .map(|i| {
                        let r = records[i].clone();
                        let weak = weak.clone();
                        let name = record_title(&r, lang);
                        let content = div()
                            .w_full()
                            .min_w_0()
                            .flex()
                            .items_center()
                            .gap_4()
                            .child(
                                div()
                                    .flex_1()
                                    .min_w_0()
                                    .flex()
                                    .flex_col()
                                    .gap_2()
                                    .overflow_hidden()
                                    .child(
                                        div()
                                            .font_weight(FontWeight::MEDIUM)
                                            .text_ellipsis()
                                            .whitespace_nowrap()
                                            .child(name.clone()),
                                    )
                                    .child(d::caption(record_subtitle(&r, lang)))
                                    .children(record_balance_hint(&r, lang).map(d::caption)),
                            )
                            .child(d::badge(r.source(lang), Tone::Neutral))
                            .child(Icon::new(IconName::ChevronRight).text_color(rgb(d::DIM)));
                        Button::new(("record", i))
                            .ghost()
                            .accessibility_label(format!("{} {name}", lang.t(Text::Open)))
                            .w_full()
                            .h(px(104. * scale))
                            .px_4()
                            .py_3()
                            .border_b_1()
                            .border_color(rgb(d::BORDER))
                            .child(content)
                            .on_click(move |_, window, cx| {
                                let _ = weak
                                    .update(cx, |this, cx| this.pick_record(r.clone(), window, cx));
                            })
                    })
                    .collect::<Vec<_>>()
            })
            .flex_1()
            .min_h_0(),
        )
    }

    pub(super) fn render_record_detail(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let r = self.selected.as_ref().cloned().unwrap_or_else(|| Record {
            page: Page::Overview,
            row: model::Row {
                title: String::new(),
                subtitle: String::new(),
                document: Value::Null,
            },
        });
        let v = &r.row.document;
        let technical_record = r.clone();
        let mut view = div()
            .id("detail-scroll")
            .flex_1()
            .min_h_0()
            .overflow_y_scroll()
            .flex()
            .flex_col()
            .gap_5();
        view = view.child(
            div()
                .flex()
                .items_center()
                .gap_3()
                .child(
                    Button::new("back-to-list")
                        .icon(IconName::ArrowLeft)
                        .ghost()
                        .label(self.t(Text::BackToList))
                        .on_click(cx.listener(|this, _, _, cx| {
                            this.selected = None;
                            this.technical = false;
                            cx.notify()
                        })),
                )
                .child(div().flex_1())
                .child(d::badge(
                    r.source(self.language),
                    if r.is_recovery() {
                        Tone::Good
                    } else {
                        Tone::Neutral
                    },
                ))
                .child(
                    Button::new("record-technical")
                        .icon(IconName::Code)
                        .ghost()
                        .label(self.t(Text::TechnicalDetails))
                        .on_click(cx.listener(move |this, _, window, cx| {
                            this.pick_record(technical_record.clone(), window, cx);
                            this.technical = true;
                            cx.notify()
                        })),
                ),
        );
        view = view.child(title_row(
            &record_title(&r, self.language),
            &record_subtitle(&r, self.language),
        ));
        if self.selection_missing {
            view = view.child(d::badge(
                self.t(Text::ThisRecordIsNoLongerIn),
                Tone::Warning,
            ));
        }
        if r.is_root() {
            return view.child(self.render_root_ceremony(&r, window, cx));
        }
        let mut facts = d::panel().flex().flex_col().gap_2();
        let keys = match r.page {
            Page::Channels => vec![
                ("channel_id", Text::ChannelID),
                ("counterparty_pubkey", Text::Counterparty),
                ("funding_context_id", Text::FundingContext),
                ("funding_epoch", Text::FundingEpoch),
                ("state_number", Text::StateNumber),
                ("phase", Text::Phase),
            ],
            Page::Factories => vec![
                ("factory_id", Text::FactoryID),
                ("update_number", Text::UpdateNumber),
            ],
            Page::Invoices => vec![
                ("invoice_id", Text::InvoiceID),
                ("description", Text::Description),
                ("status", Text::Status),
                ("network", Text::Network),
                ("payment_hash", Text::PaymentHash),
                ("channel_id", Text::Channel2),
            ],
            Page::Peers => vec![
                ("alias", Text::DisplayName),
                ("pubkey", Text::PublicKey),
                ("node_id", Text::NodeID),
            ],
            Page::Recovery if r.is_recovery() => vec![
                ("package_id", Text::PackageID),
                ("channel_id", Text::Channel3),
                ("funding_context_id", Text::FundingContext),
                ("state_number", Text::StateNumber),
                ("vault_count", Text::Vaults),
            ],
            _ => vec![
                ("event", Text::Event),
                ("severity", Text::Severity),
                ("channel_id", Text::Channel3),
                ("message", Text::Description2),
            ],
        };
        for (i, (key, label)) in keys.into_iter().enumerate() {
            if !v[key].is_null() {
                let raw = v[key]
                    .as_str()
                    .map(str::to_owned)
                    .unwrap_or_else(|| v[key].to_string());
                facts = if key == "event" {
                    facts.child(d::key_value(
                        self.t(label),
                        p::event_name(&raw, self.language),
                    ))
                } else if matches!(key, "phase" | "status" | "severity") {
                    facts.child(d::key_value(
                        self.t(label),
                        p::human_state(&raw, self.language),
                    ))
                } else {
                    facts.child(self.copyable_fact(i, self.t(label), raw, cx))
                };
            }
        }
        if let Some(message) = v["provenance"]["message"].as_str() {
            let message = match message {
                "Recorded in the Morph Hub state file only; this is not CKB devnet confirmation." => {
                    self.t(Text::SavedInThisHubOnlyCanonical)
                }
                other => other,
            };
            facts = facts.child(d::rule()).child(d::caption(message.to_owned()));
        }
        view = view.child(facts);
        let balances = v
            .get("balances")
            .or_else(|| v.get("reserve_balances"))
            .and_then(Value::as_array);
        if let Some(balances) = balances {
            view = view.child(self.render_balances(balances));
        }
        if let Some(members) = v["participant_pubkeys"].as_array() {
            let mut card = d::panel().flex().flex_col().gap_3().child(
                div()
                    .text_lg()
                    .font_weight(FontWeight::MEDIUM)
                    .child(self.t(Text::FactoryMembers)),
            );
            for (i, key) in members.iter().enumerate() {
                if let Some(key) = key.as_str() {
                    card = card.child(self.copyable_fact(
                        100 + i,
                        &format!("{} {}", self.t(Text::Member), i + 1),
                        key.into(),
                        cx,
                    ));
                }
            }
            view = view.child(card);
        }
        if let Some(children) = v["materialised_child_channels"].as_array() {
            let mut card = d::panel()
                .flex()
                .flex_col()
                .gap_3()
                .child(div().text_lg().child(self.t(Text::ChildChannels)));
            if children.is_empty() {
                card = card.child(d::caption(self.t(Text::NoChildrenRecorded)));
            }
            for (i, id) in children.iter().filter_map(Value::as_str).enumerate() {
                let id = id.to_owned();
                card = card.child(
                    div()
                        .flex()
                        .items_center()
                        .gap_3()
                        .child(d::caption(p::short(&id)).flex_1())
                        .child(
                            Button::new(("open-child", i))
                                .label(self.t(Text::ViewRecord))
                                .on_click(cx.listener(move |this, _, window, cx| {
                                    this.navigate(Page::Channels, window, cx);
                                    this.select_record_by_id(Page::Channels, &id, window, cx)
                                })),
                        ),
                );
            }
            view = view.child(card);
        }
        if r.page == Page::Invoices {
            let (asset, ckb) = p::json_asset(&v["asset"], self.language);
            view = view.child(
                d::panel()
                    .flex()
                    .flex_col()
                    .gap_3()
                    .child(d::caption(asset))
                    .child(d::title(p::amount(
                        v["amount"].as_str().unwrap_or("0"),
                        ckb,
                        self.language,
                    )))
                    .child(self.copyable_fact(
                        200,
                        self.t(Text::EncodedInvoice),
                        v["encoded_invoice"].as_str().unwrap_or("").into(),
                        cx,
                    )),
            );
        }
        if r.is_batch() {
            let document = r.row.document.clone();
            view = view.child(
                Button::new("review-saved-batch")
                    .icon(IconName::FileCheck)
                    .label(self.t(Text::ReviewThisEvidenceOffline))
                    .on_click(cx.listener(move |this, _, window, cx| {
                        this.navigate(Page::Inspector, window, cx);
                        this.inspector[0].update(cx, |input, cx| {
                            input.set_value(
                                serde_json::to_string_pretty(&document).unwrap_or_default(),
                                window,
                                cx,
                            )
                        });
                        this.inspector_files[0] = None;
                    })),
            );
        }
        let ops = match r.page {
            Page::Channels => vec![
                HubOperation::PublishChannel,
                HubOperation::SpliceChannel,
                HubOperation::FinaliseChannel,
                HubOperation::CreateInvoice,
            ],
            Page::Factories => vec![HubOperation::AdvanceFactory, HubOperation::MaterialiseChild],
            Page::Invoices => vec![HubOperation::ReceiveInvoice, HubOperation::SettleInvoice],
            Page::Recovery if r.is_recovery() => vec![HubOperation::ExportRecovery],
            _ => Vec::new(),
        };
        if ops.is_empty() {
            return view;
        }
        let mut actions = d::panel()
            .flex()
            .flex_col()
            .gap_3()
            .child(div().text_lg().child(self.t(Text::AvailableTasks)))
            .child(d::caption(
                self.t(Text::LocalRecordUpdatesAndEvidenceExport),
            ));
        for (i, op) in ops.into_iter().enumerate() {
            let reason = self.block_reason(op);
            let item = r.clone();
            actions = actions.child(
                div()
                    .flex()
                    .items_center()
                    .gap_4()
                    .child(
                        Button::new(("record-operation", i))
                            .label(operation_title(op, self.language))
                            .disabled(reason.is_some() || self.selection_missing)
                            .on_click(cx.listener(move |this, _, window, cx| {
                                this.start_for_record(op, item.clone(), window, cx)
                            })),
                    )
                    .child(d::caption(reason.unwrap_or_default())),
            );
        }
        view.child(actions)
    }

    pub(super) fn copyable_fact(
        &self,
        index: usize,
        label: &str,
        value: String,
        cx: &mut Context<Self>,
    ) -> Div {
        let full = value.clone();
        let compact = if value.len() > 24
            && value.is_ascii()
            && value
                .trim_start_matches("0x")
                .bytes()
                .all(|b| b.is_ascii_hexdigit())
        {
            p::short(&value)
        } else {
            value.clone()
        };
        div()
            .flex()
            .gap_3()
            .items_center()
            .py_2()
            .child(
                div()
                    .w(px(132.))
                    .flex_shrink_0()
                    .text_sm()
                    .text_color(rgb(d::MUTED))
                    .child(label.to_owned()),
            )
            .child(
                div()
                    .flex_1()
                    .min_w_0()
                    .overflow_hidden()
                    .line_clamp(2)
                    .child(compact),
            )
            .child(
                Button::new(("copy-fact", index))
                    .icon(IconName::Copy)
                    .ghost()
                    .small()
                    .tooltip(format!("{} · {}", self.t(Text::CopyCompleteValue), label))
                    .accessibility_label(format!("{} · {}", self.t(Text::Copy), label))
                    .on_click(cx.listener(move |_, _, _, cx| {
                        cx.write_to_clipboard(ClipboardItem::new_string(full.clone()))
                    })),
            )
    }

    pub(super) fn render_balances(&self, balances: &[Value]) -> Div {
        let mut card = d::panel()
            .flex()
            .flex_col()
            .gap_4()
            .child(
                div()
                    .text_lg()
                    .font_weight(FontWeight::MEDIUM)
                    .child(self.t(Text::BalancesByAsset)),
            )
            .child(d::caption(
                self.t(Text::RecordedValuesDoNotCombineDifferent),
            ));
        for b in balances {
            let (asset, ckb) = p::json_asset(&b["asset"], self.language);
            card = card
                .child(d::rule())
                .child(div().font_weight(FontWeight::MEDIUM).child(asset))
                .child(
                    div()
                        .flex()
                        .gap_4()
                        .child(div().flex_1().child(d::caption(self.t(Text::Local))).child(
                            p::amount(b["local"].as_str().unwrap_or("0"), ckb, self.language),
                        ))
                        .child(
                            div()
                                .flex_1()
                                .child(d::caption(self.t(Text::Remote)))
                                .child(p::amount(
                                    b["remote"].as_str().unwrap_or("0"),
                                    ckb,
                                    self.language,
                                )),
                        )
                        .child(
                            div()
                                .flex_1()
                                .child(d::caption(self.t(Text::Pending)))
                                .child(p::amount(
                                    b["pending"].as_str().unwrap_or("0"),
                                    ckb,
                                    self.language,
                                )),
                        ),
                )
        }
        card
    }

    pub(super) fn render_root_ceremony(
        &mut self,
        r: &Record,
        _window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Div {
        let v = &r.row.document;
        let exits = v["exit_signature_count"].as_u64().unwrap_or(0);
        let creation = v["creation_signature_count"].as_u64().unwrap_or(0);
        let ready = v["ready_to_export"].as_bool().unwrap_or(false);
        let mut card = d::panel()
            .flex()
            .flex_col()
            .gap_5()
            .child(
                div()
                    .text_lg()
                    .font_weight(FontWeight::SEMIBOLD)
                    .child(self.t(Text::FundingCeremony2)),
            )
            .child(self.copyable_fact(0, self.t(Text::ExactTransaction), r.id(), cx))
            .child(self.copyable_fact(
                1,
                self.t(Text::Channel),
                v["channel_id"].as_str().unwrap_or("").into(),
                cx,
            ));
        let steps = [
            (self.t(Text::TermsImported).to_owned(), true),
            (
                format!("{} {exits}/2", self.t(Text::ExitReceipts)),
                exits == 2,
            ),
            (
                format!("{} {creation}/2", self.t(Text::CreationReceipts)),
                creation == 2,
            ),
            (self.t(Text::ReadyForPrivateExport).into(), ready),
        ];
        for (i, (label, done)) in steps.into_iter().enumerate() {
            card = card.child(
                div()
                    .flex()
                    .gap_3()
                    .items_center()
                    .child(d::badge(
                        if done {
                            "✓".into()
                        } else {
                            (i + 1).to_string()
                        },
                        if done { Tone::Good } else { Tone::Neutral },
                    ))
                    .child(label),
            );
        }
        card = card.child(d::caption(
            self.t(Text::ExitAndCreationReceiptsAreIndependent),
        ));
        for (i, op) in [
            HubOperation::RootExitSignature,
            HubOperation::RootCreationSignature,
            HubOperation::ExportRoot,
            HubOperation::InspectRoot,
        ]
        .into_iter()
        .enumerate()
        {
            let semantic = match op {
                HubOperation::RootExitSignature if exits >= 2 => {
                    Some(self.t(Text::BothExitReceiptsAreSaved))
                }
                HubOperation::RootCreationSignature if exits < 2 => {
                    Some(self.t(Text::CollectBothExitReceiptsFirst))
                }
                HubOperation::RootCreationSignature if creation >= 2 => {
                    Some(self.t(Text::BothCreationReceiptsAreSaved))
                }
                HubOperation::ExportRoot if !ready => {
                    Some(self.t(Text::CompleteBothSignatureRolesFirst))
                }
                _ => None,
            };
            let reason = semantic
                .map(str::to_owned)
                .or_else(|| self.block_reason(op));
            let r = r.clone();
            card = card.child(
                div()
                    .flex()
                    .gap_4()
                    .items_center()
                    .child(
                        Button::new(("ceremony-step", i))
                            .label(operation_title(op, self.language))
                            .disabled(reason.is_some() || self.selection_missing)
                            .on_click(cx.listener(move |this, _, window, cx| {
                                this.start_for_record(op, r.clone(), window, cx)
                            })),
                    )
                    .child(d::caption(reason.unwrap_or_default())),
            );
        }
        card
    }
}
