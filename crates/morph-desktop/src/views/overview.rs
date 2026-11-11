use super::*;

impl Desktop {
    pub(super) fn render_overview(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
        wide: bool,
    ) -> impl IntoElement {
        let mut view = div()
            .id("overview-scroll")
            .flex_1()
            .min_h_0()
            .overflow_y_scroll()
            .flex()
            .flex_col()
            .gap_5();
        let intro = title_row(
            self.t(Text::Overview),
            self.t(Text::OverviewOfYourWorkspace),
        );
        view = view.child(
            div()
                .flex()
                .items_start()
                .gap_4()
                .child(intro.flex_1())
                .child(
                    Button::new("new-task")
                        .icon(IconName::Plus)
                        .primary()
                        .label(self.t(Text::NewTask))
                        .on_click(cx.listener(|this, _, window, cx| {
                            this.active = None;
                            this.navigate(Page::Actions, window, cx)
                        })),
                ),
        );
        if !self.connected {
            return view
                .child(
                    d::panel()
                        .bg(linear_gradient(
                            125.,
                            linear_color_stop(rgb(0x1c1a35), 0.),
                            linear_color_stop(rgb(0x131527), 1.),
                        ))
                        .px_8()
                        .py_8()
                        .flex()
                        .flex_col()
                        .gap_6()
                        .child(
                            img("branding/morph-logo.png")
                                .size(px(132. * self.scale()))
                                .rounded(px(24.)),
                        )
                        .child(
                            div()
                                .flex()
                                .flex_col()
                                .gap_3()
                                .child(
                                    div()
                                        .text_3xl()
                                        .font_weight(FontWeight::SEMIBOLD)
                                        .child(self.t(Text::YourNativeOperatorWorkspace)),
                                )
                                .child(
                                    div()
                                        .text_color(rgb(d::MUTED))
                                        .child(self.t(Text::ChooseAWorkspaceToGetStarted)),
                                ),
                        )
                        .child(
                            div()
                                .flex()
                                .flex_wrap()
                                .gap_3()
                                .child(
                                    Button::new("welcome-wallet")
                                        .primary()
                                        .icon(IconName::Wallet)
                                        .label(self.t(Text::OpenLocalWallet))
                                        .on_click(cx.listener(|this, _, w, cx| {
                                            this.navigate(Page::Wallet, w, cx)
                                        })),
                                )
                                .child(
                                    Button::new("welcome-connect")
                                        .icon(IconName::Plug)
                                        .label(self.t(Text::ConnectToHub))
                                        .on_click(cx.listener(|this, _, window, cx| {
                                            this.navigate(Page::Model, window, cx)
                                        })),
                                )
                                .child(
                                    Button::new("welcome-offline")
                                        .ghost()
                                        .icon(IconName::FileCheck)
                                        .label(self.t(Text::ReviewALocalFile))
                                        .on_click(cx.listener(|this, _, window, cx| {
                                            this.navigate(Page::Inspector, window, cx)
                                        })),
                                ),
                        )
                        .child(d::caption(self.t(Text::KeyAndChainOperationsRemainIn))),
                )
                .child(self.render_recent_tasks(window, cx));
        }
        if let Some(s) = &self.state {
            let balance = p::local_ckb_total(
                s.channels
                    .iter()
                    .map(|c| (c.channel_id.as_str(), c.balances.as_slice())),
            )
            .map(|value| p::amount(&value.to_string(), true, self.language))
            .unwrap_or_else(|| self.t(Text::BalanceUnavailable).into());
            let mut stats = div().flex().flex_wrap().gap_6();
            for (label, count) in [
                (Text::Channels2, s.channels.len()),
                (Text::Factory, s.factories.len()),
                (Text::RecoveryPackages, s.multi_asset_package_count),
            ] {
                stats = stats.child(
                    div()
                        .flex()
                        .flex_col()
                        .gap_1()
                        .child(
                            div()
                                .text_xl()
                                .font_weight(FontWeight::MEDIUM)
                                .child(count.to_string()),
                        )
                        .child(d::caption(self.t(label))),
                );
            }
            let hero = d::panel()
                .p_5()
                .bg(linear_gradient(
                    120.,
                    linear_color_stop(rgb(0x26213e), 0.),
                    linear_color_stop(rgb(0x142035), 1.),
                ))
                .flex()
                .flex_col()
                .gap_3()
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap_3()
                        .child(
                            d::caption(self.t(Text::LocalChannelBalance))
                                .flex_1()
                                .text_color(rgb(0xc5bfe8)),
                        )
                        .child(d::badge(self.t(Text::LocalHubProjection), Tone::Neutral)),
                )
                .child(
                    div()
                        .id("overview-ckb-total")
                        .overflow_x_scroll()
                        .whitespace_nowrap()
                        .text_size(gpui_kit::rems(if balance.len() > 24 { 1.6 } else { 2.8 }))
                        .font_weight(FontWeight::SEMIBOLD)
                        .child(balance),
                )
                .child(d::caption(self.t(Text::RecordedCKBOnly)))
                .child(div().h(px(1.)).bg(rgb(0x3a3654)))
                .child(
                    div()
                        .flex()
                        .items_end()
                        .flex_wrap()
                        .gap_4()
                        .child(stats.flex_1())
                        .child(
                            Button::new("balance-channels")
                                .ghost()
                                .icon(IconName::ArrowUpRight)
                                .label(self.t(Text::ViewChannels))
                                .on_click(cx.listener(|this, _, window, cx| {
                                    this.navigate(Page::Channels, window, cx)
                                })),
                        ),
                );
            view = view.child(hero);
        }
        let animated = self.motion_enabled(window, cx);
        let mut shortcuts = div().flex().gap_3();
        for (i, (op, icon, note)) in [
            (
                HubOperation::ImportRoot,
                IconName::ArrowLeftRight,
                Text::FundingCeremony,
            ),
            (
                HubOperation::CreateInvoice,
                IconName::Wallet,
                Text::RequestPaymentNote,
            ),
            (
                HubOperation::ImportRecovery,
                IconName::FolderOpen,
                Text::KeepRecoveryNote,
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let button = Button::new(("quick-action", i))
                .ghost()
                .h_auto()
                .py_4()
                .px_4()
                .flex_1()
                .min_w_0()
                .rounded(px(14.))
                .accessibility_label(operation_title(op, self.language))
                .child(
                    div()
                        .w_full()
                        .min_w_0()
                        .whitespace_normal()
                        .flex()
                        .flex_col()
                        .gap_3()
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .justify_between()
                                .child(d::icon_tile(icon))
                                .child(Icon::new(IconName::ArrowUpRight).text_color(rgb(d::DIM))),
                        )
                        .child(
                            div()
                                .text_base()
                                .font_weight(FontWeight::MEDIUM)
                                .child(operation_title(op, self.language)),
                        )
                        .child(d::caption(self.t(note))),
                )
                .on_click(cx.listener(move |this, _, window, cx| {
                    this.start_task(op, String::new(), window, cx)
                }));
            shortcuts = shortcuts.child(crate::motion::interactive(
                button,
                ("quick-action", i),
                animated,
                window,
                cx,
            ));
        }
        view = view.child(shortcuts);
        let pending_roots = self
            .state
            .as_ref()
            .map(|s| {
                s.root_fundings
                    .iter()
                    .filter(|r| !r.ready_to_export)
                    .cloned()
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let mut todo = d::panel()
            .flex_1()
            .min_w_0()
            .flex()
            .flex_col()
            .gap_4()
            .child(
                div()
                    .text_lg()
                    .font_weight(FontWeight::SEMIBOLD)
                    .child(self.t(Text::NeedsAttention)),
            );
        let alerts = self
            .state
            .as_ref()
            .map(|state| {
                state
                    .watchtower
                    .alerts
                    .iter()
                    .rev()
                    .filter(|a| {
                        matches!(
                            a.severity,
                            morph_sdk::api::WatchAlertSeverity::Warning
                                | morph_sdk::api::WatchAlertSeverity::Critical
                        )
                    })
                    .take(3)
                    .cloned()
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        for (i, alert) in alerts.iter().enumerate() {
            let record = Record {
                page: Page::Watch,
                row: model::Row {
                    title: self.t(Text::ObserverWarningRecord).into(),
                    subtitle: alert.message.clone(),
                    document: serde_json::to_value(alert).unwrap_or(Value::Null),
                },
            };
            todo = todo.child(d::rule()).child(
                div()
                    .flex()
                    .gap_3()
                    .items_center()
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .child(d::badge(self.t(Text::ObserverWarningRecord), Tone::Warning))
                            .child(d::caption(
                                watch_label(
                                    serde_json::to_value(&alert.event)
                                        .ok()
                                        .and_then(|v| v.as_str().map(str::to_owned))
                                        .as_deref()
                                        .unwrap_or(""),
                                    self.language,
                                )
                                .to_owned(),
                            )),
                    )
                    .child(
                        Button::new(("review-warning", i))
                            .label(self.t(Text::Review))
                            .on_click(cx.listener(move |this, _, window, cx| {
                                this.navigate(Page::Watch, window, cx);
                                this.pick_record(record.clone(), window, cx)
                            })),
                    ),
            );
        }
        if pending_roots.is_empty() && alerts.is_empty() {
            todo = todo.child(d::caption(self.t(Text::NoPendingActions)));
        }
        for (i, root) in pending_roots.iter().take(3).enumerate() {
            let id = root.root.transaction_hash.clone();
            todo = todo.child(d::rule()).child(
                div()
                    .flex()
                    .items_center()
                    .gap_3()
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .flex()
                            .flex_col()
                            .gap_2()
                            .child(format!(
                                "{} · {}",
                                self.t(Text::FundingCeremony),
                                p::short(&id)
                            ))
                            .child(d::caption(format!(
                                "{} {}/2 · {} {}/2",
                                self.t(Text::Exit),
                                root.exit_signature_count,
                                self.t(Text::Creation),
                                root.creation_signature_count
                            ))),
                    )
                    .child(
                        Button::new(("root-todo", i))
                            .label(self.t(Text::Continue))
                            .on_click(cx.listener(move |this, _, window, cx| {
                                this.navigate(Page::Recovery, window, cx);
                                this.select_record_by_id(Page::Recovery, &id, window, cx)
                            })),
                    ),
            );
        }
        todo = todo.child(
            Button::new("import-funding-overview")
                .icon(IconName::Upload)
                .label(self.t(Text::ImportFundingDraft))
                .on_click(cx.listener(|this, _, window, cx| {
                    this.start_task(HubOperation::ImportRoot, String::new(), window, cx)
                })),
        );
        let mut safety = d::panel()
            .flex_1()
            .min_w_0()
            .flex()
            .flex_col()
            .gap_4()
            .child(
                div()
                    .text_lg()
                    .font_weight(FontWeight::SEMIBOLD)
                    .child(self.t(Text::WorkspaceStatus)),
            );
        if let Some(state) = &self.state {
            safety = safety
                .child(d::key_value(
                    self.t(Text::Connection),
                    self.connected_endpoint.clone(),
                ))
                .child(d::key_value(
                    self.t(Text::Network),
                    p::network_name(&state.network, self.language),
                ))
                .child(d::key_value(
                    self.t(Text::Permissions),
                    if state.security.auth_required {
                        self.t(Text::ScopedAccess)
                    } else {
                        self.t(Text::ExplicitLoopbackMode)
                    },
                ))
                .child(d::caption(self.t(Text::HubRecordsSavedSignaturesAndChain)));
        }
        safety = safety.child(
            Button::new("overview-model")
                .ghost()
                .icon(IconName::Settings)
                .label(self.t(Text::OpenSettings))
                .on_click(
                    cx.listener(|this, _, window, cx| this.navigate(Page::Model, window, cx)),
                ),
        );
        view = view
            .child(if wide {
                div()
                    .flex()
                    .items_start()
                    .gap_5()
                    .child(self.render_asset_overview(window, cx).flex_1().min_w_0())
                    .child(
                        div()
                            .w(px(300. * self.scale()))
                            .flex_shrink_0()
                            .flex()
                            .flex_col()
                            .gap_5()
                            .child(todo)
                            .child(safety),
                    )
            } else {
                div()
                    .flex()
                    .flex_col()
                    .gap_5()
                    .child(todo)
                    .child(self.render_asset_overview(window, cx))
                    .child(safety)
            })
            .child(self.render_recent_tasks(window, cx));
        view
    }

    pub(crate) fn select_record_by_id(
        &mut self,
        page: Page,
        id: &str,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if let Some(s) = &self.state
            && let Some(r) = model::rows(s, page)
                .into_iter()
                .map(|row| Record { page, row })
                .find(|r| r.id() == id)
        {
            self.pick_record(r, window, cx)
        }
    }

    pub(super) fn render_asset_overview(&self, window: &mut Window, cx: &mut Context<Self>) -> Div {
        let animated = self.motion_enabled(window, cx);
        let mut card = d::panel()
            .flex()
            .flex_col()
            .gap_5()
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .items_center()
                    .gap_3()
                    .child(
                        div()
                            .text_lg()
                            .font_weight(FontWeight::SEMIBOLD)
                            .flex_1()
                            .child(self.t(Text::ChannelDistribution)),
                    )
                    .child(
                        div()
                            .flex()
                            .gap_4()
                            .child(allocation_label(self.t(Text::Local), 0x9f87ff))
                            .child(allocation_label(self.t(Text::Remote), 0x5878ad))
                            .child(allocation_label(self.t(Text::Pending), d::WARNING)),
                    ),
            )
            .child(d::caption(self.t(Text::PerChannelAndAssetLocalProjection)));
        let Some(s) = &self.state else { return card };
        if s.channels.is_empty() {
            return card.child(d::caption(self.t(Text::NoChannelBalancesRecordedYet)));
        }
        for (i, c) in s.channels.iter().take(6).enumerate() {
            let peer = s
                .peers
                .iter()
                .find(|p| p.pubkey == c.counterparty_pubkey)
                .map(|p| p.alias.as_str())
                .filter(|alias| !alias.trim().is_empty())
                .unwrap_or(self.t(Text::Channel));
            let id = c.channel_id.clone();
            let mut group = div().flex().flex_col().gap_4().child(
                div()
                    .flex()
                    .items_center()
                    .gap_3()
                    .child(d::icon_tile(IconName::ArrowLeftRight))
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .flex()
                            .flex_col()
                            .gap_1()
                            .child(div().font_weight(FontWeight::MEDIUM).child(peer.to_owned()))
                            .child(d::caption(p::short(&c.channel_id))),
                    )
                    .child(d::badge(
                        p::human_state(&c.phase, self.language),
                        Tone::Neutral,
                    ))
                    .child(
                        Button::new(("overview-channel", i))
                            .ghost()
                            .icon(IconName::ArrowUpRight)
                            .tooltip(self.t(Text::Open))
                            .on_click(cx.listener(move |this, _, window, cx| {
                                this.navigate(Page::Channels, window, cx);
                                this.select_record_by_id(Page::Channels, &id, window, cx)
                            })),
                    ),
            );
            for (j, b) in c.balances.iter().take(8).enumerate() {
                let ckb = matches!(b.asset, morph_sdk::api::AssetView::Ckb);
                let mut amounts = div().flex().flex_wrap().gap_4();
                for (lane, (label, value, color)) in [
                    (Text::Local, &b.local, d::TEXT),
                    (Text::Remote, &b.remote, d::MUTED),
                    (Text::Pending, &b.pending, d::MUTED),
                ]
                .into_iter()
                .enumerate()
                {
                    amounts = amounts.child(
                        div()
                            .flex_1()
                            .min_w(px(105. * self.scale()))
                            .flex()
                            .flex_col()
                            .gap_1()
                            .child(d::caption(self.t(label)))
                            .child(
                                div()
                                    .id(("allocation-value", i * 24 + j * 3 + lane))
                                    .min_w_0()
                                    .overflow_x_scroll()
                                    .whitespace_nowrap()
                                    .text_color(rgb(color))
                                    .child(p::amount(value, ckb, self.language)),
                            ),
                    );
                }
                let mut track = div()
                    .w_full()
                    .h(px(5. * self.scale()))
                    .rounded_full()
                    .bg(rgb(d::BORDER));
                if let Some(shares) = p::allocation_shares(&b.local, &b.remote, &b.pending) {
                    let bar = window.use_keyed_state(
                        gpui_kit::ElementId::Name(
                            format!("allocation-{}-{j}", c.channel_id).into(),
                        ),
                        cx,
                        |_, cx| cx.new(|_| crate::motion::Distribution::new(shares, animated)),
                    );
                    let bar = bar.read(cx).clone();
                    bar.update(cx, |bar, cx| bar.configure(shares, animated, cx));
                    track =
                        track.child(bar.cached(gpui_kit::StyleRefinement::default().size_full()));
                }
                group = group.child(
                    div()
                        .flex()
                        .flex_col()
                        .gap_3()
                        .child(d::caption(p::asset_name(&b.asset)).text_color(rgb(d::ACCENT)))
                        .child(amounts)
                        .child(track),
                );
            }
            if i > 0 {
                card = card.child(d::rule());
            }
            card = card.child(group);
        }
        if s.channels.len() > 6 {
            card = card.child(d::caption(self.t(Text::ChannelsPreviewLimit)));
        }
        card
    }

    pub(super) fn render_recent_tasks(
        &mut self,
        _window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Div {
        let running = self
            .activities
            .iter()
            .filter(|a| matches!(a.status, Status::Running | Status::Unknown))
            .count();
        d::panel()
            .flex()
            .items_center()
            .gap_4()
            .child(
                div()
                    .flex_1()
                    .flex()
                    .flex_col()
                    .gap_2()
                    .child(
                        div()
                            .font_weight(FontWeight::MEDIUM)
                            .child(self.t(Text::ThisSession)),
                    )
                    .child(d::caption(format!(
                        "{} {} · {} {}",
                        self.t(Text::Tasks),
                        self.activities.len(),
                        running,
                        self.t(Text::InProgressOrUnresolved)
                    ))),
            )
            .child(
                Button::new("overview-activity")
                    .icon(IconName::Activity)
                    .label(self.t(Text::OpenActivity))
                    .on_click(cx.listener(|this, _, window, cx| {
                        this.hub_activity = false;
                        this.navigate(Page::Events, window, cx)
                    })),
            )
    }
}

fn allocation_label(label: &'static str, color: u32) -> Div {
    div()
        .flex()
        .items_center()
        .gap_2()
        .child(div().size(px(6.)).rounded_full().bg(rgb(color)))
        .child(d::caption(label))
}
