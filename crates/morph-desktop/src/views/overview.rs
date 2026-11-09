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
        view = view.child(
            d::panel()
                .p_4()
                .bg(linear_gradient(
                    115.,
                    linear_color_stop(rgb(0x201a3d), 0.),
                    linear_color_stop(rgb(0x13192b), 1.),
                ))
                .child(
                    div()
                        .flex()
                        .items_center()
                        .flex_wrap()
                        .gap_3()
                        .child(
                            div()
                                .flex_1()
                                .child(d::caption(self.t(Text::FlowCaption)))
                                .child(
                                    div()
                                        .text_lg()
                                        .font_weight(FontWeight::MEDIUM)
                                        .child(self.t(Text::FlowNote)),
                                ),
                        )
                        .child(
                            Button::new("replay-flow")
                                .ghost()
                                .small()
                                .icon(IconName::Play)
                                .label(self.t(Text::FlowReplay))
                                .disabled(!self.motion_enabled(window, cx))
                                .on_click(cx.listener(|this, _, _, cx| {
                                    this.motion_generation = this.motion_generation.wrapping_add(1);
                                    cx.notify();
                                })),
                        ),
                )
                .child(
                    div().w_full().h(px(112. * self.scale())).child(
                        self.flux
                            .clone()
                            .cached(gpui_kit::StyleRefinement::default().size_full()),
                    ),
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
                                .size(px(104.))
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
                                    Button::new("welcome-connect")
                                        .primary()
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
            let cards = vec![
                (
                    self.t(Text::CKBRPC).to_owned(),
                    s.rpc
                        .tip_height
                        .map_or(self.t(Text::NotObserved).into(), |h| format!("#{h}")),
                    self.t(Text::ANodeObservationNotChannelConfirmation).into(),
                    if s.rpc.tip_height.is_some() {
                        Tone::Info
                    } else {
                        Tone::Neutral
                    },
                ),
                (
                    self.t(Text::WatchEvidence).into(),
                    if s.watchtower.last_error.is_some() {
                        self.t(Text::NeedsAttention).into()
                    } else if s.watchtower.configured && s.watchtower.file_exists {
                        self.t(Text::Available).into()
                    } else {
                        self.t(Text::NotConfigured).into()
                    },
                    format!(
                        "{} {}",
                        s.watchtower.alerts.len(),
                        self.t(Text::AlertsServiceHealthSeparate)
                    ),
                    if s.watchtower.last_error.is_some() {
                        Tone::Warning
                    } else {
                        Tone::Neutral
                    },
                ),
                (
                    self.t(Text::ChannelRecords).into(),
                    s.channels.len().to_string(),
                    self.t(Text::LocalHubProjection).into(),
                    Tone::Neutral,
                ),
                (
                    self.t(Text::RecoveryPackages).into(),
                    s.multi_asset_package_count.to_string(),
                    self.t(Text::SavedSignedEvidence).into(),
                    Tone::Good,
                ),
            ];
            let mut metrics = div().flex().flex_col().gap_4();
            for chunk in cards.chunks(if wide { 4 } else { 2 }) {
                let mut row = div().flex().gap_4();
                for (label, value, note, tone) in chunk {
                    let card = d::metric(label.clone(), value.clone(), note.clone(), *tone)
                        .hover(|style| style.border_color(rgb(d::ACCENT)));
                    if self.motion_enabled(window, cx) {
                        use gpui_kit::AnimationExt;
                        row = row.child(
                            card.with_animation(
                                gpui_kit::ElementId::Name(format!("metric-{label}-{value}").into()),
                                gpui_kit::Animation::new(crate::motion::ENTER_DURATION)
                                    .with_max_fps(60.),
                                |e, t| e.opacity(0.85 + 0.15 * t),
                            ),
                        );
                    } else {
                        row = row.child(card);
                    }
                }
                metrics = metrics.child(row)
            }
            view = view.child(metrics);
        }
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
                            .child(d::caption(alert.message.clone())),
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
        if pending_roots.is_empty() {
            todo = todo.child(d::caption(
                self.t(Text::NoIncompleteFundingCeremoniesImportA),
            ));
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
                .child(d::key_value(self.t(Text::Network), state.network.clone()))
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
                div().flex().gap_5().child(todo).child(safety)
            } else {
                div().flex().flex_col().gap_5().child(todo).child(safety)
            })
            .child(self.render_asset_overview())
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

    pub(super) fn render_asset_overview(&self) -> Div {
        let mut card = d::panel()
            .flex()
            .flex_col()
            .gap_4()
            .child(
                div()
                    .text_lg()
                    .font_weight(FontWeight::SEMIBOLD)
                    .child(self.t(Text::RecordedBalances)),
            )
            .child(d::caption(self.t(Text::PerChannelAndAssetLocalProjection)));
        let Some(s) = &self.state else { return card };
        if s.channels.is_empty() {
            return card.child(d::caption(self.t(Text::NoChannelBalancesRecordedYet)));
        }
        for (i, c) in s.channels.iter().take(6).enumerate() {
            for (j, b) in c.balances.iter().take(8).enumerate() {
                let ckb = matches!(b.asset, morph_sdk::api::AssetView::Ckb);
                card = card.child(d::rule()).child(
                    div()
                        .id(("balance", i * 8 + j))
                        .flex()
                        .gap_4()
                        .child(
                            div()
                                .flex_1()
                                .min_w_0()
                                .child(p::asset_name(&b.asset))
                                .child(d::caption(p::short(&c.channel_id))),
                        )
                        .child(
                            div()
                                .flex_1()
                                .min_w_0()
                                .child(d::caption(self.t(Text::Local)))
                                .child(p::amount(&b.local, ckb, self.language)),
                        )
                        .child(
                            div()
                                .flex_1()
                                .min_w_0()
                                .child(d::caption(self.t(Text::Remote)))
                                .child(p::amount(&b.remote, ckb, self.language)),
                        )
                        .child(
                            div()
                                .flex_1()
                                .min_w_0()
                                .child(d::caption(self.t(Text::Pending)))
                                .child(p::amount(&b.pending, ckb, self.language)),
                        ),
                );
            }
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
