use super::*;

impl Desktop {
    pub(crate) fn render_workspace(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let width = window.viewport_size().width;
        let scale = self.scale();
        let compact = width < px(1050. * scale);
        let drawer = self.technical && width >= px(1450. * scale);
        let available = width
            - px(if compact { 76. } else { 212. }) * scale
            - px(if drawer { 390. } else { 0. }) * scale;
        let wide = available >= px(1040. * scale);
        let body: AnyElement = if self.technical && !drawer {
            self.render_technical(window, cx).into_any_element()
        } else if self.selected.is_some()
            && !matches!(self.page, Page::Actions | Page::Model | Page::Inspector)
        {
            self.render_record_detail(window, cx).into_any_element()
        } else {
            match self.page {
                Page::Overview => self.render_overview(window, cx, wide).into_any_element(),
                Page::Actions => self.render_tasks(window, cx, wide).into_any_element(),
                Page::Model => self.render_settings(window, cx).into_any_element(),
                Page::Inspector => self.render_inspector(window, cx).into_any_element(),
                Page::Events if !self.hub_activity => {
                    self.render_activity(window, cx).into_any_element()
                }
                _ => self.render_records(window, cx).into_any_element(),
            }
        };
        let enabled = self.motion_enabled(window, cx);
        self.flux.update(cx, |flux, cx| {
            flux.configure(
                self.motion_generation,
                !enabled || self.page != Page::Overview,
                cx,
            )
        });
        let body = if enabled {
            use gpui_kit::AnimationExt;
            div()
                .flex_1()
                .min_h_0()
                .flex()
                .flex_col()
                .child(body)
                .with_animation(
                    ("page-enter", self.motion_generation),
                    gpui_kit::Animation::new(crate::motion::ENTER_DURATION).with_max_fps(60.),
                    |element, t| element.opacity(0.88 + 0.12 * (1. - (1. - t).powi(3))),
                )
                .into_any_element()
        } else {
            body
        };
        let mut main = div()
            .flex_1()
            .min_w_0()
            .h_full()
            .flex()
            .flex_col()
            .child(self.render_header(compact, window, cx));
        if self.unknown_context.is_some() {
            main = main.child(self.render_reconciliation(cx));
        }
        if let Some(n) = &self.notice {
            let tone = n.tone;
            let title = crate::i18n::stored_copy(&n.title, self.language);
            let detail = crate::i18n::stored_copy(&n.detail, self.language);
            main = main.child(
                div()
                    .mx_6()
                    .mt_3()
                    .px_4()
                    .py_3()
                    .rounded_md()
                    .bg(rgb(tone.background()))
                    .flex()
                    .gap_3()
                    .items_start()
                    .child(
                        Icon::new(if tone == Tone::Danger {
                            IconName::CircleAlert
                        } else {
                            IconName::Info
                        })
                        .text_color(rgb(tone.color())),
                    )
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .flex()
                            .flex_col()
                            .gap_1()
                            .child(div().text_sm().font_weight(FontWeight::MEDIUM).child(title))
                            .child(d::caption(detail)),
                    )
                    .child(
                        Button::new("dismiss-notice")
                            .icon(IconName::X)
                            .ghost()
                            .small()
                            .tooltip(self.t(Text::Dismiss))
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.notice = None;
                                cx.notify()
                            })),
                    ),
            );
        }
        main = main.child(
            div()
                .flex_1()
                .min_h_0()
                .flex()
                .flex_col()
                .p(if compact { px(20.) } else { px(28.) })
                .child(body),
        );
        let mut shell =
            div()
                .id("morph-workspace")
                .key_context("MorphWorkspace")
                .track_focus(&self.focus)
                .size_full()
                .flex()
                .bg(linear_gradient(
                    135.,
                    linear_color_stop(rgb(d::BG), 0.),
                    linear_color_stop(rgb(0x101020), 1.),
                ))
                .text_color(rgb(d::TEXT))
                .text_sm()
                .child(self.render_navigation(compact, window, cx))
                .child(main)
                .on_action(cx.listener(|this, _: &IncreaseText, window, cx| {
                    this.change_scale(10, window, cx)
                }))
                .on_action(cx.listener(|this, _: &DecreaseText, window, cx| {
                    this.change_scale(-10, window, cx)
                }))
                .on_action(
                    cx.listener(|this, _: &ResetText, window, cx| this.change_scale(0, window, cx)),
                )
                .on_action(cx.listener(|this, _: &FocusSearch, window, cx| {
                    this.navigate(Page::Search, window, cx);
                    window.focus(&this.search.read(cx).focus_handle(cx), cx)
                }))
                .on_action(cx.listener(|this, _: &GoHome, window, cx| {
                    this.navigate(Page::Overview, window, cx)
                }))
                .on_action(cx.listener(|this, _: &GoChannels, window, cx| {
                    this.navigate(Page::Channels, window, cx)
                }))
                .on_action(cx.listener(|this, _: &GoFactories, window, cx| {
                    this.navigate(Page::Factories, window, cx)
                }))
                .on_action(cx.listener(|this, _: &RefreshWorkspace, _, cx| this.refresh(true, cx)))
                .on_action(cx.listener(|this, _: &OpenTasks, window, cx| {
                    this.active = None;
                    this.navigate(Page::Actions, window, cx)
                }))
                .on_action(cx.listener(|this, _: &CloseDetails, _, cx| {
                    this.selected = None;
                    this.selected_activity = None;
                    this.technical = false;
                    cx.notify()
                }));
        if drawer {
            shell = shell.child(
                div()
                    .w(px(390. * scale))
                    .flex_shrink_0()
                    .h_full()
                    .child(self.render_technical(window, cx)),
            );
        }
        shell
    }

    pub(super) fn render_navigation(
        &mut self,
        compact: bool,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let scale = self.scale();
        let mut sidebar = div()
            .w(px(if compact { 76. } else { 212. }) * scale)
            .flex_shrink_0()
            .h_full()
            .bg(rgb(d::SIDEBAR))
            .border_r_1()
            .border_color(rgb(d::BORDER))
            .p_3()
            .flex()
            .flex_col()
            .gap_2();
        let mut brand = div()
            .h(px(72. * scale))
            .px_2()
            .flex()
            .gap_3()
            .items_center()
            .child(
                img("branding/morph-logo.png")
                    .size(px(40.))
                    .rounded(px(11.)),
            );
        if !compact {
            brand = brand.child(
                div()
                    .text_xl()
                    .font_weight(FontWeight::SEMIBOLD)
                    .child("Morph"),
            );
        }
        sidebar = sidebar.child(brand);
        if !compact {
            sidebar = sidebar.child(d::caption(self.t(Text::OPERATORWORKSPACE)).px_2().pb_3());
        }
        let target = match self.page {
            Page::Overview => 0.,
            Page::Channels => 1.,
            Page::Factories => 2.,
            Page::Invoices => 3.,
            Page::Recovery => 4.,
            Page::Events => 5.,
            _ => -1.,
        };
        let marker = if self.motion_enabled(window, cx) {
            gpui_kit::base::motion::transition(
                "nav-indicator",
                target,
                gpui_kit::base::motion::Transition::new(Duration::from_millis(160)),
                window,
                cx,
            )
        } else {
            target
        };
        let mut nav = div().relative().flex_shrink_0().flex().flex_col().gap_2();
        if target >= 0. {
            nav = nav.child(
                div()
                    .absolute()
                    .left_0()
                    .top(px(marker.max(0.) * 49. * scale + 12. * scale))
                    .w(px(3.))
                    .h(px(18. * scale))
                    .rounded_md()
                    .bg(rgb(d::ACCENT)),
            );
        }
        for (i, page) in [
            Page::Overview,
            Page::Channels,
            Page::Factories,
            Page::Invoices,
            Page::Recovery,
            Page::Events,
        ]
        .into_iter()
        .enumerate()
        {
            let label = page_name(page, self.language);
            let selected = self.page == page;
            let mut content = div().w_full().flex().items_center().gap_3().child(
                Icon::new(page_icon(page))
                    .size(px(18.))
                    .text_color(rgb(if selected { d::ACCENT } else { d::MUTED })),
            );
            if !compact {
                content = content.child(label);
            }
            nav = nav.child(
                Button::new(("nav", i))
                    .ghost()
                    .selected(selected)
                    .tooltip(label)
                    .accessibility_label(label)
                    .w_full()
                    .flex_shrink_0()
                    .h(px(42. * self.scale()))
                    .child(content)
                    .on_click(cx.listener(move |this, _, window, cx| {
                        this.hub_activity = false;
                        this.navigate(page, window, cx)
                    })),
            );
        }
        sidebar = sidebar.child(nav);
        sidebar = sidebar.child(div().flex_1()).child(d::rule());
        for (i, page) in [Page::Watch, Page::Model, Page::Inspector]
            .into_iter()
            .enumerate()
        {
            let label = page_name(page, self.language);
            let selected = self.page == page;
            let mut content = div().w_full().flex().items_center().gap_3().child(
                Icon::new(page_icon(page))
                    .size(px(18.))
                    .text_color(rgb(if selected { d::ACCENT } else { d::MUTED })),
            );
            if !compact {
                content = content.child(label);
            }
            sidebar = sidebar.child(
                Button::new(("nav-bottom", i))
                    .ghost()
                    .selected(selected)
                    .tooltip(label)
                    .accessibility_label(label)
                    .w_full()
                    .flex_shrink_0()
                    .h(px(42. * self.scale()))
                    .child(content)
                    .on_click(
                        cx.listener(move |this, _, window, cx| this.navigate(page, window, cx)),
                    ),
            );
        }

        if !compact {
            sidebar = sidebar.child(
                d::caption(format!("v{}", env!("CARGO_PKG_VERSION")))
                    .px_2()
                    .pt_3(),
            );
        }
        sidebar.id("navigation-scroll").overflow_y_scroll()
    }

    pub(super) fn render_header(
        &mut self,
        compact: bool,
        _window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Div {
        let fresh = self
            .last_checked
            .is_some_and(|v| v.elapsed() < Duration::from_secs(15));
        let label = if self.connected && fresh {
            self.t(Text::HubConnected)
        } else if self.connected {
            self.t(Text::HubDataStale)
        } else {
            self.t(Text::Offline)
        };
        let tone = if self.connected && fresh {
            Tone::Good
        } else {
            Tone::Neutral
        };
        let mut header = div()
            .h(px(60. * self.scale()))
            .flex_shrink_0()
            .px_6()
            .border_b_1()
            .border_color(rgb(d::BORDER))
            .flex()
            .items_center()
            .gap_3()
            .child(d::caption(format!(
                "{} / {}",
                if compact {
                    "Morph"
                } else {
                    self.t(Text::Workspace)
                },
                page_name(self.page, self.language)
            )))
            .child(div().flex_1());
        if !compact && let Some(s) = &self.state {
            header = header.child(d::badge(s.network.clone(), Tone::Neutral));
        }
        header = header.child(d::badge(label, tone));
        if !compact {
            if let Some(t) = self.last_checked {
                header = header.child(d::caption(format!(
                    "{} {}",
                    t.elapsed().as_secs(),
                    self.t(Text::Seconds)
                )));
            }
        }
        header = header.child(
            Button::new("workspace-appearance")
                .ghost()
                .small()
                .label("Aa")
                .tooltip(self.t(Text::Appearance))
                .accessibility_label(self.t(Text::Appearance))
                .on_click(cx.listener(|this, _, window, cx| {
                    this.appearance_settings = true;
                    this.navigate(Page::Model, window, cx);
                })),
        );
        header = header.child(
            Button::new("workspace-language")
                .ghost()
                .small()
                .label(if self.language == Language::Chinese {
                    "EN"
                } else {
                    "中文"
                })
                .tooltip(self.t(Text::SwitchLanguage))
                .accessibility_label(self.t(Text::SwitchLanguage))
                .on_click(cx.listener(|this, _, window, cx| {
                    let next = if this.language == Language::Chinese {
                        Language::English
                    } else {
                        Language::Chinese
                    };
                    this.set_language(next, window, cx);
                })),
        );
        header = header
            .child(
                Button::new("workspace-search")
                    .icon(IconName::Search)
                    .ghost()
                    .tooltip(self.t(Text::SearchWorkspaceCtrlK))
                    .on_click(cx.listener(|this, _, window, cx| {
                        this.navigate(Page::Search, window, cx);
                        window.focus(&this.search.read(cx).focus_handle(cx), cx)
                    })),
            )
            .child(
                Button::new("workspace-refresh")
                    .icon(IconName::RefreshCw)
                    .ghost()
                    .disabled(!self.connected || self.foreground_busy())
                    .tooltip(self.t(Text::RefreshCtrlR))
                    .on_click(cx.listener(|this, _, _, cx| this.refresh(true, cx))),
            )
            .child(
                Button::new("workspace-settings")
                    .icon(IconName::Settings)
                    .ghost()
                    .tooltip(self.t(Text::ConnectionSettings))
                    .on_click(
                        cx.listener(|this, _, window, cx| this.navigate(Page::Model, window, cx)),
                    ),
            );
        header
    }

    pub(super) fn render_reconciliation(&mut self, cx: &mut Context<Self>) -> Div {
        let endpoint = self
            .unknown_context
            .as_ref()
            .map(|c| c.0.clone())
            .unwrap_or_default();
        div()
            .mx_6()
            .mt_3()
            .p_4()
            .rounded_lg()
            .bg(rgb(0x3b3022))
            .flex()
            .flex_col()
            .gap_3()
            .child(
                div()
                    .font_weight(FontWeight::SEMIBOLD)
                    .text_color(rgb(d::WARNING))
                    .child(self.t(Text::AWriteOutcomeNeedsReview)),
            )
            .child(d::caption(format!(
                "{} · {}",
                endpoint,
                self.t(Text::StoppingAWaitDidNotCancel)
            )))
            .child(
                div()
                    .flex()
                    .gap_3()
                    .child(
                        Button::new("refresh-unknown")
                            .label(self.t(Text::ReadCurrentRecords))
                            .disabled(!self.connected || self.foreground_busy())
                            .on_click(cx.listener(|this, _, _, cx| this.refresh(true, cx))),
                    )
                    .child(
                        Button::new("acknowledge-unknown")
                            .label(self.t(Text::IReviewedTheCurrentRecords))
                            .disabled(!self.reconcile_ready)
                            .on_click(
                                cx.listener(|this, _, _, cx| this.acknowledge_reconciliation(cx)),
                            ),
                    ),
            )
    }
}
