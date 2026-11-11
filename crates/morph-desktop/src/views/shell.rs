use super::*;
use gpui_kit::TestSupportExt;

impl Desktop {
    pub(crate) fn render_workspace(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        if self.page != Page::Wallet
            && let Some(wallet) = &self.wallet
        {
            wallet.read(cx).set_visible(false);
        }
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
                Page::Wallet => {
                    let wallet = self
                        .wallet
                        .get_or_insert_with(|| {
                            cx.new(|cx| crate::wallet::WalletPane::new(self.language, window, cx))
                        })
                        .clone();
                    wallet.update(cx, |view, cx| {
                        view.language(self.language, window, cx);
                        view.set_motion(!self.reduced_motion, cx);
                        view.set_visible(window.is_visible() && window.is_window_active());
                    });
                    wallet.into_any_element()
                }
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
        self.task_signal.update(cx, |signal, cx| {
            signal.configure(self.foreground_busy(), enabled, cx)
        });
        let page_surface = div()
            .id("page-surface")
            .test_support()
            .flex_1()
            .min_h_0()
            .min_w_0()
            .flex()
            .flex_col()
            .child(body);
        let body = if enabled && self.page_enter_started.elapsed() < crate::motion::ENTER_DURATION {
            use gpui_kit::AnimationExt;
            page_surface
                .with_animation(
                    ("page-enter", self.motion_generation),
                    gpui_kit::Animation::new(crate::motion::ENTER_DURATION).with_max_fps(60.),
                    |element, t| {
                        let eased = 1. - (1. - t).powi(3);
                        element.opacity(0.82 + 0.18 * eased)
                    },
                )
                .into_any_element()
        } else {
            page_surface.into_any_element()
        };
        self.aurora
            .update(cx, |view, cx| view.configure(enabled, cx));
        let mut main = div()
            .relative()
            .flex_1()
            .min_w_0()
            .h_full()
            .flex()
            .flex_col()
            .child(
                div()
                    .absolute()
                    .top_0()
                    .left_0()
                    .w_full()
                    .h(px(320.))
                    .overflow_hidden()
                    .child(
                        self.aurora
                            .clone()
                            .cached(gpui_kit::StyleRefinement::default().size_full()),
                    ),
            )
            .child(self.render_header(compact, window, cx))
            .child(
                div()
                    .absolute()
                    .top_0()
                    .right_6()
                    .w(px(96.))
                    .h(px(2.))
                    .flex_shrink_0()
                    .child(
                        self.task_signal
                            .clone()
                            .cached(gpui_kit::StyleRefinement::default().size_full()),
                    ),
            );
        if self.unknown_context.is_some() {
            main = main.child(self.render_reconciliation(cx));
        }
        if self.notice.as_ref().is_some_and(|n| n.tone != Tone::Good) {
            main = main.child(div().mx_6().mt_3().child(self.render_notice(window, cx)));
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
        if self.notice.as_ref().is_some_and(|n| n.tone == Tone::Good) {
            main = main.child(
                div()
                    .absolute()
                    .bottom_4()
                    .right_4()
                    .w(px(400. * scale))
                    .max_w(gpui_kit::relative(0.9))
                    .shadow_lg()
                    .child(self.render_notice(window, cx)),
            );
        }
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
                .text_base()
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
                    this.navigate(Page::Actions, window, cx);
                    window.focus(&this.task_search.read(cx).focus_handle(cx), cx);
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

    fn render_notice(&self, window: &mut Window, cx: &mut Context<Self>) -> Div {
        let Some(n) = &self.notice else {
            return div();
        };
        let tone = n.tone;
        div()
            .px_4()
            .py_3()
            .rounded(px(12.))
            .border_1()
            .border_color(rgb(d::BORDER))
            .bg(rgb(if tone == Tone::Good {
                0x1b2130
            } else {
                tone.background()
            }))
            .flex()
            .gap_3()
            .items_start()
            .child(
                Icon::new(if tone == Tone::Good {
                    IconName::Check
                } else {
                    IconName::CircleAlert
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
                    .child(
                        div()
                            .font_weight(FontWeight::MEDIUM)
                            .child(crate::i18n::stored_copy(&n.title, self.language)),
                    )
                    .child(if tone == Tone::Good {
                        div().child(d::caption(crate::i18n::stored_copy(
                            &n.detail,
                            self.language,
                        )))
                    } else {
                        self.diagnostic("notice-error", n.detail.clone(), window, cx)
                    }),
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
            )
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
            .h(px(84. * scale))
            .flex_shrink_0()
            .px_1()
            .flex()
            .gap_3()
            .items_center()
            .child(
                div()
                    .id("brand-mark")
                    .test_support()
                    .size(px(if compact { 48. } else { 56. }) * scale)
                    .flex_shrink_0()
                    .child(
                        img("branding/morph-logo.png")
                            .size_full()
                            .rounded(px(14. * scale)),
                    ),
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
        let animated = self.motion_enabled(window, cx);
        let mut buttons = Vec::new();
        for (i, page) in [
            Page::Overview,
            Page::Wallet,
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
            let button = Button::new(("nav", i))
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
                }));
            buttons.push((button, selected));
        }
        sidebar = sidebar.child(crate::motion::rail(
            "primary-navigation",
            buttons,
            true,
            animated,
            window,
            cx,
        ));
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
            let button = Button::new(("nav-bottom", i))
                .ghost()
                .selected(selected)
                .tooltip(label)
                .accessibility_label(label)
                .w_full()
                .flex_shrink_0()
                .h(px(42. * self.scale()))
                .child(content)
                .on_click(cx.listener(move |this, _, window, cx| this.navigate(page, window, cx)));
            sidebar = sidebar.child(crate::motion::selection(
                button,
                ("nav-bottom", i),
                selected,
                animated,
                window,
                cx,
            ));
        }

        if !compact {
            sidebar = sidebar.child(
                d::caption(format!("v{}", env!("CARGO_PKG_VERSION")))
                    .px_2()
                    .pt_3(),
            );
        }
        sidebar
            .id("navigation-scroll")
            .test_support()
            .overflow_y_scroll()
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
        let label = if self.page == Page::Wallet {
            self.t(Text::WalletLocal)
        } else if self.connected && fresh {
            if compact {
                self.t(Text::Online)
            } else {
                self.t(Text::HubConnected)
            }
        } else if self.connected {
            self.t(Text::HubDataStale)
        } else {
            self.t(Text::Offline)
        };
        let tone = if self.page != Page::Wallet && self.connected && fresh {
            Tone::Good
        } else {
            Tone::Neutral
        };
        let mut header = div()
            .h(px(48. * self.scale()))
            .flex_shrink_0()
            .px_6()
            .border_b_1()
            .border_color(rgb(d::BORDER))
            .flex()
            .items_center()
            .gap_2()
            .child(d::status(label, tone))
            .child(div().flex_1());
        if self.page != Page::Wallet
            && !compact
            && let Some(s) = &self.state
        {
            header = header.child(d::badge(
                p::network_name(&s.network, self.language),
                Tone::Neutral,
            ));
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
        if self.page == Page::Wallet {
            return header;
        }
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
                Button::new("workspace-tasks")
                    .icon(IconName::Plus)
                    .ghost()
                    .tooltip(self.t(Text::NewTask))
                    .accessibility_label(self.t(Text::NewTask))
                    .on_click(cx.listener(|this, _, window, cx| {
                        this.active = None;
                        this.navigate(Page::Actions, window, cx)
                    })),
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
