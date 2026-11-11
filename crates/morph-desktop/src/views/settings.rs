use super::*;
use gpui_kit::TestSupportExt;

impl Desktop {
    pub(super) fn render_settings(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let mut view = div()
            .id("settings-scroll")
            .test_support()
            .flex_1()
            .min_h_0()
            .overflow_y_scroll()
            .flex()
            .flex_col()
            .gap_5()
            .child(title_row(
                if self.appearance_settings {
                    self.t(Text::Appearance)
                } else {
                    self.t(Text::ConnectionSettings2)
                },
                if self.appearance_settings {
                    self.t(Text::ScaleHelp)
                } else {
                    self.t(Text::ConnectionCredentialsStayInMemoryChannel)
                },
            ));
        view = view.child(self.segments(
            "settings-tabs",
            vec![
                self.t(Text::Connection).into(),
                self.t(Text::Appearance).into(),
            ],
            usize::from(self.appearance_settings),
            |this, index, _, cx| {
                this.appearance_settings = index == 1;
                cx.notify();
            },
            window,
            cx,
        ));
        if self.appearance_settings {
            view = view.child(
                d::panel()
                    .w_full()
                    .max_w(px(760. * self.scale()))
                    .self_center()
                    .flex()
                    .items_center()
                    .flex_wrap()
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
                                    .child(self.t(Text::Language)),
                            )
                            .child(d::caption(self.t(Text::PreferencesSavedOnThisDevice))),
                    )
                    .child(
                        Button::new("language-zh")
                            .label("简体中文")
                            .selected(self.language == Language::Chinese)
                            .on_click(cx.listener(|this, _, window, cx| {
                                this.set_language(Language::Chinese, window, cx)
                            })),
                    )
                    .child(
                        Button::new("language-en")
                            .label("English")
                            .selected(self.language == Language::English)
                            .on_click(cx.listener(|this, _, window, cx| {
                                this.set_language(Language::English, window, cx)
                            })),
                    ),
            );
            view = view.child(
                d::panel()
                    .w_full()
                    .max_w(px(760. * self.scale()))
                    .self_center()
                    .flex()
                    .flex_col()
                    .gap_4()
                    .child(
                        div()
                            .text_lg()
                            .font_weight(FontWeight::MEDIUM)
                            .child(self.t(Text::Appearance)),
                    )
                    .child(
                        div()
                            .flex()
                            .flex_wrap()
                            .items_center()
                            .gap_3()
                            .child(div().flex_1().child(self.t(Text::InterfaceScale)))
                            .child(
                                Button::new("smaller-text")
                                    .label("A−")
                                    .tooltip(self.t(Text::SmallerType))
                                    .accessibility_label(self.t(Text::SmallerType))
                                    .disabled(self.scale_percent <= 90)
                                    .on_click(cx.listener(|this, _, window, cx| {
                                        this.change_scale(-10, window, cx)
                                    })),
                            )
                            .child(div().w(px(56.)).child(format!("{}%", self.scale_percent)))
                            .child(
                                Button::new("larger-text")
                                    .label("A+")
                                    .tooltip(self.t(Text::LargerType))
                                    .accessibility_label(self.t(Text::LargerType))
                                    .disabled(self.scale_percent >= 150)
                                    .on_click(cx.listener(|this, _, window, cx| {
                                        this.change_scale(10, window, cx)
                                    })),
                            )
                            .child(
                                Button::new("reset-text")
                                    .ghost()
                                    .label(self.t(Text::ResetScale))
                                    .on_click(cx.listener(|this, _, window, cx| {
                                        this.change_scale(0, window, cx)
                                    })),
                            ),
                    )
                    .child(d::rule())
                    .child(d::caption(self.t(Text::MotionHelp)))
                    .child(
                        div()
                            .flex()
                            .flex_wrap()
                            .gap_3()
                            .child(
                                Button::new("motion-system")
                                    .label(self.t(Text::FollowSystem))
                                    .selected(!self.reduced_motion)
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.set_reduced_motion(false, cx)
                                    })),
                            )
                            .child(
                                Button::new("motion-reduced")
                                    .label(self.t(Text::ReduceMotion))
                                    .selected(self.reduced_motion)
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.set_reduced_motion(true, cx)
                                    })),
                            ),
                    ),
            );
            if self.preference_failed || self.preferences.is_none() {
                view = view.child(
                    d::caption(self.t(Text::YourLanguageSelectionRemainsActiveFor))
                        .text_color(rgb(d::WARNING)),
                );
            }
            return view;
        }
        let mut connection = d::panel()
            .w_full()
            .max_w(px(760. * self.scale()))
            .self_center()
            .flex()
            .flex_col()
            .gap_4()
            .child(
                div()
                    .text_lg()
                    .font_weight(FontWeight::SEMIBOLD)
                    .child(self.t(Text::HubConnection)),
            )
            .child(d::caption(self.t(Text::HTTPSOriginOrExplicitLoopbackHTTP)))
            .child(
                div()
                    .child(d::caption(self.t(Text::HubAddress)))
                    .child(Input::new(&self.endpoint).id("endpoint")),
            )
            .child(
                div()
                    .child(d::caption(self.t(Text::BearerTokenMemoryOnly)))
                    .child(Input::new(&self.token).id("hub-token").mask_toggle()),
            );
        if self.connected {
            connection = connection.child(d::key_value(
                self.t(Text::ActiveConnection),
                self.connected_endpoint.clone(),
            ));
        }
        if let Some(error) = &self.connection_error {
            connection =
                connection.child(self.diagnostic("connection-error", error.clone(), window, cx));
        }
        connection = connection.child(
            div()
                .flex()
                .gap_3()
                .child(
                    Button::new("connect")
                        .primary()
                        .icon(IconName::Plug)
                        .label(if self.connected {
                            self.t(Text::ReconnectWithTheseSettings)
                        } else {
                            self.t(Text::ConnectWorkspace)
                        })
                        .disabled(self.foreground_busy())
                        .on_click(cx.listener(|this, _, window, cx| this.connect(window, cx))),
                )
                .child(
                    Button::new("disconnect")
                        .label(self.t(Text::Disconnect))
                        .disabled(!self.connected)
                        .on_click(cx.listener(|this, _, window, cx| this.disconnect(window, cx))),
                ),
        );
        view = view.child(connection);
        if let Some(s) = &self.state {
            let node = s.pubkey.clone();
            let scopes = s
                .security
                .auth_scopes
                .iter()
                .map(|scope| p::scope_name(*scope, self.language))
                .collect::<Vec<_>>()
                .join(" · ");
            let capabilities = d::panel()
                .w_full()
                .max_w(px(760. * self.scale()))
                .self_center()
                .flex()
                .flex_col()
                .gap_3()
                .child(
                    div()
                        .text_lg()
                        .font_weight(FontWeight::MEDIUM)
                        .child(self.t(Text::AccessCapabilityBoundary)),
                )
                .child(self.copyable_fact(900, self.t(Text::HubIdentity), node, cx))
                .child(d::key_value(
                    self.t(Text::Permissions),
                    if !s.security.auth_required {
                        self.t(Text::ExplicitUnauthenticatedLoopback).into()
                    } else {
                        scopes
                    },
                ))
                .child(d::key_value(
                    self.t(Text::InvoiceSigning),
                    if s.security.invoice_signing_enabled {
                        self.t(Text::Enabled)
                    } else {
                        self.t(Text::Disabled)
                    },
                ))
                .child(d::key_value(
                    self.t(Text::ChainActions),
                    if s.model.chain_actions_enabled {
                        self.t(Text::ServiceReportsEnabled)
                    } else {
                        self.t(Text::NotExposedByThisHub)
                    },
                ))
                .child(d::caption(self.t(Text::TheNativeAppManagesRecordsAnd)));
            view = view.child(capabilities);
        }
        view = view.child(
            d::panel()
                .w_full()
                .max_w(px(760. * self.scale()))
                .self_center()
                .flex()
                .flex_col()
                .gap_3()
                .child(div().text_lg().child(self.t(Text::PeerRecords)))
                .child(d::caption(
                    self.t(Text::ManageDisplayNamesAndPublicIdentities),
                ))
                .child(
                    Button::new("manage-peers")
                        .label(self.t(Text::OpenPeerRecords))
                        .on_click(cx.listener(|this, _, window, cx| {
                            this.navigate(Page::Peers, window, cx)
                        })),
                ),
        );
        let restore_reason = self.block_reason(HubOperation::PreviewRestore);
        view = view.child(
            d::panel()
                .w_full()
                .max_w(px(760. * self.scale()))
                .self_center()
                .border_color(rgb(0x5b3b39))
                .flex()
                .flex_col()
                .gap_4()
                .child(
                    div()
                        .text_lg()
                        .text_color(rgb(d::WARNING))
                        .child(self.t(Text::WorkspaceExportRestore)),
                )
                .child(d::caption(
                    self.t(Text::BootstrapWorkspaceRestorationIsSeparateFrom),
                ))
                .child(
                    div()
                        .flex()
                        .gap_3()
                        .child(
                            Button::new("export-workspace")
                                .icon(IconName::Download)
                                .label(self.t(Text::ExportWorkspace))
                                .disabled(self.block_reason(HubOperation::ExportState).is_some())
                                .on_click(cx.listener(|this, _, window, cx| {
                                    this.start_task(
                                        HubOperation::ExportState,
                                        String::new(),
                                        window,
                                        cx,
                                    )
                                })),
                        )
                        .child(
                            Button::new("preview-workspace-restore")
                                .label(self.t(Text::PreviewARestore))
                                .disabled(restore_reason.is_some())
                                .on_click(cx.listener(|this, _, window, cx| {
                                    this.start_task(
                                        HubOperation::PreviewRestore,
                                        String::new(),
                                        window,
                                        cx,
                                    )
                                })),
                        ),
                )
                .child(d::caption(restore_reason.unwrap_or_default())),
        );
        view.child(
            d::panel()
                .w_full()
                .max_w(px(760. * self.scale()))
                .self_center()
                .flex()
                .flex_col()
                .gap_3()
                .child(div().text_lg().child(self.t(Text::KeyboardNavigation)))
                .child(d::key_value("Ctrl K", self.t(Text::SearchWorkspace)))
                .child(d::key_value(
                    "Ctrl 1 / 2 / 3",
                    self.t(Text::OverviewChannelsFactory),
                ))
                .child(d::key_value("Ctrl N", self.t(Text::TaskCatalog)))
                .child(d::key_value("Ctrl R", self.t(Text::ReadFreshWorkspaceData)))
                .child(d::key_value("Alt ←", self.t(Text::CloseDetails)))
                .child(d::caption(self.t(Text::EnterAndEscapeKeepTheNative))),
        )
    }
}
