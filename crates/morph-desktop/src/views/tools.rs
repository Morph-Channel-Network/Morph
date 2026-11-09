use super::*;

impl Desktop {
    pub(super) fn render_inspector(
        &mut self,
        _window: &mut Window,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let mut view = div()
            .id("inspector-scroll")
            .flex_1()
            .min_h_0()
            .overflow_y_scroll()
            .flex()
            .flex_col()
            .gap_4()
            .child(title_row(
                self.t(Text::ReviewEvidenceOffline),
                self.t(Text::StartWithOneDocumentAddBase),
            ));
        if self.result.is_some()
            && self.result_target == ResultTarget::Inspector(self.inspector_revision)
        {
            return view.child(self.render_result_card(cx)).child(
                Button::new("edit-reviewed-evidence")
                    .icon(IconName::ArrowLeft)
                    .label(self.t(Text::BackToDocuments))
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.result_target = ResultTarget::None;
                        cx.notify();
                    })),
            );
        }
        let extras = self
            .inspector
            .iter()
            .skip(1)
            .filter(|e| !e.read(cx).value().trim().is_empty())
            .count();
        for (i, label) in [
            (Text::MainDocument),
            (Text::SignedBaseRecovery),
            (Text::DetachedSignatureReceipt),
        ]
        .into_iter()
        .enumerate()
        {
            if i > 0 && !self.inspector_advanced {
                continue;
            }
            let target = DocumentTarget::Inspector(i);
            let input = self.inspector[i].clone();
            let empty = input.read(cx).value().trim().is_empty();
            let mut card = d::panel()
                .flex()
                .flex_col()
                .gap_3()
                .child(
                    div()
                        .flex()
                        .flex_wrap()
                        .gap_3()
                        .items_center()
                        .child(
                            div()
                                .flex_1()
                                .min_w_0()
                                .font_weight(FontWeight::MEDIUM)
                                .child(self.t(label)),
                        )
                        .child(
                            Button::new(("open-document", i))
                                .icon(IconName::FolderOpen)
                                .accessibility_label(format!(
                                    "{} · {}",
                                    self.t(Text::OpenFile),
                                    self.t(label)
                                ))
                                .label(self.t(Text::OpenJSON))
                                .disabled(self.file_busy() || self.dialog_pending)
                                .on_click(cx.listener(move |this, _, _, cx| {
                                    this.open_file(target.clone(), cx)
                                })),
                        ),
                )
                .child(d::caption(if i == 0 {
                    self.t(Text::CurrentRecoveryFundingProposalSpliceOr)
                } else if i == 1 {
                    self.t(Text::RequiredForProposalAndSpliceReview)
                } else {
                    self.t(Text::ChecksAReceiptAgainstTheExplicit)
                }));
            if let Some(info) = &self.inspector_files[i] {
                card = card.child(d::badge(
                    format!(
                        "{} · {} · {} {}",
                        info.name,
                        info.schema,
                        info.bytes,
                        self.t(Text::Bytes)
                    ),
                    Tone::Neutral,
                ));
            } else if !empty {
                let text = input.read(cx).value();
                card = card.child(d::caption(format!(
                    "{} · {} {}",
                    self.t(Text::EditedJSON),
                    text.len(),
                    self.t(Text::Bytes)
                )));
            }
            card = card.child(
                Textarea::new(&input)
                    .font_family("monospace")
                    .text_size(gpui_kit::rems(13. / 14.))
                    .h(px(if i == 0 { 220. } else { 140. })),
            );
            if !empty {
                card = card.child(
                    Button::new(("clear-inspector", i))
                        .ghost()
                        .small()
                        .icon(IconName::X)
                        .label(self.t(Text::RemoveDocument))
                        .accessibility_label(format!(
                            "{} · {}",
                            self.t(Text::Remove),
                            self.t(label)
                        ))
                        .on_click(cx.listener(move |this, _, window, cx| {
                            this.inspector[i].update(cx, |v, cx| v.set_value("", window, cx));
                            this.inspector_files[i] = None;
                        })),
                );
            }
            view = view.child(card);
            if i == 0 {
                view = view.child(
                    Button::new("toggle-inspector-extras")
                        .ghost()
                        .icon(if self.inspector_advanced {
                            IconName::ChevronDown
                        } else {
                            IconName::ChevronRight
                        })
                        .label(if self.inspector_advanced {
                            self.t(Text::CollapseSupportingDocuments).to_owned()
                        } else {
                            format!(
                                "{}{}",
                                self.t(Text::AddBaseRecoveryReceipt),
                                if extras > 0 {
                                    format!(" · {} {}", extras, self.t(Text::Loaded))
                                } else {
                                    String::new()
                                }
                            )
                        })
                        .on_click(cx.listener(|this, _, _, cx| {
                            this.inspector_advanced = !this.inspector_advanced;
                            cx.notify();
                        })),
                );
                if !self.inspector_advanced && extras > 0 {
                    view = view.child(d::caption(
                        self.t(Text::LoadedSupportingDocumentsAreIncludedIn),
                    ));
                }
            }
        }
        if let Some(error) = &self.inspector_error {
            view = view.child(
                d::panel()
                    .border_color(rgb(d::DANGER))
                    .child(d::caption(self.t(Text::CheckTheEvidence)))
                    .child(div().mt_2().text_color(rgb(d::DANGER)).child(error.clone())),
            );
        }
        view = view.child(
            div()
                .flex()
                .flex_wrap()
                .gap_3()
                .items_center()
                .child(
                    Button::new("inspect-evidence")
                        .primary()
                        .icon(IconName::FileCheck)
                        .label(self.t(Text::ReviewTheseExactContents))
                        .disabled(
                            self.file_busy()
                                || self.dialog_pending
                                || self.inspector[0].read(cx).value().trim().is_empty(),
                        )
                        .on_click(cx.listener(|this, _, _, cx| this.inspect(cx))),
                )
                .child(d::caption(
                    self.t(Text::OfflineContentCheckNoChainObservation),
                )),
        );
        view
    }

    pub(super) fn render_technical(
        &mut self,
        _window: &mut Window,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let mut pane = div()
            .id("technical-scroll")
            .overflow_y_scroll()
            .h_full()
            .flex_1()
            .min_w_0()
            .flex()
            .flex_col()
            .gap_4()
            .p_5()
            .bg(rgb(d::PANEL))
            .border_l_1()
            .border_color(rgb(d::BORDER))
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_3()
                    .child(
                        div()
                            .flex_1()
                            .text_lg()
                            .font_weight(FontWeight::SEMIBOLD)
                            .child(self.t(Text::TechnicalDetails)),
                    )
                    .child(
                        Button::new("close-technical")
                            .icon(IconName::X)
                            .ghost()
                            .tooltip(self.t(Text::CloseDetails))
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.technical = false;
                                cx.notify()
                            })),
                    ),
            )
            .child(d::caption(
                if matches!(self.result_target, ResultTarget::Record(..)) {
                    self.result_title.clone()
                } else {
                    crate::i18n::stored_copy(&self.result_title, self.language)
                },
            ))
            .child(d::badge(
                crate::i18n::stored_copy(&self.result_source, self.language),
                Tone::Neutral,
            ));
        if self.result.is_none() {
            return pane.child(d::caption(self.t(Text::SelectARecordOrACompleted)));
        }
        pane = pane
            .child(d::caption(
                self.t(Text::PrivateSignaturesPreimagesAndTransactionBytes),
            ))
            .child(
                Button::new("toggle-raw-details")
                    .ghost()
                    .small()
                    .label(if self.raw_details {
                        self.t(Text::HidePrivateValues)
                    } else {
                        self.t(Text::RevealOriginalJSON)
                    })
                    .on_click(cx.listener(|this, _, window, cx| {
                        this.raw_details = !this.raw_details;
                        this.update_output(window, cx);
                        cx.notify()
                    })),
            )
            .child(
                Textarea::new(&self.output)
                    .font_family("monospace")
                    .text_size(gpui_kit::rems(13. / 14.))
                    .readonly(true)
                    .h(px(360.)),
            )
            .child(
                div()
                    .flex()
                    .gap_3()
                    .child(
                        Button::new("copy-result")
                            .icon(IconName::Copy)
                            .label(if self.raw_details {
                                self.t(Text::CopyOriginalJSON)
                            } else {
                                self.t(Text::CopyRedactedView)
                            })
                            .on_click(cx.listener(|this, _, _, cx| {
                                let mut value = this.result.clone().unwrap_or(Value::Null);
                                if !this.raw_details {
                                    crate::redact(&mut value)
                                }
                                if let Ok(text) = serde_json::to_string_pretty(&value) {
                                    cx.write_to_clipboard(ClipboardItem::new_string(text))
                                }
                            })),
                    )
                    .child(
                        Button::new("technical-save-result")
                            .icon(IconName::Download)
                            .label(self.t(Text::SaveOriginal))
                            .disabled(self.file_busy() || self.dialog_pending)
                            .on_click(cx.listener(|this, _, _, cx| this.save_file(cx))),
                    ),
            );
        pane
    }
}
