use super::*;

impl Desktop {
    pub(super) fn activity_tabs(&self, window: &mut Window, cx: &mut Context<Self>) -> Div {
        self.segments(
            "activity-tabs",
            vec![
                self.t(Text::SessionTasks).into(),
                self.t(Text::HubEvents).into(),
            ],
            usize::from(self.hub_activity),
            |this, index, _, cx| {
                this.hub_activity = index == 1;
                this.rebuild();
                cx.notify();
            },
            window,
            cx,
        )
    }

    pub(super) fn render_activity(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let mut view = div()
            .id("activity-scroll")
            .flex_1()
            .min_h_0()
            .overflow_y_scroll()
            .flex()
            .flex_col()
            .gap_4()
            .child(title_row(
                self.t(Text::Activity),
                self.t(Text::TaskResultsStayHereWhileBackground),
            ))
            .child(self.activity_tabs(window, cx));
        if !self.network_jobs.is_empty() {
            view = view.child(
                Button::new("stop-network-wait")
                    .label(self.t(Text::StopWaitingForNetworkTasks))
                    .on_click(cx.listener(|this, _, _, cx| this.stop_network(cx))),
            );
        }
        if self.activities.is_empty() {
            return view.child(empty_state(
                IconName::Activity,
                self.t(Text::NoSessionTasksYet),
                self.t(Text::ConnectionEvidenceAndRecordActionsWill),
            ));
        }
        let labels = ActivityFilter::ALL
            .into_iter()
            .map(|filter| {
                format!(
                    "{} {}",
                    filter.label(self.language),
                    self.activities
                        .iter()
                        .filter(|e| filter.matches(e.status))
                        .count()
                )
            })
            .collect();
        let selected = ActivityFilter::ALL
            .iter()
            .position(|f| *f == self.activity_filter)
            .unwrap_or(0);
        let filters = self.segments(
            "activity-filter",
            labels,
            selected,
            |this, index, _, cx| {
                this.activity_filter = ActivityFilter::ALL[index];
                cx.notify();
            },
            window,
            cx,
        );
        view = view.child(filters).child(
            Input::new(&self.activity_search)
                .id("activity-search")
                .cleanable(true),
        );
        let tokens = self
            .activity_search
            .read(cx)
            .value()
            .split_whitespace()
            .map(str::to_lowercase)
            .collect::<Vec<_>>();
        let entries = self
            .activities
            .iter()
            .rev()
            .filter(|e| self.activity_filter.matches(e.status))
            .filter(|e| {
                let text = format!(
                    "{} {} {} {}",
                    e.title,
                    e.detail,
                    e.resource,
                    e.status.label(self.language)
                )
                .to_lowercase();
                tokens.iter().all(|t| text.contains(t))
            })
            .map(|e| {
                (
                    e.id,
                    crate::i18n::stored_copy(&e.title, self.language),
                    e.status,
                    crate::i18n::stored_copy(&e.detail, self.language),
                    e.resource.clone(),
                    e.elapsed,
                    e.output.is_some(),
                )
            })
            .collect::<Vec<_>>();
        if entries.is_empty() {
            return view.child(empty_state(
                IconName::Search,
                self.t(Text::NoMatchingTasks),
                self.t(Text::ChooseAllOrChangeYourSearch),
            ));
        }
        for (id, title, status, detail, resource, elapsed, output) in entries {
            let mut card = div()
                .flex_1()
                .min_w_0()
                .pb_5()
                .flex()
                .flex_col()
                .gap_3()
                .child(
                    div()
                        .flex()
                        .gap_3()
                        .items_center()
                        .child(
                            div()
                                .flex_1()
                                .min_w_0()
                                .font_weight(FontWeight::MEDIUM)
                                .child(title),
                        )
                        .child(d::badge(status.label(self.language), status_tone(status))),
                )
                .child(if matches!(status, Status::Failed | Status::Unknown) {
                    self.diagnostic(("activity-diagnostic", id as usize), detail, window, cx)
                } else {
                    div().child(d::caption(detail))
                });
            if !resource.is_empty() {
                card = card.child(d::caption(p::short(&resource)))
            }
            if let Some(t) = elapsed {
                card = card.child(d::caption(format!(
                    "{:.1} {}",
                    t.as_secs_f64(),
                    self.t(Text::Seconds)
                )))
            }
            if output {
                card = card.child(
                    Button::new(("task-output", id as usize))
                        .label(self.t(Text::ViewSavedResult))
                        .on_click(cx.listener(move |this, _, window, cx| {
                            this.select_activity(id, window, cx);
                            this.technical = false
                        })),
                );
            }
            if self.selected_activity == Some(id) && self.result.is_some() {
                card = card.child(self.render_result_card(cx));
            }
            let tone = status_tone(status);
            let icon = match status {
                Status::Running => IconName::Activity,
                Status::Done | Status::Reviewed => IconName::Check,
                Status::Failed | Status::Unknown => IconName::CircleAlert,
                Status::Stopped => IconName::X,
            };
            view = view.child(
                div()
                    .flex()
                    .gap_4()
                    .child(
                        div()
                            .w(px(36.))
                            .flex_shrink_0()
                            .flex()
                            .flex_col()
                            .items_center()
                            .gap_2()
                            .child(
                                div()
                                    .size(px(32.))
                                    .rounded_full()
                                    .bg(rgb(tone.background()))
                                    .flex()
                                    .items_center()
                                    .justify_center()
                                    .child(
                                        Icon::new(icon).size(px(15.)).text_color(rgb(tone.color())),
                                    ),
                            )
                            .child(div().flex_1().min_h(px(10.)).w(px(1.)).bg(rgb(d::BORDER))),
                    )
                    .child(card),
            );
        }
        view
    }

    pub(super) fn render_result_card(&mut self, cx: &mut Context<Self>) -> Div {
        let mut card = d::panel().flex().flex_col().gap_4().child(
            div()
                .flex()
                .items_center()
                .gap_3()
                .child(
                    div()
                        .flex_1()
                        .text_lg()
                        .font_weight(FontWeight::MEDIUM)
                        .child(crate::i18n::stored_copy(&self.result_title, self.language)),
                )
                .child(d::badge(
                    crate::i18n::stored_copy(&self.result_source, self.language),
                    Tone::Info,
                )),
        );
        let value = self
            .result_review
            .as_ref()
            .or(self.result.as_ref())
            .cloned()
            .unwrap_or(Value::Null);
        let summary = value.get("summary").unwrap_or(&value);
        for (i, (key, label)) in [
            ("channel_id", Text::Channel),
            ("funding_context_id", Text::FundingContext),
            ("transaction_hash", Text::Transaction),
            ("state_number", Text::StateNumber),
            ("vault_count", Text::VaultCount),
            ("package_id", Text::PackageID2),
            ("schema", Text::Format),
            ("signer_pubkey", Text::ReceiptSigner),
            ("pubkey", Text::PublicKey),
            ("signing_digest", Text::RoleDigest),
            ("request_id", Text::RequestID),
            ("old_funding_context_id", Text::PreviousContext),
            ("new_funding_context_id", Text::NewContext),
        ]
        .into_iter()
        .enumerate()
        {
            if !summary[key].is_null() {
                let raw = summary[key]
                    .as_str()
                    .map(str::to_owned)
                    .unwrap_or_else(|| summary[key].to_string());
                card = card.child(self.copyable_fact(400 + i, self.t(label), raw, cx));
            }
        }
        if self.result_checked {
            card = card.child(self.render_checked_terms(&value, cx));
        }
        card = card.child(d::caption(if self.result_private {
            self.t(Text::ThisResultIncludesThePrivateOriginal)
        } else {
            self.t(Text::ThisIsAReviewOrRecord)
        }));
        card.child(
            div()
                .flex()
                .flex_wrap()
                .gap_3()
                .child(
                    Button::new("save-result")
                        .icon(IconName::Download)
                        .label(if self.result_private {
                            self.t(Text::SavePrivateOriginal)
                        } else {
                            self.t(Text::SaveViewReview)
                        })
                        .disabled(self.file_busy() || self.dialog_pending)
                        .on_click(cx.listener(|this, _, _, cx| this.save_file(cx))),
                )
                .child(
                    Button::new("open-result-technical")
                        .icon(IconName::Code)
                        .ghost()
                        .label(self.t(Text::TechnicalDetails))
                        .on_click(cx.listener(|this, _, _, cx| {
                            this.technical = true;
                            cx.notify()
                        })),
                ),
        )
    }
}
