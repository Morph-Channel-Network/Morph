use super::*;

impl Desktop {
    /// Render already checked canonical terms. No byte decoding or authority is introduced here.
    pub(super) fn render_checked_terms(&self, value: &Value, cx: &mut Context<Self>) -> Div {
        let summary = value.get("summary").unwrap_or(value);
        let mut view = div().flex().flex_col().gap_4();
        if let Some(carrier) = summary["state_carrier_capacity"].as_str() {
            view = view.child(d::key_value(
                self.t(Text::StateCarrier),
                p::amount(carrier, true, self.language),
            ));
        }
        if let Some(assets) = summary["assets"].as_array() {
            let mut card = div()
                .flex()
                .flex_col()
                .gap_3()
                .child(
                    div()
                        .font_weight(FontWeight::SEMIBOLD)
                        .child(self.t(Text::CommittedCustodyByAsset)),
                )
                .child(d::caption(self.t(Text::CKBReserveBusinessValueAndToken)));
            for (i, asset) in assets.iter().enumerate() {
                card = card.child(d::rule()).child(self.copyable_fact(
                    1000 + i,
                    self.t(Text::AssetType),
                    asset["type_hash"].as_str().unwrap_or("CKB").to_owned(),
                    cx,
                ));
                card = card
                    .child(self.render_value_lanes(asset, asset["type_hash"].as_str().is_some()));
            }
            view = view.child(card);
        }
        let signers = summary
            .get("signer_pubkeys")
            .or_else(|| summary.get("participants"))
            .and_then(Value::as_array);
        if let Some(signers) = signers {
            let mut members = div()
                .flex()
                .flex_col()
                .gap_2()
                .child(d::caption(self.t(Text::CommittedParticipants)));
            for (i, key) in signers.iter().filter_map(Value::as_str).enumerate() {
                members = members.child(self.copyable_fact(
                    1100 + i,
                    &format!("{} {}", self.t(Text::Participant), i + 1),
                    key.into(),
                    cx,
                ));
            }
            view = view.child(members);
        }
        let capability = value
            .get("capability")
            .or_else(|| summary.get("capability"));
        if let Some(capability) = capability {
            match capability["kind"].as_str() {
                Some("ordinary") => {
                    view = view.child(d::badge(self.t(Text::OrdinarySettlement), Tone::Neutral))
                }
                Some("ckb_conditional") => {
                    let mut conditions = div()
                        .flex()
                        .flex_col()
                        .gap_3()
                        .child(d::badge(self.t(Text::ConditionalCKBSettlement), Tone::Info));
                    if let Some(amount) = capability["pending_ckb"].as_str() {
                        conditions = conditions.child(d::key_value(
                            self.t(Text::PendingConditions),
                            p::amount(amount, true, self.language),
                        ));
                    }
                    if let Some(transfers) = capability["transfers"].as_array() {
                        for (i, transfer) in transfers.iter().enumerate() {
                            conditions = conditions.child(d::rule()).child(d::caption(format!(
                                "{} {}",
                                self.t(Text::Condition),
                                i + 1
                            )));
                            if let Some(amount) = transfer["amount"].as_str() {
                                conditions = conditions.child(d::key_value(
                                    self.t(Text::Amount),
                                    p::amount(amount, true, self.language),
                                ));
                            }
                            if let Some(hash) = transfer["payment_hash"].as_str() {
                                conditions = conditions.child(self.copyable_fact(
                                    1200 + i,
                                    self.t(Text::PaymentHash),
                                    hash.into(),
                                    cx,
                                ));
                            }
                            if let Some(since) = transfer["refund_after_block"].as_str() {
                                conditions = conditions.child(d::key_value(
                                    self.t(Text::RefundSince),
                                    since.to_owned(),
                                ));
                            }
                        }
                    }
                    view = view.child(conditions);
                }
                _ => {}
            }
        }
        if let Some(payouts) = value["payouts"].as_array() {
            let mut payouts_view = div()
                .flex()
                .flex_col()
                .gap_3()
                .child(
                    div()
                        .font_weight(FontWeight::SEMIBOLD)
                        .child(self.t(Text::SettlementAllocations)),
                )
                .child(d::caption(
                    self.t(Text::ParticipantIndexesFollowTheCanonicalPackage),
                ));
            for (index, payout) in payouts.iter().enumerate() {
                payouts_view = payouts_view.child(d::rule()).child(self.copyable_fact(
                    1300 + index,
                    self.t(Text::AssetType),
                    payout["type_hash"].as_str().unwrap_or("CKB").into(),
                    cx,
                ));
                if let Some(allocations) = payout["allocations"].as_array() {
                    for (i, allocation) in allocations.iter().enumerate() {
                        payouts_view = payouts_view
                            .child(d::caption(format!(
                                "{} {}",
                                self.t(Text::Participant),
                                i + 1
                            )))
                            .child(self.render_value_lanes(
                                allocation,
                                payout["type_hash"].as_str().is_some(),
                            ));
                    }
                }
            }
            view = view.child(payouts_view);
        }
        view
    }

    fn render_value_lanes(&self, value: &Value, token: bool) -> Div {
        let mut row = div().flex().flex_wrap().gap_4();
        for (key, label) in [
            ("reserve", Text::CKBReserve),
            ("business_ckb", Text::CKBBusiness),
        ] {
            if let Some(amount) = value[key].as_str() {
                row = row.child(
                    div()
                        .min_w(px(175.))
                        .flex_1()
                        .flex()
                        .flex_col()
                        .gap_1()
                        .child(d::caption(self.t(label)))
                        .child(p::amount(amount, true, self.language)),
                );
            }
        }
        let mut lanes = div().flex().flex_col().gap_3().child(row);
        if token && let Some(amount) = value["amount"].as_str() {
            lanes = lanes.child(
                div()
                    .w_full()
                    .min_w_0()
                    .flex()
                    .flex_col()
                    .gap_1()
                    .child(d::caption(self.t(Text::TokenBaseUnits)))
                    .child(p::amount(amount, false, self.language)),
            );
        }
        lanes
    }
}
