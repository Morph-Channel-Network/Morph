use super::*;

impl Desktop {
    /// Pointer and keyboard selection share one path. Geometry belongs to each control.
    pub(super) fn segments(
        &self,
        id: &'static str,
        labels: Vec<String>,
        selected: usize,
        choose: fn(&mut Desktop, usize, &mut Window, &mut Context<Desktop>),
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Div {
        let enabled = self.motion_enabled(window, cx);
        let count = labels.len();
        let handles = window
            .use_keyed_state(
                (gpui_kit::ElementId::Name(id.into()), "focus"),
                cx,
                |_, cx| (0..count).map(|_| cx.focus_handle()).collect::<Vec<_>>(),
            )
            .read(cx)
            .clone();
        let mut buttons = Vec::new();
        for (index, label) in labels.into_iter().enumerate() {
            let focus = handles[index].clone();
            let keys = handles.clone();
            let button = Button::new((id, index))
                .ghost()
                .label(label)
                .selected(index == selected)
                .track_focus(&focus)
                .on_click(cx.listener(move |this, _, window, cx| {
                    window.focus(&focus, cx);
                    choose(this, index, window, cx);
                }))
                .on_key_down(cx.listener(
                    move |this, event: &gpui_kit::KeyDownEvent, window, cx| {
                        if event.keystroke.modifiers.control
                            || event.keystroke.modifiers.alt
                            || event.keystroke.modifiers.platform
                        {
                            return;
                        }
                        let next = match event.keystroke.key.as_str() {
                            "left" => (index + count - 1) % count,
                            "right" => (index + 1) % count,
                            "home" => 0,
                            "end" => count - 1,
                            _ => return,
                        };
                        cx.stop_propagation();
                        window.focus(&keys[next], cx);
                        choose(this, next, window, cx);
                    },
                ));
            buttons.push((button, index == selected));
        }
        div().flex().child(
            crate::motion::rail(id, buttons, false, enabled, window, cx)
                .rounded(px(12.))
                .bg(rgb(d::SIDEBAR)),
        )
    }
}

impl Desktop {
    pub(super) fn original_text(
        &self,
        id: impl Into<gpui_kit::ElementId>,
        label: Text,
        raw: String,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Div {
        let id = id.into();
        let expanded = window.use_keyed_state((id.clone(), "expanded"), cx, |_, _| false);
        let shown = *expanded.read(cx);
        let mut view = div().flex().flex_col().gap_2().child(
            Button::new((id.clone(), "disclosure"))
                .ghost()
                .small()
                .icon(if shown {
                    IconName::ChevronDown
                } else {
                    IconName::ChevronRight
                })
                .label(self.t(if shown { Text::HideDiagnostic } else { label }))
                .on_click(move |_, _, cx| {
                    expanded.update(cx, |v, cx| {
                        *v = !*v;
                        cx.notify();
                    })
                }),
        );
        if shown {
            view = view.child(
                div()
                    .id((id, "original"))
                    .max_h(px(180. * self.scale()))
                    .overflow_y_scroll()
                    .text_sm()
                    .child(raw),
            );
        }
        view
    }
    pub(super) fn diagnostic(
        &self,
        id: impl Into<gpui_kit::ElementId>,
        raw: String,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Div {
        let summary = crate::i18n::diagnostic_summary(&raw, self.language);
        let mut view = div()
            .flex()
            .flex_col()
            .gap_2()
            .child(d::caption(summary).text_color(rgb(d::WARNING)));
        if crate::i18n::message_key(&raw).is_none() {
            view = view.child(self.original_text(id, Text::OriginalDiagnostic, raw, window, cx));
        }
        view
    }
    pub(super) fn service_message(
        &self,
        id: impl Into<gpui_kit::ElementId>,
        raw: String,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Div {
        let summary = if let Some(key) = crate::i18n::message_key(&raw) {
            self.t(key).to_owned()
        } else if let Some(flows) =
            raw.strip_prefix("restored completed_flows not present in live state will be ignored: ")
        {
            format!("{}: {flows}", self.t(Text::IgnoredRestoreFlows))
        } else {
            self.t(Text::UnknownServiceDetail).into()
        };
        div()
            .flex()
            .flex_col()
            .gap_2()
            .child(d::caption(summary))
            .child(self.original_text(id, Text::ServiceMessage, raw, window, cx))
    }
}
