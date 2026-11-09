//! Live language switching preserves input values, composition state and all protocol authority.
use crate::*;
impl Desktop {
    pub(crate) fn ui_preferences(&self) -> preferences::Preferences {
        preferences::Preferences {
            language: self.language,
            scale_percent: self.scale_percent,
            reduced_motion: self.reduced_motion,
        }
    }
    pub(crate) fn scale(&self) -> f32 {
        self.ui_preferences().scale()
    }
    pub(crate) fn motion_enabled(&self, window: &mut Window, cx: &mut App) -> bool {
        !self.reduced_motion
            && !cx.reduce_motion()
            && window.is_window_active()
            && window.is_visible()
    }
    fn apply_scale(&self, window: &mut Window, cx: &mut App) {
        let size = px(14. * self.scale());
        Theme::update(cx, |theme| theme.font_size = size);
        window.set_rem_size(size);
        window.refresh();
    }
    pub(crate) fn change_scale(&mut self, delta: i16, window: &mut Window, cx: &mut Context<Self>) {
        self.scale_percent = if delta == 0 {
            100
        } else {
            (self.scale_percent as i16 + delta).clamp(90, 150) as u16
        };
        self.locale_revision = self.locale_revision.saturating_add(1);
        self.preference_dirty = true;
        self.apply_scale(window, cx);
        cx.notify();
    }
    pub(crate) fn set_reduced_motion(&mut self, reduced: bool, cx: &mut Context<Self>) {
        self.reduced_motion = reduced;
        self.locale_revision = self.locale_revision.saturating_add(1);
        self.preference_dirty = true;
        cx.notify();
    }

    pub(crate) fn set_language(
        &mut self,
        language: Language,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.locale_revision = self.locale_revision.saturating_add(1);
        self.preference_dirty = true;
        self.apply_language(language, window, cx);
    }
    fn apply_language(&mut self, language: Language, window: &mut Window, cx: &mut Context<Self>) {
        self.language = language;
        gpui_kit::component::set_locale(language.code());
        design::language_font(language, cx);
        window.set_window_title(language.t(Text::MorphWorkspace));
        for (input, text) in [
            (&self.search, Text::SearchRecords),
            (&self.activity_search, Text::SearchTasks),
            (&self.token, Text::AccessToken),
        ] {
            input.update(cx, |v, cx| v.set_placeholder(language.t(text), window, cx));
        }
        for (slot, input) in self.inspector.iter().enumerate() {
            let text = [
                Text::MainDocument,
                Text::SignedBaseRecovery,
                Text::DetachedReceipt,
            ][slot];
            input.update(cx, |v, cx| v.set_placeholder(language.t(text), window, cx));
        }
        for (key, draft) in &self.drafts {
            draft.target_search.update(cx, |v, cx| {
                v.set_placeholder(language.t(Text::SearchObjects), window, cx)
            });
            for (name, input) in &draft.fields {
                if let Some(field) = forms::FORMS[key.form]
                    .fields
                    .iter()
                    .find(|f| f.key == *name)
                {
                    input.update(cx, |v, cx| {
                        v.set_placeholder(language.t(field.label), window, cx)
                    });
                }
            }
            draft.documents[0].update(cx, |v, cx| {
                v.set_placeholder(language.t(Text::PasteCurrentJSON), window, cx)
            });
        }
        self.rebuild();
        cx.notify();
    }
    pub(crate) fn poll_preferences(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        for _ in 0..2 {
            let event = self
                .preferences
                .as_ref()
                .and_then(|p| p.events.try_recv().ok());
            match event {
                Some(preferences::Event::Loaded(Ok(Some(settings))))
                    if self.locale_revision == 0 =>
                {
                    self.scale_percent = settings.scale_percent;
                    self.reduced_motion = settings.reduced_motion;
                    self.apply_scale(window, cx);
                    self.apply_language(settings.language, window, cx)
                }
                Some(preferences::Event::Loaded(Err(_))) => {
                    self.preference_failed = true;
                    cx.notify();
                }
                Some(preferences::Event::Saved(revision, result)) => {
                    if revision == self.locale_revision {
                        self.preference_failed = result.is_err();
                        cx.notify();
                    }
                }
                Some(_) => {}
                None => break,
            }
        }
        if self.preference_dirty
            && let Some(p) = &self.preferences
            && p.save(self.locale_revision, self.ui_preferences())
        {
            self.preference_dirty = false;
        }
    }
}
