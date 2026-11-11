//! Application-owned visual tokens and small native components.
use gpui_kit::component::Theme;
use gpui_kit::{Div, FontWeight, ParentElement, SharedString, Styled, div, px, rgb};
pub const BASE_FONT_SIZE: f32 = 16.;
pub const BG: u32 = 0x0e0d16;
pub const SIDEBAR: u32 = 0x12111d;
pub const PANEL: u32 = 0x191824;
pub const HOVER: u32 = 0x282438;
pub const BORDER: u32 = 0x302c40;
pub const TEXT: u32 = 0xf3eff7;
pub const MUTED: u32 = 0xb0aabd;
pub const DIM: u32 = 0x888197;
pub const ACCENT: u32 = 0xb3a6fa;
pub const ACCENT_BG: u32 = 0x342b4b;
pub const WARNING: u32 = 0xe9bd7c;
pub const DANGER: u32 = 0xf59b9b;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tone {
    Neutral,
    Good,
    Warning,
    Danger,
    Info,
}
impl Tone {
    pub fn color(self) -> u32 {
        match self {
            Self::Neutral => MUTED,
            Self::Good => 0x8cdbc2,
            Self::Warning => WARNING,
            Self::Danger => DANGER,
            Self::Info => 0xa0bbeb,
        }
    }
    pub fn background(self) -> u32 {
        match self {
            Self::Neutral => 0x24263b,
            Self::Good => 0x1b302e,
            Self::Warning => 0x332b25,
            Self::Danger => 0x352333,
            Self::Info => 0x242b49,
        }
    }
}
pub fn install(cx: &mut gpui_kit::App) {
    let fonts = cx.text_system().all_font_names();
    let preferred = [
        "Source Han Sans CN",
        "Noto Sans CJK SC",
        "Microsoft YaHei UI",
        "PingFang SC",
    ]
    .into_iter()
    .find(|candidate| fonts.iter().any(|name| name == candidate));
    Theme::update(cx, |t| {
        if let Some(family) = preferred {
            t.font_family = family.into();
        }
        t.font_size = px(BASE_FONT_SIZE);
        t.radius = px(9.);
        t.colors.background = rgb(BG).into();
        t.colors.foreground = rgb(TEXT).into();
        t.colors.primary = rgb(0x8068f3).into();
        t.colors.primary_foreground = rgb(0xffffff).into();
        t.colors.button_primary = rgb(0x8068f3).into();
        t.colors.button_primary_foreground = rgb(0xffffff).into();
        t.colors.button_primary_hover = rgb(0x9484ff).into();
        t.colors.button_primary_active = rgb(0x6a54d7).into();
        t.colors.border = rgb(BORDER).into();
        t.colors.input = rgb(BORDER).into();
        t.colors.button = rgb(0x1b1d30).into();
        t.colors.button_foreground = rgb(TEXT).into();
        t.colors.button_hover = rgb(HOVER).into();
        t.colors.button_active = rgb(ACCENT_BG).into();
        t.colors.button_secondary = rgb(0x1b1d30).into();
        t.colors.button_secondary_foreground = rgb(TEXT).into();
        t.colors.button_secondary_hover = rgb(HOVER).into();
        t.colors.button_secondary_active = rgb(ACCENT_BG).into();
        t.colors.secondary = rgb(0x1b1d30).into();
        t.colors.muted = rgb(0x1b1d30).into();
        t.colors.muted_foreground = rgb(DIM).into();
        t.colors.accent = rgb(ACCENT_BG).into();
        t.colors.accent_foreground = rgb(TEXT).into();
        t.colors.caret = rgb(ACCENT).into();
        t.colors.ring = rgb(0x8068f3).into();
        t.colors.selection = rgb(0x35305c).into();
        t.colors.secondary_active = rgb(ACCENT_BG).into();
        t.colors.secondary_hover = rgb(HOVER).into();
        t.colors.secondary_foreground = rgb(TEXT).into();
    });
}
pub fn panel() -> Div {
    div()
        .bg(rgb(PANEL))
        .border_1()
        .border_color(rgb(BORDER))
        .rounded(px(14.))
        .p_5()
}
pub fn title(text: impl Into<SharedString>) -> Div {
    div()
        .text_3xl()
        .font_weight(FontWeight::SEMIBOLD)
        .text_color(rgb(TEXT))
        .child(text.into())
}
pub fn caption(text: impl Into<SharedString>) -> Div {
    div().text_sm().text_color(rgb(MUTED)).child(text.into())
}
pub fn badge(text: impl Into<SharedString>, tone: Tone) -> Div {
    div()
        .self_start()
        .flex_shrink_0()
        .px_2()
        .py(px(3.))
        .rounded_md()
        .bg(rgb(tone.background()))
        .text_xs()
        .text_color(rgb(tone.color()))
        .child(text.into())
}
pub fn rule() -> Div {
    div().h(px(1.)).w_full().bg(rgb(BORDER))
}
pub fn key_value(label: impl Into<SharedString>, value: impl Into<SharedString>) -> Div {
    div()
        .flex()
        .gap_4()
        .py_2()
        .child(
            div()
                .w(px(138.))
                .flex_shrink_0()
                .text_sm()
                .text_color(rgb(MUTED))
                .child(label.into()),
        )
        .child(
            div()
                .flex_1()
                .min_w_0()
                .text_sm()
                .text_color(rgb(TEXT))
                .overflow_hidden()
                .child(value.into()),
        )
}

pub fn language_font(language: crate::i18n::Language, cx: &mut gpui_kit::App) {
    let installed = cx.text_system().all_font_names();
    let english = ["Inter", "Adwaita Sans", "Cantarell", "DejaVu Sans"];
    let chinese = [
        "Source Han Sans CN",
        "Noto Sans CJK SC",
        "Microsoft YaHei UI",
        "PingFang SC",
    ];
    let candidates = if language == crate::i18n::Language::Chinese {
        &chinese
    } else {
        &english
    };
    if let Some(name) = candidates
        .iter()
        .find(|candidate| installed.iter().any(|font| font == *candidate))
    {
        Theme::update(cx, |theme| theme.font_family = (*name).into());
    }
}

/// A consistent, quiet icon tile; decoration never replaces a text label.
pub fn icon_tile(icon: gpui_kit::assets::IconName) -> Div {
    use gpui_kit::component::Icon;
    div()
        .size(gpui_kit::rems(2.7))
        .flex_shrink_0()
        .rounded(px(12.))
        .flex()
        .items_center()
        .justify_center()
        .bg(rgb(ACCENT_BG))
        .child(
            Icon::new(icon)
                .size(gpui_kit::rems(1.2))
                .text_color(rgb(ACCENT)),
        )
}

/// Small semantic status lights, always paired with a readable label.
pub fn status(text: impl Into<SharedString>, tone: Tone) -> Div {
    div()
        .flex()
        .items_center()
        .gap_2()
        .text_sm()
        .text_color(rgb(MUTED))
        .child(div().size(px(6.)).rounded_full().bg(rgb(tone.color())))
        .child(text.into())
}
/// Short workflows have a readable width and share the center of the workspace.
pub fn workbench(content: impl gpui_kit::IntoElement, width: f32) -> Div {
    div()
        .w_full()
        .flex()
        .justify_center()
        .child(div().w_full().max_w(px(width)).min_w_0().child(content))
}
