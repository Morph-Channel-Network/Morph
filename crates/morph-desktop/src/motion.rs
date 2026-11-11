//! Motion belongs to interactions and observed state, never to a demo timeline.
use gpui_kit::base::motion::{Transition, transition};
use gpui_kit::component::button::{Button, ButtonCustomVariant, ButtonVariants};
use gpui_kit::{
    Animation, AnimationExt, App, Bounds, Context, ElementId, IntoElement, ParentElement, Render,
    Styled, Window, canvas, div, fill, linear_color_stop, linear_gradient, point, relative, rgb,
    size,
};
use std::time::Duration;
pub const ENTER_DURATION: Duration = Duration::from_millis(210);

fn mix(a: u32, b: u32, t: f32) -> u32 {
    let mut out = 0;
    for shift in [0, 8, 16] {
        let a = ((a >> shift) & 255) as f32;
        let b = ((b >> shift) & 255) as f32;
        out |= ((a + (b - a) * t.clamp(0., 1.)).round() as u32) << shift;
    }
    out
}
/// Keep native button semantics/focus while interpolating its surface on pointer entry/exit.
pub fn interactive(
    button: Button,
    id: impl Into<ElementId>,
    enabled: bool,
    window: &mut Window,
    cx: &mut App,
) -> Button {
    let enabled =
        enabled && window.is_window_active() && window.is_visible() && !cx.reduce_motion();
    let id = id.into();
    let hover = window.use_keyed_state(
        ElementId::NamedChild(id.clone().into(), "surface-hover".into()),
        cx,
        |_, _| false,
    );
    let target = if *hover.read(cx) { 1. } else { 0. };
    let t = transition(
        (id, "surface-tint"),
        target,
        Transition::new(if enabled {
            Duration::from_millis(130)
        } else {
            Duration::ZERO
        }),
        window,
        cx,
    );
    let background = rgb(mix(0x141726, 0x242442, t));
    let border = rgb(mix(0x272b40, 0x6b61ab, t));
    // Button owns its hover style. Supplying InteractiveElement::hover a second time panics.
    button
        .custom(
            ButtonCustomVariant::new(cx)
                .color(background.into())
                .hover(background.into())
                .active(rgb(0x302b4d).into()),
        )
        .bg(background)
        .border_1()
        .border_color(border)
        .on_hover(move |inside, _, cx| {
            hover.update(cx, |value, cx| {
                if *value != *inside {
                    *value = *inside;
                    cx.notify();
                }
            })
        })
}
/// Selection stays inside its control. No inferred row offset or moving hit target.
pub fn selection(
    button: Button,
    id: impl Into<ElementId>,
    selected: bool,
    enabled: bool,
    window: &mut Window,
    cx: &mut App,
) -> Button {
    let t = selection_progress(id.into(), selected, enabled, window, cx);
    let fill = rgb(mix(crate::design::SIDEBAR, crate::design::ACCENT_BG, t));
    button
        .custom(
            ButtonCustomVariant::new(cx)
                .color(fill.into())
                .hover(rgb(crate::design::HOVER).into())
                .active(rgb(crate::design::ACCENT_BG).into()),
        )
        .bg(fill)
        .border_l_2()
        .border_color(rgb(mix(crate::design::SIDEBAR, crate::design::ACCENT, t)))
}

fn selection_progress(
    id: ElementId,
    selected: bool,
    enabled: bool,
    window: &mut Window,
    cx: &mut App,
) -> f32 {
    let enabled =
        enabled && window.is_window_active() && window.is_visible() && !cx.reduce_motion();
    transition(
        (id, "selection"),
        if selected { 1. } else { 0. },
        Transition::new(if enabled {
            Duration::from_millis(140)
        } else {
            Duration::ZERO
        }),
        window,
        cx,
    )
}

/// A measured selection surface. Every hit target remains at its layout position.
/// Prepaint records the selected child's bounds before any sibling is painted.
#[derive(Default)]
struct RailState {
    measured: Option<(usize, Bounds<gpui_kit::Pixels>)>,
    tween: RailTween,
}
#[derive(Default)]
struct RailTween {
    selected: Option<usize>,
    from: [f32; 4],
    target: [f32; 4],
    start: Option<std::time::Instant>,
}
impl RailTween {
    fn sample(
        &mut self,
        selected: usize,
        target: [f32; 4],
        now: std::time::Instant,
        animate: bool,
    ) -> ([f32; 4], bool) {
        let progress = self.start.map_or(1., |start| {
            (now.saturating_duration_since(start).as_secs_f32() / 0.22).min(1.)
        });
        let eased = 1. - (1. - progress).powi(3);
        let current =
            std::array::from_fn(|i| self.from[i] + (self.target[i] - self.from[i]) * eased);
        if !animate
            || self.selected.is_none()
            || (self.selected == Some(selected) && self.target != target)
        {
            // Geometry changes (resize, wrapping, language, text scale, scroll) are not navigation.
            self.from = target;
            self.target = target;
            self.start = None;
            self.selected = Some(selected);
            return (target, false);
        }
        if self.selected != Some(selected) {
            self.from = current;
            self.target = target;
            self.start = Some(now);
            self.selected = Some(selected);
            return (current, true);
        }
        (current, progress < 1.)
    }
}
/// Bounded, on-demand animation; no permanent timer, no guessed row height.
pub fn rail(
    id: &'static str,
    buttons: Vec<(Button, bool)>,
    vertical: bool,
    enabled: bool,
    window: &mut Window,
    cx: &mut App,
) -> gpui_kit::Stateful<gpui_kit::Div> {
    use gpui_kit::component::Selectable;
    use gpui_kit::{InteractiveElement, px, rgba};
    let state =
        window.use_keyed_state((ElementId::Name(id.into()), "rail-geometry"), cx, |_, _| {
            RailState::default()
        });
    state.update(cx, |s, _| s.measured = None);
    let paint = state.clone();
    let mut row = div().id(id).relative().flex().gap_1().p_1();
    row = if vertical {
        row.flex_col()
    } else {
        row.flex_wrap()
    };
    row = row.child(
        canvas(
            |_, _, _| (),
            move |_, _, window, cx| {
                let now = cx.background_executor().now();
                let active = enabled
                    && window.is_window_active()
                    && window.is_visible()
                    && !cx.reduce_motion();
                let geometry = paint.update(cx, |s, _| {
                    s.measured.map(|(index, bounds)| {
                        let target = [
                            bounds.left().into(),
                            bounds.top().into(),
                            bounds.size.width.into(),
                            bounds.size.height.into(),
                        ];
                        s.tween.sample(index, target, now, active)
                    })
                });
                if let Some(([x, y, w, h], running)) = geometry {
                    window.paint_quad(
                        fill(
                            Bounds::new(point(px(x), px(y)), size(px(w), px(h))),
                            rgb(crate::design::ACCENT_BG),
                        )
                        .corner_radii(px(9.)),
                    );
                    if running {
                        window.request_animation_frame();
                    }
                }
            },
        )
        .absolute()
        .size_full(),
    );
    for (index, (button, selected)) in buttons.into_iter().enumerate() {
        let measure = state.clone();
        let button = button.selected(false).toggled(selected).custom(
            ButtonCustomVariant::new(cx)
                .color(rgba(0x00000000).into())
                .hover(rgba(0xaca0f015).into())
                .active(rgba(0xaca0f028).into()),
        );
        let mut item = div().relative().flex_shrink_0();
        if vertical {
            item = item.w_full();
        }
        if selected {
            item = item.child(
                canvas(
                    move |bounds, _, cx| {
                        measure.update(cx, |s, _| s.measured = Some((index, bounds)));
                    },
                    |_, _, _, _| (),
                )
                .absolute()
                .size_full(),
            );
        }
        row = row.child(item.child(button));
    }
    row
}

/// A tiny, cached indicator for an actual outstanding foreground task.
#[derive(Default)]
pub struct TaskSignal {
    running: bool,
    enabled: bool,
}
impl TaskSignal {
    pub fn configure(&mut self, running: bool, enabled: bool, cx: &mut Context<Self>) {
        if self.running != running || self.enabled != enabled {
            self.running = running;
            self.enabled = enabled;
            cx.notify();
        }
    }
}
impl Render for TaskSignal {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let surface = div().size_full();
        if !self.running {
            return surface.into_any_element();
        }
        if !self.enabled || cx.reduce_motion() || !window.is_window_active() || !window.is_visible()
        {
            return surface.bg(rgb(crate::design::ACCENT)).into_any_element();
        }
        surface
            .with_animation(
                "foreground-work",
                Animation::new(Duration::from_millis(1400))
                    .repeat()
                    .with_max_fps(30.),
                |element, t| {
                    element.child(
                        canvas(
                            |_, _, _| (),
                            move |bounds, _, window, _| {
                                let width = bounds.size.width * 0.32;
                                let left = bounds.left() - width + (bounds.size.width + width) * t;
                                let start = left.max(bounds.left());
                                let end = (left + width).min(bounds.right());
                                if end > start {
                                    window.paint_quad(fill(
                                        Bounds::new(
                                            point(start, bounds.top()),
                                            size(end - start, bounds.size.height),
                                        ),
                                        linear_gradient(
                                            90.,
                                            linear_color_stop(rgb(0x647de8), 0.),
                                            linear_color_stop(rgb(0xb09aff), 1.),
                                        ),
                                    ));
                                }
                            },
                        )
                        .size_full(),
                    )
                },
            )
            .into_any_element()
    }
}
/// Three shares of a single asset. Exact quantities remain in the adjacent text.
pub struct Distribution {
    target: [f32; 3],
    enabled: bool,
}
impl Distribution {
    pub fn new(target: [f32; 3], enabled: bool) -> Self {
        Self { target, enabled }
    }
    pub fn configure(&mut self, target: [f32; 3], enabled: bool, cx: &mut Context<Self>) {
        if self.target != target || self.enabled != enabled {
            self.target = target;
            self.enabled = enabled;
            cx.notify();
        }
    }
}
impl Render for Distribution {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let animated = self.enabled && window.is_window_active() && window.is_visible();
        let duration = if animated {
            Duration::from_millis(280)
        } else {
            Duration::ZERO
        };
        let local = transition(
            "local-share",
            self.target[0],
            Transition::new(duration),
            window,
            cx,
        )
        .clamp(0., 1.);
        let pending = transition(
            "pending-share",
            self.target[2],
            Transition::new(duration),
            window,
            cx,
        )
        .clamp(0., 1. - local);
        let remote = (1. - local - pending).max(0.);
        div()
            .size_full()
            .rounded_full()
            .overflow_hidden()
            .flex()
            .child(div().h_full().w(relative(local)).bg(linear_gradient(
                90.,
                linear_color_stop(rgb(0x7b78ef), 0.),
                linear_color_stop(rgb(0x9f87ff), 1.),
            )))
            .child(div().h_full().w(relative(remote)).bg(rgb(0x425e91)))
            .child(
                div()
                    .h_full()
                    .w(relative(pending))
                    .bg(rgb(crate::design::WARNING)),
            )
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use gpui_kit::{
        AppContext, TestAppContext, WindowBounds, WindowOptions, px, test::TestWindowExt,
    };
    use std::{cell::Cell, rc::Rc};
    #[gpui_kit::test]
    fn task_signal_only_requests_frames_while_real_work_is_running(cx: &mut TestAppContext) {
        let handle = cx.update(|cx| {
            cx.open_window(
                WindowOptions {
                    window_bounds: Some(WindowBounds::Windowed(Bounds::new(
                        Default::default(),
                        size(px(600.), px(3.)),
                    ))),
                    ..Default::default()
                },
                |window, cx| {
                    window.activate_window();
                    cx.new(|_| TaskSignal::default())
                },
            )
            .unwrap()
        });
        cx.run_until_parked();
        let events = Rc::new(Cell::new(0));
        let seen = events.clone();
        let _sub = handle
            .update(cx, |v, _, cx| {
                let sub = cx.observe_self(move |_, _| seen.set(seen.get() + 1));
                v.configure(true, true, cx);
                sub
            })
            .unwrap();
        cx.update_window(handle.into(), |_, w, cx| w.render_frame(cx))
            .unwrap();
        cx.run_until_parked();
        let before = events.get();
        cx.executor().advance_clock(Duration::from_millis(80));
        cx.run_until_parked();
        assert!(events.get() > before);
        for (running, enabled) in [(false, true), (true, false)] {
            handle
                .update(cx, |v, _, cx| v.configure(running, enabled, cx))
                .unwrap();
            cx.update_window(handle.into(), |_, w, cx| w.render_frame(cx))
                .unwrap();
            // One callback already queued by the previous frame may drain, but must not reschedule.
            cx.executor().advance_clock(Duration::from_millis(80));
            cx.run_until_parked();
            cx.update_window(handle.into(), |_, w, cx| w.render_frame(cx))
                .unwrap();
            cx.run_until_parked();
            let idle = events.get();
            cx.executor().advance_clock(Duration::from_secs(2));
            cx.run_until_parked();
            assert_eq!(events.get(), idle);
        }
    }
}

/// Low-frequency ambient bands. An isolated cached leaf; no layouts, text or RPC per frame.
#[derive(Default)]
pub struct Aurora {
    enabled: bool,
}
impl Aurora {
    pub fn configure(&mut self, enabled: bool, cx: &mut Context<Self>) {
        if self.enabled != enabled {
            self.enabled = enabled;
            cx.notify();
        }
    }
}
impl Render for Aurora {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let active =
            self.enabled && !cx.reduce_motion() && window.is_visible() && window.is_window_active();
        let surface = div().size_full().overflow_hidden();
        if !active {
            return surface.child(aurora_frame(0.)).into_any_element();
        }
        surface
            .with_animation(
                "ambient-aurora",
                Animation::new(Duration::from_secs(44))
                    .repeat()
                    .with_max_fps(20.),
                |element, t| element.child(aurora_frame(t)),
            )
            .into_any_element()
    }
}
fn aurora_frame(t: f32) -> impl IntoElement {
    use gpui_kit::{PathBuilder, px, rgba};
    canvas(
        |_, _, _| (),
        move |bounds, _, window, _| {
            let width = f32::from(bounds.size.width);
            let height = f32::from(bounds.size.height);
            let phase = t * std::f32::consts::TAU;
            // Three broad veils, each feathered with twelve low-opacity contours.
            // Cubic curves avoid the segmented, equal-width "digital ribbon" appearance.
            for veil in 0..3 {
                let v = veil as f32;
                for layer in (0..12).rev() {
                    let feather = layer as f32 / 11.;
                    let center = height * (0.18 + v * 0.17 + 0.07 * (phase + v * 1.7).sin());
                    let thickness = 8. + feather * 100.;
                    let bend = height * (0.20 + 0.10 * (phase - v).cos());
                    let p = |x, y| bounds.origin + point(px(width * x), px(y));
                    let mut path = PathBuilder::fill();
                    path.move_to(p(-0.1, center - thickness * 0.5));
                    path.cubic_bezier_to(
                        p(1.1, center + bend * 0.3 - thickness * 0.5),
                        p(0.22, center - bend - thickness * 0.5),
                        p(0.68, center + bend - thickness * 0.5),
                    );
                    path.cubic_bezier_to(
                        p(-0.1, center + thickness * 0.5),
                        p(0.70, center + bend + thickness * 0.5),
                        p(0.25, center - bend + thickness * 0.5),
                    );
                    path.close();
                    if let Ok(path) = path.build() {
                        // Solid translucent contours avoid cached gradient seams at resize.
                        let color = [0x837de902, 0xa48cd302, 0x8b84d602][veil];
                        window.paint_path(path, rgba(color));
                    }
                }
            }
        },
    )
    .size_full()
}

#[cfg(test)]
mod selection_tests {
    use super::selection_progress;
    use gpui_kit::test::TestWindowExt;
    use gpui_kit::{
        AppContext, Context, IntoElement, Render, TestAppContext, Window, WindowOptions, div,
    };
    use std::{cell::Cell, rc::Rc, time::Duration};
    struct Probe {
        selected: bool,
        sample: Rc<Cell<f32>>,
    }
    impl Render for Probe {
        fn render(&mut self, w: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
            self.sample.set(selection_progress(
                "probe".into(),
                self.selected,
                true,
                w,
                cx,
            ));
            div()
        }
    }
    #[gpui_kit::test]
    fn selection_finishes_and_snaps_when_another_window_takes_focus(cx: &mut TestAppContext) {
        let sample = Rc::new(Cell::new(-1.));
        let read = sample.clone();
        let window = cx.update(|cx| {
            cx.open_window(WindowOptions::default(), |w, cx| {
                w.activate_window();
                cx.new(|_| Probe {
                    selected: false,
                    sample,
                })
            })
            .unwrap()
        });
        cx.run_until_parked();
        window
            .update(cx, |v, w, cx| {
                assert!(w.is_window_active());
                v.selected = true;
                cx.notify();
            })
            .unwrap();
        cx.update_window(window.into(), |_, w, cx| w.render_frame(cx))
            .unwrap();
        assert!(read.get() < 1.);
        cx.executor().advance_clock(Duration::from_millis(200));
        cx.update_window(window.into(), |_, w, cx| w.render_frame(cx))
            .unwrap();
        assert_eq!(read.get(), 1.);
        let _other = cx.update(|cx| {
            cx.open_window(WindowOptions::default(), |w, cx| {
                w.activate_window();
                cx.new(|_| Probe {
                    selected: false,
                    sample: Rc::new(Cell::new(0.)),
                })
            })
            .unwrap()
        });
        cx.run_until_parked();
        window
            .update(cx, |v, w, cx| {
                assert!(!w.is_window_active());
                v.selected = false;
                cx.notify();
            })
            .unwrap();
        cx.update_window(window.into(), |_, w, cx| w.render_frame(cx))
            .unwrap();
        assert_eq!(
            read.get(),
            0.,
            "inactive controls must not leave the old tab highlighted"
        );
    }
}

#[cfg(test)]
mod rail_tests {
    use super::*;
    #[test]
    fn rail_retargets_from_current_position_and_snaps_layout_changes() {
        let mut rail = RailTween::default();
        let now = std::time::Instant::now();
        let a = [20., 30., 80., 36.];
        let b = [110., 30., 130., 36.];
        assert_eq!(rail.sample(0, a, now, true), (a, false));
        assert_eq!(rail.sample(1, b, now, true), (a, true));
        let mid = rail.sample(1, b, now + Duration::from_millis(80), true).0;
        assert!(mid[0] > a[0] && mid[0] < b[0]);
        assert_eq!(
            rail.sample(0, a, now + Duration::from_millis(80), true),
            (mid, true)
        );
        assert_eq!(
            rail.sample(0, a, now + Duration::from_millis(400), true),
            (a, false)
        );
        let resized = [30., 70., 120., 54.];
        assert_eq!(
            rail.sample(0, resized, now + Duration::from_millis(410), true),
            (resized, false)
        );
        assert_eq!(
            rail.sample(1, b, now + Duration::from_millis(420), false),
            (b, false)
        );
    }
    #[gpui_kit::test]
    fn rail_uses_real_wrapped_control_bounds_in_both_axes(cx: &mut gpui_kit::TestAppContext) {
        use gpui_kit::{AppContext, px, test::TestWindowExt};
        use std::{cell::RefCell, rc::Rc};
        struct Probe {
            selected: usize,
            vertical: bool,
            large: bool,
            state: Rc<RefCell<Option<gpui_kit::Entity<RailState>>>>,
        }
        impl Render for Probe {
            fn render(&mut self, w: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
                *self.state.borrow_mut() = Some(w.use_keyed_state(
                    (ElementId::Name("measured-tabs".into()), "rail-geometry"),
                    cx,
                    |_, _| RailState::default(),
                ));
                let labels = if self.large {
                    ["链上资产与余额", "Receive a payment", "连接与设置"]
                } else {
                    ["资产", "Receive", "设置"]
                };
                let buttons = labels
                    .into_iter()
                    .enumerate()
                    .map(|(i, label)| {
                        (
                            Button::new(("measured-button", i)).label(label),
                            i == self.selected,
                        )
                    })
                    .collect();
                div()
                    .w(px(300.))
                    .child(rail("measured-tabs", buttons, self.vertical, false, w, cx))
            }
        }
        let state = Rc::new(RefCell::new(None));
        let (window, pane) = cx.update(|cx| {
            gpui_kit::init(cx);
            crate::design::install(cx);
            gpui_kit::open_window(gpui_kit::WindowOptions::default(), cx, |_, cx| {
                cx.new(|_| Probe {
                    selected: 0,
                    vertical: false,
                    large: false,
                    state: state.clone(),
                })
            })
            .unwrap()
        });
        cx.update_window(window, |_, w, cx| {
            for vertical in [false, true] {
                for large in [false, true] {
                    for selected in [0, 2, 1, 0] {
                        pane.update(cx, |v, cx| {
                            v.vertical = vertical;
                            v.large = large;
                            v.selected = selected;
                            cx.notify();
                        });
                        w.render_frame(cx);
                        let actual = w.find(("measured-button", selected)).bounds();
                        let snapshot = state.borrow();
                        let rail = snapshot.as_ref().unwrap().read(cx);
                        assert_eq!(rail.measured.unwrap().1, actual);
                        assert_eq!(
                            rail.tween.target,
                            [
                                f32::from(actual.left()),
                                f32::from(actual.top()),
                                f32::from(actual.size.width),
                                f32::from(actual.size.height)
                            ]
                        );
                    }
                }
            }
        })
        .unwrap();
    }
}
