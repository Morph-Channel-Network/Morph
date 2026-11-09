//! Bounded brand motion. This cached child owns no network or protocol data.
use gpui_kit::{
    Animation, AnimationExt, Bounds, Context, IntoElement, ParentElement, PathBuilder, Pixels,
    Render, Styled, Window, canvas, div, point, px, rgb,
};
use std::time::Duration;
pub const FLOW_DURATION: Duration = Duration::from_millis(1200);
pub const ENTER_DURATION: Duration = Duration::from_millis(180);
pub const LANES: usize = 3;
pub const TRAIL_POINTS: usize = 9;
#[derive(Default)]
pub struct Flux {
    generation: usize,
    suppressed: bool,
    stopped: bool,
}
impl Flux {
    pub fn configure(&mut self, generation: usize, suppressed: bool, cx: &mut Context<Self>) {
        if self.generation != generation || self.suppressed != suppressed {
            self.generation = generation;
            self.suppressed = suppressed;
            self.stopped = suppressed;
            cx.notify();
        }
    }
}
// Cubic curves in normalized coordinates, independent of window dimensions.
fn at(t: f32, lane: usize) -> (f32, f32) {
    let offset = (lane as f32 - 1.) * 0.16;
    let u = 1. - t;
    let y = u * u * u * (0.68 + offset)
        + 3. * u * u * t * (if lane == 1 { 0.95 } else { 0.05 } + offset)
        + 3. * u * t * t * (if lane == 1 { 0.05 } else { 0.95 } + offset)
        + t * t * t * (0.32 + offset);
    (0.04 + 0.92 * t, y)
}
fn paint(bounds: Bounds<Pixels>, phase: f32, window: &mut Window) {
    let p = |t, lane| {
        let (x, y) = at(t, lane);
        point(
            bounds.left() + bounds.size.width * x,
            bounds.top() + bounds.size.height * y,
        )
    };
    for lane in 0..LANES {
        let mut track = PathBuilder::stroke(px(1.));
        track.move_to(p(0., lane));
        for step in 1..=32 {
            track.line_to(p(step as f32 / 32., lane));
        }
        if let Ok(path) = track.build() {
            window.paint_path(path, rgb(0x4a426a));
        }
        // Fixed nine-segment tail. Finishes at rest; there is no repeating ticker.
        let head = (phase * 1.25 - lane as f32 * 0.10).clamp(0., 1.);
        for segment in 0..TRAIL_POINTS {
            let start = (head - (TRAIL_POINTS - segment) as f32 * 0.012).max(0.);
            let end = (start + 0.016).min(head);
            if end <= start {
                continue;
            }
            let mut path = PathBuilder::stroke(px(1. + segment as f32 * 0.16));
            path.move_to(p(start, lane));
            path.line_to(p(end, lane));
            let mut color: gpui_kit::Hsla = rgb([0x9a78ff, 0x80b7ff, 0xc4a4ff][lane]).into();
            color.a = 0.18 + segment as f32 * 0.085;
            if let Ok(path) = path.build() {
                window.paint_path(path, color);
            }
        }
        for edge in [0., 1.] {
            let c = p(edge, lane);
            window.paint_quad(
                gpui_kit::fill(
                    Bounds::new(
                        point(c.x - px(2.5), c.y - px(2.5)),
                        gpui_kit::size(px(5.), px(5.)),
                    ),
                    rgb(0xa5a3ff),
                )
                .corner_radii(px(2.5)),
            );
        }
    }
}
fn visual(phase: f32) -> impl IntoElement {
    canvas(
        |_, _, _| (),
        move |bounds, _, window, _| paint(bounds, phase, window),
    )
    .size_full()
}
impl Render for Flux {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        if self.suppressed
            || cx.reduce_motion()
            || !window.is_window_active()
            || !window.is_visible()
        {
            self.stopped = true;
        }
        let surface = div().size_full();
        if self.stopped {
            surface.child(visual(1.)).into_any_element()
        } else {
            surface
                .with_animation(
                    ("morph-flow", self.generation),
                    Animation::new(FLOW_DURATION).with_max_fps(60.),
                    |element, phase| element.child(visual(phase)),
                )
                .into_any_element()
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use gpui_kit::{AppContext, Bounds, TestAppContext, WindowBounds, WindowOptions, size};
    #[gpui_kit::test]
    fn flow_stops_scheduling_after_completion_and_under_reduced_motion(cx: &mut TestAppContext) {
        use gpui_kit::test::TestWindowExt;
        use std::{cell::Cell, rc::Rc};
        let window = cx.update(|cx| {
            cx.open_window(
                WindowOptions {
                    window_bounds: Some(WindowBounds::Windowed(Bounds::new(
                        Default::default(),
                        size(px(600.), px(140.)),
                    ))),
                    ..Default::default()
                },
                |window, cx| {
                    window.activate_window();
                    cx.new(|_| Flux::default())
                },
            )
            .unwrap()
        });
        cx.run_until_parked();
        let notifications = Rc::new(Cell::new(0));
        let count = notifications.clone();
        let _subscription = window
            .update(cx, |v, w, cx| {
                let sub = cx.observe_self(move |_, cx| {
                    let _ = cx;
                    count.set(count.get() + 1);
                });
                v.configure(1, false, cx);
                let _ = w;
                sub
            })
            .unwrap();
        cx.update_window(window.into(), |_, w, cx| w.render_frame(cx))
            .unwrap();
        cx.run_until_parked();
        let first = notifications.get();
        cx.executor().advance_clock(Duration::from_millis(100));
        cx.run_until_parked();
        assert!(
            notifications.get() > first,
            "an active flow must schedule a refresh"
        );
        cx.update_window(window.into(), |_, w, cx| w.render_frame(cx))
            .unwrap();
        cx.executor().advance_clock(Duration::from_millis(1300));
        cx.run_until_parked();
        cx.update_window(window.into(), |_, w, cx| w.render_frame(cx))
            .unwrap();
        cx.run_until_parked();
        let settled = notifications.get();
        cx.executor().advance_clock(Duration::from_secs(2));
        cx.run_until_parked();
        assert_eq!(
            notifications.get(),
            settled,
            "completed flow must not keep scheduling"
        );
        for (generation, system_reduced, suppressed) in [(2, true, false), (3, false, true)] {
            window
                .update(cx, |v, w, cx| {
                    cx.set_reduce_motion(system_reduced);
                    v.configure(generation, suppressed, cx);
                    let _ = w;
                })
                .unwrap();
            cx.update_window(window.into(), |_, w, cx| w.render_frame(cx))
                .unwrap();
            cx.run_until_parked();
            let before = notifications.get();
            cx.executor().advance_clock(Duration::from_secs(2));
            cx.run_until_parked();
            assert_eq!(
                notifications.get(),
                before,
                "suppressed flow must not schedule"
            );
        }
    }
    #[test]
    fn bounded_flow_geometry_stays_inside_its_surface() {
        assert_eq!(LANES * TRAIL_POINTS, 27);
        for lane in 0..LANES {
            for i in 0..=1200 {
                let (x, y) = at(i as f32 / 1200., lane);
                assert!((0.0..=1.0).contains(&x) && (0.0..=1.0).contains(&y));
            }
        }
    }
}
