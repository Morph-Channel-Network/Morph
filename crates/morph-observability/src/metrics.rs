use crate::{Readiness, Scope, Service};
use std::{
    fmt::Write,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Instant,
};

/// One fixed label set. Never construct labels from request paths or IDs.
#[derive(Clone, Copy)]
#[repr(usize)]
pub enum Operation {
    Read,
    Registry,
    Invoice,
    Recovery,
    Restore,
    Observe,
    Unknown,
}
const OPERATIONS: [Operation; 7] = [
    Operation::Read,
    Operation::Registry,
    Operation::Invoice,
    Operation::Recovery,
    Operation::Restore,
    Operation::Observe,
    Operation::Unknown,
];
impl Operation {
    fn label(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Registry => "registry",
            Self::Invoice => "invoice",
            Self::Recovery => "recovery",
            Self::Restore => "restore",
            Self::Observe => "observe",
            Self::Unknown => "unknown",
        }
    }
}
#[derive(Clone, Copy)]
#[repr(usize)]
pub enum Outcome {
    Success,
    Rejected,
    Busy,
    Failure,
    Aborted,
}
const OUTCOMES: [Outcome; 5] = [
    Outcome::Success,
    Outcome::Rejected,
    Outcome::Busy,
    Outcome::Failure,
    Outcome::Aborted,
];
impl Outcome {
    fn label(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Rejected => "rejected",
            Self::Busy => "busy",
            Self::Failure => "failure",
            Self::Aborted => "aborted",
        }
    }
    pub fn http(status: u16) -> Self {
        match status {
            200..=399 => Self::Success,
            429 => Self::Busy,
            400..=499 => Self::Rejected,
            _ => Self::Failure,
        }
    }
}
const BUCKETS_MS: [u64; 9] = [1, 5, 10, 50, 100, 500, 1_000, 5_000, 30_000];
pub const MAX_EXPORT_BYTES: usize = 64 * 1024;
pub struct Metrics {
    service: Service,
    counters: [[AtomicU64; 5]; 7],
    inflight: [AtomicU64; 7],
    buckets: [[AtomicU64; 9]; 7],
    counts: [AtomicU64; 7],
    sums_ms: [AtomicU64; 7],
}
fn increment(counter: &AtomicU64, value: u64) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |old| {
        Some(old.saturating_add(value))
    });
}
fn value(counter: &AtomicU64) -> u64 {
    counter.load(Ordering::Relaxed)
}
impl Metrics {
    pub fn new(service: Service) -> Self {
        Self {
            service,
            counters: std::array::from_fn(|_| std::array::from_fn(|_| AtomicU64::new(0))),
            inflight: std::array::from_fn(|_| AtomicU64::new(0)),
            buckets: std::array::from_fn(|_| std::array::from_fn(|_| AtomicU64::new(0))),
            counts: std::array::from_fn(|_| AtomicU64::new(0)),
            sums_ms: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }
    pub fn begin(self: &Arc<Self>, operation: Operation) -> Timer {
        increment(&self.inflight[operation as usize], 1);
        Timer {
            metrics: self.clone(),
            operation,
            start: Instant::now(),
            completed: false,
        }
    }
    fn observe(&self, operation: Operation, outcome: Outcome, elapsed_ms: u64) {
        let index = operation as usize;
        increment(&self.counters[index][outcome as usize], 1);
        increment(&self.counts[index], 1);
        increment(&self.sums_ms[index], elapsed_ms);
        for (position, bound) in BUCKETS_MS.iter().enumerate() {
            if elapsed_ms <= *bound {
                increment(&self.buckets[index][position], 1);
            }
        }
        let _ = self.inflight[index].fetch_update(Ordering::Relaxed, Ordering::Relaxed, |old| {
            Some(old.saturating_sub(1))
        });
    }
    /// Fixed series, no resource identifiers, arbitrary status strings or errors.
    /// Counters are process-local, saturating, and reset on restart. Scrapes are
    /// lock-free approximations; they are not transactional settlement evidence.
    pub fn render(&self, readiness: &Readiness) -> String {
        let mut text = String::with_capacity(16 * 1024);
        let service = self.service.label();
        text.push_str("# HELP morph_runtime_operations_total Dispatched operations by fixed category and outcome.\n# TYPE morph_runtime_operations_total counter\n");
        for operation in OPERATIONS {
            for outcome in OUTCOMES {
                let _ = writeln!(
                    text,
                    "morph_runtime_operations_total{{service=\"{service}\",operation=\"{}\",outcome=\"{}\"}} {}",
                    operation.label(),
                    outcome.label(),
                    value(&self.counters[operation as usize][outcome as usize])
                );
            }
        }
        text.push_str("# HELP morph_runtime_inflight Currently dispatched operations.\n# TYPE morph_runtime_inflight gauge\n");
        for operation in OPERATIONS {
            let _ = writeln!(
                text,
                "morph_runtime_inflight{{service=\"{service}\",operation=\"{}\"}} {}",
                operation.label(),
                value(&self.inflight[operation as usize])
            );
        }
        text.push_str("# HELP morph_runtime_duration_milliseconds Dispatched operation latency, excluding transport parsing and streaming lifetime.\n# TYPE morph_runtime_duration_milliseconds histogram\n");
        for operation in OPERATIONS {
            let index = operation as usize;
            for (position, bound) in BUCKETS_MS.iter().enumerate() {
                let _ = writeln!(
                    text,
                    "morph_runtime_duration_milliseconds_bucket{{service=\"{service}\",operation=\"{}\",le=\"{bound}\"}} {}",
                    operation.label(),
                    value(&self.buckets[index][position])
                );
            }
            let _ = writeln!(
                text,
                "morph_runtime_duration_milliseconds_bucket{{service=\"{service}\",operation=\"{}\",le=\"+Inf\"}} {}",
                operation.label(),
                value(&self.counts[index])
            );
            let _ = writeln!(
                text,
                "morph_runtime_duration_milliseconds_count{{service=\"{service}\",operation=\"{}\"}} {}",
                operation.label(),
                value(&self.counts[index])
            );
            let _ = writeln!(
                text,
                "morph_runtime_duration_milliseconds_sum{{service=\"{service}\",operation=\"{}\"}} {}",
                operation.label(),
                value(&self.sums_ms[index])
            );
        }
        text.push_str("# HELP morph_runtime_scope_ready Readiness for exactly this named scope, not authority.\n# TYPE morph_runtime_scope_ready gauge\n");
        for scope in Scope::ALL {
            let ready = readiness.consistent()
                && readiness.service == self.service
                && readiness.scopes.iter().filter(|s| s.scope == scope).count() == 1
                && readiness
                    .scopes
                    .iter()
                    .any(|s| s.scope == scope && s.configured && s.ready);
            let _ = writeln!(
                text,
                "morph_runtime_scope_ready{{service=\"{service}\",scope=\"{}\"}} {}",
                scope.label(),
                u8::from(ready)
            );
        }
        text
    }
}

pub struct Timer {
    metrics: Arc<Metrics>,
    operation: Operation,
    start: Instant,
    completed: bool,
}
impl Timer {
    pub fn finish(mut self, outcome: Outcome) {
        self.record(outcome);
    }
    fn record(&mut self, outcome: Outcome) {
        if !self.completed {
            self.metrics.observe(
                self.operation,
                outcome,
                self.start
                    .elapsed()
                    .as_millis()
                    .try_into()
                    .unwrap_or(u64::MAX),
            );
            self.completed = true;
        }
    }
}
impl Drop for Timer {
    fn drop(&mut self) {
        self.record(Outcome::Aborted);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn label_cardinality_is_fixed_and_raii_records_aborted_work() {
        let metrics = Arc::new(Metrics::new(Service::Hub));
        let report = Readiness::new(Service::Hub, 100, vec![]);
        let before = metrics.render(&report);
        for _ in 0..100 {
            metrics.begin(Operation::Unknown).finish(Outcome::Rejected);
        }
        drop(metrics.begin(Operation::Read));
        let after = metrics.render(&report);
        assert!(after.len() < MAX_EXPORT_BYTES);
        assert_eq!(before.lines().count(), after.lines().count());
        assert!(after.contains("operation=\"read\",outcome=\"aborted\"} 1"));
        assert!(after.contains("operation=\"unknown\",outcome=\"rejected\"} 100"));
        assert_eq!(value(&metrics.inflight[Operation::Read as usize]), 0);
    }
    #[test]
    fn counters_saturate_without_wraparound_or_extra_series() {
        let metrics = Metrics::new(Service::Hub);
        metrics.counts[0].store(u64::MAX, Ordering::Relaxed);
        metrics.observe(Operation::Read, Outcome::Success, u64::MAX);
        assert_eq!(value(&metrics.counts[0]), u64::MAX);
        assert_eq!(value(&metrics.buckets[0][8]), 0);
    }
}
