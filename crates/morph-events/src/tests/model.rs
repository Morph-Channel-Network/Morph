//! Sequential oracle for one event, its leases and immutable attempt history.
//! Multi-worker contention and HTTP authentication have separate process tests.
use super::*;

struct Model {
    state: Status,
    attempt: u8,
    generation: u8,
    enrolled: u64,
    due: u64,
    writes: u64,
}
impl Model {
    fn verify(&self, q: &Queue, dir: &Path, now: u64, bytes: &[u8]) {
        let health = q.health(now).unwrap();
        assert_eq!(health.retained, 1);
        assert_eq!(health.pending, usize::from(self.state == Status::Pending));
        assert_eq!(
            health.in_flight,
            usize::from(self.state == Status::InFlight)
        );
        assert_eq!(
            health.acknowledged,
            usize::from(self.state == Status::Acknowledged)
        );
        assert_eq!(
            health.dead_letter,
            usize::from(self.state == Status::DeadLetter)
        );
        assert_eq!(health.source_cursor_revision, 1);
        assert!(!health.source_pending);
        let consumer = db(&dir.join("consumer"));
        let integrity = consumer.validate().unwrap();
        assert_eq!(integrity.revision, 2 + self.writes); // install, ingest
        assert_eq!(integrity.attempts, self.writes);
        assert_eq!(integrity.intents, 2 + self.writes);
        let rows = consumer.records(Family::Delivery, "job:", 4).unwrap();
        assert_eq!(rows.len(), 1);
        let saved: serde_json::Value = serde_json::from_slice(rows[0].body.bytes()).unwrap();
        assert_eq!(saved["status"], serde_json::to_value(self.state).unwrap());
        assert_eq!(saved["attempts"], self.attempt);
        assert_eq!(saved["generation"], self.generation);
        assert_eq!(saved["enrolled_at_ms"], self.enrolled);
        assert_eq!(saved["next_due_ms"], self.due);
        assert_eq!(saved["body"], hex::encode(bytes));
        let source = db(&dir.join("source"));
        assert_eq!(source.revision().unwrap(), 1);
        let history = source
            .history(History::Outbox, &Cursor::default(), 4)
            .unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].body.bytes(), bytes);
    }
}

#[test]
fn seeded_delivery_model_preserves_body_leases_generations_and_acknowledgements() {
    let mut totals = [0usize; 5]; // claims, completion, replay, stale completion, ack
    for seed in [1u64, 17, 332_043_276_360] {
        let dir = directory();
        let source = db(&dir.path().join("source"));
        seed_source(&source);
        let raw = source
            .history(History::Outbox, &Cursor::default(), 1)
            .unwrap();
        let bytes = raw[0].body.bytes().to_vec();
        let id = EventEnvelope::decode(&bytes).unwrap().event_id;
        let mut q = queue(dir.path(), policy());
        assert_eq!(q.ingest(1000).unwrap(), 1);
        let mut model = Model {
            state: Status::Pending,
            attempt: 0,
            generation: 0,
            enrolled: 1000,
            due: 1000,
            writes: 0,
        };
        let mut tickets: Vec<Delivery> = vec![];
        let mut now = 1000;
        let mut rng = seed;
        for step in 0..256 {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            // Force the first lease/reclaim/stale completion before mutation-like
            // interleaving, then force age expiry and replay in the middle.
            let command = match step {
                0 | 2 => 0,
                1 => 5,
                3 => 3,
                4 if seed == 1 => 9,
                128 => 8,
                129 => 0,
                130 => 6,
                240 => 6,
                241 => 0,
                242 => 9,
                _ => (rng % 8) as usize,
            };
            match command {
                0 | 1 => {
                    let expected = matches!(model.state, Status::Pending | Status::InFlight)
                        && model.due <= now;
                    let result = q.claim(now).unwrap();
                    if expected
                        && (model.attempt == MAX_ATTEMPTS || now - model.enrolled >= MAX_AGE_MS)
                    {
                        assert!(result.is_none());
                        model.state = Status::DeadLetter;
                        model.writes += 1;
                    } else if expected {
                        let ticket = result.expect("eligible event was not claimed");
                        model.attempt += 1;
                        model.state = Status::InFlight;
                        model.due = now + LEASE_MS;
                        model.writes += 1;
                        assert_eq!(ticket.attempt(), model.attempt);
                        assert_eq!(ticket.generation(), model.generation);
                        assert_eq!(ticket.body(), bytes);
                        assert_eq!(ticket.event_id(), id);
                        tickets.push(ticket);
                        totals[0] += 1;
                    } else {
                        assert!(result.is_none());
                    }
                }
                2 | 3 | 9 if !tickets.is_empty() => {
                    let index = if command == 3 { 0 } else { tickets.len() - 1 };
                    let ticket = &tickets[index];
                    let current = model.state == Status::InFlight
                        && model.attempt == ticket.attempt()
                        && model.generation == ticket.generation();
                    let acknowledged = command == 9;
                    let outcome = if acknowledged {
                        Outcome::Acknowledged
                    } else {
                        Outcome::Failed(Failure::Transport)
                    };
                    let actual = q.complete(ticket, outcome, now);
                    if current {
                        actual.unwrap();
                        model.writes += 1;
                        totals[1] += 1;
                        if acknowledged {
                            totals[4] += 1;
                            model.state = Status::Acknowledged;
                        } else {
                            model.state = if model.attempt == MAX_ATTEMPTS
                                || now - model.enrolled >= MAX_AGE_MS
                            {
                                Status::DeadLetter
                            } else {
                                Status::Pending
                            };
                            model.due = now + (1000 << model.attempt);
                        }
                    } else {
                        assert!(matches!(actual, Err(Error::Conflict)));
                        totals[3] += 1;
                    }
                }
                4 => {
                    drop(q);
                    q = queue(dir.path(), policy());
                }
                5 => now += LEASE_MS,
                6 => {
                    let actual = q.replay_dead_letter(&id, now);
                    if model.state == Status::DeadLetter && model.generation < MAX_REPLAYS {
                        actual.unwrap();
                        model.generation += 1;
                        model.attempt = 0;
                        model.enrolled = now;
                        model.due = now;
                        model.state = Status::Pending;
                        model.writes += 1;
                        totals[2] += 1;
                    } else {
                        assert!(matches!(actual, Err(Error::Conflict)));
                    }
                }
                7 => assert_eq!(q.ingest(now).unwrap(), 0),
                8 => now += MAX_AGE_MS,
                _ => {}
            }
            model.verify(&q, dir.path(), now, &bytes);
        }
        drop(q);
        let q = queue(dir.path(), policy());
        model.verify(&q, dir.path(), now, &bytes);
    }
    assert!(
        totals.into_iter().all(|count| count > 0),
        "all model transitions must execute"
    );
}
fn seed_source(source: &Store) {
    super::seed(source, 1);
}
