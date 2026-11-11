//! Test-program model, not an application format. Independent maps are the oracle
//! for the real SQLite transaction API after every bounded step.
use anyhow::{Result, ensure};
use morph_runtime_store::{
    Append, Body, Commit, Cursor, Family, History, Protection, Receipt, Store, StoreError, Write,
};
use std::collections::BTreeMap;

const MAGIC: &[u8; 4] = b"MTR1";
const MAX_STEPS: usize = 16;
type Rows = BTreeMap<(Family, String), (u64, Vec<u8>)>;
type HistoryRows = BTreeMap<(u64, String), (String, Vec<u8>)>;
#[derive(Default)]
struct Model {
    revision: u64,
    records: Rows,
    intents: HistoryRows,
    events: HistoryRows,
    attempts: HistoryRows,
    committed: Vec<(Commit, Receipt)>,
}
impl Model {
    fn commit(&mut self, request: Commit) -> Receipt {
        self.revision += 1;
        for write in &request.writes {
            let key = (write.family, write.id.clone());
            if let Some(body) = &write.value {
                self.records
                    .insert(key, (self.revision, body.bytes().to_vec()));
            } else {
                self.records.remove(&key);
            }
        }
        self.intents.insert(
            (self.revision, request.operation_id.clone()),
            (
                request.operation_id.clone(),
                request.intent.bytes().to_vec(),
            ),
        );
        for (map, items) in [
            (&mut self.events, &request.events),
            (&mut self.attempts, &request.attempts),
        ] {
            for item in items {
                map.insert(
                    (self.revision, item.id.clone()),
                    (request.operation_id.clone(), item.body.bytes().to_vec()),
                );
            }
        }
        let receipt = Receipt {
            operation_id: request.operation_id.clone(),
            revision: self.revision,
        };
        self.committed.push((request, receipt.clone()));
        receipt
    }
    fn verify(&self, store: &Store) -> Result<()> {
        let integrity = store.validate()?;
        ensure!(
            integrity.revision == self.revision
                && integrity.records == self.records.len() as u64
                && integrity.intents == self.intents.len() as u64
                && integrity.events == self.events.len() as u64
                && integrity.attempts == self.attempts.len() as u64,
            "model aggregate/atomicity divergence"
        );
        // Check absent as well as present keys, plus independently paginated
        // family listings. A failed delete/write must not escape the model.
        for family in [Family::Hub, Family::Payment] {
            for key in 0..8 {
                let id = format!("slot-{key}");
                let observed = store.read(family, &id)?;
                ensure!(
                    observed.revision == self.revision,
                    "snapshot revision differs"
                );
                ensure!(
                    observed
                        .record
                        .map(|r| (r.revision, r.body.bytes().to_vec()))
                        == self.records.get(&(family, id)).cloned(),
                    "model projection divergence"
                );
            }
            let mut after = String::new();
            let mut actual = BTreeMap::new();
            for _ in 0..=8 {
                let page = store.records(family, &after, 2)?;
                if page.is_empty() {
                    break;
                }
                for row in page {
                    ensure!(row.id > after, "record cursor did not advance");
                    after = row.id.clone();
                    ensure!(
                        actual
                            .insert((family, row.id), (row.revision, row.body.bytes().to_vec()))
                            .is_none(),
                        "duplicate record page"
                    );
                }
            }
            let expected: Rows = self
                .records
                .iter()
                .filter(|((f, _), _)| *f == family)
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            ensure!(
                actual == expected,
                "projection pagination skipped or duplicated values"
            );
        }
        for (kind, expected) in [
            (History::Intent, &self.intents),
            (History::Outbox, &self.events),
            (History::Attempt, &self.attempts),
        ] {
            let mut actual = HistoryRows::new();
            let mut cursor = Cursor::default();
            for _ in 0..=2 * (MAX_STEPS + 1) {
                let page = store.history(kind, &cursor, 2)?;
                if page.is_empty() {
                    break;
                }
                for row in page {
                    let key = (row.revision, row.id.clone());
                    ensure!(
                        key > (cursor.revision, cursor.id.clone()),
                        "history cursor did not advance"
                    );
                    cursor = row.cursor();
                    ensure!(
                        actual
                            .insert(key, (row.operation_id, row.body.bytes().to_vec()))
                            .is_none(),
                        "duplicate history page"
                    );
                }
            }
            ensure!(actual == *expected, "model immutable history divergence");
        }
        Ok(())
    }
}
fn request(step: usize, key: u8, value: u8, revision: u64, delete: bool) -> Result<Commit> {
    let body = Body::new(vec![value, step as u8])?;
    Ok(Commit {
        operation_id: format!("operation-{step}"),
        expected_revision: revision,
        intent: body.clone(),
        writes: [Family::Hub, Family::Payment]
            .into_iter()
            .map(|family| Write {
                family,
                id: format!("slot-{key}"),
                value: (!delete).then(|| body.clone()),
            })
            .collect(),
        // Deliberately reverse append order to test same-revision ID pagination.
        events: ["z", "a"]
            .into_iter()
            .map(|suffix| Append {
                id: format!("event-{step}-{suffix}"),
                body: body.clone(),
            })
            .collect(),
        attempts: vec![Append {
            id: format!("attempt-{step}"),
            body,
        }],
    })
}
fn program(steps: &[[u8; 3]]) -> Vec<u8> {
    let mut bytes = MAGIC.to_vec();
    for step in steps {
        bytes.extend(step);
    }
    bytes
}
pub(super) fn seeds() -> Vec<Vec<u8>> {
    vec![
        program(&[
            [0, 0, 1],
            [0, 7, 2],
            [3, 0, 0],
            [2, 0, 3],
            [4, 0, 4],
            [5, 0, 5],
            [5, 1, 6],
            [6, 0, 0],
            [1, 0, 0],
            [7, 0, 0],
        ]),
        program(&[
            [0, 4, 255],
            [1, 4, 0],
            [3, 1, 0],
            [0, 4, 19],
            [4, 2, 3],
            [0, 1, 25],
            [6, 2, 0],
            [3, 2, 0],
            [5, 2, 5],
            [7, 7, 0],
        ]),
    ]
}
pub(super) fn check(bytes: &[u8]) -> Result<bool> {
    if bytes.len() < 7
        || bytes.len() > 4 + MAX_STEPS * 3
        || !bytes.starts_with(MAGIC)
        || !(bytes.len() - 4).is_multiple_of(3)
    {
        return Ok(false);
    }
    let steps = &bytes[4..];
    if steps.chunks_exact(3).any(|s| s[0] > 7 || s[1] > 7) {
        return Ok(false);
    }
    let store = Store::memory(Protection::private_plaintext())?;
    let mut model = Model::default();
    let base = request(0, 0, 0, 0, false)?;
    let expected = model.commit(base.clone());
    ensure!(
        store.commit_new(&base)? == expected,
        "initial model receipt differs"
    );
    model.verify(&store)?;
    for (index, step) in steps.chunks_exact(3).enumerate() {
        let [opcode, key, value] = <[u8; 3]>::try_from(step)?;
        let (saved, receipt) = model.committed[usize::from(key) % model.committed.len()].clone();
        let mut next = request(index + 1, key, value, model.revision, opcode == 1)?;
        match opcode {
            0 | 1 => {
                let expected = model.commit(next.clone());
                ensure!(
                    store.commit_new(&next)? == expected,
                    "new model receipt differs"
                );
            }
            2 => {
                next.expected_revision -= 1;
                ensure!(
                    store.commit(&next)
                        == Err(StoreError::Revision {
                            expected: next.expected_revision,
                            actual: model.revision
                        }),
                    "stale model revision accepted or misclassified"
                );
            }
            3 => ensure!(
                store.commit(&saved)? == receipt,
                "exact old-revision retry changed receipt"
            ),
            4 => {
                // Identical operation ID and intent, changed effect: digest must
                // cover the whole request, not only a user-visible intent field.
                let mut conflict = saved;
                conflict.events[0].body = Body::new(vec![value, 0x5a, 0xa5])?;
                ensure!(
                    store.commit(&conflict) == Err(StoreError::Conflict),
                    "changed outbox accepted under old operation ID"
                );
            }
            5 => {
                if key % 2 == 0 {
                    next.events[0].id = saved.events[0].id.clone();
                } else {
                    next.attempts[0].id = saved.attempts[0].id.clone();
                }
                ensure!(
                    store.commit_new(&next) == Err(StoreError::Conflict),
                    "duplicate immutable row accepted"
                );
            }
            6 => ensure!(
                store.commit_new(&saved) == Err(StoreError::Conflict),
                "replay regained permission for a new external effect"
            ),
            7 => {}
            _ => anyhow::bail!("invalid model opcode"),
        }
        model.verify(&store)?;
    }
    Ok(true)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_multistep_model_covers_all_commands_and_rejects_unknown_programs() -> Result<()> {
        for seed in seeds() {
            ensure!(check(&seed)?, "seed rejected");
        }
        ensure!(!check(&program(&[[8, 0, 0]]))?, "unknown command accepted");
        ensure!(!check(&program(&[[0, 8, 0]]))?, "unknown key accepted");
        ensure!(
            !check(&program(&[[0, 0, 0]; MAX_STEPS + 1]))?,
            "step bound ignored"
        );
        ensure!(!check(&[0xff; 1024 * 1024])?, "unbounded input accepted");
        Ok(())
    }
}
