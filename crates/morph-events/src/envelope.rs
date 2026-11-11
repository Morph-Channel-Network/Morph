use crate::{Error, EventCursor, EventEnvelope, EventPage, EventPageRequest, Result};
/// Durable event pagination, independent of the short UI/SSE activity buffer.
/// Retained source history is never silently truncated or renumbered.
pub fn event_page(
    source: &morph_runtime_store::Store,
    request: &EventPageRequest,
) -> Result<EventPage> {
    use morph_runtime_store::{Cursor, History};
    if !(1..=64).contains(&request.limit) {
        return Err(Error::Invalid);
    }
    let source_id = hex::encode(source.identity());
    let mut next = request.after.clone().unwrap_or_else(|| EventCursor {
        source_id: source_id.clone(),
        revision: 0,
        outbox_id: String::new(),
    });
    if next.source_id != source_id
        || (next.revision == 0 && !next.outbox_id.is_empty())
        || (next.revision != 0 && next.outbox_id.is_empty())
    {
        return Err(Error::Policy);
    }
    if next.revision != 0 {
        let record = source
            .history_entry(History::Outbox, &next.outbox_id)?
            .ok_or(Error::Policy)?;
        if record.revision != next.revision {
            return Err(Error::Policy);
        }
    }
    let mut records = source.history(
        History::Outbox,
        &Cursor {
            revision: next.revision,
            id: next.outbox_id.clone(),
        },
        request.limit as usize + 1,
    )?;
    let has_more = records.len() > request.limit as usize;
    records.truncate(request.limit as usize);
    let mut events = Vec::new();
    for record in records {
        let event = EventEnvelope::decode(record.body.bytes())?;
        if event.source_id != source_id
            || event.source_revision != record.revision
            || event.event_id != EventEnvelope::identity(&source_id, &record.id)
            || event.correlation_id != EventEnvelope::correlation(&record.operation_id)
        {
            return Err(Error::Invalid);
        }
        next.revision = record.revision;
        next.outbox_id = record.id;
        events.push(event);
    }
    Ok(EventPage {
        events,
        next,
        has_more,
    })
}
