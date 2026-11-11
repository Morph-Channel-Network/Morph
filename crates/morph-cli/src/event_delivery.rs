//! A dedicated consumer process owns webhook I/O. Hub/signers never call it
//! while holding their locks. All output/errors are safe counts or fixed classes.
mod health;
use anyhow::{Result, ensure};
use clap::Subcommand;
use morph_events::{Queue, Webhook};
use morph_runtime_store::{Protection, Store};
use std::{
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[derive(Debug, clap::Args)]
pub struct Options {
    /// Current Hub, Gateway or watch runtime database; opened read-only. Never a signer journal.
    #[arg(long)]
    source: PathBuf,
    /// Protected 32-byte hex storage key for an encrypted Gateway source.
    #[arg(long)]
    source_storage_key_file: Option<PathBuf>,
    /// Dedicated consumer database in a private directory; never the Hub database.
    #[arg(long)]
    store: PathBuf,
    /// HTTPS receiver, or literal loopback HTTP for local no-value tests.
    #[arg(long)]
    url: String,
    /// Protected file containing exactly 32 bytes of hex HMAC key material.
    #[arg(long)]
    hmac_key_file: PathBuf,
    /// Private worker heartbeat; defaults to STORE.health.json.
    #[arg(long)]
    health_file: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Persist one source page and attempt a bounded number of due deliveries.
    RunOnce {
        #[arg(long, default_value_t = 4)]
        limit: usize,
    },
    /// Continue bounded ticks; a receiver outage never blocks the producer.
    Serve {
        #[arg(long, default_value_t = 1000)]
        interval_ms: u64,
    },
    /// Safe durable backlog summary, with no payload or endpoint disclosure.
    Status,
    /// Check local dispatch readiness; prints scoped JSON and exits nonzero if unready.
    Readiness(health::ProbeOptions),
    /// Export bounded gauges for a textfile collector; no payload/URL/ID labels.
    Metrics(health::ProbeOptions),
    /// Seal this generation as its archive and carry unresolved jobs to a new private store.
    /// Keep the old database; subsequent run/serve commands use --store NEXT_STORE.
    Archive {
        #[arg(long)]
        next_store: PathBuf,
    },
    /// Locally re-arm one dead letter, preserving its original identity/bytes.
    Replay {
        #[arg(long)]
        event_id: String,
    },
}
fn now() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .try_into()?)
}
fn tick(queue: &Queue, hook: &Webhook, limit: usize) -> Result<()> {
    ensure!((1..=16).contains(&limit), "delivery limit must be 1..16");
    // A full source backlog must not prevent already-enrolled jobs from draining.
    let ingest = queue.ingest(now()?);
    if let Err(ref error) = ingest
        && !matches!(error, morph_events::Error::Full)
    {
        return Err(anyhow::anyhow!(error.to_string()));
    }
    let mut remaining = limit;
    while remaining > 0 {
        let mut tickets = Vec::new();
        for _ in 0..remaining.min(morph_events::MAX_IN_FLIGHT) {
            let Some(delivery) = queue.claim(now()?)? else {
                break;
            };
            tickets.push(delivery);
        }
        if tickets.is_empty() {
            break;
        }
        remaining -= tickets.len();
        let results = std::thread::scope(|scope| {
            let handles: Vec<_> = tickets
                .into_iter()
                .map(|delivery| {
                    scope.spawn(move || {
                        let outcome = hook.send(&delivery);
                        (delivery, outcome)
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| {
                    handle.join().map_err(|_| {
                        anyhow::anyhow!("delivery worker failed; durable claim retained")
                    })
                })
                .collect::<Result<Vec<_>>>()
        })?;
        for (delivery, outcome) in results {
            queue.complete(&delivery, outcome, now()?)?;
        }
    }
    println!("{}", serde_json::to_string(&queue.health(now()?)?)?);
    Ok(())
}
fn open(options: &Options, readonly: bool) -> Result<(Queue, Webhook)> {
    let text = morph_key_input::read_secret_file(&options.hmac_key_file)?;
    let mut key = zeroize::Zeroizing::new([0; 32]);
    hex::decode_to_slice(text.as_bytes(), key.as_mut())
        .map_err(|_| anyhow::anyhow!("webhook key must contain exactly 32 hex-encoded bytes"))?;
    let hook = Webhook::new(&options.url, key)?;
    let source_protection = match &options.source_storage_key_file {
        Some(path) => {
            let text = morph_key_input::read_secret_file(path)?;
            let mut key = zeroize::Zeroizing::new([0; 32]);
            hex::decode_to_slice(text.as_bytes(), key.as_mut()).map_err(|_| {
                anyhow::anyhow!("source storage key must contain exactly 32 hex-encoded bytes")
            })?;
            Protection::encrypted(*key)
        }
        None => Protection::private_plaintext(),
    };
    let source = Store::read_only(&options.source, source_protection)?;
    let consumer = if readonly {
        Store::read_only(&options.store, Protection::private_plaintext())?
    } else {
        Store::open(&options.store, Protection::private_plaintext())?
    };
    let queue = Queue::open(source, consumer, hook.fingerprint())?;
    Ok((queue, hook))
}
pub fn run(options: Options) -> Result<()> {
    match &options.command {
        Command::Readiness(probe) => {
            let probe = *probe;
            return health::run(options, probe, false);
        }
        Command::Metrics(probe) => {
            let probe = *probe;
            return health::run(options, probe, true);
        }
        _ => {}
    }
    // The lock belongs to this consumer only and is never removed on shutdown.
    // Another consumer for another receiver uses a different database and lock.
    let status_only = matches!(options.command, Command::Status);
    let _lock = if status_only {
        None
    } else {
        Some(
            crate::persistence::try_lock_private_path(&options.store)?
                .ok_or_else(|| anyhow::anyhow!("event delivery worker already active"))?,
        )
    };
    let (queue, hook) = open(&options, status_only)?;
    let health_path = options
        .health_file
        .clone()
        .unwrap_or_else(|| health::default_path(&options.store));
    match options.command {
        Command::Readiness(_) | Command::Metrics(_) => {
            anyhow::bail!("observation command dispatched through a mutation path")
        }
        Command::RunOnce { limit } => tick(&queue, &hook, limit),
        Command::Status => {
            println!("{}", serde_json::to_string(&queue.health(now()?)?)?);
            Ok(())
        }
        Command::Archive { next_store } => {
            let _next_lock = crate::persistence::try_lock_private_path(&next_store)?
                .ok_or_else(|| anyhow::anyhow!("successor delivery store is busy"))?;
            let next = Store::open(&next_store, Protection::private_plaintext())?;
            let report = queue.archive_to(&next)?;
            println!("{}", serde_json::to_string(&report)?);
            Ok(())
        }
        Command::Replay { event_id } => {
            queue.replay_dead_letter(&event_id, now()?)?;
            println!("{}", serde_json::to_string(&queue.health(now()?)?)?);
            Ok(())
        }
        Command::Serve { interval_ms } => {
            ensure!(
                (100..=60_000).contains(&interval_ms),
                "delivery interval must be 100..60000 ms"
            );
            loop {
                // Transport failures are persisted and do not escape tick; fatal
                // storage/schema/policy errors stop rather than dropping records.
                health::pulse(&health_path, &queue.binding(), interval_ms + 15_000, true)?;
                if let Err(error) = tick(&queue, &hook, 4) {
                    let _ =
                        health::pulse(&health_path, &queue.binding(), interval_ms + 15_000, false);
                    return Err(error);
                }
                std::thread::sleep(Duration::from_millis(interval_ms));
            }
        }
    }
}
