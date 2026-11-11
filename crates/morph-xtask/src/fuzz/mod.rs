//! Deterministic mutation fuzzing, not coverage-guided fuzzing or VM certification.
mod targets;
use anyhow::{Context, Result, ensure};
use clap::Parser;
use serde_json::json;
use std::{
    fs,
    path::PathBuf,
    process::{Command, Stdio},
    time::{Duration, Instant},
};
const MAX_INPUT: usize = 1024 * 1024;
#[derive(Parser)]
#[command(about = "Bounded current-format mutation fuzzing; preserves failed inputs")]
struct Args {
    #[arg(long)]
    output: PathBuf,
    #[arg(long, default_value_t = 1000)]
    cases: u64,
    #[arg(long, default_value_t = 0x4d4f525048)]
    seed: u64,
    #[arg(long, default_value_t = 30)]
    seconds: u64,
    #[arg(long, hide = true)]
    worker: Option<String>,
    /// Replay one saved input against the named target, under the same resource limits.
    #[arg(long, requires = "worker")]
    replay: Option<PathBuf>,
}
fn limits(seconds: u64) -> Result<()> {
    for (resource, amount) in [
        (libc::RLIMIT_AS, 1024 * 1024 * 1024u64),
        (libc::RLIMIT_CPU, seconds + 1),
        (libc::RLIMIT_FSIZE, 8 * 1024 * 1024u64),
        (libc::RLIMIT_CORE, 0),
    ] {
        let value = libc::rlimit {
            rlim_cur: amount,
            rlim_max: amount,
        };
        // SAFETY: valid resource constants and pointer to a live initialized rlimit.
        ensure!(
            unsafe { libc::setrlimit(resource, &value) } == 0,
            "cannot set fuzz resource limit"
        );
    }
    Ok(())
}
fn next(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}
fn mutate(seed: &[u8], state: &mut u64, case: u64) -> Vec<u8> {
    let mut bytes = seed.to_vec();
    let index = (next(state) as usize) % bytes.len().max(1);
    match case % 10 {
        0 => {} // Retain periodic positive coverage; never claim it is a mutation.
        1 => bytes.clear(),
        2 => bytes.truncate(index),
        3 => {
            if let Some(b) = bytes.get_mut(index) {
                *b ^= 1 << (next(state) % 8);
            }
        }
        4 => {
            if let Some(b) = bytes.get_mut(index) {
                *b = next(state) as u8;
            }
        }
        5 => bytes.extend_from_slice(&[0xff; 16]),
        6 => {
            if !bytes.is_empty() {
                bytes.remove(index);
            }
        }
        7 => {
            bytes.insert(index, next(state) as u8);
        }
        8 => {
            let end = (index + 8).min(bytes.len());
            bytes[index..end].fill(0xff);
        }
        _ => {
            if case % 100 == 99 {
                bytes.resize(MAX_INPUT, 0xff);
            } else {
                bytes.reverse();
            }
        }
    }
    bytes
}
fn hash(bytes: &[u8]) -> String {
    hex::encode(morph_core::blake2b256(bytes))
}
fn save_attempt(a: &Args, name: &str, phase: &str, case: u64, bytes: &[u8]) -> Result<()> {
    fs::write(a.output.join("current.bin"), bytes)?;
    fs::write(
        a.output.join("current.json"),
        serde_json::to_vec(&json!({
            "phase":phase,"case":case,"seed":a.seed,"target":name,"input_hash":hash(bytes)
        }))?,
    )?;
    Ok(())
}
fn failed_worker_result(
    dir: &std::path::Path,
    name: &str,
    timed_out: bool,
    code: Option<i32>,
) -> serde_json::Value {
    let metadata = fs::read(dir.join("current.json"))
        .ok()
        .and_then(|raw| serde_json::from_slice::<serde_json::Value>(&raw).ok());
    // A kill between the two writes must not attribute new bytes to old metadata.
    let input_available = metadata.as_ref().is_some_and(|meta| {
        meta["target"] == name
            && fs::read(dir.join("current.bin"))
                .ok()
                .is_some_and(|raw| raw.len() <= MAX_INPUT && meta["input_hash"] == hash(&raw))
    });
    json!({"status":"fail","target":name,"timeout":timed_out,"exit":code,
        "phase":metadata.as_ref().and_then(|m|m["phase"].as_str()).unwrap_or("interrupted_metadata"),
        "input_available":input_available,"reproducer":input_available.then_some("current.bin"),"metadata":"current.json"})
}
fn worker(a: &Args, name: &str) -> Result<()> {
    limits(a.seconds)?;
    if let Some(path) = &a.replay {
        ensure!(
            fs::metadata(path)?.len() <= MAX_INPUT as u64,
            "input too large"
        );
        let accepted = targets::check(name, &fs::read(path)?)?;
        println!("{}", json!({"accepted":accepted}));
        return Ok(());
    }
    let seeds = targets::seeds(name)?;
    ensure!(!seeds.is_empty(), "empty target corpus");
    let mut corpus = vec![];
    for (i, seed) in seeds.iter().enumerate() {
        save_attempt(a, name, "seed_validation", i as u64, seed)?;
        ensure!(
            seed.len() <= MAX_INPUT && targets::check(name, seed)?,
            "canonical seed rejected: {name}/{i}"
        );
        fs::write(a.output.join(format!("seed-{i}.bin")), seed)?;
        corpus.push(
            json!({"file":format!("seed-{i}.bin"),"ckb_blake2b256":hash(seed),"bytes":seed.len()}),
        );
    }
    let mut state = a.seed;
    let mut accepted = 0u64;
    let mut rejected = 0u64;
    let started = Instant::now();
    for case in 0..a.cases {
        let base = &seeds[((case / 10) as usize) % seeds.len()];
        let bytes = mutate(base, &mut state, case);
        // Persist the exact attempted bytes before parsing, also for abort/OOM/SIGKILL.
        save_attempt(a, name, "mutation", case, &bytes)?;
        if targets::check(name, &bytes)
            .with_context(|| format!("target={name} seed={} case={case}", a.seed))?
        {
            accepted += 1;
        } else {
            rejected += 1;
        }
    }
    ensure!(
        accepted > 0 && rejected > 0,
        "campaign needs positive and negative coverage"
    );
    fs::write(
        a.output.join("result.json"),
        serde_json::to_vec_pretty(
            &json!({"status":"pass","target":name,"cases":a.cases,"seed":a.seed,"accepted":accepted,"rejected":rejected,"elapsed_ms":started.elapsed().as_millis(),"corpus":corpus}),
        )?,
    )?;
    Ok(())
}
fn run(a: &Args) -> Result<()> {
    ensure!(!a.output.exists(), "output must be a fresh directory");
    if let Some(parent) = a.output.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent)?;
    }
    fs::create_dir(&a.output)?;
    let exe = std::env::current_exe()?;
    let started = Instant::now();
    let mut results = vec![];
    let mut all_pass = true;
    for name in targets::NAMES {
        let dir = a.output.join(name);
        fs::create_dir(&dir)?;
        fs::write(
            dir.join("current.json"),
            serde_json::to_vec(&json!({"phase":"corpus_preparation","target":name,"seed":a.seed}))?,
        )?;
        let log = fs::File::create(dir.join("worker.log"))?;
        let mut child = Command::new(&exe)
            .args(["--worker", name, "--output"])
            .arg(&dir)
            .args([
                "--cases",
                &a.cases.to_string(),
                "--seed",
                &a.seed.to_string(),
                "--seconds",
                &a.seconds.to_string(),
            ])
            .stdout(Stdio::from(log.try_clone()?))
            .stderr(Stdio::from(log))
            .spawn()?;
        let start = Instant::now();
        let mut timed_out = false;
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break status;
            }
            if start.elapsed() > Duration::from_secs(a.seconds) {
                timed_out = true;
                child.kill()?;
                break child.wait()?;
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        let pass = status.success() && !timed_out;
        all_pass &= pass;
        let result = if pass {
            serde_json::from_slice::<serde_json::Value>(&fs::read(dir.join("result.json"))?)?
        } else {
            failed_worker_result(&dir, name, timed_out, status.code())
        };
        println!("{name}: {}", if pass { "pass" } else { "FAIL" });
        results.push(result);
    }
    let version = Command::new("rustc").arg("-Vv").output()?;
    ensure!(version.status.success(), "cannot record rustc version");
    fs::write(
        a.output.join("report.json"),
        serde_json::to_vec_pretty(
            &json!({"schema":"morph.bounded_fuzz.v1","status":if all_pass{"pass"}else{"fail"},"algorithm":"xorshift64-mutation-v1","seed":a.seed,"cases_per_target":a.cases,"wall_seconds_per_target":a.seconds,"command":std::env::args().collect::<Vec<_>>(),"max_input_bytes":MAX_INPUT,"memory_limit_bytes":1024*1024*1024u64,"binary_hash":hash(&fs::read(exe)?),"lockfile_hash":hash(include_bytes!("../../../../Cargo.lock")),"rustc":String::from_utf8(version.stdout)?,"elapsed_ms":started.elapsed().as_millis(),"targets":results,"limits":"Mutation campaign only: no coverage feedback, VM execution, concurrency-model or whole-store rollback proof."}),
        )?,
    )?;
    ensure!(
        all_pass,
        "fuzz campaign failed; retain report, worker log and current input"
    );
    Ok(())
}
pub fn main() -> Result<()> {
    let args = Args::parse();
    ensure!(
        (10..=1_000_000).contains(&args.cases),
        "cases must be 10..1000000"
    );
    ensure!((1..=600).contains(&args.seconds), "seconds must be 1..600");
    ensure!(args.seed != 0, "seed must be nonzero");
    if let Some(name) = &args.worker {
        ensure!(targets::NAMES.contains(&name.as_str()), "unknown target");
        worker(&args, name)
    } else {
        run(&args)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn canonical_corpus_passes_all_invariants() -> Result<()> {
        for name in targets::NAMES {
            for seed in targets::seeds(name)? {
                ensure!(targets::check(name, &seed)?, "{name} seed rejected");
            }
        }
        Ok(())
    }
    #[test]
    fn mutation_is_bounded_and_reproducible() {
        let mut a = 17;
        let mut b = 17;
        for i in 0..1000 {
            let x = mutate(b"current-format", &mut a, i);
            assert_eq!(x, mutate(b"current-format", &mut b, i));
            assert!(x.len() <= MAX_INPUT);
        }
    }
    #[test]
    fn failure_reports_never_invent_or_misattribute_a_reproducer() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path();
        fs::write(
            path.join("current.json"),
            br#"{"phase":"corpus_preparation","target":"manifest"}"#,
        )?;
        let row = failed_worker_result(path, "manifest", true, None);
        ensure!(row["phase"] == "corpus_preparation" && row["reproducer"].is_null());
        fs::write(path.join("current.bin"), b"first")?;
        fs::write(
            path.join("current.json"),
            serde_json::to_vec(
                &json!({"phase":"seed_validation","target":"manifest","input_hash":hash(b"first")}),
            )?,
        )?;
        ensure!(failed_worker_result(path, "manifest", true, None)["reproducer"] == "current.bin");
        fs::write(path.join("current.bin"), b"second")?;
        ensure!(failed_worker_result(path, "manifest", true, None)["reproducer"].is_null());
        fs::write(path.join("current.json"), b"{")?;
        ensure!(failed_worker_result(path, "manifest", true, None)["reproducer"].is_null());
        Ok(())
    }
}
