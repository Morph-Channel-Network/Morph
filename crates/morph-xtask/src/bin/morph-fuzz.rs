//! Bounded deterministic mutation campaigns, separate from the async RPC runners.
#[cfg(target_os = "linux")]
#[path = "../fuzz/mod.rs"]
mod fuzz;
fn main() -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    return fuzz::main();
    #[cfg(not(target_os = "linux"))]
    anyhow::bail!("bounded fuzz campaigns require Linux resource limits");
}
