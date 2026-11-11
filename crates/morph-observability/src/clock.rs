//! Local observation clock, never a monotonic signing authority or rollback oracle.
use std::io;

#[derive(Debug, Clone)]
pub struct BootClock {
    pub id: String,
    pub ms: u64,
}
#[cfg(target_os = "linux")]
pub fn read() -> io::Result<BootClock> {
    let raw = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    let id = raw.trim();
    if id.len() != 36
        || !id.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
    {
        return Err(io::Error::other("invalid kernel boot identity"));
    }
    let time = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
    let seconds: u64 = time
        .tv_sec
        .try_into()
        .map_err(|_| io::Error::other("invalid boot time"))?;
    let nanos: u64 = time
        .tv_nsec
        .try_into()
        .map_err(|_| io::Error::other("invalid boot time"))?;
    let ms = seconds
        .checked_mul(1000)
        .and_then(|s| s.checked_add(nanos / 1_000_000))
        .ok_or_else(|| io::Error::other("invalid boot time"))?;
    Ok(BootClock { id: id.into(), ms })
}
#[cfg(not(target_os = "linux"))]
pub fn read() -> io::Result<BootClock> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "observation boot clock requires Linux",
    ))
}
