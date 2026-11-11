//! Linux filesystem Unix sockets, same effective UID on both ends. The parent
//! must be private; root and the account itself remain trusted. This isolates
//! process responsibilities, NOT a hostile process running as the same account.
//! One u32-BE length-prefixed JSON frame per half-closed connection, no pipelining.
//! All socket syscalls are nonblocking. A single monotonic deadline covers I/O.
use crate::{
    Error,
    signer_protocol::{MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, Request, Response},
};
use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    fd::OwnedFd,
    io::Errno,
    net::{
        self, AddressFamily, RecvFlags, SendFlags, Shutdown, SocketAddrUnix, SocketFlags,
        SocketType,
    },
};
use std::{
    fs,
    marker::PhantomData,
    os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt},
    path::{Component, Path, PathBuf},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

pub const MAX_TIMEOUT: Duration = Duration::from_secs(30);
const BACKLOG: i32 = 4;
// Separate control operation, never a signing Request or signing Response.
const PROBE_MAGIC: &[u8; 8] = b"MORPHP?!";
const PROBE_REPLY_MAGIC: &[u8; 8] = b"MORPHPR!";
const PROBE_LEN: usize = 72;
const PROBE_REPLY_LEN: usize = 73;
type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Copy)]
struct Deadline(Instant);
impl Deadline {
    fn new(timeout: Duration) -> Result<Self> {
        if timeout.is_zero() || timeout > MAX_TIMEOUT {
            return Err(Error::InvalidDeadline);
        }
        Ok(Self(Instant::now() + timeout))
    }
    fn remaining(self) -> Result<Duration> {
        self.0
            .checked_duration_since(Instant::now())
            .filter(|left| !left.is_zero())
            .ok_or(Error::Deadline)
    }
}

pub(crate) fn private_parent(path: &Path) -> Result<()> {
    if !path.is_absolute() || path.file_name().is_none() {
        return Err(Error::UntrustedEndpoint);
    }
    let parent = path.parent().ok_or(Error::UntrustedEndpoint)?;
    let uid = rustix::process::geteuid().as_raw();
    let mut at = PathBuf::new();
    let mut private_ancestor = false;
    for component in parent.components() {
        match component {
            Component::RootDir | Component::Normal(_) => at.push(component.as_os_str()),
            _ => return Err(Error::UntrustedEndpoint),
        }
        let meta = fs::symlink_metadata(&at).map_err(|_| Error::UntrustedEndpoint)?;
        let mode = meta.mode();
        // A root-owned sticky temporary ancestor is safe only because the leaf
        // parent is separately required to be owned by us and inaccessible to others.
        let sticky_root = meta.uid() == 0 && mode & 0o1000 != 0;
        if !meta.is_dir()
            || (meta.uid() != 0 && meta.uid() != uid)
            || (mode & 0o022 != 0 && !sticky_root && !private_ancestor)
        {
            return Err(Error::UntrustedEndpoint);
        }
        // Once an owner-only directory blocks all other accounts from the
        // entire subtree, permissive descendant mode bits alone do not expose
        // it. Ownership and no-symlink checks still apply to every component.
        private_ancestor |= meta.uid() == uid && mode & 0o077 == 0 && mode & 0o100 != 0;
    }
    let meta = fs::symlink_metadata(parent).map_err(|_| Error::UntrustedEndpoint)?;
    if meta.uid() != uid || meta.mode() & 0o777 != 0o700 {
        return Err(Error::UntrustedEndpoint);
    }
    Ok(())
}
fn endpoint(path: &Path) -> Result<(u64, u64)> {
    private_parent(path)?;
    let meta = fs::symlink_metadata(path).map_err(|_| Error::UntrustedEndpoint)?;
    if !meta.file_type().is_socket()
        || meta.uid() != rustix::process::geteuid().as_raw()
        || meta.mode() & 0o777 != 0o600
        || meta.nlink() != 1
    {
        return Err(Error::UntrustedEndpoint);
    }
    Ok((meta.dev(), meta.ino()))
}
fn peer(fd: &OwnedFd) -> Result<()> {
    let credentials = net::sockopt::socket_peercred(fd).map_err(|_| Error::UntrustedEndpoint)?;
    if credentials.uid != rustix::process::geteuid() {
        return Err(Error::UntrustedEndpoint);
    }
    Ok(())
}
fn socket() -> Result<OwnedFd> {
    net::socket_with(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
        None,
    )
    .map_err(|_| Error::Unavailable)
}
fn wait(fd: &OwnedFd, flags: PollFlags, deadline: Deadline) -> Result<()> {
    loop {
        let remaining = deadline.remaining()?;
        let timeout = Timespec {
            tv_sec: remaining.as_secs() as _,
            tv_nsec: remaining.subsec_nanos() as _,
        };
        let mut fds = [PollFd::new(fd, flags)];
        match poll(&mut fds, Some(&timeout)) {
            Ok(0) => return Err(Error::Deadline),
            // HUP/ERR wake the subsequent nonblocking syscall, which reports
            // EOF or the concrete failure without a spin or another timeout.
            Ok(_) => return Ok(()),
            Err(Errno::INTR) => continue,
            Err(_) => return Err(Error::Unavailable),
        }
    }
}
fn read(fd: &OwnedFd, buf: &mut [u8], deadline: Deadline) -> Result<usize> {
    loop {
        deadline.remaining()?;
        match net::recv(fd, &mut *buf, RecvFlags::empty()) {
            Ok((_, size)) => return Ok(size),
            Err(Errno::INTR) => continue,
            Err(Errno::AGAIN) => wait(fd, PollFlags::IN, deadline)?,
            Err(_) => return Err(Error::Unavailable),
        }
    }
}
fn read_exact(fd: &OwnedFd, mut buf: &mut [u8], deadline: Deadline) -> Result<()> {
    while !buf.is_empty() {
        let count = read(fd, buf, deadline)?;
        if count == 0 {
            return Err(Error::InvalidFrame);
        }
        buf = &mut buf[count..];
    }
    Ok(())
}
fn write_all(fd: &OwnedFd, mut buf: &[u8], deadline: Deadline) -> Result<()> {
    while !buf.is_empty() {
        deadline.remaining()?;
        match net::send(fd, buf, SendFlags::NOSIGNAL) {
            Ok(0) => return Err(Error::Unavailable),
            Ok(count) => buf = &buf[count..],
            Err(Errno::INTR) => continue,
            Err(Errno::AGAIN) => wait(fd, PollFlags::OUT, deadline)?,
            Err(_) => return Err(Error::Unavailable),
        }
    }
    Ok(())
}
fn receive(fd: &OwnedFd, max: usize, deadline: Deadline) -> Result<Zeroizing<Vec<u8>>> {
    let mut prefix = [0; 4];
    read_exact(fd, &mut prefix, deadline)?;
    let size = u32::from_be_bytes(prefix) as usize;
    if size == 0 || size > max {
        return Err(Error::InvalidFrame);
    }
    let mut body = Zeroizing::new(vec![0; size]);
    read_exact(fd, &mut body, deadline)?;
    if read(fd, &mut [0; 1], deadline)? != 0 {
        return Err(Error::InvalidFrame);
    }
    Ok(body)
}
fn send(fd: &OwnedFd, body: &[u8], max: usize, deadline: Deadline) -> Result<()> {
    if body.is_empty() || body.len() > max {
        return Err(Error::InvalidFrame);
    }
    write_all(fd, &(body.len() as u32).to_be_bytes(), deadline)?;
    write_all(fd, body, deadline)?;
    net::shutdown(fd, Shutdown::Write).map_err(|_| Error::Unavailable)
}

/// Call ONLY after durable reservation. No automatic reconnect or retry, and no
/// journal mutation. Any error leaves the reservation intact. A received valid
/// signature remains authority even if the request's wall-clock expiry passed.
pub fn exchange(path: &Path, request: &Request, timeout: Duration) -> Result<Response> {
    let deadline = Deadline::new(timeout)?;
    let bytes = Zeroizing::new(request.encode().map_err(|_| Error::InvalidRequest)?);
    let fd = connect(path, deadline)?;
    // Once a write is attempted, even a transport error is an unknown outcome.
    send(&fd, &bytes, MAX_REQUEST_BYTES, deadline).map_err(|_| Error::OutcomeUnknown)?;
    let reply = receive(&fd, MAX_RESPONSE_BYTES, deadline).map_err(|_| Error::OutcomeUnknown)?;
    let response = Response::decode(&reply).map_err(|_| Error::InvalidResponse)?;
    response
        .verify(request)
        .map_err(|_| Error::InvalidResponse)?;
    Ok(response)
}

fn connect(path: &Path, deadline: Deadline) -> Result<OwnedFd> {
    let identity = endpoint(path)?;
    let fd = socket()?;
    let address = SocketAddrUnix::new(path).map_err(|_| Error::UntrustedEndpoint)?;
    // A full AF_UNIX backlog yields EAGAIN; return busy without an implicit retry.
    // No data has been sent. Still never let a caller undo its reservation.
    match net::connect(&fd, &address) {
        Ok(()) => (),
        Err(Errno::INPROGRESS) => {
            wait(&fd, PollFlags::OUT, deadline)?;
            net::sockopt::socket_error(&fd)
                .map_err(|_| Error::Unavailable)?
                .map_err(|_| Error::Unavailable)?;
        }
        Err(_) => return Err(Error::Unavailable),
    }
    peer(&fd)?;
    if endpoint(path)? != identity {
        return Err(Error::UntrustedEndpoint);
    }
    Ok(fd)
}

/// Read-only live policy observation. The caller supplies a fresh random
/// challenge and the digest of its independently loaded protected configuration.
/// Same-UID endpoint authentication applies; this is not a key-possession proof.
/// No signing request, reservation, retries or journal I/O occurs here.
pub fn probe(
    path: &Path,
    challenge: [u8; 32],
    policy: [u8; 32],
    timeout: Duration,
) -> Result<bool> {
    let deadline = Deadline::new(timeout)?;
    let fd = connect(path, deadline)?;
    let mut body = [0; PROBE_LEN];
    body[..8].copy_from_slice(PROBE_MAGIC);
    body[8..40].copy_from_slice(&challenge);
    body[40..].copy_from_slice(&policy);
    send(&fd, &body, PROBE_LEN, deadline)?;
    let reply = receive(&fd, PROBE_REPLY_LEN, deadline)?;
    if reply.len() != PROBE_REPLY_LEN
        || &reply[..8] != PROBE_REPLY_MAGIC
        || reply[8..40] != challenge
        || reply[40..72] != policy
        || reply[72] > 1
    {
        return Err(Error::InvalidResponse);
    }
    Ok(reply[72] == 1)
}

pub enum Message<'a> {
    Sign(Incoming<'a>),
    Probe(ProbeIncoming<'a>),
}
impl<'a> Message<'a> {
    /// Explicitly reject a control operation when a signing request is expected.
    pub fn into_signing(self) -> Result<Incoming<'a>> {
        match self {
            Self::Sign(request) => Ok(request),
            Self::Probe(_) => Err(Error::InvalidRequest),
        }
    }
}
pub struct ProbeIncoming<'a> {
    fd: OwnedFd,
    deadline: Deadline,
    challenge: [u8; 32],
    policy: [u8; 32],
    _listener: PhantomData<&'a mut Listener>,
}
impl ProbeIncoming<'_> {
    /// Compare the loaded policy with the requested policy and independently
    /// check that the configured file has not changed before reporting readiness.
    /// A control reply contains no signature, key, journal data or caller strings.
    pub fn respond(self, loaded_policy: [u8; 32], configuration_unchanged: bool) -> Result<()> {
        let mut reply = [0; PROBE_REPLY_LEN];
        reply[..8].copy_from_slice(PROBE_REPLY_MAGIC);
        reply[8..40].copy_from_slice(&self.challenge);
        reply[40..72].copy_from_slice(&self.policy);
        reply[72] = u8::from(configuration_unchanged && self.policy == loaded_policy);
        send(&self.fd, &reply, PROBE_REPLY_LEN, self.deadline)
    }
}

/// One accepted connection at a time. A mutable borrow is retained by Incoming,
/// preventing a second acceptance until it is responded to or dropped. No worker
/// spawning and no unbounded in-process request queue. Kernel backlog is four.
pub struct Listener {
    fd: OwnedFd,
    path: PathBuf,
    identity: (u64, u64),
}
impl Listener {
    /// Never replaces an existing socket/file. Operator removal of a stale socket
    /// must occur only after establishing the old service is stopped.
    pub fn bind(path: &Path) -> Result<Self> {
        private_parent(path)?;
        let fd = socket()?;
        let address = SocketAddrUnix::new(path).map_err(|_| Error::UntrustedEndpoint)?;
        net::bind(&fd, &address).map_err(|_| Error::Unavailable)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|_| Error::UntrustedEndpoint)?;
        let identity = endpoint(path)?;
        let listener = Self {
            fd,
            path: path.to_owned(),
            identity,
        };
        net::listen(&listener.fd, BACKLOG).map_err(|_| Error::Unavailable)?;
        Ok(listener)
    }
    /// Reads a bounded request. This performs encoding validation only; it does
    /// not grant authorization, admission, freshness or permission to use a key.
    /// The timeout includes waiting for a connection and reading its full frame.
    pub fn receive(&mut self, timeout: Duration) -> Result<Message<'_>> {
        let deadline = Deadline::new(timeout)?;
        if endpoint(&self.path)? != self.identity {
            return Err(Error::UntrustedEndpoint);
        }
        let fd = loop {
            deadline.remaining()?;
            match net::accept_with(&self.fd, SocketFlags::CLOEXEC | SocketFlags::NONBLOCK) {
                Ok(fd) => break fd,
                Err(Errno::INTR) => continue,
                Err(Errno::AGAIN) => wait(&self.fd, PollFlags::IN, deadline)?,
                Err(_) => return Err(Error::Unavailable),
            }
        };
        peer(&fd)?;
        let bytes = receive(&fd, MAX_REQUEST_BYTES, deadline)?;
        if bytes.starts_with(PROBE_MAGIC) {
            if bytes.len() != PROBE_LEN {
                return Err(Error::InvalidRequest);
            }
            return Ok(Message::Probe(ProbeIncoming {
                fd,
                deadline,
                challenge: bytes[8..40].try_into().map_err(|_| Error::InvalidRequest)?,
                policy: bytes[40..72]
                    .try_into()
                    .map_err(|_| Error::InvalidRequest)?,
                _listener: PhantomData,
            }));
        }
        let request = Request::decode(&bytes).map_err(|_| Error::InvalidRequest)?;
        Ok(Message::Sign(Incoming {
            fd,
            deadline,
            request: Box::new(request),
            _listener: PhantomData,
        }))
    }
}
impl Drop for Listener {
    fn drop(&mut self) {
        // Never remove a path replaced by another service or any non-socket.
        if endpoint(&self.path).is_ok_and(|identity| identity == self.identity) {
            let _ = fs::remove_file(&self.path);
        }
    }
}
pub struct Incoming<'a> {
    fd: OwnedFd,
    deadline: Deadline,
    request: Box<Request>,
    _listener: PhantomData<&'a mut Listener>,
}
impl Incoming<'_> {
    pub fn request(&self) -> &Request {
        &self.request
    }
    /// Remaining transport budget for validation, RPC and persistence. A service
    /// must also check the request's absolute wall-clock expiry before signing.
    /// Exceeding either deadline never rolls back a durable reservation.
    pub fn remaining(&self) -> Result<Duration> {
        self.deadline.remaining()
    }
    /// Return only an authorized signature for an already durable reservation.
    /// The caller must record/fsync before releasing its participant receipt.
    /// A failed send cannot revoke the signature. Exactly one reply is permitted.
    pub fn respond(self, response: &Response) -> Result<()> {
        response
            .verify(&self.request)
            .map_err(|_| Error::InvalidResponse)?;
        let bytes =
            Zeroizing::new(serde_json::to_vec(response).map_err(|_| Error::InvalidResponse)?);
        send(&self.fd, &bytes, MAX_RESPONSE_BYTES, self.deadline)
    }
}

#[cfg(test)]
mod tests;
