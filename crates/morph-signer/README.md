# morph-signer

Linux private Unix-socket transport for the canonical participant signing review
contract in `morph-packages::signer_protocol`. This crate owns no key or journal.
The CLI integrates it through `participant-signer-serve` and the funding/session
`sign --signer-config` commands. The key process checks the existing journal;
it does not initialize a second authority.

Use `ipc::exchange` only after durably reserving the existing journal's exact
intent. Verify and durably record the resulting receipt before releasing it. Any
error leaves the reservation intact; missing responses do not revoke signatures.

`Listener` accepts one bounded message at a time and returns `Message::Sign` or
`Message::Probe`. `Incoming::request` exposes
decoded data, not authorization. A service must independently validate canonical
contents, installed policy, chain/admission, expiry and intact authority before
using a key. The library uses same-UID peer credentials and private filesystem
endpoints; it does not isolate secrets from a hostile same-account process.

`ipc::probe` is a separate, read-only control operation on this same listener.
It carries a fresh caller challenge and protected-config digest, never a signing
payload. The fixed 72-byte request (`MORPHP?!`, challenge32, digest32) and 73-byte
reply (`MORPHPR!`, challenge32, digest32, bool1) use the same length prefix,
half-close, peer credentials, filesystem checks and total I/O deadline. These
magics cannot parse as signature-request JSON. The responder must independently
check its installed policy and current config before reporting ready. A probe
reply is not a signature or cryptographic proof of key possession. A busy signing
listener cannot be hidden by an independent healthy heartbeat.

See [ADR 003](../../docs/adr/003-participant-signer-boundary.md) for implemented
bounds, tests, the explicit whole-store rollback limitation and integration work.
