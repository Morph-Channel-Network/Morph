# Morph Rust SDK

The native client uses the same protocol/package implementation as the CLI.
There is no parallel wire codec or signer journal in this crate.

```rust
use morph_sdk::HubClient;

async fn read_hub(bearer_secret: String) -> Result<(), Box<dyn std::error::Error>> {
    let client = HubClient::new("http://127.0.0.1:4617")?
        .with_token(bearer_secret)?;
    let state = client.state().await?;
    println!("{}", serde_json::to_string_pretty(&state)?);
    Ok(())
}
```

The caller supplies its runtime secret through its own protected input path;
there is no implicit environment, configuration, URL token or command-line
secret loader. The Hub applies scopes to the configured secret. The client's
Debug output is redacted; requests have bounded size/time, no redirects and no
automatic mutation retry. `HubClientError::OutcomeUnknown { mutation }` retains
its original key/revision for an explicit identical retry. It does not authorize
a cancellation or signer reset. Bind interactive writes to the reviewed
`HubView.revision` with `with_expected_revision`; use `with_mutation` only to
repeat the same request. See [the v1 mutation contract](../../docs/hub-api-mutations.md).

`morph_sdk::api` exposes owned public Hub requests/views. Private persisted Hub
state and monotonic signer journals remain server/operator implementation
objects. Amount strings and revisions are canonical decimal, identifiers canonical hex;
all Hub-owned u64 fields use the same decimal-string contract. Generated
[type schemas](../../docs/api/README.md) are checked by CI. Administrative export/preview/restore use `StateArchive` and
`RestoreArchiveRequest`, separate from the private runtime snapshot. Archive
amounts preserve the full u128 range as decimal strings; old raw-snapshot shapes
are rejected. [Generated Hub endpoints](../../docs/api/hub-endpoints.md) and
[OpenAPI](../../docs/api/hub-openapi.json) share the server's route registry.

`morph_sdk::inspection::{inspect, inspect_signature}` review public documents via
canonical package/Core validation. `morph_sdk::packages::construction` exposes
stateless proposal/root/splice construction and exact signature-role checks.
Construction/review never reserves a state number, signs a channel proposal or
reconstructs a lost signer journal. Operational signatures still use the current
funding/channel/Factory ceremony.

`PaymentGatewayClient` and `morph_sdk::gateway` reuse the existing Rust gateway's
payer authorization, signed receipts, x402 header codec and authenticated
fair-exchange decryption. Paid resource requests never inherit the gateway API
bearer token, require the signed method, and validate an independently pinned
receipt signer. Both GET and payload-carrying methods are supported.

Run `make rust-client-check`. Current package review tests reuse the canonical
samples under `fixtures/protocol`; the independent current authorization vector
lives at `fixtures/gateway/authorization.json`. Transport ambiguity, redirects,
precision and actual Hub/Gateway service paths have native Rust coverage. There
is no old SDK operation-name dispatcher or historical snapshot loader.
