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
automatic mutation retry. `HubClientError::OutcomeUnknown` means reconcile before
issuing another write. It does not authorize a cancellation or signer reset.

`morph_sdk::api` exposes owned public Hub requests/views. Private persisted Hub
state and monotonic signer journals remain server/operator implementation
objects. Public quantities are decimal strings/canonical hex; dynamic state-file
exports preserve u128 integers without conversion to floating point.

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

Run `make rust-client-check`. Independent protocol and authorization vectors live
under `fixtures/interop`; transport ambiguity, redirects, precision and actual
Hub/Gateway service paths have native Rust coverage. The SDK neither evaluates
retired scripts nor admits noncanonical earlier requirement identifiers.
