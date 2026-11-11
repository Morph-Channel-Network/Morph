# Local CKB wallet

The native desktop now has an independent **Wallet** workspace. A Hub connection is not required. This is an unpublished Linux implementation; its transfer evidence is from an isolated development chain, not production qualification.

## Everyday flow

1. Create a wallet with a name and password, import a protected key file, or restore a current wallet backup. Passwords need at least 12 characters and at most 1,024 bytes.
2. In Wallet → Settings, choose the network and CKB RPC. An empty Indexer endpoint uses the same RPC. The client verifies the public-network genesis, or pins the explicitly selected development genesis.
3. Back up the wallet before funding it. Receive shows the current full Bech32m address and QR code. Addresses encode the lock, not a particular token.
4. Send asks for recipient, asset and amount. The backend reads live cells, estimates the node fee rate, chooses inputs and change, and computes occupied capacity. Review the recipient, exact asset identity, amount, fee and change, then explicitly confirm.
5. Submission persists the exact signed transaction first. Inspect its hash and status in Transactions. A timeout means unresolved, not safely cancelled. Resend uses the saved bytes, never a newly constructed payment.

Balances refresh every 20 seconds while the wallet page is active, except during a transaction review. The displayed block identifies the observation. Sending always performs fresh checks. CKB plain available capacity, total capacity, occupied capacity, immature cellbase and signed-input reservations are different quantities; they are not additive buckets.

## Keys and backups

The wallet holds one standard secp256k1 key, not an HD/mnemonic account hierarchy. Creation uses the OS CSPRNG. Raw-key import goes through `morph-key-input`; no raw-key argv, environment or text-field path is added.

The private directory is `$XDG_CONFIG_HOME/morph/wallet`, falling back to `$HOME/.config/morph/wallet`. It requires owner-only access and a stable exclusive lock. Files are bounded, written privately and fsynced. Do not run two processes against the same directory.

The key is encrypted with Argon2id v19 (64 MiB, three passes, one lane) and AES-256-GCM with random salt and nonce. Wallet metadata is authenticated. Wrong passwords or modified ciphertext fail closed. The worker locks after five minutes without signing/unlock/secret activity. Changing the password re-encrypts the key and locks the wallet; it does not change the key/address.

The current `morph.local_wallet_backup.v1` backup includes:

- The encrypted key and authenticated encrypted invoice preimages.
- Public network/asset settings.
- Exact signed transaction evidence and its input reservations, across saved networks.

**Public metadata in the backup is readable.** The key and invoice secrets are encrypted. Keep the backup and password separately. Back up again after new invoice secrets or pending payments. An old backup can omit newer evidence; restoring the scalar alone does not restore those records. Channel signing journals are separate and must never be rolled back or replaced with this backup.

## Tokens and addresses

Only current RFC 21 full Bech32m recipient addresses are accepted. Network mismatches and malformed checksums are rejected. This does not introduce retired Morph formats.

Unknown 16-byte typed cells appear as unverified base-unit quantities; their shape alone does not prove xUDT semantics. Transfers require an explicit, network-bound asset definition. Import a public JSON file, inspect the network, Type hash and decimal precision against the issuer, then add it. A display symbol is never identity. Existing definitions cannot be silently replaced.

```json
{
  "genesis_hash": "0x<64 lowercase hex characters>",
  "assets": [{
    "symbol": "TOKEN",
    "decimals": 8,
    "script": {
      "code_hash": "0x<deployed type code hash>",
      "hash_type": "data2",
      "args": "0x<token args>"
    },
    "dependency": {
      "out_point": {"tx_hash": "0x<deployment transaction>", "index": "0x0"},
      "dep_type": "code"
    }
  }]
}
```

These placeholders are documentation, not a valid asset deployment. This bounded transfer path supports one declared token dependency/dependency group; arbitrary extensions needing additional transaction structure are not implicitly supported. Node script preflight must succeed. Tokens of different Types, CKB fees and occupied capacity are conserved independently.

## Exact transaction policy

Quotes expire after 90 seconds and are consumed once. Up to 64 inputs are selected from a maximum of 4,096 indexed cells. The fee-rate policy accepts 1–100,000 shannons/KB, and total fees may not exceed 100,000 shannons. Amounts use checked integers throughout. Data-bearing cells are never silently consumed to fund CKB payments. Insufficient capacity for valid change fails instead of donating dust as a fee.

Reads are bounded by response size and deadlines. Sync verifies the configured genesis, canonical indexer checkpoint, maximum three-block lag and stability across pages. This trusts the configured node's chain view; it is not a light-client consensus proof. The UI clears balances after a failed refresh. Transaction status is queried at the same pinned network; confirmations can change after a reorg.

Saved signed inputs remain reserved until they are spent. A node rejection does not revoke a signature. There is currently no fee-bump/cancel replacement workflow or automatic reservation abandonment. Local transaction evidence is bounded; history displays at most 200 entries. These are explicit current limits, not a claim that every possible wallet recovery workflow is complete.

Transactions automatically load the first history page and show net changes for this wallet, separately for CKB and each token Type. Change outputs cancel against spent inputs rather than appearing as new income. CKB net change includes transaction fees and cell capacity transfers. Details show the entire transaction fee only where ordinary capacity accounting applies; header-dependent transactions such as DAO withdrawals do not receive an inferred fee. Unsupported token data is explicitly left unresolved. History resolves at most ten transactions per page, 64 inputs/128 outputs per transaction, under a total 30-second read budget, with a canonical stable Indexer checkpoint. Oversized or unavailable history fails visibly instead of inventing a partial balance change.

## Morph integration

Ordinary Morph invoice creation obtains a random preimage from the unlocked wallet. The wallet encrypts and fsyncs it before returning it to the draft. The default screen shows amount and optional description; expiry, channel binding and an externally managed payment hash are advanced options. A matching local preimage can be retrieved for settlement after unlock.

The wallet does **not** yet authorize channel funding or splice. The existing CLI path reconstructs the exact funding body, validates complete initial exits, reserves admission, verifies the canonical checkpoint and signs only the declared wallet group. That path must become a shared backend before exposing a funding wizard. `POST /api/channels` registers a local record and is not a funding transaction.

## Focused verification

```sh
cargo test --locked -p morph-wallet
LIBRARY_PATH="$PWD/target/native-libs${LIBRARY_PATH:+:$LIBRARY_PATH}" \
  cargo test --locked -p morph-desktop
```

`crates/morph-wallet/tests/native.rs` contains two explicitly ignored node tests. They require a dedicated CKB 0.209.0 development node with Indexer and IntegrationTest RPC on `127.0.0.1:18314`; they verify the fixture genesis before using its public test issuer. Never point these tests at another node. The token scenario also uses the already-built `morph-devnet-xudt` ELF, solely for development evidence.

```sh
cargo test --locked -p morph-wallet --test native -- \
  --ignored --nocapture --test-threads=1
```

Evidence covers actual CKB receipt, xUDT receipt and change, separate CKB fee/change, exact-hash submission, one-shot review, encrypted backup restoration and saved invoice secret recovery. It does not replace production security review, deployed-asset qualification or native user acceptance.


## Connection presets and real-chain walkthrough

The connection screen offers public / local / custom sources. Public Testnet uses
`https://testnet.ckb.dev/`; public Mainnet uses `https://mainnet.ckb.dev/`.
Local public-network nodes default to port 8114, Morph Devnet to 18114.
Choose Custom for another port or an independent indexer; an empty indexer field
uses the node URL. Selecting a preset edits a draft; **Connect & verify** checks
network identity and indexer consistency before persisting it. There is no silent
provider failover. Existing wallet configuration takes precedence over defaults.

Backup and password changes now live under wallet settings; changing the password
is an explicit disclosure. Wallet pages remain useful while locked; unlock when
sending or when explicitly requested.

A complete disposable demonstration is available through
`scripts/native-wallet-showcase.sh`; see the [UI report](../native-ui-refinement-2026-11-10.md)
for prerequisites, the public development password and retained transaction evidence.
