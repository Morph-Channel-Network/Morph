# Morph / Fiber cost accounting — 2026-11-12

Snapshot: 2026-11-12T01:14:21.850366+08:00. CKB/USD 0.00096216; CKB/CNY 0.00641942.

This is a reporting supplement, not a new qualification receipt. Morph source `991f7e30ab2f1225afbccd72862f60784a154196`; integration-pinned Fiber `a5faac7177a2a2ec086a2c6d0da1840ec9fe5703`. Code and price dates are separate.

- `price-response.json`: raw CoinGecko API response; `price-snapshot.json`: endpoint, retrieval and provider timestamps.
- `comparison.json`: exact source identities, observed native/VM rows, explicitly source-derived Fiber shapes, ordinary capacity scenario, complete eight-claim branch totals and shared code bytes.
- `geometry.rs` / `geometry-output.txt`: audit-only canonical serialization and occupied-capacity reconstruction. Zero keys/bytes are sizing placeholders; no claim of runnable funding/close transactions or signature validation. This is not a second protocol implementation.
- `source-provenance.json`: Fiber source hashes and byte-for-byte checks against the pinned Git objects.
- `capacity-comparison.svg` / `.png`: the specified ordinary two-sided-token scenario, not conditional or Factory capacity qualification.
- `plot-capacity.py`: plotting recipe (matplotlib and WenQuanYi Zen Hei font; regenerates SVG/PNG beside the script).
- `SHA256SUMS`: artifact integrity.

Fee accounting: raw Morph sizes require +4 bytes per transaction to match `serialized_size_in_block()`. Fiber figures already include the block offset; comparison records both. For the pinned CKB source, the initial low-fee check uses size; miner ranking uses `max(size, floor(cycles * 0.0001705714))`. A scenario of 1,000 shannons/kB is not a live market quote. Native Morph configured fees (100k / replacement 200k) are distinct from this scenario. Native ten-right metadata is compute-dominated (6,518 block bytes, weight 7,685); most other listed Morph shapes are byte-dominated. Pinned Fiber cooperative shutdown deducts a whole size-based fee from each participant; commitment deducts once. Fiber cycles and complete forced-close/conditional transaction cost were not remeasured here.

Capacity: common payout args=20, token Type args=32, token data=16; every token has two nonzero participant payouts. Morph root `464 + 284*N` CKB; Fiber pure exit geometry `358*N`, default `360*N` including the two-party fee buffer. The primary same-no-buffer comparison is 4.47% at eight assets; the default-buffer comparison is 5%. Excludes spendable business liquidity, conditional output overhead, extra operating buffers, platform services and opportunity cost. Capacity is returned on valid consumption, never a burnt fee.

To reconstruct geometry, use Rust 1.95 and a matching `ckb-types` 1.1.4 rlib from the Morph build:

```sh
rustc --edition=2024 geometry.rs --extern ckb_types=/absolute/path/to/libckb_types-HASH.rlib -L dependency=/absolute/path/to/deps -o /tmp/morph-fiber-geometry
/tmp/morph-fiber-geometry
```

Published Morph native baseline: `../model-cost-991f7e3/native/transactions.json` and `native-condition-metrics.json`. Cooperative-close rows are public metric-only projections from the same private qualification run (source file digest recorded); no private journals, raw signed transactions or key material were copied. Claim branches are mutually exclusive reorg experiments, not simultaneous payments.
