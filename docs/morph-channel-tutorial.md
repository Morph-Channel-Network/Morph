# Morph Channel Tutorial

This tutorial explains Morph Channel gently. It is for readers who want the
idea before reading scripts, proof bodies, and devnet reports.

## The Problem

On-chain transactions are reliable, but they are not the best place to record
every small payment or balance change. A channel lets two parties lock assets
once, update balances off chain, and use the chain only when they need a public
settlement.

Morph Channel asks: what does that look like when the base chain is CKB and the
native object is a Cell?

## The Basic Picture

```mermaid
flowchart LR
    A["Alice"] <-->|"signed off-chain states"| B["Bob"]
    A --> S["State Cell"]
    B --> S
    S --> V["Vault Cell"]
    V --> O["settlement outputs"]
```

There are two important Cells:

- the **State Cell** says which channel state is publicly enforceable;
- the **Vault Cell** holds the assets.

Alice and Bob can exchange many signed states without touching the chain. If
they need to settle, the latest signed state can be published and the vault can
later pay out according to that state.

## Step 1: Open

Alice and Bob create:

```text
State Cell  -> channel identity, state number, funding anchor, settlement hash
Vault Cell  -> locked CKB or xUDT assets
Sponsor Cell -> optional fee budget for publication
```

From a user's point of view, this is a deposit. The funds are no longer in an
ordinary wallet cell; they are held by channel rules.

## Step 2: Update Off Chain

```mermaid
sequenceDiagram
    participant A as Alice
    participant B as Bob
    A->>B: state #1 signed
    B->>A: state #2 signed
    A->>B: state #3 signed
```

Each newer state has a higher state number. The scripts reject stale or equal
state numbers, so the public path moves forward.

## Step 3: Publish

If Alice or Bob needs the chain to recognise the latest state, they publish a
signed package.

```mermaid
flowchart TB
    P["signed package"] --> T["publication transaction"]
    F["Sponsor Cell"] --> T
    T --> N["new settling State Cell"]
    N --> C["state-type verifies signatures"]
```

The sponsor can pay the fee, but sponsor capacity cannot change the channel's
settlement. This keeps fee payment separate from value ownership.

## Step 4: Finalise

After the relative `since` delay, the Vault Cell can be spent.

```mermaid
flowchart LR
    S["current settling State Cell"] --> V["Vault lock"]
    V --> A["Alice output"]
    V --> B["Bob output"]
```

The vault lock checks that the settlement outputs match the descriptor
committed in the signed state. For xUDT, it also checks token type and exact
token amounts.

## Step 5: Resize / Re-anchor (`SPLICE` on the wire)

A resize changes a channel's funding context without closing the logical
relationship. The current wire format, package names, and CLI retain the
historical name `SPLICE`.

```mermaid
flowchart LR
    O["old funding anchor"] --> W["splice witness"]
    W --> N["new funding anchor"]
    N --> V["new vault set"]
```

Resize-in adds assets. Resize-out withdraws assets. The channel keeps its stable
`channel_id`, but its signed funding anchor, Vault commitments, and
`funding_epoch` move forward; tooling derives a new `funding_context_id` from
that context and the exact Vault OutPoint. The old Vault is consumed and the
successor Vault is committed to the new State Header. For resize-out,
participant signatures also bind the exact withdrawal lock, and the vault
script requires an output with that lock and the exact CKB/xUDT amount.

## Step 6: Factory Channels

A factory is a shared reserve that can create child channels.

```mermaid
flowchart TB
    F["Factory State Cell"] --> R["reserve rights"]
    FV["Factory Vault Cell"] --> R
    R --> C1["child channel"]
    R --> C2["child channel"]
```

The conservative path requires all factory participants to sign. Reduced paths
prove a narrow local change, such as one participant reducing their own reserve
claim. Factory scripts receive those proofs through `WitnessEnvelope`.

An internal rights update can remain off chain while the required participants
cooperate and the Factory Vault does not change. Adding/removing Factory funds,
materialising a child channel, or enforcing an exit requires an on-chain
transaction. General multi-right reduced rebalancing is not part of the current
bounded proof profile.

## Why `WitnessEnvelope` Matters

Earlier factory work used body names that still end in `current`. In the current
design, the public contract-facing factory witness is an envelope:

```mermaid
flowchart LR
    E["WitnessEnvelope"] --> K["kind"]
    E --> L["body length"]
    E --> D["body digest"]
    K --> B["specific fixed-layout body"]
```

That means the script first authenticates the envelope, then parses the body
chosen by the envelope kind.

## What To Run First

For local development:

```sh
make ci
make build-contracts
make contract-tests
```

For a local devnet smoke run:

```sh
scripts/devnet-node.sh
make devnet-smoke
```

For the full local stateful acceptance layer:

```sh
make devnet-stateful-e2e
```

## What To Read Next

- [Devnet guide](devnet.md): run the local node and report gates.
- [Implementation notes](implementation.md): protocol objects and scripts.
- [Roadmap](roadmap.md): what is done and what remains.
- [Mainnet readiness](mainnet-readiness.md): production release requirements.
