# Morph TypeScript SDK

Build and test with `npm ci && npm test`. The public JSON codecs accept only
current unpublished formats, with canonical hex and decimal strings for
u64/u128 quantities.

## Current Factory public packets

```ts
import {inspectFactoryRequest, inspectFactorySignature} from '@morph-network/agent-sdk';

const review = inspectFactoryRequest(publicRequest);
console.log(review.request_id, review.signing_digest, review.missing_deliveries);
// This verifies the detached receipt; it reserves no signer authority.
inspectFactorySignature(publicRequest, participantReceipt);
```

`inspectFactoryCustody`, `inspectFactoryRequest`, and
`inspectFactoryTransitionPackage` expose current custody and public terms.
They check canonical bytes, commitments, complete target-right roots,
compact proof roots and localisation, exact request/domain binding, participant
signatures, and public child delivery attestations. Child initial-exit terms
use the same current multi-asset parser; private recovery signatures never
belong in a parent request.

The inspection reports `validation_scope: "public_terms_and_signatures"`.
Complete Factory transition value semantics remain the native Core boundary.
Canonical source cells, approved script dependencies, VM preflight, durable
signer reservation and submission also remain native obligations. The SDK
provides no sign-ready boolean or stateless replacement for those checks.
A participant receipt is rejected while any child delivery attestation is
missing.

Rust constructors generate `test/fixtures/factory-packets.json`; it covers
Root funding and a CKB-VM-qualified reduced-child request with zero, one and
two possession attestations. The separate current Factory transition corpus
covers all five operation tags. Regeneration is explicit:

```sh
MORPH_UPDATE_FIXTURES=1 cargo test -p morph-cli \
  fixture_exports::sdk_fixture_corpus_matches_current_protocol --all-features
```

Fixtures are synthetic development evidence. They are neither deployed
contract approval nor private signer journals. The UI uses these same SDK
inspection APIs for public Factory review; local Factory projections remain
planning records.
