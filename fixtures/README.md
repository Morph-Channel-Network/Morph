# Current protocol samples and native scenarios

Only current consumed inputs and independent expected results belong here.
There are no historical SDK call recordings or compatibility dispatch fixtures.

- `protocol/`: nine current samples shared by CLI, Core and SDK review tests.
  They cover signed recovery and its expected summary, proposal/receipt, root
  funding, splice, Factory requests/transitions and public child exit terms.
- `gateway/authorization.json`: one independent signature vector for the current
  Gateway requirement and authorization format. It is test data, not JS code.
- `hub/`: the current explicit unauthenticated-loopback view used by native policy tests.
- `fiber/`: fifteen current Rust scenario families and their source inventory.
  These are executable test definitions, not captured response snapshots.

Conditional packages are constructed by current Rust fixture commands/tests;
there is no extra checked-in copy solely to serve a retired SDK. Development-node
transaction evidence stays in its run directory rather than being copied back
into this source tree. Test-only `MORPH_UPDATE_FIXTURES=1` regenerates deterministic
current constructor samples; it never migrates an older format.
