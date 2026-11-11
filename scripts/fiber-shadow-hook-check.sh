#!/usr/bin/env bash
# Reproduce the optional Fiber RPC module checks. This does not start a chain,
# route a payment, publish a release, or qualify canonical Morph shadow evidence.
set -euo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo"
manifest=integrations/fiber-shadow/manifest.json
patch_file=integrations/fiber-shadow/a5faac71-shadow.patch
for command in git cargo jq sha256sum rg; do command -v "$command" >/dev/null; done
cargo +1.95.0 nextest --version >/dev/null
revision=$(jq -er .fiber_revision "$manifest")
expected_patch=$(jq -er .patch_sha256 "$manifest")
actual_patch=$(sha256sum "$patch_file" | cut -d ' ' -f 1)
[[ "$actual_patch" == "$expected_patch" ]] || { echo 'Fiber shadow patch digest mismatch' >&2; exit 1; }

# The patch's path dependencies require a direct child of Morph/target. Never
# apply it to the developer's Fiber checkout or copy that checkout's node state.
mkdir -p target
checkout=$(mktemp -d "$repo/target/fiber-shadow-check.XXXXXXXX")
run=$(basename "$checkout")
evidence="$repo/target/fiber-shadow-evidence/$run"
mkdir -p "$evidence"
source_repo=${FIBER_SOURCE:-https://github.com/nervosnetwork/fiber.git}
git clone --no-checkout "$source_repo" "$checkout" >"$evidence/clone.log" 2>&1
git -C "$checkout" checkout --detach "$revision" >>"$evidence/clone.log" 2>&1
[[ "$(git -C "$checkout" rev-parse HEAD)" == "$revision" ]]
git -C "$checkout" apply --check "$repo/$patch_file"
git -C "$checkout" apply "$repo/$patch_file"

source_hashes() {
    {
        printf '%s\n' Cargo.toml Cargo.lock rust-toolchain.toml .cargo/config.toml scripts/fiber-shadow-hook-check.sh "$patch_file" "$manifest"
        rg --files crates/morph-core crates/morph-packages crates/morph-runtime-store crates/morph-fiber-adapter vendor/ckb-* vendor/molecule-*
    } | LC_ALL=C sort | while IFS= read -r path; do sha256sum "$path"; done
}
fiber_hashes() {
    (
        cd "$checkout"
        {
            git ls-files -z
            printf '%s\0' crates/fiber-lib/src/rpc/morph_shadow.rs
        } | LC_ALL=C sort -zu | while IFS= read -r -d '' path; do sha256sum "$path"; done
    )
}
source_hashes >"$evidence/source-before.sha256"
fiber_hashes >"$evidence/fiber-source-before.sha256"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$repo/target/fiber-shadow-build}"
(
    cd "$checkout"
    cargo +1.95.0 check --locked -p fiber-bin --no-default-features --features sqlite,morph-shadow >"$evidence/build.log" 2>&1
    cargo +1.95.0 nextest run --locked -p fnn --lib --no-default-features --features sqlite,morph-shadow,watchtower -E 'test(morph_shadow)' >"$evidence/hook-tests.log" 2>&1
    cargo +1.95.0 nextest run --locked -p fiber-store --lib --no-default-features --features sqlite -E 'test(sqlite)' >"$evidence/sqlite-tests.log" 2>&1
    sha256sum Cargo.lock >"$evidence/fiber-lock.sha256"
)
source_hashes >"$evidence/source-after.sha256"
fiber_hashes >"$evidence/fiber-source-after.sha256"
cmp "$evidence/source-before.sha256" "$evidence/source-after.sha256"
cmp "$evidence/fiber-source-before.sha256" "$evidence/fiber-source-after.sha256"
jq -n --arg revision "$revision" --arg patch "$actual_patch" --arg checkout "$checkout" \
    '{schema:"morph.fiber_shadow_check.v1", fiber_revision:$revision, patch_sha256:$patch,
      checkout:$checkout, toolchain:"1.95.0", profile:"morph.external_edges.shadow.v1",
      checks:["fiber_sqlite_build","native_rpc_module_and_auth","fiber_sqlite_backend"],
      forwarding:false, source_unchanged:true, canonical_chain_acceptance:false,
      clean_commit_qualification:false, passed:true}' >"$evidence/verification.json"
printf 'Fiber shadow module checks passed. Evidence: %s\n' "$evidence"
