CARGO ?= cargo
CONTRACT_CARGO ?= $(CARGO)
AUDIT ?= cargo audit
DENY ?= cargo deny
# Explicit, reviewable upstream waivers. `audit` denies every other warning.
# - paste and rand 0.7 arrive through the published CKB dependency family.
#   Morph defines no custom logger that calls rand, so the documented rand
#   re-entrancy trigger is absent.
# - memmap2 0.5 is confined to ckb-testtool -> cacache in the test graph.
# - lru 0.7 is test-only through ckb-testtool -> ckb-verification. The affected
#   cache key is CKB Byte32 (no panicking Drop), so the advisory's required
#   panic-unwind/catch-unwind trigger is absent. ckb-verification 1.2.1 still
#   requires lru 0.7; remove the waiver once that dependency is fixed upstream.
# - faster-hex 0.6 remains in the latest published CKB host, build and test
#   dependencies, ckb-testtool and Molecule (RUSTSEC-2026-0306). Neither Morph
#   nor those callers use the unsound `hex_decode_unchecked` AVX2 entrypoint.
#   The patched >=0.10.1 release is outside their ^0.6 requirements. Remove
#   the waiver when all seven current paths accept a patched version; see
#   docs/ckb-toolchain-upgrade.md. A toolchain bump alone does not fix them.
# Remove each waiver as soon as its upstream dependency path is upgraded.
AUDIT_IGNORE ?= --ignore RUSTSEC-2024-0436 --ignore RUSTSEC-2026-0097 --ignore RUSTSEC-2026-0186 --ignore RUSTSEC-2026-0253 --ignore RUSTSEC-2026-0306

.PHONY: ci full-test test lint fmt fmt-check source-hygiene audit deny supply-chain smoke fixture-checks sdk-check hub-ui-check build-contracts contract-tests verify-contract-manifest preproduction-envelope-check runbook-check release-readiness package-contract-release devnet-smoke devnet-e2e devnet-stateful-e2e fiber-morph-devnet-preflight fiber-morph-devnet-acceptance fiber-morph-devnet-acceptance-full fiber-morph-devnet-audit smoke-report smoke-assert smoke-assert-budget devnet-stateful-report devnet-stateful-assert

ci: fmt-check lint source-hygiene supply-chain test fixture-checks sdk-check hub-ui-check contract-tests release-readiness

full-test: test fixture-checks contract-tests

test:
	$(CARGO) test --workspace --all-features
	PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts/tests -p 'test_*.py'

lint:
	$(CARGO) clippy --workspace --all-features --all-targets -- -D warnings

fmt:
	$(CARGO) fmt --all

fmt-check:
	$(CARGO) fmt --all -- --check

source-hygiene:
	@for script in scripts/*.sh; do bash -n "$$script" || exit; done
	! grep -n "registry.npmmirror.com" sdk/typescript/package-lock.json ui/morph-hub/package-lock.json
	! grep -R -n "VITE_MORPH_HUB_AUTH_TOKEN" ui/morph-hub/src
	$(CARGO) clippy --workspace --all-features --bins --lib -- -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic

audit:
	$(AUDIT) --deny warnings $(AUDIT_IGNORE)

deny:
	$(DENY) check

supply-chain: audit deny

smoke:
	$(CARGO) test --workspace
	$(CARGO) run -p morph-cli -- validate-fixture

.PHONY: devnet-current-e2e
devnet-current-e2e:
	bash scripts/devnet-current-e2e.sh

fixture-checks:
	mkdir -p target/fixture-checks
	$(CARGO) run -q -p morph-cli -- validate-fixture
	$(CARGO) run -q -p morph-cli -- print-fixture > target/fixture-checks/bilateral.json
	$(CARGO) run -q -p morph-cli -- validate-multi-asset-package target/fixture-checks/bilateral.json --json > target/fixture-checks/bilateral-summary.json
	$(CARGO) run -q -p morph-cli -- print-conditional-batch-fixture > target/fixture-checks/conditional-batch.json
	$(CARGO) run -q -p morph-cli -- validate-conditional-batch-package target/fixture-checks/conditional-batch.json --json > target/fixture-checks/conditional-batch-summary.json
	jq '.cases[0].request' sdk/typescript/test/fixtures/factory-packets.json > target/fixture-checks/factory-root-request.json
	$(CARGO) run -q -p morph-cli -- inspect-factory-request target/fixture-checks/factory-root-request.json > target/fixture-checks/factory-root-summary.json
	jq '.cases[-1].request' sdk/typescript/test/fixtures/factory-packets.json > target/fixture-checks/factory-child-request.json
	$(CARGO) run -q -p morph-cli -- inspect-factory-request target/fixture-checks/factory-child-request.json > target/fixture-checks/factory-child-summary.json
	for index in 0 1 2 3 4; do jq ".cases[$$index].package" sdk/typescript/test/fixtures/factory-transitions.json > target/fixture-checks/factory-transition-$$index.json; $(CARGO) run -q -p morph-cli -- inspect-factory-transition target/fixture-checks/factory-transition-$$index.json > target/fixture-checks/factory-transition-$$index-summary.json; done
	$(CARGO) run -q -p morph-cli -- print-value-limit-policy-fixture > target/fixture-checks/value-limit-policy.json
	$(CARGO) run -q -p morph-cli -- validate-value-limit-policy target/fixture-checks/value-limit-policy.json --json > target/fixture-checks/value-limit-policy-summary.json
	$(CARGO) run -q -p morph-cli -- value-limit-check --policy target/fixture-checks/value-limit-policy.json --package target/fixture-checks/factory-root-request.json > target/fixture-checks/value-limit-check.txt
	$(CARGO) run -q -p morph-cli -- print-watch-policy-fixture > target/fixture-checks/watch-policy.json
	$(CARGO) run -q -p morph-cli -- validate-watch-policy target/fixture-checks/watch-policy.json --json > target/fixture-checks/watch-policy-summary.json
	$(CARGO) run -q -p morph-cli -- print-watch-config-fixture > target/fixture-checks/watch-config.json
	$(CARGO) run -q -p morph-cli --features devnet -- devnet --devnet-only publication-profile-fixture --json > target/fixture-checks/publication-profile.json
	$(CARGO) run -q -p morph-cli -- validate-watch-config target/fixture-checks/watch-config.json --json > target/fixture-checks/watch-config-summary.json

sdk-check:
	cd sdk/typescript && npm ci && npm audit --registry=https://registry.npmjs.org --audit-level=high && npm run check && npm test

hub-ui-check: sdk-check
	cd ui/morph-hub && npm ci && npm audit --registry=https://registry.npmjs.org --audit-level=high && npm test && npm run build

build-contracts:
	CARGO="$(CONTRACT_CARGO)" scripts/build-contracts.sh

contract-tests: build-contracts
	$(CARGO) test -p morph-core --test contract_scripts -- --ignored --test-threads=1

verify-contract-manifest:
	$(CARGO) run -q -p morph-cli -- verify-contract-manifest --manifest release/factory-preproduction/contracts.json --contracts-dir target/riscv64imac-unknown-none-elf/release

preproduction-envelope-check:
	$(CARGO) run -q -p morph-cli -- validate-preproduction-envelope --envelope release/factory-preproduction/envelope.json

runbook-check:
	scripts/check-release-readiness.sh

release-readiness: verify-contract-manifest preproduction-envelope-check runbook-check

package-contract-release: release-readiness
	scripts/package-contract-release.sh

devnet-smoke:
	scripts/devnet-smoke.sh

devnet-e2e:
	scripts/devnet-e2e.sh

devnet-stateful-e2e:
	scripts/devnet-stateful-e2e.sh

fiber-morph-devnet-preflight:
	FIBER_MORPH_ACCEPTANCE_MODE=preflight scripts/fiber-morph-devnet-acceptance.sh

fiber-morph-devnet-acceptance:
	FIBER_MORPH_ACCEPTANCE_MODE=coexistence scripts/fiber-morph-devnet-acceptance.sh

fiber-morph-devnet-acceptance-full:
	FIBER_MORPH_ACCEPTANCE_MODE=full scripts/fiber-morph-devnet-acceptance.sh

fiber-morph-devnet-audit:
	@if [ -n "$(FIBER_MORPH_ACCEPTANCE_RUN)" ]; then \
		scripts/fiber-morph-devnet-audit.sh "$(FIBER_MORPH_ACCEPTANCE_RUN)"; \
	else \
		scripts/fiber-morph-devnet-audit.sh; \
	fi

smoke-report:
	$(CARGO) run -p morph-cli -- devnet-smoke-report

smoke-assert:
	$(CARGO) run -p morph-cli -- devnet-smoke-assert

smoke-assert-budget:
	$(CARGO) run -p morph-cli -- devnet-smoke-assert --budget-profile docs/devnet-smoke-budget.example.json

devnet-stateful-report:
	$(CARGO) run -p morph-cli -- devnet-stateful-report --audit-profile docs/devnet-audit-profile.example.json

devnet-stateful-assert:
	$(CARGO) run -p morph-cli -- devnet-stateful-assert --audit-profile docs/devnet-audit-profile.example.json --budget-profile docs/devnet-stateful-budget.example.json
