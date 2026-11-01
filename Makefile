CARGO ?= cargo
CONTRACT_CARGO ?= $(CARGO)
AUDIT ?= cargo audit
DENY ?= cargo deny
# Explicit, reviewable upstream waivers. `audit` denies every other warning.
# - paste and rand 0.7 arrive through the pinned CKB 1.1 dependency family.
#   Morph defines no custom logger that calls rand, so the documented rand
#   re-entrancy trigger is absent.
# - memmap2 0.5 is confined to ckb-testtool -> cacache in the test graph.
# - proc-macro-error2 is compile-time-only through biscuit-auth's required
#   datalog macro feature.
# - lru 0.7 is test-only through ckb-testtool -> ckb-verification. The affected
#   cache key is CKB Byte32 (no panicking Drop), so the advisory's required
#   panic-unwind/catch-unwind trigger is absent. ckb-verification 1.2 removes
#   this line but requires Rust 1.95; remove the waiver when CKB supports the
#   workspace's pinned Rust release.
# Remove each waiver as soon as its upstream dependency path is upgraded.
AUDIT_IGNORE ?= --ignore RUSTSEC-2024-0436 --ignore RUSTSEC-2026-0097 --ignore RUSTSEC-2026-0186 --ignore RUSTSEC-2026-0173 --ignore RUSTSEC-2026-0253

.PHONY: ci full-test test lint fmt fmt-check source-hygiene audit deny supply-chain smoke fixture-checks sdk-check hub-ui-check build-contracts contract-tests verify-contract-manifest preproduction-envelope-check runbook-check release-readiness package-contract-release devnet-smoke devnet-e2e devnet-stateful-e2e fiber-morph-devnet-preflight fiber-morph-devnet-acceptance fiber-morph-devnet-acceptance-full fiber-morph-devnet-audit smoke-report smoke-assert smoke-assert-budget devnet-stateful-report devnet-stateful-assert

ci: fmt-check lint source-hygiene supply-chain test fixture-checks sdk-check hub-ui-check contract-tests release-readiness

full-test: test fixture-checks contract-tests

test:
	$(CARGO) test --workspace --all-features

lint:
	$(CARGO) clippy --workspace --all-features --all-targets -- -D warnings

fmt:
	$(CARGO) fmt --all

fmt-check:
	$(CARGO) fmt --all -- --check

source-hygiene:
	bash -n scripts/*.sh
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

fixture-checks:
	mkdir -p target/fixture-checks
	$(CARGO) run -q -p morph-cli -- validate-fixture
	$(CARGO) run -q -p morph-cli -- print-multi-asset-fixture > target/fixture-checks/multi-asset.json
	$(CARGO) run -q -p morph-cli -- validate-multi-asset-package target/fixture-checks/multi-asset.json --json > target/fixture-checks/multi-asset-summary.json
	$(CARGO) run -q -p morph-cli -- print-conditional-batch-fixture > target/fixture-checks/conditional-batch.json
	$(CARGO) run -q -p morph-cli -- validate-conditional-batch-package target/fixture-checks/conditional-batch.json --json > target/fixture-checks/conditional-batch-summary.json
	$(CARGO) run -q -p morph-cli -- print-factory-fixture > target/fixture-checks/factory-update.json
	$(CARGO) run -q -p morph-cli -- validate-factory-package target/fixture-checks/factory-update.json --json > target/fixture-checks/factory-update-summary.json
	$(CARGO) run -q -p morph-cli -- print-factory-state-fixture > target/fixture-checks/factory-state.json
	$(CARGO) run -q -p morph-cli -- validate-factory-state-package target/fixture-checks/factory-state.json --json > target/fixture-checks/factory-state-summary.json
	$(CARGO) run -q -p morph-cli -- print-reduced-factory-state-fixture > target/fixture-checks/factory-state-reduced.json
	$(CARGO) run -q -p morph-cli -- validate-factory-state-package target/fixture-checks/factory-state-reduced.json --json > target/fixture-checks/factory-state-reduced-summary.json
	$(CARGO) run -q -p morph-cli -- print-factory-reduced-rights-fixture > target/fixture-checks/factory-reduced-rights.json
	$(CARGO) run -q -p morph-cli -- validate-factory-reduced-rights-package target/fixture-checks/factory-reduced-rights.json --json > target/fixture-checks/factory-reduced-rights-summary.json
	$(CARGO) run -q -p morph-cli -- print-factory-reduced-exit-fixture > target/fixture-checks/factory-reduced-exit.json
	$(CARGO) run -q -p morph-cli -- validate-factory-reduced-exit-package target/fixture-checks/factory-reduced-exit.json --json > target/fixture-checks/factory-reduced-exit-summary.json
	$(CARGO) run -q -p morph-cli -- print-factory-merkle-update-fixture > target/fixture-checks/factory-merkle-update.json
	$(CARGO) run -q -p morph-cli -- validate-factory-merkle-update-package target/fixture-checks/factory-merkle-update.json --json > target/fixture-checks/factory-merkle-update-summary.json
	$(CARGO) run -q -p morph-cli -- print-factory-multi-right-update-fixture > target/fixture-checks/factory-multi-right-update.json
	$(CARGO) run -q -p morph-cli -- validate-factory-multi-right-update-package target/fixture-checks/factory-multi-right-update.json --json > target/fixture-checks/factory-multi-right-update-summary.json
	$(CARGO) run -q -p morph-cli -- print-factory-local-exit-fixture > target/fixture-checks/factory-local-exit.json
	$(CARGO) run -q -p morph-cli -- validate-factory-local-exit-package target/fixture-checks/factory-local-exit.json --json > target/fixture-checks/factory-local-exit-summary.json
	$(CARGO) run -q -p morph-cli -- print-factory-splice-fixture --kind splice-in > target/fixture-checks/factory-splice-in.json
	$(CARGO) run -q -p morph-cli -- validate-factory-splice-package target/fixture-checks/factory-splice-in.json --json > target/fixture-checks/factory-splice-in-summary.json
	$(CARGO) run -q -p morph-cli -- print-factory-splice-fixture --kind xudt-splice-out > target/fixture-checks/factory-xudt-splice-out.json
	$(CARGO) run -q -p morph-cli -- validate-factory-splice-package target/fixture-checks/factory-xudt-splice-out.json --json > target/fixture-checks/factory-xudt-splice-out-summary.json
	$(CARGO) run -q -p morph-cli -- print-factory-reduced-splice-fixture --kind splice-in > target/fixture-checks/factory-reduced-splice-in.json
	$(CARGO) run -q -p morph-cli -- validate-factory-reduced-splice-package target/fixture-checks/factory-reduced-splice-in.json --json > target/fixture-checks/factory-reduced-splice-in-summary.json
	$(CARGO) run -q -p morph-cli -- print-factory-reduced-splice-fixture --kind xudt-splice-out > target/fixture-checks/factory-reduced-xudt-splice-out.json
	$(CARGO) run -q -p morph-cli -- validate-factory-reduced-splice-package target/fixture-checks/factory-reduced-xudt-splice-out.json --json > target/fixture-checks/factory-reduced-xudt-splice-out-summary.json
	$(CARGO) run -q -p morph-cli -- print-watch-policy-fixture > target/fixture-checks/watch-policy.json
	$(CARGO) run -q -p morph-cli -- validate-watch-policy target/fixture-checks/watch-policy.json --json > target/fixture-checks/watch-policy-summary.json
	$(CARGO) run -q -p morph-cli -- print-value-limit-policy-fixture > target/fixture-checks/value-limit-policy.json
	$(CARGO) run -q -p morph-cli -- validate-value-limit-policy target/fixture-checks/value-limit-policy.json --json > target/fixture-checks/value-limit-policy-summary.json
	$(CARGO) run -q -p morph-cli -- value-limit-check --policy target/fixture-checks/value-limit-policy.json --package target/fixture-checks/factory-splice-in.json > target/fixture-checks/value-limit-check-factory-splice-in.txt
	$(CARGO) run -q -p morph-cli -- print-watch-config-fixture > target/fixture-checks/watch-config.json
	$(CARGO) run -q -p morph-cli -- validate-watch-config target/fixture-checks/watch-config.json --json > target/fixture-checks/watch-config-summary.json

sdk-check:
	cd sdk/typescript && npm ci && npm audit --registry=https://registry.npmjs.org --audit-level=high && npm run check && npm test

hub-ui-check:
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
