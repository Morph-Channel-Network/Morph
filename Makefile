CARGO ?= cargo
CONTRACT_CARGO ?= $(CARGO)
AUDIT ?= cargo audit
DENY ?= cargo deny
export LIBRARY_PATH := $(CURDIR)/target/native-libs$(if $(LIBRARY_PATH),:$(LIBRARY_PATH))
# Explicit, reviewable upstream waivers. `audit` denies every other warning.
# - rand 0.7 arrives through CKB's numext integer APIs, VM and PHF codegen.
#   Morph defines no custom logger that calls rand, so the documented rand
#   re-entrancy trigger is absent. Upgrading numext requires changing generated
#   public RNG trait implementations; do not remove its support_rand feature.
#   Remove this last waiver when all three incoming roots use patched rand
#   without losing those APIs. See docs/ckb-toolchain-upgrade.md.
# faster-hex, paste, memmap2 and lru are migrated by the exact consumer patches
# verified by vendor-check; their former advisory waivers must not return.
AUDIT_IGNORE ?= --ignore RUSTSEC-2026-0097

.PHONY: native-build-env desktop desktop-build package-desktop ci full-test test lint fmt fmt-check source-hygiene vendor-check audit deny supply-chain smoke fixture-checks rust-client-check desktop-check build-contracts contract-tests verify-contract-manifest preproduction-envelope-check runbook-check release-readiness package-contract-release devnet-smoke devnet-e2e devnet-stateful-e2e fiber-morph-devnet-preflight fiber-morph-devnet-acceptance fiber-morph-devnet-acceptance-full fiber-morph-devnet-audit smoke-report smoke-assert smoke-assert-budget devnet-stateful-report devnet-stateful-assert

ci: fmt-check lint source-hygiene supply-chain test fixture-checks desktop-build contract-tests release-readiness

.PHONY: qualify-local-candidate
qualify-local-candidate:
	scripts/qualify-local-candidate.sh

full-test: test fixture-checks contract-tests

test: native-build-env
	$(CARGO) test --workspace --all-features
	PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts/tests -p 'test_*.py'

lint: native-build-env
	$(CARGO) clippy --workspace --all-features --all-targets -- -D warnings

fmt:
	$(CARGO) fmt --all

fmt-check:
	$(CARGO) fmt --all -- --check

source-hygiene:
	@for script in scripts/*.sh; do bash -n "$$script" || exit; done
	$(CARGO) run --locked -q -p morph-xtask -- verify-rust-clients
	$(CARGO) clippy --workspace --all-features --bins --lib -- -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic

audit:
	$(AUDIT) --deny warnings $(AUDIT_IGNORE)

vendor-check:
	PYTHONDONTWRITEBYTECODE=1 python3 vendor/check.py

deny:
	$(DENY) check

supply-chain: vendor-check audit deny

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
	jq '.cases[0].request' fixtures/protocol/factory-packets.json > target/fixture-checks/factory-root-request.json
	$(CARGO) run -q -p morph-cli -- inspect-factory-request target/fixture-checks/factory-root-request.json > target/fixture-checks/factory-root-summary.json
	jq '.cases[-1].request' fixtures/protocol/factory-packets.json > target/fixture-checks/factory-child-request.json
	$(CARGO) run -q -p morph-cli -- inspect-factory-request target/fixture-checks/factory-child-request.json > target/fixture-checks/factory-child-summary.json
	for index in 0 1 2 3 4; do jq ".cases[$$index].package" fixtures/protocol/factory-transitions.json > target/fixture-checks/factory-transition-$$index.json; $(CARGO) run -q -p morph-cli -- inspect-factory-transition target/fixture-checks/factory-transition-$$index.json > target/fixture-checks/factory-transition-$$index-summary.json; done
	$(CARGO) run -q -p morph-cli -- print-value-limit-policy-fixture > target/fixture-checks/value-limit-policy.json
	$(CARGO) run -q -p morph-cli -- validate-value-limit-policy target/fixture-checks/value-limit-policy.json --json > target/fixture-checks/value-limit-policy-summary.json
	$(CARGO) run -q -p morph-cli -- value-limit-check --policy target/fixture-checks/value-limit-policy.json --package target/fixture-checks/factory-root-request.json > target/fixture-checks/value-limit-check.txt
	$(CARGO) run -q -p morph-cli -- print-watch-policy-fixture > target/fixture-checks/watch-policy.json
	$(CARGO) run -q -p morph-cli -- validate-watch-policy target/fixture-checks/watch-policy.json --json > target/fixture-checks/watch-policy-summary.json
	$(CARGO) run -q -p morph-cli -- print-watch-config-fixture > target/fixture-checks/watch-config.json
	$(CARGO) run -q -p morph-cli --features devnet -- devnet --devnet-only publication-profile-fixture --json > target/fixture-checks/publication-profile.json
	$(CARGO) run -q -p morph-cli -- validate-watch-config target/fixture-checks/watch-config.json --json > target/fixture-checks/watch-config-summary.json

native-build-env:
	scripts/prepare-native-desktop.sh

rust-client-check:
	$(CARGO) test -p morph-sdk -p morph-packages -p morph-hub-api -p morph-xtask

desktop-build: native-build-env
	$(CARGO) build --locked -p morph-desktop

desktop-check: desktop-build
	$(CARGO) test -p morph-desktop

desktop: native-build-env
	$(CARGO) run --locked -p morph-desktop

package-desktop: native-build-env
	$(CARGO) build --locked --profile desktop -p morph-desktop
	scripts/package-native-desktop.sh

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
