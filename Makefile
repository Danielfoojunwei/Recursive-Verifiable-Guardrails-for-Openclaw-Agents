.PHONY: build test install lint fmt clean help

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

build: ## Build all crates (release mode)
	cargo build --workspace --release

test: ## Run all tests
	cargo test --workspace

lint: ## Run clippy with warnings as errors
	cargo clippy --workspace -- -D warnings

fmt: ## Check formatting
	cargo fmt --check

fmt-fix: ## Fix formatting
	cargo fmt

install: ## Install aegx binary to ~/.cargo/bin
	cargo install --path crates/aegx-cli --locked

package-skill: ## Build a distributable Provenable skill bundle into dist/
	bash packaging/skill/package_skill.sh

validate-skill-bundle: ## Validate the latest packaged skill bundle from dist/
	bash packaging/skill/validate_skill_bundle.sh --bundle "$$(find dist -maxdepth 1 -mindepth 1 -type d -name 'provenable-skill-*' | sort | tail -n 1)"

skill-smoke: package-skill validate-skill-bundle ## Build and validate the packaged skill bundle

clean: ## Remove build artifacts
	cargo clean
	rm -rf dist results

check: lint fmt test ## Run lint, format check, and tests
