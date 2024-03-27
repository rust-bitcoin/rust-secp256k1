default:
  @just --list

# Cargo build everything.
build:
  cargo build --all-targets --all-features

# Cargo check everything.
check:
  cargo check --all-targets --all-features

# Lint everything.
lint:
  cargo clippy --all-targets --all-features -- --deny warnings

# Check the formatting
format:
  cargo +nightly fmt --check

# Quick and dirty CI useful for pre-push checks.
sane: lint
  cargo test --quiet --all-targets --no-default-features > /dev/null || exit 1
  cargo test --quiet --all-targets > /dev/null || exit 1
  cargo test --quiet --all-targets --all-features > /dev/null || exit 1

  # doctests don't get run from workspace root with `cargo test`.
  cargo test --quiet --doc || exit 1

  # Make an attempt to catch feature gate problems in doctests
  cargo test --manifest-path Cargo.toml --doc --no-default-features > /dev/null || exit 1

# Check for API changes.
check-api:
  ./contrib/check-for-api-changes.sh

# Update the lock files.
update-lock-files:
  ./contrib/update-lock-files.sh
