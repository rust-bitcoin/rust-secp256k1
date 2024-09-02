#!/usr/bin/env bash

set -ex

REPO_DIR=$(git rev-parse --show-toplevel)

# Make all cargo invocations verbose.
export CARGO_TERM_VERBOSE=true

# Set to false to turn off verbose output.
flag_verbose=true

# Use the current `Cargo.lock` file without updating it.
cargo="cargo --locked"

main() {
    source_test_vars            # Get feature list.
    local features="$FEATURES_WITH_STD"

    RUSTFLAGS='--cfg=secp256k1_fuzz' RUSTDOCFLAGS='--cfg=secp256k1_fuzz' $cargo test --locked --all
    RUSTFLAGS='--cfg=secp256k1_fuzz' RUSTDOCFLAGS='--cfg=secp256k1_fuzz' $cargo test --locked --all --features="$features"

    $cargo test --all --features="rand serde"
}

# ShellCheck can't follow non-constant source, `test_vars_script` is correct.
# shellcheck disable=SC1090
source_test_vars() {
    local test_vars_script="$REPO_DIR/contrib/test_vars.sh"

    verbose_say "Sourcing $test_vars_script"

    if [ -e "$test_vars_script" ]; then
        # Set crate specific variables.
        . "$test_vars_script"
    else
        err "Missing $test_vars_script"
    fi
}

say() {
    echo "extra_tests: $1"
}

verbose_say() {
    if [ "$flag_verbose" = true ]; then
	say "$1"
    fi
}

err() {
    echo "$1" >&2
    exit 1
}

#
# Main script
#
main "$@"
exit 0
