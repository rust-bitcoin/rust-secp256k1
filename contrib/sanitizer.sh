#!/usr/bin/env bash
#
# Run the Address/Memory Sanitizer tests.

set -euox pipefail

REPO_DIR=$(git rev-parse --show-toplevel)

# Set to true to enable verbose output.
flag_verbose=false

main() {
    source_test_vars            # Get feature list.
    local features="$FEATURES_WITH_STD"

    clang --version
    cargo clean

    CC='clang -fsanitize=address -fno-omit-frame-pointer'                                        \
      RUSTFLAGS='-Zsanitizer=address -Clinker=clang -Cforce-frame-pointers=yes'                    \
      ASAN_OPTIONS='detect_leaks=1 detect_invalid_pointer_pairs=1 detect_stack_use_after_return=1' \
      cargo test --lib --all --features="$features" -Zbuild-std --target x86_64-unknown-linux-gnu
    cargo clean

    # The -Cllvm-args=-msan-eager-checks=0 flag was added to overcome this issue:
    # https://github.com/rust-bitcoin/rust-secp256k1/pull/573#issuecomment-1399465995
    CC='clang -fsanitize=memory -fno-omit-frame-pointer'                                                                        \
      RUSTFLAGS='-Zsanitizer=memory -Zsanitizer-memory-track-origins -Cforce-frame-pointers=yes -Cllvm-args=-msan-eager-checks=0' \
      cargo test --lib --all --features="$features" -Zbuild-std --target x86_64-unknown-linux-gnu
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
