#!/usr/bin/env bash
#
# Run no-std tests, requires nightly toolchain.

set -euox pipefail

main() {
    need_nightly
    check_required_commands

    pushd no_std_test > /dev/null

    xargo run --release --target=x86_64-unknown-linux-gnu | grep -q "Verified Successfully"
    xargo run --release --target=x86_64-unknown-linux-gnu --features=alloc | grep -q "Verified alloc Successfully"

    popd
}

# Check all the commands we use are present in the current environment.
check_required_commands() {
    need_cmd xargo
}

need_cmd() {
    if ! command -v "$1" > /dev/null 2>&1
    then err "need '$1' (command not found)"
    fi
}

err() {
    echo "$1" >&2
    exit 1
}

need_nightly() {
    cargo_ver=$(cargo --version)
    if echo "$cargo_ver" | grep -q -v nightly; then
        err "Need a nightly compiler; have $(cargo --version)"
    fi
}

#
# Main script
#
main "$@"
exit 0
