#!/usr/bin/env bash
#
# Run no-std tests, requires nightly toolchain.

set -euox pipefail

main() {
    need_nightly

    pushd no_std_test > /dev/null

    cargo run --release -Z build-std=core,alloc --target=x86_64-unknown-linux-gnu | grep -q "Verified Successfully"
    cargo run --release -Z build-std=core,alloc --target=x86_64-unknown-linux-gnu --features=alloc | grep -q "Verified alloc Successfully"

    popd
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
