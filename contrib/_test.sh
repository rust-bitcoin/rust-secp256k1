#!/usr/bin/env bash

set -ex

REPO_DIR=$(git rev-parse --show-toplevel)
FEATURES="hashes global-context lowmemory rand recovery serde std alloc hashes-std rand-std"

cargo --version
rustc --version

# Work out if we are using a nightly toolchain.
NIGHTLY=false
if cargo --version | grep nightly; then
    NIGHTLY=true
fi

# Pin dependencies as required if we are using MSRV toolchain.
if cargo --version | grep "1\.48"; then
    cargo update -p wasm-bindgen-test --precise 0.3.34
    cargo update -p serde_test --precise 1.0.175
fi

# Test if panic in C code aborts the process (either with a real panic or with SIGILL)
cargo test -- --ignored --exact 'tests::test_panic_raw_ctx_should_terminate_abnormally' 2>&1 \
    | tee /dev/stderr \
    | grep "SIGILL\\|\[libsecp256k1] illegal argument. "

# Make all cargo invocations verbose
export CARGO_TERM_VERBOSE=true

# Defaults / sanity checks
cargo build --locked --all
cargo test --locked --all

if [ "$DO_FEATURE_MATRIX" = true ]; then
    cargo build --locked --all --no-default-features
    cargo test --locked --all --no-default-features

    # All features
    cargo build --locked --all --no-default-features --features="$FEATURES"
    cargo test --locked --all --no-default-features --features="$FEATURES"
    # Single features
    for feature in ${FEATURES}
    do
        cargo build --locked --all --no-default-features --features="$feature"
        cargo test --locked --all --no-default-features --features="$feature"
    done
    # Features tested with 'std' feature enabled.
    for feature in ${FEATURES}
    do
        cargo build --locked --all --no-default-features --features="std,$feature"
        cargo test --locked --all --no-default-features --features="std,$feature"
    done
    # Other combos
    RUSTFLAGS='--cfg=secp256k1_fuzz' RUSTDOCFLAGS='--cfg=secp256k1_fuzz' cargo test --locked --all
    RUSTFLAGS='--cfg=secp256k1_fuzz' RUSTDOCFLAGS='--cfg=secp256k1_fuzz' cargo test --locked --all --features="$FEATURES"
    cargo test --locked --all --features="rand serde"

    if [ "$NIGHTLY" = true ]; then
        cargo test --locked --all --all-features
        RUSTFLAGS='--cfg=secp256k1_fuzz' RUSTDOCFLAGS='--cfg=secp256k1_fuzz' cargo test --locked --all --all-features
    fi

    # Examples
    cargo run --locked --example sign_verify --features=hashes-std
    cargo run --locked --example sign_verify_recovery --features=recovery,hashes-std
    cargo run --locked --example generate_keys --features=rand-std
fi

if [ "$DO_LINT" = true ]
then
    cargo clippy --locked --all-features --all-targets -- -D warnings
    cargo clippy --locked --example sign_verify --features=hashes-std -- -D warnings
    cargo clippy --locked --example sign_verify_recovery --features=recovery,hashes-std -- -D warnings
    cargo clippy --locked --example generate_keys --features=rand-std -- -D warnings
fi

# Build the docs if told to (this only works with the nightly toolchain)
if [ "$DO_DOCSRS" = true ]; then
    RUSTDOCFLAGS="--cfg docsrs -D warnings -D rustdoc::broken-intra-doc-links" cargo +nightly doc --all-features
fi

# Build the docs with a stable toolchain, in unison with the DO_DOCSRS command
# above this checks that we feature guarded docs imports correctly.
if [ "$DO_DOCS" = true ]; then
    RUSTDOCFLAGS="-D warnings" cargo +stable doc --all-features
fi

# Address Sanitizer
if [ "$DO_ASAN" = true ]; then
    clang --version
    cargo clean
    CC='clang -fsanitize=address -fno-omit-frame-pointer'                                        \
    RUSTFLAGS='-Zsanitizer=address -Clinker=clang -Cforce-frame-pointers=yes'                    \
    ASAN_OPTIONS='detect_leaks=1 detect_invalid_pointer_pairs=1 detect_stack_use_after_return=1' \
    cargo test --lib --all --features="$FEATURES" -Zbuild-std --target x86_64-unknown-linux-gnu
    cargo clean
    # The -Cllvm-args=-msan-eager-checks=0 flag was added to overcome this issue:
    # https://github.com/rust-bitcoin/rust-secp256k1/pull/573#issuecomment-1399465995
    CC='clang -fsanitize=memory -fno-omit-frame-pointer'                                                                        \
    RUSTFLAGS='-Zsanitizer=memory -Zsanitizer-memory-track-origins -Cforce-frame-pointers=yes -Cllvm-args=-msan-eager-checks=0' \
    cargo test --lib --all --features="$FEATURES" -Zbuild-std --target x86_64-unknown-linux-gnu

    cargo run --release --manifest-path=./no_std_test/Cargo.toml | grep -q "Verified Successfully"
    cargo run --release --features=alloc --manifest-path=./no_std_test/Cargo.toml | grep -q "Verified alloc Successfully"
fi

# Run formatter if told to.
if [ "$DO_FMT" = true ]; then
    if [ "$NIGHTLY" = false ]; then
        echo "DO_FMT requires a nightly toolchain (consider using RUSTUP_TOOLCHAIN)"
        exit 1
    fi
    rustup component add rustfmt
    cargo fmt --check || exit 1
fi

# Bench if told to, only works with non-stable toolchain (nightly, beta).
if [ "$DO_BENCH" = true ]
then
    RUSTFLAGS='--cfg=bench' cargo bench --features=recovery,rand-std
fi

exit 0
