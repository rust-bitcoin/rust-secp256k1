#!/bin/sh -ex

# TODO: Add "alloc" once we bump MSRV to past 1.29
FEATURES="bitcoin_hashes global-context lowmemory rand rand-std recovery serde std"

# Use toolchain if explicitly specified
if [ -n "$TOOLCHAIN" ]
then
    alias cargo="cargo +$TOOLCHAIN"
fi

cargo --version
rustc --version

# Make all cargo invocations verbose
export CARGO_TERM_VERBOSE=true

# Defaults / sanity checks
cargo build --all
cargo test --all

if [ "$DO_FEATURE_MATRIX" = true ]; then
    cargo build --all --no-default-features
    cargo test --all --no-default-features

    # All features
    cargo build --all --no-default-features --features="$FEATURES"
    cargo test --all --no-default-features --features="$FEATURES"
    # Single features
    for feature in ${FEATURES}
    do
        cargo build --all --no-default-features --features="$feature"
        cargo test --all --no-default-features --features="$feature"
    done

    # Other combos 
    RUSTFLAGS='--cfg=fuzzing' RUSTDOCFLAGS=$RUSTFLAGS cargo test --all
    RUSTFLAGS='--cfg=fuzzing' RUSTDOCFLAGS=$RUSTFLAGS cargo test --all --features="$FEATURES"
    cargo test --all --features="rand rand-std"
    cargo test --all --features="rand serde"

    if [ "$DO_BENCH" = true ]; then  # proxy for us having a nightly compiler
        cargo test --all --all-features
        RUSTFLAGS='--cfg=fuzzing' RUSTDOCFLAGS='--cfg=fuzzing' cargo test --all --all-features
    fi

    # Examples
    cargo run --example sign_verify --features=std
    cargo run --example sign_verify_recovery --features=std,recovery
    cargo run --example generate_keys --features=std,rand-std
fi

# Docs
if [ "$DO_DOCS" = true ]; then
    cargo doc --all --features="$FEATURES"
fi

# Webassembly stuff
if [ "$DO_WASM" = true ]; then
    clang --version &&
    CARGO_TARGET_DIR=wasm cargo install --force wasm-pack &&
    printf '\n[lib]\ncrate-type = ["cdylib", "rlib"]\n' >> Cargo.toml &&
    CC=clang-9 wasm-pack build &&
    CC=clang-9 wasm-pack test --node;
fi

# Address Sanitizer
if [ "$DO_ASAN" = true ]; then
    cargo clean
    CC='clang -fsanitize=address -fno-omit-frame-pointer'                                        \
    RUSTFLAGS='-Zsanitizer=address -Clinker=clang -Cforce-frame-pointers=yes'                    \
    ASAN_OPTIONS='detect_leaks=1 detect_invalid_pointer_pairs=1 detect_stack_use_after_return=1' \
    cargo test --lib --all --features="$FEATURES" -Zbuild-std --target x86_64-unknown-linux-gnu &&
    cargo clean &&
    CC='clang -fsanitize=memory -fno-omit-frame-pointer'                                         \
    RUSTFLAGS='-Zsanitizer=memory -Zsanitizer-memory-track-origins -Cforce-frame-pointers=yes'   \
    cargo test --lib --all --features="$FEATURES" -Zbuild-std --target x86_64-unknown-linux-gnu &&
    cargo run --release --manifest-path=./no_std_test/Cargo.toml | grep -q "Verified Successfully"
    cargo run --release --features=alloc --manifest-path=./no_std_test/Cargo.toml | grep -q "Verified alloc Successfully"
fi

# Test if panic in C code aborts the process (either with a real panic or with SIGILL)
cargo test -- --ignored --exact 'tests::test_panic_raw_ctx_should_terminate_abnormally' 2>&1 | tee /dev/stderr | grep "SIGILL\\|panicked at '\[libsecp256k1\]"

# Bench
if [ "$DO_BENCH" = true ]; then
    cargo bench --all --features="unstable"
fi

