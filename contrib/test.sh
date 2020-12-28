#!/bin/sh -ex

FEATURES="bitcoin_hashes endomorphism global-context lowmemory rand rand-std recovery serde"

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
    #This doesn't work but probably should --andrew
    #cargo test --all --no-default-features

    # All features
    cargo build --all --no-default-features --features="$FEATURES"
    cargo test --all --features="$FEATURES"
    # Single features
    for feature in ${FEATURES}
    do
        cargo build --all --no-default-features --features="$feature"
        cargo test --all --features="$feature"
    done

    # Other combos 
    RUSTFLAGS='--cfg=rust_secp_fuzz' RUSTDOCFLAGS=$RUSTFLAGS cargo test --all
    RUSTFLAGS='--cfg=rust_secp_fuzz' RUSTDOCFLAGS=$RUSTFLAGS cargo test --all --features="$FEATURES"
    cargo test --all --features="rand rand-std"
    cargo test --all --features="rand serde"

    if [ "$DO_BENCH" = true ]; then  # proxy for us having a nightly compiler
        cargo test --all --all-features
        RUSTFLAGS='--cfg=rust_secp_fuzz' RUSTDOCFLAGS='--cfg=rust_secp_fuzz' cargo test --all --all-features
    fi

    # Examples
    cargo run --example sign_verify
    cargo run --example sign_verify_recovery --features=recovery
    cargo run --example generate_keys --features=rand
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
fi

# Bench
if [ "$DO_BENCH" = true ]; then
    cargo bench --all --features="unstable"
fi

