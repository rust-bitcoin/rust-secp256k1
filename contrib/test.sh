#!/usr/bin/env bash

set -ex

REPO_DIR=$(git rev-parse --show-toplevel)
DEPS="recent minimal"

# Webassembly stuff
#
# The wasm-pack command does not correctly pass args to cargo so we cannot use --locked and test
# with per-commited lockfiles (recent/minimal). Just run the WASM tests from here instead.
if [ "$DO_WASM" = true ]; then
    clang --version
    CARGO_TARGET_DIR=wasm cargo install --force wasm-pack
    printf '\n[lib]\ncrate-type = ["cdylib", "rlib"]\n' >> Cargo.toml
    CC=clang wasm-pack build
    CC=clang wasm-pack test --node

    exit 0
fi

for dep in $DEPS
do
    cp "Cargo-$dep.lock" Cargo.lock
    $REPO_DIR/contrib/_test.sh

    if [ "$dep" = recent ];
    then
        # We always test committed dependencies but we want to warn if they could've been updated
        cargo update
        if diff Cargo-recent.lock Cargo.lock;
        then
            echo "Dependencies are up to date"
        else
            echo "::warning file=Cargo-recent.lock::Dependencies could be updated"
        fi
    fi
done

exit 0
