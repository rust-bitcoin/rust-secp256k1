#!/bin/sh

set -ex

REPO_DIR=$(git rev-parse --show-toplevel)

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

$REPO_DIR/contrib/_test.sh
