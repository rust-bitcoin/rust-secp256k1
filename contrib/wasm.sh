#!/usr/bin/env bash
#
# Run the WASM tests.
#
# The wasm-pack command does not correctly pass args to cargo so we cannot use --locked and test
# with per-commited lockfiles (recent/minimal). Just run the WASM tests from here instead.

set -euox pipefail

clang --version
CARGO_TARGET_DIR=wasm cargo install --force wasm-pack
printf '\n[lib]\ncrate-type = ["cdylib", "rlib"]\n' >> Cargo.toml
CC=clang wasm-pack build
CC=clang wasm-pack test --node
