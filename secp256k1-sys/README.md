<div align="center">
  <h1>Rust secp256k1-sys</h1>

  <p>
    <a href="https://crates.io/crates/secp256k1-sys"><img alt="Crate Info" src="https://img.shields.io/crates/v/secp256k1-sys.svg"/></a>
    <a href="https://github.com/rust-bitcoin/rust-secp256k1/blob/master/LICENSE"><img alt="CC0 1.0 Universal Licensed" src="https://img.shields.io/badge/license-CC0--1.0-blue.svg"/></a>
    <a href="https://docs.rs/secp256k1"><img alt="API Docs" src="https://img.shields.io/badge/docs.rs-secp256k1-green"/></a>
    <a href="https://blog.rust-lang.org/2020/02/27/Rust-1.56.1.html"><img alt="Rustc Version 1.56.1+" src="https://img.shields.io/badge/rustc-1.56.1%2B-lightgrey.svg"/></a>
  </p>
</div>

Provides low-level bindings to the C FFI exposed by [libsecp256k1](https://github.com/bitcoin-core/secp256k1).

## Vendoring

The default build process is to build using the vendored `libsecp256k1` sources in the `depend`
directory. These sources are prefixed with a special rust-secp256k1-sys-specific prefix
`rustsecp256k1_v1_2_3_`.

This prefix ensures that no symbol collision can happen:

- When a Rust project has two different versions of `rust-secp256k1` in its depepdency tree, or
- When `rust-secp256k1` is used for building a static library in a context where existing
  `libsecp256k1` symbols are already linked.

To update the vendored sources, use the `vendor-libsecp.sh` script: `./vendor-libsecp.sh <rev>`

- Where `<rev>` is the git revision of `libsecp256k1` to checkout. If you do not specify a revision,
  the script will simply clone the repo and use whatever revision the default branch is pointing to.

## Linking to external symbols

**Danger: doing this incorrectly may have catastrophic consequences!**

This is mainly intended for applications consisting of various programming languages that intend to
link the same library to save space, or bundles of multiple binaries coming from the same source. Do
not use this to link to a random secp256k1 library you found in your OS! If you are packaging
software that depends on `rust-secp256k1`, using this flag to link to another package, make sure you
stay within the binary compatibility guarantees of that package. For example, in Debian if you need
`libsecp256k1 1.2.3`, make sure your package requires a version strictly`>= 1.2.3 << 1.2.4`. Note
also that unless you're packaging the library for an official repository you should prefix your
package and the library with a string specific to you. E.g. if you have a set of packages called
`my-awesome-packages` you should package `libsecp256k1` as `libmy-awesome-packages-secp256k1` and
depend on that library/package name from your application.

If you want to compile this library without using the bundled symbols (which may be required for
integration into other build systems), you can do so by adding `--cfg=rust_secp_no_symbol_renaming'`
to your `RUSTFLAGS` variable.

## Minimum Supported Rust Version

This library should always compile with any combination of features on **Rust 1.56.1**.
