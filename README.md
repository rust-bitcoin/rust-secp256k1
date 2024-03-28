<div align="center">
  <h1>Rust Secp256k1</h1>

  <p>
    <a href="https://crates.io/crates/secp256k1"><img alt="Crate Info" src="https://img.shields.io/crates/v/secp256k1.svg"/></a>
    <a href="https://github.com/rust-bitcoin/rust-secp256k1/blob/master/LICENSE"><img alt="CC0 1.0 Universal Licensed" src="https://img.shields.io/badge/license-CC0--1.0-blue.svg"/></a>
    <a href="https://github.com/rust-bitcoin/rust-secp256k1/actions?query=workflow%3AContinuous%20integration"><img alt="CI Status" src="https://github.com/rust-bitcoin/rust-secp256k1/workflows/Continuous%20integration/badge.svg"></a>
    <a href="https://docs.rs/secp256k1"><img alt="API Docs" src="https://img.shields.io/badge/docs.rs-secp256k1-green"/></a>
    <a href="https://blog.rust-lang.org/2020/02/27/Rust-1.56.1.html"><img alt="Rustc Version 1.56.1+" src="https://img.shields.io/badge/rustc-1.56.1.0%2B-lightgrey.svg"/></a>
  </p>
</div>

`rust-secp256k1` is a wrapper around [libsecp256k1](https://github.com/bitcoin-core/secp256k1), a C
library implementing various cryptographic functions using the [SECG](https://www.secg.org/) curve
[secp256k1](https://en.bitcoin.it/wiki/Secp256k1).

This library:

* exposes type-safe Rust bindings for all `libsecp256k1` functions
* implements key generation
* implements deterministic nonce generation via RFC6979
* implements many unit tests, adding to those already present in `libsecp256k1`
* makes no allocations (except in unit tests) for efficiency and use in freestanding implementations

### Contributing

Contributions to this library are welcome. A few guidelines:

* Any breaking changes must have an accompanied entry in CHANGELOG.md
* No new dependencies, please.
* No crypto should be implemented in Rust, with the possible exception of hash functions. Cryptographic contributions should be directed upstream to libsecp256k1.
* This library should always compile with any combination of features on **Rust 1.56.1**.

### Githooks

To assist devs in catching errors _before_ running CI we provide some githooks. If you do not
already have locally configured githooks you can use the ones in this repository by running, in the
root directory of the repository:
```
git config --local core.hooksPath githooks/
```

Alternatively add symlinks in your `.git/hooks` directory to any of the githooks we provide.

### Benchmarks

We use a custom Rust compiler configuration conditional to guard the bench mark code. To run the
bench marks use: `RUSTFLAGS='--cfg=bench' cargo +nightly bench --features=recovery`.

### A note on `non_secure_erase`

This crate's secret types (`SecretKey`, `Keypair`, `SharedSecret`, `Scalar`, and `DisplaySecret`)
have a method called `non_secure_erase` that *attempts* to overwrite the contained secret. This
method is provided to assist other libraries in building secure secret erasure. However, this
library makes no guarantees about the security of using `non_secure_erase`. In particular,
the compiler doesn't have any concept of secrets and in most cases can arbitrarily move or copy
values anywhere it pleases. For more information, consult the [`zeroize`](https://docs.rs/zeroize)
documentation.

## Fuzzing

If you want to fuzz this library, or any library which depends on it, you will
probably want to disable the actual cryptography, since fuzzers are unable to
forge signatures and therefore won't test many interesting codepaths. To instead
use a trivially-broken but fuzzer-accessible signature scheme, compile with
`--cfg=secp256k1_fuzz` in your `RUSTFLAGS` variable.

Note that `cargo hfuzz` does **not** set this config flag automatically. In 0.27.0
and earlier versions, we used the `--cfg=fuzzing` which honggfuzz does set, but we
changed this because there was no way to override it.

