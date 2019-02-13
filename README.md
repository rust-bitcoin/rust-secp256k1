[![Build Status](https://travis-ci.org/rust-bitcoin/rust-secp256k1-zkp.png?branch=master)](https://travis-ci.org/rust-bitcoin/rust-secp256k1-zkp)

[Full documentation](https://docs.rs/secp256k1-zkp/)

### rust-secp256k1

`rust-secp256k1-zkp` is a wrapper around ![libsecp256k1](https://github.com/ElementsProject/secp256k1-zkp),
a C library by Pieter Wuille for producing ECDSA signatures using the SECG curve
`secp256k1`. This library
* exposes type-safe Rust bindings for `libsecp256k1-zkp` functions
* implements key generation
* implements deterministic nonce generation via RFC6979
* implements many unit tests, adding to those already present in `libsecp256k1-zkp`
* makes no allocations (except in unit tests) for efficiency and use in freestanding implementations

### Contributing

Contributions to this library are welcome. A few guidelines:

* Any breaking changes must have an accompanied entry in CHANGELOG.md
* No new dependencies, please.
* This library should always compile with any combination of features on **Rust 1.14**, which is the currently shipping compiler on Debian.

