# SGX port of rust-secp256k1

This is a port of [rust-secp256k1]() to SGX environment based on [Rust SGX SDK](https://github.com/baidu/rust-sgx-sdk). Features include: 

- supports basic APIs and the `rand` feature (see [upstream doc](https://docs.rs/secp256k1/) for a complete list of APIs).

See [CHANGELOG.md](CHANGELOG.md) for details.


# Upstream README

### rust-secp256k1

`rust-secp256k1` is a wrapper around [libsecp256k1](https://github.com/bitcoin-core/secp256k1),
a C library by Pieter Wuille for producing ECDSA signatures using the SECG curve
`secp256k1`. This library
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
* This library should always compile with any combination of features on **Rust 1.14**, which is the currently shipping compiler on Debian.

