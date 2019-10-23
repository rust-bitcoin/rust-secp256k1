[![Build Status](https://gitlab.parity.io/parity/rust-secp256k1/badges/master/build.svg)](https://gitlab.parity.io/parity/rust-secp256k1/commits/master)
![crates.io](https://img.shields.io/crates/v/parity-secp256k1.svg)
[![](https://tokei.rs/b1/github/paritytech/rust-secp256k1)](https://github.com/paritytech/rust-secp256k1)


### parity-secp256k1

`parity-secp256k1` is a wrapper around [libsecp256k1](https://github.com/bitcoin/secp256k1),
a C library by Peter Wuille for producing ECDSA signatures using the SECG curve
`secp256k1`. It is a fork of [`rust-secp256k1`](https://github.com/rust-bitcoin/rust-secp256k1).
 
This library
* exposes type-safe Rust bindings for all `libsecp256k1` functions
* implements key generation
* implements deterministic nonce generation via RFC6979
* implements many unit tests, adding to those already present in `libsecp256k1`
* makes no allocations (except in unit tests) for efficiency and use in freestanding implementations

[Full documentation](https://docs.rs/parity-secp256k1)

#### Build

Clone the repository. Run the following:

```
git submodule init
git submodule update
cargo check
```

