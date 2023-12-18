# 0.9.2 - 2023-12-18

* Fix incorrect FFI binding for `secp256k1_pubkey_combine`

# 0.9.1 - 2023-12-07

* Patch out any instances of printf in upstream [#663](https://github.com/rust-bitcoin/rust-secp256k1/pull/663)

# 0.9.0 - 2023-10-23

* Add bindings to the ElligatorSwift implementation [#627](https://github.com/rust-bitcoin/rust-secp256k1/pull/627)
* Update vendored lib secp256k1 to v0.4.0 [#653](https://github.com/rust-bitcoin/rust-secp256k1/pull/653)
* Bump MSRV to 1.48 [#595](https://github.com/rust-bitcoin/rust-secp256k1/pull/595)

# 0.8.1 - 2023-03-16

* [Implement `insecure-erase`](https://github.com/rust-bitcoin/rust-secp256k1/pull/582).

# 0.8.0 - 2202-12-19

* Update libsecp25k1 to v0.2.0

# 0.7.0 - 2022-12-01

* [Make comparison functions stable across library versions](https://github.com/rust-bitcoin/rust-secp256k1/pull/518)
* Add public methods `cmp_fast_unstable` and `eq_fast_unstable` for types that contain an inner array (see PR linked above).

# 0.6.0 - 2022-06-21

* [Bump MSRV to 1.41](https://github.com/rust-bitcoin/rust-secp256k1/pull/331)
* [Re-implement `Ord` on `PublicKey` using upstream ordering function](https://github.com/rust-bitcoin/rust-secp256k1/pull/449)

# 0.5.1 - 2022-04-30

* [Fix WASM build](https://github.com/rust-bitcoin/rust-secp256k1/pull/421)

# 0.3.0 - 2020-08-27

* **Update MSRV to 1.29.0**

# 0.2.0 - 2020-08-26

* Update upstream to `670cdd3f8be25f81472b2d16dcd228b0d24a5c45`
* [Add missing return](https://github.com/rust-bitcoin/rust-secp256k1/pull/195) `c_int` to `NonceFn`
* [Got wasm support working again](https://github.com/rust-bitcoin/rust-secp256k1/pull/208)
* Removed `cc` restriction, rustc 1.22 support [now requires some downstream effort](https://github.com/rust-bitcoin/rust-secp256k1/pull/204)
* [Exposed a reference to the underlying byte array](https://github.com/rust-bitcoin/rust-secp256k1/pull/219) for all byte-array-wrapping types
* Allow all-zeroes `Message` [to be constructed](https://github.com/rust-bitcoin/rust-secp256k1/pull/207)
* Expose `secp256k1_ec_pubkey_negate` [from upstream](https://github.com/rust-bitcoin/rust-secp256k1/pull/222)

