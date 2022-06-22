
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

