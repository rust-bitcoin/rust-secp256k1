secp256k1-sys
=============


This crate provides Rust definitions for the FFI structures and methods.


## Vendoring

The default build process is to build using the vendored libsecp256k1 sources in
the depend folder. These sources are prefixed with a special
rust-secp256k1-sys-specific prefix `rustsecp256k1_v1_2_3_`.

This prefix ensures that no symbol collision can happen:
- when a Rust project has two different versions of rust-secp256k1 in its
  depepdency tree, or
- when rust-secp256k1 is used for building a static library in a context where
  existing libsecp256k1 symbols are already linked.

To update the vendored sources, use the `vendor-libsecp.sh` script:

```
$ ./vendor-libsecp.sh depend <version-code> <rev>
```

- Where `<version-code>` is the secp256k1-sys version number underscored: `0_1_2`.
- Where `<rev>` is the git revision of libsecp256k1 to checkout.


## Linking to external symbols

If you want to compile this library without using the bundled symbols (which may
be required for integration into other build systems), you can do so by adding
`--cfg=rust_secp_no_symbol_renaming'` to your `RUSTFLAGS` variable.

