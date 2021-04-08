secp256k1-sys
=============


This crate provides Rust definitions for the FFI structures and methods.

## Linking to external symbols

If you want to compile this library without using the bundled symbols (which may
be required for integration into other build systems), you can do so by adding
`--cfg=rust_secp_no_symbol_renaming'` to your `RUSTFLAGS` variable.

