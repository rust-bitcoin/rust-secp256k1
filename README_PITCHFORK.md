### Build test to emit LLVM bitcode

Haybale-pitchfork requires llvm-sys (LLVM Rust bindings) and boolector to be
installed as shared libraries prior to generating bitcode and compiling this test.

Generate LLVM bitcode:

```
CARGO_INCREMENTAL="" cargo rustc -- -g --emit llvm-bc
```

Run test:

```
cargo test --test pitchfork
```
