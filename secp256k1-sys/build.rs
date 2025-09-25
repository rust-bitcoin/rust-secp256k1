// SPDX-License-Identifier: CC0-1.0

//! # Build script

// Coding conventions
#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
#![warn(missing_docs)]

extern crate cc;

use std::env;

fn main() {
    // Actual build
    let mut base_config = cc::Build::new();
    base_config
        .include("depend/secp256k1/")
        .include("depend/secp256k1/include")
        .include("depend/secp256k1/src")
        .flag_if_supported("-Wno-unused-function") // some ecmult stuff is defined but not used upstream
        .flag_if_supported("-Wno-unused-parameter") // patching out printf causes this warning
        .define("SECP256K1_API", Some(""))
        .define("ENABLE_MODULE_ECDH", Some("1"))
        .define("ENABLE_MODULE_SCHNORRSIG", Some("1"))
        .define("ENABLE_MODULE_EXTRAKEYS", Some("1"))
        .define("ENABLE_MODULE_ELLSWIFT", Some("1"))
        .define("ENABLE_MODULE_MUSIG", Some("1"))
        // upstream sometimes introduces calls to printf, which we cannot compile
        // with WASM due to its lack of libc. printf is never necessary and we can
        // just #define it away.
        .define("printf(...)", Some(""));

    if env::var("CARGO_CFG_TARGET_ARCH").unwrap() == "riscv32" {
        const DEFAULT_RISCV_GNU_TOOLCHAIN: &str = "/opt/riscv";
        println!("cargo:rerun-if-env-changed=RISCV_GNU_TOOLCHAIN");

        let riscv_gnu_toolchain_path = env::var("RISCV_GNU_TOOLCHAIN").unwrap_or_else(|_| {
            println!("cargo:warning=Variable RISCV_GNU_TOOLCHAIN unset. Assuming '{DEFAULT_RISCV_GNU_TOOLCHAIN}'");
            println!("cargo:warning=Please make sure to build riscv toolchain:");
            println!("cargo:warning=  git clone https://github.com/riscv-collab/riscv-gnu-toolchain && cd riscv-gnu-toolchain");
            println!("cargo:warning=  export RISCV_GNU_TOOLCHAIN={DEFAULT_RISCV_GNU_TOOLCHAIN}");
            println!("cargo:warning=  configure --prefix=\"$RISCV_GNU_TOOLCHAIN\" --with-arch=rv32im --with-abi=ilp32");
            println!("cargo:warning=  make -j$(nproc)");

            // if unset, try the default and fail eventually
            DEFAULT_RISCV_GNU_TOOLCHAIN.into()
        });

        base_config
            .compiler("clang")
            .no_default_flags(true)
            .flag(&format!("--sysroot={riscv_gnu_toolchain_path}/riscv32-unknown-elf"))
            .flag(&format!("--gcc-toolchain={riscv_gnu_toolchain_path}"))
            .flag("--target=riscv32-unknown-none-elf")
            .flag("-march=rv32im")
            .flag("-mabi=ilp32")
            .flag("-mcmodel=medany")
            .flag("-Os")
            .flag("-fdata-sections")
            .flag("-ffunction-sections")
            .flag("-flto")
            .target("riscv32-unknown-none-elf");
    }

    if cfg!(feature = "lowmemory") {
        base_config.define("ECMULT_WINDOW_SIZE", Some("4")); // A low-enough value to consume negligible memory
        base_config.define("COMB_BLOCKS", Some("2"));
        base_config.define("COMB_TEETH", Some("5"));
    } else {
        base_config.define("ECMULT_WINDOW_SIZE", Some("15")); // This is the default in the configure file (`auto`)
        base_config.define("COMB_BLOCKS", Some("43"));
        base_config.define("COMB_TEETH", Some("6"));
    }
    base_config.define("USE_EXTERNAL_DEFAULT_CALLBACKS", Some("1"));
    #[cfg(feature = "recovery")]
    base_config.define("ENABLE_MODULE_RECOVERY", Some("1"));

    // WASM headers and size/align defines.
    if env::var("CARGO_CFG_TARGET_ARCH").unwrap() == "wasm32" {
        base_config.include("wasm/wasm-sysroot").file("wasm/wasm.c");
    }

    // secp256k1
    base_config
        .file("depend/secp256k1/contrib/lax_der_parsing.c")
        .file("depend/secp256k1/src/precomputed_ecmult_gen.c")
        .file("depend/secp256k1/src/precomputed_ecmult.c")
        .file("depend/secp256k1/src/secp256k1.c");

    if base_config.try_compile("libsecp256k1.a").is_err() {
        // Some embedded platforms may not have, eg, string.h available, so if the build fails
        // simply try again with the wasm sysroot (but without the wasm type sizes) in the hopes
        // that it works.
        base_config.include("wasm/wasm-sysroot");
        base_config.compile("libsecp256k1.a");
    }
}
