// Bitcoin secp256k1 bindings
// Written in 2015 by
//   Andrew Poelstra
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! # Build script

// Coding conventions
#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
#![warn(missing_docs)]

extern crate cc;

use std::env;

fn gen_max_align() {
    configured_cc()
        .file("depend/max_align.c")
        .cargo_metadata(false)
        .compile("max_align.o");
    let out_dir = std::path::PathBuf::from(std::env::var_os("OUT_DIR").expect("missing OUT_DIR"));
    let target_endian = std::env::var("CARGO_CFG_TARGET_ENDIAN")
        .expect("missing CARGO_CFG_TARGET_ENDIAN");
    let target_pointer_width_bytes = std::env::var("CARGO_CFG_TARGET_POINTER_WIDTH")
        .expect("missing CARGO_CFG_TARGET_POINTER_WIDTH")
        .parse::<usize>()
        .expect("malformed CARGO_CFG_TARGET_POINTER_WIDTH")
        // CARGO_CFG_TARGET_POINTER_WIDTH is in bits, we want bytes
        / 8;
    let max_align_bin = out_dir.join("max_align.bin");
    // Note that this copies *whole* sections to a binary file.
    // It's a bit brittle because some other symbol could theoretically end up there.
    // Currently it only has one on my machine and we guard against unexpected changes by checking
    // the size - it must match the target pointer width.
    let objcopy = std::process::Command::new("objcopy")
        .args(&["-O", "binary"])
        // cc inserts depend - WTF
        .arg(out_dir.join("depend/max_align.o"))
        .arg(&max_align_bin)
        .spawn()
        .expect("failed to run objcopy")
        .wait()
        .expect("failed to wait for objcopy");
    assert!(objcopy.success(), "objcopy failed");
    let mut max_align_bytes = std::fs::read(max_align_bin).expect("failed to read max_align.bin");
    // The `usize` of target and host may not match so we need to do conversion.
    // Sensible alignments should be very small anyway but we don't want crappy `unsafe` code.
    // Little endian happens to be a bit easier to process so we convert into that.
    // If the type is smaller than `u64` we zero-pad it.
    // If the type is larger than `u6` but the number fits into `u64` it'll have
    // unused tail which is easy to cut-off.
    // If the number is larger than `u64::MAX` then bytes beyond `u64` size will
    // be non-zero.
    //
    // So as long as the max alignment fits into `u64` this can decode alignment
    // for any architecture on any architecture.
    assert_eq!(max_align_bytes.len(), target_pointer_width_bytes);
    if target_endian != "little" {
        max_align_bytes.reverse()
    }
    // copying like this auto-pads the number with zeroes
    let mut buf = [0; std::mem::size_of::<u64>()];
    let to_copy = buf.len().min(max_align_bytes.len());
    // Overflow check
    if max_align_bytes[to_copy..].iter().any(|b| *b != 0) {
        panic!("max alignment overflowed u64");
    }
    buf[..to_copy].copy_from_slice(&max_align_bytes[..to_copy]);
    let max_align = u64::from_le_bytes(buf);
    let src = format!(r#"
/// A type that is as aligned as the biggest alignment for fundamental types in C.
///
/// Since C11 that means as aligned as `max_align_t` is.
/// The exact size/alignment is unspecified.
#[repr(align({}))]
#[derive(Default, Copy, Clone)]
pub struct AlignedType([u8; {}]);"#, max_align, max_align);
    std::fs::write(out_dir.join("aligned_type.rs"), src.as_bytes()).expect("failed to write aligned_type.rs");
}

/// Returns CC builder configured with all defines but no C files.
fn configured_cc() -> cc::Build {
    // While none of these currently affect max alignment we prefer to keep the "hygiene" so that
    // new code will be correct.
    let mut base_config = cc::Build::new();
    base_config.define("SECP256K1_API", Some(""))
               .define("ENABLE_MODULE_ECDH", Some("1"))
               .define("ENABLE_MODULE_SCHNORRSIG", Some("1"))
               .define("ENABLE_MODULE_EXTRAKEYS", Some("1"));

    if cfg!(feature = "lowmemory") {
        base_config.define("ECMULT_WINDOW_SIZE", Some("4")); // A low-enough value to consume negligible memory
        base_config.define("ECMULT_GEN_PREC_BITS", Some("2"));
    } else {
        base_config.define("ECMULT_GEN_PREC_BITS", Some("4"));
        base_config.define("ECMULT_WINDOW_SIZE", Some("15")); // This is the default in the configure file (`auto`)
    }
    base_config.define("USE_EXTERNAL_DEFAULT_CALLBACKS", Some("1"));
    #[cfg(feature = "recovery")]
    base_config.define("ENABLE_MODULE_RECOVERY", Some("1"));

    base_config
}

fn build_secp256k1() {
    let mut base_config = configured_cc();
    base_config.include("depend/secp256k1/")
               .include("depend/secp256k1/include")
               .include("depend/secp256k1/src")
               .flag_if_supported("-Wno-unused-function"); // some ecmult stuff is defined but not used upstream


    // WASM headers and size/align defines.
    if env::var("CARGO_CFG_TARGET_ARCH").unwrap() == "wasm32" {
        base_config.include("wasm/wasm-sysroot")
                   .file("wasm/wasm.c");
    }

    // secp256k1
    base_config.file("depend/secp256k1/contrib/lax_der_parsing.c")
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

fn main() {
    gen_max_align();
    build_secp256k1();
}
