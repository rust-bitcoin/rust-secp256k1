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

#[macro_use]
extern crate cfg_if;

extern crate cc;

use std::env;
use std::ffi::OsString;
use std::path::PathBuf;

cfg_if! {
	if #[cfg(target_os = "macos")] {
		const OS: &'static str = "darwin";
	} else if #[cfg(target_os = "linux")] {
		const OS: &'static str = "linux";
	} else if #[cfg(target_os = "windows")] {
		const OS: &'static str = "windows";
	} else {
		// all other OS without android support
		const OS: &'static str = "unknown";
	}
}

const ANDROID_INCLUDE: &'static str = "platforms/android-21/arch-arm64/usr/include";

fn android_aarch_compiler() -> String {
	"toolchains/aarch64-linux-android-4.9/prebuilt/".to_owned() + OS + "-x86_64/bin"
}

fn android_arm_compiler() -> String {
	"toolchains/arm-linux-androideabi-4.9/prebuilt/".to_owned() + OS + "-x86_64/bin"
}

fn android_i686_compiler() -> String {
	"toolchains/x86-4.9/prebuilt/".to_owned() + OS + "-x86_64/bin"
}

fn concat_paths(first: &str, second: &str) -> PathBuf {
	let mut path = PathBuf::from(first);
	path.push(second);
	path
}

fn setup_android(config: &mut cc::Build) {
	assert_ne!(OS, "unknown", "unsupported android toolchain");
	let path = env::var_os("PATH").unwrap_or_else(OsString::new);
	let ndk_home = env::var("NDK_HOME").expect("NDK_HOME is not set");
	let mut paths = env::split_paths(&path).collect::<Vec<_>>();
	paths.push(concat_paths(&ndk_home, &android_aarch_compiler()));
	paths.push(concat_paths(&ndk_home, &android_arm_compiler()));
	paths.push(concat_paths(&ndk_home, &android_i686_compiler()));

	let new_path = env::join_paths(paths).expect("all paths were created using PathBuf's; qed");
	env::set_var("PATH", new_path);

	config.include(&concat_paths(&ndk_home, ANDROID_INCLUDE));
}

fn main() {
	// Check whether we can use 64-bit compilation
	let use_64bit_compilation = if env::var("CARGO_CFG_TARGET_POINTER_WIDTH").unwrap() == "64" {
		let check = cc::Build::new().file("depend/check_uint128_t.c")
			.cargo_metadata(false)
			.try_compile("check_uint128_t")
			.is_ok();
		if !check {
			println!("cargo:warning=Compiling in 32-bit mode on a 64-bit architecture due to lack of uint128_t support.");
		}
		check
	} else {
		false
	};

	let mut base_config = cc::Build::new();
	base_config.include("depend/secp256k1/")
		.include("depend/secp256k1/include")
		.include("depend/secp256k1/src")
		.debug(true)
		.flag_if_supported("-Wno-unused-function") // some ecmult stuff is defined but not used upstream
		.define("SECP256K1_BUILD", Some("1"))
		// Allowed values are 2..24, there is a tradeoff between
		// memory and cpu time (tuned for best ratio)
		.define("ECMULT_WINDOW_SIZE", Some("8"))
		// Allowed values are: 2, 4, and 8 (tuned for best perf)
		.define("ECMULT_GEN_PREC_BITS", Some("4"))
		// TODO these three should be changed to use libgmp, at least until secp PR 290 is merged
		.define("USE_NUM_NONE", Some("1"))
		.define("USE_FIELD_INV_BUILTIN", Some("1"))
		.define("USE_SCALAR_INV_BUILTIN", Some("1"))
		.define("USE_ENDOMORPHISM", Some("1"))
		.define("ENABLE_MODULE_ECDH", Some("1"))
		// SCHNORR support was removed in the upstream
		// .define("ENABLE_MODULE_SCHNORR", Some("1"))
		.define("ENABLE_MODULE_RECOVERY", Some("1"));

	let target = env::var("TARGET").expect("TARGET env variable is set by cargo; qed");
	if target.contains("android") {
		setup_android(&mut base_config);
	}

	if let Ok(target_endian) = env::var("CARGO_CFG_TARGET_ENDIAN") {
		if target_endian == "big" {
			base_config.define("WORDS_BIGENDIAN", Some("1"));
		}
	}

	if use_64bit_compilation {
		base_config.define("USE_FIELD_5X52", Some("1"))
			.define("USE_SCALAR_4X64", Some("1"))
			.define("HAVE___INT128", Some("1"));
	} else {
		base_config.define("USE_FIELD_10X26", Some("1"))
			.define("USE_SCALAR_8X32", Some("1"));
	}

	// secp256k1
	base_config.file("depend/secp256k1/contrib/lax_der_parsing.c")
		.file("depend/ext.c")
		.compile("libsecp256k1.a");
}

