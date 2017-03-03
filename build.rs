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

extern crate gcc;

use std::env;
use std::ffi::OsString;
use std::path::PathBuf;

#[cfg(target_os = "macos")]
const OS: &'static str = "darwin";
#[cfg(target_os = "linux")]
const OS: &'static str = "linux";
#[cfg(target_os = "windows")]
const OS: &'static str = "windows";

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

fn setup_android(config: &mut gcc::Config) {
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
	let mut base_config = gcc::Config::new();
	base_config.include("depend/secp256k1/")
		.include("depend/secp256k1/include")
		.include("depend/secp256k1/src");

	let target = env::var("TARGET").expect("TARGET env variable is set by cargo; qed");
	if target.contains("android") {
		setup_android(&mut base_config);
	}

	base_config.flag("-g")
		// TODO these three should be changed to use libgmp, at least until secp PR 290 is merged
		.define("USE_NUM_NONE", Some("1"))
		.define("USE_FIELD_INV_BUILTIN", Some("1"))
		.define("USE_SCALAR_INV_BUILTIN", Some("1"))
		// TODO these should use 64-bit variants on 64-bit systems
		.define("USE_FIELD_10X26", Some("1"))
		.define("USE_SCALAR_8X32", Some("1"))
		.define("USE_ENDOMORPHISM", Some("1"))
		// These all are OK.
		.define("ENABLE_MODULE_ECDH", Some("1"))
		.define("ENABLE_MODULE_SCHNORR", Some("1"))
		.define("ENABLE_MODULE_RECOVERY", Some("1"));

	// secp256k1
	base_config.file("depend/secp256k1/contrib/lax_der_parsing.c")
		.file("depend/secp256k1/src/ext.c")
		.compile("libsecp256k1.a");
}

