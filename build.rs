//! # Build script

// Coding conventions
#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
#![warn(missing_docs)]

//extern crate mktemp;

use std::env;
use std::fs;
use std::io::ErrorKind;
use std::process::Command;
use std::path::PathBuf;

fn main() {
    let src = env::current_dir().unwrap().join("depend/secp256k1");

    let dst = PathBuf::from("/tmp/secp256k1");
    let _ = fs::create_dir_all(&dst).unwrap();

    run(Command::new("sh").current_dir(&src).arg("autogen.sh"), "sh");

    let mut cmd = Command::new("sh");
    cmd.current_dir(&src)
        .env("CFLAGS", "-fPIC")
        .arg("configure")
        .arg("--enable-shared")
        .arg("--enable-endomorphism")
        .arg("--enable-module-recovery")
        .arg("--enable-tests=no")
        .arg("--enable-openssl-tests=no")
        .arg("--enable-exhaustive-tests=no")
        .arg("--with-bignum=no")
        .arg(format!("--prefix={}", dst.display()));

    run(&mut cmd, "sh");

    run(
        Command::new("make")
            .current_dir(&src)
            .env("CFLAGS", "-fPIC")
            .arg("install"),
        "make",
    );

    println!("cargo:rustc-link-search=native={}/lib", dst.display());
    println!("cargo:rustc-link-lib=static=secp256k1");
}

fn run(cmd: &mut Command, program: &str) {
    println!("running: {:?}", cmd);
    let status = match cmd.status() {
        Ok(status) => status,
        Err(ref e) if e.kind() == ErrorKind::NotFound => {
            fail(&format!(
                "failed to execute command: {}\nis `{}` not installed?",
                e, program
            ));
        }
        Err(e) => fail(&format!("failed to execute command: {}", e)),
    };
    if !status.success() {
        fail(&format!(
            "command did not execute successfully, got: {}",
            status
        ));
    }
}

fn fail(s: &str) -> ! {
    panic!("\n{}\n\nbuild script failed, must exit now", s)
}
