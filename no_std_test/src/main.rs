// Bitcoin secp256k1 bindings
// Written in 2019 by
//   Elichai Turkel
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

//! # secp256k1 no-std test.
//! This binary is a short smallest rust code to produce a working binary *without libstd*.
//! This gives us 2 things:
//!     1. Test that the parts of the code that should work in a no-std enviroment actually work.
//!     2. Test that we don't accidentally import libstd into `secp256k1`.
//!
//! The first is tested using the following command `cargo run --release | grep -q "Verified Successfully"`.
//! (Making sure that it successfully printed that. i.e. it didn't abort before that).
//!
//! The second is tested by the fact that it compiles. if we accidentally link against libstd we should see the following error:
//! `error[E0152]: duplicate lang item found`.
//! Example:
//! ```
//! error[E0152]: duplicate lang item found: `eh_personality`.
//!   --> src/main.rs:37:1
//!    |
//! 37 | pub extern "C" fn rust_eh_personality() {}
//!    | ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
//!    |
//!    = note: first defined in crate `panic_unwind` (which `std` depends on).
//! ```
//!
//! Notes:
//!     * Requires `panic=abort` and `--release` to not depend on libunwind(which is provided usually by libstd) https://github.com/rust-lang/rust/issues/47493
//!     * Requires linking with `libc` for calling `printf`.
//!

#![feature(lang_items)]
#![feature(start)]
#![feature(core_intrinsics)]
#![feature(panic_info_message)]
#![no_std]
extern crate libc;
extern crate secp256k1;
extern crate serde_cbor;

use core::fmt::{self, write, Write};
use core::intrinsics;
use core::panic::PanicInfo;

use secp256k1::ecdh::SharedSecret;
use secp256k1::ffi::types::AlignedType;
use secp256k1::rand::{self, RngCore};
use secp256k1::serde::Serialize;
use secp256k1::*;

use serde_cbor::de;
use serde_cbor::ser::SliceWrite;
use serde_cbor::Serializer;

struct FakeRng;
impl RngCore for FakeRng {
    fn next_u32(&mut self) -> u32 {
        57
    }
    fn next_u64(&mut self) -> u64 {
        57
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        for i in dest {
            *i = 57;
        }
        Ok(())
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.try_fill_bytes(dest).unwrap();
    }
}

#[start]
fn start(_argc: isize, _argv: *const *const u8) -> isize {
    let mut buf = [AlignedType::zeroed(); 37_000];
    let size = Secp256k1::preallocate_size();
    unsafe { libc::printf("needed size: %d\n\0".as_ptr() as _, size) };

    let mut secp = Secp256k1::preallocated_new(&mut buf).unwrap();
    secp.randomize(&mut FakeRng);
    let secret_key = SecretKey::new(&mut FakeRng);
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    let message = Message::from_slice(&[0xab; 32]).expect("32 bytes");

    let sig = secp.sign(&message, &secret_key);
    assert!(secp.verify(&message, &sig, &public_key).is_ok());

    let mut cbor_ser = [0u8; 100];
    let writer = SliceWrite::new(&mut cbor_ser[..]);
    let mut ser = Serializer::new(writer);
    sig.serialize(&mut ser).unwrap();
    let size = ser.into_inner().bytes_written();
    let new_sig: Signature = de::from_mut_slice(&mut cbor_ser[..size]).unwrap();
    assert_eq!(sig, new_sig);

    let _ = SharedSecret::new(&public_key, &secret_key);
    let mut x_arr = [0u8; 32];
    let y_arr = SharedSecret::new_with_hash(&public_key, &secret_key, |x,y| {
        x_arr = x;
        y.into()
    });
    assert_ne!(x_arr, [0u8; 32]);
    assert_ne!(&y_arr[..], &[0u8; 32][..]);

    unsafe { libc::printf("Verified Successfully!\n\0".as_ptr() as _) };
    0
}

const MAX_PRINT: usize = 511;
struct Print {
    loc: usize,
    buf: [u8; 512],
}

impl Print {
    pub fn new() -> Self {
        Self {
            loc: 0,
            buf: [0u8; 512],
        }
    }

    pub fn print(&self) {
        unsafe {
            let newline = "\n";
            libc::printf(self.buf.as_ptr() as _);
            libc::printf(newline.as_ptr() as _);
        }
    }
}

impl Write for Print {
    fn write_str(&mut self, s: &str) -> Result<(), fmt::Error> {
        let curr = self.loc;
        if curr + s.len() > MAX_PRINT {
            unsafe {
                libc::printf("overflow\n\0".as_ptr() as _);
                intrinsics::abort();
            }
        }
        self.loc += s.len();
        self.buf[curr..self.loc].copy_from_slice(s.as_bytes());
        Ok(())
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    unsafe { libc::printf("shi1\n\0".as_ptr() as _) };
    let msg = info.message().unwrap();
    let mut buf = Print::new();
    write(&mut buf, *msg).unwrap();
    buf.print();
    intrinsics::abort()
}
