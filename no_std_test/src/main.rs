#![feature(lang_items)]
#![feature(start)]
#![feature(core_intrinsics)]
#![feature(panic_info_message)]
#![no_std]
extern crate libc;
extern crate secp256k1;

use core::fmt::*;
use core::intrinsics;
use core::panic::PanicInfo;

use secp256k1::*;

#[start]
fn start(_argc: isize, _argv: *const *const u8) -> isize {
    let mut buf = [0u8; 600_000];
    let size = Secp256k1::preallocate_size();
    unsafe { libc::printf("needed size: %d\n\0".as_ptr() as _, size) };

    let secp = Secp256k1::preallocated_new(&mut buf).unwrap();
    let secret_key = SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order");
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    let message = Message::from_slice(&[0xab; 32]).expect("32 bytes");

    let sig = secp.sign(&message, &secret_key);
    assert!(secp.verify(&message, &sig, &public_key).is_ok());
    unsafe { libc::printf("Verified Successfully!\n\0".as_ptr() as _) };
    0
}

// These functions are used by the compiler, but not
// for a bare-bones hello world. These are normally
// provided by libstd.
#[lang = "eh_personality"]
#[no_mangle]
pub extern "C" fn rust_eh_personality() {}

// This function may be needed based on the compilation target.
#[lang = "eh_unwind_resume"]
#[no_mangle]
pub extern "C" fn rust_eh_unwind_resume() {}

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
    fn write_str(&mut self, s: &str) -> Result {
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
    unsafe { intrinsics::abort() }
}
