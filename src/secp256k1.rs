
//! # Secp256k1
//! Rust bindings for Pieter Wuille's secp256k1 library, which is used for
//! fast and accurate manipulation of ECDSA signatures on the secp256k1
//! curve. Such signatures are used extensively by the Bitcoin network
//! and its derivatives.
//!

#![crate_type = "lib"]
#![crate_type = "rlib"]
#![crate_type = "dylib"]
#![crate_name = "bitcoin-secp256k1-rs"]
#![comment = "Bindings and wrapper functions for bitcoin secp256k1 library."]
#![feature(phase)]
#![feature(globs)]  // for tests only

// Coding conventions
#![deny(non_uppercase_pattern_statics)]
#![deny(uppercase_variables)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case_functions)]
#![deny(unused_mut)]
#![warn(missing_doc)]

extern crate libc;
extern crate sync;

use libc::c_int;
use sync::one::{Once, ONCE_INIT};

pub mod ffi;

/// A secret 256-bit nonce used as `k` in an ECDSA signature
pub type Nonce = [u8, ..32];

/// A secret 256-bit key used as `x` in an ECDSA signature
pub type SecKey = [u8, ..32];

/// A public key
pub enum PubKey {
    /// A compressed (1-bit x-coordinate) EC public key
    Compressed([u8, ..33]),
    /// An uncompressed (full x-coordinate) EC public key
    Uncompressed([u8, ..65])
}
/// An ECDSA signature
pub type Signature = Vec<u8>;

/// An ECDSA error
#[deriving(Show)]
#[deriving(Eq)]
#[deriving(PartialEq)]
pub enum Error {
    /// Bad public key
    InvalidPublicKey,
    /// Bad signature
    InvalidSignature,
    /// Bad secret key
    InvalidSecretKey,
    /// Bad nonce
    InvalidNonce,
}

#[deriving(Eq)]
#[deriving(PartialEq)]
/// Result of verifying a signature
pub type VerifyResult = Result<bool, Error>;

static mut Secp256k1_init : Once = ONCE_INIT;

/// The secp256k1 engine, used to execute all signature operations
pub struct Secp256k1;


impl Secp256k1 {
    /// Constructs a new secp256k1 engine.
    pub fn new() -> Secp256k1 {
        unsafe {
            Secp256k1_init.doit(|| {
                ffi::secp256k1_start();
            });
        }
        Secp256k1
    }

    /// Determines the public key corresponding to a given private key.
    pub fn pubkey_create(
        &self,
        pubkey : &mut PubKey,
        seckey : &SecKey
        ) -> Result<(), Error> {

        let (compressed, pub_ptr, pub_len) = match *pubkey {
            Uncompressed(ref mut key) => (false, key.as_mut_ptr(), key.len()),
            Compressed(ref mut key) => (true, key.as_mut_ptr(), key.len()),
        };
        let mut len = pub_len as c_int;
        let res = unsafe {
            ffi::secp256k1_ecdsa_pubkey_create(
                pub_ptr, &mut len,
                seckey.as_ptr(),
                if compressed {1} else {0}
                )
        };

        assert_eq!(pub_len as i32, len);

        match res {
            0 => Err(InvalidSecretKey),
            1 => Ok(()),
            _ => fail!("secp256k1_ecdsa_pubkey_create invalid return value"),
        }
    }

    /// Constructs a signature for `msg` using the secret key `seckey`
    pub fn sign(&self, sig : &mut Signature, msg : &[u8], seckey : &SecKey, nonce : &Nonce) -> Result<(), Error> {

        let origlen = 72u;
        let mut siglen = origlen as c_int;

        if sig.len() != origlen {
            fail!("invalid length of signature buffer");
        }

        let res = unsafe {
            ffi::secp256k1_ecdsa_sign(
                msg.as_ptr(), msg.len() as c_int,
                sig.as_mut_ptr(), &mut siglen,
                seckey.as_ptr(),
                nonce.as_ptr()
                )
        };

        if (origlen as c_int) < siglen {
            fail!("secp256k1_ecdsa_sign wrong return len");
        }

        match res {
            0 => Err(InvalidNonce),
            1 => { sig.truncate(siglen as uint); Ok(()) },
            _ => fail!("secp256k1_ecdsa_sign invalid return value"),
        }
    }

    /// Constructs a compact signature for `msg` using the secret key `seckey`
    pub fn sign_compact(
        &self,
        sig : &mut [u8],
        msg : &[u8],
        seckey : &SecKey,
        nonce : &Nonce
        ) -> Result<i32, Error> {

        let origlen = 64u;

        if sig.len() != origlen {
            fail!("invalid length of signature buffer");
        }

        let mut recid = 0;

        let res = unsafe {
            ffi::secp256k1_ecdsa_sign_compact(
                msg.as_ptr(), msg.len() as c_int,
                sig.as_mut_ptr(),
                seckey.as_ptr(),
                nonce.as_ptr(),
                &mut recid
                )
        };

        match res {
            0 => Err(InvalidNonce),
            1 => { Ok(recid) },
            _ => fail!("secp256k1_ecdsa_sign_compact invalid return value"),
        }
    }

    /// Determines the public key for which `sig` is a valid signature for
    /// `msg`. Returns through the out-pointer `pubkey`.
    pub fn recover_compact(
        &self,
        msg : &[u8],
        sig : &[u8],
        pubkey : &mut PubKey,
        recid : i32
        ) -> Result<(), Error> {

        let (compressed, pub_ptr, pub_len) = match *pubkey {
            Uncompressed(ref mut key) => (false, key.as_mut_ptr(), key.len()),
            Compressed(ref mut key) => (true, key.as_mut_ptr(), key.len()),
        };

        let origlen = 64u;

        if sig.len() != origlen {
            fail!("invalid length of signature buffer");
        }

        let mut len = pub_len as c_int;
        let res = unsafe {
            ffi::secp256k1_ecdsa_recover_compact(
                msg.as_ptr(), msg.len() as i32,
                sig.as_ptr(),
                pub_ptr, &mut len,
                if compressed {1} else {0},
                recid
                )
        };

        assert_eq!(pub_len as i32, len);

        match res {
            0 => Err(InvalidSignature),
            1 => Ok(()),
            _ => fail!("secp256k1_ecdsa_recover_compact invalid return value"),
        }
    }


    /// Checks that `sig` is a valid ECDSA signature for `msg` using the public
    /// key `pubkey`. Returns `Ok(true)` on success.
    pub fn verify(&self, msg : &[u8], sig : &[u8], pubkey : &PubKey) -> VerifyResult {

        let (pub_ptr, pub_len) = match *pubkey {
            Uncompressed(ref key) => (key.as_ptr(), key.len()),
            Compressed(ref key) => (key.as_ptr(), key.len()),
        };

        let res = unsafe {
            ffi::secp256k1_ecdsa_verify(
                msg.as_ptr(), msg.len() as c_int,
                sig.as_ptr(), sig.len() as c_int,
                pub_ptr, pub_len as c_int
                )
        };

        match res {
            1 => Ok(true),
            0 => Ok(false),
            -1 => Err(InvalidPublicKey),
            -2 => Err(InvalidSignature),
            _ => fail!("secp256k1_ecdsa_verify() invalid return value")
        }
    }
}


#[cfg(test)]
mod test {

    use std::rand;
    use std::rand::Rng;
    use super::*;

    #[test]
    fn invalid_pubkey() {
        let s = Secp256k1::new();

        let mut msg = Vec::from_elem(32, 0u8);
        let sig = Vec::from_elem(32, 0u8);
        let pubkey = Compressed([0u8, .. 33]);

        rand::task_rng().fill_bytes(msg.as_mut_slice());

        assert_eq!(s.verify(msg.as_mut_slice(), sig.as_slice(), &pubkey), Err(InvalidPublicKey));
    }

    #[test]
    fn valid_pubkey_uncompressed() {
        let s = Secp256k1::new();

        let seckey = [0u8, ..32];
        let mut pubkey = Uncompressed([0u8, ..65]);
        s.pubkey_create(&mut pubkey, &seckey).unwrap();
        let mut msg = Vec::from_elem(32, 0u8);
        let sig = Vec::from_elem(32, 0u8);

        rand::task_rng().fill_bytes(msg.as_mut_slice());

        assert_eq!(s.verify(msg.as_mut_slice(), sig.as_slice(), &pubkey), Err(InvalidSignature));
    }

    #[test]
    fn valid_pubkey_compressed() {
        let s = Secp256k1::new();

        let seckey = [0u8, ..32];
        let mut pubkey = Compressed([0u8, .. 33]);
        s.pubkey_create(&mut pubkey, &seckey).unwrap();
        let mut msg = Vec::from_elem(32, 0u8);
        let sig = Vec::from_elem(32, 0u8);

        rand::task_rng().fill_bytes(msg.as_mut_slice());

        assert_eq!(s.verify(msg.as_mut_slice(), sig.as_slice(), &pubkey), Err(InvalidSignature));
    }

    #[test]
    fn sign() {
        let s = Secp256k1::new();

        let mut msg = [0u8, ..32];
        let mut seckey = [0u8, ..32];
        let mut nonce = [0u8, ..32];
        let mut sig = Vec::from_elem(72, 0u8);
        rand::task_rng().fill_bytes(msg);
        rand::task_rng().fill_bytes(nonce);
        rand::task_rng().fill_bytes(seckey);

        s.sign(&mut sig, msg.as_slice(), &seckey, &nonce).unwrap();
    }

    #[test]
    fn sign_and_verify() {
        let s = Secp256k1::new();

        let mut msg = Vec::from_elem(32, 0u8);
        let mut seckey = [0u8, ..32];
        let mut pubkey = Compressed([0u8, .. 33]);
        let mut nonce = [0u8, ..32];
        let mut sig = Vec::from_elem(72, 0u8);
        rand::task_rng().fill_bytes(msg.as_mut_slice());
        rand::task_rng().fill_bytes(nonce);
        rand::task_rng().fill_bytes(seckey);

        s.pubkey_create(&mut pubkey, &seckey).unwrap();

        s.sign(&mut sig, msg.as_slice(), &seckey, &nonce).unwrap();

        assert_eq!(s.verify(msg.as_slice(), sig.as_slice(), &pubkey), Ok(true));
    }

    #[test]
    fn sign_and_verify_fail() {
        let s = Secp256k1::new();

        let mut msg = Vec::from_elem(32, 0u8);
        let mut seckey = [0u8, ..32];
        let mut pubkey = Compressed([0u8, .. 33]);
        let mut nonce = [0u8, ..32];
        let mut sig = Vec::from_elem(72, 0u8);
        rand::task_rng().fill_bytes(msg.as_mut_slice());
        rand::task_rng().fill_bytes(nonce);
        rand::task_rng().fill_bytes(seckey);

        s.pubkey_create(&mut pubkey, &seckey).unwrap();
        s.sign(&mut sig, msg.as_slice(), &seckey, &nonce).unwrap();

        rand::task_rng().fill_bytes(msg.as_mut_slice());
        assert_eq!(s.verify(msg.as_slice(), sig.as_slice(), &pubkey), Ok(false));
    }

    #[test]
    fn sign_compact_with_recovery() {
        let s = Secp256k1::new();

        let mut msg = [0u8, ..32];
        let mut seckey = [0u8, ..32];
        let mut pubkey = Uncompressed([0u8, ..65]);
        let mut nonce = [0u8, ..32];
        let mut sig = Vec::from_elem(64, 0u8);
        rand::task_rng().fill_bytes(msg.as_mut_slice());
        rand::task_rng().fill_bytes(nonce);
        rand::task_rng().fill_bytes(seckey);

        s.pubkey_create(&mut pubkey, &seckey).unwrap();

        let recid = s.sign_compact(sig.as_mut_slice(), msg.as_slice(), &seckey, &nonce).unwrap();

        assert_eq!(s.recover_compact(msg.as_slice(), sig.as_slice(), &mut pubkey, recid), Ok(()));
    }
}
