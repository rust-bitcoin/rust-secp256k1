// Bitcoin secp256k1 bindings
// Written in 2014 by
//   Dawid Ciężarkiewicz
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

use std::io::{IoError, IoResult};
use std::rand::OsRng;
use libc::c_int;
use sync::one::{Once, ONCE_INIT};

pub mod constants;
pub mod ffi;
pub mod key;

/// A tag used for recovering the public key from a compact signature
pub struct RecoveryId(i32);

/// An ECDSA signature
pub struct Signature(uint, [u8, ..constants::MAX_SIGNATURE_SIZE]);

impl Signature {
    /// Converts the signature to a mutable raw pointer suitable for use
    /// with the FFI functions
    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        let &Signature(_, ref mut data) = self;
        data.as_mut_slice().as_mut_ptr()
    }

    /// Converts the signature to a byte slice suitable for verification
    #[inline]
    pub fn as_slice<'a>(&'a self) -> &'a [u8] {
        let &Signature(len, ref data) = self;
        data.slice_to(len)
    }

    /// Returns the length of the signature
    #[inline]
    pub fn len(&self) -> uint {
        let &Signature(len, _) = self;
        len
    }
}

/// An ECDSA error
#[deriving(PartialEq, Eq, Clone, Show)]
pub enum Error {
    /// Signature failed verification
    IncorrectSignature,
    /// Bad public key
    InvalidPublicKey,
    /// Bad signature
    InvalidSignature,
    /// Bad secret key
    InvalidSecretKey,
    /// Bad nonce
    InvalidNonce,
    /// Rng problem
    RngError(IoError),
}

/// Result type
pub type Result<T> = ::std::prelude::Result<T, Error>;

static mut Secp256k1_init : Once = ONCE_INIT;

/// The secp256k1 engine, used to execute all signature operations
pub struct Secp256k1 {
    rng: IoResult<OsRng>
}

/// Does one-time initialization of the secp256k1 engine. Can be called
/// multiple times, and is called by the `Secp256k1` constructor. This
/// only needs to be called directly if you are using the library without
/// a `Secp256k1` object, e.g. batch key generation through
/// `key::PublicKey::from_secret_key`.
pub fn init() {
    unsafe {
        Secp256k1_init.doit(|| {
            ffi::secp256k1_start();
        });
    }
}

impl Secp256k1 {
    /// Constructs a new secp256k1 engine.
    pub fn new() -> Secp256k1 {
        init();
        Secp256k1 { rng: OsRng::new() }
    }

    /// Generates a random keypair. Convenience function for `key::SecretKey::new`
    /// and `key::PublicKey::from_secret_key`; call those functions directly for
    /// batch key generation.
    pub fn generate_keypair(&mut self, compressed: bool)
                            -> Result<(key::SecretKey, key::PublicKey)> {
        match self.rng {
            Ok(ref mut rng) => {
                let sk = key::SecretKey::new(rng);
                Ok(unsafe { (sk, key::PublicKey::from_secret_key(&sk, compressed)) })
            }
            Err(ref e) => Err(RngError(e.clone()))
        }
    }

    /// Generates a random nonce. Convenience function for `key::Nonce::new`; call
    /// that function directly for batch nonce generation
    pub fn generate_nonce(&mut self) -> Result<key::Nonce> {
        match self.rng {
            Ok(ref mut rng) => Ok(key::Nonce::new(rng)),
            Err(ref e) => Err(RngError(e.clone()))
        }
    }

    /// Constructs a signature for `msg` using the secret key `sk` and nonce `nonce`
    pub fn sign(&self, msg: &[u8], sk: &key::SecretKey, nonce: &key::Nonce)
                -> Result<Signature> {
        let mut sig = [0, ..constants::MAX_SIGNATURE_SIZE];
        let mut len = constants::MAX_SIGNATURE_SIZE as c_int;
        unsafe {
            if ffi::secp256k1_ecdsa_sign(msg.as_ptr(), msg.len() as c_int,
                                         sig.as_mut_slice().as_mut_ptr(), &mut len,
                                         sk.as_ptr(), nonce.as_ptr()) != 1 {
                return Err(InvalidNonce);
            }
            // This assertation is probably too late :)
            assert!(len as uint <= constants::MAX_SIGNATURE_SIZE);
        };
        Ok(Signature(len as uint, sig))
    }

    /// Constructs a compact signature for `msg` using the secret key `sk`
    pub fn sign_compact(&self, msg: &[u8], sk: &key::SecretKey, nonce: &key::Nonce)
                        -> Result<(Signature, RecoveryId)> {
        let mut sig = [0, ..constants::MAX_SIGNATURE_SIZE];
        let mut recid = 0;
        unsafe {
            if ffi::secp256k1_ecdsa_sign_compact(msg.as_ptr(), msg.len() as c_int,
                                                 sig.as_mut_slice().as_mut_ptr(), sk.as_ptr(),
                                                 nonce.as_ptr(), &mut recid) != 1 {
                return Err(InvalidNonce);
            }
        };
        Ok((Signature(constants::MAX_COMPACT_SIGNATURE_SIZE, sig), RecoveryId(recid)))
    }

    /// Determines the public key for which `sig` is a valid signature for
    /// `msg`. Returns through the out-pointer `pubkey`.
    pub fn recover_compact(&self, msg: &[u8], sig: &[u8],
                           compressed: bool, recid: RecoveryId)
                            -> Result<key::PublicKey> {
        let mut pk = key::PublicKey::new(compressed);
        let RecoveryId(recid) = recid;

        unsafe {
            let mut len = 0;
            if ffi::secp256k1_ecdsa_recover_compact(msg.as_ptr(), msg.len() as c_int,
                                                    sig.as_ptr(), pk.as_mut_ptr(), &mut len,
                                                    if compressed {1} else {0},
                                                    recid) != 1 {
                return Err(InvalidSignature);
            }
            assert_eq!(len as uint, pk.len());
        };
        Ok(pk)
    }


    /// Checks that `sig` is a valid ECDSA signature for `msg` using the public
    /// key `pubkey`. Returns `Ok(true)` on success.
    pub fn verify(&self, msg: &[u8], sig: &[u8], pk: &key::PublicKey) -> Result<()> {
        let res = unsafe {
            ffi::secp256k1_ecdsa_verify(msg.as_ptr(), msg.len() as c_int,
                                        sig.as_ptr(), sig.len() as c_int,
                                        pk.as_ptr(), pk.len() as c_int)
        };

        match res {
            1 => Ok(()),
            0 => Err(IncorrectSignature),
            -1 => Err(InvalidPublicKey),
            -2 => Err(InvalidSignature),
            _ => unreachable!()
        }
    }
}


#[cfg(test)]
mod test {

    use std::rand;
    use std::rand::Rng;
    use super::*;
    use key::PublicKey;

    #[test]
    fn invalid_pubkey() {
        let s = Secp256k1::new();

        let mut msg = Vec::from_elem(32, 0u8);
        let sig = Vec::from_elem(32, 0u8);
        let pk = PublicKey::new(true);

        rand::task_rng().fill_bytes(msg.as_mut_slice());

        assert_eq!(s.verify(msg.as_mut_slice(), sig.as_slice(), &pk), Err(InvalidPublicKey));
    }

    #[test]
    fn valid_pubkey_uncompressed() {
        let mut s = Secp256k1::new();

        let (_, pk) = s.generate_keypair(false).unwrap();

        let mut msg = Vec::from_elem(32, 0u8);
        let sig = Vec::from_elem(32, 0u8);

        rand::task_rng().fill_bytes(msg.as_mut_slice());

        assert_eq!(s.verify(msg.as_mut_slice(), sig.as_slice(), &pk), Err(InvalidSignature));
    }

    #[test]
    fn valid_pubkey_compressed() {
        let mut s = Secp256k1::new();

        let (_, pk) = s.generate_keypair(true).unwrap();
        let mut msg = Vec::from_elem(32, 0u8);
        let sig = Vec::from_elem(32, 0u8);

        rand::task_rng().fill_bytes(msg.as_mut_slice());

        assert_eq!(s.verify(msg.as_mut_slice(), sig.as_slice(), &pk), Err(InvalidSignature));
    }

    #[test]
    fn sign() {
        let mut s = Secp256k1::new();

        let mut msg = [0u8, ..32];
        rand::task_rng().fill_bytes(msg);

        let (sk, _) = s.generate_keypair(false).unwrap();
        let nonce = s.generate_nonce().unwrap();

        s.sign(msg.as_slice(), &sk, &nonce).unwrap();
    }

    #[test]
    fn sign_and_verify() {
        let mut s = Secp256k1::new();

        let mut msg = Vec::from_elem(32, 0u8);
        rand::task_rng().fill_bytes(msg.as_mut_slice());

        let (sk, pk) = s.generate_keypair(false).unwrap();
        let nonce = s.generate_nonce().unwrap();

        let sig = s.sign(msg.as_slice(), &sk, &nonce).unwrap();

        assert_eq!(s.verify(msg.as_slice(), sig.as_slice(), &pk), Ok(()));
    }

    #[test]
    fn sign_and_verify_fail() {
        let mut s = Secp256k1::new();

        let mut msg = Vec::from_elem(32, 0u8);
        rand::task_rng().fill_bytes(msg.as_mut_slice());

        let (sk, pk) = s.generate_keypair(false).unwrap();
        let nonce = s.generate_nonce().unwrap();

        let sig = s.sign(msg.as_slice(), &sk, &nonce).unwrap();

        rand::task_rng().fill_bytes(msg.as_mut_slice());
        assert_eq!(s.verify(msg.as_slice(), sig.as_slice(), &pk), Err(IncorrectSignature));
    }

    #[test]
    fn sign_compact_with_recovery() {
        let mut s = Secp256k1::new();

        let mut msg = [0u8, ..32];
        rand::task_rng().fill_bytes(msg.as_mut_slice());

        let (sk, pk) = s.generate_keypair(false).unwrap();
        let nonce = s.generate_nonce().unwrap();

        let (sig, recid) = s.sign_compact(msg.as_slice(), &sk, &nonce).unwrap();

        assert_eq!(s.recover_compact(msg.as_slice(), sig.as_slice(), false, recid), Ok(pk));
    }
}
