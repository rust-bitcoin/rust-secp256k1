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

// Keep this until 1.0 I guess; it's needed for `black_box` at least
#![allow(unstable)]

// Coding conventions
#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
#![warn(missing_docs)]

extern crate crypto;

extern crate libc;
extern crate serialize;
extern crate test;

use std::intrinsics::copy_nonoverlapping;
use std::io;
use std::rand::{OsRng, Rng, SeedableRng};
use std::sync::{Once, ONCE_INIT};
use libc::c_int;

use crypto::fortuna::Fortuna;

#[macro_use]
mod macros;
pub mod constants;
pub mod ffi;
pub mod key;

/// I dunno where else to put this..
fn assert_type_is_copy<T: Copy>() { }

/// A tag used for recovering the public key from a compact signature
pub struct RecoveryId(i32);
impl Copy for RecoveryId {}

/// An ECDSA signature
pub struct Signature(usize, [u8; constants::MAX_SIGNATURE_SIZE]);
impl Copy for Signature {}

impl Signature {
    /// Converts the signature to a raw pointer suitable for use
    /// with the FFI functions
    #[inline]
    pub fn as_ptr(&self) -> *const u8 {
        let &Signature(_, ref data) = self;
        data.as_slice().as_ptr()
    }

    /// Converts the signature to a mutable raw pointer suitable for use
    /// with the FFI functions
    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        let &mut Signature(_, ref mut data) = self;
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
    pub fn len(&self) -> usize {
        let &Signature(len, _) = self;
        len
    }

    /// Converts a byte slice to a signature
    #[inline]
    pub fn from_slice(data: &[u8]) -> Result<Signature> {
        if data.len() <= constants::MAX_SIGNATURE_SIZE {
            let mut ret = [0; constants::MAX_SIGNATURE_SIZE];
            unsafe {
                copy_nonoverlapping(ret.as_mut_ptr(),
                                    data.as_ptr(),
                                    data.len());
            }
            Ok(Signature(data.len(), ret))
        } else {
            Err(Error::InvalidSignature)
        }
    }
}

/// An ECDSA error
#[derive(PartialEq, Eq, Clone, Debug)]
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
    /// Boolean-returning function returned the wrong boolean
    Unknown
}
impl Copy for Error {}

/// Result type
pub type Result<T> = ::std::result::Result<T, Error>;

static mut Secp256k1_init: Once = ONCE_INIT;

/// The secp256k1 engine, used to execute all signature operations
pub struct Secp256k1 {
    rng: Fortuna
}

/// Does one-time initialization of the secp256k1 engine. Can be called
/// multiple times, and is called by the `Secp256k1` constructor. This
/// only needs to be called directly if you are using the library without
/// a `Secp256k1` object, e.g. batch key generation through
/// `key::PublicKey::from_secret_key`.
pub fn init() {
    unsafe {
        Secp256k1_init.call_once(|| {
            ffi::secp256k1_start(ffi::SECP256K1_START_VERIFY |
                                 ffi::SECP256K1_START_SIGN);
        });
    }
}

impl Secp256k1 {
    /// Constructs a new secp256k1 engine.
    pub fn new() -> io::Result<Secp256k1> {
        init();
        let mut osrng = try!(OsRng::new());
        let mut seed = [0; 2048];
        osrng.fill_bytes(seed.as_mut_slice());
        Ok(Secp256k1 { rng: SeedableRng::from_seed(seed.as_slice()) })
    }

    /// Generates a random keypair. Convenience function for `key::SecretKey::new`
    /// and `key::PublicKey::from_secret_key`; call those functions directly for
    /// batch key generation.
    #[inline]
    pub fn generate_keypair(&mut self, compressed: bool)
                            -> (key::SecretKey, key::PublicKey) {
        let sk = key::SecretKey::new(&mut self.rng);
        let pk = key::PublicKey::from_secret_key(&sk, compressed);
        (sk, pk)
    }

    /// Generates a random nonce. Convenience function for `key::Nonce::new`; call
    /// that function directly for batch nonce generation
    #[inline]
    pub fn generate_nonce(&mut self) -> key::Nonce {
        key::Nonce::new(&mut self.rng)
    }

    /// Constructs a signature for `msg` using the secret key `sk` and nonce `nonce`
    pub fn sign(&self, msg: &[u8], sk: &key::SecretKey, nonce: &key::Nonce)
                -> Result<Signature> {
        let mut sig = [0; constants::MAX_SIGNATURE_SIZE];
        let mut len = constants::MAX_SIGNATURE_SIZE as c_int;
        unsafe {
            if ffi::secp256k1_ecdsa_sign(msg.as_ptr(), msg.len() as c_int,
                                         sig.as_mut_slice().as_mut_ptr(), &mut len,
                                         sk.as_ptr(), nonce.as_ptr()) != 1 {
                return Err(Error::InvalidNonce);
            }
            // This assertation is probably too late :)
            assert!(len as usize <= constants::MAX_SIGNATURE_SIZE);
        };
        Ok(Signature(len as usize, sig))
    }

    /// Constructs a compact signature for `msg` using the secret key `sk`
    pub fn sign_compact(&self, msg: &[u8], sk: &key::SecretKey, nonce: &key::Nonce)
                        -> Result<(Signature, RecoveryId)> {
        let mut sig = [0; constants::MAX_SIGNATURE_SIZE];
        let mut recid = 0;
        unsafe {
            if ffi::secp256k1_ecdsa_sign_compact(msg.as_ptr(), msg.len() as c_int,
                                                 sig.as_mut_slice().as_mut_ptr(), sk.as_ptr(),
                                                 nonce.as_ptr(), &mut recid) != 1 {
                return Err(Error::InvalidNonce);
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
                return Err(Error::InvalidSignature);
            }
            assert_eq!(len as usize, pk.len());
        };
        Ok(pk)
    }

    /// Checks that `sig` is a valid ECDSA signature for `msg` using the public
    /// key `pubkey`. Returns `Ok(true)` on success. Note that this function cannot
    /// be used for Bitcoin consensus checking since there are transactions out
    /// there with zero-padded signatures that don't fit in the `Signature` type.
    /// Use `verify_raw` instead.
    #[inline]
    pub fn verify(msg: &[u8], sig: &Signature, pk: &key::PublicKey) -> Result<()> {
        Secp256k1::verify_raw(msg, sig.as_slice(), pk)
    }

    /// Checks that `sig` is a valid ECDSA signature for `msg` using the public
    /// key `pubkey`. Returns `Ok(true)` on success.
    #[inline]
    pub fn verify_raw(msg: &[u8], sig: &[u8], pk: &key::PublicKey) -> Result<()> {
        init();  // This is a static function, so we have to init
        let res = unsafe {
            ffi::secp256k1_ecdsa_verify(msg.as_ptr(), msg.len() as c_int,
                                        sig.as_ptr(), sig.len() as c_int,
                                        pk.as_ptr(), pk.len() as c_int)
        };

        match res {
            1 => Ok(()),
            0 => Err(Error::IncorrectSignature),
            -1 => Err(Error::InvalidPublicKey),
            -2 => Err(Error::InvalidSignature),
            _ => unreachable!()
        }
    }
}


#[cfg(test)]
mod tests {
    use std::iter::repeat;
    use std::rand;
    use std::rand::Rng;

    use test::{Bencher, black_box};

    use key::{PublicKey, Nonce};
    use super::{Secp256k1, Signature};
    use super::Error::{InvalidPublicKey, IncorrectSignature, InvalidSignature};

    #[test]
    fn invalid_pubkey() {
        let mut msg: Vec<u8> = repeat(0).take(32).collect();
        let sig = Signature::from_slice(&[0; 72]).unwrap();
        let pk = PublicKey::new(true);

        rand::thread_rng().fill_bytes(msg.as_mut_slice());

        assert_eq!(Secp256k1::verify(msg.as_mut_slice(), &sig, &pk), Err(InvalidPublicKey));
    }

    #[test]
    fn valid_pubkey_uncompressed() {
        let mut s = Secp256k1::new().unwrap();

        let (_, pk) = s.generate_keypair(false);

        let mut msg: Vec<u8> = repeat(0).take(32).collect();
        let sig = Signature::from_slice(&[0; 72]).unwrap();

        rand::thread_rng().fill_bytes(msg.as_mut_slice());

        assert_eq!(Secp256k1::verify(msg.as_mut_slice(), &sig, &pk), Err(InvalidSignature));
    }

    #[test]
    fn valid_pubkey_compressed() {
        let mut s = Secp256k1::new().unwrap();

        let (_, pk) = s.generate_keypair(true);
        let mut msg: Vec<u8> = repeat(0).take(32).collect();
        let sig = Signature::from_slice(&[0; 72]).unwrap();

        rand::thread_rng().fill_bytes(msg.as_mut_slice());

        assert_eq!(Secp256k1::verify(msg.as_mut_slice(), &sig, &pk), Err(InvalidSignature));
    }

    #[test]
    fn sign() {
        let mut s = Secp256k1::new().unwrap();

        let mut msg = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut msg);

        let (sk, _) = s.generate_keypair(false);
        let nonce = s.generate_nonce();

        s.sign(msg.as_slice(), &sk, &nonce).unwrap();
    }

    #[test]
    fn sign_and_verify() {
        let mut s = Secp256k1::new().unwrap();

        let mut msg: Vec<u8> = repeat(0).take(32).collect();
        rand::thread_rng().fill_bytes(msg.as_mut_slice());

        let (sk, pk) = s.generate_keypair(false);
        let nonce = s.generate_nonce();

        let sig = s.sign(msg.as_slice(), &sk, &nonce).unwrap();

        assert_eq!(Secp256k1::verify(msg.as_slice(), &sig, &pk), Ok(()));
    }

    #[test]
    fn sign_and_verify_fail() {
        let mut s = Secp256k1::new().unwrap();

        let mut msg: Vec<u8> = repeat(0).take(32).collect();
        rand::thread_rng().fill_bytes(msg.as_mut_slice());

        let (sk, pk) = s.generate_keypair(false);
        let nonce = s.generate_nonce();

        let sig = s.sign(msg.as_slice(), &sk, &nonce).unwrap();

        rand::thread_rng().fill_bytes(msg.as_mut_slice());
        assert_eq!(Secp256k1::verify(msg.as_slice(), &sig, &pk), Err(IncorrectSignature));
    }

    #[test]
    fn sign_compact_with_recovery() {
        let mut s = Secp256k1::new().unwrap();

        let mut msg = [0u8; 32];
        rand::thread_rng().fill_bytes(msg.as_mut_slice());

        let (sk, pk) = s.generate_keypair(false);
        let nonce = s.generate_nonce();

        let (sig, recid) = s.sign_compact(msg.as_slice(), &sk, &nonce).unwrap();

        assert_eq!(s.recover_compact(msg.as_slice(), sig.as_slice(), false, recid), Ok(pk));
    }

    #[test]
    fn deterministic_sign() {
        let mut msg = [0u8; 32];
        rand::thread_rng().fill_bytes(msg.as_mut_slice());

        let mut s = Secp256k1::new().unwrap();
        let (sk, pk) = s.generate_keypair(true);
        let nonce = Nonce::deterministic(&mut msg, &sk);

        let sig = s.sign(msg.as_slice(), &sk, &nonce).unwrap();

        assert_eq!(Secp256k1::verify(msg.as_slice(), &sig, &pk), Ok(()));
    }

    #[bench]
    pub fn generate_compressed(bh: &mut Bencher) {
        let mut s = Secp256k1::new().unwrap();
        bh.iter( || {
          let (sk, pk) = s.generate_keypair(true);
          black_box(sk);
          black_box(pk);
        });
    }

    #[bench]
    pub fn generate_uncompressed(bh: &mut Bencher) {
        let mut s = Secp256k1::new().unwrap();
        bh.iter( || {
          let (sk, pk) = s.generate_keypair(false);
          black_box(sk);
          black_box(pk);
        });
    }
}
