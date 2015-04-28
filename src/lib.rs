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
#![crate_name = "secp256k1"]

// Keep this until 1.0 I guess; it's needed for `black_box` at least
#![cfg_attr(test, feature(test))]

// Coding conventions
#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
#![warn(missing_docs)]

extern crate rustc_serialize as serialize;
extern crate serde;
#[cfg(test)] extern crate test;

extern crate libc;
extern crate rand;

use std::intrinsics::copy_nonoverlapping;
use std::{cmp, fmt, ops, ptr};
use libc::c_int;
use rand::Rng;

#[macro_use]
mod macros;
pub mod constants;
pub mod ffi;
pub mod key;

/// A tag used for recovering the public key from a compact signature
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct RecoveryId(i32);

/// An ECDSA signature
#[derive(Copy)]
pub struct Signature(usize, [u8; constants::MAX_SIGNATURE_SIZE]);

impl Signature {
    /// Converts the signature to a raw pointer suitable for use
    /// with the FFI functions
    #[inline]
    pub fn as_ptr(&self) -> *const u8 {
        let &Signature(_, ref data) = self;
        data.as_ptr()
    }

    /// Converts the signature to a mutable raw pointer suitable for use
    /// with the FFI functions
    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        let &mut Signature(_, ref mut data) = self;
        data.as_mut_ptr()
    }

    /// Returns the length of the signature
    #[inline]
    pub fn len(&self) -> usize {
        let &Signature(len, _) = self;
        len
    }

    /// Converts a byte slice to a signature
    #[inline]
    pub fn from_slice(data: &[u8]) -> Result<Signature, Error> {
        if data.len() <= constants::MAX_SIGNATURE_SIZE {
            let mut ret = [0; constants::MAX_SIGNATURE_SIZE];
            unsafe {
                copy_nonoverlapping(data.as_ptr(),
                                    ret.as_mut_ptr(),
                                    data.len());
            }
            Ok(Signature(data.len(), ret))
        } else {
            Err(Error::InvalidSignature)
        }
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        try!(write!(f, "Signature("));
        for i in self[..].iter().cloned() {
            try!(write!(f, "{:02x}", i));
        }
        write!(f, ")")
    }
}

impl ops::Index<usize> for Signature {
    type Output = u8;

    #[inline]
    fn index(&self, index: usize) -> &u8 {
        assert!(index < self.0);
        &self.1[index]
    }
}

impl ops::Index<ops::Range<usize>> for Signature {
    type Output = [u8];

    #[inline]
    fn index(&self, index: ops::Range<usize>) -> &[u8] {
        assert!(index.end < self.0);
        &self.1[index]
    }
}

impl ops::Index<ops::RangeFrom<usize>> for Signature {
    type Output = [u8];

    #[inline]
    fn index(&self, index: ops::RangeFrom<usize>) -> &[u8] {
        &self.1[index.start..self.0]
    }
}

impl ops::Index<ops::RangeFull> for Signature {
    type Output = [u8];

    #[inline]
    fn index(&self, _: ops::RangeFull) -> &[u8] {
        &self.1[0..self.0]
    }
}

impl cmp::PartialEq for Signature {
    #[inline]
    fn eq(&self, other: &Signature) -> bool {
        &self[..] == &other[..]
    }
}
impl cmp::Eq for Signature { }

impl Clone for Signature {
    #[inline]
    fn clone(&self) -> Signature {
        unsafe {
            use std::mem;
            let mut ret: Signature = mem::uninitialized();
            copy_nonoverlapping(self.as_ptr(),
                                ret.as_mut_ptr(),
                                mem::size_of::<Signature>());
            ret
        }
    }
}

/// A (hashed) message input to an ECDSA signature
pub struct Message([u8; constants::MESSAGE_SIZE]);
impl_array_newtype!(Message, u8, constants::MESSAGE_SIZE);

impl Message {
    /// Converts a `MESSAGE_SIZE`-byte slice to a nonce
    #[inline]
    pub fn from_slice(data: &[u8]) -> Result<Message, Error> {
        match data.len() {
            constants::MESSAGE_SIZE => {
                let mut ret = [0; constants::MESSAGE_SIZE];
                unsafe {
                    copy_nonoverlapping(data.as_ptr(),
                                        ret.as_mut_ptr(),
                                        data.len());
                }
                Ok(Message(ret))
            }
            _ => Err(Error::InvalidMessage)
        }
    }
}

impl fmt::Debug for Message {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        try!(write!(f, "Message("));
        for i in self[..].iter().cloned() {
            try!(write!(f, "{:02x}", i));
        }
        write!(f, ")")
    }
}

/// An ECDSA error
#[derive(Copy, PartialEq, Eq, Clone, Debug)]
pub enum Error {
    /// A `Secp256k1` was used for an operation, but it was not created to
    /// support this (so necessary precomputations have not been done)
    IncapableContext,
    /// Signature failed verification
    IncorrectSignature,
    /// Badly sized message
    InvalidMessage,
    /// Bad public key
    InvalidPublicKey,
    /// Bad signature
    InvalidSignature,
    /// Bad secret key
    InvalidSecretKey,
    /// Boolean-returning function returned the wrong boolean
    Unknown
}

// Passthrough Debug to Display, since errors should be user-visible
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        fmt::Debug::fmt(self, f)
    }
}

/// The secp256k1 engine, used to execute all signature operations
pub struct Secp256k1 {
    ctx: ffi::Context,
    caps: ContextFlag
}

/// Flags used to determine the capabilities of a `Secp256k1` object;
/// the more capabilities, the more expensive it is to create.
#[derive(PartialEq, Eq, Copy, Clone, Debug)]
pub enum ContextFlag {
    /// Can neither sign nor verify signatures (cheapest to create, useful
    /// for cases not involving signatures, such as creating keys from slices)
    None,
    /// Can sign but not verify signatures
    SignOnly,
    /// Can verify but not create signatures
    VerifyOnly,
    /// Can verify and create signatures
    Full
}

// Passthrough Debug to Display, since caps should be user-visible
impl fmt::Display for ContextFlag {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        fmt::Debug::fmt(self, f)
    }
}

impl Clone for Secp256k1 {
    fn clone(&self) -> Secp256k1 {
        Secp256k1 {
            ctx: unsafe { ffi::secp256k1_context_clone(self.ctx) },
            caps: self.caps
        }
    }
}

impl PartialEq for Secp256k1 {
    fn eq(&self, other: &Secp256k1) -> bool { self.caps == other.caps }
}
impl Eq for Secp256k1 { }

impl fmt::Debug for Secp256k1 {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "Secp256k1 {{ [private], caps: {:?} }}", self.caps)
    }
}

impl Drop for Secp256k1 {
    fn drop(&mut self) {
        unsafe { ffi::secp256k1_context_destroy(self.ctx); }
    }
}

impl Secp256k1 {
    /// Creates a new Secp256k1 context
    #[inline]
    pub fn new() -> Secp256k1 {
        Secp256k1::with_caps(ContextFlag::Full)
    }

    /// Creates a new Secp256k1 context with the specified capabilities
    pub fn with_caps(caps: ContextFlag) -> Secp256k1 {
        let flag = match caps {
            ContextFlag::None => 0,
            ContextFlag::SignOnly => ffi::SECP256K1_START_SIGN,
            ContextFlag::VerifyOnly => ffi::SECP256K1_START_VERIFY,
            ContextFlag::Full => ffi::SECP256K1_START_SIGN | ffi::SECP256K1_START_VERIFY
        };
        Secp256k1 { ctx: unsafe { ffi::secp256k1_context_create(flag) }, caps: caps }
    }

    /// Generates a random keypair. Convenience function for `key::SecretKey::new`
    /// and `key::PublicKey::from_secret_key`; call those functions directly for
    /// batch key generation. Requires a signing-capable context.
    #[inline]
    pub fn generate_keypair<R: Rng>(&self, rng: &mut R, compressed: bool)
                                   -> Result<(key::SecretKey, key::PublicKey), Error> {
        if self.caps == ContextFlag::VerifyOnly || self.caps == ContextFlag::None {
            return Err(Error::IncapableContext);
        }

        let sk = key::SecretKey::new(self, rng);
        let pk = key::PublicKey::from_secret_key(self, &sk, compressed);
        Ok((sk, pk))
    }

    /// Constructs a signature for `msg` using the secret key `sk` and nonce `nonce`.
    /// Requires a signing-capable context.
    pub fn sign(&self, msg: &Message, sk: &key::SecretKey)
                -> Result<Signature, Error> {
        if self.caps == ContextFlag::VerifyOnly || self.caps == ContextFlag::None {
            return Err(Error::IncapableContext);
        }

        let mut sig = [0; constants::MAX_SIGNATURE_SIZE];
        let mut len = constants::MAX_SIGNATURE_SIZE as c_int;
        unsafe {
            // We can assume the return value because it's not possible to construct
            // an invalid signature from a valid `Message` and `SecretKey`
            assert_eq!(ffi::secp256k1_ecdsa_sign(self.ctx, msg.as_ptr(), sig.as_mut_ptr(),
                                                 &mut len, sk.as_ptr(),
                                                 ffi::secp256k1_nonce_function_rfc6979,
                                                 ptr::null()), 1);
            // This assertation is probably too late :)
            debug_assert!(len as usize <= constants::MAX_SIGNATURE_SIZE);
        }
        Ok(Signature(len as usize, sig))
    }

    /// Constructs a compact signature for `msg` using the secret key `sk`.
    /// Requires a signing-capable context.
    pub fn sign_compact(&self, msg: &Message, sk: &key::SecretKey)
                        -> Result<(Signature, RecoveryId), Error> {
        if self.caps == ContextFlag::VerifyOnly || self.caps == ContextFlag::None {
            return Err(Error::IncapableContext);
        }

        let mut sig = [0; constants::MAX_SIGNATURE_SIZE];
        let mut recid = 0;
        unsafe {
            // We can assume the return value because it's not possible to construct
            // an invalid signature from a valid `Message` and `SecretKey`
            assert_eq!(ffi::secp256k1_ecdsa_sign_compact(self.ctx, msg.as_ptr(),
                                                         sig.as_mut_ptr(), sk.as_ptr(),
                                                         ffi::secp256k1_nonce_function_default,
                                                         ptr::null(), &mut recid), 1);
        }
        Ok((Signature(constants::COMPACT_SIGNATURE_SIZE, sig), RecoveryId(recid)))
    }

    /// Determines the public key for which `sig` is a valid signature for
    /// `msg`. Returns through the out-pointer `pubkey`. Requires a verify-capable
    /// context.
    pub fn recover_compact(&self, msg: &Message, sig: &[u8],
                           compressed: bool, recid: RecoveryId)
                            -> Result<key::PublicKey, Error> {
        if self.caps == ContextFlag::SignOnly || self.caps == ContextFlag::None {
            return Err(Error::IncapableContext);
        }

        let mut pk = key::PublicKey::new(compressed);
        let RecoveryId(recid) = recid;

        if sig.len() != constants::COMPACT_SIGNATURE_SIZE {
            return Err(Error::InvalidSignature);
        }
        unsafe {
            let mut len = 0;
            if ffi::secp256k1_ecdsa_recover_compact(self.ctx, msg.as_ptr(),
                                                    sig.as_ptr(), pk.as_mut_ptr(), &mut len,
                                                    if compressed {1} else {0},
                                                    recid) != 1 {
                return Err(Error::InvalidSignature);
            }
            debug_assert_eq!(len as usize, pk.len());
        };
        Ok(pk)
    }

    /// Checks that `sig` is a valid ECDSA signature for `msg` using the public
    /// key `pubkey`. Returns `Ok(true)` on success. Note that this function cannot
    /// be used for Bitcoin consensus checking since there may exist signatures
    /// which OpenSSL would verify but not libsecp256k1, or vice-versa. Requires a
    /// verify-capable context.
    #[inline]
    pub fn verify(&self, msg: &Message, sig: &Signature, pk: &key::PublicKey) -> Result<(), Error> {
        self.verify_raw(msg, &sig[..], pk)
    }

    /// Verifies a signature described as a slice of bytes rather than opaque `Signature`.
    /// Requires a verify-capable context.
    pub fn verify_raw(&self, msg: &Message, sig: &[u8], pk: &key::PublicKey) -> Result<(), Error> {
        if self.caps == ContextFlag::SignOnly || self.caps == ContextFlag::None {
            return Err(Error::IncapableContext);
        }

        let res = unsafe {
            ffi::secp256k1_ecdsa_verify(self.ctx, msg.as_ptr(),
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
    use rand::{Rng, thread_rng};

    use test::{Bencher, black_box};

    use key::{SecretKey, PublicKey};
    use super::constants;
    use super::{Secp256k1, Signature, Message, RecoveryId, ContextFlag};
    use super::Error::{InvalidMessage, InvalidPublicKey, IncorrectSignature, InvalidSignature,
                       IncapableContext};

    #[test]
    fn capabilities() {
        let none = Secp256k1::with_caps(ContextFlag::None);
        let sign = Secp256k1::with_caps(ContextFlag::SignOnly);
        let vrfy = Secp256k1::with_caps(ContextFlag::VerifyOnly);
        let full = Secp256k1::with_caps(ContextFlag::Full);

        let mut msg = [0u8; 32];
        thread_rng().fill_bytes(&mut msg);
        let msg = Message::from_slice(&msg).unwrap();

        // Try key generation
        assert_eq!(none.generate_keypair(&mut thread_rng(), true), Err(IncapableContext));
        assert_eq!(none.generate_keypair(&mut thread_rng(), false), Err(IncapableContext));
        assert_eq!(vrfy.generate_keypair(&mut thread_rng(), true), Err(IncapableContext));
        assert_eq!(vrfy.generate_keypair(&mut thread_rng(), false), Err(IncapableContext));
        assert!(sign.generate_keypair(&mut thread_rng(), true).is_ok());
        assert!(sign.generate_keypair(&mut thread_rng(), false).is_ok());
        assert!(full.generate_keypair(&mut thread_rng(), true).is_ok());
        assert!(full.generate_keypair(&mut thread_rng(), false).is_ok());
        let (sk, pk) = full.generate_keypair(&mut thread_rng(), true).unwrap();

        // Try signing
        assert_eq!(none.sign(&msg, &sk), Err(IncapableContext));
        assert_eq!(vrfy.sign(&msg, &sk), Err(IncapableContext));
        assert!(sign.sign(&msg, &sk).is_ok());
        assert!(full.sign(&msg, &sk).is_ok());
        assert_eq!(sign.sign(&msg, &sk), full.sign(&msg, &sk));
        let sig = full.sign(&msg, &sk).unwrap();

        // Try verifying
        assert_eq!(none.verify(&msg, &sig, &pk), Err(IncapableContext));
        assert_eq!(sign.verify(&msg, &sig, &pk), Err(IncapableContext));
        assert!(vrfy.verify(&msg, &sig, &pk).is_ok());
        assert!(full.verify(&msg, &sig, &pk).is_ok());

        // Try compact signing
        assert_eq!(none.sign_compact(&msg, &sk), Err(IncapableContext));
        assert_eq!(vrfy.sign_compact(&msg, &sk), Err(IncapableContext));
        assert!(sign.sign_compact(&msg, &sk).is_ok());
        assert!(full.sign_compact(&msg, &sk).is_ok());
        let (csig, recid) = full.sign_compact(&msg, &sk).unwrap();

        // Try pk recovery
        assert_eq!(none.recover_compact(&msg, &csig[..], true, recid), Err(IncapableContext));
        assert_eq!(none.recover_compact(&msg, &csig[..], false, recid), Err(IncapableContext));
        assert_eq!(sign.recover_compact(&msg, &csig[..], true, recid), Err(IncapableContext));
        assert_eq!(sign.recover_compact(&msg, &csig[..], false, recid), Err(IncapableContext));
        assert!(vrfy.recover_compact(&msg, &csig[..], false, recid).is_ok());
        assert!(vrfy.recover_compact(&msg, &csig[..], true, recid).is_ok());
        assert!(full.recover_compact(&msg, &csig[..], false, recid).is_ok());
        assert!(full.recover_compact(&msg, &csig[..], true, recid).is_ok());

        assert_eq!(vrfy.recover_compact(&msg, &csig[..], false, recid),
                   full.recover_compact(&msg, &csig[..], false, recid));
        assert_eq!(vrfy.recover_compact(&msg, &csig[..], true, recid),
                   full.recover_compact(&msg, &csig[..], true, recid));

        assert_eq!(full.recover_compact(&msg, &csig[..], true, recid), Ok(pk));

        // Check that we can produce keys from slices with no precomputation
        let (pk_slice, sk_slice) = (&pk[..], &sk[..]);
        let new_pk = PublicKey::from_slice(&none, pk_slice).unwrap();
        let new_sk = SecretKey::from_slice(&none, sk_slice).unwrap();
        assert_eq!(sk, new_sk);
        assert_eq!(pk, new_pk);
    }

    #[test]
    fn recid_sanity_check() {
        let one = RecoveryId(1);
        assert_eq!(one, one.clone());
    }

    #[test]
    fn invalid_pubkey() {
        let s = Secp256k1::new();
        let sig = Signature::from_slice(&[0; 72]).unwrap();
        let pk = PublicKey::new(true);
        let mut msg = [0u8; 32];
        thread_rng().fill_bytes(&mut msg);
        let msg = Message::from_slice(&msg).unwrap();

        assert_eq!(s.verify(&msg, &sig, &pk), Err(InvalidPublicKey));
    }

    #[test]
    fn valid_pubkey_uncompressed() {
        let s = Secp256k1::new();

        let (_, pk) = s.generate_keypair(&mut thread_rng(), false).unwrap();

        let sig = Signature::from_slice(&[0; 72]).unwrap();
        let mut msg = [0u8; 32];
        thread_rng().fill_bytes(&mut msg);
        let msg = Message::from_slice(&msg).unwrap();

        assert_eq!(s.verify(&msg, &sig, &pk), Err(InvalidSignature));
    }

    #[test]
    fn valid_pubkey_compressed() {
        let s = Secp256k1::new();

        let (_, pk) = s.generate_keypair(&mut thread_rng(), true).unwrap();
        let sig = Signature::from_slice(&[0; 72]).unwrap();
        let mut msg = [0u8; 32];
        thread_rng().fill_bytes(&mut msg);
        let msg = Message::from_slice(&msg).unwrap();

        assert_eq!(s.verify(&msg, &sig, &pk), Err(InvalidSignature));
    }

    #[test]
    fn sign() {
        let s = Secp256k1::new();
        let one = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

        let sk = SecretKey::from_slice(&s, &one).unwrap();
        let msg = Message::from_slice(&one).unwrap();

        let sig = s.sign(&msg, &sk).unwrap();
        assert_eq!(sig, Signature(70, [
            0x30, 0x44, 0x02, 0x20, 0x66, 0x73, 0xff, 0xad,
            0x21, 0x47, 0x74, 0x1f, 0x04, 0x77, 0x2b, 0x6f,
            0x92, 0x1f, 0x0b, 0xa6, 0xaf, 0x0c, 0x1e, 0x77,
            0xfc, 0x43, 0x9e, 0x65, 0xc3, 0x6d, 0xed, 0xf4,
            0x09, 0x2e, 0x88, 0x98, 0x02, 0x20, 0x4c, 0x1a,
            0x97, 0x16, 0x52, 0xe0, 0xad, 0xa8, 0x80, 0x12,
            0x0e, 0xf8, 0x02, 0x5e, 0x70, 0x9f, 0xff, 0x20,
            0x80, 0xc4, 0xa3, 0x9a, 0xae, 0x06, 0x8d, 0x12,
            0xee, 0xd0, 0x09, 0xb6, 0x8c, 0x89, 0x00, 0x00]))
    }

    #[test]
    fn sign_and_verify() {
        let s = Secp256k1::new();

        let mut msg = [0; 32];
        for _ in 0..100 {
            thread_rng().fill_bytes(&mut msg);
            let msg = Message::from_slice(&msg).unwrap();

            let (sk, pk) = s.generate_keypair(&mut thread_rng(), false).unwrap();
            let sig = s.sign(&msg, &sk).unwrap();
            assert_eq!(s.verify(&msg, &sig, &pk), Ok(()));
         }
    }

    #[test]
    fn sign_and_verify_extreme() {
        let s = Secp256k1::new();

        // Wild keys: 1, CURVE_ORDER - 1
        // Wild msgs: 0, 1, CURVE_ORDER - 1, CURVE_ORDER
        let mut wild_keys = [[0; 32]; 2];
        let mut wild_msgs = [[0; 32]; 4];

        wild_keys[0][0] = 1;
        wild_msgs[1][0] = 1;
        unsafe {
            use constants;
            use std::intrinsics::copy_nonoverlapping;
            copy_nonoverlapping(constants::CURVE_ORDER.as_ptr(),
                                wild_keys[1].as_mut_ptr(),
                                32);
            copy_nonoverlapping(constants::CURVE_ORDER.as_ptr(),
                                wild_msgs[1].as_mut_ptr(),
                                32);
            copy_nonoverlapping(constants::CURVE_ORDER.as_ptr(),
                                wild_msgs[2].as_mut_ptr(),
                                32);
            wild_keys[1][0] -= 1;
            wild_msgs[1][0] -= 1;
        }

        for key in wild_keys.iter().map(|k| SecretKey::from_slice(&s, &k[..]).unwrap()) {
            for msg in wild_msgs.iter().map(|m| Message::from_slice(&m[..]).unwrap()) {
                let sig = s.sign(&msg, &key).unwrap();
                let pk = PublicKey::from_secret_key(&s, &key, true);
                assert_eq!(s.verify(&msg, &sig, &pk), Ok(()));
            }
        }
    }

    #[test]
    fn sign_and_verify_fail() {
        let s = Secp256k1::new();

        let mut msg = [0u8; 32];
        thread_rng().fill_bytes(&mut msg);
        let msg = Message::from_slice(&msg).unwrap();

        let (sk, pk) = s.generate_keypair(&mut thread_rng(), false).unwrap();

        let sig = s.sign(&msg, &sk).unwrap();
        let (sig_compact, recid) = s.sign_compact(&msg, &sk).unwrap();

        let mut msg = [0u8; 32];
        thread_rng().fill_bytes(&mut msg);
        let msg = Message::from_slice(&msg).unwrap();
        assert_eq!(s.verify(&msg, &sig, &pk), Err(IncorrectSignature));

        let recovered_key = s.recover_compact(&msg, &sig_compact[..], false, recid).unwrap();
        assert!(recovered_key != pk);
    }

    #[test]
    fn sign_compact_with_recovery() {
        let s = Secp256k1::new();

        let mut msg = [0u8; 32];
        thread_rng().fill_bytes(&mut msg);
        let msg = Message::from_slice(&msg).unwrap();

        let (sk, pk) = s.generate_keypair(&mut thread_rng(), false).unwrap();

        let (sig, recid) = s.sign_compact(&msg, &sk).unwrap();

        assert_eq!(s.recover_compact(&msg, &sig[..], false, recid), Ok(pk));
    }

    #[test]
    fn bad_recovery() {
        let s = Secp256k1::new();

        let msg = Message::from_slice(&[0x55; 32]).unwrap();

        // Bad length
        assert_eq!(s.recover_compact(&msg, &[1; 63], false, RecoveryId(0)), Err(InvalidSignature));
        assert_eq!(s.recover_compact(&msg, &[1; 65], false, RecoveryId(0)), Err(InvalidSignature));
        // Zero is not a valid sig
        assert_eq!(s.recover_compact(&msg, &[0; 64], false, RecoveryId(0)), Err(InvalidSignature));
        // ...but 111..111 is
        assert!(s.recover_compact(&msg, &[1; 64], false, RecoveryId(0)).is_ok());
    }

    #[test]
    fn test_bad_slice() {
        assert_eq!(Signature::from_slice(&[0; constants::MAX_SIGNATURE_SIZE + 1]),
                   Err(InvalidSignature));
        assert!(Signature::from_slice(&[0; constants::MAX_SIGNATURE_SIZE]).is_ok());

        assert_eq!(Message::from_slice(&[0; constants::MESSAGE_SIZE - 1]),
                   Err(InvalidMessage));
        assert_eq!(Message::from_slice(&[0; constants::MESSAGE_SIZE + 1]),
                   Err(InvalidMessage));
        assert!(Signature::from_slice(&[0; constants::MESSAGE_SIZE]).is_ok());
    }

    #[test]
    fn test_debug_output() {
        let sig = Signature(0, [4; 72]);
        assert_eq!(&format!("{:?}", sig), "Signature()");
        let sig = Signature(10, [5; 72]);
        assert_eq!(&format!("{:?}", sig), "Signature(05050505050505050505)");
        let sig = Signature(72, [6; 72]);
        assert_eq!(&format!("{:?}", sig), "Signature(060606060606060606060606060606060606060606060606060606060606060606060606060606060606060606060606060606060606060606060606060606060606060606060606)");

        let msg = Message([1, 2, 3, 4, 5, 6, 7, 8,
                           9, 10, 11, 12, 13, 14, 15, 16,
                           17, 18, 19, 20, 21, 22, 23, 24,
                           25, 26, 27, 28, 29, 30, 31, 255]);
        assert_eq!(&format!("{:?}", msg), "Message(0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1fff)");
    }

    #[bench]
    pub fn generate_compressed(bh: &mut Bencher) {
        struct CounterRng(u32);
        impl Rng for CounterRng {
            fn next_u32(&mut self) -> u32 { self.0 += 1; self.0 }
        }

        let s = Secp256k1::new();
        let mut r = CounterRng(0);
        bh.iter( || {
          let (sk, pk) = s.generate_keypair(&mut r, true).unwrap();
          black_box(sk);
          black_box(pk);
        });
    }

    #[bench]
    pub fn generate_uncompressed(bh: &mut Bencher) {
        struct CounterRng(u32);
        impl Rng for CounterRng {
            fn next_u32(&mut self) -> u32 { self.0 += 1; self.0 }
        }

        let s = Secp256k1::new();
        let mut r = CounterRng(0);
        bh.iter( || {
          let (sk, pk) = s.generate_keypair(&mut r, false).unwrap();
          black_box(sk);
          black_box(pk);
        });
    }
}
