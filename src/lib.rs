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

// Coding conventions
#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
#![warn(missing_docs)]

#![cfg_attr(all(test, feature = "unstable"), feature(test))]
#[cfg(all(test, feature = "unstable"))] extern crate test;

extern crate arrayvec;
extern crate rustc_serialize as serialize;
extern crate serde;
extern crate serde_json as json;

extern crate libc;
extern crate rand;

use std::intrinsics::copy_nonoverlapping;
use std::{fmt, ops, ptr};
use rand::Rng;

#[macro_use]
mod macros;
pub mod constants;
pub mod ecdh;
pub mod ffi;
pub mod key;

/// A tag used for recovering the public key from a compact signature
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct RecoveryId(i32);

/// An ECDSA signature
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Signature(ffi::Signature);

/// An ECDSA signature with a recovery ID for pubkey recovery
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct RecoverableSignature(ffi::RecoverableSignature);

impl Signature {
    #[inline]
    /// Converts a DER-encoded byte slice to a signature
    pub fn from_der(secp: &Secp256k1, data: &[u8]) -> Result<Signature, Error> {
        let mut ret = unsafe { ffi::Signature::blank() };

        unsafe {
            if ffi::secp256k1_ecdsa_signature_parse_der(secp.ctx, &mut ret,
                                                        data.as_ptr(), data.len() as libc::size_t) == 1 {
                Ok(Signature(ret))
            } else {
                Err(Error::InvalidSignature)
            }
        }
    }

    /// Creates a new public key from a FFI public key
    #[inline]
    pub fn from_ffi(sig: ffi::Signature) -> Signature {
        Signature(sig)
    }

    /// Obtains a raw pointer suitable for use with FFI functions
    #[inline]
    pub fn as_ptr(&self) -> *const ffi::Signature {
        &self.0 as *const _
    }
}

impl RecoverableSignature {
    #[inline]
    /// Converts a compact-encoded byte slice to a signature. This
    /// representation is nonstandard and defined by the libsecp256k1
    /// library.
    pub fn from_compact(secp: &Secp256k1, data: &[u8], recid: RecoveryId) -> Result<RecoverableSignature, Error> {
        let mut ret = unsafe { ffi::RecoverableSignature::blank() };

        unsafe {
            if data.len() != 64 {
                Err(Error::InvalidSignature)
            } else if ffi::secp256k1_ecdsa_recoverable_signature_parse_compact(secp.ctx, &mut ret,
                                                                               data.as_ptr(), recid.0) == 1 {
                Ok(RecoverableSignature(ret))
            } else {
                Err(Error::InvalidSignature)
            }
        }
    }

    /// Creates a new public key from a FFI public key
    #[inline]
    pub fn from_ffi(sig: ffi::RecoverableSignature) -> RecoverableSignature {
        RecoverableSignature(sig)
    }

    /// Obtains a raw pointer suitable for use with FFI functions
    #[inline]
    pub fn as_ptr(&self) -> *const ffi::RecoverableSignature {
        &self.0 as *const _
    }

    /// Converts a recoverable signature to a non-recoverable one (this is needed
    /// for verification
    #[inline]
    pub fn to_standard(&self, secp: &Secp256k1) -> Signature {
        let mut ret = unsafe { ffi::Signature::blank() };
        unsafe {
            let err = ffi::secp256k1_ecdsa_recoverable_signature_convert(secp.ctx, &mut ret, self.as_ptr());
            assert!(err == 1);
        }
        Signature(ret)
    }
}

impl ops::Index<usize> for Signature {
    type Output = u8;

    #[inline]
    fn index(&self, index: usize) -> &u8 {
        &self.0[index]
    }
}

impl ops::Index<ops::Range<usize>> for Signature {
    type Output = [u8];

    #[inline]
    fn index(&self, index: ops::Range<usize>) -> &[u8] {
        &self.0[index]
    }
}

impl ops::Index<ops::RangeFrom<usize>> for Signature {
    type Output = [u8];

    #[inline]
    fn index(&self, index: ops::RangeFrom<usize>) -> &[u8] {
        &self.0[index.start..]
    }
}

impl ops::Index<ops::RangeFull> for Signature {
    type Output = [u8];

    #[inline]
    fn index(&self, _: ops::RangeFull) -> &[u8] {
        &self.0[..]
    }
}

/// A (hashed) message input to an ECDSA signature
pub struct Message([u8; constants::MESSAGE_SIZE]);
impl_array_newtype!(Message, u8, constants::MESSAGE_SIZE);
impl_pretty_debug!(Message);

impl Message {
    /// Converts a `MESSAGE_SIZE`-byte slice to a message object
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

    /// (Re)randomizes the Secp256k1 context for cheap sidechannel resistence;
    /// see comment in libsecp256k1 commit d2275795f by Gregory Maxwell
    pub fn randomize<R: Rng>(&mut self, rng: &mut R) {
        let mut seed = [0; 32];
        rng.fill_bytes(&mut seed);
        unsafe {
            let err = ffi::secp256k1_context_randomize(self.ctx, seed.as_ptr());
            // This function cannot fail; it has an error return for future-proofing.
            // We do not expose this error since it is impossible to hit, and we have
            // precedent for not exposing impossible errors (for example in
            // `PublicKey::from_secret_key` where it is impossble to create an invalid
            // secret key through the API.)
            // However, if this DOES fail, the result is potentially weaker side-channel
            // resistance, which is deadly and undetectable, so we take out the entire
            // thread to be on the safe side.
            assert!(err == 1);
        }
    }

    /// Generates a random keypair. Convenience function for `key::SecretKey::new`
    /// and `key::PublicKey::from_secret_key`; call those functions directly for
    /// batch key generation. Requires a signing-capable context.
    #[inline]
    pub fn generate_keypair<R: Rng>(&self, rng: &mut R)
                                   -> Result<(key::SecretKey, key::PublicKey), Error> {
        if self.caps == ContextFlag::VerifyOnly || self.caps == ContextFlag::None {
            return Err(Error::IncapableContext);
        }

        let sk = key::SecretKey::new(self, rng);
        let pk = key::PublicKey::from_secret_key(self, &sk);
        Ok((sk, pk))
    }

    /// Constructs a signature for `msg` using the secret key `sk` and nonce `nonce`.
    /// Requires a signing-capable context.
    pub fn sign(&self, msg: &Message, sk: &key::SecretKey)
                -> Result<Signature, Error> {
        if self.caps == ContextFlag::VerifyOnly || self.caps == ContextFlag::None {
            return Err(Error::IncapableContext);
        }

        let mut ret = unsafe { ffi::Signature::blank() };
        unsafe {
            // We can assume the return value because it's not possible to construct
            // an invalid signature from a valid `Message` and `SecretKey`
            assert_eq!(ffi::secp256k1_ecdsa_sign(self.ctx, &mut ret, msg.as_ptr(),
                                                 sk.as_ptr(), ffi::secp256k1_nonce_function_rfc6979,
                                                 ptr::null()), 1);
        }
        Ok(Signature::from_ffi(ret))
    }

    /// Constructs a signature for `msg` using the secret key `sk` and nonce `nonce`.
    /// Requires a signing-capable context.
    pub fn sign_recoverable(&self, msg: &Message, sk: &key::SecretKey)
                -> Result<RecoverableSignature, Error> {
        if self.caps == ContextFlag::VerifyOnly || self.caps == ContextFlag::None {
            return Err(Error::IncapableContext);
        }

        let mut ret = unsafe { ffi::RecoverableSignature::blank() };
        unsafe {
            // We can assume the return value because it's not possible to construct
            // an invalid signature from a valid `Message` and `SecretKey`
            assert_eq!(ffi::secp256k1_ecdsa_sign_recoverable(self.ctx, &mut ret, msg.as_ptr(),
                                                             sk.as_ptr(), ffi::secp256k1_nonce_function_rfc6979,
                                                             ptr::null()), 1);
        }
        Ok(RecoverableSignature::from_ffi(ret))
    }

    /// Determines the public key for which `sig` is a valid signature for
    /// `msg`. Returns through the out-pointer `pubkey`. Requires a verify-capable
    /// context.
    pub fn recover(&self, msg: &Message, sig: &RecoverableSignature)
                  -> Result<key::PublicKey, Error> {
        if self.caps == ContextFlag::SignOnly || self.caps == ContextFlag::None {
            return Err(Error::IncapableContext);
        }

        let mut pk = unsafe { ffi::PublicKey::blank() };

        unsafe {
            if ffi::secp256k1_ecdsa_recover(self.ctx, &mut pk,
                                            sig.as_ptr(), msg.as_ptr()) != 1 {
                return Err(Error::InvalidSignature);
            }
        };
        Ok(key::PublicKey::from_ffi(pk))
    }

    /// Checks that `sig` is a valid ECDSA signature for `msg` using the public
    /// key `pubkey`. Returns `Ok(true)` on success. Note that this function cannot
    /// be used for Bitcoin consensus checking since there may exist signatures
    /// which OpenSSL would verify but not libsecp256k1, or vice-versa. Requires a
    /// verify-capable context.
    #[inline]
    pub fn verify(&self, msg: &Message, sig: &Signature, pk: &key::PublicKey) -> Result<(), Error> {
        if self.caps == ContextFlag::SignOnly || self.caps == ContextFlag::None {
            return Err(Error::IncapableContext);
        }

        if !pk.is_valid() {
            Err(Error::InvalidPublicKey)
        } else if unsafe { ffi::secp256k1_ecdsa_verify(self.ctx, sig.as_ptr(), msg.as_ptr(),
                                                       pk.as_ptr()) } == 0 {
            Err(Error::IncorrectSignature)
        } else {
            Ok(())
        }
    }
}


#[cfg(test)]
mod tests {
    use rand::{Rng, thread_rng};

    use key::{SecretKey, PublicKey};
    use super::constants;
    use super::{Secp256k1, Signature, RecoverableSignature, Message, RecoveryId, ContextFlag};
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
        assert_eq!(none.generate_keypair(&mut thread_rng()), Err(IncapableContext));
        assert_eq!(vrfy.generate_keypair(&mut thread_rng()), Err(IncapableContext));
        assert!(sign.generate_keypair(&mut thread_rng()).is_ok());
        assert!(full.generate_keypair(&mut thread_rng()).is_ok());
        let (sk, pk) = full.generate_keypair(&mut thread_rng()).unwrap();

        // Try signing
        assert_eq!(none.sign(&msg, &sk), Err(IncapableContext));
        assert_eq!(vrfy.sign(&msg, &sk), Err(IncapableContext));
        assert!(sign.sign(&msg, &sk).is_ok());
        assert!(full.sign(&msg, &sk).is_ok());
        assert_eq!(none.sign_recoverable(&msg, &sk), Err(IncapableContext));
        assert_eq!(vrfy.sign_recoverable(&msg, &sk), Err(IncapableContext));
        assert!(sign.sign_recoverable(&msg, &sk).is_ok());
        assert!(full.sign_recoverable(&msg, &sk).is_ok());
        assert_eq!(sign.sign(&msg, &sk), full.sign(&msg, &sk));
        assert_eq!(sign.sign_recoverable(&msg, &sk), full.sign_recoverable(&msg, &sk));
        let sig = full.sign(&msg, &sk).unwrap();
        let sigr = full.sign_recoverable(&msg, &sk).unwrap();

        // Try verifying
        assert_eq!(none.verify(&msg, &sig, &pk), Err(IncapableContext));
        assert_eq!(sign.verify(&msg, &sig, &pk), Err(IncapableContext));
        assert!(vrfy.verify(&msg, &sig, &pk).is_ok());
        assert!(full.verify(&msg, &sig, &pk).is_ok());

        // Try pk recovery
        assert_eq!(none.recover(&msg, &sigr), Err(IncapableContext));
        assert_eq!(none.recover(&msg, &sigr), Err(IncapableContext));
        assert_eq!(sign.recover(&msg, &sigr), Err(IncapableContext));
        assert_eq!(sign.recover(&msg, &sigr), Err(IncapableContext));
        assert!(vrfy.recover(&msg, &sigr).is_ok());
        assert!(vrfy.recover(&msg, &sigr).is_ok());
        assert!(full.recover(&msg, &sigr).is_ok());
        assert!(full.recover(&msg, &sigr).is_ok());

        assert_eq!(vrfy.recover(&msg, &sigr),
                   full.recover(&msg, &sigr));
        assert_eq!(full.recover(&msg, &sigr), Ok(pk));

        // Check that we can produce keys from slices with no precomputation
        let (pk_slice, sk_slice) = (&pk.serialize_vec(&none, true), &sk[..]);
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
        let sig = RecoverableSignature::from_compact(&s, &[1; 64], RecoveryId(0)).unwrap();
        let pk = PublicKey::new();
        let mut msg = [0u8; 32];
        thread_rng().fill_bytes(&mut msg);
        let msg = Message::from_slice(&msg).unwrap();

        assert_eq!(s.verify(&msg, &sig.to_standard(&s), &pk), Err(InvalidPublicKey));
    }

    #[test]
    fn sign() {
        let mut s = Secp256k1::new();
        s.randomize(&mut thread_rng());
        let one = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

        let sk = SecretKey::from_slice(&s, &one).unwrap();
        let msg = Message::from_slice(&one).unwrap();

        let sig = s.sign_recoverable(&msg, &sk).unwrap();
        assert_eq!(Ok(sig), RecoverableSignature::from_compact(&s, &[
            0x66, 0x73, 0xff, 0xad, 0x21, 0x47, 0x74, 0x1f,
            0x04, 0x77, 0x2b, 0x6f, 0x92, 0x1f, 0x0b, 0xa6,
            0xaf, 0x0c, 0x1e, 0x77, 0xfc, 0x43, 0x9e, 0x65,
            0xc3, 0x6d, 0xed, 0xf4, 0x09, 0x2e, 0x88, 0x98,
            0x4c, 0x1a, 0x97, 0x16, 0x52, 0xe0, 0xad, 0xa8,
            0x80, 0x12, 0x0e, 0xf8, 0x02, 0x5e, 0x70, 0x9f,
            0xff, 0x20, 0x80, 0xc4, 0xa3, 0x9a, 0xae, 0x06,
            0x8d, 0x12, 0xee, 0xd0, 0x09, 0xb6, 0x8c, 0x89],
            RecoveryId(1)))
    }

    #[test]
    fn sign_and_verify() {
        let mut s = Secp256k1::new();
        s.randomize(&mut thread_rng());

        let mut msg = [0; 32];
        for _ in 0..100 {
            thread_rng().fill_bytes(&mut msg);
            let msg = Message::from_slice(&msg).unwrap();

            let (sk, pk) = s.generate_keypair(&mut thread_rng()).unwrap();
            let sig = s.sign(&msg, &sk).unwrap();
            assert_eq!(s.verify(&msg, &sig, &pk), Ok(()));
         }
    }

    #[test]
    fn sign_and_verify_extreme() {
        let mut s = Secp256k1::new();
        s.randomize(&mut thread_rng());

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
                let pk = PublicKey::from_secret_key(&s, &key);
                assert_eq!(s.verify(&msg, &sig, &pk), Ok(()));
            }
        }
    }

    #[test]
    fn sign_and_verify_fail() {
        let mut s = Secp256k1::new();
        s.randomize(&mut thread_rng());

        let mut msg = [0u8; 32];
        thread_rng().fill_bytes(&mut msg);
        let msg = Message::from_slice(&msg).unwrap();

        let (sk, pk) = s.generate_keypair(&mut thread_rng()).unwrap();

        let sigr = s.sign_recoverable(&msg, &sk).unwrap();
        let sig = sigr.to_standard(&s);

        let mut msg = [0u8; 32];
        thread_rng().fill_bytes(&mut msg);
        let msg = Message::from_slice(&msg).unwrap();
        assert_eq!(s.verify(&msg, &sig, &pk), Err(IncorrectSignature));

        let recovered_key = s.recover(&msg, &sigr).unwrap();
        assert!(recovered_key != pk);
    }

    #[test]
    fn sign_with_recovery() {
        let mut s = Secp256k1::new();
        s.randomize(&mut thread_rng());

        let mut msg = [0u8; 32];
        thread_rng().fill_bytes(&mut msg);
        let msg = Message::from_slice(&msg).unwrap();

        let (sk, pk) = s.generate_keypair(&mut thread_rng()).unwrap();

        let sig = s.sign_recoverable(&msg, &sk).unwrap();

        assert_eq!(s.recover(&msg, &sig), Ok(pk));
    }

    #[test]
    fn bad_recovery() {
        let mut s = Secp256k1::new();
        s.randomize(&mut thread_rng());

        let msg = Message::from_slice(&[0x55; 32]).unwrap();

        // Zero is not a valid sig
        let sig = RecoverableSignature::from_compact(&s, &[0; 64], RecoveryId(0)).unwrap();
        assert_eq!(s.recover(&msg, &sig), Err(InvalidSignature));
        // ...but 111..111 is
        let sig = RecoverableSignature::from_compact(&s, &[1; 64], RecoveryId(0)).unwrap();
        assert!(s.recover(&msg, &sig).is_ok());
    }

    #[test]
    fn test_bad_slice() {
        let s = Secp256k1::new();
        assert_eq!(Signature::from_der(&s, &[0; constants::MAX_SIGNATURE_SIZE + 1]),
                   Err(InvalidSignature));
        assert_eq!(Signature::from_der(&s, &[0; constants::MAX_SIGNATURE_SIZE]),
                   Err(InvalidSignature));

        assert_eq!(Message::from_slice(&[0; constants::MESSAGE_SIZE - 1]),
                   Err(InvalidMessage));
        assert_eq!(Message::from_slice(&[0; constants::MESSAGE_SIZE + 1]),
                   Err(InvalidMessage));
        assert!(Message::from_slice(&[0; constants::MESSAGE_SIZE]).is_ok());
    }

    #[test]
    fn test_debug_output() {
        let s = Secp256k1::new();
        let sig = RecoverableSignature::from_compact(&s, &[
            0x66, 0x73, 0xff, 0xad, 0x21, 0x47, 0x74, 0x1f,
            0x04, 0x77, 0x2b, 0x6f, 0x92, 0x1f, 0x0b, 0xa6,
            0xaf, 0x0c, 0x1e, 0x77, 0xfc, 0x43, 0x9e, 0x65,
            0xc3, 0x6d, 0xed, 0xf4, 0x09, 0x2e, 0x88, 0x98,
            0x4c, 0x1a, 0x97, 0x16, 0x52, 0xe0, 0xad, 0xa8,
            0x80, 0x12, 0x0e, 0xf8, 0x02, 0x5e, 0x70, 0x9f,
            0xff, 0x20, 0x80, 0xc4, 0xa3, 0x9a, 0xae, 0x06,
            0x8d, 0x12, 0xee, 0xd0, 0x09, 0xb6, 0x8c, 0x89],
            RecoveryId(1)).unwrap();
        assert_eq!(&format!("{:?}", sig), "RecoverableSignature(98882e09f4ed6dc3659e43fc771e0cafa60b1f926f2b77041f744721adff7366898cb609d0ee128d06ae9aa3c48020ff9f705e02f80e1280a8ade05216971a4c01)");

        let msg = Message([1, 2, 3, 4, 5, 6, 7, 8,
                           9, 10, 11, 12, 13, 14, 15, 16,
                           17, 18, 19, 20, 21, 22, 23, 24,
                           25, 26, 27, 28, 29, 30, 31, 255]);
        assert_eq!(&format!("{:?}", msg), "Message(0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1fff)");
    }
}

#[cfg(all(test, feature = "unstable"))]
mod benches {
    use rand::{Rng, thread_rng};
    use test::{Bencher, black_box};

    use super::{Secp256k1, Message};

    #[bench]
    pub fn generate(bh: &mut Bencher) {
        struct CounterRng(u32);
        impl Rng for CounterRng {
            fn next_u32(&mut self) -> u32 { self.0 += 1; self.0 }
        }

        let s = Secp256k1::new();
        let mut r = CounterRng(0);
        bh.iter( || {
            let (sk, pk) = s.generate_keypair(&mut r).unwrap();
            black_box(sk);
            black_box(pk);
        });
    }

    #[bench]
    pub fn bench_sign(bh: &mut Bencher) {
        let s = Secp256k1::new();
        let mut msg = [0u8; 32];
        thread_rng().fill_bytes(&mut msg);
        let msg = Message::from_slice(&msg).unwrap();
        let (sk, _) = s.generate_keypair(&mut thread_rng()).unwrap();

        bh.iter(|| {
            let sig = s.sign(&msg, &sk).unwrap();
            black_box(sig);
        });
    }

    #[bench]
    pub fn bench_verify(bh: &mut Bencher) {
        let s = Secp256k1::new();
        let mut msg = [0u8; 32];
        thread_rng().fill_bytes(&mut msg);
        let msg = Message::from_slice(&msg).unwrap();
        let (sk, pk) = s.generate_keypair(&mut thread_rng()).unwrap();
        let sig = s.sign(&msg, &sk).unwrap();

        bh.iter(|| {
            let res = s.verify(&msg, &sig, &pk).unwrap();
            black_box(res);
        });
    }

    #[bench]
    pub fn bench_recover(bh: &mut Bencher) {
        let s = Secp256k1::new();
        let mut msg = [0u8; 32];
        thread_rng().fill_bytes(&mut msg);
        let msg = Message::from_slice(&msg).unwrap();
        let (sk, _) = s.generate_keypair(&mut thread_rng()).unwrap();
        let sig = s.sign_recoverable(&msg, &sk).unwrap();

        bh.iter(|| {
            let res = s.recover(&msg, &sig).unwrap();
            black_box(res);
        });
    }
}

