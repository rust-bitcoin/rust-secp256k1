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

#![cfg_attr(feature = "dev", allow(unstable_features))]
#![cfg_attr(feature = "dev", feature(plugin))]
#![cfg_attr(feature = "dev", plugin(clippy))]

#![cfg_attr(all(test, feature = "unstable"), feature(test))]
#[cfg(all(test, feature = "unstable"))] extern crate test;
#[cfg(any(test, feature = "rand"))] extern crate rand;
#[cfg(feature = "serde")] extern crate serde;
#[cfg(all(test, feature = "serde"))] extern crate serde_test;

extern crate libc;

use libc::size_t;
use std::{error, fmt, ops, ptr};
#[cfg(any(test, feature = "rand"))] use rand::Rng;

#[macro_use]
mod macros;
pub mod constants;
pub mod ecdh;
pub mod ffi;
pub mod key;

pub use key::SecretKey;
pub use key::PublicKey;
use std::marker::PhantomData;

/// A tag used for recovering the public key from a compact signature
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct RecoveryId(i32);

/// An ECDSA signature
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Signature(ffi::Signature);

/// An ECDSA signature with a recovery ID for pubkey recovery
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct RecoverableSignature(ffi::RecoverableSignature);

impl RecoveryId {
    #[inline]
    /// Allows library users to create valid recovery IDs from i32.
    pub fn from_i32(id: i32) -> Result<RecoveryId, Error> {
        match id {
            0 | 1 | 2 | 3 => Ok(RecoveryId(id)),
            _ => Err(Error::InvalidRecoveryId)
        }
    }

    #[inline]
    /// Allows library users to convert recovery IDs to i32.
    pub fn to_i32(&self) -> i32 {
        self.0
    }
}

impl Signature {
    #[inline]
    /// Converts a DER-encoded byte slice to a signature
    pub fn from_der<C>(secp: &Secp256k1<C>, data: &[u8]) -> Result<Signature, Error> {
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

    /// Converts a 64-byte compact-encoded byte slice to a signature
    pub fn from_compact<C>(secp: &Secp256k1<C>, data: &[u8]) -> Result<Signature, Error> {
        let mut ret = unsafe { ffi::Signature::blank() };
        if data.len() != 64 {
            return Err(Error::InvalidSignature)
        }

        unsafe {
            if ffi::secp256k1_ecdsa_signature_parse_compact(secp.ctx, &mut ret,
                                                            data.as_ptr()) == 1 {
                Ok(Signature(ret))
            } else {
                Err(Error::InvalidSignature)
            }
        }
    }

    /// Converts a "lax DER"-encoded byte slice to a signature. This is basically
    /// only useful for validating signatures in the Bitcoin blockchain from before
    /// 2016. It should never be used in new applications. This library does not
    /// support serializing to this "format"
    pub fn from_der_lax<C>(secp: &Secp256k1<C>, data: &[u8]) -> Result<Signature, Error> {
        unsafe {
            let mut ret = ffi::Signature::blank();
            if ffi::ecdsa_signature_parse_der_lax(secp.ctx, &mut ret,
                                                  data.as_ptr(), data.len() as libc::size_t) == 1 {
                Ok(Signature(ret))
            } else {
                Err(Error::InvalidSignature)
            }
        }
    }

    /// Normalizes a signature to a "low S" form. In ECDSA, signatures are
    /// of the form (r, s) where r and s are numbers lying in some finite
    /// field. The verification equation will pass for (r, s) iff it passes
    /// for (r, -s), so it is possible to ``modify'' signatures in transit
    /// by flipping the sign of s. This does not constitute a forgery since
    /// the signed message still cannot be changed, but for some applications,
    /// changing even the signature itself can be a problem. Such applications
    /// require a "strong signature". It is believed that ECDSA is a strong
    /// signature except for this ambiguity in the sign of s, so to accomodate
    /// these applications libsecp256k1 will only accept signatures for which
    /// s is in the lower half of the field range. This eliminates the
    /// ambiguity.
    ///
    /// However, for some systems, signatures with high s-values are considered
    /// valid. (For example, parsing the historic Bitcoin blockchain requires
    /// this.) For these applications we provide this normalization function,
    /// which ensures that the s value lies in the lower half of its range.
    pub fn normalize_s<C>(&mut self, secp: &Secp256k1<C>) {
        unsafe {
            // Ignore return value, which indicates whether the sig
            // was already normalized. We don't care.
            ffi::secp256k1_ecdsa_signature_normalize(secp.ctx, self.as_mut_ptr(),
                                                     self.as_ptr());
        }
    }

    /// Obtains a raw pointer suitable for use with FFI functions
    #[inline]
    pub fn as_ptr(&self) -> *const ffi::Signature {
        &self.0 as *const _
    }

    /// Obtains a raw mutable pointer suitable for use with FFI functions
    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut ffi::Signature {
        &mut self.0 as *mut _
    }

    #[inline]
    /// Serializes the signature in DER format
    pub fn serialize_der<C>(&self, secp: &Secp256k1<C>) -> Vec<u8> {
        let mut ret = Vec::with_capacity(72);
        let mut len: size_t = ret.capacity() as size_t;
        unsafe {
            let err = ffi::secp256k1_ecdsa_signature_serialize_der(secp.ctx, ret.as_mut_ptr(),
                                                                   &mut len, self.as_ptr());
            debug_assert!(err == 1);
            ret.set_len(len as usize);
        }
        ret
    }

    #[inline]
    /// Serializes the signature in compact format
    pub fn serialize_compact<C>(&self, secp: &Secp256k1<C>) -> [u8; 64] {
        let mut ret = [0; 64];
        unsafe {
            let err = ffi::secp256k1_ecdsa_signature_serialize_compact(secp.ctx, ret.as_mut_ptr(),
                                                                       self.as_ptr());
            debug_assert!(err == 1);
        }
        ret
    }
}

/// Creates a new signature from a FFI signature
impl From<ffi::Signature> for Signature {
    #[inline]
    fn from(sig: ffi::Signature) -> Signature {
        Signature(sig)
    }
}


impl RecoverableSignature {
    #[inline]
    /// Converts a compact-encoded byte slice to a signature. This
    /// representation is nonstandard and defined by the libsecp256k1
    /// library.
    pub fn from_compact<C>(secp: &Secp256k1<C>, data: &[u8], recid: RecoveryId) -> Result<RecoverableSignature, Error> {
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

    /// Obtains a raw pointer suitable for use with FFI functions
    #[inline]
    pub fn as_ptr(&self) -> *const ffi::RecoverableSignature {
        &self.0 as *const _
    }

    #[inline]
    /// Serializes the recoverable signature in compact format
    pub fn serialize_compact<C>(&self, secp: &Secp256k1<C>) -> (RecoveryId, [u8; 64]) {
        let mut ret = [0u8; 64];
        let mut recid = 0i32;
        unsafe {
            let err = ffi::secp256k1_ecdsa_recoverable_signature_serialize_compact(
                secp.ctx, ret.as_mut_ptr(), &mut recid, self.as_ptr());
            assert!(err == 1);
        }
        (RecoveryId(recid), ret)
    }

    /// Converts a recoverable signature to a non-recoverable one (this is needed
    /// for verification
    #[inline]
    pub fn to_standard<C>(&self, secp: &Secp256k1<C>) -> Signature {
        let mut ret = unsafe { ffi::Signature::blank() };
        unsafe {
            let err = ffi::secp256k1_ecdsa_recoverable_signature_convert(secp.ctx, &mut ret, self.as_ptr());
            assert!(err == 1);
        }
        Signature(ret)
    }
}

/// Creates a new recoverable signature from a FFI one
impl From<ffi::RecoverableSignature> for RecoverableSignature {
    #[inline]
    fn from(sig: ffi::RecoverableSignature) -> RecoverableSignature {
        RecoverableSignature(sig)
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

#[cfg(feature = "serde")]
impl ::serde::Serialize for Signature {
    fn serialize<S: ::serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let secp = Secp256k1::without_caps();
        s.serialize_bytes(&self.serialize_der(&secp))
    }
}

#[cfg(feature = "serde")]
impl<'de> ::serde::Deserialize<'de> for Signature {
    fn deserialize<D: ::serde::Deserializer<'de>>(d: D) -> Result<Signature, D::Error> {
        use ::serde::de::Error;

        let secp = Secp256k1::without_caps();
        let sl: &[u8] = ::serde::Deserialize::deserialize(d)?;
        Signature::from_der(&secp, sl).map_err(D::Error::custom)
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
                ret[..].copy_from_slice(data);
                Ok(Message(ret))
            }
            _ => Err(Error::InvalidMessage)
        }
    }
}

/// Creates a message from a `MESSAGE_SIZE` byte array
impl From<[u8; constants::MESSAGE_SIZE]> for Message {
    fn from(buf: [u8; constants::MESSAGE_SIZE]) -> Message {
        Message(buf)
    }
}

/// An ECDSA error
#[derive(Copy, PartialEq, Eq, Clone, Debug)]
pub enum Error {
    /// Signature failed verification
    IncorrectSignature,
    /// Badly sized message ("messages" are actually fixed-sized digests; see the `MESSAGE_SIZE`
    /// constant)
    InvalidMessage,
    /// Bad public key
    InvalidPublicKey,
    /// Bad signature
    InvalidSignature,
    /// Bad secret key
    InvalidSecretKey,
    /// Bad recovery id
    InvalidRecoveryId,
}

// Passthrough Debug to Display, since errors should be user-visible
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        f.write_str(error::Error::description(self))
    }
}

impl error::Error for Error {
    fn cause(&self) -> Option<&error::Error> { None }

    fn description(&self) -> &str {
        match *self {
            Error::IncorrectSignature => "secp: signature failed verification",
            Error::InvalidMessage => "secp: message was not 32 bytes (do you need to hash?)",
            Error::InvalidPublicKey => "secp: malformed public key",
            Error::InvalidSignature => "secp: malformed signature",
            Error::InvalidSecretKey => "secp: malformed or out-of-range secret key",
            Error::InvalidRecoveryId => "secp: bad recovery id"
        }
    }
}

/// Marker trait for indicating that an instance of `Secp256k1` can be used for signing.
pub trait Signing {}

/// Marker trait for indicating that an instance of `Secp256k1` can be used for verification.
pub trait Verification {}

/// Represents the empty set of capabilities.
pub struct None {}

/// Represents the set of capabilities needed for signing.
pub struct SignOnly {}

/// Represents the set of capabilities needed for verification.
pub struct VerifyOnly {}

/// Represents the set of all capabilities.
pub struct All {}

impl Signing for SignOnly {}
impl Signing for All {}

impl Verification for VerifyOnly {}
impl Verification for All {}

/// The secp256k1 engine, used to execute all signature operations
pub struct Secp256k1<C> {
    ctx: *mut ffi::Context,
    phantom: PhantomData<C>
}

// The underlying secp context does not contain any references to memory it does not own
unsafe impl<C> Send for Secp256k1<C> {}
// The API does not permit any mutation of `Secp256k1` objects except through `&mut` references
unsafe impl<C> Sync for Secp256k1<C> {}

impl<C> Clone for Secp256k1<C> {
    fn clone(&self) -> Secp256k1<C> {
        Secp256k1 {
            ctx: unsafe { ffi::secp256k1_context_clone(self.ctx) },
            phantom: self.phantom
        }
    }
}

impl<C> PartialEq for Secp256k1<C> {
    fn eq(&self, _other: &Secp256k1<C>) -> bool { true }
}

impl<C> Eq for Secp256k1<C> { }

impl<C> Drop for Secp256k1<C> {
    fn drop(&mut self) {
        unsafe { ffi::secp256k1_context_destroy(self.ctx); }
    }
}

impl Secp256k1<None> {
    /// Creates a new Secp256k1 context with no capabilities (just de/serialization)
    pub fn without_caps() -> Secp256k1<None> {
        Secp256k1 { ctx: unsafe { ffi::secp256k1_context_create(ffi::SECP256K1_START_NONE) }, phantom: PhantomData }
    }
}

impl Secp256k1<All> {
    /// Creates a new Secp256k1 context with all capabilities
    pub fn new() -> Secp256k1<All> {
        Secp256k1 { ctx: unsafe { ffi::secp256k1_context_create(ffi::SECP256K1_START_SIGN | ffi::SECP256K1_START_VERIFY) }, phantom: PhantomData }
    }
}

impl Secp256k1<SignOnly> {
    /// Creates a new Secp256k1 context that can only be used for signing
    pub fn signing_only() -> Secp256k1<SignOnly> {
        Secp256k1 { ctx: unsafe { ffi::secp256k1_context_create(ffi::SECP256K1_START_SIGN) }, phantom: PhantomData }
    }
}

impl Secp256k1<VerifyOnly> {
    /// Creates a new Secp256k1 context that can only be used for verification
    pub fn verification_only() -> Secp256k1<VerifyOnly> {
        Secp256k1 { ctx: unsafe { ffi::secp256k1_context_create(ffi::SECP256K1_START_VERIFY) }, phantom: PhantomData }
    }
}

impl<C> Secp256k1<C> {

    /// (Re)randomizes the Secp256k1 context for cheap sidechannel resistance;
    /// see comment in libsecp256k1 commit d2275795f by Gregory Maxwell
    #[cfg(any(test, feature = "rand"))]
    pub fn randomize<R: Rng>(&mut self, rng: &mut R) {
        let mut seed = [0; 32];
        rng.fill_bytes(&mut seed);
        unsafe {
            let err = ffi::secp256k1_context_randomize(self.ctx, seed.as_ptr());
            // This function cannot fail; it has an error return for future-proofing.
            // We do not expose this error since it is impossible to hit, and we have
            // precedent for not exposing impossible errors (for example in
            // `PublicKey::from_secret_key` where it is impossible to create an invalid
            // secret key through the API.)
            // However, if this DOES fail, the result is potentially weaker side-channel
            // resistance, which is deadly and undetectable, so we take out the entire
            // thread to be on the safe side.
            assert!(err == 1);
        }
    }

}

impl<C: Signing> Secp256k1<C> {

    /// Constructs a signature for `msg` using the secret key `sk` and RFC6979 nonce
    /// Requires a signing-capable context.
    pub fn sign(&self, msg: &Message, sk: &key::SecretKey)
                -> Signature {

        let mut ret = unsafe { ffi::Signature::blank() };
        unsafe {
            // We can assume the return value because it's not possible to construct
            // an invalid signature from a valid `Message` and `SecretKey`
            assert_eq!(ffi::secp256k1_ecdsa_sign(self.ctx, &mut ret, msg.as_ptr(),
                                                 sk.as_ptr(), ffi::secp256k1_nonce_function_rfc6979,
                                                 ptr::null()), 1);
        }

        Signature::from(ret)
    }

    /// Constructs a signature for `msg` using the secret key `sk` and RFC6979 nonce
    /// Requires a signing-capable context.
    pub fn sign_recoverable(&self, msg: &Message, sk: &key::SecretKey)
                            -> RecoverableSignature {

        let mut ret = unsafe { ffi::RecoverableSignature::blank() };
        unsafe {
            // We can assume the return value because it's not possible to construct
            // an invalid signature from a valid `Message` and `SecretKey`
            assert_eq!(ffi::secp256k1_ecdsa_sign_recoverable(self.ctx, &mut ret, msg.as_ptr(),
                                                             sk.as_ptr(), ffi::secp256k1_nonce_function_rfc6979,
                                                             ptr::null()), 1);
        }

        RecoverableSignature::from(ret)
    }

    /// Generates a random keypair. Convenience function for `key::SecretKey::new`
    /// and `key::PublicKey::from_secret_key`; call those functions directly for
    /// batch key generation. Requires a signing-capable context.
    #[inline]
    #[cfg(any(test, feature = "rand"))]
    pub fn generate_keypair<R: Rng>(&self, rng: &mut R)
                                    -> (key::SecretKey, key::PublicKey) {
        let sk = key::SecretKey::new(self, rng);
        let pk = key::PublicKey::from_secret_key(self, &sk);
        (sk, pk)
    }
}

impl<C: Verification> Secp256k1<C> {

    /// Determines the public key for which `sig` is a valid signature for
    /// `msg`. Requires a verify-capable context.
    pub fn recover(&self, msg: &Message, sig: &RecoverableSignature)
                   -> Result<key::PublicKey, Error> {

        let mut pk = unsafe { ffi::PublicKey::blank() };

        unsafe {
            if ffi::secp256k1_ecdsa_recover(self.ctx, &mut pk,
                                            sig.as_ptr(), msg.as_ptr()) != 1 {
                return Err(Error::InvalidSignature);
            }
        };
        Ok(key::PublicKey::from(pk))
    }

    /// Checks that `sig` is a valid ECDSA signature for `msg` using the public
    /// key `pubkey`. Returns `Ok(true)` on success. Note that this function cannot
    /// be used for Bitcoin consensus checking since there may exist signatures
    /// which OpenSSL would verify but not libsecp256k1, or vice-versa. Requires a
    /// verify-capable context.
    #[inline]
    pub fn verify(&self, msg: &Message, sig: &Signature, pk: &key::PublicKey) -> Result<(), Error> {
        unsafe {
            if ffi::secp256k1_ecdsa_verify(self.ctx, sig.as_ptr(), msg.as_ptr(), pk.as_ptr()) == 0 {
                Err(Error::IncorrectSignature)
            } else {
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use rand::{Rng, thread_rng};

    use key::{SecretKey, PublicKey};
    use super::constants;
    use super::{Secp256k1, Signature, RecoverableSignature, Message, RecoveryId};
    use super::Error::{InvalidMessage, IncorrectSignature, InvalidSignature};

    macro_rules! hex {
        ($hex:expr) => {
            {
                let mut vec = Vec::new();
                let mut b = 0;
                for (idx, c) in $hex.as_bytes().iter().enumerate() {
                    b <<= 4;
                    match *c {
                        b'A'...b'F' => b |= c - b'A' + 10,
                        b'a'...b'f' => b |= c - b'a' + 10,
                        b'0'...b'9' => b |= c - b'0',
                        _ => panic!("Bad hex"),
                    }
                    if (idx & 1) == 1 {
                        vec.push(b);
                        b = 0;
                    }
                }
                vec
            }
        }
    }

    #[test]
    fn capabilities() {
        let none = Secp256k1::without_caps();
        let sign = Secp256k1::signing_only();
        let vrfy = Secp256k1::verification_only();
        let full = Secp256k1::new();

        let mut msg = [0u8; 32];
        thread_rng().fill_bytes(&mut msg);
        let msg = Message::from_slice(&msg).unwrap();

        // Try key generation
        let (sk, pk) = full.generate_keypair(&mut thread_rng());

        // Try signing
        assert_eq!(sign.sign(&msg, &sk), full.sign(&msg, &sk));
        assert_eq!(sign.sign_recoverable(&msg, &sk), full.sign_recoverable(&msg, &sk));
        let sig = full.sign(&msg, &sk);
        let sigr = full.sign_recoverable(&msg, &sk);

        // Try verifying
        assert!(vrfy.verify(&msg, &sig, &pk).is_ok());
        assert!(full.verify(&msg, &sig, &pk).is_ok());

        // Try pk recovery
        assert!(vrfy.recover(&msg, &sigr).is_ok());
        assert!(full.recover(&msg, &sigr).is_ok());

        assert_eq!(vrfy.recover(&msg, &sigr),
                   full.recover(&msg, &sigr));
        assert_eq!(full.recover(&msg, &sigr), Ok(pk));

        // Check that we can produce keys from slices with no precomputation
        let (pk_slice, sk_slice) = (&pk.serialize(), &sk[..]);
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
    fn sign() {
        let mut s = Secp256k1::new();
        s.randomize(&mut thread_rng());
        let one = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

        let sk = SecretKey::from_slice(&s, &one).unwrap();
        let msg = Message::from_slice(&one).unwrap();

        let sig = s.sign_recoverable(&msg, &sk);
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
    fn signature_serialize_roundtrip() {
        let mut s = Secp256k1::new();
        s.randomize(&mut thread_rng());

        let mut msg = [0; 32];
        for _ in 0..100 {
            thread_rng().fill_bytes(&mut msg);
            let msg = Message::from_slice(&msg).unwrap();

            let (sk, _) = s.generate_keypair(&mut thread_rng());
            let sig1 = s.sign(&msg, &sk);
            let der = sig1.serialize_der(&s);
            let sig2 = Signature::from_der(&s, &der[..]).unwrap();
            assert_eq!(sig1, sig2);

            let compact = sig1.serialize_compact(&s);
            let sig2 = Signature::from_compact(&s, &compact[..]).unwrap();
            assert_eq!(sig1, sig2);

            assert!(Signature::from_compact(&s, &der[..]).is_err());
            assert!(Signature::from_compact(&s, &compact[0..4]).is_err());
            assert!(Signature::from_der(&s, &compact[..]).is_err());
            assert!(Signature::from_der(&s, &der[0..4]).is_err());
         }
    }

    #[test]
    fn signature_lax_der() {
        macro_rules! check_lax_sig(
            ($hex:expr) => ({
                let secp = Secp256k1::without_caps();
                let sig = hex!($hex);
                assert!(Signature::from_der_lax(&secp, &sig[..]).is_ok());
            })
        );

        check_lax_sig!("304402204c2dd8a9b6f8d425fcd8ee9a20ac73b619906a6367eac6cb93e70375225ec0160220356878eff111ff3663d7e6bf08947f94443845e0dcc54961664d922f7660b80c");
        check_lax_sig!("304402202ea9d51c7173b1d96d331bd41b3d1b4e78e66148e64ed5992abd6ca66290321c0220628c47517e049b3e41509e9d71e480a0cdc766f8cdec265ef0017711c1b5336f");
        check_lax_sig!("3045022100bf8e050c85ffa1c313108ad8c482c4849027937916374617af3f2e9a881861c9022023f65814222cab09d5ec41032ce9c72ca96a5676020736614de7b78a4e55325a");
        check_lax_sig!("3046022100839c1fbc5304de944f697c9f4b1d01d1faeba32d751c0f7acb21ac8a0f436a72022100e89bd46bb3a5a62adc679f659b7ce876d83ee297c7a5587b2011c4fcc72eab45");
        check_lax_sig!("3046022100eaa5f90483eb20224616775891397d47efa64c68b969db1dacb1c30acdfc50aa022100cf9903bbefb1c8000cf482b0aeeb5af19287af20bd794de11d82716f9bae3db1");
        check_lax_sig!("3045022047d512bc85842ac463ca3b669b62666ab8672ee60725b6c06759e476cebdc6c102210083805e93bd941770109bcc797784a71db9e48913f702c56e60b1c3e2ff379a60");
        check_lax_sig!("3044022023ee4e95151b2fbbb08a72f35babe02830d14d54bd7ed1320e4751751d1baa4802206235245254f58fd1be6ff19ca291817da76da65c2f6d81d654b5185dd86b8acf");
    }

    #[test]
    fn sign_and_verify() {
        let mut s = Secp256k1::new();
        s.randomize(&mut thread_rng());

        let mut msg = [0; 32];
        for _ in 0..100 {
            thread_rng().fill_bytes(&mut msg);
            let msg = Message::from_slice(&msg).unwrap();

            let (sk, pk) = s.generate_keypair(&mut thread_rng());
            let sig = s.sign(&msg, &sk);
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

        use constants;
        wild_keys[1][..].copy_from_slice(&constants::CURVE_ORDER[..]);
        wild_msgs[1][..].copy_from_slice(&constants::CURVE_ORDER[..]);
        wild_msgs[2][..].copy_from_slice(&constants::CURVE_ORDER[..]);

        wild_keys[1][0] -= 1;
        wild_msgs[1][0] -= 1;

        for key in wild_keys.iter().map(|k| SecretKey::from_slice(&s, &k[..]).unwrap()) {
            for msg in wild_msgs.iter().map(|m| Message::from_slice(&m[..]).unwrap()) {
                let sig = s.sign(&msg, &key);
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

        let (sk, pk) = s.generate_keypair(&mut thread_rng());

        let sigr = s.sign_recoverable(&msg, &sk);
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

        let (sk, pk) = s.generate_keypair(&mut thread_rng());

        let sig = s.sign_recoverable(&msg, &sk);

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

    #[test]
    fn test_recov_sig_serialize_compact() {
        let s = Secp256k1::new();

        let recid_in = RecoveryId(1);
        let bytes_in = &[
            0x66, 0x73, 0xff, 0xad, 0x21, 0x47, 0x74, 0x1f,
            0x04, 0x77, 0x2b, 0x6f, 0x92, 0x1f, 0x0b, 0xa6,
            0xaf, 0x0c, 0x1e, 0x77, 0xfc, 0x43, 0x9e, 0x65,
            0xc3, 0x6d, 0xed, 0xf4, 0x09, 0x2e, 0x88, 0x98,
            0x4c, 0x1a, 0x97, 0x16, 0x52, 0xe0, 0xad, 0xa8,
            0x80, 0x12, 0x0e, 0xf8, 0x02, 0x5e, 0x70, 0x9f,
            0xff, 0x20, 0x80, 0xc4, 0xa3, 0x9a, 0xae, 0x06,
            0x8d, 0x12, 0xee, 0xd0, 0x09, 0xb6, 0x8c, 0x89];
        let sig = RecoverableSignature::from_compact(
            &s, bytes_in, recid_in).unwrap();
        let (recid_out, bytes_out) = sig.serialize_compact(&s);
        assert_eq!(recid_in, recid_out);
        assert_eq!(&bytes_in[..], &bytes_out[..]);
    }

    #[test]
    fn test_recov_id_conversion_between_i32() {
        assert!(RecoveryId::from_i32(-1).is_err());
        assert!(RecoveryId::from_i32(0).is_ok());
        assert!(RecoveryId::from_i32(1).is_ok());
        assert!(RecoveryId::from_i32(2).is_ok());
        assert!(RecoveryId::from_i32(3).is_ok());
        assert!(RecoveryId::from_i32(4).is_err());
        let id0 = RecoveryId::from_i32(0).unwrap();
        assert_eq!(id0.to_i32(), 0);
        let id1 = RecoveryId(1);
        assert_eq!(id1.to_i32(), 1);
    }

    #[test]
    fn test_low_s() {
        // nb this is a transaction on testnet
        // txid 8ccc87b72d766ab3128f03176bb1c98293f2d1f85ebfaf07b82cc81ea6891fa9
        //      input number 3
        let sig = hex!("3046022100839c1fbc5304de944f697c9f4b1d01d1faeba32d751c0f7acb21ac8a0f436a72022100e89bd46bb3a5a62adc679f659b7ce876d83ee297c7a5587b2011c4fcc72eab45");
        let pk = hex!("031ee99d2b786ab3b0991325f2de8489246a6a3fdb700f6d0511b1d80cf5f4cd43");
        let msg = hex!("a4965ca63b7d8562736ceec36dfa5a11bf426eb65be8ea3f7a49ae363032da0d");

        let secp = Secp256k1::new();
        let mut sig = Signature::from_der(&secp, &sig[..]).unwrap();
        let pk = PublicKey::from_slice(&secp, &pk[..]).unwrap();
        let msg = Message::from_slice(&msg[..]).unwrap();

        // without normalization we expect this will fail
        assert_eq!(secp.verify(&msg, &sig, &pk), Err(IncorrectSignature));
        // after normalization it should pass
        sig.normalize_s(&secp);
        assert_eq!(secp.verify(&msg, &sig, &pk), Ok(()));
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_signature_serde() {
        use serde_test::{Token, assert_tokens};

        let s = Secp256k1::new();

        let msg = Message::from_slice(&[1; 32]).unwrap();
        let sk = SecretKey::from_slice(&s, &[2; 32]).unwrap();
        let sig = s.sign(&msg, &sk);
        static SIG_BYTES: [u8; 71] = [
            48, 69, 2, 33, 0, 157, 11, 173, 87, 103, 25, 211, 42, 231, 107, 237,
            179, 76, 119, 72, 102, 103, 60, 189, 227, 244, 225, 41, 81, 85, 92, 148,
            8, 230, 206, 119, 75, 2, 32, 40, 118, 231, 16, 47, 32, 79, 107, 254,
            226, 108, 150, 124, 57, 38, 206, 112, 44, 249, 125, 75, 1, 0, 98, 225,
            147, 247, 99, 25, 15, 103, 118
        ];

        assert_tokens(&sig, &[Token::BorrowedBytes(&SIG_BYTES[..])]);
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
            let (sk, pk) = s.generate_keypair(&mut r);
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
        let (sk, _) = s.generate_keypair(&mut thread_rng());

        bh.iter(|| {
            let sig = s.sign(&msg, &sk);
            black_box(sig);
        });
    }

    #[bench]
    pub fn bench_verify(bh: &mut Bencher) {
        let s = Secp256k1::new();
        let mut msg = [0u8; 32];
        thread_rng().fill_bytes(&mut msg);
        let msg = Message::from_slice(&msg).unwrap();
        let (sk, pk) = s.generate_keypair(&mut thread_rng());
        let sig = s.sign(&msg, &sk);

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
        let (sk, _) = s.generate_keypair(&mut thread_rng());
        let sig = s.sign_recoverable(&msg, &sk);

        bh.iter(|| {
            let res = s.recover(&msg, &sig).unwrap();
            black_box(res);
        });
    }
}

