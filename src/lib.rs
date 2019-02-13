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
//! Rust bindings for Pieter Wuille's secp256k1-zkp library, which is used for
//! fast and accurate manipulation of ECDSA signatures on the secp256k1
//! curve. Such signatures are used extensively by the Bitcoin network
//! and its derivatives.
//!
//! To minimize dependencies, some functions are feature-gated. To generate
//! random keys or to re-randomize a context object, compile with the "rand"
//! feature. To de/serialize objects with serde, compile with "serde".
//!
//! Where possible, the bindings use the Rust type system to ensure that
//! API usage errors are impossible. For example, the library uses context
//! objects that contain precomputation tables which are created on object
//! construction. Since this is a slow operation (10+ milliseconds, vs ~50
//! microseconds for typical crypto operations, on a 2.70 Ghz i7-6820HQ)
//! the tables are optional, giving a performance boost for users who only
//! care about signing, only care about verification, or only care about
//! parsing. In the upstream library, if you attempt to sign a message using
//! a context that does not support this, it will trigger an assertion
//! failure and terminate the program. In `rust-secp256k1-zkp`, this is caught
//! at compile-time; in fact, it is impossible to compile code that will
//! trigger any assertion failures in the upstream library.
//!
//! ```rust
//! extern crate secp256k1_zkp;
//! # #[cfg(feature="rand")]
//! extern crate rand;
//!
//! #
//! # fn main() {
//! # #[cfg(feature="rand")] {
//! use rand::OsRng;
//! use secp256k1_zkp::{Secp256k1, Message};
//!
//! let secp = Secp256k1::new();
//! let mut rng = OsRng::new().expect("OsRng");
//! let (secret_key, public_key) = secp.generate_keypair(&mut rng);
//! let message = Message::from_slice(&[0xab; 32]).expect("32 bytes");
//!
//! let sig = secp.sign(&message, &secret_key);
//! assert!(secp.verify(&message, &sig, &public_key).is_ok());
//! # } }
//! ```
//!
//! The above code requires `rust-secp256k1-zkp` to be compiled with the `rand`
//! feature enabled, to get access to [`generate_keypair`](struct.Secp256k1.html#method.generate_keypair)
//! Alternately, keys can be parsed from slices, like
//!
//! ```rust
//! # fn main() {
//! use self::secp256k1_zkp::{Secp256k1, Message, SecretKey, PublicKey};
//!
//! let secp = Secp256k1::new();
//! let secret_key = SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order");
//! let public_key = PublicKey::from_secret_key(&secp, &secret_key);
//! let message = Message::from_slice(&[0xab; 32]).expect("32 bytes");
//!
//! let sig = secp.sign(&message, &secret_key);
//! assert!(secp.verify(&message, &sig, &public_key).is_ok());
//! # }
//! ```
//!
//! Users who only want to verify signatures can use a cheaper context, like so:
//!
//! ```rust
//! # fn main() {
//! use secp256k1_zkp::{Secp256k1, Message, Signature, PublicKey};
//!
//! let secp = Secp256k1::verification_only();
//!
//! let public_key = PublicKey::from_slice(&[
//!     0x02,
//!     0xc6, 0x6e, 0x7d, 0x89, 0x66, 0xb5, 0xc5, 0x55,
//!     0xaf, 0x58, 0x05, 0x98, 0x9d, 0xa9, 0xfb, 0xf8,
//!     0xdb, 0x95, 0xe1, 0x56, 0x31, 0xce, 0x35, 0x8c,
//!     0x3a, 0x17, 0x10, 0xc9, 0x62, 0x67, 0x90, 0x63,
//! ]).expect("public keys must be 33 or 65 bytes, serialized according to SEC 2");
//!
//! let message = Message::from_slice(&[
//!     0xaa, 0xdf, 0x7d, 0xe7, 0x82, 0x03, 0x4f, 0xbe,
//!     0x3d, 0x3d, 0xb2, 0xcb, 0x13, 0xc0, 0xcd, 0x91,
//!     0xbf, 0x41, 0xcb, 0x08, 0xfa, 0xc7, 0xbd, 0x61,
//!     0xd5, 0x44, 0x53, 0xcf, 0x6e, 0x82, 0xb4, 0x50,
//! ]).expect("messages must be 32 bytes and are expected to be hashes");
//!
//! let sig = Signature::from_compact(&[
//!     0xdc, 0x4d, 0xc2, 0x64, 0xa9, 0xfe, 0xf1, 0x7a,
//!     0x3f, 0x25, 0x34, 0x49, 0xcf, 0x8c, 0x39, 0x7a,
//!     0xb6, 0xf1, 0x6f, 0xb3, 0xd6, 0x3d, 0x86, 0x94,
//!     0x0b, 0x55, 0x86, 0x82, 0x3d, 0xfd, 0x02, 0xae,
//!     0x3b, 0x46, 0x1b, 0xb4, 0x33, 0x6b, 0x5e, 0xcb,
//!     0xae, 0xfd, 0x66, 0x27, 0xaa, 0x92, 0x2e, 0xfc,
//!     0x04, 0x8f, 0xec, 0x0c, 0x88, 0x1c, 0x10, 0xc4,
//!     0xc9, 0x42, 0x8f, 0xca, 0x69, 0xc1, 0x32, 0xa2,
//! ]).expect("compact signatures are 64 bytes; DER signatures are 68-72 bytes");
//!
//! assert!(secp.verify(&message, &sig, &public_key).is_ok());
//! # }
//! ```
//!
//! Observe that the same code using, say [`signing_only`](struct.Secp256k1.html#method.signing_only)
//! to generate a context would simply not compile.
//!

#![crate_type = "lib"]
#![crate_type = "rlib"]
#![crate_type = "dylib"]
#![crate_name = "secp256k1_zkp"]

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
#[cfg(any(test, feature = "rand"))] pub extern crate rand;
#[cfg(feature = "serde")] pub extern crate serde;
#[cfg(all(test, feature = "serde"))] extern crate serde_test;

use std::{error, fmt, ptr, str};
#[cfg(any(test, feature = "rand"))] use rand::Rng;

#[macro_use]
mod macros;
pub mod constants;
pub mod ecdh;
pub mod schnorrsig;
pub mod ffi;
pub mod key;

pub use key::SecretKey;
pub use key::PublicKey;
use std::marker::PhantomData;

/// A tag used for recovering the public key from a compact signature
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct RecoveryId(i32);

/// An ECDSA signature
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct Signature(ffi::Signature);

impl fmt::Debug for Signature {
fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    fmt::Display::fmt(self, f)
}
}

impl fmt::Display for Signature {
fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    let mut v = [0; 72];
    let mut len = v.len() as usize;
    unsafe {
        let err = ffi::secp256k1_ecdsa_signature_serialize_der(
            ffi::secp256k1_context_no_precomp,
            v.as_mut_ptr(),
            &mut len,
            self.as_ptr()
        );
        debug_assert!(err == 1);
    }
    for ch in &v[..] {
        write!(f, "{:02x}", *ch)?;
    }
    Ok(())
}
}

impl str::FromStr for Signature {
type Err = Error;
fn from_str(s: &str) -> Result<Signature, Error> {
    let mut res = [0; 72];
    match from_hex(s, &mut res) {
        Ok(x) => Signature::from_der(&res[0..x]),
        _ => Err(Error::InvalidSignature),
    }
}
}

/// An ECDSA signature with a recovery ID for pubkey recovery
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct RecoverableSignature(ffi::RecoverableSignature);

/// Trait describing something that promises to be a 32-byte random number; in particular,
/// it has negligible probability of being zero or overflowing the group order. Such objects
/// may be converted to `Message`s without any error paths.
pub trait ThirtyTwoByteHash {
    /// Converts the object into a 32-byte array
    fn into_32(self) -> [u8; 32];
}

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
    pub fn from_der(data: &[u8]) -> Result<Signature, Error> {
        let mut ret = unsafe { ffi::Signature::blank() };

        unsafe {
            if ffi::secp256k1_ecdsa_signature_parse_der(
                ffi::secp256k1_context_no_precomp,
                &mut ret,
                data.as_ptr(),
                data.len() as usize,
            ) == 1
            {
                Ok(Signature(ret))
            } else {
                Err(Error::InvalidSignature)
            }
        }
    }

    /// Converts a 64-byte compact-encoded byte slice to a signature
    pub fn from_compact(data: &[u8]) -> Result<Signature, Error> {
        let mut ret = unsafe { ffi::Signature::blank() };
        if data.len() != 64 {
            return Err(Error::InvalidSignature)
        }

        unsafe {
            if ffi::secp256k1_ecdsa_signature_parse_compact(
                ffi::secp256k1_context_no_precomp,
                &mut ret,
                data.as_ptr(),
            ) == 1
            {
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
    pub fn from_der_lax(data: &[u8]) -> Result<Signature, Error> {
        unsafe {
            let mut ret = ffi::Signature::blank();
            if ffi::ecdsa_signature_parse_der_lax(
                ffi::secp256k1_context_no_precomp,
                &mut ret,
                data.as_ptr(),
                data.len() as usize,
            ) == 1
            {
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
    /// signature except for this ambiguity in the sign of s, so to accommodate
    /// these applications libsecp256k1 will only accept signatures for which
    /// s is in the lower half of the field range. This eliminates the
    /// ambiguity.
    ///
    /// However, for some systems, signatures with high s-values are considered
    /// valid. (For example, parsing the historic Bitcoin blockchain requires
    /// this.) For these applications we provide this normalization function,
    /// which ensures that the s value lies in the lower half of its range.
    pub fn normalize_s(&mut self) {
        unsafe {
            // Ignore return value, which indicates whether the sig
            // was already normalized. We don't care.
            ffi::secp256k1_ecdsa_signature_normalize(
                ffi::secp256k1_context_no_precomp,
                self.as_mut_ptr(),
                self.as_ptr(),
            );
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
    pub fn serialize_der(&self) -> Vec<u8> {
        let mut ret = Vec::with_capacity(72);
        let mut len: usize = ret.capacity() as usize;
        unsafe {
            let err = ffi::secp256k1_ecdsa_signature_serialize_der(
                ffi::secp256k1_context_no_precomp,
                ret.as_mut_ptr(),
                &mut len,
                self.as_ptr(),
            );
            debug_assert!(err == 1);
            ret.set_len(len as usize);
        }
        ret
    }

    #[inline]
    /// Serializes the signature in compact format
    pub fn serialize_compact(&self) -> [u8; 64] {
        let mut ret = [0; 64];
        unsafe {
            let err = ffi::secp256k1_ecdsa_signature_serialize_compact(
                ffi::secp256k1_context_no_precomp,
                ret.as_mut_ptr(),
                self.as_ptr(),
            );
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
    pub fn from_compact(data: &[u8], recid: RecoveryId) -> Result<RecoverableSignature, Error> {
        let mut ret = unsafe { ffi::RecoverableSignature::blank() };

        unsafe {
            if data.len() != 64 {
                Err(Error::InvalidSignature)
            } else if ffi::secp256k1_ecdsa_recoverable_signature_parse_compact(
                ffi::secp256k1_context_no_precomp,
                &mut ret,
                data.as_ptr(),
                recid.0,
            ) == 1
            {
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
    pub fn serialize_compact(&self) -> (RecoveryId, [u8; 64]) {
        let mut ret = [0u8; 64];
        let mut recid = 0i32;
        unsafe {
            let err = ffi::secp256k1_ecdsa_recoverable_signature_serialize_compact(
                ffi::secp256k1_context_no_precomp,
                ret.as_mut_ptr(),
                &mut recid,
                self.as_ptr(),
            );
            assert!(err == 1);
        }
        (RecoveryId(recid), ret)
    }

    /// Converts a recoverable signature to a non-recoverable one (this is needed
    /// for verification
    #[inline]
    pub fn to_standard(&self) -> Signature {
        let mut ret = unsafe { ffi::Signature::blank() };
        unsafe {
            let err = ffi::secp256k1_ecdsa_recoverable_signature_convert(
                ffi::secp256k1_context_no_precomp,
                &mut ret,
                self.as_ptr(),
            );
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

#[cfg(feature = "serde")]
impl ::serde::Serialize for Signature {
    fn serialize<S: ::serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(&self.serialize_der())
    }
}

#[cfg(feature = "serde")]
impl<'de> ::serde::Deserialize<'de> for Signature {
    fn deserialize<D: ::serde::Deserializer<'de>>(d: D) -> Result<Signature, D::Error> {
        use ::serde::de::Error;

        let sl: &[u8] = ::serde::Deserialize::deserialize(d)?;
        Signature::from_der(sl).map_err(D::Error::custom)
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
        if data == &[0; constants::MESSAGE_SIZE] {
            return Err(Error::InvalidMessage);
        }

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

impl<T: ThirtyTwoByteHash> From<T> for Message {
    /// Converts a 32-byte hash directly to a message without error paths
    fn from(t: T) -> Message {
        Message(t.into_32())
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
    /// Invalid tweak for add_*_assign or mul_*_assign
    InvalidTweak,
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
            Error::InvalidRecoveryId => "secp: bad recovery id",
            Error::InvalidTweak => "secp: bad tweak",
        }
    }
}

/// Marker trait for indicating that an instance of `Secp256k1` can be used for signing.
pub trait Signing {}

/// Marker trait for indicating that an instance of `Secp256k1` can be used for verification.
pub trait Verification {}

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

impl fmt::Debug for Secp256k1<SignOnly> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "<secp256k1 context {:?}, signing only>", self.ctx)
    }
}

impl fmt::Debug for Secp256k1<VerifyOnly> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "<secp256k1 context {:?}, verification only>", self.ctx)
    }
}

impl fmt::Debug for Secp256k1<All> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "<secp256k1 context {:?}, all capabilities>", self.ctx)
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
    /// see comment in libsecp256k1 commit d2275795f by Gregory Maxwell. Requires
    /// compilation with "rand" feature.
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
            assert_eq!(
                ffi::secp256k1_ecdsa_sign_recoverable(
                    self.ctx,
                    &mut ret,
                    msg.as_ptr(),
                    sk.as_ptr(),
                    ffi::secp256k1_nonce_function_rfc6979,
                    ptr::null()
                ),
                1
            );
        }

        RecoverableSignature::from(ret)
    }

    /// Generates a random keypair. Convenience function for `key::SecretKey::new`
    /// and `key::PublicKey::from_secret_key`; call those functions directly for
    /// batch key generation. Requires a signing-capable context. Requires compilation
    /// with the "rand" feature.
    #[inline]
    #[cfg(any(test, feature = "rand"))]
    pub fn generate_keypair<R: Rng>(&self, rng: &mut R)
                                    -> (key::SecretKey, key::PublicKey) {
        let sk = key::SecretKey::new(rng);
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

/// Utility function used to parse hex into a target u8 buffer. Returns
/// the number of bytes converted or an error if it encounters an invalid
/// character or unexpected end of string.
fn from_hex(hex: &str, target: &mut [u8]) -> Result<usize, ()> {
    if hex.len() % 2 == 1 || hex.len() > target.len() * 2 {
        return Err(());
    }

    let mut b = 0;
    let mut idx = 0;
    for c in hex.bytes() {
        b <<= 4;
        match c {
            b'A'...b'F' => b |= c - b'A' + 10,
            b'a'...b'f' => b |= c - b'a' + 10,
            b'0'...b'9' => b |= c - b'0',
            _ => return Err(()),
        }
        if (idx & 1) == 1 {
            target[idx / 2] = b;
            b = 0;
        }
        idx += 1;
    }
    Ok(idx / 2)
}


#[cfg(test)]
mod tests {
    use rand::{Rng, thread_rng};
    use std::str::FromStr;

    use key::{SecretKey, PublicKey};
    use super::from_hex;
    use super::constants;
    use super::{Secp256k1, Signature, RecoverableSignature, Message, RecoveryId};
    use super::Error::{InvalidMessage, IncorrectSignature, InvalidSignature};

    macro_rules! hex {
        ($hex:expr) => ({
            let mut result = vec![0; $hex.len() / 2];
            from_hex($hex, &mut result).expect("valid hex string");
            result
        });
    }

    #[test]
    fn capabilities() {
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
        let new_pk = PublicKey::from_slice(pk_slice).unwrap();
        let new_sk = SecretKey::from_slice(sk_slice).unwrap();
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

        let sk = SecretKey::from_slice(&one).unwrap();
        let msg = Message::from_slice(&one).unwrap();

        let sig = s.sign_recoverable(&msg, &sk);
        assert_eq!(Ok(sig), RecoverableSignature::from_compact(&[
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
            let der = sig1.serialize_der();
            let sig2 = Signature::from_der(&der[..]).unwrap();
            assert_eq!(sig1, sig2);

            let compact = sig1.serialize_compact();
            let sig2 = Signature::from_compact(&compact[..]).unwrap();
            assert_eq!(sig1, sig2);

            assert!(Signature::from_compact(&der[..]).is_err());
            assert!(Signature::from_compact(&compact[0..4]).is_err());
            assert!(Signature::from_der(&compact[..]).is_err());
            assert!(Signature::from_der(&der[0..4]).is_err());
         }
    }

    #[test]
    fn signature_display() {
        let hex_str = "3046022100839c1fbc5304de944f697c9f4b1d01d1faeba32d751c0f7acb21ac8a0f436a72022100e89bd46bb3a5a62adc679f659b7ce876d83ee297c7a5587b2011c4fcc72eab45";
        let byte_str = hex!(hex_str);

        assert_eq!(
            Signature::from_der(&byte_str).expect("byte str decode"),
            Signature::from_str(&hex_str).expect("byte str decode")
        );

        let sig = Signature::from_str(&hex_str).expect("byte str decode");
        assert_eq!(&sig.to_string(), hex_str);
        assert_eq!(&format!("{:?}", sig), hex_str);

        assert!(Signature::from_str(
            "3046022100839c1fbc5304de944f697c9f4b1d01d1faeba32d751c0f7acb21ac8a0f436a\
             72022100e89bd46bb3a5a62adc679f659b7ce876d83ee297c7a5587b2011c4fcc72eab4"
        ).is_err());
        assert!(Signature::from_str(
            "3046022100839c1fbc5304de944f697c9f4b1d01d1faeba32d751c0f7acb21ac8a0f436a\
             72022100e89bd46bb3a5a62adc679f659b7ce876d83ee297c7a5587b2011c4fcc72eab"
        ).is_err());
        assert!(Signature::from_str(
            "3046022100839c1fbc5304de944f697c9f4b1d01d1faeba32d751c0f7acb21ac8a0f436a\
             72022100e89bd46bb3a5a62adc679f659b7ce876d83ee297c7a5587b2011c4fcc72eabxx"
        ).is_err());
        assert!(Signature::from_str(
            "3046022100839c1fbc5304de944f697c9f4b1d01d1faeba32d751c0f7acb21ac8a0f436a\
             72022100e89bd46bb3a5a62adc679f659b7ce876d83ee297c7a5587b2011c4fcc72eab45\
             72022100e89bd46bb3a5a62adc679f659b7ce876d83ee297c7a5587b2011c4fcc72eab45\
             72022100e89bd46bb3a5a62adc679f659b7ce876d83ee297c7a5587b2011c4fcc72eab45\
             72022100e89bd46bb3a5a62adc679f659b7ce876d83ee297c7a5587b2011c4fcc72eab45\
             72022100e89bd46bb3a5a62adc679f659b7ce876d83ee297c7a5587b2011c4fcc72eab45"
        ).is_err());
    }

    #[test]
    fn signature_lax_der() {
        macro_rules! check_lax_sig(
            ($hex:expr) => ({
                let sig = hex!($hex);
                assert!(Signature::from_der_lax(&sig[..]).is_ok());
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
        // Wild msgs: 1, CURVE_ORDER - 1
        let mut wild_keys = [[0; 32]; 2];
        let mut wild_msgs = [[0; 32]; 2];

        wild_keys[0][0] = 1;
        wild_msgs[0][0] = 1;

        use constants;
        wild_keys[1][..].copy_from_slice(&constants::CURVE_ORDER[..]);
        wild_msgs[1][..].copy_from_slice(&constants::CURVE_ORDER[..]);

        wild_keys[1][0] -= 1;
        wild_msgs[1][0] -= 1;

        for key in wild_keys.iter().map(|k| SecretKey::from_slice(&k[..]).unwrap()) {
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
        let sig = sigr.to_standard();

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
        let sig = RecoverableSignature::from_compact(&[0; 64], RecoveryId(0)).unwrap();
        assert_eq!(s.recover(&msg, &sig), Err(InvalidSignature));
        // ...but 111..111 is
        let sig = RecoverableSignature::from_compact(&[1; 64], RecoveryId(0)).unwrap();
        assert!(s.recover(&msg, &sig).is_ok());
    }

    #[test]
    fn test_bad_slice() {
        assert_eq!(Signature::from_der(&[0; constants::MAX_SIGNATURE_SIZE + 1]),
                   Err(InvalidSignature));
        assert_eq!(Signature::from_der(&[0; constants::MAX_SIGNATURE_SIZE]),
                   Err(InvalidSignature));

        assert_eq!(Message::from_slice(&[0; constants::MESSAGE_SIZE - 1]),
                   Err(InvalidMessage));
        assert_eq!(Message::from_slice(&[0; constants::MESSAGE_SIZE + 1]),
                   Err(InvalidMessage));
        assert_eq!(
            Message::from_slice(&[0; constants::MESSAGE_SIZE]),
            Err(InvalidMessage)
        );
        assert!(Message::from_slice(&[1; constants::MESSAGE_SIZE]).is_ok());
    }

    #[test]
    fn test_debug_output() {
        let sig = RecoverableSignature::from_compact(&[
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
            bytes_in,
            recid_in,
        ).unwrap();
        let (recid_out, bytes_out) = sig.serialize_compact();
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
        let mut sig = Signature::from_der(&sig[..]).unwrap();
        let pk = PublicKey::from_slice(&pk[..]).unwrap();
        let msg = Message::from_slice(&msg[..]).unwrap();

        // without normalization we expect this will fail
        assert_eq!(secp.verify(&msg, &sig, &pk), Err(IncorrectSignature));
        // after normalization it should pass
        sig.normalize_s();
        assert_eq!(secp.verify(&msg, &sig, &pk), Ok(()));
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_signature_serde() {
        use serde_test::{Token, assert_tokens};

        let s = Secp256k1::new();

        let msg = Message::from_slice(&[1; 32]).unwrap();
        let sk = SecretKey::from_slice(&[2; 32]).unwrap();
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

