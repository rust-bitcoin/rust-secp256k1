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
//! failure and terminate the program. In `rust-secp256k1`, this is caught
//! at compile-time; in fact, it is impossible to compile code that will
//! trigger any assertion failures in the upstream library.
//!
//! ```rust
//! # #[cfg(all(feature="rand", feature="bitcoin_hashes"))] {
//! use secp256k1::rand::rngs::OsRng;
//! use secp256k1::{Secp256k1, Message};
//! use secp256k1::bitcoin_hashes::sha256;
//!
//! let secp = Secp256k1::new();
//! let mut rng = OsRng::new().expect("OsRng");
//! let (secret_key, public_key) = secp.generate_keypair(&mut rng);
//! let message = Message::from_hashed_data::<sha256::Hash>("Hello World!".as_bytes());
//!
//! let sig = secp.sign(&message, &secret_key);
//! assert!(secp.verify(&message, &sig, &public_key).is_ok());
//! # }
//! ```
//!
//! The above code requires `rust-secp256k1` to be compiled with the `rand` and `bitcoin_hashes`
//! feature enabled, to get access to [`generate_keypair`](struct.Secp256k1.html#method.generate_keypair)
//! Alternately, keys and messages can be parsed from slices, like
//!
//! ```rust
//! use self::secp256k1::{Secp256k1, Message, SecretKey, PublicKey};
//!
//! let secp = Secp256k1::new();
//! let secret_key = SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order");
//! let public_key = PublicKey::from_secret_key(&secp, &secret_key);
//! // This is unsafe unless the supplied byte slice is the output of a cryptographic hash function.
//! // See the above example for how to use this library together with bitcoin_hashes.
//! let message = Message::from_slice(&[0xab; 32]).expect("32 bytes");
//!
//! let sig = secp.sign(&message, &secret_key);
//! assert!(secp.verify(&message, &sig, &public_key).is_ok());
//! ```
//!
//! Users who only want to verify signatures can use a cheaper context, like so:
//!
//! ```rust
//! use secp256k1::{Secp256k1, Message, Signature, PublicKey};
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
//! # #[cfg(not(fuzzing))]
//! assert!(secp.verify(&message, &sig, &public_key).is_ok());
//! ```
//!
//! Observe that the same code using, say [`signing_only`](struct.Secp256k1.html#method.signing_only)
//! to generate a context would simply not compile.
//!

// Coding conventions
#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
#![warn(missing_docs)]


#![cfg_attr(all(not(test), not(feature = "std")), no_std)]
#![cfg_attr(all(test, feature = "unstable"), feature(test))]

#[macro_use]
pub extern crate secp256k1_sys;
pub use secp256k1_sys as ffi;

#[cfg(feature = "bitcoin_hashes")] pub extern crate bitcoin_hashes;
#[cfg(all(test, feature = "unstable"))] extern crate test;
#[cfg(any(test, feature = "rand"))] pub extern crate rand;
#[cfg(any(test))] extern crate rand_core;
#[cfg(feature = "serde")] pub extern crate serde;
#[cfg(all(test, feature = "serde"))] extern crate serde_test;
#[cfg(any(test, feature = "rand"))] use rand::Rng;
#[cfg(any(test, feature = "std"))] extern crate core;
#[cfg(all(test, target_arch = "wasm32"))] extern crate wasm_bindgen_test;
#[cfg(feature = "alloc")] extern crate alloc;

use core::{fmt, ptr, str};

#[macro_use]
mod macros;
mod context;
pub mod constants;
pub mod ecdh;
pub mod key;
pub mod schnorrsig;
#[cfg(feature = "recovery")]
pub mod recovery;
#[cfg(feature = "serde")]
mod serde_util;

pub use key::SecretKey;
pub use key::PublicKey;
pub use context::*;
use core::marker::PhantomData;
use core::ops::Deref;
use core::mem;
use ffi::{CPtr, types::AlignedType};

#[cfg(feature = "global-context-less-secure")]
pub use context::global::SECP256K1;

#[cfg(feature = "bitcoin_hashes")]
use bitcoin_hashes::Hash;

/// An ECDSA signature
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct Signature(ffi::Signature);

/// A DER serialized Signature
#[derive(Copy, Clone)]
pub struct SerializedSignature {
    data: [u8; 72],
    len: usize,
}

impl fmt::Debug for Signature {
fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    fmt::Display::fmt(self, f)
}
}

impl fmt::Display for Signature {
fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    let sig = self.serialize_der();
    for v in sig.iter() {
        write!(f, "{:02x}", v)?;
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

/// Trait describing something that promises to be a 32-byte random number; in particular,
/// it has negligible probability of being zero or overflowing the group order. Such objects
/// may be converted to `Message`s without any error paths.
pub trait ThirtyTwoByteHash {
    /// Converts the object into a 32-byte array
    fn into_32(self) -> [u8; 32];
}

#[cfg(feature = "bitcoin_hashes")]
impl ThirtyTwoByteHash for bitcoin_hashes::sha256::Hash {
    fn into_32(self) -> [u8; 32] {
        self.into_inner()
    }
}

#[cfg(feature = "bitcoin_hashes")]
impl ThirtyTwoByteHash for bitcoin_hashes::sha256d::Hash {
    fn into_32(self) -> [u8; 32] {
        self.into_inner()
    }
}

#[cfg(feature = "bitcoin_hashes")]
impl<T: bitcoin_hashes::sha256t::Tag> ThirtyTwoByteHash for bitcoin_hashes::sha256t::Hash<T> {
    fn into_32(self) -> [u8; 32] {
        self.into_inner()
    }
}

impl SerializedSignature {
    /// Get a pointer to the underlying data with the specified capacity.
    pub(crate) fn get_data_mut_ptr(&mut self) -> *mut u8 {
        self.data.as_mut_ptr()
    }

    /// Get the capacity of the underlying data buffer.
    pub fn capacity(&self) -> usize {
        self.data.len()
    }

    /// Get the len of the used data.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Set the length of the object.
    pub(crate) fn set_len(&mut self, len: usize) {
        self.len = len;
    }

    /// Convert the serialized signature into the Signature struct.
    /// (This DER deserializes it)
    pub fn to_signature(&self) -> Result<Signature, Error> {
        Signature::from_der(&self)
    }

    /// Create a SerializedSignature from a Signature.
    /// (this DER serializes it)
    pub fn from_signature(sig: &Signature) -> SerializedSignature {
        sig.serialize_der()
    }

    /// Check if the space is zero.
    pub fn is_empty(&self) -> bool { self.len() == 0 }
}

impl Signature {
#[inline]
    /// Converts a DER-encoded byte slice to a signature
    pub fn from_der(data: &[u8]) -> Result<Signature, Error> {
        if data.is_empty() {return Err(Error::InvalidSignature);}

        unsafe {
            let mut ret = ffi::Signature::new();
            if ffi::secp256k1_ecdsa_signature_parse_der(
                ffi::secp256k1_context_no_precomp,
                &mut ret,
                data.as_c_ptr(),
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
        if data.len() != 64 {
            return Err(Error::InvalidSignature)
        }

        unsafe {
            let mut ret = ffi::Signature::new();
            if ffi::secp256k1_ecdsa_signature_parse_compact(
                ffi::secp256k1_context_no_precomp,
                &mut ret,
                data.as_c_ptr(),
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
        if data.is_empty() {return Err(Error::InvalidSignature);}

        unsafe {
            let mut ret = ffi::Signature::new();
            if ffi::ecdsa_signature_parse_der_lax(
                ffi::secp256k1_context_no_precomp,
                &mut ret,
                data.as_c_ptr(),
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
                self.as_mut_c_ptr(),
                self.as_c_ptr(),
            );
        }
    }

    /// Obtains a raw pointer suitable for use with FFI functions
    #[inline]
    pub fn as_ptr(&self) -> *const ffi::Signature {
        &self.0
    }

    /// Obtains a raw mutable pointer suitable for use with FFI functions
    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut ffi::Signature {
        &mut self.0
    }

    #[inline]
    /// Serializes the signature in DER format
    pub fn serialize_der(&self) -> SerializedSignature {
        let mut ret = SerializedSignature::default();
        let mut len: usize = ret.capacity();
        unsafe {
            let err = ffi::secp256k1_ecdsa_signature_serialize_der(
                ffi::secp256k1_context_no_precomp,
                ret.get_data_mut_ptr(),
                &mut len,
                self.as_c_ptr(),
            );
            debug_assert!(err == 1);
            ret.set_len(len);
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
                ret.as_mut_c_ptr(),
                self.as_c_ptr(),
            );
            debug_assert!(err == 1);
        }
        ret
    }
}

impl CPtr for Signature {
    type Target = ffi::Signature;
    fn as_c_ptr(&self) -> *const Self::Target {
        self.as_ptr()
    }

    fn as_mut_c_ptr(&mut self) -> *mut Self::Target {
        self.as_mut_ptr()
    }
}

/// Creates a new signature from a FFI signature
impl From<ffi::Signature> for Signature {
    #[inline]
    fn from(sig: ffi::Signature) -> Signature {
        Signature(sig)
    }
}


#[cfg(feature = "serde")]
impl ::serde::Serialize for Signature {
    fn serialize<S: ::serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.collect_str(self)
        } else {
            s.serialize_bytes(&self.serialize_der())
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> ::serde::Deserialize<'de> for Signature {
    fn deserialize<D: ::serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        if d.is_human_readable() {
            d.deserialize_str(serde_util::FromStrVisitor::new(
                "a hex string representing a DER encoded Signature"
            ))
        } else {
            d.deserialize_bytes(serde_util::BytesVisitor::new(
                "raw byte stream, that represents a DER encoded Signature",
                Signature::from_der
            ))
        }
    }
}

/// A (hashed) message input to an ECDSA signature
pub struct Message([u8; constants::MESSAGE_SIZE]);
impl_array_newtype!(Message, u8, constants::MESSAGE_SIZE);
impl_pretty_debug!(Message);

impl Message {
    /// **If you just want to sign an arbitrary message use `Message::from_hashed_data` instead.**
    ///
    /// Converts a `MESSAGE_SIZE`-byte slice to a message object. **WARNING:** the slice has to be a
    /// cryptographically secure hash of the actual message that's going to be signed. Otherwise
    /// the result of signing isn't a
    /// [secure signature](https://twitter.com/pwuille/status/1063582706288586752).
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

    /// Constructs a `Message` by hashing `data` with hash algorithm `H`. This requires the feature
    /// `bitcoin_hashes` to be enabled.
    /// ```rust
    /// extern crate bitcoin_hashes;
    /// # extern crate secp256k1;
    /// use secp256k1::Message;
    /// use bitcoin_hashes::sha256;
    /// use bitcoin_hashes::Hash;
    ///
    /// let m1 = Message::from_hashed_data::<sha256::Hash>("Hello world!".as_bytes());
    /// // is equivalent to
    /// let m2 = Message::from(sha256::Hash::hash("Hello world!".as_bytes()));
    ///
    /// assert_eq!(m1, m2);
    /// ```
    #[cfg(feature = "bitcoin_hashes")]
    pub fn from_hashed_data<H: ThirtyTwoByteHash + bitcoin_hashes::Hash>(data: &[u8]) -> Self {
        <H as bitcoin_hashes::Hash>::hash(data).into()
    }
}

impl<T: ThirtyTwoByteHash> From<T> for Message {
    /// Converts a 32-byte hash directly to a message without error paths
    fn from(t: T) -> Message {
        Message(t.into_32())
    }
}

/// An ECDSA error
#[derive(Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Debug)]
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
    /// `tweak_add_check` failed on an xonly public key
    TweakCheckFailed,
    /// Didn't pass enough memory to context creation with preallocated memory
    NotEnoughMemory,
}

impl Error {
    fn as_str(&self) -> &str {
        match *self {
            Error::IncorrectSignature => "secp: signature failed verification",
            Error::InvalidMessage => "secp: message was not 32 bytes (do you need to hash?)",
            Error::InvalidPublicKey => "secp: malformed public key",
            Error::InvalidSignature => "secp: malformed signature",
            Error::InvalidSecretKey => "secp: malformed or out-of-range secret key",
            Error::InvalidRecoveryId => "secp: bad recovery id",
            Error::InvalidTweak => "secp: bad tweak",
            Error::TweakCheckFailed => "secp: xonly_pubkey_tewak_add_check failed",
            Error::NotEnoughMemory => "secp: not enough memory allocated",
        }
    }
}

// Passthrough Debug to Display, since errors should be user-visible
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        f.write_str(self.as_str())
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}


/// The secp256k1 engine, used to execute all signature operations
pub struct Secp256k1<C: Context> {
    ctx: *mut ffi::Context,
    phantom: PhantomData<C>,
    size: usize,
}

// The underlying secp context does not contain any references to memory it does not own
unsafe impl<C: Context> Send for Secp256k1<C> {}
// The API does not permit any mutation of `Secp256k1` objects except through `&mut` references
unsafe impl<C: Context> Sync for Secp256k1<C> {}


impl<C: Context> PartialEq for Secp256k1<C> {
    fn eq(&self, _other: &Secp256k1<C>) -> bool { true }
}

impl Default for SerializedSignature {
    fn default() -> SerializedSignature {
        SerializedSignature {
            data: [0u8; 72],
            len: 0,
        }
    }
}

impl PartialEq for SerializedSignature {
    fn eq(&self, other: &SerializedSignature) -> bool {
        self.data[..self.len] == other.data[..other.len]
    }
}

impl AsRef<[u8]> for SerializedSignature {
    fn as_ref(&self) -> &[u8] {
        &self.data[..self.len]
    }
}

impl Deref for SerializedSignature {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.data[..self.len]
    }
}

impl Eq for SerializedSignature {}

impl<C: Context> Eq for Secp256k1<C> { }

impl<C: Context> Drop for Secp256k1<C> {
    fn drop(&mut self) {
        unsafe {
            ffi::secp256k1_context_preallocated_destroy(self.ctx);
            C::deallocate(self.ctx as _, self.size);
        }
    }
}

impl<C: Context> fmt::Debug for Secp256k1<C> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "<secp256k1 context {:?}, {}>", self.ctx, C::DESCRIPTION)
    }
}

impl<C: Context> Secp256k1<C> {

    /// Getter for the raw pointer to the underlying secp256k1 context. This
    /// shouldn't be needed with normal usage of the library. It enables
    /// extending the Secp256k1 with more cryptographic algorithms outside of
    /// this crate.
    pub fn ctx(&self) -> &*mut ffi::Context {
        &self.ctx
    }

    /// Returns the required memory for a preallocated context buffer in a generic manner(sign/verify/all)
    pub fn preallocate_size_gen() -> usize {
        let word_size = mem::size_of::<AlignedType>();
        let bytes = unsafe { ffi::secp256k1_context_preallocated_size(C::FLAGS) };

        (bytes + word_size - 1) / word_size
    }

    /// (Re)randomizes the Secp256k1 context for cheap sidechannel resistance;
    /// see comment in libsecp256k1 commit d2275795f by Gregory Maxwell. Requires
    /// compilation with "rand" feature.
    #[cfg(any(test, feature = "rand"))]
    pub fn randomize<R: Rng + ?Sized>(&mut self, rng: &mut R) {
        let mut seed = [0; 32];
        rng.fill_bytes(&mut seed);
        self.seeded_randomize(&seed);
    }

    /// (Re)randomizes the Secp256k1 context for cheap sidechannel resistance given 32 bytes of
    /// cryptographically-secure random data;
    /// see comment in libsecp256k1 commit d2275795f by Gregory Maxwell.
    pub fn seeded_randomize(&mut self, seed: &[u8; 32]) {
        unsafe {
            let err = ffi::secp256k1_context_randomize(self.ctx, seed.as_c_ptr());
            // This function cannot fail; it has an error return for future-proofing.
            // We do not expose this error since it is impossible to hit, and we have
            // precedent for not exposing impossible errors (for example in
            // `PublicKey::from_secret_key` where it is impossible to create an invalid
            // secret key through the API.)
            // However, if this DOES fail, the result is potentially weaker side-channel
            // resistance, which is deadly and undetectable, so we take out the entire
            // thread to be on the safe side.
            assert_eq!(err, 1);
        }
    }
}

fn der_length_check(sig: &ffi::Signature, max_len: usize) -> bool {
    let mut ser_ret = [0; 72];
    let mut len: usize = ser_ret.len();
    unsafe {
        let err = ffi::secp256k1_ecdsa_signature_serialize_der(
            ffi::secp256k1_context_no_precomp,
            ser_ret.as_mut_c_ptr(),
            &mut len,
            sig,
        );
        debug_assert!(err == 1);
    }
    len <= max_len
}

fn compact_sig_has_zero_first_bit(sig: &ffi::Signature) -> bool {
    let mut compact = [0; 64];
    unsafe {
        let err = ffi::secp256k1_ecdsa_signature_serialize_compact(
            ffi::secp256k1_context_no_precomp,
            compact.as_mut_c_ptr(),
            sig,
        );
        debug_assert!(err == 1);
    }
    compact[0] < 0x80
}

impl<C: Signing> Secp256k1<C> {

    /// Constructs a signature for `msg` using the secret key `sk` and RFC6979 nonce
    /// Requires a signing-capable context.
    pub fn sign(&self, msg: &Message, sk: &key::SecretKey)
                -> Signature {

        unsafe {
            let mut ret = ffi::Signature::new();
            // We can assume the return value because it's not possible to construct
            // an invalid signature from a valid `Message` and `SecretKey`
            assert_eq!(ffi::secp256k1_ecdsa_sign(self.ctx, &mut ret, msg.as_c_ptr(),
                                                 sk.as_c_ptr(), ffi::secp256k1_nonce_function_rfc6979,
                                                 ptr::null()), 1);
            Signature::from(ret)
        }
    }

    fn sign_grind_with_check(
        &self, msg: &Message,
        sk: &key::SecretKey,
        check: impl Fn(&ffi::Signature) -> bool) -> Signature {
            let mut entropy_p : *const ffi::types::c_void = ptr::null();
            let mut counter : u32 = 0;
            let mut extra_entropy = [0u8; 32];
            loop {
                unsafe {
                    let mut ret = ffi::Signature::new();
                    // We can assume the return value because it's not possible to construct
                    // an invalid signature from a valid `Message` and `SecretKey`
                    assert_eq!(ffi::secp256k1_ecdsa_sign(self.ctx, &mut ret, msg.as_c_ptr(),
                                                        sk.as_c_ptr(), ffi::secp256k1_nonce_function_rfc6979,
                                                        entropy_p), 1);
                    if check(&ret) {
                        return Signature::from(ret);
                    }

                    counter += 1;
                    // From 1.32 can use `to_le_bytes` instead
                    let le_counter = counter.to_le();
                    let le_counter_bytes : [u8; 4] = mem::transmute(le_counter);
                    for (i, b) in le_counter_bytes.iter().enumerate() {
                        extra_entropy[i] = *b;
                    }

                    entropy_p = extra_entropy.as_ptr() as *const ffi::types::c_void;

                    // When fuzzing, these checks will usually spinloop forever, so just short-circuit them.
                    #[cfg(fuzzing)]
                    return Signature::from(ret);
                }
            }
    }

    /// Constructs a signature for `msg` using the secret key `sk`, RFC6979 nonce
    /// and "grinds" the nonce by passing extra entropy if necessary to produce
    /// a signature that is less than 71 - bytes_to_grund bytes. The number
    /// of signing operation performed by this function is exponential in the
    /// number of bytes grinded.
    /// Requires a signing capable context.
    pub fn sign_grind_r(&self, msg: &Message, sk: &key::SecretKey, bytes_to_grind: usize) -> Signature {
        let len_check = |s : &ffi::Signature| der_length_check(s, 71 - bytes_to_grind);
        return self.sign_grind_with_check(msg, sk, len_check);
    }

    /// Constructs a signature for `msg` using the secret key `sk`, RFC6979 nonce
    /// and "grinds" the nonce by passing extra entropy if necessary to produce
    /// a signature that is less than 71 bytes and compatible with the low r
    /// signature implementation of bitcoin core. In average, this function
    /// will perform two signing operations.
    /// Requires a signing capable context.
    pub fn sign_low_r(&self, msg: &Message, sk: &key::SecretKey) -> Signature {
        return self.sign_grind_with_check(msg, sk, compact_sig_has_zero_first_bit)
    }

    /// Generates a random keypair. Convenience function for `key::SecretKey::new`
    /// and `key::PublicKey::from_secret_key`; call those functions directly for
    /// batch key generation. Requires a signing-capable context. Requires compilation
    /// with the "rand" feature.
    #[inline]
    #[cfg(any(test, feature = "rand"))]
    pub fn generate_keypair<R: Rng + ?Sized>(&self, rng: &mut R)
                                    -> (key::SecretKey, key::PublicKey) {
        let sk = key::SecretKey::new(rng);
        let pk = key::PublicKey::from_secret_key(self, &sk);
        (sk, pk)
    }
}

impl<C: Verification> Secp256k1<C> {
    /// Checks that `sig` is a valid ECDSA signature for `msg` using the public
    /// key `pubkey`. Returns `Ok(())` on success. Note that this function cannot
    /// be used for Bitcoin consensus checking since there may exist signatures
    /// which OpenSSL would verify but not libsecp256k1, or vice-versa. Requires a
    /// verify-capable context.
    ///
    /// ```rust
    /// # #[cfg(feature="rand")] {
    /// # use secp256k1::rand::rngs::OsRng;
    /// # use secp256k1::{Secp256k1, Message, Error};
    /// #
    /// # let secp = Secp256k1::new();
    /// # let mut rng = OsRng::new().expect("OsRng");
    /// # let (secret_key, public_key) = secp.generate_keypair(&mut rng);
    /// #
    /// let message = Message::from_slice(&[0xab; 32]).expect("32 bytes");
    /// let sig = secp.sign(&message, &secret_key);
    /// assert_eq!(secp.verify(&message, &sig, &public_key), Ok(()));
    ///
    /// let message = Message::from_slice(&[0xcd; 32]).expect("32 bytes");
    /// assert_eq!(secp.verify(&message, &sig, &public_key), Err(Error::IncorrectSignature));
    /// # }
    /// ```
    #[inline]
    pub fn verify(&self, msg: &Message, sig: &Signature, pk: &key::PublicKey) -> Result<(), Error> {
        unsafe {
            if ffi::secp256k1_ecdsa_verify(self.ctx, sig.as_c_ptr(), msg.as_c_ptr(), pk.as_c_ptr()) == 0 {
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
            b'A'..=b'F' => b |= c - b'A' + 10,
            b'a'..=b'f' => b |= c - b'a' + 10,
            b'0'..=b'9' => b |= c - b'0',
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
    use rand::{RngCore, thread_rng};
    use std::str::FromStr;
    use std::marker::PhantomData;

    use key::{SecretKey, PublicKey};
    use super::from_hex;
    use super::constants;
    use super::{Secp256k1, Signature, Message};
    use super::Error::{InvalidMessage, IncorrectSignature, InvalidSignature};
    use ffi::{self, types::AlignedType};
    use context::*;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    macro_rules! hex {
        ($hex:expr) => ({
            let mut result = vec![0; $hex.len() / 2];
            from_hex($hex, &mut result).expect("valid hex string");
            result
        });
    }


    #[test]
    fn test_manual_create_destroy() {
        let ctx_full = unsafe { ffi::secp256k1_context_create(AllPreallocated::FLAGS) };
        let ctx_sign = unsafe { ffi::secp256k1_context_create(SignOnlyPreallocated::FLAGS) };
        let ctx_vrfy = unsafe { ffi::secp256k1_context_create(VerifyOnlyPreallocated::FLAGS) };

        let size = 0;
        let full: Secp256k1<AllPreallocated> = Secp256k1{ctx: ctx_full, phantom: PhantomData, size};
        let sign: Secp256k1<SignOnlyPreallocated> = Secp256k1{ctx: ctx_sign, phantom: PhantomData, size};
        let vrfy: Secp256k1<VerifyOnlyPreallocated> = Secp256k1{ctx: ctx_vrfy, phantom: PhantomData, size};

        let (sk, pk) = full.generate_keypair(&mut thread_rng());
        let msg = Message::from_slice(&[2u8; 32]).unwrap();
        // Try signing
        assert_eq!(sign.sign(&msg, &sk), full.sign(&msg, &sk));
        let sig = full.sign(&msg, &sk);

        // Try verifying
        assert!(vrfy.verify(&msg, &sig, &pk).is_ok());
        assert!(full.verify(&msg, &sig, &pk).is_ok());

        drop(full);drop(sign);drop(vrfy);

        unsafe { ffi::secp256k1_context_destroy(ctx_vrfy) };
        unsafe { ffi::secp256k1_context_destroy(ctx_sign) };
        unsafe { ffi::secp256k1_context_destroy(ctx_full) };
    }

    #[test]
    fn test_raw_ctx() {
        use std::mem::ManuallyDrop;

        let ctx_full = Secp256k1::new();
        let ctx_sign = Secp256k1::signing_only();
        let ctx_vrfy = Secp256k1::verification_only();

        let mut full = unsafe {Secp256k1::from_raw_all(ctx_full.ctx)};
        let mut sign = unsafe {Secp256k1::from_raw_signining_only(ctx_sign.ctx)};
        let mut vrfy = unsafe {Secp256k1::from_raw_verification_only(ctx_vrfy.ctx)};

        let (sk, pk) = full.generate_keypair(&mut thread_rng());
        let msg = Message::from_slice(&[2u8; 32]).unwrap();
        // Try signing
        assert_eq!(sign.sign(&msg, &sk), full.sign(&msg, &sk));
        let sig = full.sign(&msg, &sk);

        // Try verifying
        assert!(vrfy.verify(&msg, &sig, &pk).is_ok());
        assert!(full.verify(&msg, &sig, &pk).is_ok());

        unsafe {
            ManuallyDrop::drop(&mut full);
            ManuallyDrop::drop(&mut sign);
            ManuallyDrop::drop(&mut vrfy);

        }
        drop(ctx_full);
        drop(ctx_sign);
        drop(ctx_vrfy);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    #[ignore] // Panicking from C may trap (SIGILL) intentionally, so we test this manually.
    fn test_panic_raw_ctx_should_terminate_abnormally() {
        let ctx_vrfy = Secp256k1::verification_only();
        let raw_ctx_verify_as_full = unsafe {Secp256k1::from_raw_all(ctx_vrfy.ctx)};
        // Generating a key pair in verify context will panic (ARG_CHECK).
        raw_ctx_verify_as_full.generate_keypair(&mut thread_rng());
    }

    #[test]
    fn test_preallocation() {
        let mut buf_ful = vec![AlignedType::zeroed(); Secp256k1::preallocate_size()];
        let mut buf_sign = vec![AlignedType::zeroed(); Secp256k1::preallocate_signing_size()];
        let mut buf_vfy = vec![AlignedType::zeroed(); Secp256k1::preallocate_verification_size()];

        let full = Secp256k1::preallocated_new(&mut buf_ful).unwrap();
        let sign = Secp256k1::preallocated_signing_only(&mut buf_sign).unwrap();
        let vrfy = Secp256k1::preallocated_verification_only(&mut buf_vfy).unwrap();

//        drop(buf_vfy); // The buffer can't get dropped before the context.
//        println!("{:?}", buf_ful[5]); // Can't even read the data thanks to the borrow checker.

        let (sk, pk) = full.generate_keypair(&mut thread_rng());
        let msg = Message::from_slice(&[2u8; 32]).unwrap();
        // Try signing
        assert_eq!(sign.sign(&msg, &sk), full.sign(&msg, &sk));
        let sig = full.sign(&msg, &sk);

        // Try verifying
        assert!(vrfy.verify(&msg, &sig, &pk).is_ok());
        assert!(full.verify(&msg, &sig, &pk).is_ok());
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
        let sig = full.sign(&msg, &sk);

        // Try verifying
        assert!(vrfy.verify(&msg, &sig, &pk).is_ok());
        assert!(full.verify(&msg, &sig, &pk).is_ok());

        // Check that we can produce keys from slices with no precomputation
        let (pk_slice, sk_slice) = (&pk.serialize(), &sk[..]);
        let new_pk = PublicKey::from_slice(pk_slice).unwrap();
        let new_sk = SecretKey::from_slice(sk_slice).unwrap();
        assert_eq!(sk, new_sk);
        assert_eq!(pk, new_pk);
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

        // 71 byte signature
        let hex_str = "30450221009d0bad576719d32ae76bedb34c774866673cbde3f4e12951555c9408e6ce774b02202876e7102f204f6bfee26c967c3926ce702cf97d4b010062e193f763190f6776";
        let sig = Signature::from_str(&hex_str).expect("byte str decode");
        assert_eq!(&format!("{}", sig), hex_str);
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
            let low_r_sig = s.sign_low_r(&msg, &sk);
            assert_eq!(s.verify(&msg, &low_r_sig, &pk), Ok(()));
            let grind_r_sig = s.sign_grind_r(&msg, &sk, 1);
            assert_eq!(s.verify(&msg, &grind_r_sig, &pk), Ok(()));
            let compact = sig.serialize_compact();
            if compact[0] < 0x80 {
                assert_eq!(sig, low_r_sig);
            } else {
                #[cfg(not(fuzzing))]  // mocked sig generation doesn't produce low-R sigs
                assert_ne!(sig, low_r_sig);
            }
            #[cfg(not(fuzzing))]  // mocked sig generation doesn't produce low-R sigs
            assert!(super::compact_sig_has_zero_first_bit(&low_r_sig.0));
            #[cfg(not(fuzzing))]  // mocked sig generation doesn't produce low-R sigs
            assert!(super::der_length_check(&grind_r_sig.0, 70));
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
                let low_r_sig = s.sign_low_r(&msg, &key);
                let grind_r_sig = s.sign_grind_r(&msg, &key, 1);
                let pk = PublicKey::from_secret_key(&s, &key);
                assert_eq!(s.verify(&msg, &sig, &pk), Ok(()));
                assert_eq!(s.verify(&msg, &low_r_sig, &pk), Ok(()));
                assert_eq!(s.verify(&msg, &grind_r_sig, &pk), Ok(()));
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

        let sig = s.sign(&msg, &sk);

        let mut msg = [0u8; 32];
        thread_rng().fill_bytes(&mut msg);
        let msg = Message::from_slice(&msg).unwrap();
        assert_eq!(s.verify(&msg, &sig, &pk), Err(IncorrectSignature));
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
        assert!(Message::from_slice(&[0; constants::MESSAGE_SIZE]).is_ok());
        assert!(Message::from_slice(&[1; constants::MESSAGE_SIZE]).is_ok());
    }

    #[test]
    #[cfg(not(fuzzing))]  // fixed sig vectors can't work with fuzz-sigs
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

    #[test]
    #[cfg(not(fuzzing))]  // fuzz-sigs have fixed size/format
    fn test_low_r() {
        let secp = Secp256k1::new();
        let msg = hex!("887d04bb1cf1b1554f1b268dfe62d13064ca67ae45348d50d1392ce2d13418ac");
        let msg = Message::from_slice(&msg).unwrap();
        let sk = SecretKey::from_str("57f0148f94d13095cfda539d0da0d1541304b678d8b36e243980aab4e1b7cead").unwrap();
        let expected_sig = hex!("047dd4d049db02b430d24c41c7925b2725bcd5a85393513bdec04b4dc363632b1054d0180094122b380f4cfa391e6296244da773173e78fc745c1b9c79f7b713");
        let expected_sig = Signature::from_compact(&expected_sig).unwrap();

        let sig = secp.sign_low_r(&msg, &sk);

        assert_eq!(expected_sig, sig);
    }

    #[test]
    #[cfg(not(fuzzing))]  // fuzz-sigs have fixed size/format
    fn test_grind_r() {
        let secp = Secp256k1::new();
        let msg = hex!("ef2d5b9a7c61865a95941d0f04285420560df7e9d76890ac1b8867b12ce43167");
        let msg = Message::from_slice(&msg).unwrap();
        let sk = SecretKey::from_str("848355d75fe1c354cf05539bb29b2015f1863065bcb6766b44d399ab95c3fa0b").unwrap();
        let expected_sig = Signature::from_str("304302202ffc447100d518c8ba643d11f3e6a83a8640488e7d2537b1954b942408be6ea3021f26e1248dd1e52160c3a38af9769d91a1a806cab5f9d508c103464d3c02d6e1").unwrap();

        let sig = secp.sign_grind_r(&msg, &sk, 2);

        assert_eq!(expected_sig, sig);
    }

    #[cfg(feature = "serde")]
    #[cfg(not(fuzzing))]  // fixed sig vectors can't work with fuzz-sigs
    #[test]
    fn test_serde() {
        use serde_test::{Configure, Token, assert_tokens};

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
        static SIG_STR: &'static str = "\
            30450221009d0bad576719d32ae76bedb34c774866673cbde3f4e12951555c9408e6ce77\
            4b02202876e7102f204f6bfee26c967c3926ce702cf97d4b010062e193f763190f6776\
        ";

        assert_tokens(&sig.compact(), &[Token::BorrowedBytes(&SIG_BYTES[..])]);
        assert_tokens(&sig.compact(), &[Token::Bytes(&SIG_BYTES)]);
        assert_tokens(&sig.compact(), &[Token::ByteBuf(&SIG_BYTES)]);

        assert_tokens(&sig.readable(), &[Token::BorrowedStr(SIG_STR)]);
        assert_tokens(&sig.readable(), &[Token::Str(SIG_STR)]);
        assert_tokens(&sig.readable(), &[Token::String(SIG_STR)]);

    }

    #[cfg(feature = "global-context-less-secure")]
    #[test]
    fn test_global_context() {
        use super::SECP256K1;

        let sk_data = hex!("e6dd32f8761625f105c39a39f19370b3521d845a12456d60ce44debd0a362641");
        let sk = SecretKey::from_slice(&sk_data).unwrap();
        let msg_data = hex!("a4965ca63b7d8562736ceec36dfa5a11bf426eb65be8ea3f7a49ae363032da0d");
        let msg = Message::from_slice(&msg_data).unwrap();

        // Check usage as explicit parameter
        let pk = PublicKey::from_secret_key(&SECP256K1, &sk);

        // Check usage as self
        let sig = SECP256K1.sign(&msg, &sk);
        assert!(SECP256K1.verify(&msg, &sig, &pk).is_ok());
    }

    #[cfg(feature = "bitcoin_hashes")]
    #[test]
    fn test_from_hash() {
        use bitcoin_hashes;
        use bitcoin_hashes::Hash;

        let test_bytes = "Hello world!".as_bytes();

        let hash = bitcoin_hashes::sha256::Hash::hash(test_bytes);
        let msg = Message::from(hash);
        assert_eq!(msg.0, hash.into_inner());
        assert_eq!(
            msg,
            Message::from_hashed_data::<bitcoin_hashes::sha256::Hash>(test_bytes)
        );

        let hash = bitcoin_hashes::sha256d::Hash::hash(test_bytes);
        let msg = Message::from(hash);
        assert_eq!(msg.0, hash.into_inner());
        assert_eq!(
            msg,
            Message::from_hashed_data::<bitcoin_hashes::sha256d::Hash>(test_bytes)
        );
    }
}

#[cfg(all(test, feature = "unstable"))]
mod benches {
    use rand::{thread_rng, RngCore};
    use test::{Bencher, black_box};

    use super::{Secp256k1, Message};

    #[bench]
    pub fn generate(bh: &mut Bencher) {
        struct CounterRng(u64);
        impl RngCore for CounterRng {
            fn next_u32(&mut self) -> u32 {
                self.next_u64() as u32
            }

            fn next_u64(&mut self) -> u64 {
                self.0 += 1;
                self.0
            }

            fn fill_bytes(&mut self, dest: &mut [u8]) {
                for chunk in dest.chunks_mut(64/8) {
                    let rand: [u8; 64/8] = unsafe {std::mem::transmute(self.next_u64())};
                    chunk.copy_from_slice(&rand[..chunk.len()]);
                }
            }

            fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
                Ok(self.fill_bytes(dest))
            }
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
}
