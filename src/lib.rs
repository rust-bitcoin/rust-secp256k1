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
//! use secp256k1::hashes::sha256;
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
//! use secp256k1::{Secp256k1, Message, ecdsa::Signature, PublicKey};
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

#[cfg(feature = "bitcoin_hashes")] pub extern crate bitcoin_hashes as hashes;
#[cfg(all(test, feature = "unstable"))] extern crate test;
#[cfg(any(test, feature = "rand"))] pub extern crate rand;
#[cfg(any(test))] extern crate rand_core;
#[cfg(feature = "serde")] pub extern crate serde;
#[cfg(all(test, feature = "serde"))] extern crate serde_test;
#[cfg(any(test, feature = "std"))] extern crate core;
#[cfg(all(test, target_arch = "wasm32"))] extern crate wasm_bindgen_test;
#[cfg(feature = "alloc")] extern crate alloc;

use core::{fmt, str};

#[cfg(test)]
#[macro_export]
/// Macro for test purposes
macro_rules! hex {
    ($hex:expr) => ({
        let mut result = vec![0; $hex.len() / 2];
        from_hex($hex, &mut result).expect("valid hex string");
        result
    });
}

#[macro_use]
mod macros;
mod context;
pub mod constants;
pub mod ecdh;
pub mod key;
pub mod ecdsa;
pub mod schnorr;
#[cfg(feature = "recovery")]
pub mod recovery;
#[cfg(feature = "serde")]
mod serde_util;

pub use key::{SecretKey, PublicKey, XOnlyPubkey, KeyPair};
pub use context::*;
use core::marker::PhantomData;
use core::mem;
use ffi::{CPtr, types::AlignedType};

#[cfg(feature = "global-context-less-secure")]
pub use context::global::SECP256K1;

#[cfg(feature = "bitcoin_hashes")]
use hashes::Hash;
#[cfg(any(test, feature = "rand"))]
use rand::Rng;

/// Secp256k1-related errors
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

/// Trait describing something that promises to be a 32-byte random number; in particular,
/// it has negligible probability of being zero or overflowing the group order. Such objects
/// may be converted to `Message`s without any error paths.
pub trait ThirtyTwoByteHash {
    /// Converts the object into a 32-byte array
    fn into_32(self) -> [u8; 32];
}

#[cfg(feature = "bitcoin_hashes")]
impl ThirtyTwoByteHash for hashes::sha256::Hash {
    fn into_32(self) -> [u8; 32] {
        self.into_inner()
    }
}

#[cfg(feature = "bitcoin_hashes")]
impl ThirtyTwoByteHash for hashes::sha256d::Hash {
    fn into_32(self) -> [u8; 32] {
        self.into_inner()
    }
}

#[cfg(feature = "bitcoin_hashes")]
impl<T: hashes::sha256t::Tag> ThirtyTwoByteHash for hashes::sha256t::Hash<T> {
    fn into_32(self) -> [u8; 32] {
        self.into_inner()
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
    pub fn from_hashed_data<H: ThirtyTwoByteHash + hashes::Hash>(data: &[u8]) -> Self {
        <H as hashes::Hash>::hash(data).into()
    }
}

impl<T: ThirtyTwoByteHash> From<T> for Message {
    /// Converts a 32-byte hash directly to a message without error paths
    fn from(t: T) -> Message {
        Message(t.into_32())
    }
}

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
    use std::marker::PhantomData;

    use key::{SecretKey, PublicKey};
    use super::from_hex;
    use super::{Secp256k1, Message};
    use ffi::{self, types::AlignedType};
    use context::*;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

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
        use hashes;
        use hashes::Hash;

        let test_bytes = "Hello world!".as_bytes();

        let hash = hashes::sha256::Hash::hash(test_bytes);
        let msg = Message::from(hash);
        assert_eq!(msg.0, hash.into_inner());
        assert_eq!(
            msg,
            Message::from_hashed_data::<hashes::sha256::Hash>(test_bytes)
        );

        let hash = hashes::sha256d::Hash::hash(test_bytes);
        let msg = Message::from(hash);
        assert_eq!(msg.0, hash.into_inner());
        assert_eq!(
            msg,
            Message::from_hashed_data::<hashes::sha256d::Hash>(test_bytes)
        );
    }
}
