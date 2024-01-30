// SPDX-License-Identifier: CC0-1.0

//! This module provides an implementation of ElligatorSwift as well as a
//! version of x-only ECDH using it (including compatibility with BIP324).
//!
//! `ElligatorSwift` is described in `https://eprint.iacr.org/2022/759` by
//! Chavez-Saab, Rodriguez-Henriquez, and Tibouchi. It permits encoding
//! uniformly chosen public keys as 64-byte arrays which are indistinguishable
//! from uniformly random arrays.
//!
//! Let f be the function from pairs of field elements to point X coordinates,
//! defined as follows (all operations modulo p = 2^256 - 2^32 - 977)
//! f(u,t):
//! - Let C = 0xa2d2ba93507f1df233770c2a797962cc61f6d15da14ecd47d8d27ae1cd5f852,
//!   a square root of -3.
//! - If u=0, set u=1 instead.
//! - If t=0, set t=1 instead.
//! - If u^3 + t^2 + 7 = 0, multiply t by 2.
//! - Let X = (u^3 + 7 - t^2) / (2 * t)
//! - Let Y = (X + t) / (C * u)
//! - Return the first in [u + 4 * Y^2, (-X/Y - u) / 2, (X/Y - u) / 2] that is an
//!   X coordinate on the curve (at least one of them is, for any u and t).
//!
//! Then an `ElligatorSwift` encoding of x consists of the 32-byte big-endian
//! encodings of field elements u and t concatenated, where f(u,t) = x.
//! The encoding algorithm is described in the paper, and effectively picks a
//! uniformly random pair (u,t) among those which encode x.
//!
//! If the Y coordinate is relevant, it is given the same parity as t.
//!
//! Changes w.r.t. the paper:
//! - The u=0, t=0, and u^3+t^2+7=0 conditions result in decoding to the point
//!   at infinity in the paper. Here they are remapped to finite points.
//! - The paper uses an additional encoding bit for the parity of y. Here the
//!   parity of t is used (negating t does not affect the decoded x coordinate,
//!   so this is possible).

use core::fmt::{self, Display, Formatter};
use core::ptr;
use core::str::FromStr;

use ffi::CPtr;
use secp256k1_sys::types::{c_int, c_uchar, c_void};

use crate::{constants, ffi, from_hex, Error, PublicKey, Secp256k1, SecretKey, Verification};

unsafe extern "C" fn hash_callback<F>(
    output: *mut c_uchar,
    x32: *const c_uchar,
    ell_a64: *const c_uchar,
    ell_b64: *const c_uchar,
    hash_func: *mut c_void,
) -> c_int
where
    F: FnMut([u8; 32], [u8; 64], [u8; 64]) -> ElligatorSwiftSharedSecret,
{
    let callback: &mut F = &mut *(hash_func as *mut F);
    let mut x32_array = [0u8; 32];
    let mut ell_a64_array = [0u8; 64];
    let mut ell_b64_array = [0u8; 64];

    // Copy the data into Rust slices
    ptr::copy_nonoverlapping(x32, x32_array.as_mut_c_ptr(), 32);
    ptr::copy_nonoverlapping(ell_a64, ell_a64_array.as_mut_c_ptr(), 64);
    ptr::copy_nonoverlapping(ell_b64, ell_b64_array.as_mut_c_ptr(), 64);
    // Call the hash function that was passed in through the `data` pointer
    let secret = callback(x32_array, ell_a64_array, ell_b64_array);
    // Copy the output from a [ElligatorSwiftSharedSecret] into the output pointer
    ptr::copy_nonoverlapping(secret.0.as_ptr(), output, secret.0.len());
    // Always returns 1
    1
}

/// `ElligatorSwift` is an encoding of a uniformly chosen point on the curve
/// as a 64-byte array that is indistinguishable from a uniformly random array.
/// This object holds two field elements u and t, which are the inputs to
/// the `ElligatorSwift` encoding function.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ElligatorSwift(ffi::ElligatorSwift);

impl ElligatorSwift {
    /// Create a new `ElligatorSwift` object from a 64-byte array.
    pub fn new(secret_key: SecretKey, rand: [u8; 32]) -> ElligatorSwift {
        let mut ell_out = [0u8; constants::ELLSWIFT_ENCODING_SIZE];
        unsafe {
            let ret = ffi::secp256k1_ellswift_create(
                ffi::secp256k1_context_no_precomp,
                ell_out.as_mut_c_ptr(),
                secret_key.as_c_ptr(),
                rand.as_ptr(),
            );
            debug_assert_eq!(ret, 1);
        }
        ElligatorSwift(ffi::ElligatorSwift::from_array(ell_out))
    }

    /// Creates an `ElligatorSwift` object from a 64-byte array.
    pub fn from_array(ellswift: [u8; 64]) -> ElligatorSwift {
        ElligatorSwift(ffi::ElligatorSwift::from_array(ellswift))
    }

    /// Returns the 64-byte array representation of this `ElligatorSwift` object.
    pub fn to_array(&self) -> [u8; 64] { self.0.to_array() }

    /// Creates the Elligator Swift encoding from a secret key, using some aux_rand if defined.
    /// This method is preferred instead of just decoding, because the private key offers extra
    /// entropy.
    /// # Example
    /// ```
    /// # #[cfg(feature = "alloc")] {
    ///     use secp256k1::{ellswift::ElligatorSwift, PublicKey, Secp256k1, SecretKey};
    ///     let secp = Secp256k1::new();
    ///     let sk = SecretKey::from_slice(&[1; 32]).unwrap();
    ///     let es = ElligatorSwift::from_seckey(&secp, sk, None);
    /// # }
    /// ```
    pub fn from_seckey<C: Verification>(
        secp: &Secp256k1<C>,
        sk: SecretKey,
        aux_rand: Option<[u8; 32]>,
    ) -> ElligatorSwift {
        let mut es_out = [0u8; constants::ELLSWIFT_ENCODING_SIZE];
        let aux_rand_ptr = aux_rand.as_c_ptr();
        unsafe {
            let ret = ffi::secp256k1_ellswift_create(
                secp.ctx().as_ptr(),
                es_out.as_mut_c_ptr(),
                sk.as_c_ptr(),
                aux_rand_ptr,
            );
            debug_assert_eq!(ret, 1);
        }
        ElligatorSwift(ffi::ElligatorSwift::from_array(es_out))
    }

    /// Computes the `ElligatorSwift` encoding for a valid public key
    /// # Example
    /// ```
    /// # #[cfg(feature = "alloc")] {
    ///     use secp256k1::{ellswift::ElligatorSwift, PublicKey, Secp256k1, SecretKey};
    ///     let secp = Secp256k1::new();
    ///     let sk = SecretKey::from_slice(&[1; 32]).unwrap();
    ///     let pk = PublicKey::from_secret_key(&secp, &sk);
    ///     let es = ElligatorSwift::from_pubkey(pk);
    /// # }
    ///
    /// ```
    pub fn from_pubkey(pk: PublicKey) -> ElligatorSwift { Self::encode(pk) }

    /// Computes a shared secret only known by Alice and Bob. This is obtained by computing
    /// the x-only Elliptic Curve Diffie-Hellman (ECDH) shared secret between Alice and Bob.
    /// # Example
    /// ```
    /// # #[cfg(feature = "alloc")] {
    ///     use secp256k1::{
    ///         ellswift::{ElligatorSwift, ElligatorSwiftParty},
    ///         PublicKey, SecretKey, XOnlyPublicKey, Secp256k1,
    ///     };
    ///     use core::str::FromStr;
    ///
    ///     let secp = Secp256k1::new();
    ///
    ///     let alice_sk = SecretKey::from_str("e714e76bdd67ad9f495683c37934148f4efc25ce3f01652c8a906498339e1f3a").unwrap();
    ///     let bob_sk = SecretKey::from_str("b6c4b0e2f8c4359caf356a618cd1649d18790a1d67f7c2d1e4760e04c785db4f").unwrap();
    ///
    ///     let alice_es = ElligatorSwift::from_seckey(&secp, alice_sk, None);
    ///     let bob_es = ElligatorSwift::from_seckey(&secp, bob_sk, None);
    ///
    ///     let alice_shared_secret = ElligatorSwift::shared_secret(alice_es, bob_es, alice_sk, ElligatorSwiftParty::A, None);
    ///     let bob_shared_secret = ElligatorSwift::shared_secret(alice_es, bob_es, bob_sk, ElligatorSwiftParty::B, None);
    ///
    ///     assert_eq!(alice_shared_secret, bob_shared_secret);
    /// # }
    /// ```
    pub fn shared_secret(
        ellswift_a: ElligatorSwift,
        ellswift_b: ElligatorSwift,
        secret_key: SecretKey,
        party: ElligatorSwiftParty,
        data: Option<&[u8]>,
    ) -> ElligatorSwiftSharedSecret {
        let mut shared_secret = [0u8; 32];
        unsafe {
            let ret = ffi::secp256k1_ellswift_xdh(
                ffi::secp256k1_context_no_precomp,
                shared_secret.as_mut_c_ptr(),
                ellswift_a.as_c_ptr(),
                ellswift_b.as_c_ptr(),
                secret_key.as_c_ptr(),
                party.to_ffi_int(),
                ffi::secp256k1_ellswift_xdh_hash_function_bip324,
                data.as_c_ptr() as *mut c_void,
            );
            debug_assert_eq!(ret, 1);
        }
        ElligatorSwiftSharedSecret(shared_secret)
    }

    /// Computes a shared secret, just like `shared_secret`, but with a custom hash function
    /// for computing the shared secret. For compatibility with other libraries, you should
    /// use `shared_secret` instead, which is already compatible with BIP324.
    /// The hash function takes three arguments: the shared point, and the `ElligatorSwift`
    /// encodings of the two parties and returns a 32-byte shared secret.
    pub fn shared_secret_with_hasher<F>(
        ellswift_a: ElligatorSwift,
        ellswift_b: ElligatorSwift,
        secret_key: SecretKey,
        party: ElligatorSwiftParty,
        mut hash_function: F,
    ) -> ElligatorSwiftSharedSecret
    where
        F: FnMut([u8; 32], [u8; 64], [u8; 64]) -> ElligatorSwiftSharedSecret,
    {
        let mut shared_secret = [0u8; 32];
        let hashfp = hash_callback::<F>;
        unsafe {
            let ret = ffi::secp256k1_ellswift_xdh(
                ffi::secp256k1_context_no_precomp,
                shared_secret.as_mut_c_ptr(),
                ellswift_a.0.as_c_ptr(),
                ellswift_b.0.as_c_ptr(),
                secret_key.as_c_ptr(),
                party.to_ffi_int(),
                Some(hashfp),
                &mut hash_function as *mut F as *mut c_void,
            );
            debug_assert_eq!(ret, 1);
        }
        ElligatorSwiftSharedSecret(shared_secret)
    }

    /// Encodes a public key into an `ElligatorSwift` encoding
    fn encode(pk: PublicKey) -> ElligatorSwift {
        let mut ell_out = [0u8; constants::ELLSWIFT_ENCODING_SIZE];
        unsafe {
            let ret = ffi::secp256k1_ellswift_encode(
                ffi::secp256k1_context_no_precomp,
                ell_out.as_mut_c_ptr(),
                pk.as_c_ptr(),
                [0u8; 32].as_ptr(),
            );
            debug_assert_eq!(ret, 1);
        }
        ElligatorSwift(ffi::ElligatorSwift::from_array(ell_out))
    }

    /// Decodes an `ElligatorSwift` encoding into a [`PublicKey`].
    pub(crate) fn decode(ell: ElligatorSwift) -> PublicKey {
        unsafe {
            let mut pk = ffi::PublicKey::new();

            let ret = ffi::secp256k1_ellswift_decode(
                ffi::secp256k1_context_no_precomp,
                pk.as_mut_c_ptr(),
                ell.as_c_ptr(),
            );
            debug_assert_eq!(ret, 1);
            PublicKey::from(pk)
        }
    }
}

/// The result of `ElligatorSwift::shared_secret`, which is a shared secret
/// computed from the x-only ECDH using both parties' public keys (`ElligatorSwift` encoded) and our own
/// private key.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ElligatorSwiftSharedSecret([u8; 32]);

impl ElligatorSwiftSharedSecret {
    /// Creates shared secret from bytes.
    ///
    /// This is generally not needed except for unusual cases like restoring the secret from a
    /// database.
    pub const fn from_secret_bytes(bytes: [u8; 32]) -> Self { Self(bytes) }

    /// Returns the secret bytes as an array.
    pub const fn to_secret_bytes(self) -> [u8; 32] { self.0 }

    /// Returns the secret bytes as a reference to an array.
    pub const fn as_secret_bytes(&self) -> &[u8; 32] { &self.0 }
}

/// Represents which party we are in the ECDH, A is the initiator, B is the responder.
/// This is important because the hash of the shared secret is different depending on which party
/// we are. In this context, "we" means the party that is using this library, and possesses the
/// secret key passed to `ElligatorSwift::shared_secret`.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ElligatorSwiftParty {
    /// We are the initiator of the ECDH
    A,
    /// We are the responder of the ECDH
    B,
}

impl ElligatorSwiftParty {
    fn to_ffi_int(self) -> c_int {
        match self {
            ElligatorSwiftParty::A => 0,
            ElligatorSwiftParty::B => 1,
        }
    }
}

impl FromStr for ElligatorSwift {
    fn from_str(hex: &str) -> Result<Self, Self::Err> {
        let mut ser = [0u8; 64];
        let parsed = from_hex(hex, &mut ser);
        match parsed {
            Ok(64) => Ok(ElligatorSwift::from_array(ser)),
            _ => Err(Error::InvalidEllSwift),
        }
    }
    type Err = Error;
}

impl fmt::LowerHex for ElligatorSwift {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let ser = self.to_array();
        for ch in ser.iter() {
            write!(f, "{:02x}", ch)?;
        }
        Ok(())
    }
}

impl Display for ElligatorSwift {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result { core::fmt::LowerHex::fmt(&self, f) }
}

impl ffi::CPtr for ElligatorSwift {
    type Target = u8;
    fn as_mut_c_ptr(&mut self) -> *mut Self::Target { self.0.as_mut_c_ptr() }
    fn as_c_ptr(&self) -> *const Self::Target { self.0.as_c_ptr() }
}

#[cfg(test)]
mod tests {
    use core::str::FromStr;

    use crate::ellswift::ElligatorSwift;
    #[cfg(all(not(secp256k1_fuzz), feature = "alloc"))]
    use crate::ellswift::{ElligatorSwiftParty, ElligatorSwiftSharedSecret};
    #[cfg(all(not(secp256k1_fuzz), feature = "alloc"))]
    use crate::SecretKey;
    use crate::{from_hex, PublicKey, XOnlyPublicKey};

    #[test]
    #[cfg(all(not(secp256k1_fuzz), feature = "alloc"))]
    fn test_elligator_swift_rtt() {
        // Test that we can round trip an ElligatorSwift encoding
        let secp = crate::Secp256k1::new();
        let public_key =
            PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[1u8; 32]).unwrap());

        let ell = ElligatorSwift::from_pubkey(public_key);
        let pk = PublicKey::from_ellswift(ell);
        assert_eq!(pk, public_key);
    }
    #[test]
    #[cfg(all(not(secp256k1_fuzz), feature = "alloc"))]
    fn test_create_elligator_swift_create_rtt() {
        // Test that we can round trip an ElligatorSwift created from a secret key
        let secp = crate::Secp256k1::new();
        let rand32 = [1u8; 32];
        let priv32 = [1u8; 32];
        let ell = ElligatorSwift::from_seckey(&secp, SecretKey::from_slice(&rand32).unwrap(), None);
        let pk = PublicKey::from_ellswift(ell);
        let expected = PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&priv32).unwrap());

        assert_eq!(pk, expected);
    }
    #[test]
    #[cfg(all(not(secp256k1_fuzz), feature = "alloc"))]
    fn test_xdh_with_custom_hasher() {
        // Test the ECDH with a custom hash function
        let secp = crate::Secp256k1::new();
        let rand32 = [1u8; 32];
        let priv32 = [2u8; 32];
        let ell = ElligatorSwift::from_seckey(
            &secp,
            SecretKey::from_slice(&rand32).unwrap(),
            Some(rand32),
        );
        let pk = ElligatorSwift::shared_secret_with_hasher(
            ell,
            ell,
            SecretKey::from_slice(&priv32).unwrap(),
            ElligatorSwiftParty::A,
            |_, _, _| ElligatorSwiftSharedSecret([0xff; 32]),
        );
        assert_eq!(pk, ElligatorSwiftSharedSecret([0xff; 32]));
    }
    #[test]
    #[cfg(all(not(secp256k1_fuzz), feature = "alloc"))]
    fn ellswift_ecdh_test() {
        let tests = vec![
            (
                [
                    0x61, 0x06, 0x2e, 0xa5, 0x07, 0x1d, 0x80, 0x0b, 0xbf, 0xd5, 0x9e, 0x2e, 0x8b,
                    0x53, 0xd4, 0x7d, 0x19, 0x4b, 0x09, 0x5a, 0xe5, 0xa4, 0xdf, 0x04, 0x93, 0x6b,
                    0x49, 0x77, 0x2e, 0xf0, 0xd4, 0xd7,
                ],
                [
                    0xec, 0x0a, 0xdf, 0xf2, 0x57, 0xbb, 0xfe, 0x50, 0x0c, 0x18, 0x8c, 0x80, 0xb4,
                    0xfd, 0xd6, 0x40, 0xf6, 0xb4, 0x5a, 0x48, 0x2b, 0xbc, 0x15, 0xfc, 0x7c, 0xef,
                    0x59, 0x31, 0xde, 0xff, 0x0a, 0xa1, 0x86, 0xf6, 0xeb, 0x9b, 0xba, 0x7b, 0x85,
                    0xdc, 0x4d, 0xcc, 0x28, 0xb2, 0x87, 0x22, 0xde, 0x1e, 0x3d, 0x91, 0x08, 0xb9,
                    0x85, 0xe2, 0x96, 0x70, 0x45, 0x66, 0x8f, 0x66, 0x09, 0x8e, 0x47, 0x5b,
                ],
                [
                    0xa4, 0xa9, 0x4d, 0xfc, 0xe6, 0x9b, 0x4a, 0x2a, 0x0a, 0x09, 0x93, 0x13, 0xd1,
                    0x0f, 0x9f, 0x7e, 0x7d, 0x64, 0x9d, 0x60, 0x50, 0x1c, 0x9e, 0x1d, 0x27, 0x4c,
                    0x30, 0x0e, 0x0d, 0x89, 0xaa, 0xfa, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x8f, 0xaf, 0x88, 0xd5,
                ],
                1,
                [
                    0xc6, 0x99, 0x2a, 0x11, 0x7f, 0x5e, 0xdb, 0xea, 0x70, 0xc3, 0xf5, 0x11, 0xd3,
                    0x2d, 0x26, 0xb9, 0x79, 0x8b, 0xe4, 0xb8, 0x1a, 0x62, 0xea, 0xee, 0x1a, 0x5a,
                    0xca, 0xa8, 0x45, 0x9a, 0x35, 0x92,
                ],
            ),
            (
                [
                    0x1f, 0x9c, 0x58, 0x1b, 0x35, 0x23, 0x18, 0x38, 0xf0, 0xf1, 0x7c, 0xf0, 0xc9,
                    0x79, 0x83, 0x5b, 0xac, 0xcb, 0x7f, 0x3a, 0xbb, 0xbb, 0x96, 0xff, 0xcc, 0x31,
                    0x8a, 0xb7, 0x1e, 0x6e, 0x12, 0x6f,
                ],
                [
                    0xa1, 0x85, 0x5e, 0x10, 0xe9, 0x4e, 0x00, 0xba, 0xa2, 0x30, 0x41, 0xd9, 0x16,
                    0xe2, 0x59, 0xf7, 0x04, 0x4e, 0x49, 0x1d, 0xa6, 0x17, 0x12, 0x69, 0x69, 0x47,
                    0x63, 0xf0, 0x18, 0xc7, 0xe6, 0x36, 0x93, 0xd2, 0x95, 0x75, 0xdc, 0xb4, 0x64,
                    0xac, 0x81, 0x6b, 0xaa, 0x1b, 0xe3, 0x53, 0xba, 0x12, 0xe3, 0x87, 0x6c, 0xba,
                    0x76, 0x28, 0xbd, 0x0b, 0xd8, 0xe7, 0x55, 0xe7, 0x21, 0xeb, 0x01, 0x40,
                ],
                [
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ],
                0,
                [
                    0xa0, 0x13, 0x8f, 0x56, 0x4f, 0x74, 0xd0, 0xad, 0x70, 0xbc, 0x33, 0x7d, 0xac,
                    0xc9, 0xd0, 0xbf, 0x1d, 0x23, 0x49, 0x36, 0x4c, 0xaf, 0x11, 0x88, 0xa1, 0xe6,
                    0xe8, 0xdd, 0xb3, 0xb7, 0xb1, 0x84,
                ],
            ),
            (
                [
                    0x02, 0x86, 0xc4, 0x1c, 0xd3, 0x09, 0x13, 0xdb, 0x0f, 0xdf, 0xf7, 0xa6, 0x4e,
                    0xbd, 0xa5, 0xc8, 0xe3, 0xe7, 0xce, 0xf1, 0x0f, 0x2a, 0xeb, 0xc0, 0x0a, 0x76,
                    0x50, 0x44, 0x3c, 0xf4, 0xc6, 0x0d,
                ],
                [
                    0xd1, 0xee, 0x8a, 0x93, 0xa0, 0x11, 0x30, 0xcb, 0xf2, 0x99, 0x24, 0x9a, 0x25,
                    0x8f, 0x94, 0xfe, 0xb5, 0xf4, 0x69, 0xe7, 0xd0, 0xf2, 0xf2, 0x8f, 0x69, 0xee,
                    0x5e, 0x9a, 0xa8, 0xf9, 0xb5, 0x4a, 0x60, 0xf2, 0xc3, 0xff, 0x2d, 0x02, 0x36,
                    0x34, 0xec, 0x7f, 0x41, 0x27, 0xa9, 0x6c, 0xc1, 0x16, 0x62, 0xe4, 0x02, 0x89,
                    0x4c, 0xf1, 0xf6, 0x94, 0xfb, 0x9a, 0x7e, 0xaa, 0x5f, 0x1d, 0x92, 0x44,
                ],
                [
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0x22, 0xd5, 0xe4, 0x41, 0x52, 0x4d, 0x57, 0x1a, 0x52, 0xb3, 0xde,
                    0xf1, 0x26, 0x18, 0x9d, 0x3f, 0x41, 0x68, 0x90, 0xa9, 0x9d, 0x4d, 0xa6, 0xed,
                    0xe2, 0xb0, 0xcd, 0xe1, 0x76, 0x0c, 0xe2, 0xc3, 0xf9, 0x84, 0x57, 0xae,
                ],
                1,
                [
                    0x25, 0x0b, 0x93, 0x57, 0x0d, 0x41, 0x11, 0x49, 0x10, 0x5a, 0xb8, 0xcb, 0x0b,
                    0xc5, 0x07, 0x99, 0x14, 0x90, 0x63, 0x06, 0x36, 0x8c, 0x23, 0xe9, 0xd7, 0x7c,
                    0x2a, 0x33, 0x26, 0x5b, 0x99, 0x4c,
                ],
            ),
            (
                [
                    0x6c, 0x77, 0x43, 0x2d, 0x1f, 0xda, 0x31, 0xe9, 0xf9, 0x42, 0xf8, 0xaf, 0x44,
                    0x60, 0x7e, 0x10, 0xf3, 0xad, 0x38, 0xa6, 0x5f, 0x8a, 0x4b, 0xdd, 0xae, 0x82,
                    0x3e, 0x5e, 0xff, 0x90, 0xdc, 0x38,
                ],
                [
                    0xd2, 0x68, 0x50, 0x70, 0xc1, 0xe6, 0x37, 0x6e, 0x63, 0x3e, 0x82, 0x52, 0x96,
                    0x63, 0x4f, 0xd4, 0x61, 0xfa, 0x9e, 0x5b, 0xdf, 0x21, 0x09, 0xbc, 0xeb, 0xd7,
                    0x35, 0xe5, 0xa9, 0x1f, 0x3e, 0x58, 0x7c, 0x5c, 0xb7, 0x82, 0xab, 0xb7, 0x97,
                    0xfb, 0xf6, 0xbb, 0x50, 0x74, 0xfd, 0x15, 0x42, 0xa4, 0x74, 0xf2, 0xa4, 0x5b,
                    0x67, 0x37, 0x63, 0xec, 0x2d, 0xb7, 0xfb, 0x99, 0xb7, 0x37, 0xbb, 0xb9,
                ],
                [
                    0x56, 0xbd, 0x0c, 0x06, 0xf1, 0x03, 0x52, 0xc3, 0xa1, 0xa9, 0xf4, 0xb4, 0xc9,
                    0x2f, 0x6f, 0xa2, 0xb2, 0x6d, 0xf1, 0x24, 0xb5, 0x78, 0x78, 0x35, 0x3c, 0x1f,
                    0xc6, 0x91, 0xc5, 0x1a, 0xbe, 0xa7, 0x7c, 0x88, 0x17, 0xda, 0xee, 0xb9, 0xfa,
                    0x54, 0x6b, 0x77, 0xc8, 0xda, 0xf7, 0x9d, 0x89, 0xb2, 0x2b, 0x0e, 0x1b, 0x87,
                    0x57, 0x4e, 0xce, 0x42, 0x37, 0x1f, 0x00, 0x23, 0x7a, 0xa9, 0xd8, 0x3a,
                ],
                0,
                [
                    0x19, 0x18, 0xb7, 0x41, 0xef, 0x5f, 0x9d, 0x1d, 0x76, 0x70, 0xb0, 0x50, 0xc1,
                    0x52, 0xb4, 0xa4, 0xea, 0xd2, 0xc3, 0x1b, 0xe9, 0xae, 0xcb, 0x06, 0x81, 0xc0,
                    0xcd, 0x43, 0x24, 0x15, 0x08, 0x53,
                ],
            ),
            (
                [
                    0xa6, 0xec, 0x25, 0x12, 0x7c, 0xa1, 0xaa, 0x4c, 0xf1, 0x6b, 0x20, 0x08, 0x4b,
                    0xa1, 0xe6, 0x51, 0x6b, 0xaa, 0xe4, 0xd3, 0x24, 0x22, 0x28, 0x8e, 0x9b, 0x36,
                    0xd8, 0xbd, 0xdd, 0x2d, 0xe3, 0x5a,
                ],
                [
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0x05, 0x3d, 0x7e, 0xcc, 0xa5, 0x3e, 0x33, 0xe1, 0x85, 0xa8, 0xb9,
                    0xbe, 0x4e, 0x76, 0x99, 0xa9, 0x7c, 0x6f, 0xf4, 0xc7, 0x95, 0x52, 0x2e, 0x59,
                    0x18, 0xab, 0x7c, 0xd6, 0xb6, 0x88, 0x4f, 0x67, 0xe6, 0x83, 0xf3, 0xdc,
                ],
                [
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xa7, 0x73, 0x0b, 0xe3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ],
                1,
                [
                    0xdd, 0x21, 0x0a, 0xa6, 0x62, 0x9f, 0x20, 0xbb, 0x32, 0x8e, 0x5d, 0x89, 0xda,
                    0xa6, 0xeb, 0x2a, 0xc3, 0xd1, 0xc6, 0x58, 0xa7, 0x25, 0x53, 0x6f, 0xf1, 0x54,
                    0xf3, 0x1b, 0x53, 0x6c, 0x23, 0xb2,
                ],
            ),
            (
                [
                    0x0a, 0xf9, 0x52, 0x65, 0x9e, 0xd7, 0x6f, 0x80, 0xf5, 0x85, 0x96, 0x6b, 0x95,
                    0xab, 0x6e, 0x6f, 0xd6, 0x86, 0x54, 0x67, 0x28, 0x27, 0x87, 0x86, 0x84, 0xc8,
                    0xb5, 0x47, 0xb1, 0xb9, 0x4f, 0x5a,
                ],
                [
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xc8, 0x10, 0x17, 0xfd, 0x92, 0xfd, 0x31, 0x63, 0x7c, 0x26, 0xc9,
                    0x06, 0xb4, 0x20, 0x92, 0xe1, 0x1c, 0xc0, 0xd3, 0xaf, 0xae, 0x8d, 0x90, 0x19,
                    0xd2, 0x57, 0x8a, 0xf2, 0x27, 0x35, 0xce, 0x7b, 0xc4, 0x69, 0xc7, 0x2d,
                ],
                [
                    0x96, 0x52, 0xd7, 0x8b, 0xae, 0xfc, 0x02, 0x8c, 0xd3, 0x7a, 0x6a, 0x92, 0x62,
                    0x5b, 0x8b, 0x8f, 0x85, 0xfd, 0xe1, 0xe4, 0xc9, 0x44, 0xad, 0x3f, 0x20, 0xe1,
                    0x98, 0xbe, 0xf8, 0xc0, 0x2f, 0x19, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf2, 0xe9, 0x18, 0x70,
                ],
                0,
                [
                    0x35, 0x68, 0xf2, 0xae, 0xa2, 0xe1, 0x4e, 0xf4, 0xee, 0x4a, 0x3c, 0x2a, 0x8b,
                    0x8d, 0x31, 0xbc, 0x5e, 0x31, 0x87, 0xba, 0x86, 0xdb, 0x10, 0x73, 0x9b, 0x4f,
                    0xf8, 0xec, 0x92, 0xff, 0x66, 0x55,
                ],
            ),
            (
                [
                    0xf9, 0x0e, 0x08, 0x0c, 0x64, 0xb0, 0x58, 0x24, 0xc5, 0xa2, 0x4b, 0x25, 0x01,
                    0xd5, 0xae, 0xaf, 0x08, 0xaf, 0x38, 0x72, 0xee, 0x86, 0x0a, 0xa8, 0x0b, 0xdc,
                    0xd4, 0x30, 0xf7, 0xb6, 0x34, 0x94,
                ],
                [
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0x11, 0x51, 0x73, 0x76, 0x5d, 0xc2, 0x02, 0xcf, 0x02, 0x9a, 0xd3,
                    0xf1, 0x54, 0x79, 0x73, 0x5d, 0x57, 0x69, 0x7a, 0xf1, 0x2b, 0x01, 0x31, 0xdd,
                    0x21, 0x43, 0x0d, 0x57, 0x72, 0xe4, 0xef, 0x11, 0x47, 0x4d, 0x58, 0xb9,
                ],
                [
                    0x12, 0xa5, 0x0f, 0x3f, 0xaf, 0xea, 0x7c, 0x1e, 0xea, 0xda, 0x4c, 0xf8, 0xd3,
                    0x37, 0x77, 0x70, 0x4b, 0x77, 0x36, 0x14, 0x53, 0xaf, 0xc8, 0x3b, 0xda, 0x91,
                    0xee, 0xf3, 0x49, 0xae, 0x04, 0x4d, 0x20, 0x12, 0x6c, 0x62, 0x00, 0x54, 0x7e,
                    0xa5, 0xa6, 0x91, 0x17, 0x76, 0xc0, 0x5d, 0xee, 0x2a, 0x7f, 0x1a, 0x9b, 0xa7,
                    0xdf, 0xba, 0xbb, 0xbd, 0x27, 0x3c, 0x3e, 0xf2, 0x9e, 0xf4, 0x6e, 0x46,
                ],
                1,
                [
                    0xe2, 0x54, 0x61, 0xfb, 0x0e, 0x4c, 0x16, 0x2e, 0x18, 0x12, 0x3e, 0xcd, 0xe8,
                    0x83, 0x42, 0xd5, 0x4d, 0x44, 0x96, 0x31, 0xe9, 0xb7, 0x5a, 0x26, 0x6f, 0xd9,
                    0x26, 0x0c, 0x2b, 0xb2, 0xf4, 0x1d,
                ],
            ),
        ];
        for (my_secret, ellswift_ours, ellswift_theirs, initiator, shared_secret) in tests {
            // We are not the initiator, so we are B
            let (el_a, el_b) = if initiator == 0 {
                (
                    ElligatorSwift::from_array(ellswift_theirs),
                    ElligatorSwift::from_array(ellswift_ours),
                )
            } else {
                // We are the initiator, so we are A
                (
                    ElligatorSwift::from_array(ellswift_ours),
                    ElligatorSwift::from_array(ellswift_theirs),
                )
            };
            let sec_key = SecretKey::from_slice(&my_secret).unwrap();
            let initiator =
                if initiator == 0 { ElligatorSwiftParty::B } else { ElligatorSwiftParty::A };

            let shared = ElligatorSwift::shared_secret(el_a, el_b, sec_key, initiator, None);

            assert_eq!(shared.0, shared_secret);
        }
    }
    #[test]
    #[cfg(not(secp256k1_fuzz))]
    fn ellswift_decode_test() {
        struct EllswiftDecodeTest {
            enc: [u8; 64],
            key: PublicKey,
        }
        #[inline]
        fn parse_test(ell: &str, x: &str, parity: u32) -> EllswiftDecodeTest {
            let mut enc = [0u8; 64];
            from_hex(ell, &mut enc).unwrap();
            let xo = XOnlyPublicKey::from_str(x).unwrap();
            let parity = if parity == 0 { crate::Parity::Even } else { crate::Parity::Odd };
            let pk = PublicKey::from_x_only_public_key(xo, parity);
            EllswiftDecodeTest { enc, key: pk }
        }
        macro_rules! make_tests {
            ($(($ell: literal, $x: literal, $parity: literal)),+) => {
                [$(
                    parse_test($ell, $x, $parity),
                )+]
            };
        }
        let tests = make_tests!(
            ("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","edd1fd3e327ce90cc7a3542614289aee9682003e9cf7dcc9cf2ca9743be5aa0c", 0),
            ("000000000000000000000000000000000000000000000000000000000000000001d3475bf7655b0fb2d852921035b2ef607f49069b97454e6795251062741771","b5da00b73cd6560520e7c364086e7cd23a34bf60d0e707be9fc34d4cd5fdfa2c", 1),
            ("000000000000000000000000000000000000000000000000000000000000000082277c4a71f9d22e66ece523f8fa08741a7c0912c66a69ce68514bfd3515b49f","f482f2e241753ad0fb89150d8491dc1e34ff0b8acfbb442cfe999e2e5e6fd1d2", 1),
            ("00000000000000000000000000000000000000000000000000000000000000008421cc930e77c9f514b6915c3dbe2a94c6d8f690b5b739864ba6789fb8a55dd0","9f59c40275f5085a006f05dae77eb98c6fd0db1ab4a72ac47eae90a4fc9e57e0", 0),
            ("0000000000000000000000000000000000000000000000000000000000000000bde70df51939b94c9c24979fa7dd04ebd9b3572da7802290438af2a681895441","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa9fffffd6b", 1),
            ("0000000000000000000000000000000000000000000000000000000000000000d19c182d2759cd99824228d94799f8c6557c38a1c0d6779b9d4b729c6f1ccc42","70720db7e238d04121f5b1afd8cc5ad9d18944c6bdc94881f502b7a3af3aecff", 0),
            ("0000000000000000000000000000000000000000000000000000000000000000fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f","edd1fd3e327ce90cc7a3542614289aee9682003e9cf7dcc9cf2ca9743be5aa0c", 0),
            ("0000000000000000000000000000000000000000000000000000000000000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff2664bbd5","50873db31badcc71890e4f67753a65757f97aaa7dd5f1e82b753ace32219064b", 0),
            ("0000000000000000000000000000000000000000000000000000000000000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff7028de7d","1eea9cc59cfcf2fa151ac6c274eea4110feb4f7b68c5965732e9992e976ef68e", 0),
            ("0000000000000000000000000000000000000000000000000000000000000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffcbcfb7e7","12303941aedc208880735b1f1795c8e55be520ea93e103357b5d2adb7ed59b8e", 0),
            ("0000000000000000000000000000000000000000000000000000000000000000fffffffffffffffffffffffffffffffffffffffffffffffffffffffff3113ad9","7eed6b70e7b0767c7d7feac04e57aa2a12fef5e0f48f878fcbb88b3b6b5e0783", 0),
            ("0a2d2ba93507f1df233770c2a797962cc61f6d15da14ecd47d8d27ae1cd5f8530000000000000000000000000000000000000000000000000000000000000000","532167c11200b08c0e84a354e74dcc40f8b25f4fe686e30869526366278a0688", 0),
            ("0a2d2ba93507f1df233770c2a797962cc61f6d15da14ecd47d8d27ae1cd5f853fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f","532167c11200b08c0e84a354e74dcc40f8b25f4fe686e30869526366278a0688", 0),
            ("0ffde9ca81d751e9cdaffc1a50779245320b28996dbaf32f822f20117c22fbd6c74d99efceaa550f1ad1c0f43f46e7ff1ee3bd0162b7bf55f2965da9c3450646","74e880b3ffd18fe3cddf7902522551ddf97fa4a35a3cfda8197f947081a57b8f", 0),
            ("0ffde9ca81d751e9cdaffc1a50779245320b28996dbaf32f822f20117c22fbd6ffffffffffffffffffffffffffffffffffffffffffffffffffffffff156ca896","377b643fce2271f64e5c8101566107c1be4980745091783804f654781ac9217c", 1),
            ("123658444f32be8f02ea2034afa7ef4bbe8adc918ceb49b12773b625f490b368ffffffffffffffffffffffffffffffffffffffffffffffffffffffff8dc5fe11","ed16d65cf3a9538fcb2c139f1ecbc143ee14827120cbc2659e667256800b8142", 0),
            ("146f92464d15d36e35382bd3ca5b0f976c95cb08acdcf2d5b3570617990839d7ffffffffffffffffffffffffffffffffffffffffffffffffffffffff3145e93b","0d5cd840427f941f65193079ab8e2e83024ef2ee7ca558d88879ffd879fb6657", 0),
            ("15fdf5cf09c90759add2272d574d2bb5fe1429f9f3c14c65e3194bf61b82aa73ffffffffffffffffffffffffffffffffffffffffffffffffffffffff04cfd906","16d0e43946aec93f62d57eb8cde68951af136cf4b307938dd1447411e07bffe1", 1),
            ("1f67edf779a8a649d6def60035f2fa22d022dd359079a1a144073d84f19b92d50000000000000000000000000000000000000000000000000000000000000000","025661f9aba9d15c3118456bbe980e3e1b8ba2e047c737a4eb48a040bb566f6c", 0),
            ("1f67edf779a8a649d6def60035f2fa22d022dd359079a1a144073d84f19b92d5fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f","025661f9aba9d15c3118456bbe980e3e1b8ba2e047c737a4eb48a040bb566f6c", 0),
            ("1fe1e5ef3fceb5c135ab7741333ce5a6e80d68167653f6b2b24bcbcfaaaff507fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f","98bec3b2a351fa96cfd191c1778351931b9e9ba9ad1149f6d9eadca80981b801", 0),
            ("4056a34a210eec7892e8820675c860099f857b26aad85470ee6d3cf1304a9dcf375e70374271f20b13c9986ed7d3c17799698cfc435dbed3a9f34b38c823c2b4","868aac2003b29dbcad1a3e803855e078a89d16543ac64392d122417298cec76e", 0),
            ("4197ec3723c654cfdd32ab075506648b2ff5070362d01a4fff14b336b78f963fffffffffffffffffffffffffffffffffffffffffffffffffffffffffb3ab1e95","ba5a6314502a8952b8f456e085928105f665377a8ce27726a5b0eb7ec1ac0286", 0),
            ("47eb3e208fedcdf8234c9421e9cd9a7ae873bfbdbc393723d1ba1e1e6a8e6b24ffffffffffffffffffffffffffffffffffffffffffffffffffffffff7cd12cb1","d192d52007e541c9807006ed0468df77fd214af0a795fe119359666fdcf08f7c", 0),
            ("5eb9696a2336fe2c3c666b02c755db4c0cfd62825c7b589a7b7bb442e141c1d693413f0052d49e64abec6d5831d66c43612830a17df1fe4383db896468100221","ef6e1da6d6c7627e80f7a7234cb08a022c1ee1cf29e4d0f9642ae924cef9eb38", 1),
            ("7bf96b7b6da15d3476a2b195934b690a3a3de3e8ab8474856863b0de3af90b0e0000000000000000000000000000000000000000000000000000000000000000","50851dfc9f418c314a437295b24feeea27af3d0cd2308348fda6e21c463e46ff", 0),
            ("7bf96b7b6da15d3476a2b195934b690a3a3de3e8ab8474856863b0de3af90b0efffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f","50851dfc9f418c314a437295b24feeea27af3d0cd2308348fda6e21c463e46ff", 0),
            ("851b1ca94549371c4f1f7187321d39bf51c6b7fb61f7cbf027c9da62021b7a65fc54c96837fb22b362eda63ec52ec83d81bedd160c11b22d965d9f4a6d64d251","3e731051e12d33237eb324f2aa5b16bb868eb49a1aa1fadc19b6e8761b5a5f7b", 1),
            ("943c2f775108b737fe65a9531e19f2fc2a197f5603e3a2881d1d83e4008f91250000000000000000000000000000000000000000000000000000000000000000","311c61f0ab2f32b7b1f0223fa72f0a78752b8146e46107f8876dd9c4f92b2942", 0),
            ("943c2f775108b737fe65a9531e19f2fc2a197f5603e3a2881d1d83e4008f9125fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f","311c61f0ab2f32b7b1f0223fa72f0a78752b8146e46107f8876dd9c4f92b2942", 0),
            ("a0f18492183e61e8063e573606591421b06bc3513631578a73a39c1c3306239f2f32904f0d2a33ecca8a5451705bb537d3bf44e071226025cdbfd249fe0f7ad6","97a09cf1a2eae7c494df3c6f8a9445bfb8c09d60832f9b0b9d5eabe25fbd14b9", 0),
            ("a1ed0a0bd79d8a23cfe4ec5fef5ba5cccfd844e4ff5cb4b0f2e71627341f1c5b17c499249e0ac08d5d11ea1c2c8ca7001616559a7994eadec9ca10fb4b8516dc","65a89640744192cdac64b2d21ddf989cdac7500725b645bef8e2200ae39691f2", 0),
            ("ba94594a432721aa3580b84c161d0d134bc354b690404d7cd4ec57c16d3fbe98ffffffffffffffffffffffffffffffffffffffffffffffffffffffffea507dd7","5e0d76564aae92cb347e01a62afd389a9aa401c76c8dd227543dc9cd0efe685a", 0),
            ("bcaf7219f2f6fbf55fe5e062dce0e48c18f68103f10b8198e974c184750e1be3932016cbf69c4471bd1f656c6a107f1973de4af7086db897277060e25677f19a","2d97f96cac882dfe73dc44db6ce0f1d31d6241358dd5d74eb3d3b50003d24c2b", 0),
            ("bcaf7219f2f6fbf55fe5e062dce0e48c18f68103f10b8198e974c184750e1be3ffffffffffffffffffffffffffffffffffffffffffffffffffffffff6507d09a","e7008afe6e8cbd5055df120bd748757c686dadb41cce75e4addcc5e02ec02b44", 1),
            ("c5981bae27fd84401c72a155e5707fbb811b2b620645d1028ea270cbe0ee225d4b62aa4dca6506c1acdbecc0552569b4b21436a5692e25d90d3bc2eb7ce24078","948b40e7181713bc018ec1702d3d054d15746c59a7020730dd13ecf985a010d7", 0),
            ("c894ce48bfec433014b931a6ad4226d7dbd8eaa7b6e3faa8d0ef94052bcf8cff336eeb3919e2b4efb746c7f71bbca7e9383230fbbc48ffafe77e8bcc69542471","f1c91acdc2525330f9b53158434a4d43a1c547cff29f15506f5da4eb4fe8fa5a", 1),
            ("cbb0deab125754f1fdb2038b0434ed9cb3fb53ab735391129994a535d925f6730000000000000000000000000000000000000000000000000000000000000000","872d81ed8831d9998b67cb7105243edbf86c10edfebb786c110b02d07b2e67cd", 0),
            ("d917b786dac35670c330c9c5ae5971dfb495c8ae523ed97ee2420117b171f41effffffffffffffffffffffffffffffffffffffffffffffffffffffff2001f6f6","e45b71e110b831f2bdad8651994526e58393fde4328b1ec04d59897142584691", 1),
            ("e28bd8f5929b467eb70e04332374ffb7e7180218ad16eaa46b7161aa679eb4260000000000000000000000000000000000000000000000000000000000000000","66b8c980a75c72e598d383a35a62879f844242ad1e73ff12edaa59f4e58632b5", 0),
            ("e28bd8f5929b467eb70e04332374ffb7e7180218ad16eaa46b7161aa679eb426fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f","66b8c980a75c72e598d383a35a62879f844242ad1e73ff12edaa59f4e58632b5", 0),
            ("e7ee5814c1706bf8a89396a9b032bc014c2cac9c121127dbf6c99278f8bb53d1dfd04dbcda8e352466b6fcd5f2dea3e17d5e133115886eda20db8a12b54de71b","e842c6e3529b234270a5e97744edc34a04d7ba94e44b6d2523c9cf0195730a50", 1),
            ("f292e46825f9225ad23dc057c1d91c4f57fcb1386f29ef10481cb1d22518593fffffffffffffffffffffffffffffffffffffffffffffffffffffffff7011c989","3cea2c53b8b0170166ac7da67194694adacc84d56389225e330134dab85a4d55", 0),
            ("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f0000000000000000000000000000000000000000000000000000000000000000","edd1fd3e327ce90cc7a3542614289aee9682003e9cf7dcc9cf2ca9743be5aa0c", 0),
            ("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f01d3475bf7655b0fb2d852921035b2ef607f49069b97454e6795251062741771","b5da00b73cd6560520e7c364086e7cd23a34bf60d0e707be9fc34d4cd5fdfa2c", 1),
            ("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f4218f20ae6c646b363db68605822fb14264ca8d2587fdd6fbc750d587e76a7ee","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa9fffffd6b", 0),
            ("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f82277c4a71f9d22e66ece523f8fa08741a7c0912c66a69ce68514bfd3515b49f","f482f2e241753ad0fb89150d8491dc1e34ff0b8acfbb442cfe999e2e5e6fd1d2", 1),
            ("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f8421cc930e77c9f514b6915c3dbe2a94c6d8f690b5b739864ba6789fb8a55dd0","9f59c40275f5085a006f05dae77eb98c6fd0db1ab4a72ac47eae90a4fc9e57e0", 0),
            ("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fd19c182d2759cd99824228d94799f8c6557c38a1c0d6779b9d4b729c6f1ccc42","70720db7e238d04121f5b1afd8cc5ad9d18944c6bdc94881f502b7a3af3aecff", 0),
            ("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2ffffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f","edd1fd3e327ce90cc7a3542614289aee9682003e9cf7dcc9cf2ca9743be5aa0c", 0),
            ("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fffffffffffffffffffffffffffffffffffffffffffffffffffffffff2664bbd5","50873db31badcc71890e4f67753a65757f97aaa7dd5f1e82b753ace32219064b", 0),
            ("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fffffffffffffffffffffffffffffffffffffffffffffffffffffffff7028de7d","1eea9cc59cfcf2fa151ac6c274eea4110feb4f7b68c5965732e9992e976ef68e", 0),
            ("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fffffffffffffffffffffffffffffffffffffffffffffffffffffffffcbcfb7e7","12303941aedc208880735b1f1795c8e55be520ea93e103357b5d2adb7ed59b8e", 0),
            ("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2ffffffffffffffffffffffffffffffffffffffffffffffffffffffffff3113ad9","7eed6b70e7b0767c7d7feac04e57aa2a12fef5e0f48f878fcbb88b3b6b5e0783", 0),
            ("ffffffffffffffffffffffffffffffffffffffffffffffffffffffff13cea4a70000000000000000000000000000000000000000000000000000000000000000","649984435b62b4a25d40c6133e8d9ab8c53d4b059ee8a154a3be0fcf4e892edb", 0),
            ("ffffffffffffffffffffffffffffffffffffffffffffffffffffffff13cea4a7fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f","649984435b62b4a25d40c6133e8d9ab8c53d4b059ee8a154a3be0fcf4e892edb", 0),
            ("ffffffffffffffffffffffffffffffffffffffffffffffffffffffff15028c590063f64d5a7f1c14915cd61eac886ab295bebd91992504cf77edb028bdd6267f","3fde5713f8282eead7d39d4201f44a7c85a5ac8a0681f35e54085c6b69543374", 1),
            ("ffffffffffffffffffffffffffffffffffffffffffffffffffffffff2715de860000000000000000000000000000000000000000000000000000000000000000","3524f77fa3a6eb4389c3cb5d27f1f91462086429cd6c0cb0df43ea8f1e7b3fb4", 0),
            ("ffffffffffffffffffffffffffffffffffffffffffffffffffffffff2715de86fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f","3524f77fa3a6eb4389c3cb5d27f1f91462086429cd6c0cb0df43ea8f1e7b3fb4", 0),
            ("ffffffffffffffffffffffffffffffffffffffffffffffffffffffff2c2c5709e7156c417717f2feab147141ec3da19fb759575cc6e37b2ea5ac9309f26f0f66","d2469ab3e04acbb21c65a1809f39caafe7a77c13d10f9dd38f391c01dc499c52", 0),
            ("ffffffffffffffffffffffffffffffffffffffffffffffffffffffff3a08cc1efffffffffffffffffffffffffffffffffffffffffffffffffffffffff760e9f0","38e2a5ce6a93e795e16d2c398bc99f0369202ce21e8f09d56777b40fc512bccc", 1),
            ("ffffffffffffffffffffffffffffffffffffffffffffffffffffffff3e91257d932016cbf69c4471bd1f656c6a107f1973de4af7086db897277060e25677f19a","864b3dc902c376709c10a93ad4bbe29fce0012f3dc8672c6286bba28d7d6d6fc", 0),
            ("ffffffffffffffffffffffffffffffffffffffffffffffffffffffff795d6c1c322cadf599dbb86481522b3cc55f15a67932db2afa0111d9ed6981bcd124bf44","766dfe4a700d9bee288b903ad58870e3d4fe2f0ef780bcac5c823f320d9a9bef", 0),
            ("ffffffffffffffffffffffffffffffffffffffffffffffffffffffff8e426f0392389078c12b1a89e9542f0593bc96b6bfde8224f8654ef5d5cda935a3582194","faec7bc1987b63233fbc5f956edbf37d54404e7461c58ab8631bc68e451a0478", 0),
            ("ffffffffffffffffffffffffffffffffffffffffffffffffffffffff91192139ffffffffffffffffffffffffffffffffffffffffffffffffffffffff45f0f1eb","ec29a50bae138dbf7d8e24825006bb5fc1a2cc1243ba335bc6116fb9e498ec1f", 0),
            ("ffffffffffffffffffffffffffffffffffffffffffffffffffffffff98eb9ab76e84499c483b3bf06214abfe065dddf43b8601de596d63b9e45a166a580541fe","1e0ff2dee9b09b136292a9e910f0d6ac3e552a644bba39e64e9dd3e3bbd3d4d4", 0),
            ("ffffffffffffffffffffffffffffffffffffffffffffffffffffffff9b77b7f2c74d99efceaa550f1ad1c0f43f46e7ff1ee3bd0162b7bf55f2965da9c3450646","8b7dd5c3edba9ee97b70eff438f22dca9849c8254a2f3345a0a572ffeaae0928", 0),
            ("ffffffffffffffffffffffffffffffffffffffffffffffffffffffff9b77b7f2ffffffffffffffffffffffffffffffffffffffffffffffffffffffff156ca896","0881950c8f51d6b9a6387465d5f12609ef1bb25412a08a74cb2dfb200c74bfbf", 1),
            ("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffa2f5cd838816c16c4fe8a1661d606fdb13cf9af04b979a2e159a09409ebc8645d58fde02","2f083207b9fd9b550063c31cd62b8746bd543bdc5bbf10e3a35563e927f440c8", 0),
            ("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffb13f75c00000000000000000000000000000000000000000000000000000000000000000","4f51e0be078e0cddab2742156adba7e7a148e73157072fd618cd60942b146bd0", 0),
            ("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffb13f75c0fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f","4f51e0be078e0cddab2742156adba7e7a148e73157072fd618cd60942b146bd0", 0),
            ("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffe7bc1f8d0000000000000000000000000000000000000000000000000000000000000000","16c2ccb54352ff4bd794f6efd613c72197ab7082da5b563bdf9cb3edaafe74c2", 0),
            ("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffe7bc1f8dfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f","16c2ccb54352ff4bd794f6efd613c72197ab7082da5b563bdf9cb3edaafe74c2", 0),
            ("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffef64d162750546ce42b0431361e52d4f5242d8f24f33e6b1f99b591647cbc808f462af51","d41244d11ca4f65240687759f95ca9efbab767ededb38fd18c36e18cd3b6f6a9", 1),
            ("fffffffffffffffffffffffffffffffffffffffffffffffffffffffff0e5be52372dd6e894b2a326fc3605a6e8f3c69c710bf27d630dfe2004988b78eb6eab36","64bf84dd5e03670fdb24c0f5d3c2c365736f51db6c92d95010716ad2d36134c8", 0),
            ("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffefbb982fffffffffffffffffffffffffffffffffffffffffffffffffffffffff6d6db1f","1c92ccdfcf4ac550c28db57cff0c8515cb26936c786584a70114008d6c33a34b", 0)
        );

        for test in tests.iter() {
            let pk = PublicKey::from_ellswift(ElligatorSwift::from_array(test.enc));
            assert_eq!(pk, test.key);
        }
    }
}
