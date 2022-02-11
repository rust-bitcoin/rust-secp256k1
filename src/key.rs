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

//! Public and secret keys.
//!

#[cfg(any(test, feature = "rand"))] use rand::Rng;

use core::{fmt, ptr, str};
use core::ops::BitXor;

use super::{from_hex, Secp256k1};
use super::Error::{self, InvalidPublicKey, InvalidPublicKeySum, InvalidSecretKey};
use ::{Signing};
use Verification;
use constants;
use ffi::{self, CPtr};

#[cfg(feature = "global-context")]
use {Message, ecdsa, SECP256K1};
#[cfg(all(feature  = "global-context", feature = "rand-std"))]
use schnorr;

/// Secret 256-bit key used as `x` in an ECDSA signature.
///
/// # Examples
///
/// Basic usage:
///
/// ```
/// # #[cfg(all(feature = "std", feature =  "rand-std"))] {
/// use secp256k1::{rand, Secp256k1, SecretKey};
///
/// let secp = Secp256k1::new();
/// let secret_key = SecretKey::new(&mut rand::thread_rng());
/// # }
/// ```
pub struct SecretKey([u8; constants::SECRET_KEY_SIZE]);
impl_array_newtype!(SecretKey, u8, constants::SECRET_KEY_SIZE);
impl_display_secret!(SecretKey);

impl str::FromStr for SecretKey {
    type Err = Error;
    fn from_str(s: &str) -> Result<SecretKey, Error> {
        let mut res = [0u8; constants::SECRET_KEY_SIZE];
        match from_hex(s, &mut res) {
            Ok(constants::SECRET_KEY_SIZE) => SecretKey::from_slice(&res),
            _ => Err(Error::InvalidSecretKey)
        }
    }
}

/// The number 1 encoded as a secret key.
pub const ONE_KEY: SecretKey = SecretKey([0, 0, 0, 0, 0, 0, 0, 0,
                                          0, 0, 0, 0, 0, 0, 0, 0,
                                          0, 0, 0, 0, 0, 0, 0, 0,
                                          0, 0, 0, 0, 0, 0, 0, 1]);

/// A Secp256k1 public key, used for verification of signatures.
///
/// # Examples
///
/// Basic usage:
///
/// ```
/// # #[cfg(any(feature =  "alloc", feature = "std"))] {
/// use secp256k1::{SecretKey, Secp256k1, PublicKey};
///
/// let secp = Secp256k1::new();
/// let secret_key = SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order");
/// let public_key = PublicKey::from_secret_key(&secp, &secret_key);
/// # }
/// ```
#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
#[repr(transparent)]
pub struct PublicKey(ffi::PublicKey);

impl fmt::LowerHex for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let ser = self.serialize();
        for ch in &ser[..] {
            write!(f, "{:02x}", *ch)?;
        }
        Ok(())
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(self, f)
    }
}

impl str::FromStr for PublicKey {
    type Err = Error;
    fn from_str(s: &str) -> Result<PublicKey, Error> {
        let mut res = [0u8; constants::UNCOMPRESSED_PUBLIC_KEY_SIZE];
        match from_hex(s, &mut res) {
            Ok(constants::PUBLIC_KEY_SIZE) => {
                PublicKey::from_slice(
                    &res[0..constants::PUBLIC_KEY_SIZE]
                )
            }
            Ok(constants::UNCOMPRESSED_PUBLIC_KEY_SIZE) => {
                PublicKey::from_slice(&res)
            }
            _ => Err(Error::InvalidPublicKey)
        }
    }
}

#[cfg(any(test, feature = "rand"))]
fn random_32_bytes<R: Rng + ?Sized>(rng: &mut R) -> [u8; 32] {
    let mut ret = [0u8; 32];
    rng.fill_bytes(&mut ret);
    ret
}

impl SecretKey {
    /// Generates a new random secret key.
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(all(feature = "std", feature =  "rand-std"))] {
    /// use secp256k1::{rand, SecretKey};
    /// let secret_key = SecretKey::new(&mut rand::thread_rng());
    /// # }
    /// ```
    #[inline]
    #[cfg(any(test, feature = "rand"))]
    #[cfg_attr(docsrs, doc(cfg(feature = "rand")))]
    pub fn new<R: Rng + ?Sized>(rng: &mut R) -> SecretKey {
        let mut data = random_32_bytes(rng);
        unsafe {
            while ffi::secp256k1_ec_seckey_verify(
                ffi::secp256k1_context_no_precomp,
                data.as_c_ptr(),
            ) == 0
            {
                data = random_32_bytes(rng);
            }
        }
        SecretKey(data)
    }

    /// Converts a `SECRET_KEY_SIZE`-byte slice to a secret key.
    ///
    /// # Examples
    ///
    /// ```
    /// use secp256k1::SecretKey;
    /// let sk = SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order");
    /// ```
    #[inline]
    pub fn from_slice(data: &[u8])-> Result<SecretKey, Error> {
        match data.len() {
            constants::SECRET_KEY_SIZE => {
                let mut ret = [0u8; constants::SECRET_KEY_SIZE];
                unsafe {
                    if ffi::secp256k1_ec_seckey_verify(
                        ffi::secp256k1_context_no_precomp,
                        data.as_c_ptr(),
                    ) == 0
                    {
                        return Err(InvalidSecretKey);
                    }
                }
                ret[..].copy_from_slice(data);
                Ok(SecretKey(ret))
            }
            _ => Err(InvalidSecretKey)
        }
    }

    /// Creates a new secret key using data from BIP-340 [`KeyPair`].
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(all(feature = "std", feature =  "rand-std"))] {
    /// use secp256k1::{rand, Secp256k1, SecretKey, KeyPair};
    ///
    /// let secp = Secp256k1::new();
    /// let key_pair = KeyPair::new(&secp, &mut rand::thread_rng());
    /// let secret_key = SecretKey::from_keypair(&key_pair);
    /// # }
    /// ```
    #[inline]
    pub fn from_keypair(keypair: &KeyPair) -> Self {
        let mut sk = [0u8; constants::SECRET_KEY_SIZE];
        unsafe {
            let ret = ffi::secp256k1_keypair_sec(
                ffi::secp256k1_context_no_precomp,
                sk.as_mut_c_ptr(),
                keypair.as_ptr()
            );
            debug_assert_eq!(ret, 1);
        }
        SecretKey(sk)
    }

    /// Serializes the secret key as byte value.
    #[inline]
    pub fn serialize_secret(&self) -> [u8; constants::SECRET_KEY_SIZE] {
        self.0
    }

    #[inline]
    /// Negates one secret key.
    pub fn negate_assign(
        &mut self
    ) {
        unsafe {
            let res = ffi::secp256k1_ec_seckey_negate(
                ffi::secp256k1_context_no_precomp,
                self.as_mut_c_ptr()
            );
            debug_assert_eq!(res, 1);
        }
    }

    #[inline]
    /// Adds one secret key to another, modulo the curve order.
    ///
    /// # Errors
    ///
    /// Returns an error if the resulting key would be invalid or if the tweak was not a 32-byte
    /// length slice.
    pub fn add_assign(
        &mut self,
        other: &[u8],
    ) -> Result<(), Error> {
        if other.len() != 32 {
            return Err(Error::InvalidTweak);
        }
        unsafe {
            if ffi::secp256k1_ec_seckey_tweak_add(
                ffi::secp256k1_context_no_precomp,
                self.as_mut_c_ptr(),
                other.as_c_ptr(),
            ) != 1
            {
                Err(Error::InvalidTweak)
            } else {
                Ok(())
            }
        }
    }

    #[inline]
    /// Multiplies one secret key by another, modulo the curve order. Will
    /// return an error if the resulting key would be invalid or if
    /// the tweak was not a 32-byte length slice.
    pub fn mul_assign(
        &mut self,
        other: &[u8],
    ) -> Result<(), Error> {
        if other.len() != 32 {
            return Err(Error::InvalidTweak);
        }
        unsafe {
            if ffi::secp256k1_ec_seckey_tweak_mul(
                ffi::secp256k1_context_no_precomp,
                self.as_mut_c_ptr(),
                other.as_c_ptr(),
            ) != 1
            {
                Err(Error::InvalidTweak)
            } else {
                Ok(())
            }
        }
    }

    /// Constructs an ECDSA signature for `msg` using the global [`SECP256K1`] context.
    #[inline]
    #[cfg(feature = "global-context")]
    #[cfg_attr(docsrs, doc(cfg(feature = "global-context")))]
    pub fn sign_ecdsa(&self, msg: Message) -> ecdsa::Signature {
        SECP256K1.sign_ecdsa(&msg, self)
    }
}

#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
impl ::serde::Serialize for SecretKey {
    fn serialize<S: ::serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            let mut buf = [0u8; 64];
            s.serialize_str(::to_hex(&self.0, &mut buf).expect("fixed-size hex serialization"))
        } else {
            s.serialize_bytes(&self[..])
        }
    }
}

#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
impl<'de> ::serde::Deserialize<'de> for SecretKey {
    fn deserialize<D: ::serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        if d.is_human_readable() {
            d.deserialize_str(super::serde_util::FromStrVisitor::new(
                "a hex string representing 32 byte SecretKey"
            ))
        } else {
            d.deserialize_bytes(super::serde_util::BytesVisitor::new(
                "raw 32 bytes SecretKey",
                SecretKey::from_slice
            ))
        }
    }
}

impl PublicKey {
    /// Obtains a raw const pointer suitable for use with FFI functions.
    #[inline]
    pub fn as_ptr(&self) -> *const ffi::PublicKey {
        &self.0
    }

    /// Obtains a raw mutable pointer suitable for use with FFI functions.
    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut ffi::PublicKey {
        &mut self.0
    }

    /// Creates a new public key from a [`SecretKey`].
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(all(feature = "std", feature =  "rand-std"))] {
    /// use secp256k1::{rand, Secp256k1, SecretKey, PublicKey};
    ///
    /// let secp = Secp256k1::new();
    /// let secret_key = SecretKey::new(&mut rand::thread_rng());
    /// let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    /// # }
    /// ```
    #[inline]
    pub fn from_secret_key<C: Signing>(secp: &Secp256k1<C>,sk: &SecretKey) -> PublicKey {
        unsafe {
            let mut pk = ffi::PublicKey::new();
            // We can assume the return value because it's not possible to construct
            // an invalid `SecretKey` without transmute trickery or something.
            let res = ffi::secp256k1_ec_pubkey_create(secp.ctx, &mut pk, sk.as_c_ptr());
            debug_assert_eq!(res, 1);
            PublicKey(pk)
        }
    }

    /// Creates a new public key from a [`SecretKey`] and the global [`SECP256K1`] context.
    #[inline]
    #[cfg(feature = "global-context")]
    #[cfg_attr(docsrs, doc(cfg(feature = "global-context")))]
    pub fn from_secret_key_global(sk: &SecretKey) -> PublicKey {
        PublicKey::from_secret_key(&SECP256K1, sk)
    }

    /// Creates a public key directly from a slice.
    #[inline]
    pub fn from_slice(data: &[u8]) -> Result<PublicKey, Error> {
        if data.is_empty() {return Err(Error::InvalidPublicKey);}

        unsafe {
            let mut pk = ffi::PublicKey::new();
            if ffi::secp256k1_ec_pubkey_parse(
                ffi::secp256k1_context_no_precomp,
                &mut pk,
                data.as_c_ptr(),
                data.len() as usize,
            ) == 1
            {
                Ok(PublicKey(pk))
            } else {
                Err(InvalidPublicKey)
            }
        }
    }

    /// Creates a new compressed public key using data from BIP-340 [`KeyPair`].
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(all(feature = "std", feature =  "rand-std"))] {
    /// use secp256k1::{rand, Secp256k1, PublicKey, KeyPair};
    ///
    /// let secp = Secp256k1::new();
    /// let key_pair = KeyPair::new(&secp, &mut rand::thread_rng());
    /// let public_key = PublicKey::from_keypair(&key_pair);
    /// # }
    /// ```
    #[inline]
    pub fn from_keypair(keypair: &KeyPair) -> Self {
        unsafe {
            let mut pk = ffi::PublicKey::new();
            let ret = ffi::secp256k1_keypair_pub(
                ffi::secp256k1_context_no_precomp,
                &mut pk,
                keypair.as_ptr()
            );
            debug_assert_eq!(ret, 1);
            PublicKey(pk)
        }
    }

    #[inline]
    /// Serializes the key as a byte-encoded pair of values. In compressed form the y-coordinate is
    /// represented by only a single bit, as x determines it up to one bit.
    pub fn serialize(&self) -> [u8; constants::PUBLIC_KEY_SIZE] {
        let mut ret = [0u8; constants::PUBLIC_KEY_SIZE];

        unsafe {
            let mut ret_len = constants::PUBLIC_KEY_SIZE as usize;
            let err = ffi::secp256k1_ec_pubkey_serialize(
                ffi::secp256k1_context_no_precomp,
                ret.as_mut_c_ptr(),
                &mut ret_len,
                self.as_c_ptr(),
                ffi::SECP256K1_SER_COMPRESSED,
            );
            debug_assert_eq!(err, 1);
            debug_assert_eq!(ret_len, ret.len());
        }
        ret
    }

    /// Serializes the key as a byte-encoded pair of values, in uncompressed form.
    pub fn serialize_uncompressed(&self) -> [u8; constants::UNCOMPRESSED_PUBLIC_KEY_SIZE] {
        let mut ret = [0u8; constants::UNCOMPRESSED_PUBLIC_KEY_SIZE];

        unsafe {
            let mut ret_len = constants::UNCOMPRESSED_PUBLIC_KEY_SIZE as usize;
            let err = ffi::secp256k1_ec_pubkey_serialize(
                ffi::secp256k1_context_no_precomp,
                ret.as_mut_c_ptr(),
                &mut ret_len,
                self.as_c_ptr(),
                ffi::SECP256K1_SER_UNCOMPRESSED,
            );
            debug_assert_eq!(err, 1);
            debug_assert_eq!(ret_len, ret.len());
        }
        ret
    }

    #[inline]
    /// Negates the public key in place.
    pub fn negate_assign<C: Verification>(
        &mut self,
        secp: &Secp256k1<C>
    ) {
        unsafe {
            let res = ffi::secp256k1_ec_pubkey_negate(secp.ctx, &mut self.0);
            debug_assert_eq!(res, 1);
        }
    }

    #[inline]
    /// Adds the `other` public key to `self` in place.
    ///
    /// # Errors
    ///
    /// Returns an error if the resulting key would be invalid or if the tweak was not a 32-byte
    /// length slice.
    pub fn add_exp_assign<C: Verification>(
        &mut self,
        secp: &Secp256k1<C>,
        other: &[u8]
    ) -> Result<(), Error> {
        if other.len() != 32 {
            return Err(Error::InvalidTweak);
        }
        unsafe {
            if ffi::secp256k1_ec_pubkey_tweak_add(secp.ctx, &mut self.0, other.as_c_ptr()) == 1 {
                Ok(())
            } else {
                Err(Error::InvalidTweak)
            }
        }
    }

    #[inline]
    /// Muliplies the public key in place by the scalar `other`.
    ///
    /// # Errors
    ///
    /// Returns an error if the resulting key would be invalid or if the tweak was not a 32-byte
    /// length slice.
    pub fn mul_assign<C: Verification>(
        &mut self,
        secp: &Secp256k1<C>,
        other: &[u8],
    ) -> Result<(), Error> {
        if other.len() != 32 {
            return Err(Error::InvalidTweak);
        }
        unsafe {
            if ffi::secp256k1_ec_pubkey_tweak_mul(secp.ctx, &mut self.0, other.as_c_ptr()) == 1 {
                Ok(())
            } else {
                Err(Error::InvalidTweak)
            }
        }
    }

    /// Adds a second key to this one, returning the sum.
    ///
    /// # Errors
    ///
    /// If the result would be the point at infinity, i.e. adding this point to its own negation.
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(all(feature = "rand-std", any(feature =  "alloc", feature = "std")))] {
    /// use secp256k1::{rand, Secp256k1};
    ///
    /// let secp = Secp256k1::new();
    /// let mut rng = rand::thread_rng();
    /// let (_, pk1) = secp.generate_keypair(&mut rng);
    /// let (_, pk2) = secp.generate_keypair(&mut rng);
    /// let sum = pk1.combine(&pk2).expect("It's improbable to fail for 2 random public keys");
    /// # }
    ///```
    pub fn combine(&self, other: &PublicKey) -> Result<PublicKey, Error> {
        PublicKey::combine_keys(&[self, other])
    }

    /// Adds the keys in the provided slice together, returning the sum.
    ///
    /// # Errors
    ///
    /// Errors under any of the following conditions:
    /// - The result would be the point at infinity, i.e. adding a point to its own negation.
    /// - The provided slice is empty.
    /// - The number of elements in the provided slice is greater than `i32::MAX`.
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(all(feature = "std", feature =  "rand-std"))] {
    /// use secp256k1::{rand, Secp256k1, PublicKey};
    ///
    /// let secp = Secp256k1::new();
    /// let mut rng = rand::thread_rng();
    /// let (_, pk1) = secp.generate_keypair(&mut rng);
    /// let (_, pk2) = secp.generate_keypair(&mut rng);
    /// let (_, pk3) = secp.generate_keypair(&mut rng);
    /// let sum = PublicKey::combine_keys(&[&pk1, &pk2, &pk3]).expect("It's improbable to fail for 3 random public keys");
    /// # }
    /// ```
    pub fn combine_keys(keys: &[&PublicKey]) -> Result<PublicKey, Error> {
        use core::mem::transmute;
        use core::i32::MAX;

        if keys.is_empty() || keys.len() > MAX as usize {
            return Err(InvalidPublicKeySum);
        }

        unsafe {
            let mut ret = ffi::PublicKey::new();
            let ptrs : &[*const ffi::PublicKey] =
                transmute::<&[&PublicKey], &[*const ffi::PublicKey]>(keys);
            if ffi::secp256k1_ec_pubkey_combine(
                ffi::secp256k1_context_no_precomp,
                &mut ret,
                ptrs.as_c_ptr(),
                keys.len() as i32
            ) == 1
            {
                Ok(PublicKey(ret))
            } else {
                Err(InvalidPublicKeySum)
            }
        }
    }
}

impl CPtr for PublicKey {
    type Target = ffi::PublicKey;
    fn as_c_ptr(&self) -> *const Self::Target {
        self.as_ptr()
    }

    fn as_mut_c_ptr(&mut self) -> *mut Self::Target {
        self.as_mut_ptr()
    }
}


/// Creates a new public key from a FFI public key
impl From<ffi::PublicKey> for PublicKey {
    #[inline]
    fn from(pk: ffi::PublicKey) -> PublicKey {
        PublicKey(pk)
    }
}

#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
impl ::serde::Serialize for PublicKey {
    fn serialize<S: ::serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.collect_str(self)
        } else {
            s.serialize_bytes(&self.serialize())
        }
    }
}

#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
impl<'de> ::serde::Deserialize<'de> for PublicKey {
    fn deserialize<D: ::serde::Deserializer<'de>>(d: D) -> Result<PublicKey, D::Error> {
        if d.is_human_readable() {
            d.deserialize_str(super::serde_util::FromStrVisitor::new(
                "an ASCII hex string representing a public key"
            ))
        } else {
            d.deserialize_bytes(super::serde_util::BytesVisitor::new(
                "a bytestring representing a public key",
                PublicKey::from_slice
            ))
        }
    }
}

impl PartialOrd for PublicKey {
    fn partial_cmp(&self, other: &PublicKey) -> Option<::core::cmp::Ordering> {
        self.serialize().partial_cmp(&other.serialize())
    }
}

impl Ord for PublicKey {
    fn cmp(&self, other: &PublicKey) -> ::core::cmp::Ordering {
        self.serialize().cmp(&other.serialize())
    }
}

/// Opaque data structure that holds a keypair consisting of a secret and a public key.
///
/// # Serde support
///
/// [`Serialize`] and [`Deserialize`] are not implemented for this type, even with the `serde`
/// feature active. This is due to security considerations, see the [`serde_keypair`] documentation
/// for details.
///
/// If the `serde` and `global-context` features are active `KeyPair`s can be serialized and
/// deserialized by annotating them with `#[serde(with = "secp256k1::serde_keypair")]`
/// inside structs or enums for which [`Serialize`] and [`Deserialize`] are being derived.
///
/// # Examples
///
/// Basic usage:
///
/// ```
/// # #[cfg(all(feature = "std", feature =  "rand-std"))] {
/// use secp256k1::{rand, KeyPair, Secp256k1};
///
/// let secp = Secp256k1::new();
/// let (secret_key, public_key) = secp.generate_keypair(&mut rand::thread_rng());
/// let key_pair = KeyPair::from_secret_key(&secp, secret_key);
/// # }
/// ```
/// [`Deserialize`]: serde::Deserialize
/// [`Serialize`]: serde::Serialize
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyPair(ffi::KeyPair);
impl_display_secret!(KeyPair);

impl KeyPair {
    /// Obtains a raw const pointer suitable for use with FFI functions.
    #[inline]
    pub fn as_ptr(&self) -> *const ffi::KeyPair {
        &self.0
    }

    /// Obtains a raw mutable pointer suitable for use with FFI functions.
    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut ffi::KeyPair {
        &mut self.0
    }

    /// Creates a Schnorr [`KeyPair`] directly from generic Secp256k1 secret key.
    ///
    /// # Panics
    ///
    /// Panics if internal representation of the provided [`SecretKey`] does not hold correct secret
    /// key value obtained from Secp256k1 library previously, specifically when secret key value is
    /// out-of-range (0 or in excess of the group order).
    #[inline]
    pub fn from_secret_key<C: Signing>(
        secp: &Secp256k1<C>,
        sk: SecretKey,
    ) -> KeyPair {
        unsafe {
            let mut kp = ffi::KeyPair::new();
            if ffi::secp256k1_keypair_create(secp.ctx, &mut kp, sk.as_c_ptr()) == 1 {
                KeyPair(kp)
            } else {
                panic!("the provided secret key is invalid: it is corrupted or was not produced by Secp256k1 library")
            }
        }
    }

    /// Creates a Schnorr [`KeyPair`] directly from a secret key slice.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidSecretKey`] if the provided data has an incorrect length, exceeds Secp256k1
    /// field `p` value or the corresponding public key is not even.
    #[inline]
    pub fn from_seckey_slice<C: Signing>(
        secp: &Secp256k1<C>,
        data: &[u8],
    ) -> Result<KeyPair, Error> {
        if data.is_empty() || data.len() != constants::SECRET_KEY_SIZE {
            return Err(Error::InvalidSecretKey);
        }

        unsafe {
            let mut kp = ffi::KeyPair::new();
            if ffi::secp256k1_keypair_create(secp.ctx, &mut kp, data.as_c_ptr()) == 1 {
                Ok(KeyPair(kp))
            } else {
                Err(Error::InvalidSecretKey)
            }
        }
    }

    /// Creates a Schnorr [`KeyPair`] directly from a secret key string.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidSecretKey`] if corresponding public key for the provided secret key is not even.
    #[inline]
    pub fn from_seckey_str<C: Signing>(secp: &Secp256k1<C>, s: &str) -> Result<KeyPair, Error> {
        let mut res = [0u8; constants::SECRET_KEY_SIZE];
        match from_hex(s, &mut res) {
            Ok(constants::SECRET_KEY_SIZE) => {
                KeyPair::from_seckey_slice(secp, &res[0..constants::SECRET_KEY_SIZE])
            }
            _ => Err(Error::InvalidPublicKey),
        }
    }

    /// Creates a Schnorr [`KeyPair`] directly from a secret key string and the global [`SECP256K1`] context.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidSecretKey`] if corresponding public key for the provided secret key is not even.
    #[inline]
    #[cfg(feature = "global-context")]
    #[cfg_attr(docsrs, doc(cfg(feature = "global-context")))]
    pub fn from_seckey_str_global(s: &str) -> Result<KeyPair, Error> {
        KeyPair::from_seckey_str(SECP256K1, s)
    }

    /// Generates a new random secret key.
    /// # Examples
    ///
    /// ```
    /// # #[cfg(all(feature = "std", feature =  "rand-std"))] {
    /// use secp256k1::{rand, Secp256k1, SecretKey, KeyPair};
    ///
    /// let secp = Secp256k1::new();
    /// let key_pair = KeyPair::new(&secp, &mut rand::thread_rng());
    /// # }
    /// ```
    #[inline]
    #[cfg(any(test, feature = "rand"))]
    #[cfg_attr(docsrs, doc(cfg(feature = "rand")))]
    pub fn new<R: ::rand::Rng + ?Sized, C: Signing>(secp: &Secp256k1<C>, rng: &mut R) -> KeyPair {
        let mut random_32_bytes = || {
            let mut ret = [0u8; 32];
            rng.fill_bytes(&mut ret);
            ret
        };
        let mut data = random_32_bytes();
        unsafe {
            let mut keypair = ffi::KeyPair::new();
            while ffi::secp256k1_keypair_create(secp.ctx, &mut keypair, data.as_c_ptr()) == 0 {
                data = random_32_bytes();
            }
            KeyPair(keypair)
        }
    }

    /// Generates a new random secret key using the global [`SECP256K1`] context.
    #[inline]
    #[cfg(all(feature = "global-context", feature = "rand"))]
    #[cfg_attr(docsrs, doc(cfg(all(feature = "global-context", feature = "rand"))))]
    pub fn new_global<R: ::rand::Rng + ?Sized>(rng: &mut R) -> KeyPair {
        KeyPair::new(SECP256K1, rng)
    }

    /// Serializes the key pair as a secret key byte value.
    #[inline]
    pub fn serialize_secret(&self) -> [u8; constants::SECRET_KEY_SIZE] {
        *SecretKey::from_keypair(self).as_ref()
    }

    /// Tweaks a keypair by adding the given tweak to the secret key and updating the public key
    /// accordingly.
    ///
    /// # Errors
    ///
    /// Returns an error if the resulting key would be invalid or if the tweak was not a 32-byte
    /// length slice.
    ///
    /// NB: Will not error if the tweaked public key has an odd value and can't be used for
    ///     BIP 340-342 purposes.
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(all(feature = "std", feature =  "rand-std"))] {
    /// use secp256k1::{Secp256k1, KeyPair};
    /// use secp256k1::rand::{RngCore, thread_rng};
    ///
    /// let secp = Secp256k1::new();
    /// let mut tweak = [0u8; 32];
    /// thread_rng().fill_bytes(&mut tweak);
    ///
    /// let mut key_pair = KeyPair::new(&secp, &mut thread_rng());
    /// key_pair.tweak_add_assign(&secp, &tweak).expect("Improbable to fail with a randomly generated tweak");
    /// # }
    /// ```
    // TODO: Add checked implementation
    #[inline]
    pub fn tweak_add_assign<C: Verification>(
        &mut self,
        secp: &Secp256k1<C>,
        tweak: &[u8],
    ) -> Result<(), Error> {
        if tweak.len() != 32 {
            return Err(Error::InvalidTweak);
        }

        unsafe {
            let err = ffi::secp256k1_keypair_xonly_tweak_add(
                secp.ctx,
                &mut self.0,
                tweak.as_c_ptr(),
            );
            if err != 1 {
                return Err(Error::InvalidTweak);
            }

            Ok(())
        }
    }

    /// Gets the [XOnlyPublicKey] for this [KeyPair].
    #[inline]
    pub fn public_key(&self) -> XOnlyPublicKey {
        XOnlyPublicKey::from_keypair(self)
    }

    /// Constructs an schnorr signature for `msg` using the global [`SECP256K1`] context.
    #[inline]
    #[cfg(all(feature = "global-context", feature = "rand-std"))]
    #[cfg_attr(docsrs, doc(cfg(all(feature = "global-context", feature = "rand-std"))))]
    pub fn sign_schnorr(&self, msg: Message) -> schnorr::Signature {
        SECP256K1.sign_schnorr(&msg, self)
    }
}

impl From<KeyPair> for SecretKey {
    #[inline]
    fn from(pair: KeyPair) -> Self {
        SecretKey::from_keypair(&pair)
    }
}

impl<'a> From<&'a KeyPair> for SecretKey {
    #[inline]
    fn from(pair: &'a KeyPair) -> Self {
        SecretKey::from_keypair(pair)
    }
}

impl From<KeyPair> for PublicKey {
    #[inline]
    fn from(pair: KeyPair) -> Self {
        PublicKey::from_keypair(&pair)
    }
}

impl<'a> From<&'a KeyPair> for PublicKey {
    #[inline]
    fn from(pair: &'a KeyPair) -> Self {
        PublicKey::from_keypair(pair)
    }
}

impl str::FromStr for KeyPair {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let ctx = unsafe {
            Secp256k1::from_raw_all(ffi::secp256k1_context_no_precomp as *mut ffi::Context)
        };
        KeyPair::from_seckey_str(&ctx, s)
    }
}

#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
impl ::serde::Serialize for KeyPair {
    fn serialize<S: ::serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            let mut buf = [0u8; 64];
            s.serialize_str(::to_hex(&self.serialize_secret(), &mut buf)
                .expect("fixed-size hex serialization"))
        } else {
            s.serialize_bytes(&self.0[..])
        }
    }
}

#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
impl<'de> ::serde::Deserialize<'de> for KeyPair {
    fn deserialize<D: ::serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        if d.is_human_readable() {
            d.deserialize_str(super::serde_util::FromStrVisitor::new(
                "a hex string representing 32 byte KeyPair"
            ))
        } else {
            d.deserialize_bytes(super::serde_util::BytesVisitor::new(
                "raw 32 bytes KeyPair",
                |data| unsafe {
                    let ctx = Secp256k1::from_raw_all(ffi::secp256k1_context_no_precomp as *mut ffi::Context);
                    KeyPair::from_seckey_slice(&ctx, data)
                }
            ))
        }
    }
}

/// An x-only public key, used for verification of Schnorr signatures and serialized according to BIP-340.
///
/// # Examples
///
/// Basic usage:
///
/// ```
/// # #[cfg(all(feature = "std", feature =  "rand-std"))] {
/// use secp256k1::{rand, Secp256k1, KeyPair, XOnlyPublicKey};
///
/// let secp = Secp256k1::new();
/// let key_pair = KeyPair::new(&secp, &mut rand::thread_rng());
/// let xonly = XOnlyPublicKey::from_keypair(&key_pair);
/// # }
/// ```
#[derive(Copy, Clone, PartialEq, Eq, Debug, PartialOrd, Ord, Hash)]
pub struct XOnlyPublicKey(ffi::XOnlyPublicKey);

impl fmt::LowerHex for XOnlyPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let ser = self.serialize();
        for ch in &ser[..] {
            write!(f, "{:02x}", *ch)?;
        }
        Ok(())
    }
}

impl fmt::Display for XOnlyPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(self, f)
    }
}

impl str::FromStr for XOnlyPublicKey {
    type Err = Error;
    fn from_str(s: &str) -> Result<XOnlyPublicKey, Error> {
        let mut res = [0u8; constants::SCHNORRSIG_PUBLIC_KEY_SIZE];
        match from_hex(s, &mut res) {
            Ok(constants::SCHNORRSIG_PUBLIC_KEY_SIZE) => {
                XOnlyPublicKey::from_slice(&res[0..constants::SCHNORRSIG_PUBLIC_KEY_SIZE])
            }
            _ => Err(Error::InvalidPublicKey),
        }
    }
}

impl XOnlyPublicKey {
    /// Obtains a raw const pointer suitable for use with FFI functions.
    #[inline]
    pub fn as_ptr(&self) -> *const ffi::XOnlyPublicKey {
        &self.0
    }

    /// Obtains a raw mutable pointer suitable for use with FFI functions.
    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut ffi::XOnlyPublicKey {
        &mut self.0
    }

    /// Creates a new Schnorr public key from a Schnorr key pair.
    #[inline]
    pub fn from_keypair(keypair: &KeyPair) -> XOnlyPublicKey {
        let mut pk_parity = 0;
        unsafe {
            let mut xonly_pk = ffi::XOnlyPublicKey::new();
            let ret = ffi::secp256k1_keypair_xonly_pub(
                ffi::secp256k1_context_no_precomp,
                &mut xonly_pk,
                &mut pk_parity,
                keypair.as_ptr(),
            );
            debug_assert_eq!(ret, 1);
            XOnlyPublicKey(xonly_pk)
        }
    }

    /// Creates a Schnorr public key directly from a slice.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPublicKey`] if the length of the data slice is not 32 bytes or the
    /// slice does not represent a valid Secp256k1 point x coordinate.
    #[inline]
    pub fn from_slice(data: &[u8]) -> Result<XOnlyPublicKey, Error> {
        if data.is_empty() || data.len() != constants::SCHNORRSIG_PUBLIC_KEY_SIZE {
            return Err(Error::InvalidPublicKey);
        }

        unsafe {
            let mut pk = ffi::XOnlyPublicKey::new();
            if ffi::secp256k1_xonly_pubkey_parse(
                ffi::secp256k1_context_no_precomp,
                &mut pk,
                data.as_c_ptr(),
            ) == 1
            {
                Ok(XOnlyPublicKey(pk))
            } else {
                Err(Error::InvalidPublicKey)
            }
        }
    }

    #[inline]
    /// Serializes the key as a byte-encoded x coordinate value (32 bytes).
    pub fn serialize(&self) -> [u8; constants::SCHNORRSIG_PUBLIC_KEY_SIZE] {
        let mut ret = [0u8; constants::SCHNORRSIG_PUBLIC_KEY_SIZE];

        unsafe {
            let err = ffi::secp256k1_xonly_pubkey_serialize(
                ffi::secp256k1_context_no_precomp,
                ret.as_mut_c_ptr(),
                self.as_c_ptr(),
            );
            debug_assert_eq!(err, 1);
        }
        ret
    }

    /// Tweaks an x-only PublicKey by adding the generator multiplied with the given tweak to it.
    ///
    /// # Returns
    ///
    /// An opaque type representing the parity of the tweaked key, this should be provided to
    /// `tweak_add_check` which can be used to verify a tweak more efficiently than regenerating
    /// it and checking equality.
    ///
    /// # Errors
    ///
    /// If the resulting key would be invalid or if the tweak was not a 32-byte length slice.
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(all(feature = "std", feature =  "rand-std"))] {
    /// use secp256k1::{Secp256k1, KeyPair};
    /// use secp256k1::rand::{RngCore, thread_rng};
    ///
    /// let secp = Secp256k1::new();
    /// let mut tweak = [0u8; 32];
    /// thread_rng().fill_bytes(&mut tweak);
    ///
    /// let mut key_pair = KeyPair::new(&secp, &mut thread_rng());
    /// let mut public_key = key_pair.public_key();
    /// public_key.tweak_add_assign(&secp, &tweak).expect("Improbable to fail with a randomly generated tweak");
    /// # }
    /// ```
    pub fn tweak_add_assign<V: Verification>(
        &mut self,
        secp: &Secp256k1<V>,
        tweak: &[u8],
    ) -> Result<Parity, Error> {
        if tweak.len() != 32 {
            return Err(Error::InvalidTweak);
        }

        unsafe {
            let mut pubkey = ffi::PublicKey::new();
            let mut err = ffi::secp256k1_xonly_pubkey_tweak_add(
                secp.ctx,
                &mut pubkey,
                self.as_c_ptr(),
                tweak.as_c_ptr(),
            );
            if err != 1 {
                return Err(Error::InvalidTweak);
            }

            let mut parity: ::secp256k1_sys::types::c_int = 0;
            err = ffi::secp256k1_xonly_pubkey_from_pubkey(
                secp.ctx,
                &mut self.0,
                &mut parity,
                &pubkey,
            );
            if err == 0 {
                return Err(Error::InvalidPublicKey);
            }

            Parity::from_i32(parity)
        }
    }

    /// Verifies that a tweak produced by [`XOnlyPublicKey::tweak_add_assign`] was computed correctly.
    ///
    /// Should be called on the original untweaked key. Takes the tweaked key and output parity from
    /// [`XOnlyPublicKey::tweak_add_assign`] as input.
    ///
    /// Currently this is not much more efficient than just recomputing the tweak and checking
    /// equality. However, in future this API will support batch verification, which is
    /// significantly faster, so it is wise to design protocols with this in mind.
    ///
    /// # Returns
    ///
    /// True if tweak and check is successful, false otherwise.
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(all(feature = "std", feature =  "rand-std"))] {
    /// use secp256k1::{Secp256k1, KeyPair};
    /// use secp256k1::rand::{thread_rng, RngCore};
    ///
    /// let secp = Secp256k1::new();
    /// let mut tweak = [0u8; 32];
    /// thread_rng().fill_bytes(&mut tweak);
    ///
    /// let mut key_pair = KeyPair::new(&secp, &mut thread_rng());
    /// let mut public_key = key_pair.public_key();
    /// let original = public_key;
    /// let parity = public_key.tweak_add_assign(&secp, &tweak).expect("Improbable to fail with a randomly generated tweak");
    /// assert!(original.tweak_add_check(&secp, &public_key, parity, tweak));
    /// # }
    /// ```
    pub fn tweak_add_check<V: Verification>(
        &self,
        secp: &Secp256k1<V>,
        tweaked_key: &Self,
        tweaked_parity: Parity,
        tweak: [u8; 32],
    ) -> bool {
        let tweaked_ser = tweaked_key.serialize();
        unsafe {
            let err = ffi::secp256k1_xonly_pubkey_tweak_add_check(
                secp.ctx,
                tweaked_ser.as_c_ptr(),
                tweaked_parity.to_i32(),
                &self.0,
                tweak.as_c_ptr(),
            );

            err == 1
        }
    }
}

/// Represents the parity passed between FFI function calls.
#[derive(Copy, Clone, PartialEq, Eq, Debug, PartialOrd, Ord, Hash)]
pub enum Parity {
    /// Even parity.
    Even = 0,
    /// Odd parity.
    Odd = 1,
}

impl Parity {
    /// Converts parity into an integer (byte) value.
    ///
    /// This returns `0` for even parity and `1` for odd parity.
    pub fn to_u8(self) -> u8 {
        self as u8
    }

    /// Converts parity into an integer value.
    ///
    /// This returns `0` for even parity and `1` for odd parity.
    pub fn to_i32(self) -> i32 {
        self as i32
    }

    /// Constructs a [`Parity`] from a byte.
    ///
    /// The only allowed values are `0` meaning even parity and `1` meaning odd.
    /// Other values result in error being returned.
    pub fn from_u8(parity: u8) -> Result<Parity, Error> {
        Parity::from_i32(parity.into())
    }

    /// Constructs a [`Parity`] from a signed integer.
    ///
    /// The only allowed values are `0` meaning even parity and `1` meaning odd.
    /// Other values result in error being returned.
    pub fn from_i32(parity: i32) -> Result<Parity, Error> {
        match parity {
            0 => Ok(Parity::Even),
            1 => Ok(Parity::Odd),
            _ => Err(Error::InvalidParityValue),
        }
    }
}

impl From<i32> for Parity {
    /// Please note, this method is deprecated and will be removed in an upcoming release, it
    /// is **not** equivalent to `from_u32()`, it is better to use `Parity::from_u32`.
    ///
    /// This method returns same parity as the parity of input integer.
    fn from(parity: i32) -> Parity {
        if parity % 2 == 0 {
            Parity::Even
        } else {
            Parity::Odd
        }
    }
}

/// The conversion returns `0` for even parity and `1` for odd.
impl From<Parity> for i32 {
    fn from(parity: Parity) -> i32 {
        parity.to_i32()
    }
}

/// Returns even parity if the operands are equal, odd otherwise.
impl BitXor for Parity {
    type Output = Parity;

    fn bitxor(self, rhs: Parity) -> Self::Output {
        // This works because Parity has only two values (i.e. only 1 bit of information).
        if self == rhs {
            Parity::Even        // 1^1==0 and 0^0==0
        } else {
            Parity::Odd         // 1^0==1 and 0^1==1
        }
    }
}

/// The parity is serialized as `i32` - `0` for even, `1` for odd.
#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
impl ::serde::Serialize for Parity {
    fn serialize<S: ::serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_i32(self.to_i32())
    }
}

/// The parity is deserialized as `i32` - `0` for even, `1` for odd.
#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
impl<'de> ::serde::Deserialize<'de> for Parity {
    fn deserialize<D: ::serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct I32Visitor;

        impl<'de> ::serde::de::Visitor<'de> for I32Visitor
        {
            type Value = Parity;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("32-bit integer with value 0 or 1")
            }

            fn visit_i32<E>(self, v: i32) -> Result<Self::Value, E>
                where E: ::serde::de::Error
            {
                use serde::de::Unexpected;

                Parity::from_i32(v)
                    .map_err(|_| E::invalid_value(Unexpected::Signed(v.into()), &"0 or 1"))
            }
        }

        d.deserialize_i32(I32Visitor)
    }
}

impl CPtr for XOnlyPublicKey {
    type Target = ffi::XOnlyPublicKey;
    fn as_c_ptr(&self) -> *const Self::Target {
        self.as_ptr()
    }

    fn as_mut_c_ptr(&mut self) -> *mut Self::Target {
        self.as_mut_ptr()
    }
}

/// Creates a new Schnorr public key from a FFI x-only public key.
impl From<ffi::XOnlyPublicKey> for XOnlyPublicKey {
    #[inline]
    fn from(pk: ffi::XOnlyPublicKey) -> XOnlyPublicKey {
        XOnlyPublicKey(pk)
    }
}

impl From<::key::PublicKey> for XOnlyPublicKey {
    fn from(src: ::key::PublicKey) -> XOnlyPublicKey {
        unsafe {
            let mut pk = ffi::XOnlyPublicKey::new();
            assert_eq!(
                1,
                ffi::secp256k1_xonly_pubkey_from_pubkey(
                    ffi::secp256k1_context_no_precomp,
                    &mut pk,
                    ptr::null_mut(),
                    src.as_c_ptr(),
                )
            );
            XOnlyPublicKey(pk)
        }
    }
}

#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
impl ::serde::Serialize for XOnlyPublicKey {
    fn serialize<S: ::serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.collect_str(self)
        } else {
            s.serialize_bytes(&self.serialize())
        }
    }
}

#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
impl<'de> ::serde::Deserialize<'de> for XOnlyPublicKey {
    fn deserialize<D: ::serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        if d.is_human_readable() {
            d.deserialize_str(super::serde_util::FromStrVisitor::new(
                "a hex string representing 32 byte schnorr public key"
            ))
        } else {
            d.deserialize_bytes(super::serde_util::BytesVisitor::new(
                "raw 32 bytes schnorr public key",
                XOnlyPublicKey::from_slice
            ))
        }
    }
}

/// Serde implementation for the [`KeyPair`] type.
///
/// Only the secret key part of the [`KeyPair`] is serialized using the [`SecretKey`] serde
/// implementation, meaning the public key has to be regenerated on deserialization.
///
/// **Attention:** The deserialization algorithm uses the [global context] to generate the public key
/// belonging to the secret key to form a [`KeyPair`]. The typical caveats regarding use of the
/// [global context] with secret data apply.
///
/// [`SecretKey`]: crate::SecretKey
/// [global context]: crate::SECP256K1
#[cfg(all(feature = "global-context", feature = "serde"))]
pub mod serde_keypair {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use key::KeyPair;
    use key::SecretKey;

    #[allow(missing_docs)]
    pub fn serialize<S>(key: &KeyPair, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
    {
        SecretKey::from_keypair(key).serialize(serializer)
    }

    #[allow(missing_docs)]
    pub fn deserialize<'de, D>(deserializer: D) -> Result<KeyPair, D::Error>
        where
            D: Deserializer<'de>,
    {
        let secret_key = SecretKey::deserialize(deserializer)?;

        Ok(KeyPair::from_secret_key(
            &::SECP256K1,
            secret_key,
        ))
    }
}

#[cfg(test)]
#[allow(unused_imports)]
mod test {
    use super::*;

    #[cfg(any(feature = "alloc", feature = "std"))]
    use core::iter;
    use core::str::FromStr;

    #[cfg(any(feature = "alloc", feature = "std"))]
    use rand::{Error, ErrorKind, RngCore, thread_rng};
    #[cfg(any(feature = "alloc", feature = "std"))]
    use rand_core::impls;

    use constants;
    use Error::{InvalidPublicKey, InvalidSecretKey};

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
    fn skey_from_slice() {
        let sk = SecretKey::from_slice(&[1; 31]);
        assert_eq!(sk, Err(InvalidSecretKey));

        let sk = SecretKey::from_slice(&[1; 32]);
        assert!(sk.is_ok());
    }

    #[test]
    fn pubkey_from_slice() {
        assert_eq!(PublicKey::from_slice(&[]), Err(InvalidPublicKey));
        assert_eq!(PublicKey::from_slice(&[1, 2, 3]), Err(InvalidPublicKey));

        let uncompressed = PublicKey::from_slice(&[4, 54, 57, 149, 239, 162, 148, 175, 246, 254, 239, 75, 154, 152, 10, 82, 234, 224, 85, 220, 40, 100, 57, 121, 30, 162, 94, 156, 135, 67, 74, 49, 179, 57, 236, 53, 162, 124, 149, 144, 168, 77, 74, 30, 72, 211, 229, 110, 111, 55, 96, 193, 86, 227, 183, 152, 195, 155, 51, 247, 123, 113, 60, 228, 188]);
        assert!(uncompressed.is_ok());

        let compressed = PublicKey::from_slice(&[3, 23, 183, 225, 206, 31, 159, 148, 195, 42, 67, 115, 146, 41, 248, 140, 11, 3, 51, 41, 111, 180, 110, 143, 114, 134, 88, 73, 198, 174, 52, 184, 78]);
        assert!(compressed.is_ok());
    }

    #[test]
    #[cfg(any(feature = "alloc", feature = "std"))]
    fn keypair_slice_round_trip() {
        let s = Secp256k1::new();

        let (sk1, pk1) = s.generate_keypair(&mut thread_rng());
        assert_eq!(SecretKey::from_slice(&sk1[..]), Ok(sk1));
        assert_eq!(PublicKey::from_slice(&pk1.serialize()[..]), Ok(pk1));
        assert_eq!(PublicKey::from_slice(&pk1.serialize_uncompressed()[..]), Ok(pk1));
    }

    #[test]
    #[cfg(any(feature = "alloc", feature = "std"))]
    fn invalid_secret_key() {
        // Zero
        assert_eq!(SecretKey::from_slice(&[0; 32]), Err(InvalidSecretKey));
        assert_eq!(
            SecretKey::from_str("0000000000000000000000000000000000000000000000000000000000000000"),
            Err(InvalidSecretKey)
        );
        // -1
        assert_eq!(SecretKey::from_slice(&[0xff; 32]), Err(InvalidSecretKey));
        // Top of range
        assert!(SecretKey::from_slice(&[
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
            0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
            0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x40,
        ]).is_ok());
        // One past top of range
        assert!(SecretKey::from_slice(&[
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
            0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
            0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
        ]).is_err());
    }

    #[test]
    #[cfg(any(feature = "alloc", feature = "std"))]
    fn test_out_of_range() {

        struct BadRng(u8);
        impl RngCore for BadRng {
            fn next_u32(&mut self) -> u32 { unimplemented!() }
            fn next_u64(&mut self) -> u64 { unimplemented!() }
            // This will set a secret key to a little over the
            // group order, then decrement with repeated calls
            // until it returns a valid key
            fn fill_bytes(&mut self, data: &mut [u8]) {
                let group_order: [u8; 32] = [
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
                    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
                    0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41];
                assert_eq!(data.len(), 32);
                data.copy_from_slice(&group_order[..]);
                data[31] = self.0;
                self.0 -= 1;
            }
            fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
                self.fill_bytes(dest);
                Ok(())
            }
        }

        let s = Secp256k1::new();
        s.generate_keypair(&mut BadRng(0xff));
    }

    #[test]
    fn test_pubkey_from_bad_slice() {
        // Bad sizes
        assert_eq!(
            PublicKey::from_slice(&[0; constants::PUBLIC_KEY_SIZE - 1]),
            Err(InvalidPublicKey)
        );
        assert_eq!(
            PublicKey::from_slice(&[0; constants::PUBLIC_KEY_SIZE + 1]),
            Err(InvalidPublicKey)
        );
        assert_eq!(
            PublicKey::from_slice(&[0; constants::UNCOMPRESSED_PUBLIC_KEY_SIZE - 1]),
            Err(InvalidPublicKey)
        );
        assert_eq!(
            PublicKey::from_slice(&[0; constants::UNCOMPRESSED_PUBLIC_KEY_SIZE + 1]),
            Err(InvalidPublicKey)
        );

        // Bad parse
        assert_eq!(
            PublicKey::from_slice(&[0xff; constants::UNCOMPRESSED_PUBLIC_KEY_SIZE]),
            Err(InvalidPublicKey)
        );
        assert_eq!(
            PublicKey::from_slice(&[0x55; constants::PUBLIC_KEY_SIZE]),
            Err(InvalidPublicKey)
        );
        assert_eq!(
            PublicKey::from_slice(&[]),
            Err(InvalidPublicKey)
        );
    }

    #[test]
    fn test_seckey_from_bad_slice() {
        // Bad sizes
        assert_eq!(
            SecretKey::from_slice(&[0; constants::SECRET_KEY_SIZE - 1]),
            Err(InvalidSecretKey)
        );
        assert_eq!(
            SecretKey::from_slice(&[0; constants::SECRET_KEY_SIZE + 1]),
            Err(InvalidSecretKey)
        );
        // Bad parse
        assert_eq!(
            SecretKey::from_slice(&[0xff; constants::SECRET_KEY_SIZE]),
            Err(InvalidSecretKey)
        );
        assert_eq!(
            SecretKey::from_slice(&[0x00; constants::SECRET_KEY_SIZE]),
            Err(InvalidSecretKey)
        );
        assert_eq!(
            SecretKey::from_slice(&[]),
            Err(InvalidSecretKey)
        );
    }

    #[test]
    #[cfg(all(feature = "rand", any(feature = "alloc", feature = "std")))]
    fn test_debug_output() {
        use to_hex;

        struct DumbRng(u32);
        impl RngCore for DumbRng {
            fn next_u32(&mut self) -> u32 {
                self.0 = self.0.wrapping_add(1);
                self.0
            }
            fn next_u64(&mut self) -> u64 {
                self.next_u32() as u64
            }
            fn fill_bytes(&mut self, dest: &mut [u8]) {
                impls::fill_bytes_via_next(self, dest);
            }

            fn try_fill_bytes(&mut self, _dest: &mut [u8]) -> Result<(), Error> {
                Err(Error::new(ErrorKind::Unavailable, "not implemented"))
            }
        }

        let s = Secp256k1::new();
        let (sk, _) = s.generate_keypair(&mut DumbRng(0));

        assert_eq!(&format!("{:?}", sk),
                   "SecretKey(#d3e0c51a23169bb5)");

        let mut buf = [0u8; constants::SECRET_KEY_SIZE * 2];
        assert_eq!(to_hex(&sk[..], &mut buf).unwrap(),
                   "0100000000000000020000000000000003000000000000000400000000000000");
    }

    #[test]
    #[cfg(any(feature = "alloc", feature = "std"))]
    fn test_display_output() {
        static SK_BYTES: [u8; 32] = [
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0xff, 0xff, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00,
            0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63,
        ];

        #[cfg(not(fuzzing))]
        let s = Secp256k1::signing_only();
        let sk = SecretKey::from_slice(&SK_BYTES).expect("sk");

        // In fuzzing mode secret->public key derivation is different, so
        // hard-code the expected result.
        #[cfg(not(fuzzing))]
        let pk = PublicKey::from_secret_key(&s, &sk);
        #[cfg(fuzzing)]
        let pk = PublicKey::from_slice(&[0x02, 0x18, 0x84, 0x57, 0x81, 0xf6, 0x31, 0xc4, 0x8f, 0x1c, 0x97, 0x09, 0xe2, 0x30, 0x92, 0x06, 0x7d, 0x06, 0x83, 0x7f, 0x30, 0xaa, 0x0c, 0xd0, 0x54, 0x4a, 0xc8, 0x87, 0xfe, 0x91, 0xdd, 0xd1, 0x66]).expect("pk");

        assert_eq!(
            sk.display_secret().to_string(),
            "01010101010101010001020304050607ffff0000ffff00006363636363636363"
        );
        assert_eq!(
            SecretKey::from_str("01010101010101010001020304050607ffff0000ffff00006363636363636363").unwrap(),
            sk
        );
        assert_eq!(
            pk.to_string(),
            "0218845781f631c48f1c9709e23092067d06837f30aa0cd0544ac887fe91ddd166"
        );
        assert_eq!(
            PublicKey::from_str("0218845781f631c48f1c9709e23092067d06837f30aa0cd0544ac887fe91ddd166").unwrap(),
            pk
        );
        assert_eq!(
            PublicKey::from_str("04\
                18845781f631c48f1c9709e23092067d06837f30aa0cd0544ac887fe91ddd166\
                84B84DB303A340CD7D6823EE88174747D12A67D2F8F2F9BA40846EE5EE7A44F6"
            ).unwrap(),
            pk
        );

        assert!(SecretKey::from_str("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").is_err());
        assert!(SecretKey::from_str("01010101010101010001020304050607ffff0000ffff0000636363636363636363").is_err());
        assert!(SecretKey::from_str("01010101010101010001020304050607ffff0000ffff0000636363636363636").is_err());
        assert!(SecretKey::from_str("01010101010101010001020304050607ffff0000ffff000063636363636363").is_err());
        assert!(SecretKey::from_str("01010101010101010001020304050607ffff0000ffff000063636363636363xx").is_err());
        assert!(PublicKey::from_str("0300000000000000000000000000000000000000000000000000000000000000000").is_err());
        assert!(PublicKey::from_str("0218845781f631c48f1c9709e23092067d06837f30aa0cd0544ac887fe91ddd16601").is_err());
        assert!(PublicKey::from_str("0218845781f631c48f1c9709e23092067d06837f30aa0cd0544ac887fe91ddd16").is_err());
        assert!(PublicKey::from_str("0218845781f631c48f1c9709e23092067d06837f30aa0cd0544ac887fe91ddd1").is_err());
        assert!(PublicKey::from_str("xx0218845781f631c48f1c9709e23092067d06837f30aa0cd0544ac887fe91ddd1").is_err());

        let long_str: String = iter::repeat('a').take(1024 * 1024).collect();
        assert!(SecretKey::from_str(&long_str).is_err());
        assert!(PublicKey::from_str(&long_str).is_err());
    }

    #[test]
    // In fuzzing mode the Y coordinate is expected to match the X, so this
    // test uses invalid public keys.
    #[cfg(not(fuzzing))]
    #[cfg(any(feature = "alloc", feature = "std"))]
    fn test_pubkey_serialize() {
        struct DumbRng(u32);
        impl RngCore for DumbRng {
            fn next_u32(&mut self) -> u32 {
                self.0 = self.0.wrapping_add(1);
                self.0
            }
            fn next_u64(&mut self) -> u64 {
                self.next_u32() as u64
            }
            fn try_fill_bytes(&mut self, _dest: &mut [u8]) -> Result<(), Error> {
                Err(Error::new(ErrorKind::Unavailable, "not implemented"))
            }

            fn fill_bytes(&mut self, dest: &mut [u8]) {
                impls::fill_bytes_via_next(self, dest);
            }
        }

        let s = Secp256k1::new();
        let (_, pk1) = s.generate_keypair(&mut DumbRng(0));
        assert_eq!(&pk1.serialize_uncompressed()[..],
                   &[4, 124, 121, 49, 14, 253, 63, 197, 50, 39, 194, 107, 17, 193, 219, 108, 154, 126, 9, 181, 248, 2, 12, 149, 233, 198, 71, 149, 134, 250, 184, 154, 229, 185, 28, 165, 110, 27, 3, 162, 126, 238, 167, 157, 242, 221, 76, 251, 237, 34, 231, 72, 39, 245, 3, 191, 64, 111, 170, 117, 103, 82, 28, 102, 163][..]);
        assert_eq!(&pk1.serialize()[..],
                   &[3, 124, 121, 49, 14, 253, 63, 197, 50, 39, 194, 107, 17, 193, 219, 108, 154, 126, 9, 181, 248, 2, 12, 149, 233, 198, 71, 149, 134, 250, 184, 154, 229][..]);
    }

    #[test]
    #[cfg(any(feature = "alloc", feature = "std"))]
    fn test_addition() {
        let s = Secp256k1::new();

        let (mut sk1, mut pk1) = s.generate_keypair(&mut thread_rng());
        let (mut sk2, mut pk2) = s.generate_keypair(&mut thread_rng());

        assert_eq!(PublicKey::from_secret_key(&s, &sk1), pk1);
        assert!(sk1.add_assign(&sk2[..]).is_ok());
        assert!(pk1.add_exp_assign(&s, &sk2[..]).is_ok());
        assert_eq!(PublicKey::from_secret_key(&s, &sk1), pk1);

        assert_eq!(PublicKey::from_secret_key(&s, &sk2), pk2);
        assert!(sk2.add_assign(&sk1[..]).is_ok());
        assert!(pk2.add_exp_assign(&s, &sk1[..]).is_ok());
        assert_eq!(PublicKey::from_secret_key(&s, &sk2), pk2);
    }

    #[test]
    #[cfg(any(feature = "alloc", feature = "std"))]
    fn test_multiplication() {
        let s = Secp256k1::new();

        let (mut sk1, mut pk1) = s.generate_keypair(&mut thread_rng());
        let (mut sk2, mut pk2) = s.generate_keypair(&mut thread_rng());

        assert_eq!(PublicKey::from_secret_key(&s, &sk1), pk1);
        assert!(sk1.mul_assign(&sk2[..]).is_ok());
        assert!(pk1.mul_assign(&s, &sk2[..]).is_ok());
        assert_eq!(PublicKey::from_secret_key(&s, &sk1), pk1);

        assert_eq!(PublicKey::from_secret_key(&s, &sk2), pk2);
        assert!(sk2.mul_assign(&sk1[..]).is_ok());
        assert!(pk2.mul_assign(&s, &sk1[..]).is_ok());
        assert_eq!(PublicKey::from_secret_key(&s, &sk2), pk2);
    }

    #[test]
    #[cfg(any(feature = "alloc", feature = "std"))]
    fn test_negation() {
        let s = Secp256k1::new();

        let (mut sk, mut pk) = s.generate_keypair(&mut thread_rng());

        let original_sk = sk;
        let original_pk = pk;

        assert_eq!(PublicKey::from_secret_key(&s, &sk), pk);
        sk.negate_assign();
        pk.negate_assign(&s);
        assert_ne!(original_sk, sk);
        assert_ne!(original_pk, pk);
        sk.negate_assign();
        pk.negate_assign(&s);
        assert_eq!(original_sk, sk);
        assert_eq!(original_pk, pk);
        assert_eq!(PublicKey::from_secret_key(&s, &sk), pk);
    }

    #[test]
    #[cfg(any(feature = "alloc", feature = "std"))]
    fn pubkey_hash() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        use std::collections::HashSet;

        fn hash<T: Hash>(t: &T) -> u64 {
            let mut s = DefaultHasher::new();
            t.hash(&mut s);
            s.finish()
        }

        let s = Secp256k1::new();
        let mut set = HashSet::new();
        const COUNT : usize = 1024;
        for _ in 0..COUNT {
            let (_, pk) = s.generate_keypair(&mut thread_rng());
            let hash = hash(&pk);
            assert!(!set.contains(&hash));
            set.insert(hash);
        };
        assert_eq!(set.len(), COUNT);
    }

    #[test]
    #[cfg(not(fuzzing))]
    fn pubkey_combine() {
        let compressed1 = PublicKey::from_slice(
            &hex!("0241cc121c419921942add6db6482fb36243faf83317c866d2a28d8c6d7089f7ba"),
        ).unwrap();
        let compressed2 = PublicKey::from_slice(
            &hex!("02e6642fd69bd211f93f7f1f36ca51a26a5290eb2dd1b0d8279a87bb0d480c8443"),
        ).unwrap();
        let exp_sum = PublicKey::from_slice(
            &hex!("0384526253c27c7aef56c7b71a5cd25bebb66dddda437826defc5b2568bde81f07"),
        ).unwrap();

        let sum1 = compressed1.combine(&compressed2);
        assert!(sum1.is_ok());
        let sum2 = compressed2.combine(&compressed1);
        assert!(sum2.is_ok());
        assert_eq!(sum1, sum2);
        assert_eq!(sum1.unwrap(), exp_sum);
    }

    #[test]
    #[cfg(not(fuzzing))]
    fn pubkey_combine_keys() {
        let compressed1 = PublicKey::from_slice(
            &hex!("0241cc121c419921942add6db6482fb36243faf83317c866d2a28d8c6d7089f7ba"),
        ).unwrap();
        let compressed2 = PublicKey::from_slice(
            &hex!("02e6642fd69bd211f93f7f1f36ca51a26a5290eb2dd1b0d8279a87bb0d480c8443"),
        ).unwrap();
        let compressed3 = PublicKey::from_slice(
            &hex!("03e74897d8644eb3e5b391ca2ab257aec2080f4d1a95cad57e454e47f021168eb0")
        ).unwrap();
        let exp_sum = PublicKey::from_slice(
            &hex!("0252d73a47f66cf341e5651542f0348f452b7c793af62a6d8bff75ade703a451ad"),
        ).unwrap();

        let sum1 = PublicKey::combine_keys(&[&compressed1, &compressed2, &compressed3]);
        assert!(sum1.is_ok());
        let sum2 = PublicKey::combine_keys(&[&compressed1, &compressed2, &compressed3]);
        assert!(sum2.is_ok());
        assert_eq!(sum1, sum2);
        assert_eq!(sum1.unwrap(), exp_sum);
    }

    #[test]
    #[cfg(not(fuzzing))]
    fn pubkey_combine_keys_empty_slice() {
        assert!(PublicKey::combine_keys(&[]).is_err());
    }

    #[test]
    #[cfg(any(feature = "alloc", feature = "std"))]
    fn create_pubkey_combine() {
        let s = Secp256k1::new();

        let (mut sk1, pk1) = s.generate_keypair(&mut thread_rng());
        let (sk2, pk2) = s.generate_keypair(&mut thread_rng());

        let sum1 = pk1.combine(&pk2);
        assert!(sum1.is_ok());
        let sum2 = pk2.combine(&pk1);
        assert!(sum2.is_ok());
        assert_eq!(sum1, sum2);

        assert!(sk1.add_assign(&sk2.as_ref()[..]).is_ok());
        let sksum = PublicKey::from_secret_key(&s, &sk1);
        assert_eq!(Ok(sksum), sum1);
    }

    #[test]
    fn pubkey_equal() {
        let pk1 = PublicKey::from_slice(
            &hex!("0241cc121c419921942add6db6482fb36243faf83317c866d2a28d8c6d7089f7ba"),
        ).unwrap();
        let pk2 = pk1;
        let pk3 = PublicKey::from_slice(
            &hex!("02e6642fd69bd211f93f7f1f36ca51a26a5290eb2dd1b0d8279a87bb0d480c8443"),
        ).unwrap();

        assert!(pk1 == pk2);
        assert!(pk1 <= pk2);
        assert!(pk2 <= pk1);
        assert!(!(pk2 < pk1));
        assert!(!(pk1 < pk2));

        assert!(pk3 > pk1);
        assert!(pk1 < pk3);
        assert!(pk3 >= pk1);
        assert!(pk1 <= pk3);
    }

    #[test]
    #[cfg(all(feature = "serde", any(feature = "alloc", feature = "std")))]
    fn test_serde() {
        use serde_test::{Configure, Token, assert_tokens};
        static SK_BYTES: [u8; 32] = [
            1, 1, 1, 1, 1, 1, 1, 1,
            0, 1, 2, 3, 4, 5, 6, 7,
            0xff, 0xff, 0, 0, 0xff, 0xff, 0, 0,
            99, 99, 99, 99, 99, 99, 99, 99
        ];
        static SK_STR: &'static str = "\
            01010101010101010001020304050607ffff0000ffff00006363636363636363\
        ";
        static PK_BYTES: [u8; 33] = [
            0x02,
            0x18, 0x84, 0x57, 0x81, 0xf6, 0x31, 0xc4, 0x8f,
            0x1c, 0x97, 0x09, 0xe2, 0x30, 0x92, 0x06, 0x7d,
            0x06, 0x83, 0x7f, 0x30, 0xaa, 0x0c, 0xd0, 0x54,
            0x4a, 0xc8, 0x87, 0xfe, 0x91, 0xdd, 0xd1, 0x66,
        ];
        static PK_STR: &'static str = "\
            0218845781f631c48f1c9709e23092067d06837f30aa0cd0544ac887fe91ddd166\
        ";

        #[cfg(not(fuzzing))]
        let s = Secp256k1::new();
        let sk = SecretKey::from_slice(&SK_BYTES).unwrap();

        // In fuzzing mode secret->public key derivation is different, so
        // hard-code the expected result.
        #[cfg(not(fuzzing))]
        let pk = PublicKey::from_secret_key(&s, &sk);
        #[cfg(fuzzing)]
        let pk = PublicKey::from_slice(&PK_BYTES).expect("pk");

        assert_tokens(&sk.compact(), &[Token::BorrowedBytes(&SK_BYTES[..])]);
        assert_tokens(&sk.compact(), &[Token::Bytes(&SK_BYTES)]);
        assert_tokens(&sk.compact(), &[Token::ByteBuf(&SK_BYTES)]);

        assert_tokens(&sk.readable(), &[Token::BorrowedStr(SK_STR)]);
        assert_tokens(&sk.readable(), &[Token::Str(SK_STR)]);
        assert_tokens(&sk.readable(), &[Token::String(SK_STR)]);

        assert_tokens(&pk.compact(), &[Token::BorrowedBytes(&PK_BYTES[..])]);
        assert_tokens(&pk.compact(), &[Token::Bytes(&PK_BYTES)]);
        assert_tokens(&pk.compact(), &[Token::ByteBuf(&PK_BYTES)]);

        assert_tokens(&pk.readable(), &[Token::BorrowedStr(PK_STR)]);
        assert_tokens(&pk.readable(), &[Token::Str(PK_STR)]);
        assert_tokens(&pk.readable(), &[Token::String(PK_STR)]);

    }

    #[test]
    #[cfg(any(feature = "alloc", feature = "std"))]
    fn test_tweak_add_assign_then_tweak_add_check() {
        let s = Secp256k1::new();

        for _ in 0..10 {
            let mut tweak = [0u8; 32];
            thread_rng().fill_bytes(&mut tweak);

            let mut kp = KeyPair::new(&s, &mut thread_rng());
            let mut pk = kp.public_key();

            let orig_pk = pk;
            kp.tweak_add_assign(&s, &tweak).expect("Tweak error");
            let parity = pk.tweak_add_assign(&s, &tweak).expect("Tweak error");
            assert_eq!(XOnlyPublicKey::from_keypair(&kp), pk);
            assert!(orig_pk.tweak_add_check(&s, &pk, parity, tweak));
        }
    }

    #[test]
    fn test_from_key_pubkey() {
        let kpk1 = PublicKey::from_str(
            "02e6642fd69bd211f93f7f1f36ca51a26a5290eb2dd1b0d8279a87bb0d480c8443",
        )
        .unwrap();
        let kpk2 = PublicKey::from_str(
            "0384526253c27c7aef56c7b71a5cd25bebb66dddda437826defc5b2568bde81f07",
        )
        .unwrap();

        let pk1 = XOnlyPublicKey::from(kpk1);
        let pk2 = XOnlyPublicKey::from(kpk2);

        assert_eq!(pk1.serialize()[..], kpk1.serialize()[1..]);
        assert_eq!(pk2.serialize()[..], kpk2.serialize()[1..]);
    }

    #[test]
    #[cfg(all(feature = "global-context", feature = "serde"))]
    fn test_serde_keypair() {
        use serde::{Deserialize, Deserializer, Serialize, Serializer};
        use serde_test::{Configure, Token, assert_tokens};
        use super::serde_keypair;
        use key::KeyPair;

        // Normally users would derive the serde traits, but we can't easily enable the serde macros
        // here, so they are implemented manually to be able to test the behaviour.
        #[derive(Debug, Copy, Clone, Eq, PartialEq)]
        struct KeyPairWrapper(KeyPair);

        impl<'de> Deserialize<'de> for KeyPairWrapper {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
                where D: Deserializer<'de> {
                serde_keypair::deserialize(deserializer).map(KeyPairWrapper)
            }
        }

        impl Serialize for KeyPairWrapper {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
                serde_keypair::serialize(&self.0, serializer)
            }
        }

        static SK_BYTES: [u8; 32] = [
            1, 1, 1, 1, 1, 1, 1, 1,
            0, 1, 2, 3, 4, 5, 6, 7,
            0xff, 0xff, 0, 0, 0xff, 0xff, 0, 0,
            99, 99, 99, 99, 99, 99, 99, 99
        ];
        static SK_STR: &'static str = "\
            01010101010101010001020304050607ffff0000ffff00006363636363636363\
        ";

        let sk = KeyPairWrapper(KeyPair::from_seckey_slice(&::SECP256K1, &SK_BYTES).unwrap());

        assert_tokens(&sk.compact(), &[Token::BorrowedBytes(&SK_BYTES[..])]);
        assert_tokens(&sk.compact(), &[Token::Bytes(&SK_BYTES)]);
        assert_tokens(&sk.compact(), &[Token::ByteBuf(&SK_BYTES)]);

        assert_tokens(&sk.readable(), &[Token::BorrowedStr(SK_STR)]);
        assert_tokens(&sk.readable(), &[Token::Str(SK_STR)]);
        assert_tokens(&sk.readable(), &[Token::String(SK_STR)]);
    }
}
