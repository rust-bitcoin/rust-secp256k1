// SPDX-License-Identifier: CC0-1.0

//! Public and secret keys.
//!

mod secret;

use core::ops::BitXor;
use core::{fmt, ptr, str};

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
#[cfg(feature = "serde")]
use serde::ser::SerializeTuple;

pub use self::secret::SecretKey;
use crate::ellswift::ElligatorSwift;
use crate::ffi::types::c_uint;
use crate::ffi::{self, CPtr};
use crate::Error::{self, InvalidPublicKey, InvalidPublicKeySum};
use crate::{constants, ecdsa, from_hex, schnorr, Message, Scalar, Secp256k1, Verification};

/// Public key - used to verify ECDSA signatures and to do Taproot tweaks.
///
/// # Serde support
///
/// Implements de/serialization with the `serde` feature enabled. We treat the byte value as a tuple
/// of 33 `u8`s for non-human-readable formats. This representation is optimal for some formats
/// (e.g. [`bincode`]) however other formats may be less optimal (e.g. [`cbor`]).
///
/// # Examples
///
/// Basic usage:
///
/// ```
/// # #[cfg(feature =  "alloc")] {
/// use secp256k1::{SecretKey, PublicKey};
///
/// let secret_key = SecretKey::from_byte_array([0xcd; 32]).expect("32 bytes, within curve order");
/// let public_key = PublicKey::from_secret_key(&secret_key);
/// # }
/// ```
/// [`bincode`]: https://docs.rs/bincode
/// [`cbor`]: https://docs.rs/cbor
#[derive(Copy, Clone, PartialOrd, Ord, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct PublicKey(ffi::PublicKey);
impl_fast_comparisons!(PublicKey);

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
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::LowerHex::fmt(self, f) }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::LowerHex::fmt(self, f) }
}

impl str::FromStr for PublicKey {
    type Err = Error;
    fn from_str(s: &str) -> Result<PublicKey, Error> {
        let mut res = [0u8; constants::UNCOMPRESSED_PUBLIC_KEY_SIZE];
        match from_hex(s, &mut res) {
            Ok(constants::PUBLIC_KEY_SIZE) => {
                let bytes: [u8; constants::PUBLIC_KEY_SIZE] =
                    res[0..constants::PUBLIC_KEY_SIZE].try_into().unwrap();
                PublicKey::from_byte_array_compressed(bytes)
            }
            Ok(constants::UNCOMPRESSED_PUBLIC_KEY_SIZE) =>
                PublicKey::from_byte_array_uncompressed(res),
            _ => Err(Error::InvalidPublicKey),
        }
    }
}

impl PublicKey {
    /// Creates a new public key from a [`SecretKey`].
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(all(feature = "rand", feature = "std"))] {
    /// use secp256k1::{rand, SecretKey, PublicKey};
    ///
    /// let secret_key = SecretKey::new(&mut rand::rng());
    /// let public_key = PublicKey::from_secret_key(&secret_key);
    /// # }
    /// ```
    #[inline]
    pub fn from_secret_key(sk: &SecretKey) -> PublicKey {
        unsafe {
            let mut pk = ffi::PublicKey::new();
            // We can assume the return value because it's not possible to construct
            // an invalid `SecretKey` without transmute trickery or something.
            let res = crate::with_global_context(
                |secp: &Secp256k1<crate::AllPreallocated>| {
                    ffi::secp256k1_ec_pubkey_create(secp.ctx.as_ptr(), &mut pk, sk.as_c_ptr())
                },
                Some(&sk.to_secret_bytes()),
            );
            debug_assert_eq!(res, 1);
            PublicKey(pk)
        }
    }
    /// Creates a new public key from an [`ElligatorSwift`].
    #[inline]
    pub fn from_ellswift(ellswift: ElligatorSwift) -> PublicKey { ElligatorSwift::decode(ellswift) }

    /// Creates a new public key from a [`SecretKey`].
    #[inline]
    #[cfg(feature = "global-context")]
    #[deprecated(since = "TBD", note = "use from_secret_key instead")]
    pub fn from_secret_key_global(sk: &SecretKey) -> PublicKey { PublicKey::from_secret_key(sk) }

    /// Creates a public key directly from a slice.
    #[inline]
    pub fn from_slice(data: &[u8]) -> Result<PublicKey, Error> {
        match data.len() {
            constants::PUBLIC_KEY_SIZE => PublicKey::from_byte_array_compressed(
                <[u8; constants::PUBLIC_KEY_SIZE]>::try_from(data).unwrap(),
            ),
            constants::UNCOMPRESSED_PUBLIC_KEY_SIZE => PublicKey::from_byte_array_uncompressed(
                <[u8; constants::UNCOMPRESSED_PUBLIC_KEY_SIZE]>::try_from(data).unwrap(),
            ),
            _ => Err(InvalidPublicKey),
        }
    }

    /// Creates a public key from a serialized array in compressed format.
    #[inline]
    pub fn from_byte_array_compressed(
        data: [u8; constants::PUBLIC_KEY_SIZE],
    ) -> Result<PublicKey, Error> {
        unsafe {
            let mut pk = ffi::PublicKey::new();
            if ffi::secp256k1_ec_pubkey_parse(
                ffi::secp256k1_context_no_precomp,
                &mut pk,
                data.as_c_ptr(),
                constants::PUBLIC_KEY_SIZE,
            ) == 1
            {
                Ok(PublicKey(pk))
            } else {
                Err(InvalidPublicKey)
            }
        }
    }

    /// Creates a public key from a serialized array in uncompressed format.
    #[inline]
    pub fn from_byte_array_uncompressed(
        data: [u8; constants::UNCOMPRESSED_PUBLIC_KEY_SIZE],
    ) -> Result<PublicKey, Error> {
        unsafe {
            let mut pk = ffi::PublicKey::new();
            if ffi::secp256k1_ec_pubkey_parse(
                ffi::secp256k1_context_no_precomp,
                &mut pk,
                data.as_c_ptr(),
                constants::UNCOMPRESSED_PUBLIC_KEY_SIZE,
            ) == 1
            {
                Ok(PublicKey(pk))
            } else {
                Err(InvalidPublicKey)
            }
        }
    }

    /// Creates a new compressed public key using data from BIP-340 [`Keypair`].
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(all(feature = "rand", feature = "std"))] {
    /// use secp256k1::{rand, PublicKey, Keypair};
    ///
    /// let keypair = Keypair::new(&mut rand::rng());
    /// let public_key = PublicKey::from_keypair(&keypair);
    /// # }
    /// ```
    #[inline]
    pub fn from_keypair(keypair: &Keypair) -> Self {
        unsafe {
            let mut pk = ffi::PublicKey::new();
            let ret = ffi::secp256k1_keypair_pub(
                ffi::secp256k1_context_no_precomp,
                &mut pk,
                keypair.as_c_ptr(),
            );
            debug_assert_eq!(ret, 1);
            PublicKey(pk)
        }
    }

    /// Creates a [`PublicKey`] using the key material from `pk` combined with the `parity`.
    pub fn from_x_only_public_key(pk: XOnlyPublicKey, parity: Parity) -> PublicKey {
        let mut buf = [0u8; 33];

        // First byte of a compressed key should be `0x02 AND parity`.
        buf[0] = match parity {
            Parity::Even => 0x02,
            Parity::Odd => 0x03,
        };
        buf[1..].clone_from_slice(&pk.serialize());

        PublicKey::from_byte_array_compressed(buf).expect("we know the buffer is valid")
    }

    #[inline]
    /// Serializes the key as a byte-encoded pair of values. In compressed form the y-coordinate is
    /// represented by only a single bit, as x determines it up to one bit.
    pub fn serialize(&self) -> [u8; constants::PUBLIC_KEY_SIZE] {
        let mut ret = [0u8; constants::PUBLIC_KEY_SIZE];
        self.serialize_internal(&mut ret, ffi::SECP256K1_SER_COMPRESSED);
        ret
    }

    #[inline]
    /// Serializes the key as a byte-encoded pair of values, in uncompressed form.
    pub fn serialize_uncompressed(&self) -> [u8; constants::UNCOMPRESSED_PUBLIC_KEY_SIZE] {
        let mut ret = [0u8; constants::UNCOMPRESSED_PUBLIC_KEY_SIZE];
        self.serialize_internal(&mut ret, ffi::SECP256K1_SER_UNCOMPRESSED);
        ret
    }

    #[inline(always)]
    fn serialize_internal(&self, ret: &mut [u8], flag: c_uint) {
        let mut ret_len = ret.len();
        let res = unsafe {
            ffi::secp256k1_ec_pubkey_serialize(
                ffi::secp256k1_context_no_precomp,
                ret.as_mut_c_ptr(),
                &mut ret_len,
                self.as_c_ptr(),
                flag,
            )
        };
        debug_assert_eq!(res, 1);
        debug_assert_eq!(ret_len, ret.len());
    }

    /// Negates the public key.
    #[inline]
    #[must_use = "you forgot to use the negated public key"]
    pub fn negate(mut self) -> PublicKey {
        let res = crate::with_raw_global_context(
            |ctx| unsafe { ffi::secp256k1_ec_pubkey_negate(ctx.as_ptr(), &mut self.0) },
            None,
        );
        debug_assert_eq!(res, 1);
        self
    }

    /// Tweaks a [`PublicKey`] by adding `tweak * G` modulo the curve order.
    ///
    /// # Errors
    ///
    /// Returns an error if the resulting key would be invalid.
    #[inline]
    pub fn add_exp_tweak(mut self, tweak: &Scalar) -> Result<PublicKey, Error> {
        if crate::with_raw_global_context(
            |ctx| unsafe {
                ffi::secp256k1_ec_pubkey_tweak_add(ctx.as_ptr(), &mut self.0, tweak.as_c_ptr())
            },
            None,
        ) == 1
        {
            Ok(self)
        } else {
            Err(Error::InvalidTweak)
        }
    }

    /// Tweaks a [`PublicKey`] by multiplying by `tweak` modulo the curve order.
    ///
    /// # Errors
    ///
    /// Returns an error if the resulting key would be invalid.
    #[inline]
    pub fn mul_tweak(mut self, tweak: &Scalar) -> Result<PublicKey, Error> {
        unsafe {
            let res = crate::with_global_context(
                |secp: &Secp256k1<crate::AllPreallocated>| {
                    ffi::secp256k1_ec_pubkey_tweak_mul(
                        secp.ctx.as_ptr(),
                        &mut self.0,
                        tweak.as_c_ptr(),
                    )
                },
                None,
            );
            if res == 1 {
                Ok(self)
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
    /// # #[cfg(all(feature = "rand", feature = "std"))] {
    /// use secp256k1::rand;
    ///
    /// let mut rng = rand::rng();
    /// let (_, pk1) = secp256k1::generate_keypair(&mut rng);
    /// let (_, pk2) = secp256k1::generate_keypair(&mut rng);
    /// let sum = pk1.combine(&pk2).expect("It's improbable to fail for 2 random public keys");
    /// # }
    /// ```
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
    /// # #[cfg(all(feature = "rand", feature = "std"))] {
    /// use secp256k1::{rand, PublicKey};
    ///
    /// let mut rng = rand::rng();
    /// let (_, pk1) = secp256k1::generate_keypair(&mut rng);
    /// let (_, pk2) = secp256k1::generate_keypair(&mut rng);
    /// let (_, pk3) = secp256k1::generate_keypair(&mut rng);
    /// let sum = PublicKey::combine_keys(&[&pk1, &pk2, &pk3]).expect("It's improbable to fail for 3 random public keys");
    /// # }
    /// ```
    pub fn combine_keys(keys: &[&PublicKey]) -> Result<PublicKey, Error> {
        use core::mem::transmute;

        if keys.is_empty() || keys.len() > i32::MAX as usize {
            return Err(InvalidPublicKeySum);
        }

        unsafe {
            let mut ret = ffi::PublicKey::new();
            let ptrs: &[*const ffi::PublicKey] =
                transmute::<&[&PublicKey], &[*const ffi::PublicKey]>(keys);
            if ffi::secp256k1_ec_pubkey_combine(
                ffi::secp256k1_context_no_precomp,
                &mut ret,
                ptrs.as_c_ptr(),
                keys.len(),
            ) == 1
            {
                Ok(PublicKey(ret))
            } else {
                Err(InvalidPublicKeySum)
            }
        }
    }

    /// Returns the [`XOnlyPublicKey`] (and its [`Parity`]) for this [`PublicKey`].
    #[inline]
    pub fn x_only_public_key(&self) -> (XOnlyPublicKey, Parity) {
        let mut pk_parity = 0;
        unsafe {
            let mut xonly_pk = ffi::XOnlyPublicKey::new();
            let ret = ffi::secp256k1_xonly_pubkey_from_pubkey(
                ffi::secp256k1_context_no_precomp,
                &mut xonly_pk,
                &mut pk_parity,
                self.as_c_ptr(),
            );
            debug_assert_eq!(ret, 1);
            let parity =
                Parity::from_i32(pk_parity).expect("should not panic, pk_parity is 0 or 1");

            (XOnlyPublicKey(xonly_pk), parity)
        }
    }

    /// Checks that `sig` is a valid ECDSA signature for `msg` using this public key.
    pub fn verify(&self, msg: impl Into<Message>, sig: &ecdsa::Signature) -> Result<(), Error> {
        ecdsa::verify(sig, msg, self)
    }
}

/// This trait enables interaction with the FFI layer and even though it is part of the public API
/// normal users should never need to directly interact with FFI types.
impl CPtr for PublicKey {
    type Target = ffi::PublicKey;

    /// Obtains a const pointer suitable for use with FFI functions.
    fn as_c_ptr(&self) -> *const Self::Target { &self.0 }

    /// Obtains a mutable pointer suitable for use with FFI functions.
    fn as_mut_c_ptr(&mut self) -> *mut Self::Target { &mut self.0 }
}

/// Creates a new public key from a FFI public key.
///
/// Note, normal users should never need to interact directly with FFI types.
impl From<ffi::PublicKey> for PublicKey {
    #[inline]
    fn from(pk: ffi::PublicKey) -> PublicKey { PublicKey(pk) }
}

#[cfg(feature = "serde")]
impl serde::Serialize for PublicKey {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.collect_str(self)
        } else {
            let mut tuple = s.serialize_tuple(constants::PUBLIC_KEY_SIZE)?;
            // Serialize in compressed form.
            for byte in self.serialize().iter() {
                tuple.serialize_element(&byte)?;
            }
            tuple.end()
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for PublicKey {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<PublicKey, D::Error> {
        if d.is_human_readable() {
            d.deserialize_str(super::serde_util::FromStrVisitor::new(
                "an ASCII hex string representing a public key",
            ))
        } else {
            let visitor = super::serde_util::Tuple33Visitor::new(
                "33 bytes compressed public key",
                PublicKey::from_byte_array_compressed,
            );
            d.deserialize_tuple(constants::PUBLIC_KEY_SIZE, visitor)
        }
    }
}

/// Opaque data structure that holds a keypair consisting of a secret and a public key.
///
/// # Serde support
///
/// Implements de/serialization with the `serde` and `global-context` features enabled. Serializes
/// the secret bytes only. We treat the byte value as a tuple of 32 `u8`s for non-human-readable
/// formats. This representation is optimal for some formats (e.g. [`bincode`]) however other
/// formats may be less optimal (e.g. [`cbor`]). For human-readable formats we use a hex string.
///
/// # Examples
///
/// Basic usage:
///
/// ```
/// # #[cfg(all(feature = "rand", feature = "std"))] {
/// use secp256k1::{rand, Keypair};
///
/// let (secret_key, public_key) = secp256k1::generate_keypair(&mut rand::rng());
/// let keypair = Keypair::from_secret_key(&secret_key);
/// # }
/// ```
/// [`bincode`]: https://docs.rs/bincode
/// [`cbor`]: https://docs.rs/cbor
#[derive(Copy, Clone, PartialOrd, Ord, PartialEq, Eq, Hash)]
pub struct Keypair(ffi::Keypair);
impl_fast_comparisons!(Keypair);

impl Keypair {
    /// Creates a [`Keypair`] directly from a Secp256k1 secret key.
    #[inline]
    pub fn from_secret_key(sk: &SecretKey) -> Keypair {
        unsafe {
            let mut kp = ffi::Keypair::new();
            let res = crate::with_global_context(
                |secp: &Secp256k1<crate::AllPreallocated>| {
                    ffi::secp256k1_keypair_create(secp.ctx.as_ptr(), &mut kp, sk.as_c_ptr())
                },
                Some(&sk.to_secret_bytes()),
            );

            if res == 1 {
                Keypair(kp)
            } else {
                panic!("the provided secret key is invalid: it is corrupted or was not produced by Secp256k1 library")
            }
        }
    }

    /// Creates a [`Keypair`] directly from a secret key slice.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidSecretKey`] if the slice is not exactly 32 bytes long,
    /// or if the encoded number is an invalid scalar.
    #[deprecated(since = "0.31.0", note = "Use `from_seckey_byte_array` instead.")]
    #[inline]
    pub fn from_seckey_slice(data: &[u8]) -> Result<Keypair, Error> {
        match <[u8; constants::SECRET_KEY_SIZE]>::try_from(data) {
            Ok(data) => Self::from_seckey_byte_array(data),
            Err(_) => Err(Error::InvalidSecretKey),
        }
    }

    /// Creates a [`Keypair`] directly from a secret key byte array.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidSecretKey`] if the encoded number is an invalid scalar.
    #[inline]
    pub fn from_seckey_byte_array(
        data: [u8; constants::SECRET_KEY_SIZE],
    ) -> Result<Keypair, Error> {
        unsafe {
            let mut kp = ffi::Keypair::new();
            if crate::with_raw_global_context(
                |ctx| ffi::secp256k1_keypair_create(ctx.as_ptr(), &mut kp, data.as_c_ptr()),
                Some(&data),
            ) == 1
            {
                Ok(Keypair(kp))
            } else {
                Err(Error::InvalidSecretKey)
            }
        }
    }

    /// Creates a [`Keypair`] directly from a secret key string.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidSecretKey`] if the string does not consist of exactly 64 hex characters,
    /// or if the encoded number is an invalid scalar.
    #[inline]
    #[deprecated(note = "use FromStr or parse instead")]
    pub fn from_seckey_str(s: &str) -> Result<Self, Error> { s.parse() }

    /// Creates a [`Keypair`] directly from a secret key string.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidSecretKey`] if the string does not consist of exactly 64 hex characters,
    /// or if the encoded number is an invalid scalar.
    #[inline]
    #[deprecated(note = "use FromStr or parse instead")]
    pub fn from_seckey_str_global(s: &str) -> Result<Keypair, Error> { s.parse() }

    /// Generates a new random key pair.
    /// # Examples
    ///
    /// ```
    /// # #[cfg(all(feature = "rand", feature = "std"))] {
    /// use secp256k1::{rand, SecretKey, Keypair};
    ///
    /// let keypair = Keypair::new(&mut rand::rng());
    /// # }
    /// ```
    #[inline]
    #[cfg(feature = "rand")]
    pub fn new<R: rand::Rng + ?Sized>(rng: &mut R) -> Keypair {
        let mut data = crate::random_32_bytes(rng);
        let mut ret = 0;

        unsafe {
            let mut keypair = ffi::Keypair::new();

            while ret == 0 {
                ret = crate::with_global_context(
                    |secp: &Secp256k1<crate::AllPreallocated>| {
                        ffi::secp256k1_keypair_create(
                            secp.ctx.as_ptr(),
                            &mut keypair,
                            data.as_c_ptr(),
                        )
                    },
                    Some(&data),
                );

                if ret != 0 {
                    break;
                }

                data = crate::random_32_bytes(rng);
            }

            Keypair(keypair)
        }
    }

    /// Generates a new random secret key.
    #[inline]
    #[cfg(all(feature = "global-context", feature = "rand"))]
    #[deprecated(since = "TBD", note = "use Keypair::new instead")]
    pub fn new_global<R: ::rand::Rng + ?Sized>(rng: &mut R) -> Keypair { Keypair::new(rng) }

    /// Returns the secret bytes for this key pair.
    #[inline]
    pub fn to_secret_bytes(&self) -> [u8; constants::SECRET_KEY_SIZE] {
        *SecretKey::from_keypair(self).as_ref()
    }

    /// Returns the secret bytes for this key pair.
    #[deprecated(since = "TBD", note = "use to_secret_bytes instead")]
    #[inline]
    pub fn secret_bytes(&self) -> [u8; constants::SECRET_KEY_SIZE] { self.to_secret_bytes() }

    /// Tweaks a keypair by first converting the public key to an xonly key and tweaking it.
    ///
    /// # Errors
    ///
    /// Returns an error if the resulting key would be invalid.
    ///
    /// NB: Will not error if the tweaked public key has an odd value and can't be used for
    ///     BIP 340-342 purposes.
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(all(feature = "rand", feature = "std"))] {
    /// use secp256k1::{Keypair, Scalar};
    ///
    /// let tweak = Scalar::random();
    ///
    /// let mut keypair = Keypair::new(&mut rand::rng());
    /// let tweaked = keypair.add_xonly_tweak(&tweak).expect("Improbable to fail with a randomly generated tweak");
    /// # }
    /// ```
    // TODO: Add checked implementation
    #[inline]
    pub fn add_xonly_tweak(mut self, tweak: &Scalar) -> Result<Keypair, Error> {
        unsafe {
            let err = crate::with_global_context(
                |secp: &Secp256k1<crate::AllPreallocated>| {
                    ffi::secp256k1_keypair_xonly_tweak_add(
                        secp.ctx.as_ptr(),
                        &mut self.0,
                        tweak.as_c_ptr(),
                    )
                },
                None,
            );
            if err != 1 {
                return Err(Error::InvalidTweak);
            }

            Ok(self)
        }
    }

    /// Returns the [`SecretKey`] for this [`Keypair`].
    ///
    /// This is equivalent to using [`SecretKey::from_keypair`].
    #[inline]
    pub fn secret_key(&self) -> SecretKey { SecretKey::from_keypair(self) }

    /// Returns the [`PublicKey`] for this [`Keypair`].
    ///
    /// This is equivalent to using [`PublicKey::from_keypair`].
    #[inline]
    pub fn public_key(&self) -> PublicKey { PublicKey::from_keypair(self) }

    /// Returns the [`XOnlyPublicKey`] (and its [`Parity`]) for this [`Keypair`].
    ///
    /// This is equivalent to using [`XOnlyPublicKey::from_keypair`].
    #[inline]
    pub fn x_only_public_key(&self) -> (XOnlyPublicKey, Parity) {
        XOnlyPublicKey::from_keypair(self)
    }

    /// Constructs a schnorr signature for `msg`.
    #[inline]
    #[cfg(all(feature = "rand", feature = "std"))]
    pub fn sign_schnorr(&self, msg: &[u8]) -> schnorr::Signature { schnorr::sign(msg, self) }

    /// Constructs a schnorr signature without aux rand for `msg`.
    #[inline]
    pub fn sign_schnorr_no_aux_rand(&self, msg: &[u8]) -> schnorr::Signature {
        schnorr::sign_no_aux_rand(msg, self)
    }

    /// Attempts to erase the secret within the underlying array.
    ///
    /// Note, however, that the compiler is allowed to freely copy or move the contents
    /// of this array to other places in memory. Preventing this behavior is very subtle.
    /// For more discussion on this, please see the documentation of the
    /// [`zeroize`](https://docs.rs/zeroize) crate.
    #[inline]
    pub fn non_secure_erase(&mut self) { self.0.non_secure_erase(); }

    /// Constructor for unit testing.
    #[cfg(test)]
    pub fn test_random() -> Self {
        let sk = SecretKey::test_random();
        Self::from_secret_key(&sk)
    }
}

impl fmt::Debug for Keypair {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        f.debug_struct("Keypair")
            .field("pubkey", &self.public_key())
            .field("secret", &"<hidden>")
            .finish()
    }
}

impl From<Keypair> for SecretKey {
    #[inline]
    fn from(pair: Keypair) -> Self { SecretKey::from_keypair(&pair) }
}

impl<'a> From<&'a Keypair> for SecretKey {
    #[inline]
    fn from(pair: &'a Keypair) -> Self { SecretKey::from_keypair(pair) }
}

impl From<Keypair> for PublicKey {
    #[inline]
    fn from(pair: Keypair) -> Self { PublicKey::from_keypair(&pair) }
}

impl<'a> From<&'a Keypair> for PublicKey {
    #[inline]
    fn from(pair: &'a Keypair) -> Self { PublicKey::from_keypair(pair) }
}

impl str::FromStr for Keypair {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut res = [0u8; constants::SECRET_KEY_SIZE];
        match from_hex(s, &mut res) {
            Ok(constants::SECRET_KEY_SIZE) => Keypair::from_seckey_byte_array(res),
            _ => Err(Error::InvalidSecretKey),
        }
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Keypair {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            let mut buf = [0u8; constants::SECRET_KEY_SIZE * 2];
            s.serialize_str(
                crate::to_hex(&self.secret_bytes(), &mut buf)
                    .expect("fixed-size hex serialization"),
            )
        } else {
            let mut tuple = s.serialize_tuple(constants::SECRET_KEY_SIZE)?;
            for byte in self.secret_bytes().iter() {
                tuple.serialize_element(&byte)?;
            }
            tuple.end()
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Keypair {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        if d.is_human_readable() {
            d.deserialize_str(super::serde_util::FromStrVisitor::new(
                "a hex string representing 32 byte Keypair",
            ))
        } else {
            let visitor = super::serde_util::Tuple32Visitor::new(
                "raw 32 bytes Keypair",
                Keypair::from_seckey_byte_array,
            );
            d.deserialize_tuple(constants::SECRET_KEY_SIZE, visitor)
        }
    }
}

impl CPtr for Keypair {
    type Target = ffi::Keypair;
    fn as_c_ptr(&self) -> *const Self::Target { &self.0 }

    fn as_mut_c_ptr(&mut self) -> *mut Self::Target { &mut self.0 }
}

/// An x-only public key, used for verification of Taproot signatures and serialized according to BIP-340.
///
/// # Serde support
///
/// Implements de/serialization with the `serde` feature enabled. We treat the byte value as a tuple
/// of 32 `u8`s for non-human-readable formats. This representation is optimal for some formats
/// (e.g. [`bincode`]) however other formats may be less optimal (e.g. [`cbor`]).
///
/// # Examples
///
/// Basic usage:
///
/// ```
/// # #[cfg(all(feature = "rand", feature = "std"))] {
/// use secp256k1::{rand, Keypair, XOnlyPublicKey};
///
/// let keypair = Keypair::new(&mut rand::rng());
/// let xonly = XOnlyPublicKey::from_keypair(&keypair);
/// # }
/// ```
/// [`bincode`]: https://docs.rs/bincode
/// [`cbor`]: https://docs.rs/cbor
#[derive(Copy, Clone, PartialOrd, Ord, PartialEq, Eq, Hash)]
pub struct XOnlyPublicKey(ffi::XOnlyPublicKey);
impl_fast_comparisons!(XOnlyPublicKey);

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
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::LowerHex::fmt(self, f) }
}

impl fmt::Debug for XOnlyPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::LowerHex::fmt(self, f) }
}

impl str::FromStr for XOnlyPublicKey {
    type Err = Error;
    fn from_str(s: &str) -> Result<XOnlyPublicKey, Error> {
        let mut res = [0u8; constants::SCHNORR_PUBLIC_KEY_SIZE];
        match from_hex(s, &mut res) {
            Ok(constants::SCHNORR_PUBLIC_KEY_SIZE) => XOnlyPublicKey::from_byte_array(res),
            _ => Err(Error::InvalidPublicKey),
        }
    }
}

impl XOnlyPublicKey {
    /// Returns the [`XOnlyPublicKey`] (and its [`Parity`]) for `keypair`.
    #[inline]
    pub fn from_keypair(keypair: &Keypair) -> (XOnlyPublicKey, Parity) {
        let mut pk_parity = 0;
        unsafe {
            let mut xonly_pk = ffi::XOnlyPublicKey::new();
            let ret = ffi::secp256k1_keypair_xonly_pub(
                ffi::secp256k1_context_no_precomp,
                &mut xonly_pk,
                &mut pk_parity,
                keypair.as_c_ptr(),
            );
            debug_assert_eq!(ret, 1);
            let parity =
                Parity::from_i32(pk_parity).expect("should not panic, pk_parity is 0 or 1");

            (XOnlyPublicKey(xonly_pk), parity)
        }
    }

    /// Creates a schnorr public key directly from a slice.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPublicKey`] if the length of the data slice is not 32 bytes or the
    /// slice does not represent a valid Secp256k1 point x coordinate.
    #[deprecated(since = "0.31.0", note = "Use `from_byte_array` instead.")]
    #[inline]
    pub fn from_slice(data: &[u8]) -> Result<XOnlyPublicKey, Error> {
        match <[u8; constants::SCHNORR_PUBLIC_KEY_SIZE]>::try_from(data) {
            Ok(data) => Self::from_byte_array(data),
            Err(_) => Err(InvalidPublicKey),
        }
    }

    /// Creates a schnorr public key directly from a byte array.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPublicKey`] if the array does not represent a valid Secp256k1 point
    /// x coordinate.
    #[inline]
    pub fn from_byte_array(
        data: [u8; constants::SCHNORR_PUBLIC_KEY_SIZE],
    ) -> Result<XOnlyPublicKey, Error> {
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
    pub fn serialize(&self) -> [u8; constants::SCHNORR_PUBLIC_KEY_SIZE] {
        let mut ret = [0u8; constants::SCHNORR_PUBLIC_KEY_SIZE];

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

    /// Tweaks an [`XOnlyPublicKey`] by adding the generator multiplied with the given tweak to it.
    ///
    /// # Returns
    ///
    /// The newly tweaked key plus an opaque type representing the parity of the tweaked key, this
    /// should be provided to `tweak_add_check` which can be used to verify a tweak more efficiently
    /// than regenerating it and checking equality.
    ///
    /// # Errors
    ///
    /// If the resulting key would be invalid.
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(all(feature = "rand", feature = "std"))] {
    /// use secp256k1::{Keypair, Scalar, XOnlyPublicKey};
    ///
    /// let tweak = Scalar::random();
    ///
    /// let mut keypair = Keypair::new(&mut rand::rng());
    /// let (xonly, _parity) = keypair.x_only_public_key();
    /// let tweaked = xonly.add_tweak(&tweak).expect("Improbable to fail with a randomly generated tweak");
    /// # }
    /// ```
    pub fn add_tweak(mut self, tweak: &Scalar) -> Result<(XOnlyPublicKey, Parity), Error> {
        let mut pk_parity = 0;
        unsafe {
            let mut pubkey = ffi::PublicKey::new();
            let mut err = crate::with_global_context(
                |secp: &Secp256k1<crate::AllPreallocated>| {
                    ffi::secp256k1_xonly_pubkey_tweak_add(
                        secp.ctx.as_ptr(),
                        &mut pubkey,
                        self.as_c_ptr(),
                        tweak.as_c_ptr(),
                    )
                },
                None,
            );
            if err != 1 {
                return Err(Error::InvalidTweak);
            }

            err = crate::with_global_context(
                |secp: &Secp256k1<crate::AllPreallocated>| {
                    ffi::secp256k1_xonly_pubkey_from_pubkey(
                        secp.ctx.as_ptr(),
                        &mut self.0,
                        &mut pk_parity,
                        &pubkey,
                    )
                },
                None,
            );
            if err == 0 {
                return Err(Error::InvalidPublicKey);
            }

            let parity = Parity::from_i32(pk_parity)?;
            Ok((self, parity))
        }
    }

    /// Verifies that a tweak produced by [`XOnlyPublicKey::add_tweak`] was computed correctly.
    ///
    /// Should be called on the original untweaked key. Takes the tweaked key and output parity from
    /// [`XOnlyPublicKey::add_tweak`] as input.
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
    /// # #[cfg(all(feature = "rand", feature = "std"))] {
    /// use secp256k1::{Keypair, Scalar};
    ///
    /// let tweak = Scalar::random();
    ///
    /// let mut keypair = Keypair::new(&mut rand::rng());
    /// let (mut public_key, _) = keypair.x_only_public_key();
    /// let original = public_key;
    /// let (tweaked, parity) = public_key.add_tweak(&tweak).expect("Improbable to fail with a randomly generated tweak");
    /// assert!(original.tweak_add_check(&tweaked, parity, tweak));
    /// # }
    /// ```
    pub fn tweak_add_check(
        &self,
        tweaked_key: &Self,
        tweaked_parity: Parity,
        tweak: Scalar,
    ) -> bool {
        let tweaked_ser = tweaked_key.serialize();
        unsafe {
            let err = crate::with_global_context(
                |secp: &Secp256k1<crate::AllPreallocated>| {
                    ffi::secp256k1_xonly_pubkey_tweak_add_check(
                        secp.ctx.as_ptr(),
                        tweaked_ser.as_c_ptr(),
                        tweaked_parity.to_i32(),
                        &self.0,
                        tweak.as_c_ptr(),
                    )
                },
                None,
            );

            err == 1
        }
    }

    /// Returns the [`PublicKey`] for this [`XOnlyPublicKey`].
    ///
    /// This is equivalent to using [`PublicKey::from_xonly_and_parity(self, parity)`].
    #[inline]
    pub fn public_key(&self, parity: Parity) -> PublicKey {
        PublicKey::from_x_only_public_key(*self, parity)
    }

    /// Checks that `sig` is a valid schnorr signature for `msg` using this public key.
    pub fn verify<C: Verification>(
        &self,
        msg: &[u8],
        sig: &schnorr::Signature,
    ) -> Result<(), Error> {
        schnorr::verify(sig, msg, self)
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
    pub fn to_u8(self) -> u8 { self as u8 }

    /// Converts parity into an integer value.
    ///
    /// This returns `0` for even parity and `1` for odd parity.
    pub fn to_i32(self) -> i32 { self as i32 }

    /// Constructs a [`Parity`] from a byte.
    ///
    /// The only allowed values are `0` meaning even parity and `1` meaning odd.
    /// Other values result in error being returned.
    pub fn from_u8(parity: u8) -> Result<Parity, InvalidParityValue> {
        Parity::from_i32(parity.into())
    }

    /// Constructs a [`Parity`] from a signed integer.
    ///
    /// The only allowed values are `0` meaning even parity and `1` meaning odd.
    /// Other values result in error being returned.
    pub fn from_i32(parity: i32) -> Result<Parity, InvalidParityValue> {
        match parity {
            0 => Ok(Parity::Even),
            1 => Ok(Parity::Odd),
            _ => Err(InvalidParityValue(parity)),
        }
    }
}

/// `Even` for `0`, `Odd` for `1`, error for anything else
impl TryFrom<i32> for Parity {
    type Error = InvalidParityValue;

    fn try_from(parity: i32) -> Result<Self, Self::Error> { Self::from_i32(parity) }
}

/// `Even` for `0`, `Odd` for `1`, error for anything else
impl TryFrom<u8> for Parity {
    type Error = InvalidParityValue;

    fn try_from(parity: u8) -> Result<Self, Self::Error> { Self::from_u8(parity) }
}

/// The conversion returns `0` for even parity and `1` for odd.
impl From<Parity> for i32 {
    fn from(parity: Parity) -> i32 { parity.to_i32() }
}

/// The conversion returns `0` for even parity and `1` for odd.
impl From<Parity> for u8 {
    fn from(parity: Parity) -> u8 { parity.to_u8() }
}

/// Returns even parity if the operands are equal, odd otherwise.
impl BitXor for Parity {
    type Output = Parity;

    fn bitxor(self, rhs: Parity) -> Self::Output {
        // This works because Parity has only two values (i.e. only 1 bit of information).
        if self == rhs {
            Parity::Even // 1^1==0 and 0^0==0
        } else {
            Parity::Odd // 1^0==1 and 0^1==1
        }
    }
}

/// Error returned when conversion from an integer to `Parity` fails.
//
// Note that we don't allow inspecting the value because we may change the type.
// Yes, this comment is intentionally NOT doc comment.
// Too many derives for compatibility with current Error type.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct InvalidParityValue(i32);

impl fmt::Display for InvalidParityValue {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "invalid value {} for Parity - must be 0 or 1", self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InvalidParityValue {}

impl From<InvalidParityValue> for Error {
    fn from(error: InvalidParityValue) -> Self { Error::InvalidParityValue(error) }
}

/// The parity is serialized as `u8` - `0` for even, `1` for odd.
#[cfg(feature = "serde")]
impl serde::Serialize for Parity {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u8(self.to_u8())
    }
}

/// The parity is deserialized as `u8` - `0` for even, `1` for odd.
#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Parity {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Visitor;

        impl serde::de::Visitor<'_> for Visitor {
            type Value = Parity;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("8-bit integer (byte) with value 0 or 1")
            }

            fn visit_u8<E>(self, v: u8) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                use serde::de::Unexpected;

                Parity::from_u8(v)
                    .map_err(|_| E::invalid_value(Unexpected::Unsigned(v.into()), &"0 or 1"))
            }
        }

        d.deserialize_u8(Visitor)
    }
}

impl CPtr for XOnlyPublicKey {
    type Target = ffi::XOnlyPublicKey;
    fn as_c_ptr(&self) -> *const Self::Target { &self.0 }

    fn as_mut_c_ptr(&mut self) -> *mut Self::Target { &mut self.0 }
}

/// Creates a new schnorr public key from a FFI x-only public key.
impl From<ffi::XOnlyPublicKey> for XOnlyPublicKey {
    #[inline]
    fn from(pk: ffi::XOnlyPublicKey) -> XOnlyPublicKey { XOnlyPublicKey(pk) }
}

impl From<PublicKey> for XOnlyPublicKey {
    fn from(src: PublicKey) -> XOnlyPublicKey {
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
impl serde::Serialize for XOnlyPublicKey {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.collect_str(self)
        } else {
            let mut tuple = s.serialize_tuple(constants::SCHNORR_PUBLIC_KEY_SIZE)?;
            for byte in self.serialize().iter() {
                tuple.serialize_element(&byte)?;
            }
            tuple.end()
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for XOnlyPublicKey {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        if d.is_human_readable() {
            d.deserialize_str(super::serde_util::FromStrVisitor::new(
                "a hex string representing 32 byte schnorr public key",
            ))
        } else {
            let visitor = super::serde_util::Tuple32Visitor::new(
                "raw 32 bytes schnorr public key",
                XOnlyPublicKey::from_byte_array,
            );
            d.deserialize_tuple(constants::SCHNORR_PUBLIC_KEY_SIZE, visitor)
        }
    }
}

/// Sort public keys using lexicographic (of compressed serialization) order.
///
/// This is the canonical way to sort public keys for use with Musig2.
///
/// Example:
///
/// ```rust
/// # # [cfg(any(test, feature = "rand-std"))] {
/// # use secp256k1::rand::{rng, RngCore};
/// # use secp256k1::{SecretKey, Keypair, PublicKey, pubkey_sort};
/// # let sk1 = SecretKey::new(&mut rng());
/// # let pub_key1 = PublicKey::from_secret_key(&sk1);
/// # let sk2 = SecretKey::new(&mut rng());
/// # let pub_key2 = PublicKey::from_secret_key(&sk2);
/// #
/// # let pubkeys = [pub_key1, pub_key2];
/// # let mut pubkeys_ref: Vec<&PublicKey> = pubkeys.iter().collect();
/// # let pubkeys_ref = pubkeys_ref.as_mut_slice();
/// #
/// # secp256k1::sort_pubkeys(pubkeys_ref);
/// # }
/// ```
pub fn sort_pubkeys(pubkeys: &mut [&PublicKey]) {
    unsafe {
        // SAFETY: `PublicKey` has repr(transparent) so we can convert to `ffi::PublicKey`
        let pubkeys_ptr = pubkeys.as_mut_c_ptr() as *mut *const ffi::PublicKey;

        let ret = crate::with_global_context(
            |secp: &Secp256k1<crate::AllPreallocated>| {
                ffi::secp256k1_ec_pubkey_sort(secp.ctx.as_ptr(), pubkeys_ptr, pubkeys.len())
            },
            None,
        );

        if ret == 0 {
            unreachable!("Invalid public keys for sorting function")
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for PublicKey {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(PublicKey::from_x_only_public_key(u.arbitrary()?, u.arbitrary()?))
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for Parity {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        match bool::arbitrary(u)? {
            true => Ok(Parity::Even),
            false => Ok(Parity::Odd),
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for SecretKey {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let mut bytes = [0u8; constants::SECRET_KEY_SIZE];
        loop {
            // Unstructured::fill_buffer pads the buffer with zeroes if it runs out of data
            if u.len() < constants::SECRET_KEY_SIZE {
                return Err(arbitrary::Error::NotEnoughData);
            }
            u.fill_buffer(&mut bytes[..])?;

            if let Ok(sk) = SecretKey::from_secret_bytes(bytes) {
                return Ok(sk);
            }
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for XOnlyPublicKey {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let mut bytes = [0u8; 32];
        loop {
            // Unstructured::fill_buffer pads the buffer with zeroes if it runs out of data
            if u.len() < 32 {
                return Err(arbitrary::Error::NotEnoughData);
            }

            u.fill_buffer(&mut bytes[..])?;
            if let Ok(pk) = XOnlyPublicKey::from_byte_array(bytes) {
                return Ok(pk);
            }
        }
    }
}

#[cfg(test)]
#[allow(unused_imports)]
mod test {
    use core::str::FromStr;

    #[cfg(not(secp256k1_fuzz))]
    use hex_lit::hex;
    #[cfg(feature = "rand")]
    use rand::{self, RngCore, SeedableRng as _};
    #[cfg(feature = "rand")]
    use rand_xoshiro::Xoshiro128PlusPlus as SmallRng;
    use serde_test::{Configure, Token};
    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use super::*;
    use crate::Error::{InvalidPublicKey, InvalidSecretKey};
    use crate::{constants, from_hex, to_hex, Scalar};

    #[test]
    fn pubkey_from_slice() {
        assert_eq!(PublicKey::from_slice(&[]), Err(InvalidPublicKey));
        assert_eq!(PublicKey::from_slice(&[1, 2, 3]), Err(InvalidPublicKey));

        let uncompressed = PublicKey::from_slice(&[
            4, 54, 57, 149, 239, 162, 148, 175, 246, 254, 239, 75, 154, 152, 10, 82, 234, 224, 85,
            220, 40, 100, 57, 121, 30, 162, 94, 156, 135, 67, 74, 49, 179, 57, 236, 53, 162, 124,
            149, 144, 168, 77, 74, 30, 72, 211, 229, 110, 111, 55, 96, 193, 86, 227, 183, 152, 195,
            155, 51, 247, 123, 113, 60, 228, 188,
        ]);
        assert!(uncompressed.is_ok());

        let compressed = PublicKey::from_slice(&[
            3, 23, 183, 225, 206, 31, 159, 148, 195, 42, 67, 115, 146, 41, 248, 140, 11, 3, 51, 41,
            111, 180, 110, 143, 114, 134, 88, 73, 198, 174, 52, 184, 78,
        ]);
        assert!(compressed.is_ok());
    }

    #[test]
    fn keypair_slice_round_trip() {
        let (sk1, pk1) = crate::test_random_keypair();
        assert_eq!(SecretKey::from_secret_bytes(sk1.to_secret_bytes()), Ok(sk1));
        assert_eq!(PublicKey::from_slice(&pk1.serialize()[..]), Ok(pk1));
        assert_eq!(PublicKey::from_slice(&pk1.serialize_uncompressed()[..]), Ok(pk1));
    }

    #[test]
    #[cfg(not(secp256k1_fuzz))]
    fn erased_keypair_is_valid() {
        let kp = Keypair::from_seckey_byte_array([1u8; constants::SECRET_KEY_SIZE])
            .expect("valid secret key");
        let mut kp2 = kp;
        kp2.non_secure_erase();
        assert!(kp.eq_fast_unstable(&kp2));
    }

    #[test]
    #[rustfmt::skip]
    fn invalid_secret_key() {
        // Zero
        assert_eq!(SecretKey::from_secret_bytes([0; 32]), Err(InvalidSecretKey));
        assert_eq!(
            SecretKey::from_str("0000000000000000000000000000000000000000000000000000000000000000"),
            Err(InvalidSecretKey)
        );
        // -1
        assert_eq!(SecretKey::from_secret_bytes([0xff; 32]), Err(InvalidSecretKey));
        // Top of range
        assert!(SecretKey::from_secret_bytes([
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
            0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
            0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x40,
        ]).is_ok());
        // One past top of range
        assert!(SecretKey::from_secret_bytes([
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
            0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
            0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
        ]).is_err());
    }

    #[test]
    #[cfg(all(feature = "rand", feature = "alloc"))]
    fn test_out_of_range() {
        struct BadRng(u8);
        impl RngCore for BadRng {
            fn next_u32(&mut self) -> u32 { unimplemented!() }
            fn next_u64(&mut self) -> u64 { unimplemented!() }
            // This will set a secret key to a little over the
            // group order, then decrement with repeated calls
            // until it returns a valid key
            fn fill_bytes(&mut self, data: &mut [u8]) {
                #[rustfmt::skip]
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
        }

        crate::generate_keypair(&mut BadRng(0xff));
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
        assert_eq!(PublicKey::from_slice(&[]), Err(InvalidPublicKey));
    }

    #[test]
    #[cfg(all(feature = "rand", feature = "alloc"))]
    fn test_debug_output() {
        let (sk, _) = crate::generate_keypair(&mut SmallRng::from_seed([0; 16]));

        assert_eq!(&format!("{:?}", sk), "SecretKey(55f970894288f83a)");

        let mut buf = [0u8; constants::SECRET_KEY_SIZE * 2];
        assert_eq!(
            to_hex(&sk[..], &mut buf).unwrap(),
            "a3da5346582b9273dd4a2bb83bbdfad9c398863cff589b1c4646accc16fde327"
        );
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn test_display_output() {
        #[rustfmt::skip]
        static SK_BYTES: [u8; 32] = [
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0xff, 0xff, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00,
            0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63,
        ];

        let sk = SecretKey::from_secret_bytes(SK_BYTES).expect("sk");

        // In fuzzing mode secret->public key derivation is different, so
        // hard-code the expected result.
        #[cfg(not(secp256k1_fuzz))]
        let pk = PublicKey::from_secret_key(&sk);
        #[cfg(secp256k1_fuzz)]
        let pk = PublicKey::from_slice(&[
            0x02, 0x18, 0x84, 0x57, 0x81, 0xf6, 0x31, 0xc4, 0x8f, 0x1c, 0x97, 0x09, 0xe2, 0x30,
            0x92, 0x06, 0x7d, 0x06, 0x83, 0x7f, 0x30, 0xaa, 0x0c, 0xd0, 0x54, 0x4a, 0xc8, 0x87,
            0xfe, 0x91, 0xdd, 0xd1, 0x66,
        ])
        .expect("pk");

        assert_eq!(
            sk.display_secret().to_string(),
            "01010101010101010001020304050607ffff0000ffff00006363636363636363"
        );
        assert_eq!(
            SecretKey::from_str("01010101010101010001020304050607ffff0000ffff00006363636363636363")
                .unwrap(),
            sk
        );
        assert_eq!(
            pk.to_string(),
            "0218845781f631c48f1c9709e23092067d06837f30aa0cd0544ac887fe91ddd166"
        );
        assert_eq!(
            PublicKey::from_str(
                "0218845781f631c48f1c9709e23092067d06837f30aa0cd0544ac887fe91ddd166"
            )
            .unwrap(),
            pk
        );
        assert_eq!(
            PublicKey::from_str(
                "04\
                18845781f631c48f1c9709e23092067d06837f30aa0cd0544ac887fe91ddd166\
                84B84DB303A340CD7D6823EE88174747D12A67D2F8F2F9BA40846EE5EE7A44F6"
            )
            .unwrap(),
            pk
        );

        assert!(SecretKey::from_str(
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        )
        .is_err());
        assert!(SecretKey::from_str(
            "01010101010101010001020304050607ffff0000ffff0000636363636363636363"
        )
        .is_err());
        assert!(SecretKey::from_str(
            "01010101010101010001020304050607ffff0000ffff0000636363636363636"
        )
        .is_err());
        assert!(SecretKey::from_str(
            "01010101010101010001020304050607ffff0000ffff000063636363636363"
        )
        .is_err());
        assert!(SecretKey::from_str(
            "01010101010101010001020304050607ffff0000ffff000063636363636363xx"
        )
        .is_err());
        assert!(PublicKey::from_str(
            "0300000000000000000000000000000000000000000000000000000000000000000"
        )
        .is_err());
        assert!(PublicKey::from_str(
            "0218845781f631c48f1c9709e23092067d06837f30aa0cd0544ac887fe91ddd16601"
        )
        .is_err());
        assert!(PublicKey::from_str(
            "0218845781f631c48f1c9709e23092067d06837f30aa0cd0544ac887fe91ddd16"
        )
        .is_err());
        assert!(PublicKey::from_str(
            "0218845781f631c48f1c9709e23092067d06837f30aa0cd0544ac887fe91ddd1"
        )
        .is_err());
        assert!(PublicKey::from_str(
            "xx0218845781f631c48f1c9709e23092067d06837f30aa0cd0544ac887fe91ddd1"
        )
        .is_err());

        let long_str = "a".repeat(1024 * 1024);
        assert!(SecretKey::from_str(&long_str).is_err());
        assert!(PublicKey::from_str(&long_str).is_err());
    }

    #[test]
    #[cfg(not(secp256k1_fuzz))]
    #[cfg(all(feature = "alloc", feature = "rand"))]
    fn test_pubkey_serialize() {
        let (_, pk1) = crate::generate_keypair(&mut SmallRng::from_seed([1; 16]));
        assert_eq!(
            &pk1.serialize_uncompressed()[..],
            &[
                4, 56, 223, 70, 19, 126, 3, 194, 155, 88, 167, 37, 54, 98, 138, 203, 136, 98, 66,
                247, 172, 101, 50, 193, 106, 108, 55, 252, 115, 176, 125, 88, 41, 21, 0, 223, 206,
                246, 198, 43, 80, 189, 247, 183, 48, 90, 209, 30, 195, 64, 214, 36, 109, 251, 121,
                60, 160, 172, 76, 9, 164, 224, 180, 189, 228
            ]
        );
        assert_eq!(
            &pk1.serialize()[..],
            &[
                2, 56, 223, 70, 19, 126, 3, 194, 155, 88, 167, 37, 54, 98, 138, 203, 136, 98, 66,
                247, 172, 101, 50, 193, 106, 108, 55, 252, 115, 176, 125, 88, 41
            ]
        );
    }

    #[test]
    #[cfg(feature = "std")]
    fn tweak_add_arbitrary_data() {
        let (sk, pk) = crate::test_random_keypair();
        assert_eq!(PublicKey::from_secret_key(&sk), pk); // Sanity check.

        // TODO: This would be better tested with a _lot_ of different tweaks.
        let tweak = Scalar::test_random();

        let tweaked_sk = sk.add_tweak(&tweak).unwrap();
        assert_ne!(sk, tweaked_sk); // Make sure we did something.
        let tweaked_pk = pk.add_exp_tweak(&tweak).unwrap();
        assert_ne!(pk, tweaked_pk);

        assert_eq!(PublicKey::from_secret_key(&tweaked_sk), tweaked_pk);
    }

    #[test]
    fn tweak_add_zero() {
        let (sk, pk) = crate::test_random_keypair();

        let tweak = Scalar::ZERO;

        let tweaked_sk = sk.add_tweak(&tweak).unwrap();
        assert_eq!(sk, tweaked_sk); // Tweak by zero does nothing.
        let tweaked_pk = pk.add_exp_tweak(&tweak).unwrap();
        assert_eq!(pk, tweaked_pk);
    }

    #[test]
    #[cfg(feature = "std")]
    fn tweak_mul_arbitrary_data() {
        let (sk, pk) = crate::test_random_keypair();
        assert_eq!(PublicKey::from_secret_key(&sk), pk); // Sanity check.

        for _ in 0..10 {
            let tweak = Scalar::test_random();

            let tweaked_sk = sk.mul_tweak(&tweak).unwrap();
            assert_ne!(sk, tweaked_sk); // Make sure we did something.
            let tweaked_pk = pk.mul_tweak(&tweak).unwrap();
            assert_ne!(pk, tweaked_pk);
            assert_eq!(PublicKey::from_secret_key(&tweaked_sk), tweaked_pk);
        }
    }

    #[test]
    fn tweak_mul_zero() {
        let (sk, _) = crate::test_random_keypair();

        let tweak = Scalar::ZERO;
        assert!(sk.mul_tweak(&tweak).is_err())
    }

    #[test]
    #[cfg(feature = "std")]
    fn test_negation() {
        let (sk, pk) = crate::test_random_keypair();

        assert_eq!(PublicKey::from_secret_key(&sk), pk); // Sanity check.

        let neg = sk.negate();
        assert_ne!(sk, neg);
        let back_sk = neg.negate();
        assert_eq!(sk, back_sk);

        let neg = pk.negate();
        assert_ne!(pk, neg);
        let back_pk = neg.negate();
        assert_eq!(pk, back_pk);

        assert_eq!(PublicKey::from_secret_key(&back_sk), pk);
    }

    #[test]
    #[cfg(feature = "std")]
    fn pubkey_hash() {
        use std::collections::hash_map::DefaultHasher;
        use std::collections::HashSet;
        use std::hash::{Hash, Hasher};

        fn hash<T: Hash>(t: &T) -> u64 {
            let mut s = DefaultHasher::new();
            t.hash(&mut s);
            s.finish()
        }

        let mut set = HashSet::new();
        const COUNT: usize = 1024;
        for _ in 0..COUNT {
            let (_, pk) = crate::test_random_keypair();
            let hash = hash(&pk);
            assert!(!set.contains(&hash));
            set.insert(hash);
        }
        assert_eq!(set.len(), COUNT);
    }

    #[test]
    #[cfg(not(secp256k1_fuzz))]
    fn pubkey_combine() {
        let compressed1 = PublicKey::from_slice(&hex!(
            "0241cc121c419921942add6db6482fb36243faf83317c866d2a28d8c6d7089f7ba"
        ))
        .unwrap();
        let compressed2 = PublicKey::from_slice(&hex!(
            "02e6642fd69bd211f93f7f1f36ca51a26a5290eb2dd1b0d8279a87bb0d480c8443"
        ))
        .unwrap();
        let exp_sum = PublicKey::from_slice(&hex!(
            "0384526253c27c7aef56c7b71a5cd25bebb66dddda437826defc5b2568bde81f07"
        ))
        .unwrap();

        let sum1 = compressed1.combine(&compressed2);
        assert!(sum1.is_ok());
        let sum2 = compressed2.combine(&compressed1);
        assert!(sum2.is_ok());
        assert_eq!(sum1, sum2);
        assert_eq!(sum1.unwrap(), exp_sum);
    }

    #[test]
    #[cfg(not(secp256k1_fuzz))]
    fn pubkey_combine_keys() {
        let compressed1 = PublicKey::from_slice(&hex!(
            "0241cc121c419921942add6db6482fb36243faf83317c866d2a28d8c6d7089f7ba"
        ))
        .unwrap();
        let compressed2 = PublicKey::from_slice(&hex!(
            "02e6642fd69bd211f93f7f1f36ca51a26a5290eb2dd1b0d8279a87bb0d480c8443"
        ))
        .unwrap();
        let compressed3 = PublicKey::from_slice(&hex!(
            "03e74897d8644eb3e5b391ca2ab257aec2080f4d1a95cad57e454e47f021168eb0"
        ))
        .unwrap();
        let exp_sum = PublicKey::from_slice(&hex!(
            "0252d73a47f66cf341e5651542f0348f452b7c793af62a6d8bff75ade703a451ad"
        ))
        .unwrap();

        let sum1 = PublicKey::combine_keys(&[&compressed1, &compressed2, &compressed3]);
        assert!(sum1.is_ok());
        let sum2 = PublicKey::combine_keys(&[&compressed1, &compressed2, &compressed3]);
        assert!(sum2.is_ok());
        assert_eq!(sum1, sum2);
        assert_eq!(sum1.unwrap(), exp_sum);
    }

    #[test]
    #[cfg(not(secp256k1_fuzz))]
    fn pubkey_combine_keys_empty_slice() {
        assert!(PublicKey::combine_keys(&[]).is_err());
    }

    #[test]
    #[cfg(feature = "std")]
    fn create_pubkey_combine() {
        let (sk1, pk1) = crate::test_random_keypair();
        let (sk2, pk2) = crate::test_random_keypair();

        let sum1 = pk1.combine(&pk2);
        assert!(sum1.is_ok());
        let sum2 = pk2.combine(&pk1);
        assert!(sum2.is_ok());
        assert_eq!(sum1, sum2);

        let tweaked = sk1.add_tweak(&Scalar::from(sk2)).unwrap();
        let sksum = PublicKey::from_secret_key(&tweaked);
        assert_eq!(Ok(sksum), sum1);
    }

    #[cfg(not(secp256k1_fuzz))]
    #[test]
    #[allow(clippy::nonminimal_bool)]
    fn pubkey_equal() {
        let pk1 = PublicKey::from_slice(&hex!(
            "0241cc121c419921942add6db6482fb36243faf83317c866d2a28d8c6d7089f7ba"
        ))
        .unwrap();
        let pk2 = pk1;
        let pk3 = PublicKey::from_slice(&hex!(
            "02e6642fd69bd211f93f7f1f36ca51a26a5290eb2dd1b0d8279a87bb0d480c8443"
        ))
        .unwrap();

        assert_eq!(pk1, pk2);
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
    #[cfg(all(feature = "serde", feature = "alloc"))]
    fn test_serde() {
        use serde_test::{assert_tokens, Configure, Token};
        #[rustfmt::skip]
        static SK_BYTES: [u8; 32] = [
            1, 1, 1, 1, 1, 1, 1, 1,
            0, 1, 2, 3, 4, 5, 6, 7,
            0xff, 0xff, 0, 0, 0xff, 0xff, 0, 0,
            99, 99, 99, 99, 99, 99, 99, 99
        ];
        static SK_STR: &str = "01010101010101010001020304050607ffff0000ffff00006363636363636363";

        #[cfg(secp256k1_fuzz)]
        #[rustfmt::skip]
        static PK_BYTES: [u8; 33] = [
            0x02,
            0x18, 0x84, 0x57, 0x81, 0xf6, 0x31, 0xc4, 0x8f,
            0x1c, 0x97, 0x09, 0xe2, 0x30, 0x92, 0x06, 0x7d,
            0x06, 0x83, 0x7f, 0x30, 0xaa, 0x0c, 0xd0, 0x54,
            0x4a, 0xc8, 0x87, 0xfe, 0x91, 0xdd, 0xd1, 0x66,
        ];
        static PK_STR: &str = "0218845781f631c48f1c9709e23092067d06837f30aa0cd0544ac887fe91ddd166";

        let sk = SecretKey::from_secret_bytes(SK_BYTES).unwrap();

        // In fuzzing mode secret->public key derivation is different, so
        // hard-code the expected result.
        #[cfg(not(secp256k1_fuzz))]
        let pk = PublicKey::from_secret_key(&sk);
        #[cfg(secp256k1_fuzz)]
        let pk = PublicKey::from_slice(&PK_BYTES).expect("pk");

        #[rustfmt::skip]
        assert_tokens(&sk.compact(), &[
            Token::Tuple{ len: 32 },
            Token::U8(1), Token::U8(1), Token::U8(1), Token::U8(1), Token::U8(1), Token::U8(1), Token::U8(1), Token::U8(1),
            Token::U8(0), Token::U8(1), Token::U8(2), Token::U8(3), Token::U8(4), Token::U8(5), Token::U8(6), Token::U8(7),
            Token::U8(0xff), Token::U8(0xff), Token::U8(0), Token::U8(0), Token::U8(0xff), Token::U8(0xff), Token::U8(0), Token::U8(0),
            Token::U8(99), Token::U8(99), Token::U8(99), Token::U8(99), Token::U8(99), Token::U8(99), Token::U8(99), Token::U8(99),
            Token::TupleEnd
        ]);

        assert_tokens(&sk.readable(), &[Token::BorrowedStr(SK_STR)]);
        assert_tokens(&sk.readable(), &[Token::Str(SK_STR)]);
        assert_tokens(&sk.readable(), &[Token::String(SK_STR)]);

        #[rustfmt::skip]
        assert_tokens(&pk.compact(), &[
            Token::Tuple{ len: 33 },
            Token::U8(0x02),
            Token::U8(0x18), Token::U8(0x84), Token::U8(0x57), Token::U8(0x81), Token::U8(0xf6), Token::U8(0x31), Token::U8(0xc4), Token::U8(0x8f),
            Token::U8(0x1c), Token::U8(0x97), Token::U8(0x09), Token::U8(0xe2), Token::U8(0x30), Token::U8(0x92), Token::U8(0x06), Token::U8(0x7d),
            Token::U8(0x06), Token::U8(0x83), Token::U8(0x7f), Token::U8(0x30), Token::U8(0xaa), Token::U8(0x0c), Token::U8(0xd0), Token::U8(0x54),
            Token::U8(0x4a), Token::U8(0xc8), Token::U8(0x87), Token::U8(0xfe), Token::U8(0x91), Token::U8(0xdd), Token::U8(0xd1), Token::U8(0x66),
            Token::TupleEnd
        ]);

        assert_tokens(&pk.readable(), &[Token::BorrowedStr(PK_STR)]);
        assert_tokens(&pk.readable(), &[Token::Str(PK_STR)]);
        assert_tokens(&pk.readable(), &[Token::String(PK_STR)]);
    }

    #[test]
    #[cfg(feature = "std")]
    fn test_tweak_add_then_tweak_add_check() {
        for _ in 0..10 {
            let tweak = Scalar::test_random();

            let kp = Keypair::test_random();
            let (xonly, _) = XOnlyPublicKey::from_keypair(&kp);

            let tweaked_kp = kp.add_xonly_tweak(&tweak).expect("keypair tweak add failed");
            let (tweaked_xonly, parity) =
                xonly.add_tweak(&tweak).expect("xonly pubkey tweak failed");

            let (want_tweaked_xonly, tweaked_kp_parity) = XOnlyPublicKey::from_keypair(&tweaked_kp);

            assert_eq!(tweaked_xonly, want_tweaked_xonly);
            assert_eq!(parity, tweaked_kp_parity);

            assert!(xonly.tweak_add_check(&tweaked_xonly, parity, tweak));
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
        use serde_test::{assert_tokens, Configure, Token};

        use crate::key::Keypair;
        use crate::SECP256K1;

        #[rustfmt::skip]
        static SK_BYTES: [u8; 32] = [
            1, 1, 1, 1, 1, 1, 1, 1,
            0, 1, 2, 3, 4, 5, 6, 7,
            0xff, 0xff, 0, 0, 0xff, 0xff, 0, 0,
            99, 99, 99, 99, 99, 99, 99, 99
        ];
        static SK_STR: &str = "01010101010101010001020304050607ffff0000ffff00006363636363636363";

        let sk = Keypair::from_seckey_byte_array(SK_BYTES).unwrap();
        #[rustfmt::skip]
        assert_tokens(&sk.compact(), &[
            Token::Tuple{ len: 32 },
            Token::U8(1), Token::U8(1), Token::U8(1), Token::U8(1), Token::U8(1), Token::U8(1), Token::U8(1), Token::U8(1),
            Token::U8(0), Token::U8(1), Token::U8(2), Token::U8(3), Token::U8(4), Token::U8(5), Token::U8(6), Token::U8(7),
            Token::U8(0xff), Token::U8(0xff), Token::U8(0), Token::U8(0), Token::U8(0xff), Token::U8(0xff), Token::U8(0), Token::U8(0),
            Token::U8(99), Token::U8(99), Token::U8(99), Token::U8(99), Token::U8(99), Token::U8(99), Token::U8(99), Token::U8(99),
            Token::TupleEnd
        ]);

        assert_tokens(&sk.readable(), &[Token::BorrowedStr(SK_STR)]);
        assert_tokens(&sk.readable(), &[Token::Str(SK_STR)]);
        assert_tokens(&sk.readable(), &[Token::String(SK_STR)]);
    }

    #[cfg(all(not(secp256k1_fuzz), feature = "alloc"))]
    fn keys() -> (SecretKey, PublicKey, Keypair, XOnlyPublicKey) {
        #[rustfmt::skip]
        static SK_BYTES: [u8; 32] = [
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0xff, 0xff, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00,
            0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63,
        ];

        #[rustfmt::skip]
        static PK_BYTES: [u8; 32] = [
            0x18, 0x84, 0x57, 0x81, 0xf6, 0x31, 0xc4, 0x8f,
            0x1c, 0x97, 0x09, 0xe2, 0x30, 0x92, 0x06, 0x7d,
            0x06, 0x83, 0x7f, 0x30, 0xaa, 0x0c, 0xd0, 0x54,
            0x4a, 0xc8, 0x87, 0xfe, 0x91, 0xdd, 0xd1, 0x66
        ];

        let mut pk_bytes = [0u8; 33];
        pk_bytes[0] = 0x02; // Use positive Y co-ordinate.
        pk_bytes[1..].clone_from_slice(&PK_BYTES);

        let sk = SecretKey::from_secret_bytes(SK_BYTES).expect("failed to parse sk bytes");
        let pk = PublicKey::from_slice(&pk_bytes).expect("failed to create pk from iterator");
        let kp = Keypair::from_secret_key(&sk);
        let xonly =
            XOnlyPublicKey::from_byte_array(PK_BYTES).expect("failed to get xonly from slice");

        (sk, pk, kp, xonly)
    }

    #[test]
    #[cfg(all(not(secp256k1_fuzz), feature = "alloc"))]
    fn convert_public_key_to_xonly_public_key() {
        let (_sk, pk, _kp, want) = keys();
        let (got, parity) = pk.x_only_public_key();

        assert_eq!(parity, Parity::Even);
        assert_eq!(got, want)
    }

    #[test]
    #[cfg(all(not(secp256k1_fuzz), feature = "alloc"))]
    fn convert_secret_key_to_public_key() {
        let (sk, want, _kp, _xonly) = keys();
        let got = sk.public_key();

        assert_eq!(got, want)
    }

    #[test]
    #[cfg(all(not(secp256k1_fuzz), feature = "alloc"))]
    fn convert_secret_key_to_x_only_public_key() {
        let (sk, _pk, _kp, want) = keys();
        let (got, parity) = sk.x_only_public_key();

        assert_eq!(parity, Parity::Even);
        assert_eq!(got, want)
    }

    #[test]
    #[cfg(all(not(secp256k1_fuzz), feature = "alloc"))]
    fn convert_keypair_to_public_key() {
        let (_sk, want, kp, _xonly) = keys();
        let got = kp.public_key();

        assert_eq!(got, want)
    }

    #[test]
    #[cfg(all(not(secp256k1_fuzz), feature = "alloc"))]
    fn convert_keypair_to_x_only_public_key() {
        let (_sk, _pk, kp, want) = keys();
        let (got, parity) = kp.x_only_public_key();

        assert_eq!(parity, Parity::Even);
        assert_eq!(got, want)
    }

    // SecretKey -> Keypair -> SecretKey
    #[test]
    #[cfg(all(not(secp256k1_fuzz), feature = "alloc"))]
    fn roundtrip_secret_key_via_keypair() {
        let (sk, _pk, _kp, _xonly) = keys();

        let kp = sk.keypair();
        let back = kp.secret_key();

        assert_eq!(back, sk)
    }

    // Keypair -> SecretKey -> Keypair
    #[test]
    #[cfg(all(not(secp256k1_fuzz), feature = "alloc"))]
    fn roundtrip_keypair_via_secret_key() {
        let (_sk, _pk, kp, _xonly) = keys();

        let sk = kp.secret_key();
        let back = sk.keypair();

        assert_eq!(back, kp)
    }

    // XOnlyPublicKey -> PublicKey -> XOnlyPublicKey
    #[test]
    #[cfg(all(not(secp256k1_fuzz), feature = "alloc"))]
    fn roundtrip_x_only_public_key_via_public_key() {
        let (_sk, _pk, _kp, xonly) = keys();

        let pk = xonly.public_key(Parity::Even);
        let (back, parity) = pk.x_only_public_key();

        assert_eq!(parity, Parity::Even);
        assert_eq!(back, xonly)
    }

    // PublicKey -> XOnlyPublicKey -> PublicKey
    #[test]
    #[cfg(all(not(secp256k1_fuzz), feature = "alloc"))]
    fn roundtrip_public_key_via_x_only_public_key() {
        let (_sk, pk, _kp, _xonly) = keys();

        let (xonly, parity) = pk.x_only_public_key();
        let back = xonly.public_key(parity);

        assert_eq!(back, pk)
    }

    #[test]
    fn public_key_from_x_only_public_key_and_odd_parity() {
        let s = "18845781f631c48f1c9709e23092067d06837f30aa0cd0544ac887fe91ddd166";
        let mut want = String::from("03");
        want.push_str(s);

        let xonly = XOnlyPublicKey::from_str(s).expect("failed to parse xonly pubkey string");
        let pk = xonly.public_key(Parity::Odd);
        let got = format!("{}", pk);

        assert_eq!(got, want)
    }

    #[test]
    #[cfg(not(secp256k1_fuzz))]
    #[cfg(all(feature = "global-context", feature = "serde"))]
    fn test_serde_x_only_pubkey() {
        use serde_test::{assert_tokens, Configure, Token};

        #[rustfmt::skip]
        static SK_BYTES: [u8; 32] = [
            1, 1, 1, 1, 1, 1, 1, 1,
            0, 1, 2, 3, 4, 5, 6, 7,
            0xff, 0xff, 0, 0, 0xff, 0xff, 0, 0,
            99, 99, 99, 99, 99, 99, 99, 99
        ];

        static PK_STR: &str = "18845781f631c48f1c9709e23092067d06837f30aa0cd0544ac887fe91ddd166";

        let kp = Keypair::from_seckey_byte_array(SK_BYTES).unwrap();
        let (pk, _parity) = XOnlyPublicKey::from_keypair(&kp);

        #[rustfmt::skip]
        assert_tokens(&pk.compact(), &[
            Token::Tuple{ len: 32 },
            Token::U8(0x18), Token::U8(0x84), Token::U8(0x57), Token::U8(0x81), Token::U8(0xf6), Token::U8(0x31), Token::U8(0xc4), Token::U8(0x8f),
            Token::U8(0x1c), Token::U8(0x97), Token::U8(0x09), Token::U8(0xe2), Token::U8(0x30), Token::U8(0x92), Token::U8(0x06), Token::U8(0x7d),
            Token::U8(0x06), Token::U8(0x83), Token::U8(0x7f), Token::U8(0x30), Token::U8(0xaa), Token::U8(0x0c), Token::U8(0xd0), Token::U8(0x54),
            Token::U8(0x4a), Token::U8(0xc8), Token::U8(0x87), Token::U8(0xfe), Token::U8(0x91), Token::U8(0xdd), Token::U8(0xd1), Token::U8(0x66),
            Token::TupleEnd
        ]);

        assert_tokens(&pk.readable(), &[Token::BorrowedStr(PK_STR)]);
        assert_tokens(&pk.readable(), &[Token::Str(PK_STR)]);
        assert_tokens(&pk.readable(), &[Token::String(PK_STR)]);
    }

    #[test]
    fn test_keypair_from_str() {
        let keypair = Keypair::test_random();
        let mut buf = [0_u8; constants::SECRET_KEY_SIZE * 2]; // Holds hex digits.
        let s = to_hex(&keypair.secret_key().to_secret_bytes(), &mut buf).unwrap();
        let parsed_key = Keypair::from_str(s).unwrap();
        assert_eq!(parsed_key, keypair);
    }

    #[test]
    #[cfg(feature = "serde")]
    fn test_keypair_deserialize_serde() {
        let sec_key_str = "4242424242424242424242424242424242424242424242424242424242424242";
        let keypair = Keypair::from_str(sec_key_str).unwrap();

        serde_test::assert_tokens(&keypair.readable(), &[Token::String(sec_key_str)]);

        let sec_key_bytes = keypair.secret_key().to_secret_bytes();
        let tokens = std::iter::once(Token::Tuple { len: 32 })
            .chain(sec_key_bytes.iter().copied().map(Token::U8))
            .chain(std::iter::once(Token::TupleEnd))
            .collect::<Vec<_>>();
        serde_test::assert_tokens(&keypair.compact(), &tokens);
    }
}

#[cfg(bench)]
mod benches {
    use std::collections::BTreeSet;

    use test::Bencher;

    use crate::constants::GENERATOR_X;
    use crate::PublicKey;

    #[bench]
    fn bench_pk_ordering(b: &mut Bencher) {
        let mut map = BTreeSet::new();
        let mut g_slice = [02u8; 33];
        g_slice[1..].copy_from_slice(&GENERATOR_X);
        let g = PublicKey::from_slice(&g_slice).unwrap();
        let mut pk = g;
        b.iter(|| {
            map.insert(pk);
            pk = pk.combine(&pk).unwrap();
        })
    }
}
