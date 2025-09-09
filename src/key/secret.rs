// SPDX-License-Identifier: CC0-1.0
//! Secret signing keys.

use core::{ops, str};

#[cfg(feature = "serde")]
use serde::ser::SerializeTuple;

use crate::ffi::CPtr as _;
use crate::{
    constants, ffi, from_hex, Error, Keypair, Parity, PublicKey, Scalar, Secp256k1, Signing,
    XOnlyPublicKey,
};
#[cfg(feature = "global-context")]
use crate::{ecdsa, Message, SECP256K1};

mod encapsulate {
    use crate::constants::SECRET_KEY_SIZE;
    use crate::ffi::{self, CPtr};
    use crate::Error;

    /// Secret key - a 256-bit key used to create ECDSA and Taproot signatures.
    ///
    /// This value should be generated using a [cryptographically secure pseudorandom number generator].
    ///
    /// # Side channel attacks
    ///
    /// We have attempted to reduce the side channel attack surface by implementing a constant time `eq`
    /// method. For similar reasons we explicitly do not implement `PartialOrd`, `Ord`, or `Hash` on
    /// `SecretKey`. If you really want to order secret keys then you can use `AsRef` to get at the
    /// underlying bytes and compare them - however this is almost certainly a bad idea.
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
    /// use secp256k1::{rand, SecretKey};
    ///
    /// let secret_key = SecretKey::new(&mut rand::rng());
    /// # }
    /// ```
    /// [`bincode`]: https://docs.rs/bincode
    /// [`cbor`]: https://docs.rs/cbor
    /// [cryptographically secure pseudorandom number generator]: https://en.wikipedia.org/wiki/Cryptographically_secure_pseudorandom_number_generator
    #[derive(Copy, Clone)]
    pub struct SecretKey([u8; SECRET_KEY_SIZE]);
    // FIXME these two macro call should be moved outside of the encapsulate module
    impl_display_secret!(SecretKey);
    impl_non_secure_erase!(SecretKey, 0, [1u8; SECRET_KEY_SIZE]);

    impl SecretKey {
        /// Returns the secret key as a byte value.
        ///
        /// # Side channel attacks
        ///
        /// Using ordering functions (`PartialOrd`/`Ord`) on a reference to secret keys leaks data
        /// because the implementations are not constant time. Doing so will make your code vulnerable
        /// to side channel attacks. [`SecretKey::eq`] is implemented using a constant time algorithm,
        /// please consider using it to do comparisons of secret keys.
        #[inline]
        pub fn to_secret_bytes(&self) -> [u8; SECRET_KEY_SIZE] { self.0 }

        /// Returns a reference to the secret key as a byte array.
        ///
        /// See note on [`Self::to_secret_bytes`].
        #[inline]
        pub fn as_secret_bytes(&self) -> &[u8; SECRET_KEY_SIZE] { &self.0 }

        /// Converts a 32-byte array to a secret key.
        ///
        /// See note on [`Self::to_secret_bytes`].
        ///
        /// # Errors
        ///
        /// Returns an error when the secret key is invalid: when it is all-zeros or would exceed
        /// the curve order when interpreted as a big-endian unsigned integer.
        ///
        /// # Examples
        ///
        /// ```
        /// use secp256k1::SecretKey;
        /// let sk = SecretKey::from_byte_array([0xcd; 32]).expect("32 bytes, within curve order");
        /// ```
        #[inline]
        pub fn from_secret_bytes(data: [u8; SECRET_KEY_SIZE]) -> Result<SecretKey, Error> {
            crate::with_raw_global_context(
                |ctx| unsafe {
                    if ffi::secp256k1_ec_seckey_verify(ctx.as_ptr(), data.as_c_ptr()) == 0 {
                        return Err(Error::InvalidSecretKey);
                    }
                    Ok(SecretKey(data))
                },
                None,
            )
        }
    }

    // Must be inside the `encapsulate` module since there is no way to obtain mutable
    // access to the internal array outside of the module.
    impl CPtr for SecretKey {
        type Target = u8;

        fn as_c_ptr(&self) -> *const Self::Target { self.as_secret_bytes().as_ptr() }

        fn as_mut_c_ptr(&mut self) -> *mut Self::Target { self.0.as_mut_ptr() }
    }
}
pub use encapsulate::SecretKey;

impl PartialEq for SecretKey {
    /// This implementation is designed to be constant time to help prevent side channel attacks.
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        let accum = self
            .as_secret_bytes()
            .iter()
            .zip(other.as_secret_bytes())
            .fold(0, |accum, (a, b)| accum | a ^ b);
        unsafe { core::ptr::read_volatile(&accum) == 0 }
    }
}

impl Eq for SecretKey {}

impl AsRef<[u8; constants::SECRET_KEY_SIZE]> for SecretKey {
    /// Gets a reference to the underlying array.
    ///
    /// See note on [`Self::to_secret_bytes`].
    #[inline]
    fn as_ref(&self) -> &[u8; constants::SECRET_KEY_SIZE] { self.as_secret_bytes() }
}

impl<I> ops::Index<I> for SecretKey
where
    [u8]: ops::Index<I>,
{
    type Output = <[u8] as ops::Index<I>>::Output;

    #[inline]
    fn index(&self, index: I) -> &Self::Output { &self.as_secret_bytes()[index] }
}

impl str::FromStr for SecretKey {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut res = [0u8; constants::SECRET_KEY_SIZE];
        match from_hex(s, &mut res) {
            Ok(constants::SECRET_KEY_SIZE) => SecretKey::from_secret_bytes(res),
            _ => Err(Error::InvalidSecretKey),
        }
    }
}

impl SecretKey {
    /// Generates a new random secret key.
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(all(feature = "std", feature =  "rand"))] {
    /// use secp256k1::{rand, SecretKey};
    /// let secret_key = SecretKey::new(&mut rand::rng());
    /// # }
    /// ```
    #[inline]
    #[cfg(feature = "rand")]
    pub fn new<R: rand::Rng + ?Sized>(rng: &mut R) -> Self {
        loop {
            let data = crate::random_32_bytes(rng);
            if let Ok(key) = Self::from_secret_bytes(data) {
                return key;
            }
        }
    }

    /// Converts a 32-byte array to a secret key.
    #[deprecated(since = "0.32.0", note = "use from_secret_bytes instead")]
    pub fn from_byte_array(data: [u8; constants::SECRET_KEY_SIZE]) -> Result<SecretKey, Error> {
        Self::from_secret_bytes(data)
    }

    /// Creates a new secret key using data from BIP-340 [`Keypair`].
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(all(feature = "rand", feature = "std"))] {
    /// use secp256k1::{rand, Secp256k1, SecretKey, Keypair};
    ///
    /// let secp = Secp256k1::new();
    /// let keypair = Keypair::new(&secp, &mut rand::rng());
    /// let secret_key = SecretKey::from_keypair(&keypair);
    /// # }
    /// ```
    #[inline]
    pub fn from_keypair(keypair: &Keypair) -> Self {
        let mut sk = [0u8; constants::SECRET_KEY_SIZE];
        unsafe {
            let ret = ffi::secp256k1_keypair_sec(
                ffi::secp256k1_context_no_precomp,
                sk.as_mut_c_ptr(),
                keypair.as_c_ptr(),
            );
            debug_assert_eq!(ret, 1);
        }
        Self::from_secret_bytes(sk).expect("a valid Keypair has a valid SecretKey")
    }

    /// Returns the secret key as a byte value.
    #[inline]
    #[deprecated(since = "0.32.0", note = "use to_secret_bytes instead")]
    pub fn secret_bytes(&self) -> [u8; constants::SECRET_KEY_SIZE] { self.to_secret_bytes() }

    /// Negates the secret key.
    #[inline]
    #[must_use = "you forgot to use the negated secret key"]
    pub fn negate(mut self) -> SecretKey {
        unsafe {
            let res = ffi::secp256k1_ec_seckey_negate(
                ffi::secp256k1_context_no_precomp,
                self.as_mut_c_ptr(),
            );
            debug_assert_eq!(res, 1);
        }
        self
    }

    /// Tweaks a [`SecretKey`] by adding `tweak` modulo the curve order.
    ///
    /// # Errors
    ///
    /// Returns an error if the resulting key would be invalid.
    #[inline]
    pub fn add_tweak(mut self, tweak: &Scalar) -> Result<SecretKey, Error> {
        unsafe {
            if ffi::secp256k1_ec_seckey_tweak_add(
                ffi::secp256k1_context_no_precomp,
                self.as_mut_c_ptr(),
                tweak.as_c_ptr(),
            ) != 1
            {
                Err(Error::InvalidTweak)
            } else {
                Ok(self)
            }
        }
    }

    /// Tweaks a [`SecretKey`] by multiplying by `tweak` modulo the curve order.
    ///
    /// # Errors
    ///
    /// Returns an error if the resulting key would be invalid.
    #[inline]
    pub fn mul_tweak(mut self, tweak: &Scalar) -> Result<SecretKey, Error> {
        unsafe {
            if ffi::secp256k1_ec_seckey_tweak_mul(
                ffi::secp256k1_context_no_precomp,
                self.as_mut_c_ptr(),
                tweak.as_c_ptr(),
            ) != 1
            {
                Err(Error::InvalidTweak)
            } else {
                Ok(self)
            }
        }
    }

    /// Constructs an ECDSA signature for `msg` using the global [`SECP256K1`] context.
    #[inline]
    #[cfg(feature = "global-context")]
    pub fn sign_ecdsa(&self, msg: impl Into<Message>) -> ecdsa::Signature {
        SECP256K1.sign_ecdsa(msg, self)
    }

    /// Returns the [`Keypair`] for this [`SecretKey`].
    ///
    /// This is equivalent to using [`Keypair::from_secret_key`].
    #[inline]
    pub fn keypair<C: Signing>(&self, secp: &Secp256k1<C>) -> Keypair {
        Keypair::from_secret_key(secp, self)
    }

    /// Returns the [`PublicKey`] for this [`SecretKey`].
    ///
    /// This is equivalent to using [`PublicKey::from_secret_key`].
    #[inline]
    pub fn public_key(&self) -> PublicKey { PublicKey::from_secret_key(self) }

    /// Returns the [`XOnlyPublicKey`] (and its [`Parity`]) for this [`SecretKey`].
    ///
    /// This is equivalent to `XOnlyPublicKey::from_keypair(self.keypair(secp))`.
    #[inline]
    pub fn x_only_public_key<C: Signing>(&self, secp: &Secp256k1<C>) -> (XOnlyPublicKey, Parity) {
        let kp = self.keypair(secp);
        XOnlyPublicKey::from_keypair(&kp)
    }

    /// Constructor for unit testing.
    #[cfg(test)]
    #[cfg(all(feature = "rand", feature = "std"))]
    pub fn test_random() -> Self { Self::new(&mut rand::rng()) }

    /// Constructor for unit testing.
    #[cfg(test)]
    #[cfg(not(all(feature = "rand", feature = "std")))]
    pub fn test_random() -> Self {
        loop {
            if let Ok(ret) = Self::from_secret_bytes(crate::test_random_32_bytes()) {
                return ret;
            }
        }
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for SecretKey {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            let mut buf = [0u8; constants::SECRET_KEY_SIZE * 2];
            s.serialize_str(
                crate::to_hex(self.as_secret_bytes(), &mut buf)
                    .expect("fixed-size hex serialization"),
            )
        } else {
            let mut tuple = s.serialize_tuple(constants::SECRET_KEY_SIZE)?;
            for byte in self.as_secret_bytes().iter() {
                tuple.serialize_element(byte)?;
            }
            tuple.end()
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for SecretKey {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        if d.is_human_readable() {
            d.deserialize_str(crate::serde_util::FromStrVisitor::new(
                "a hex string representing 32 byte SecretKey",
            ))
        } else {
            let visitor =
                crate::serde_util::Tuple32Visitor::new("raw 32 bytes SecretKey", |bytes| {
                    SecretKey::from_secret_bytes(bytes)
                });
            d.deserialize_tuple(constants::SECRET_KEY_SIZE, visitor)
        }
    }
}
