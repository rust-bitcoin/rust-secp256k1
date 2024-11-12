//! This module implements high-level Rust bindings for a Schnorr-based
//! multi-signature scheme called MuSig2 [paper](https://eprint.iacr.org/2020/1261).
//! It is compatible with bip-schnorr.
//!
//! The documentation in this module is for reference and may not be sufficient
//! for advanced use-cases. A full description of the C API usage along with security considerations
//! can be found in [C-musig.md](secp256k1-sys/depend/secp256k1/src/modules/musig/musig.md).
use core;
use core::fmt;
use core::mem::MaybeUninit;
#[cfg(feature = "std")]
use std;

use crate::ffi::{self, CPtr};
use crate::{
    schnorr, Error, Keypair, Message, PublicKey, Scalar, Secp256k1, SecretKey, Signing, Verification, XOnlyPublicKey
};

/// Musig partial signature parsing errors
#[derive(Debug, Clone, Copy, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub enum ParseError {
    /// Parse Argument is malformed. This might occur if the point is on the secp order,
    /// or if the secp scalar is outside of group order
    MalformedArg,
}

#[cfg(feature = "std")]
impl std::error::Error for ParseError {}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match *self {
            ParseError::MalformedArg => write!(f, "Malformed parse argument"),
        }
    }
}

/// Session Id for a MuSig session.
#[allow(missing_copy_implementations)]
#[derive(Debug, Eq, PartialEq)]
pub struct SessionSecretRand([u8; 32]);

impl SessionSecretRand {
    /// Generates a new session ID using thread RNG.
    #[cfg(all(feature = "rand", feature = "std"))]
    pub fn new() -> Self {
        Self::from_rng(&mut rand::thread_rng())
    }

    /// Creates a new [`SessionSecretRand`] with random bytes from the given rng
    #[cfg(feature = "rand")]
    pub fn from_rng<R: rand::Rng + ?Sized>(rng: &mut R) -> Self {
        let session_secrand = crate::random_32_bytes(rng);
        SessionSecretRand(session_secrand)
    }

    /// Creates a new [`SessionSecretRand`] with the given bytes.
    ///
    /// Special care must be taken that the bytes are unique for each call to
    /// [`KeyAggCache::nonce_gen`] or [`new_nonce_pair`]. The simplest
    /// recommendation is to use a cryptographicaly random 32-byte value.
    ///
    /// In rand-std environment, [`SessionSecretRand::new`] can be used to generate a random
    /// session id using thread rng.
    pub fn assume_unique_per_nonce_gen(inner: [u8; 32]) -> Self { SessionSecretRand(inner) }

    /// Obtains the inner bytes of the [`SessionSecretRand`].
    pub fn to_bytes(&self) -> [u8; 32] { self.0 }

    /// Obtains a reference to the inner bytes of the [`SessionSecretRand`].
    pub fn as_bytes(&self) -> &[u8; 32] { &self.0 }
}

///  Cached data related to a key aggregation.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyAggCache{
    data: ffi::MusigKeyAggCache,
    aggregated_xonly_public_key: XOnlyPublicKey
}

impl CPtr for KeyAggCache {
    type Target = ffi::MusigKeyAggCache;

    fn as_c_ptr(&self) -> *const Self::Target { self.as_ptr() }

    fn as_mut_c_ptr(&mut self) -> *mut Self::Target { self.as_mut_ptr() }
}


/// Musig tweaking related error.
#[derive(Debug, Clone, Copy, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub struct InvalidTweakErr;

#[cfg(feature = "std")]
impl std::error::Error for InvalidTweakErr {}

impl fmt::Display for InvalidTweakErr {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "The tweak is negation of secret key")
    }
}

/// Low level API for starting a signing session by generating a nonce.
///
/// Use [`KeyAggCache::nonce_gen`] whenever
/// possible. This API provides full flexibility in providing custom nonce generation,
/// but should be use with care.
///
/// This function outputs a secret nonce that will be required for signing and a
/// corresponding public nonce that is intended to be sent to other signers.
///
/// MuSig differs from regular Schnorr signing in that implementers _must_ take
/// special care to not reuse a nonce. If you cannot provide a `sec_key`, `session_secrand`
/// UNIFORMLY RANDOM AND KEPT SECRET (even from other signers). Refer to libsecp256k1
/// documentation for additional considerations.
///
/// MuSig2 nonces can be precomputed without knowing the aggregate public key, the message to sign.
/// Refer to libsecp256k1 documentation for additional considerations.
///
/// # Arguments:
///
/// * `secp` : [`Secp256k1`] context object initialized for signing
/// * `session_secrand`: [`SessionSecretRand`] Uniform random identifier for this session. Each call to this
///   function must have a UNIQUE `session_secrand`.
/// * `sec_key`: Optional [`SecretKey`] that we will use to sign to a create partial signature. Provide this
///   for maximal mis-use resistance.
/// * `pub_key`: [`PublicKey`] that we will use to create partial signature. The secnonce
///   output of this function cannot be used to sign for any other public key.
/// * `msg`: Optional [`Message`] that will be signed later on. Provide this for maximal misuse resistance.
/// * `extra_rand`: Additional randomness for mis-use resistance. Provide this for maximal misuse resistance
///
/// Remember that nonce reuse will immediately leak the secret key!
///
/// # Errors:
///
/// * `ZeroSession`: if the `session_secrand` is supplied is all zeros.
///
/// Example:
///
/// ```rust
/// # # [cfg(any(test, feature = "rand-std"))] {
/// # use secp256k1::rand::{thread_rng, RngCore};
/// # use secp256k1::{PublicKey, Secp256k1, SecretKey, new_nonce_pair, SessionSecretRand};
/// # let secp = Secp256k1::new();
/// // The session id must be sampled at random. Read documentation for more details.
/// let session_secrand = SessionSecretRand::new(&mut thread_rng());
/// let sk = SecretKey::new(&mut thread_rng());
/// let pk = PublicKey::from_secret_key(&secp, &sk);
///
/// // Supply extra auxillary randomness to prevent misuse(for example, time of day)
/// let extra_rand : Option<[u8; 32]> = None;
///
/// let (_sec_nonce, _pub_nonce) = new_nonce_pair(&secp, session_secrand, None, Some(sk), pk, None, None)
///     .expect("non zero session id");
/// # }
/// ```
pub fn new_nonce_pair<C: Signing>(
    secp: &Secp256k1<C>,
    session_secrand: SessionSecretRand,
    key_agg_cache: Option<&KeyAggCache>,
    sec_key: Option<SecretKey>,
    pub_key: PublicKey,
    msg: Option<Message>,
    extra_rand: Option<[u8; 32]>,
) -> (SecretNonce, PublicNonce) {
    let cx = secp.ctx().as_ptr();
    let extra_ptr = extra_rand.as_ref().map(|e| e.as_ptr()).unwrap_or(core::ptr::null());
    let sk_ptr = sec_key.as_ref().map(|e| e.as_c_ptr()).unwrap_or(core::ptr::null());
    let msg_ptr = msg.as_ref().map(|e| e.as_c_ptr()).unwrap_or(core::ptr::null());
    let cache_ptr = key_agg_cache.map(|e| e.as_ptr()).unwrap_or(core::ptr::null());
    unsafe {
        let mut sec_nonce = MaybeUninit::<ffi::MusigSecNonce>::uninit();
        let mut pub_nonce = MaybeUninit::<ffi::MusigPubNonce>::uninit();
        if ffi::secp256k1_musig_nonce_gen(
            cx,
            sec_nonce.as_mut_ptr(),
            pub_nonce.as_mut_ptr(),
            session_secrand.as_bytes().as_ptr(),
            sk_ptr,
            pub_key.as_c_ptr(),
            msg_ptr,
            cache_ptr,
            extra_ptr,
        ) == 0
        {
            // Rust type system guarantees that
            // - input secret key is valid
            // - msg is 32 bytes
            // - Key agg cache is valid
            // - extra input is 32 bytes
            // This can only happen when the session id is all zeros
            panic!("A zero session id was supplied")
        } else {
            let pub_nonce = PublicNonce(pub_nonce.assume_init());
            let sec_nonce = SecretNonce(sec_nonce.assume_init());
            (sec_nonce, pub_nonce)
        }
    }
}

/// A Musig partial signature.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct PartialSignature(ffi::MusigPartialSignature);

impl CPtr for PartialSignature {
    type Target = ffi::MusigPartialSignature;

    fn as_c_ptr(&self) -> *const Self::Target { self.as_ptr() }

    fn as_mut_c_ptr(&mut self) -> *mut Self::Target { self.as_mut_ptr() }
}

impl PartialSignature {
    /// Serialize a PartialSignature.
    ///
    /// # Returns
    ///
    /// 32-byte array
    pub fn serialize(&self) -> [u8; 32] {
        let mut data = MaybeUninit::<[u8; 32]>::uninit();
        unsafe {
            if ffi::secp256k1_musig_partial_sig_serialize(
                ffi::secp256k1_context_no_precomp,
                data.as_mut_ptr() as *mut u8,
                self.as_ptr(),
            ) == 0
            {
                // Only fails if args are null pointer which is possible in safe rust
                unreachable!("Serialization cannot fail")
            } else {
                data.assume_init()
            }
        }
    }

    /// Deserialize a PartialSignature from bytes.
    ///
    /// # Errors:
    ///
    /// - MalformedArg: If the signature [`PartialSignature`] is out of curve order
    pub fn from_byte_array(data: &[u8; ffi::MUSIG_PART_SIG_SERIALIZED_LEN]) -> Result<Self, ParseError> {
        let mut partial_sig = MaybeUninit::<ffi::MusigPartialSignature>::uninit();
        unsafe {
            if ffi::secp256k1_musig_partial_sig_parse(
                ffi::secp256k1_context_no_precomp,
                partial_sig.as_mut_ptr(),
                data.as_ptr(),
            ) == 0
            {
                Err(ParseError::MalformedArg)
            } else {
                Ok(PartialSignature(partial_sig.assume_init()))
            }
        }
    }

    /// Get a const pointer to the inner PartialSignature
    pub fn as_ptr(&self) -> *const ffi::MusigPartialSignature { &self.0 }

    /// Get a mut pointer to the inner PartialSignature
    pub fn as_mut_ptr(&mut self) -> *mut ffi::MusigPartialSignature { &mut self.0 }
}

impl KeyAggCache {
    /// Creates a new [`KeyAggCache`] by supplying a list of PublicKeys used in the session.
    ///
    /// Computes a combined public key and the hash of the given public keys.
    ///
    /// Different orders of `pubkeys` result in different `agg_pk`s.
    /// The pubkeys can be sorted lexicographically before combining with which
    /// ensures the same resulting `agg_pk` for the same multiset of pubkeys.
    /// This is useful to do before aggregating pubkeys, such that the order of pubkeys
    /// does not affect the combined public key.
    ///
    /// # Returns
    ///
    ///  A [`KeyAggCache`] the can be used [`KeyAggCache::nonce_gen`] and [`Session::new`].
    ///
    /// # Args:
    ///
    /// * `secp` - Secp256k1 context object initialized for verification
    /// * `pubkeys` - Input array of public keys to combine. The order is important; a
    ///   different order will result in a different combined public key
    ///
    /// Example:
    ///
    /// ```rust
    /// # # [cfg(any(test, feature = "rand-std"))] {
    /// # use secp256k1::rand::{thread_rng, RngCore};
    /// # use secp256k1::{KeyAggCache, Secp256k1, SecretKey, Keypair, PublicKey};
    /// # let secp = Secp256k1::new();
    /// # let sk1 = SecretKey::new(&mut thread_rng());
    /// # let pub_key1 = PublicKey::from_secret_key(&secp, &sk1);
    /// # let sk2 = SecretKey::new(&mut thread_rng());
    /// # let pub_key2 = PublicKey::from_secret_key(&secp, &sk2);
    /// #
    /// let key_agg_cache = KeyAggCache::new(&secp, &[pub_key1, pub_key2]);
    /// let _agg_pk = key_agg_cache.agg_pk();
    /// # }
    /// ```
    pub fn new<C: Verification>(secp: &Secp256k1<C>, pubkeys: &[&PublicKey]) -> Self {
        let cx = secp.ctx().as_ptr();

        let mut key_agg_cache = MaybeUninit::<ffi::MusigKeyAggCache>::uninit();
        let mut agg_pk = MaybeUninit::<ffi::XOnlyPublicKey>::uninit();

        unsafe {
            let pubkeys_ref = core::slice::from_raw_parts(pubkeys.as_c_ptr() as *const *const ffi::PublicKey, pubkeys.len());

            if ffi::secp256k1_musig_pubkey_agg(
                cx,
                agg_pk.as_mut_ptr(),
                key_agg_cache.as_mut_ptr(),
                pubkeys_ref.as_ptr(),
                pubkeys_ref.len(),
            ) == 0
            {
                // Returns 0 only if the keys are malformed that never happens in safe rust type system.
                unreachable!("Invalid XOnlyPublicKey in input pubkeys")
            } else {
                // secp256k1_musig_pubkey_agg overwrites the cache and the key so this is sound.
                let key_agg_cache = key_agg_cache.assume_init();
                let agg_pk = XOnlyPublicKey::from(agg_pk.assume_init());
                KeyAggCache{ data: key_agg_cache,  aggregated_xonly_public_key: agg_pk }
            }
        }
    }

    /// Obtains the aggregate public key for this [`KeyAggCache`]
    pub fn agg_pk(&self) -> XOnlyPublicKey { self.aggregated_xonly_public_key }

    /// Obtains the aggregate public key for this [`KeyAggCache`] as a full [`PublicKey`].
    ///
    /// This is only useful if you need the non-xonly public key, in particular for
    /// plain (non-xonly) tweaking or batch-verifying multiple key aggregations
    /// (not supported yet).
    pub fn agg_pk_full(&self) -> PublicKey {
        unsafe {
            let mut pk = PublicKey::from(ffi::PublicKey::new());
            if ffi::secp256k1_musig_pubkey_get(
                ffi::secp256k1_context_no_precomp,
                pk.as_mut_c_ptr(),
                self.as_ptr(),
            ) == 0
            {
                // Returns 0 only if the keys are malformed that never happens in safe rust type system.
                unreachable!("All the arguments are valid")
            } else {
                pk
            }
        }
    }

    /// Apply ordinary "EC" tweaking to a public key in a [`KeyAggCache`].
    ///
    /// This is done by adding the generator multiplied with `tweak32` to it. Returns the tweaked [`PublicKey`].
    /// This is useful for deriving child keys from an aggregate public key via BIP32.
    /// This function is required if you want to _sign_ for a tweaked aggregate key.
    ///
    /// # Arguments:
    ///
    /// * `secp` : [`Secp256k1`] context object initialized for verification
    /// * `tweak`: tweak of type [`Scalar`] with which to tweak the aggregated key
    ///
    /// # Errors:
    ///
    /// If resulting public key would be invalid (only when the tweak is the negation of the corresponding
    /// secret key). For uniformly random 32-byte arrays(for example, in BIP 32 derivation) the chance of
    /// being invalid is negligible (around 1 in 2^128).
    ///
    /// Example:
    ///
    /// ```rust
    /// # # [cfg(any(test, feature = "rand-std"))] {
    /// # use secp256k1::rand::{thread_rng, RngCore};
    /// # use secp256k1::{KeyAggCache, Secp256k1, SecretKey, Keypair, PublicKey};
    /// # let secp = Secp256k1::new();
    /// # let sk1 = SecretKey::new(&mut thread_rng());
    /// # let pub_key1 = PublicKey::from_secret_key(&secp, &sk1);
    /// # let sk2 = SecretKey::new(&mut thread_rng());
    /// # let pub_key2 = PublicKey::from_secret_key(&secp, &sk2);
    /// #
    /// let mut key_agg_cache = KeyAggCache::new(&secp, &[pub_key1, pub_key2]);
    ///
    /// let tweak: [u8; 32] = *b"this could be a BIP32 tweak....\0";
    /// let tweak = Scalar::from_be_bytes(tweak).unwrap();
    /// let tweaked_key = key_agg_cache.pubkey_ec_tweak_add(&secp, tweak).unwrap();
    /// # }
    /// ```
    pub fn pubkey_ec_tweak_add<C: Verification>(
        &mut self,
        secp: &Secp256k1<C>,
        tweak: &Scalar,
    ) -> Result<PublicKey, InvalidTweakErr> {
        let cx = secp.ctx().as_ptr();
        unsafe {
            let mut out = PublicKey::from(ffi::PublicKey::new());
            if ffi::secp256k1_musig_pubkey_ec_tweak_add(
                cx,
                out.as_mut_c_ptr(),
                self.as_mut_ptr(),
                tweak.as_c_ptr(),
            ) == 0
            {
                Err(InvalidTweakErr)
            } else {
                self.aggregated_xonly_public_key = out.x_only_public_key().0;
                Ok(out)
            }
        }
    }

    /// Apply "x-only" tweaking to a public key in a [`KeyAggCache`].
    ///
    /// This is done by adding the generator multiplied with `tweak32` to it. Returns the tweaked [`XOnlyPublicKey`].
    /// This is useful in creating taproot outputs.
    /// This function is required if you want to _sign_ for a tweaked aggregate key.
    ///
    /// # Arguments:
    ///
    /// * `secp` : [`Secp256k1`] context object initialized for verification
    /// * `tweak`: tweak of type [`SecretKey`] with which to tweak the aggregated key
    ///
    /// # Errors:
    ///
    /// If resulting public key would be invalid (only when the tweak is the negation of the corresponding
    /// secret key). For uniformly random 32-byte arrays(for example, in BIP341 taproot tweaks) the chance of
    /// being invalid is negligible (around 1 in 2^128)
    ///
    /// Example:
    ///
    /// ```rust
    /// # # [cfg(any(test, feature = "rand-std"))] {
    /// # use secp256k1::rand::{thread_rng, RngCore};
    /// # use secp256k1::{KeyAggCache, Secp256k1, SecretKey, Keypair, PublicKey};
    /// # let secp = Secp256k1::new();
    /// # let sk1 = SecretKey::new(&mut thread_rng());
    /// # let pub_key1 = PublicKey::from_secret_key(&secp, &sk1);
    /// # let sk2 = SecretKey::new(&mut thread_rng());
    /// # let pub_key2 = PublicKey::from_secret_key(&secp, &sk2);
    ///
    /// let mut key_agg_cache = KeyAggCache::new(&secp, &[pub_key1, pub_key2]);
    ///
    /// let tweak = SecretKey::from_slice(b"Insecure tweak, Don't use this!!").unwrap(); // tweak could be from tap
    /// let _x_only_key_tweaked = key_agg_cache.pubkey_xonly_tweak_add(&secp, tweak).unwrap();
    /// # }
    /// ```
    pub fn pubkey_xonly_tweak_add<C: Verification>(
        &mut self,
        secp: &Secp256k1<C>,
        tweak: &Scalar,
    ) -> Result<PublicKey, InvalidTweakErr> {
        let cx = secp.ctx().as_ptr();
        unsafe {
            let mut out = PublicKey::from(ffi::PublicKey::new());
            if ffi::secp256k1_musig_pubkey_xonly_tweak_add(
                cx,
                out.as_mut_c_ptr(),
                self.as_mut_ptr(),
                tweak.as_c_ptr(),
            ) == 0
            {
                Err(InvalidTweakErr)
            } else {
                self.aggregated_xonly_public_key = out.x_only_public_key().0;
                Ok(out)
            }
        }
    }

    /// Starts a signing session by generating a nonce
    ///
    /// This function outputs a secret nonce that will be required for signing and a
    /// corresponding public nonce that is intended to be sent to other signers.
    ///
    /// MuSig differs from regular Schnorr signing in that implementers _must_ take
    /// special care to not reuse a nonce. If you cannot provide a `sec_key`, `session_secrand`
    /// UNIFORMLY RANDOM AND KEPT SECRET (even from other signers).
    /// Refer to libsecp256k1 documentation for additional considerations.
    ///
    /// MuSig2 nonces can be precomputed without knowing the aggregate public key, the message to sign.
    /// See the `new_nonce_pair` method that allows generating [`SecretNonce`] and [`PublicNonce`]
    /// with only the `session_secrand` field.
    ///
    /// Remember that nonce reuse will immediately leak the secret key!
    ///
    /// # Returns:
    ///
    /// A pair of ([`SecretNonce`], [`PublicNonce`]) that can be later used signing and aggregation
    ///
    /// # Arguments:
    ///
    /// * `secp` : [`Secp256k1`] context object initialized for signing
    /// * `session_secrand`: [`SessionSecretRand`] Uniform random identifier for this session. Each call to this
    ///   function must have a UNIQUE `session_secrand`.
    /// * `pub_key`: [`PublicKey`] of the signer creating the nonce.
    /// * `msg`: [`Message`] that will be signed later on.
    /// * `extra_rand`: Additional randomness for mis-use resistance
    ///
    /// # Errors:
    ///
    /// * `ZeroSession`: if the `session_secrand` is supplied is all zeros.
    ///
    /// Example:
    ///
    /// ```rust
    /// # # [cfg(any(test, feature = "rand-std"))] {
    /// # use secp256k1::rand::{thread_rng, RngCore};
    /// # use secp256k1::{KeyAggCache, Secp256k1, SecretKey, Keypair, PublicKey, SessionSecretRand, Message};
    /// # let secp = Secp256k1::new();
    /// # let sk1 = SecretKey::new(&mut thread_rng());
    /// # let pub_key1 = PublicKey::from_secret_key(&secp, &sk1);
    /// # let sk2 = SecretKey::new(&mut thread_rng());
    /// # let pub_key2 = PublicKey::from_secret_key(&secp, &sk2);
    /// #
    /// let key_agg_cache = KeyAggCache::new(&secp, &[pub_key1, pub_key2]);
    /// // The session id must be sampled at random. Read documentation for more details.
    /// let session_secrand = SessionSecretRand::new(&mut thread_rng());
    ///
    /// let msg = Message::from_digest_slice(b"Public Message we want to sign!!").unwrap();
    ///
    /// // Provide the current time for mis-use resistance
    /// let extra_rand : Option<[u8; 32]> = None;
    /// let (_sec_nonce, _pub_nonce) = key_agg_cache.nonce_gen(&secp, session_secrand, pub_key1, msg, extra_rand)
    ///     .expect("non zero session id");
    /// # }
    /// ```
    pub fn nonce_gen<C: Signing>(
        &self,
        secp: &Secp256k1<C>,
        session_secrand: SessionSecretRand,
        pub_key: PublicKey,
        msg: Message,
        extra_rand: Option<[u8; 32]>,
    ) -> (SecretNonce, PublicNonce) {
        // The secret key here is supplied as NULL. This is okay because we supply the
        // public key and the message.
        // This makes a simple API for the user because it does not require them to pass here.
        new_nonce_pair(secp, session_secrand, Some(self), None, pub_key, Some(msg), extra_rand)
    }

    /// Get a const pointer to the inner KeyAggCache
    pub fn as_ptr(&self) -> *const ffi::MusigKeyAggCache { &self.data }

    /// Get a mut pointer to the inner KeyAggCache
    pub fn as_mut_ptr(&mut self) -> *mut ffi::MusigKeyAggCache { &mut self.data }
}

/// Musig Secret Nonce.
///
/// This structure MUST NOT be copied or
/// read or written to it directly. A signer who is online throughout the whole
/// process and can keep this structure in memory can use the provided API
/// functions for a safe standard workflow. See
/// <https://blockstream.com/2019/02/18/musig-a-new-multisignature-standard/> for
/// more details about the risks associated with serializing or deserializing
/// this structure. There are no serialization and parsing functions (yet).
///
/// Note this deliberately does not implement `Copy` or `Clone`. After creation, the only
/// use of this nonce is [`Session::partial_sign`] API that takes ownership of this
/// and drops it. This is to prevent accidental misuse of this nonce.
///
/// A signer who is online throughout the whole process and can keep this
/// structure in memory can use the provided API functions for a safe standard
/// workflow.
///
/// Signers that pre-compute and save these nonces are not yet supported. Users
/// who want to serialize this must use unsafe rust to do so.
#[allow(missing_copy_implementations)]
#[derive(Debug)]
pub struct SecretNonce(ffi::MusigSecNonce);

impl CPtr for SecretNonce {
    type Target = ffi::MusigSecNonce;

    fn as_c_ptr(&self) -> *const Self::Target { self.as_ptr() }

    fn as_mut_c_ptr(&mut self) -> *mut Self::Target { self.as_mut_ptr() }
}

impl SecretNonce {
    /// Get a const pointer to the inner KeyAggCache
    pub fn as_ptr(&self) -> *const ffi::MusigSecNonce { &self.0 }

    /// Get a mut pointer to the inner KeyAggCache
    pub fn as_mut_ptr(&mut self) -> *mut ffi::MusigSecNonce { &mut self.0 }

    /// Function to return a copy of the internal array. See WARNING before using this function.
    ///
    /// # Warning:
    ///  This structure MUST NOT be copied or read or written to directly. A
    ///  signer who is online throughout the whole process and can keep this
    ///  structure in memory can use the provided API functions for a safe standard
    ///  workflow.
    ///
    ///  We repeat, copying this data structure can result in nonce reuse which will
    ///  leak the secret signing key.
    pub fn dangerous_into_bytes(self) -> [u8; secp256k1_sys::MUSIG_SECNONCE_LEN] {
        self.0.dangerous_into_bytes()
    }

    /// Function to create a new MusigKeyAggCoef from a 32 byte array. See WARNING before using this function.
    ///
    /// Refer to [`SecretNonce::dangerous_into_bytes`] for more details.
    pub fn dangerous_from_bytes(array: [u8; secp256k1_sys::MUSIG_SECNONCE_LEN]) -> Self {
        SecretNonce(ffi::MusigSecNonce::dangerous_from_bytes(array))
    }
}

/// An individual MuSig public nonce. Not to be confused with [`AggregatedNonce`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct PublicNonce(ffi::MusigPubNonce);

impl CPtr for PublicNonce {
    type Target = ffi::MusigPubNonce;

    fn as_c_ptr(&self) -> *const Self::Target { self.as_ptr() }

    fn as_mut_c_ptr(&mut self) -> *mut Self::Target { self.as_mut_ptr() }
}

impl PublicNonce {
    /// Serialize a PublicNonce
    pub fn serialize(&self) -> [u8; ffi::MUSIG_PUBNONCE_SERIALIZED_LEN] {
        let mut data = [0; ffi::MUSIG_PUBNONCE_SERIALIZED_LEN];
        unsafe {
            if ffi::secp256k1_musig_pubnonce_serialize(
                ffi::secp256k1_context_no_precomp,
                data.as_mut_ptr(),
                self.as_ptr(),
            ) == 0
            {
                // Only fails when the arguments are invalid which is not possible in safe rust
                unreachable!("Arguments must be valid and well-typed")
            } else {
                data
            }
        }
    }

    /// Deserialize a PublicNonce from a portable byte representation
    ///
    /// # Errors:
    ///
    /// - MalformedArg: If the [`PublicNonce`] is 132 bytes, but out of curve order
    pub fn from_byte_array(data: &[u8; ffi::MUSIG_PUBNONCE_SERIALIZED_LEN]) -> Result<Self, ParseError> {
        let mut pub_nonce = MaybeUninit::<ffi::MusigPubNonce>::uninit();
        unsafe {
            if ffi::secp256k1_musig_pubnonce_parse(
                ffi::secp256k1_context_no_precomp,
                pub_nonce.as_mut_ptr(),
                data.as_ptr(),
            ) == 0
            {
                Err(ParseError::MalformedArg)
            } else {
                Ok(PublicNonce(pub_nonce.assume_init()))
            }
        }
    }

    /// Get a const pointer to the inner PublicNonce
    pub fn as_ptr(&self) -> *const ffi::MusigPubNonce { &self.0 }

    /// Get a mut pointer to the inner PublicNonce
    pub fn as_mut_ptr(&mut self) -> *mut ffi::MusigPubNonce { &mut self.0 }
}

/// Musig aggregated nonce computed by aggregating all individual public nonces
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AggregatedNonce(ffi::MusigAggNonce);

impl CPtr for AggregatedNonce {
    type Target = ffi::MusigAggNonce;

    fn as_c_ptr(&self) -> *const Self::Target { self.as_ptr() }

    fn as_mut_c_ptr(&mut self) -> *mut Self::Target { self.as_mut_ptr() }
}

impl AggregatedNonce {
    /// Combine received public nonces into a single aggregated nonce
    ///
    /// This is useful to reduce the communication between signers, because instead
    /// of everyone sending nonces to everyone else, there can be one party
    /// receiving all nonces, combining the nonces with this function and then
    /// sending only the combined nonce back to the signers.
    ///
    /// Example:
    ///
    /// ```rust
    /// # # [cfg(any(test, feature = "rand-std"))] {
    /// # use secp256k1::rand::{thread_rng, RngCore};
    /// # use secp256k1::{KeyAggCache, Secp256k1, SecretKey, Keypair, PublicKey, SessionSecretRand, Message, AggregatedNonce};
    /// # let secp = Secp256k1::new();
    /// # let sk1 = SecretKey::new(&mut thread_rng());
    /// # let pub_key1 = PublicKey::from_secret_key(&secp, &sk1);
    /// # let sk2 = SecretKey::new(&mut thread_rng());
    /// # let pub_key2 = PublicKey::from_secret_key(&secp, &sk2);
    ///
    /// # let key_agg_cache = KeyAggCache::new(&secp, &[pub_key1, pub_key2]);
    /// // The session id must be sampled at random. Read documentation for more details.
    ///
    /// let msg = Message::from_digest_slice(b"Public Message we want to sign!!").unwrap();
    ///
    /// let session_secrand1 = SessionSecretRand::new(&mut thread_rng());
    /// let (_sec_nonce1, pub_nonce1) = key_agg_cache.nonce_gen(&secp, session_secrand1, pub_key1, msg, None)
    ///     .expect("non zero session id");
    ///
    /// // Signer two does the same: Possibly on a different device
    /// let session_secrand2 = SessionSecretRand::new(&mut thread_rng());
    /// let (_sec_nonce2, pub_nonce2) = key_agg_cache.nonce_gen(&secp, session_secrand2, pub_key2, msg, None)
    ///     .expect("non zero session id");
    ///
    /// let aggnonce = AggregatedNonce::new(&secp, &[pub_nonce1, pub_nonce2]);
    /// # }
    /// ```
    pub fn new<C: Signing>(secp: &Secp256k1<C>, nonces: &[&PublicNonce]) -> Self {

        if nonces.is_empty() {
            panic!("Cannot aggregate an empty slice of nonces");
        }

        let mut aggnonce = MaybeUninit::<ffi::MusigAggNonce>::uninit();

        unsafe {
            let pubnonces = core::slice::from_raw_parts(nonces.as_c_ptr() as *const *const ffi::MusigPubNonce, nonces.len());

            if ffi::secp256k1_musig_nonce_agg(
                secp.ctx().as_ptr(),
                aggnonce.as_mut_ptr(),
                pubnonces.as_ptr(),
                pubnonces.len(),
            ) == 0
            {
                // This can only crash if the individual nonces are invalid which is not possible is rust.
                // Note that even if aggregate nonce is point at infinity, the musig spec sets it as `G`
                unreachable!("Public key nonces are well-formed and valid in rust typesystem")
            } else {
                AggregatedNonce(aggnonce.assume_init())
            }
        }
    }

    /// Serialize a AggregatedNonce into a 66 bytes array.
    pub fn serialize(&self) -> [u8; ffi::MUSIG_AGGNONCE_SERIALIZED_LEN] {
        let mut data = [0; ffi::MUSIG_AGGNONCE_SERIALIZED_LEN];
        unsafe {
            if ffi::secp256k1_musig_aggnonce_serialize(
                ffi::secp256k1_context_no_precomp,
                data.as_mut_ptr(),
                self.as_ptr(),
            ) == 0
            {
                // Only fails when the arguments are invalid which is not possible in safe rust
                unreachable!("Arguments must be valid and well-typed")
            } else {
                data
            }
        }
    }

    /// Deserialize a AggregatedNonce from byte slice
    ///
    /// # Errors:
    ///
    /// - MalformedArg: If the byte slice is 66 bytes, but the [`AggregatedNonce`] is invalid
    pub fn from_byte_array(data: &[u8; ffi::MUSIG_AGGNONCE_SERIALIZED_LEN]) -> Result<Self, ParseError> {
        let mut aggnonce = MaybeUninit::<ffi::MusigAggNonce>::uninit();
        unsafe {
            if ffi::secp256k1_musig_aggnonce_parse(
                ffi::secp256k1_context_no_precomp,
                aggnonce.as_mut_ptr(),
                data.as_ptr(),
            ) == 0
            {
                Err(ParseError::MalformedArg)
            } else {
                Ok(AggregatedNonce(aggnonce.assume_init()))
            }
        }
    }

    /// Get a const pointer to the inner AggregatedNonce
    pub fn as_ptr(&self) -> *const ffi::MusigAggNonce { &self.0 }

    /// Get a mut pointer to the inner AggregatedNonce
    pub fn as_mut_ptr(&mut self) -> *mut ffi::MusigAggNonce { &mut self.0 }
}

/// The aggregated signature of all partial signatures.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AggregatedSignature([u8; 64]);

impl AggregatedSignature {
    /// Returns the aggregated signature [`schnorr::Signature`] assuming it is valid.
    ///
    /// The `partial_sig_agg` function cannot guarantee that the produced signature is valid because participants
    /// may send invalid signatures. In some applications this doesn't matter because the invalid message is simply
    /// dropped with no consequences. These can simply call this function to obtain the resulting signature. However
    /// in applications that require having valid signatures before continuing (e.g. presigned transactions in Bitcoin Lightning Network) this would be exploitable. Such applications MUST verify the resulting signature using the
    /// [`verify`](Self::verify) method.
    ///
    /// Note that while an alternative approach of verifying partial signatures is valid, verifying the aggregated
    /// signature is more performant. Thus it should be generally better to verify the signature using this function first
    /// and fall back to detection of violators if it fails.
    pub fn assume_valid(self) -> schnorr::Signature {
        schnorr::Signature::from_slice(&self.0)
            .expect("Invalid signature data")
    }

    /// Verify the aggregated signature against the aggregate public key and message
    /// before returning the signature.
    pub fn verify<C: Verification>(self, secp: &Secp256k1<C>, aggregate_key: &XOnlyPublicKey, message: &[u8]) -> Result<schnorr::Signature, Error> {
        let sig = schnorr::Signature::from_slice(&self.0)?;
        secp.verify_schnorr(&sig, message, aggregate_key)
            .map(|_| sig)
            .map_err(|_| Error::IncorrectSignature)
    }
}

/// A musig Siging session.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Session(ffi::MusigSession);

impl Session {
    /// Creates a new musig signing session.
    ///
    /// Takes the public nonces of all signers and computes a session that is
    /// required for signing and verification of partial signatures.
    ///
    /// # Returns:
    ///
    /// A [`Session`] that can be later used for signing.
    ///
    /// # Arguments:
    ///
    /// * `secp` : [`Secp256k1`] context object initialized for signing
    /// * `key_agg_cache`: [`KeyAggCache`] to be used for this session
    /// * `agg_nonce`: [`AggregatedNonce`], the aggregate nonce
    /// * `msg`: [`Message`] that will be signed later on.
    ///
    /// Example:
    ///
    /// ```rust
    /// # # [cfg(any(test, feature = "rand-std"))] {
    /// # use secp256k1::rand::{thread_rng, RngCore};
    /// # use secp256k1::{KeyAggCache, Secp256k1, SecretKey, Keypair, PublicKey, SessionSecretRand, Message, AggregatedNonce, Session};
    /// # let secp = Secp256k1::new();
    /// # let sk1 = SecretKey::new(&mut thread_rng());
    /// # let pub_key1 = PublicKey::from_secret_key(&secp, &sk1);
    /// # let sk2 = SecretKey::new(&mut thread_rng());
    /// # let pub_key2 = PublicKey::from_secret_key(&secp, &sk2);
    ///
    /// # let key_agg_cache = KeyAggCache::new(&secp, &[pub_key1, pub_key2]);
    /// // The session id must be sampled at random. Read documentation for more details.
    ///
    /// let msg = Message::from_digest_slice(b"Public Message we want to sign!!").unwrap();
    ///
    /// // Provide the current time for mis-use resistance
    /// let session_secrand1 = SessionSecretRand::new(&mut thread_rng());
    /// let extra_rand1 : Option<[u8; 32]> = None;
    /// let (_sec_nonce1, pub_nonce1) = key_agg_cache.nonce_gen(&secp, session_secrand1, pub_key1, msg, extra_rand1)
    ///     .expect("non zero session id");
    ///
    /// // Signer two does the same. Possibly on a different device
    /// let session_secrand2 = SessionSecretRand::new(&mut thread_rng());
    /// let extra_rand2 : Option<[u8; 32]> = None;
    /// let (_sec_nonce2, pub_nonce2) = key_agg_cache.nonce_gen(&secp, session_secrand2, pub_key2, msg, extra_rand2)
    ///     .expect("non zero session id");
    ///
    /// let aggnonce = AggregatedNonce::new(&secp, &[pub_nonce1, pub_nonce2]);
    ///
    /// let session = Session::new(
    ///     &secp,
    ///     &key_agg_cache,
    ///     aggnonce,
    ///     msg,
    /// );
    /// # }
    /// ```
    pub fn new<C: Signing>(
        secp: &Secp256k1<C>,
        key_agg_cache: &KeyAggCache,
        agg_nonce: AggregatedNonce,
        msg: Message,
    ) -> Self {
        let mut session = MaybeUninit::<ffi::MusigSession>::uninit();

        unsafe {
            if ffi::secp256k1_musig_nonce_process(
                secp.ctx().as_ptr(),
                session.as_mut_ptr(),
                agg_nonce.as_ptr(),
                msg.as_c_ptr(),
                key_agg_cache.as_ptr(),
            ) == 0
            {
                // Only fails on cryptographically unreachable codes or if the args are invalid.
                // None of which can occur in safe rust.
                unreachable!("Impossible to construct invalid arguments in safe rust.
                    Also reaches here if R1 + R2*b == point at infinity, but only occurs with 2^128 probability")
            } else {
                Session(session.assume_init())
            }
        }
    }

    /// Produces a partial signature for a given key pair and secret nonce.
    ///
    /// Remember that nonce reuse will immediately leak the secret key!
    ///
    /// # Returns:
    ///
    /// A [`PartialSignature`] that can be later be aggregated into a [`schnorr::Signature`]
    ///
    /// # Arguments:
    ///
    /// * `secp` : [`Secp256k1`] context object initialized for signing
    /// * `sec_nonce`: [`SecretNonce`] to be used for this session that has never
    ///   been used before. For mis-use resistance, this API takes a mutable reference
    ///   to `sec_nonce` and sets it to zero even if the partial signing fails.
    /// * `key_pair`: The [`Keypair`] to sign the message
    /// * `key_agg_cache`: [`KeyAggCache`] containing the aggregate pubkey used in
    ///   the creation of this session
    ///
    /// # Errors:
    ///
    /// - If the provided [`SecretNonce`] has already been used for signing
    ///
    pub fn partial_sign<C: Signing>(
        &self,
        secp: &Secp256k1<C>,
        mut secnonce: SecretNonce,
        keypair: &Keypair,
        key_agg_cache: &KeyAggCache,
    ) -> PartialSignature {
        unsafe {
            let mut partial_sig = MaybeUninit::<ffi::MusigPartialSignature>::uninit();

            let res = ffi::secp256k1_musig_partial_sign(
                secp.ctx().as_ptr(),
                partial_sig.as_mut_ptr(),
                secnonce.as_mut_ptr(),
                keypair.as_c_ptr(),
                key_agg_cache.as_ptr(),
                self.as_ptr(),
            );

            assert_eq!(res, 1);
            PartialSignature(partial_sig.assume_init())
        }
    }

    /// Checks that an individual partial signature verifies
    ///
    /// This function is essential when using protocols with adaptor signatures.
    /// However, it is not essential for regular MuSig's, in the sense that if any
    /// partial signatures does not verify, the full signature will also not verify, so the
    /// problem will be caught. But this function allows determining the specific party
    /// who produced an invalid signature, so that signing can be restarted without them.
    ///
    /// # Returns:
    ///
    /// true if the partial signature successfully verifies, otherwise returns false
    ///
    /// # Arguments:
    ///
    /// * `secp` : [`Secp256k1`] context object initialized for signing
    /// * `key_agg_cache`: [`KeyAggCache`] containing the aggregate pubkey used in
    ///   the creation of this session
    /// * `partial_sig`: [`PartialSignature`] sent by the signer associated with
    ///   the given `pub_nonce` and `pubkey`
    /// * `pub_nonce`: The [`PublicNonce`] of the signer associated with the `partial_sig`
    ///   and `pub_key`
    /// * `pub_key`: The [`XOnlyPublicKey`] of the signer associated with the given
    ///   `partial_sig` and `pub_nonce`
    ///
    /// Example:
    ///
    /// ```rust
    /// # # [cfg(any(test, feature = "rand-std"))] {
    /// # use secp256k1::rand::{thread_rng, RngCore};
    /// # use secp256k1::{KeyAggCache, Secp256k1, SecretKey, Keypair, PublicKey, SessionSecretRand, Message, AggregatedNonce, Session};
    /// # let secp = Secp256k1::new();
    /// # let sk1 = SecretKey::new(&mut thread_rng());
    /// # let pub_key1 = PublicKey::from_secret_key(&secp, &sk1);
    /// # let sk2 = SecretKey::new(&mut thread_rng());
    /// # let pub_key2 = PublicKey::from_secret_key(&secp, &sk2);
    ///
    /// # let key_agg_cache = KeyAggCache::new(&secp, &[pub_key1, pub_key2]);
    /// // The session id must be sampled at random. Read documentation for more details.
    ///
    /// let msg = Message::from_digest_slice(b"Public Message we want to sign!!").unwrap();
    ///
    /// // Provide the current time for mis-use resistance
    /// let session_secrand1 = SessionSecretRand::new(&mut thread_rng());
    /// let (mut sec_nonce1, pub_nonce1) = key_agg_cache.nonce_gen(&secp, session_secrand1, pub_key1, msg, None)
    ///     .expect("non zero session id");
    ///
    /// // Signer two does the same. Possibly on a different device
    /// let session_secrand2 = SessionSecretRand::new(&mut thread_rng());
    /// let (_sec_nonce2, pub_nonce2) = key_agg_cache.nonce_gen(&secp, session_secrand2, pub_key2, msg, None)
    ///     .expect("non zero session id");
    ///
    /// let aggnonce = AggregatedNonce::new(&secp, &[pub_nonce1, pub_nonce2]);
    ///
    /// let session = Session::new(
    ///     &secp,
    ///     &key_agg_cache,
    ///     aggnonce,
    ///     msg,
    /// );
    ///
    /// let keypair = Keypair::from_secret_key(&secp, &sk1);
    /// let partial_sig1 = session.partial_sign(
    ///     &secp,
    ///     sec_nonce1,
    ///     &keypair,
    ///     &key_agg_cache,
    /// ).unwrap();
    ///
    /// assert!(session.partial_verify(
    ///     &secp,
    ///     &key_agg_cache,
    ///     partial_sig1,
    ///     pub_nonce1,
    ///     pub_key1,
    /// ));
    /// # }
    /// ```
    pub fn partial_verify<C: Signing>(
        &self,
        secp: &Secp256k1<C>,
        key_agg_cache: &KeyAggCache,
        partial_sig: PartialSignature,
        pub_nonce: PublicNonce,
        pub_key: PublicKey,
    ) -> bool {
        let cx = secp.ctx().as_ptr();
        unsafe {
            ffi::secp256k1_musig_partial_sig_verify(
                cx,
                partial_sig.as_ptr(),
                pub_nonce.as_ptr(),
                pub_key.as_c_ptr(),
                key_agg_cache.as_ptr(),
                self.as_ptr(),
            ) == 1
        }
    }

    /// Aggregate partial signatures for this session into a single [`schnorr::Signature`]
    ///
    /// # Returns:
    ///
    /// A single [`schnorr::Signature`]. Note that this does *NOT* mean that the signature verifies with respect to the
    /// aggregate public key.
    ///
    /// # Arguments:
    ///
    /// * `partial_sigs`: Array of [`PartialSignature`] to be aggregated
    ///
    /// ```rust
    /// # # [cfg(any(test, feature = "rand-std"))] {
    /// # use secp256k1::rand::{thread_rng, RngCore};
    /// # use secp256k1::{KeyAggCache, Secp256k1, SecretKey, Keypair, PublicKey, SessionSecretRand, Message, AggregatedNonce, Session};
    /// # let secp = Secp256k1::new();
    /// # let sk1 = SecretKey::new(&mut thread_rng());
    /// # let pub_key1 = PublicKey::from_secret_key(&secp, &sk1);
    /// # let sk2 = SecretKey::new(&mut thread_rng());
    /// # let pub_key2 = PublicKey::from_secret_key(&secp, &sk2);
    ///
    /// let key_agg_cache = KeyAggCache::new(&secp, &[pub_key1, pub_key2]);
    /// // The session id must be sampled at random. Read documentation for more details.
    ///
    /// let msg = Message::from_digest_slice(b"Public Message we want to sign!!").unwrap();
    ///
    /// // Provide the current time for mis-use resistance
    /// let session_secrand1 = SessionSecretRand::new(&mut thread_rng());
    /// let (mut sec_nonce1, pub_nonce1) = key_agg_cache.nonce_gen(&secp, session_secrand1, pub_key1, msg, None)
    ///     .expect("non zero session id");
    ///
    /// // Signer two does the same. Possibly on a different device
    /// let session_secrand2 = SessionSecretRand::new(&mut thread_rng());
    /// let (mut sec_nonce2, pub_nonce2) = key_agg_cache.nonce_gen(&secp, session_secrand2, pub_key2, msg, None)
    ///     .expect("non zero session id");
    ///
    /// let aggnonce = AggregatedNonce::new(&secp, &[pub_nonce1, pub_nonce2]);
    ///
    /// let session = Session::new(
    ///     &secp,
    ///     &key_agg_cache,
    ///     aggnonce,
    ///     msg,
    /// );
    ///
    /// let partial_sig1 = session.partial_sign(
    ///     &secp,
    ///     sec_nonce1,
    ///     &Keypair::from_secret_key(&secp, &sk1),
    ///     &key_agg_cache,
    /// ).unwrap();
    ///
    /// // Other party creates the other partial signature
    /// let partial_sig2 = session.partial_sign(
    ///     &secp,
    ///     sec_nonce2,
    ///     &Keypair::from_secret_key(&secp, &sk2),
    ///     &key_agg_cache,
    /// ).unwrap();
    ///
    /// let partial_sigs = [partial_sign1, partial_sign2];
    /// let partial_sigs_ref: Vec<&PartialSignature> = partial_sigs.iter().collect();
    /// let partial_sigs_ref = partial_sigs_ref.as_slice();
    ///
    /// let aggregated_signature = session.partial_sig_agg(partial_sigs_ref);
    ///
    /// // Get the final schnorr signature
    /// assert!(aggregated_signature.verify(&secp, &agg_pk, &msg_bytes).is_ok());
    /// # }
    /// ```
    pub fn partial_sig_agg(&self, partial_sigs: &[&PartialSignature]) -> AggregatedSignature {

        if partial_sigs.is_empty() {
            panic!("Cannot aggregate an empty slice of partial signatures");
        }

        let mut sig = [0u8; 64];
        unsafe {

            let partial_sigs_ref = core::slice::from_raw_parts(partial_sigs.as_ptr() as *const *const ffi::MusigPartialSignature, partial_sigs.len());

            if ffi::secp256k1_musig_partial_sig_agg(
                ffi::secp256k1_context_no_precomp,
                sig.as_mut_ptr(),
                self.as_ptr(),
                partial_sigs_ref.as_ptr(),
                partial_sigs_ref.len(),
            ) == 0
            {
                // All arguments are well-typed partial signatures
                unreachable!("Impossible to construct invalid(not well-typed) partial signatures")
            } else {
                // Resulting signature must be well-typed. Does not mean that will be succeed verification
                AggregatedSignature(sig)
            }
        }
    }

    /// Get a const pointer to the inner Session
    pub fn as_ptr(&self) -> *const ffi::MusigSession { &self.0 }

    /// Get a mut pointer to the inner Session
    pub fn as_mut_ptr(&mut self) -> *mut ffi::MusigSession { &mut self.0 }
}
