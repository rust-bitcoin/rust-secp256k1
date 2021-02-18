//! # schnorrsig
//! Support for Schnorr signatures.
//!

#[cfg(any(test, feature = "rand-std"))]
use rand::thread_rng;
#[cfg(any(test, feature = "rand"))]
use rand::{CryptoRng, Rng};

use super::Error::{InvalidPublicKey, InvalidSecretKey, InvalidSignature};
use super::{from_hex, Error};
use core::{fmt, ptr, str};
use ffi::{self, CPtr};
use {constants, Secp256k1};
use {Message, Signing, Verification};

/// Represents a Schnorr signature.
pub struct Signature([u8; constants::SCHNORRSIG_SIGNATURE_SIZE]);
impl_array_newtype!(Signature, u8, constants::SCHNORRSIG_SIGNATURE_SIZE);
impl_pretty_debug!(Signature);

#[cfg(feature = "serde")]
impl ::serde::Serialize for Signature {
    fn serialize<S: ::serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.collect_str(self)
        } else {
            s.serialize_bytes(&self[..])
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> ::serde::Deserialize<'de> for Signature {
    fn deserialize<D: ::serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        if d.is_human_readable() {
            d.deserialize_str(super::serde_util::FromStrVisitor::new(
                "a hex string representing 64 byte schnorr signature"
            ))
        } else {
            d.deserialize_bytes(super::serde_util::BytesVisitor::new(
                "raw 64 bytes schnorr signature",
                Signature::from_slice
            ))
        }
    }
}

impl fmt::LowerHex for Signature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for ch in &self.0[..] {
            write!(f, "{:02x}", ch)?;
        }
        Ok(())
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(self, f)
    }
}

impl str::FromStr for Signature {
    type Err = Error;
    fn from_str(s: &str) -> Result<Signature, Error> {
        let mut res = [0; constants::SCHNORRSIG_SIGNATURE_SIZE];
        match from_hex(s, &mut res) {
            Ok(constants::SCHNORRSIG_SIGNATURE_SIZE) => {
                Signature::from_slice(&res[0..constants::SCHNORRSIG_SIGNATURE_SIZE])
            }
            _ => Err(Error::InvalidSignature),
        }
    }
}

/// Opaque data structure that holds a keypair consisting of a secret and a public key.
#[derive(Copy, Clone, PartialEq, Eq, Debug, PartialOrd, Ord, Hash)]
pub struct KeyPair(ffi::KeyPair);

/// A Schnorr public key, used for verification of Schnorr signatures
#[derive(Copy, Clone, PartialEq, Eq, Debug, PartialOrd, Ord, Hash)]
pub struct PublicKey(ffi::XOnlyPublicKey);

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
        let mut res = [0; constants::SCHNORRSIG_PUBLIC_KEY_SIZE];
        match from_hex(s, &mut res) {
            Ok(constants::SCHNORRSIG_PUBLIC_KEY_SIZE) => {
                PublicKey::from_slice(&res[0..constants::SCHNORRSIG_PUBLIC_KEY_SIZE])
            }
            _ => Err(InvalidPublicKey),
        }
    }
}

impl Signature {
    /// Creates a Signature directly from a slice
    #[inline]
    pub fn from_slice(data: &[u8]) -> Result<Signature, Error> {
        match data.len() {
            constants::SCHNORRSIG_SIGNATURE_SIZE => {
                let mut ret = [0; constants::SCHNORRSIG_SIGNATURE_SIZE];
                ret[..].copy_from_slice(data);
                Ok(Signature(ret))
            }
            _ => Err(InvalidSignature),
        }
    }
}

impl KeyPair {
    /// Obtains a raw const pointer suitable for use with FFI functions
    #[inline]
    pub fn as_ptr(&self) -> *const ffi::KeyPair {
        &self.0
    }

    /// Obtains a raw mutable pointer suitable for use with FFI functions
    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut ffi::KeyPair {
        &mut self.0
    }

    /// Creates a Schnorr KeyPair directly from generic Secp256k1 secret key
    ///
    /// Panics if internal representation of the provided [`SecretKey`] does not
    /// holds correct secret key value obtained from Secp256k1 library
    /// previously
    #[inline]
    pub fn from_secret_key<C: Signing>(
        secp: &Secp256k1<C>,
        sk: ::key::SecretKey,
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

    /// Creates a Schnorr KeyPair directly from a secret key slice
    #[inline]
    pub fn from_seckey_slice<C: Signing>(
        secp: &Secp256k1<C>,
        data: &[u8],
    ) -> Result<KeyPair, Error> {
        if data.is_empty() || data.len() != constants::SECRET_KEY_SIZE {
            return Err(InvalidPublicKey);
        }

        unsafe {
            let mut kp = ffi::KeyPair::new();
            if ffi::secp256k1_keypair_create(secp.ctx, &mut kp, data.as_c_ptr()) == 1 {
                Ok(KeyPair(kp))
            } else {
                Err(InvalidSecretKey)
            }
        }
    }

    /// Creates a Schnorr KeyPair directly from a secret key string
    #[inline]
    pub fn from_seckey_str<C: Signing>(secp: &Secp256k1<C>, s: &str) -> Result<KeyPair, Error> {
        let mut res = [0; constants::SECRET_KEY_SIZE];
        match from_hex(s, &mut res) {
            Ok(constants::SECRET_KEY_SIZE) => {
                KeyPair::from_seckey_slice(secp, &res[0..constants::SECRET_KEY_SIZE])
            }
            _ => Err(InvalidPublicKey),
        }
    }

    /// Creates a new random secret key. Requires compilation with the "rand" feature.
    #[inline]
    #[cfg(any(test, feature = "rand"))]
    pub fn new<R: Rng + ?Sized, C: Signing>(secp: &Secp256k1<C>, rng: &mut R) -> KeyPair {
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

    /// Tweak a keypair by adding the given tweak to the secret key and updating the
    /// public key accordingly.
    /// Will return an error if the resulting key would be invalid or if
    /// the tweak was not a 32-byte length slice.
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

            if err == 1 {
                Ok(())
            } else {
                Err(Error::InvalidTweak)
            }
        }
    }
}

impl PublicKey {
    /// Obtains a raw const pointer suitable for use with FFI functions
    #[inline]
    pub fn as_ptr(&self) -> *const ffi::XOnlyPublicKey {
        &self.0
    }

    /// Obtains a raw mutable pointer suitable for use with FFI functions
    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut ffi::XOnlyPublicKey {
        &mut self.0
    }

    /// Creates a new Schnorr public key from a Schnorr key pair
    #[inline]
    pub fn from_keypair<C: Signing>(secp: &Secp256k1<C>, keypair: &KeyPair) -> PublicKey {
        let mut pk_parity = 0;
        unsafe {
            let mut xonly_pk = ffi::XOnlyPublicKey::new();
            let ret = ffi::secp256k1_keypair_xonly_pub(
                secp.ctx,
                &mut xonly_pk,
                &mut pk_parity,
                keypair.as_ptr(),
            );
            debug_assert_eq!(ret, 1);
            PublicKey(xonly_pk)
        }
    }

    /// Creates a Schnorr public key directly from a slice
    #[inline]
    pub fn from_slice(data: &[u8]) -> Result<PublicKey, Error> {
        if data.is_empty() || data.len() != constants::SCHNORRSIG_PUBLIC_KEY_SIZE {
            return Err(InvalidPublicKey);
        }

        unsafe {
            let mut pk = ffi::XOnlyPublicKey::new();
            if ffi::secp256k1_xonly_pubkey_parse(
                ffi::secp256k1_context_no_precomp,
                &mut pk,
                data.as_c_ptr(),
            ) == 1
            {
                Ok(PublicKey(pk))
            } else {
                Err(InvalidPublicKey)
            }
        }
    }

    #[inline]
    /// Serialize the key as a byte-encoded pair of values. In compressed form
    /// the y-coordinate is represented by only a single bit, as x determines
    /// it up to one bit.
    pub fn serialize(&self) -> [u8; constants::SCHNORRSIG_PUBLIC_KEY_SIZE] {
        let mut ret = [0; constants::SCHNORRSIG_PUBLIC_KEY_SIZE];

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

    /// Tweak an x-only PublicKey by adding the generator multiplied with the given tweak to it.
    ///
    /// Returns a boolean representing the parity of the tweaked key, which can be provided to 
    /// `tweak_add_check` which can be used to verify a tweak more efficiently than regenerating
    /// it and checking equality. Will return an error if the resulting key would be invalid or
    /// if the tweak was not a 32-byte length slice.
    pub fn tweak_add_assign<V: Verification>(
        &mut self,
        secp: &Secp256k1<V>,
        tweak: &[u8],
    ) -> Result<bool, Error> {
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
                Err(Error::InvalidPublicKey)
            } else {
                Ok(parity != 0)
            }
        }
    }

    /// Verify that a tweak produced by `tweak_add_assign` was computed correctly
    ///
    /// Should be called on the original untweaked key. Takes the tweaked key and
    /// output parity from `tweak_add_assign` as input.
    ///
    /// Currently this is not much more efficient than just recomputing the tweak
    /// and checking equality. However, in future this API will support batch
    /// verification, which is significantly faster, so it is wise to design
    /// protocols with this in mind.
    pub fn tweak_add_check<V: Verification>(
        &self,
        secp: &Secp256k1<V>,
        tweaked_key: &Self,
        tweaked_parity: bool,
        tweak: [u8; 32],
    ) -> bool {
        let tweaked_ser = tweaked_key.serialize();
        unsafe {
            let err = ffi::secp256k1_xonly_pubkey_tweak_add_check(
                secp.ctx,
                tweaked_ser.as_c_ptr(),
                if tweaked_parity { 1 } else { 0 },
                &self.0,
                tweak.as_c_ptr(),
            );

            err == 1
        }
    }
}

impl CPtr for PublicKey {
    type Target = ffi::XOnlyPublicKey;
    fn as_c_ptr(&self) -> *const Self::Target {
        self.as_ptr()
    }

    fn as_mut_c_ptr(&mut self) -> *mut Self::Target {
        self.as_mut_ptr()
    }
}

/// Creates a new Schnorr public key from a FFI x-only public key
impl From<ffi::XOnlyPublicKey> for PublicKey {
    #[inline]
    fn from(pk: ffi::XOnlyPublicKey) -> PublicKey {
        PublicKey(pk)
    }
}

impl From<::key::PublicKey> for PublicKey {
    fn from(src: ::key::PublicKey) -> PublicKey {
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
            PublicKey(pk)
        }
    }
}

#[cfg(feature = "serde")]
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
impl<'de> ::serde::Deserialize<'de> for PublicKey {
    fn deserialize<D: ::serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        if d.is_human_readable() {
            d.deserialize_str(super::serde_util::FromStrVisitor::new(
                "a hex string representing 32 byte schnorr public key"
            ))
        } else {
            d.deserialize_bytes(super::serde_util::BytesVisitor::new(
                "raw 32 bytes schnorr public key",
                PublicKey::from_slice
            ))
        }
    }
}

impl<C: Signing> Secp256k1<C> {
    fn schnorrsig_sign_helper(
        &self,
        msg: &Message,
        keypair: &KeyPair,
        nonce_data: *const ffi::types::c_void,
    ) -> Signature {
        unsafe {
            let mut sig = [0u8; constants::SCHNORRSIG_SIGNATURE_SIZE];
            assert_eq!(
                1,
                ffi::secp256k1_schnorrsig_sign(
                    self.ctx,
                    sig.as_mut_c_ptr(),
                    msg.as_c_ptr(),
                    keypair.as_ptr(),
                    ffi::secp256k1_nonce_function_bip340,
                    nonce_data
                )
            );

            Signature(sig)
        }
    }

    /// Create a schnorr signature internally using the ThreadRng random number
    /// generator to generate the auxiliary random data.
    /// Requires compilation with "rand-std" feature.
    #[cfg(any(test, feature = "rand-std"))]
    pub fn schnorrsig_sign(&self, msg: &Message, keypair: &KeyPair) -> Signature {
        let mut rng = thread_rng();
        self.schnorrsig_sign_with_rng(msg, keypair, &mut rng)
    }

    /// Create a schnorr signature without using any auxiliary random data.
    pub fn schnorrsig_sign_no_aux_rand(
        &self,
        msg: &Message,
        keypair: &KeyPair,
    ) -> Signature {
        self.schnorrsig_sign_helper(msg, keypair, ptr::null())
    }

    /// Create a Schnorr signature using the given auxiliary random data.
    pub fn schnorrsig_sign_with_aux_rand(
        &self,
        msg: &Message,
        keypair: &KeyPair,
        aux_rand: &[u8; 32],
    ) -> Signature {
        self.schnorrsig_sign_helper(
            msg,
            keypair,
            aux_rand.as_c_ptr() as *const ffi::types::c_void,
        )
    }

    /// Create a schnorr signature using the given random number generator to
    /// generate the auxiliary random data. Requires compilation with "rand"
    /// feature.
    #[cfg(any(test, feature = "rand"))]
    pub fn schnorrsig_sign_with_rng<R: Rng + CryptoRng>(
        &self,
        msg: &Message,
        keypair: &KeyPair,
        rng: &mut R,
    ) -> Signature {
        let mut aux = [0u8; 32];
        rng.fill_bytes(&mut aux);
        self.schnorrsig_sign_helper(msg, keypair, aux.as_c_ptr() as *const ffi::types::c_void)
    }

    /// Verify a Schnorr signature.
    pub fn schnorrsig_verify(
        &self,
        sig: &Signature,
        msg: &Message,
        pubkey: &PublicKey,
    ) -> Result<(), Error> {
        unsafe {
            let ret = ffi::secp256k1_schnorrsig_verify(
                self.ctx,
                sig.as_c_ptr(),
                msg.as_c_ptr(),
                pubkey.as_c_ptr(),
            );

            if ret == 1 {
                Ok(())
            } else {
                Err(Error::InvalidSignature)
            }
        }
    }

    /// Generates a random Schnorr KeyPair and its associated Schnorr PublicKey.
    /// Convenience function for `schnorrsig::KeyPair::new` and
    /// `schnorrsig::PublicKey::from_keypair`; call those functions directly for
    /// batch key generation. Requires a signing-capable context. Requires compilation
    /// with the "rand" feature.
    #[inline]
    #[cfg(any(test, feature = "rand"))]
    pub fn generate_schnorrsig_keypair<R: Rng + ?Sized>(
        &self,
        rng: &mut R,
    ) -> (KeyPair, PublicKey) {
        let sk = KeyPair::new(self, rng);
        let pubkey = PublicKey::from_keypair(self, &sk);
        (sk, pubkey)
    }
}

#[cfg(test)]
mod tests {
    use super::super::Error::InvalidPublicKey;
    use super::super::{constants, from_hex, All, Message, Secp256k1};
    use super::{KeyPair, PublicKey, Signature};
    use rand::{rngs::ThreadRng, thread_rng, Error, ErrorKind, RngCore};
    use rand_core::impls;
    use std::iter;
    use std::str::FromStr;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    macro_rules! hex_32 {
        ($hex:expr) => {{
            let mut result = [0; 32];
            from_hex($hex, &mut result).expect("valid hex string");
            result
        }};
    }

    fn test_schnorrsig_sign_helper(
        sign: fn(&Secp256k1<All>, &Message, &KeyPair, &mut ThreadRng) -> Signature,
    ) {
        let secp = Secp256k1::new();

        let mut rng = thread_rng();
        let (seckey, pubkey) = secp.generate_schnorrsig_keypair(&mut rng);
        let mut msg = [0; 32];

        for _ in 0..100 {
            rng.fill_bytes(&mut msg);
            let msg = Message::from_slice(&msg).unwrap();

            let sig = sign(&secp, &msg, &seckey, &mut rng);

            assert!(secp.schnorrsig_verify(&sig, &msg, &pubkey).is_ok());
        }
    }

    #[test]
    fn test_schnorrsig_sign_with_aux_rand_verify() {
        test_schnorrsig_sign_helper(|secp, msg, seckey, rng| {
            let mut aux_rand = [0; 32];
            rng.fill_bytes(&mut aux_rand);
            secp.schnorrsig_sign_with_aux_rand(msg, seckey, &aux_rand)
        })
    }

    #[test]
    fn test_schnorrsig_sign_with_rng_verify() {
        test_schnorrsig_sign_helper(|secp, msg, seckey, mut rng| {
            secp.schnorrsig_sign_with_rng(msg, seckey, &mut rng)
        })
    }

    #[test]
    fn test_schnorrsig_sign_verify() {
        test_schnorrsig_sign_helper(|secp, msg, seckey, _| {
            secp.schnorrsig_sign(msg, seckey)
        })
    }

    #[test]
    fn test_schnorrsig_sign_no_aux_rand_verify() {
        test_schnorrsig_sign_helper(|secp, msg, seckey, _| {
            secp.schnorrsig_sign_no_aux_rand(msg, seckey)
        })
    }

    #[test]
    #[cfg(not(fuzzing))]  // fixed sig vectors can't work with fuzz-sigs
    fn test_schnorrsig_sign() {
        let secp = Secp256k1::new();

        let hex_msg = hex_32!("E48441762FB75010B2AA31A512B62B4148AA3FB08EB0765D76B252559064A614");
        let msg = Message::from_slice(&hex_msg).unwrap();
        let sk = KeyPair::from_seckey_str(
            &secp,
            "688C77BC2D5AAFF5491CF309D4753B732135470D05B7B2CD21ADD0744FE97BEF",
        )
        .unwrap();
        let aux_rand: [u8; 32] =
            hex_32!("02CCE08E913F22A36C5648D6405A2C7C50106E7AA2F1649E381C7F09D16B80AB");
        let expected_sig = Signature::from_str("6470FD1303DDA4FDA717B9837153C24A6EAB377183FC438F939E0ED2B620E9EE5077C4A8B8DCA28963D772A94F5F0DDF598E1C47C137F91933274C7C3EDADCE8").unwrap();

        let sig = secp
            .schnorrsig_sign_with_aux_rand(&msg, &sk, &aux_rand);

        assert_eq!(expected_sig, sig);
    }

    #[test]
    #[cfg(not(fuzzing))]  // fixed sig vectors can't work with fuzz-sigs
    fn test_schnorrsig_verify() {
        let secp = Secp256k1::new();

        let hex_msg = hex_32!("E48441762FB75010B2AA31A512B62B4148AA3FB08EB0765D76B252559064A614");
        let msg = Message::from_slice(&hex_msg).unwrap();
        let sig = Signature::from_str("6470FD1303DDA4FDA717B9837153C24A6EAB377183FC438F939E0ED2B620E9EE5077C4A8B8DCA28963D772A94F5F0DDF598E1C47C137F91933274C7C3EDADCE8").unwrap();
        let pubkey =
            PublicKey::from_str("B33CC9EDC096D0A83416964BD3C6247B8FECD256E4EFA7870D2C854BDEB33390")
                .unwrap();

        assert!(secp.schnorrsig_verify(&sig, &msg, &pubkey).is_ok());
    }

    #[test]
    fn pubkey_from_slice() {
        assert_eq!(PublicKey::from_slice(&[]), Err(InvalidPublicKey));
        assert_eq!(PublicKey::from_slice(&[1, 2, 3]), Err(InvalidPublicKey));
        let pk = PublicKey::from_slice(&[
            0xB3, 0x3C, 0xC9, 0xED, 0xC0, 0x96, 0xD0, 0xA8, 0x34, 0x16, 0x96, 0x4B, 0xD3, 0xC6,
            0x24, 0x7B, 0x8F, 0xEC, 0xD2, 0x56, 0xE4, 0xEF, 0xA7, 0x87, 0x0D, 0x2C, 0x85, 0x4B,
            0xDE, 0xB3, 0x33, 0x90,
        ]);
        assert!(pk.is_ok());
    }

    #[test]
    fn pubkey_serialize_roundtrip() {
        let secp = Secp256k1::new();
        let (_, pubkey) = secp.generate_schnorrsig_keypair(&mut thread_rng());
        let ser = pubkey.serialize();
        let pubkey2 = PublicKey::from_slice(&ser).unwrap();
        assert_eq!(pubkey, pubkey2);
    }

    #[test]
    fn test_pubkey_from_bad_slice() {
        // Bad sizes
        assert_eq!(
            PublicKey::from_slice(&[0; constants::SCHNORRSIG_PUBLIC_KEY_SIZE - 1]),
            Err(InvalidPublicKey)
        );
        assert_eq!(
            PublicKey::from_slice(&[0; constants::SCHNORRSIG_PUBLIC_KEY_SIZE + 1]),
            Err(InvalidPublicKey)
        );

        // Bad parse
        assert_eq!(
            PublicKey::from_slice(&[0xff; constants::SCHNORRSIG_PUBLIC_KEY_SIZE]),
            Err(InvalidPublicKey)
        );
        // In fuzzing mode restrictions on public key validity are much more
        // relaxed, thus the invalid check below is expected to fail.
        #[cfg(not(fuzzing))]
        assert_eq!(
            PublicKey::from_slice(&[0x55; constants::SCHNORRSIG_PUBLIC_KEY_SIZE]),
            Err(InvalidPublicKey)
        );
        assert_eq!(PublicKey::from_slice(&[]), Err(InvalidPublicKey));
    }

    #[test]
    fn test_pubkey_display_output() {
        let secp = Secp256k1::new();
        static SK_BYTES: [u8; 32] = [
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
            0x06, 0x07, 0xff, 0xff, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x63, 0x63, 0x63, 0x63,
            0x63, 0x63, 0x63, 0x63,
        ];

        let s = Secp256k1::signing_only();
        let sk = KeyPair::from_seckey_slice(&secp, &SK_BYTES).expect("sk");

        // In fuzzing mode secret->public key derivation is different, so
        // hard-code the epected result.
        #[cfg(not(fuzzing))]
        let pk = PublicKey::from_keypair(&s, &sk);
        #[cfg(fuzzing)]
        let pk = PublicKey::from_slice(&[0x18, 0x84, 0x57, 0x81, 0xf6, 0x31, 0xc4, 0x8f, 0x1c, 0x97, 0x09, 0xe2, 0x30, 0x92, 0x06, 0x7d, 0x06, 0x83, 0x7f, 0x30, 0xaa, 0x0c, 0xd0, 0x54, 0x4a, 0xc8, 0x87, 0xfe, 0x91, 0xdd, 0xd1, 0x66]).expect("pk");

        assert_eq!(
            pk.to_string(),
            "18845781f631c48f1c9709e23092067d06837f30aa0cd0544ac887fe91ddd166"
        );
        assert_eq!(
            PublicKey::from_str("18845781f631c48f1c9709e23092067d06837f30aa0cd0544ac887fe91ddd166")
                .unwrap(),
            pk
        );

        assert!(PublicKey::from_str(
            "00000000000000000000000000000000000000000000000000000000000000000"
        )
        .is_err());
        assert!(PublicKey::from_str(
            "18845781f631c48f1c9709e23092067d06837f30aa0cd0544ac887fe91ddd16601"
        )
        .is_err());
        assert!(PublicKey::from_str(
            "18845781f631c48f1c9709e23092067d06837f30aa0cd0544ac887fe91ddd16"
        )
        .is_err());
        assert!(PublicKey::from_str(
            "18845781f631c48f1c9709e23092067d06837f30aa0cd0544ac887fe91ddd1"
        )
        .is_err());
        assert!(PublicKey::from_str(
            "xx18845781f631c48f1c9709e23092067d06837f30aa0cd0544ac887fe91ddd1"
        )
        .is_err());

        let long_str: String = iter::repeat('a').take(1024 * 1024).collect();
        assert!(PublicKey::from_str(&long_str).is_err());
    }

    #[test]
    // In fuzzing mode secret->public key derivation is different, so
    // this test will never correctly derive the static pubkey.
    #[cfg(not(fuzzing))]
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
        let (_, pubkey) = s.generate_schnorrsig_keypair(&mut DumbRng(0));
        assert_eq!(
            &pubkey.serialize()[..],
            &[
                124, 121, 49, 14, 253, 63, 197, 50, 39, 194, 107, 17, 193, 219, 108, 154, 126, 9,
                181, 248, 2, 12, 149, 233, 198, 71, 149, 134, 250, 184, 154, 229
            ][..]
        );
    }

    #[cfg(feature = "serde")]
    #[cfg(not(fuzzing))]  // fixed sig vectors can't work with fuzz-sigs
    #[test]
    fn test_serde() {
        use serde_test::{assert_tokens, Configure, Token};

        let s = Secp256k1::new();

        let msg = Message::from_slice(&[1; 32]).unwrap();
        let keypair = KeyPair::from_seckey_slice(&s, &[2; 32]).unwrap();
        let aux = [3; 32];
        let sig = s
            .schnorrsig_sign_with_aux_rand(&msg, &keypair, &aux);
        static SIG_BYTES: [u8; constants::SCHNORRSIG_SIGNATURE_SIZE] = [
            0x14, 0xd0, 0xbf, 0x1a, 0x89, 0x53, 0x50, 0x6f, 0xb4, 0x60, 0xf5, 0x8b, 0xe1, 0x41,
            0xaf, 0x76, 0x7f, 0xd1, 0x12, 0x53, 0x5f, 0xb3, 0x92, 0x2e, 0xf2, 0x17, 0x30, 0x8e,
            0x2c, 0x26, 0x70, 0x6f, 0x1e, 0xeb, 0x43, 0x2b, 0x3d, 0xba, 0x9a, 0x01, 0x08, 0x2f,
            0x9e, 0x4d, 0x4e, 0xf5, 0x67, 0x8a, 0xd0, 0xd9, 0xd5, 0x32, 0xc0, 0xdf, 0xa9, 0x07,
            0xb5, 0x68, 0x72, 0x2d, 0x0b, 0x01, 0x19, 0xba,
        ];
        static SIG_STR: &'static str = "\
            14d0bf1a8953506fb460f58be141af767fd112535fb3922ef217308e2c26706f1eeb432b3dba9a01082f9e4d4ef5678ad0d9d532c0dfa907b568722d0b0119ba\
        ";

        static PK_BYTES: [u8; 32] = [
            24, 132, 87, 129, 246, 49, 196, 143, 28, 151, 9, 226, 48, 146, 6, 125, 6, 131, 127,
            48, 170, 12, 208, 84, 74, 200, 135, 254, 145, 221, 209, 102
        ];
        static PK_STR: &'static str = "\
            18845781f631c48f1c9709e23092067d06837f30aa0cd0544ac887fe91ddd166\
        ";
        let pk = PublicKey::from_slice(&PK_BYTES).unwrap();

        assert_tokens(&sig.compact(), &[Token::BorrowedBytes(&SIG_BYTES[..])]);
        assert_tokens(&sig.compact(), &[Token::Bytes(&SIG_BYTES[..])]);
        assert_tokens(&sig.compact(), &[Token::ByteBuf(&SIG_BYTES[..])]);

        assert_tokens(&sig.readable(), &[Token::BorrowedStr(SIG_STR)]);
        assert_tokens(&sig.readable(), &[Token::Str(SIG_STR)]);
        assert_tokens(&sig.readable(), &[Token::String(SIG_STR)]);

        assert_tokens(&pk.compact(), &[Token::BorrowedBytes(&PK_BYTES[..])]);
        assert_tokens(&pk.compact(), &[Token::Bytes(&PK_BYTES[..])]);
        assert_tokens(&pk.compact(), &[Token::ByteBuf(&PK_BYTES[..])]);

        assert_tokens(&pk.readable(), &[Token::BorrowedStr(PK_STR)]);
        assert_tokens(&pk.readable(), &[Token::Str(PK_STR)]);
        assert_tokens(&pk.readable(), &[Token::String(PK_STR)]);
    }
    #[test]
    fn test_addition() {
        let s = Secp256k1::new();

        for _ in 0..10 {
            let mut tweak = [0u8; 32];
            thread_rng().fill_bytes(&mut tweak);
            let (mut kp, mut pk) = s.generate_schnorrsig_keypair(&mut thread_rng());
            let orig_pk = pk;
            kp.tweak_add_assign(&s, &tweak).expect("Tweak error");
            let parity = pk.tweak_add_assign(&s, &tweak).expect("Tweak error");
            assert_eq!(PublicKey::from_keypair(&s, &kp), pk);
            assert!(orig_pk.tweak_add_check(&s, &pk, parity, tweak));
        }
    }

    #[test]
    fn test_from_key_pubkey() {
        let kpk1 = ::key::PublicKey::from_str(
            "02e6642fd69bd211f93f7f1f36ca51a26a5290eb2dd1b0d8279a87bb0d480c8443",
        )
        .unwrap();
        let kpk2 = ::key::PublicKey::from_str(
            "0384526253c27c7aef56c7b71a5cd25bebb66dddda437826defc5b2568bde81f07",
        )
        .unwrap();

        let pk1 = PublicKey::from(kpk1);
        let pk2 = PublicKey::from(kpk2);

        assert_eq!(pk1.serialize()[..], kpk1.serialize()[1..]);
        assert_eq!(pk2.serialize()[..], kpk2.serialize()[1..]);
    }
}
