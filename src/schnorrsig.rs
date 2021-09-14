//! # schnorrsig
//! Support for Schnorr signatures.
//!

#[cfg(any(test, feature = "rand-std"))]
use rand::thread_rng;
#[cfg(any(test, feature = "rand"))]
use rand::{CryptoRng, Rng};

use super::{from_hex, Error};
use core::{fmt, ptr, str};
use ffi::{self, CPtr};
use {constants, Secp256k1};
use {Message, Signing};
use {XOnlyPubkey, KeyPair};

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
            _ => Err(Error::InvalidSignature),
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
        pubkey: &XOnlyPubkey,
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
    ) -> (KeyPair, XOnlyPubkey) {
        let sk = KeyPair::new(self, rng);
        let pubkey = XOnlyPubkey::from_keypair(self, &sk);
        (sk, pubkey)
    }
}

#[cfg(test)]
mod tests {
    use super::super::{constants, from_hex, All, Message, Secp256k1};
    use super::{KeyPair, XOnlyPubkey, Signature};
    use rand::{rngs::ThreadRng, thread_rng, RngCore};
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
            XOnlyPubkey::from_str("B33CC9EDC096D0A83416964BD3C6247B8FECD256E4EFA7870D2C854BDEB33390")
                .unwrap();

        assert!(secp.schnorrsig_verify(&sig, &msg, &pubkey).is_ok());
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
        let pk = XOnlyPubkey::from_slice(&PK_BYTES).unwrap();

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
}
