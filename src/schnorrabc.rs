//! # schnorrabc
//! Support for ABC Schnorr signatures.
//!

#[cfg(any(test, feature = "rand-std"))]
use rand::thread_rng;
#[cfg(any(test, feature = "rand"))]
use rand::{CryptoRng, Rng};

use crate::schnorrsig::Signature;

use super::Error;
use core::ptr;
use ffi::{self, CPtr};
use {constants, Secp256k1};
use {Message, Signing};

impl<C: Signing> Secp256k1<C> {
    fn schnorrabc_sign_helper(
        &self,
        msg: &Message,
        seckey: &::key::SecretKey,
        nonce_data: *const ffi::types::c_void,
    ) -> Signature {
        unsafe {
            let mut sig = [0u8; constants::SCHNORRSIG_SIGNATURE_SIZE];
            assert_eq!(
                1,
                ffi::secp256k1_schnorr_sign(
                    self.ctx,
                    sig.as_mut_c_ptr(),
                    msg.as_c_ptr(),
                    seckey.as_c_ptr(),
                    ffi::secp256k1_nonce_function_default,
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
    pub fn schnorrabc_sign(&self, msg: &Message, seckey: &::key::SecretKey) -> Signature {
        let mut rng = thread_rng();
        self.schnorrabc_sign_with_rng(msg, seckey, &mut rng)
    }

    /// Create a schnorr signature without using any auxiliary random data.
    pub fn schnorrabc_sign_no_aux_rand(
        &self,
        msg: &Message,
        seckey: &::key::SecretKey,
    ) -> Signature {
        self.schnorrabc_sign_helper(msg, seckey, ptr::null())
    }

    /// Create a Schnorr signature using the given auxiliary random data.
    pub fn schnorrabc_sign_with_aux_rand(
        &self,
        msg: &Message,
        seckey: &::key::SecretKey,
        aux_rand: &[u8; 32],
    ) -> Signature {
        self.schnorrabc_sign_helper(
            msg,
            seckey,
            aux_rand.as_c_ptr() as *const ffi::types::c_void,
        )
    }

    /// Create a schnorr signature using the given random number generator to
    /// generate the auxiliary random data. Requires compilation with "rand"
    /// feature.
    #[cfg(any(test, feature = "rand"))]
    pub fn schnorrabc_sign_with_rng<R: Rng + CryptoRng>(
        &self,
        msg: &Message,
        seckey: &::key::SecretKey,
        rng: &mut R,
    ) -> Signature {
        let mut aux = [0u8; 32];
        rng.fill_bytes(&mut aux);
        self.schnorrabc_sign_helper(msg, seckey, aux.as_c_ptr() as *const ffi::types::c_void)
    }

    /// Verify a Schnorr signature.
    pub fn schnorrabc_verify(
        &self,
        sig: &Signature,
        msg: &Message,
        pubkey: &::key::PublicKey,
    ) -> Result<(), Error> {
        unsafe {
            let ret = ffi::secp256k1_schnorr_verify(
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
}

#[cfg(test)]
mod tests {
    use crate::PublicKey;

    use super::super::{from_hex, All, Message, Secp256k1};
    use super::Signature;
    use rand::{rngs::ThreadRng, thread_rng, RngCore};
    use std::str::FromStr;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;
    use ::key::SecretKey;

    macro_rules! hex_32 {
        ($hex:expr) => {{
            let mut result = [0; 32];
            from_hex($hex, &mut result).expect("valid hex string");
            result
        }};
    }

    fn test_schnorrabc_sign_helper(
        sign: fn(&Secp256k1<All>, &Message, &SecretKey, &mut ThreadRng) -> Signature,
    ) {
        let secp = Secp256k1::new();

        let mut rng = thread_rng();
        let seckey = SecretKey::new(&mut rng);
        let pubkey = PublicKey::from_secret_key(&secp, &seckey);
        let mut msg = [0; 32];

        for _ in 0..100 {
            rng.fill_bytes(&mut msg);
            let msg = Message::from_slice(&msg).unwrap();

            let sig = sign(&secp, &msg, &seckey, &mut rng);

            assert!(secp.schnorrabc_verify(&sig, &msg, &pubkey).is_ok());
        }
    }

    #[test]
    fn test_schnorrabc_sign_with_aux_rand_verify() {
        test_schnorrabc_sign_helper(|secp, msg, seckey, rng| {
            let mut aux_rand = [0; 32];
            rng.fill_bytes(&mut aux_rand);
            secp.schnorrabc_sign_with_aux_rand(msg, seckey, &aux_rand)
        })
    }

    #[test]
    fn test_schnorrabc_sign_with_rng_verify() {
        test_schnorrabc_sign_helper(|secp, msg, seckey, mut rng| {
            secp.schnorrabc_sign_with_rng(msg, seckey, &mut rng)
        })
    }

    #[test]
    fn test_schnorrabc_sign_verify() {
        test_schnorrabc_sign_helper(|secp, msg, seckey, _| secp.schnorrabc_sign(msg, seckey))
    }

    #[test]
    fn test_schnorrabc_sign_no_aux_rand_verify() {
        test_schnorrabc_sign_helper(|secp, msg, seckey, _| {
            secp.schnorrabc_sign_no_aux_rand(msg, seckey)
        })
    }

    #[test]
    #[cfg(not(fuzzing))] // fixed sig vectors can't work with fuzz-sigs
    fn test_schnorrabc_sign() {
        let secp = Secp256k1::new();

        let hex_msg = hex_32!("E48441762FB75010B2AA31A512B62B4148AA3FB08EB0765D76B252559064A614");
        let msg = Message::from_slice(&hex_msg).unwrap();
        let seckey: SecretKey = "688C77BC2D5AAFF5491CF309D4753B732135470D05B7B2CD21ADD0744FE97BEF"
            .parse()
            .unwrap();
        let aux_rand: [u8; 32] =
            hex_32!("02CCE08E913F22A36C5648D6405A2C7C50106E7AA2F1649E381C7F09D16B80AB");
        let expected_sig = Signature::from_str("EDA588A9DDA57D3003E7DC9FEE6637B963016D4E425202C47E\
                                                         A1F72408AC6EEDEF8E96112AEE39AA242AEB93D0D479FA0EAB\
                                                         AA8C5606E7B72346C701B71B1210").unwrap();

        let sig = secp.schnorrabc_sign_with_aux_rand(&msg, &seckey, &aux_rand);

        assert_eq!(expected_sig, sig);
    }

    #[test]
    #[cfg(not(fuzzing))] // fixed sig vectors can't work with fuzz-sigs
    fn test_schnorrabc_verify() {
        let secp = Secp256k1::new();

        let hex_msg = hex_32!("E48441762FB75010B2AA31A512B62B4148AA3FB08EB0765D76B252559064A614");
        let msg = Message::from_slice(&hex_msg).unwrap();
        let sig = Signature::from_str("EDA588A9DDA57D3003E7DC9FEE6637B963016D4E425202C47EA1F72408AC\
                                                6EEDEF8E96112AEE39AA242AEB93D0D479FA0EABAA8C5606E7B72346C701\
                                                B71B1210").unwrap();
        let pubkey: PublicKey =
            "03B33CC9EDC096D0A83416964BD3C6247B8FECD256E4EFA7870D2C854BDEB33390"
                .parse()
                .unwrap();

        assert!(secp.schnorrabc_verify(&sig, &msg, &pubkey).is_ok());
    }
}
