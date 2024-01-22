// SPDX-License-Identifier: CC0-1.0

//! Provides a signing function that allows recovering the public key from the
//! signature.
//!

use core::ptr;

use self::super_ffi::CPtr;
use super::ffi as super_ffi;
use crate::ecdsa::Signature;
use crate::ffi::recovery as ffi;
use crate::{key, Error, Message, Secp256k1, Signing, Verification};

/// A tag used for recovering the public key from a compact signature.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Ord, PartialOrd)]
pub struct RecoveryId(i32);

/// An ECDSA signature with a recovery ID for pubkey recovery.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash, Ord, PartialOrd)]
pub struct RecoverableSignature(ffi::RecoverableSignature);

impl RecoveryId {
    #[inline]
    /// Allows library users to create valid recovery IDs from i32.
    pub fn from_i32(id: i32) -> Result<RecoveryId, Error> {
        match id {
            0..=3 => Ok(RecoveryId(id)),
            _ => Err(Error::InvalidRecoveryId),
        }
    }

    #[inline]
    /// Allows library users to convert recovery IDs to i32.
    pub fn to_i32(self) -> i32 { self.0 }
}

impl RecoverableSignature {
    #[inline]
    /// Converts a compact-encoded byte slice to a signature. This
    /// representation is nonstandard and defined by the libsecp256k1 library.
    pub fn from_compact(data: &[u8], recid: RecoveryId) -> Result<RecoverableSignature, Error> {
        if data.is_empty() {
            return Err(Error::InvalidSignature);
        }

        let mut ret = ffi::RecoverableSignature::new();

        unsafe {
            if data.len() != 64 {
                Err(Error::InvalidSignature)
            } else if ffi::secp256k1_ecdsa_recoverable_signature_parse_compact(
                super_ffi::secp256k1_context_no_precomp,
                &mut ret,
                data.as_c_ptr(),
                recid.0,
            ) == 1
            {
                Ok(RecoverableSignature(ret))
            } else {
                Err(Error::InvalidSignature)
            }
        }
    }

    /// Obtains a raw pointer suitable for use with FFI functions.
    #[inline]
    #[deprecated(since = "0.25.0", note = "Use Self::as_c_ptr if you need to access the FFI layer")]
    pub fn as_ptr(&self) -> *const ffi::RecoverableSignature { self.as_c_ptr() }

    /// Obtains a raw mutable pointer suitable for use with FFI functions.
    #[inline]
    #[deprecated(
        since = "0.25.0",
        note = "Use Self::as_mut_c_ptr if you need to access the FFI layer"
    )]
    pub fn as_mut_ptr(&mut self) -> *mut ffi::RecoverableSignature { self.as_mut_c_ptr() }

    #[inline]
    /// Serializes the recoverable signature in compact format.
    pub fn serialize_compact(&self) -> (RecoveryId, [u8; 64]) {
        let mut ret = [0u8; 64];
        let mut recid = 0i32;
        unsafe {
            let err = ffi::secp256k1_ecdsa_recoverable_signature_serialize_compact(
                super_ffi::secp256k1_context_no_precomp,
                ret.as_mut_c_ptr(),
                &mut recid,
                self.as_c_ptr(),
            );
            assert!(err == 1);
        }
        (RecoveryId(recid), ret)
    }

    /// Converts a recoverable signature to a non-recoverable one (this is needed
    /// for verification).
    #[inline]
    pub fn to_standard(&self) -> Signature {
        unsafe {
            let mut ret = super_ffi::Signature::new();
            let err = ffi::secp256k1_ecdsa_recoverable_signature_convert(
                super_ffi::secp256k1_context_no_precomp,
                &mut ret,
                self.as_c_ptr(),
            );
            assert!(err == 1);
            Signature(ret)
        }
    }

    /// Determines the public key for which this [`Signature`] is valid for `msg`. Requires a
    /// verify-capable context.
    #[inline]
    #[cfg(feature = "global-context")]
    pub fn recover(&self, msg: &Message) -> Result<key::PublicKey, Error> {
        crate::SECP256K1.recover_ecdsa(msg, self)
    }
}

impl CPtr for RecoverableSignature {
    type Target = ffi::RecoverableSignature;
    fn as_c_ptr(&self) -> *const Self::Target { &self.0 }

    fn as_mut_c_ptr(&mut self) -> *mut Self::Target { &mut self.0 }
}

/// Creates a new recoverable signature from a FFI one.
impl From<ffi::RecoverableSignature> for RecoverableSignature {
    #[inline]
    fn from(sig: ffi::RecoverableSignature) -> RecoverableSignature { RecoverableSignature(sig) }
}

impl<C: Signing> Secp256k1<C> {
    fn sign_ecdsa_recoverable_with_noncedata_pointer(
        &self,
        msg: &Message,
        sk: &key::SecretKey,
        noncedata_ptr: *const super_ffi::types::c_void,
    ) -> RecoverableSignature {
        let mut ret = ffi::RecoverableSignature::new();
        unsafe {
            // We can assume the return value because it's not possible to construct
            // an invalid signature from a valid `Message` and `SecretKey`
            assert_eq!(
                ffi::secp256k1_ecdsa_sign_recoverable(
                    self.ctx.as_ptr(),
                    &mut ret,
                    msg.as_c_ptr(),
                    sk.as_c_ptr(),
                    super_ffi::secp256k1_nonce_function_rfc6979,
                    noncedata_ptr
                ),
                1
            );
        }

        RecoverableSignature::from(ret)
    }

    /// Constructs a signature for `msg` using the secret key `sk` and RFC6979 nonce
    /// Requires a signing-capable context.
    pub fn sign_ecdsa_recoverable(
        &self,
        msg: &Message,
        sk: &key::SecretKey,
    ) -> RecoverableSignature {
        self.sign_ecdsa_recoverable_with_noncedata_pointer(msg, sk, ptr::null())
    }

    /// Constructs a signature for `msg` using the secret key `sk` and RFC6979 nonce
    /// and includes 32 bytes of noncedata in the nonce generation via inclusion in
    /// one of the hash operations during nonce generation. This is useful when multiple
    /// signatures are needed for the same Message and SecretKey while still using RFC6979.
    /// Requires a signing-capable context.
    pub fn sign_ecdsa_recoverable_with_noncedata(
        &self,
        msg: &Message,
        sk: &key::SecretKey,
        noncedata: &[u8; 32],
    ) -> RecoverableSignature {
        let noncedata_ptr = noncedata.as_ptr() as *const super_ffi::types::c_void;
        self.sign_ecdsa_recoverable_with_noncedata_pointer(msg, sk, noncedata_ptr)
    }
}

impl<C: Verification> Secp256k1<C> {
    /// Determines the public key for which `sig` is a valid signature for
    /// `msg`. Requires a verify-capable context.
    pub fn recover_ecdsa(
        &self,
        msg: &Message,
        sig: &RecoverableSignature,
    ) -> Result<key::PublicKey, Error> {
        unsafe {
            let mut pk = super_ffi::PublicKey::new();
            if ffi::secp256k1_ecdsa_recover(
                self.ctx.as_ptr(),
                &mut pk,
                sig.as_c_ptr(),
                msg.as_c_ptr(),
            ) != 1
            {
                return Err(Error::InvalidSignature);
            }
            Ok(key::PublicKey::from(pk))
        }
    }
}

#[cfg(test)]
#[allow(unused_imports)]
mod tests {
    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use super::{RecoverableSignature, RecoveryId};
    use crate::constants::ONE;
    use crate::{Error, Message, Secp256k1, SecretKey};

    #[test]
    #[cfg(feature = "rand-std")]
    fn capabilities() {
        let sign = Secp256k1::signing_only();
        let vrfy = Secp256k1::verification_only();
        let full = Secp256k1::new();

        let msg = crate::random_32_bytes(&mut rand::thread_rng());
        let msg = Message::from_digest_slice(&msg).unwrap();

        // Try key generation
        let (sk, pk) = full.generate_keypair(&mut rand::thread_rng());

        // Try signing
        assert_eq!(sign.sign_ecdsa_recoverable(&msg, &sk), full.sign_ecdsa_recoverable(&msg, &sk));
        let sigr = full.sign_ecdsa_recoverable(&msg, &sk);

        // Try pk recovery
        assert!(vrfy.recover_ecdsa(&msg, &sigr).is_ok());
        assert!(full.recover_ecdsa(&msg, &sigr).is_ok());

        assert_eq!(vrfy.recover_ecdsa(&msg, &sigr), full.recover_ecdsa(&msg, &sigr));
        assert_eq!(full.recover_ecdsa(&msg, &sigr), Ok(pk));
    }

    #[test]
    fn recid_sanity_check() {
        let one = RecoveryId(1);
        assert_eq!(one, one.clone());
    }

    #[test]
    #[cfg(not(secp256k1_fuzz))]  // fixed sig vectors can't work with fuzz-sigs
    #[cfg(feature = "rand-std")]
    #[rustfmt::skip]
    fn sign() {
        let mut s = Secp256k1::new();
        s.randomize(&mut rand::thread_rng());

        let sk = SecretKey::from_slice(&ONE).unwrap();
        let msg = Message::from_digest_slice(&ONE).unwrap();

        let sig = s.sign_ecdsa_recoverable(&msg, &sk);

        assert_eq!(Ok(sig), RecoverableSignature::from_compact(&[
            0x66, 0x73, 0xff, 0xad, 0x21, 0x47, 0x74, 0x1f,
            0x04, 0x77, 0x2b, 0x6f, 0x92, 0x1f, 0x0b, 0xa6,
            0xaf, 0x0c, 0x1e, 0x77, 0xfc, 0x43, 0x9e, 0x65,
            0xc3, 0x6d, 0xed, 0xf4, 0x09, 0x2e, 0x88, 0x98,
            0x4c, 0x1a, 0x97, 0x16, 0x52, 0xe0, 0xad, 0xa8,
            0x80, 0x12, 0x0e, 0xf8, 0x02, 0x5e, 0x70, 0x9f,
            0xff, 0x20, 0x80, 0xc4, 0xa3, 0x9a, 0xae, 0x06,
            0x8d, 0x12, 0xee, 0xd0, 0x09, 0xb6, 0x8c, 0x89],
            RecoveryId(1)))
    }

    #[test]
    #[cfg(not(secp256k1_fuzz))]  // fixed sig vectors can't work with fuzz-sigs
    #[cfg(feature = "rand-std")]
    #[rustfmt::skip]
    fn sign_with_noncedata() {
        let mut s = Secp256k1::new();
        s.randomize(&mut rand::thread_rng());

        let sk = SecretKey::from_slice(&ONE).unwrap();
        let msg = Message::from_digest_slice(&ONE).unwrap();
        let noncedata = [42u8; 32];

        let sig = s.sign_ecdsa_recoverable_with_noncedata(&msg, &sk, &noncedata);

        assert_eq!(Ok(sig), RecoverableSignature::from_compact(&[
            0xb5, 0x0b, 0xb6, 0x79, 0x5f, 0x31, 0x74, 0x8a,
            0x4d, 0x37, 0xc3, 0xa9, 0x7e, 0xbd, 0x06, 0xa2,
            0x2e, 0xa3, 0x37, 0x71, 0x04, 0x0f, 0x5c, 0x05,
            0xd6, 0xe2, 0xbb, 0x2d, 0x38, 0xc6, 0x22, 0x7c,
            0x34, 0x3b, 0x66, 0x59, 0xdb, 0x96, 0x99, 0x59,
            0xd9, 0xfd, 0xdb, 0x44, 0xbd, 0x0d, 0xd9, 0xb9,
            0xdd, 0x47, 0x66, 0x6a, 0xb5, 0x28, 0x71, 0x90,
            0x1d, 0x17, 0x61, 0xeb, 0x82, 0xec, 0x87, 0x22],
            RecoveryId(0)))
    }

    #[test]
    #[cfg(feature = "rand-std")]
    fn sign_and_verify_fail() {
        let mut s = Secp256k1::new();
        s.randomize(&mut rand::thread_rng());

        let msg = crate::random_32_bytes(&mut rand::thread_rng());
        let msg = Message::from_digest_slice(&msg).unwrap();

        let (sk, pk) = s.generate_keypair(&mut rand::thread_rng());

        let sigr = s.sign_ecdsa_recoverable(&msg, &sk);
        let sig = sigr.to_standard();

        let msg = crate::random_32_bytes(&mut rand::thread_rng());
        let msg = Message::from_digest_slice(&msg).unwrap();
        assert_eq!(s.verify_ecdsa(&msg, &sig, &pk), Err(Error::IncorrectSignature));

        let recovered_key = s.recover_ecdsa(&msg, &sigr).unwrap();
        assert!(recovered_key != pk);
    }

    #[test]
    #[cfg(feature = "rand-std")]
    fn sign_with_recovery() {
        let mut s = Secp256k1::new();
        s.randomize(&mut rand::thread_rng());

        let msg = crate::random_32_bytes(&mut rand::thread_rng());
        let msg = Message::from_digest_slice(&msg).unwrap();

        let (sk, pk) = s.generate_keypair(&mut rand::thread_rng());

        let sig = s.sign_ecdsa_recoverable(&msg, &sk);

        assert_eq!(s.recover_ecdsa(&msg, &sig), Ok(pk));
    }

    #[test]
    #[cfg(feature = "rand-std")]
    fn sign_with_recovery_and_noncedata() {
        let mut s = Secp256k1::new();
        s.randomize(&mut rand::thread_rng());

        let msg = crate::random_32_bytes(&mut rand::thread_rng());
        let msg = Message::from_digest_slice(&msg).unwrap();

        let noncedata = [42u8; 32];

        let (sk, pk) = s.generate_keypair(&mut rand::thread_rng());

        let sig = s.sign_ecdsa_recoverable_with_noncedata(&msg, &sk, &noncedata);

        assert_eq!(s.recover_ecdsa(&msg, &sig), Ok(pk));
    }

    #[test]
    #[cfg(feature = "rand-std")]
    fn bad_recovery() {
        let mut s = Secp256k1::new();
        s.randomize(&mut rand::thread_rng());

        let msg = Message::from_digest_slice(&[0x55; 32]).unwrap();

        // Zero is not a valid sig
        let sig = RecoverableSignature::from_compact(&[0; 64], RecoveryId(0)).unwrap();
        assert_eq!(s.recover_ecdsa(&msg, &sig), Err(Error::InvalidSignature));
        // ...but 111..111 is
        let sig = RecoverableSignature::from_compact(&[1; 64], RecoveryId(0)).unwrap();
        assert!(s.recover_ecdsa(&msg, &sig).is_ok());
    }

    #[test]
    fn test_debug_output() {
        #[rustfmt::skip]
        let sig = RecoverableSignature::from_compact(&[
            0x66, 0x73, 0xff, 0xad, 0x21, 0x47, 0x74, 0x1f,
            0x04, 0x77, 0x2b, 0x6f, 0x92, 0x1f, 0x0b, 0xa6,
            0xaf, 0x0c, 0x1e, 0x77, 0xfc, 0x43, 0x9e, 0x65,
            0xc3, 0x6d, 0xed, 0xf4, 0x09, 0x2e, 0x88, 0x98,
            0x4c, 0x1a, 0x97, 0x16, 0x52, 0xe0, 0xad, 0xa8,
            0x80, 0x12, 0x0e, 0xf8, 0x02, 0x5e, 0x70, 0x9f,
            0xff, 0x20, 0x80, 0xc4, 0xa3, 0x9a, 0xae, 0x06,
            0x8d, 0x12, 0xee, 0xd0, 0x09, 0xb6, 0x8c, 0x89],
            RecoveryId(1)).unwrap();
        assert_eq!(&format!("{:?}", sig), "RecoverableSignature(6673ffad2147741f04772b6f921f0ba6af0c1e77fc439e65c36dedf4092e88984c1a971652e0ada880120ef8025e709fff2080c4a39aae068d12eed009b68c8901)");
    }

    #[test]
    fn test_recov_sig_serialize_compact() {
        let recid_in = RecoveryId(1);
        #[rustfmt::skip]
        let bytes_in = &[
            0x66, 0x73, 0xff, 0xad, 0x21, 0x47, 0x74, 0x1f,
            0x04, 0x77, 0x2b, 0x6f, 0x92, 0x1f, 0x0b, 0xa6,
            0xaf, 0x0c, 0x1e, 0x77, 0xfc, 0x43, 0x9e, 0x65,
            0xc3, 0x6d, 0xed, 0xf4, 0x09, 0x2e, 0x88, 0x98,
            0x4c, 0x1a, 0x97, 0x16, 0x52, 0xe0, 0xad, 0xa8,
            0x80, 0x12, 0x0e, 0xf8, 0x02, 0x5e, 0x70, 0x9f,
            0xff, 0x20, 0x80, 0xc4, 0xa3, 0x9a, 0xae, 0x06,
            0x8d, 0x12, 0xee, 0xd0, 0x09, 0xb6, 0x8c, 0x89];
        let sig = RecoverableSignature::from_compact(bytes_in, recid_in).unwrap();
        let (recid_out, bytes_out) = sig.serialize_compact();
        assert_eq!(recid_in, recid_out);
        assert_eq!(&bytes_in[..], &bytes_out[..]);
    }

    #[test]
    fn test_recov_id_conversion_between_i32() {
        assert!(RecoveryId::from_i32(-1).is_err());
        assert!(RecoveryId::from_i32(0).is_ok());
        assert!(RecoveryId::from_i32(1).is_ok());
        assert!(RecoveryId::from_i32(2).is_ok());
        assert!(RecoveryId::from_i32(3).is_ok());
        assert!(RecoveryId::from_i32(4).is_err());
        let id0 = RecoveryId::from_i32(0).unwrap();
        assert_eq!(id0.to_i32(), 0);
        let id1 = RecoveryId(1);
        assert_eq!(id1.to_i32(), 1);
    }
}

#[cfg(bench)]
#[cfg(feature = "rand-std")] // Currently only a single bench that requires "rand-std".
mod benches {
    use test::{black_box, Bencher};

    use super::{Message, Secp256k1};

    #[bench]
    pub fn bench_recover(bh: &mut Bencher) {
        let s = Secp256k1::new();
        let msg = crate::random_32_bytes(&mut rand::thread_rng());
        let msg = Message::from_digest_slice(&msg).unwrap();
        let (sk, _) = s.generate_keypair(&mut rand::thread_rng());
        let sig = s.sign_ecdsa_recoverable(&msg, &sk);

        bh.iter(|| {
            let res = s.recover_ecdsa(&msg, &sig).unwrap();
            black_box(res);
        });
    }
}
