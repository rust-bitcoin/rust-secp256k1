// Bitcoin secp256k1-zkp bindings
// Written in 2015 by
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

//! # Schnorrsig
//! Support for Schnorr signatures
//!

use std::{ptr, fmt, error};

use {Secp256k1, Signing, Verification, Message};

use ffi;
use key;

/// An Schnorrsig error
#[derive(Copy, PartialEq, Eq, Clone, Debug)]
pub enum Error {
    /// Signature failed verification
    IncorrectSignature,
    /// Bad signature
    InvalidSignature,
}

// Passthrough Debug to Display, since errors should be user-visible
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        f.write_str(error::Error::description(self))
    }
}

impl error::Error for Error {
    fn cause(&self) -> Option<&error::Error> { None }

    fn description(&self) -> &str {
        match *self {
            Error::IncorrectSignature => "secp: signature failed verification",
            Error::InvalidSignature => "secp: malformed signature",
        }
    }
}

/// A Schnorr signature
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct SchnorrSignature(ffi::SchnorrSignature);
impl SchnorrSignature {
    #[inline]
    /// Converts a DER-encoded byte slice to a signature
    pub fn parse(data: &[u8]) -> Result<SchnorrSignature, Error> {
        let mut ret = unsafe { ffi::SchnorrSignature::blank() };

        unsafe {
            if ffi::secp256k1_schnorrsig_parse(
                ffi::secp256k1_context_no_precomp,
                &mut ret,
                data.as_ptr(),
            ) == 1
            {
                Ok(SchnorrSignature(ret))
            } else {
                Err(Error::InvalidSignature)
            }
        }
    }

    #[inline]
    /// Serializes the signature in compact format
    pub fn serialize(&self) -> [u8; 64] {
        let mut ret = [0; 64];
        unsafe {
            let err = ffi::secp256k1_schnorrsig_serialize(
                ffi::secp256k1_context_no_precomp,
                ret.as_mut_ptr(),
                self.as_ptr(),
            );
            debug_assert!(err == 1);
        }
        ret
    }

    /// Obtains a raw pointer suitable for use with FFI functions
    #[inline]
    pub fn as_ptr(&self) -> *const ffi::SchnorrSignature {
        &self.0 as *const _
    }
}

/// Creates a new signature from a FFI signature
impl From<ffi::SchnorrSignature> for SchnorrSignature {
    #[inline]
    fn from(sig: ffi::SchnorrSignature) -> SchnorrSignature {
        SchnorrSignature(sig)
    }
}

impl<C: Signing> Secp256k1<C> {
    /// Constructs a signature for `msg` using the secret key `sk` and BIP-schnorr nonce
    /// Requires a signing-capable context.
    pub fn schnorrsig_sign(&self, msg: &Message, sk: &key::SecretKey)
                -> SchnorrSignature {
        let mut ret = unsafe { ffi::SchnorrSignature::blank() };
        unsafe {
            // We can assume the return value because it's not possible to construct
            // an invalid signature from a valid `Message` and `SecretKey`
            assert_eq!(ffi::secp256k1_schnorrsig_sign(
                self.ctx,
                &mut ret,
                ptr::null_mut(),
                msg.as_ptr(),
                sk.as_ptr(),
                ffi::secp256k1_nonce_function_rfc6979,
                ptr::null_mut()), 1);
        }
        SchnorrSignature::from(ret)
    }
}

impl<C: Verification> Secp256k1<C> {
    /// Checks that `sig` is a valid Schnorr signature for `msg` using the public key
    /// `pubkey`. Returns `Ok(true)` on success.Requires a verify-capable context.
    #[inline]
    pub fn schnorrsig_verify(&self, msg: &Message, sig: &SchnorrSignature, pk: &key::PublicKey) -> Result<(), Error> {
        unsafe {
            if ffi::secp256k1_schnorrsig_verify(self.ctx, sig.as_ptr(), msg.as_ptr(), pk.as_ptr()) == 0 {
                Err(Error::IncorrectSignature)
            } else {
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use rand::{Rng, thread_rng};
    use {Secp256k1, Message};
    use super::{SchnorrSignature, Error};

    #[test]
    fn serialization_roundtrip() {
        let ser_sig = [
            0x78, 0x7A, 0x84, 0x8E, 0x71, 0x04, 0x3D, 0x28,
            0x0C, 0x50, 0x47, 0x0E, 0x8E, 0x15, 0x32, 0xB2,
            0xDD, 0x5D, 0x20, 0xEE, 0x91, 0x2A, 0x45, 0xDB,
            0xDD, 0x2B, 0xD1, 0xDF, 0xBF, 0x18, 0x7E, 0xF6,
            0x70, 0x31, 0xA9, 0x88, 0x31, 0x85, 0x9D, 0xC3,
            0x4D, 0xFF, 0xEE, 0xDD, 0xA8, 0x68, 0x31, 0x84,
            0x2C, 0xCD, 0x00, 0x79, 0xE1, 0xF9, 0x2A, 0xF1,
            0x77, 0xF7, 0xF2, 0x2C, 0xC1, 0xDC, 0xED, 0x05
        ];
        let sig = SchnorrSignature::parse(&ser_sig).unwrap();
        let ser_sig2 = SchnorrSignature::serialize(&sig);
        assert_eq!(ser_sig.to_vec(), ser_sig2.to_vec());

        // Parsing sig where first 32 bytes are not X-coordinate on the curve
        let ser_sig = [
            0x4A, 0x29, 0x8D, 0xAC, 0xAE, 0x57, 0x39, 0x5A,
            0x15, 0xD0, 0x79, 0x5D, 0xDB, 0xFD, 0x1D, 0xCB,
            0x56, 0x4D, 0xA8, 0x2B, 0x0F, 0x26, 0x9B, 0xC7,
            0x0A, 0x74, 0xF8, 0x22, 0x04, 0x29, 0xBA, 0x1D,
            0x1E, 0x51, 0xA2, 0x2C, 0xCE, 0xC3, 0x55, 0x99,
            0xB8, 0xF2, 0x66, 0x91, 0x22, 0x81, 0xF8, 0x36,
            0x5F, 0xFC, 0x2D, 0x03, 0x5A, 0x23, 0x04, 0x34,
            0xA1, 0xA6, 0x4D, 0xC5, 0x9F, 0x70, 0x13, 0xFD
        ];
        // Shouldn't return error right now
        SchnorrSignature::parse(&ser_sig).unwrap();
    }

    #[test]
    fn sign_and_verify() {
        let mut s = Secp256k1::new();
        s.randomize(&mut thread_rng());

        let mut msg = [0; 32];
        for _ in 0..100 {
            thread_rng().fill_bytes(&mut msg);
            let msg = Message::from_slice(&msg).unwrap();

            let (sk, pk) = s.generate_keypair(&mut thread_rng());
            let sig = s.schnorrsig_sign(&msg, &sk);
            assert_eq!(s.schnorrsig_verify(&msg, &sig, &pk), Ok(()));

            // Verifying signature under different public key should fail
            let (_, pk) = s.generate_keypair(&mut thread_rng());
            assert_eq!(s.schnorrsig_verify(&msg, &sig, &pk), Err(Error::IncorrectSignature));
         }
    }
}
