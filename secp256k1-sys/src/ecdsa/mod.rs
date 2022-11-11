//! The Elliptic Curve Digital Signature Algorithm (ECDSA).
//!

#[cfg(feature = "recovery")]
#[cfg_attr(docsrs, doc(cfg(feature = "recovery")))]
pub mod recovery;

use core::ptr;

use crate::types::*;
use crate::{impl_array_newtype, impl_raw_debug, secp256k1_context_no_precomp, SecretKey, PublicKey, Secp256k1};

/// Signs `msg` with `sk` using the ECDSA.
pub fn sign(ctx: &Secp256k1, msg: [u8; 32], sk: &SecretKey, noncedata: Option<&[u8; 32]>) -> Option<Signature> {
    unsafe {
        let mut sig = Signature::new();
        let noncedata_ptr = match noncedata {
            Some(arr) => arr.as_ptr() as *const _,
            None => ptr::null(),
        };

        let res = crate::secp256k1_ecdsa_sign(
            ctx.as_ptr(), &mut sig, msg.as_ptr(), sk.as_ptr(), crate::secp256k1_nonce_function_rfc6979, noncedata_ptr
        );
        if res == 1 { Some(sig) } else { None }
    }
}

/// Library-internal representation of a Secp256k1 signature
#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Signature([c_uchar; 64]);
impl_array_newtype!(Signature, c_uchar, 64);
impl_raw_debug!(Signature);

impl Signature {
    /// Checks that `self` is a valid ECDSA signature for `msg` using `pk`.
    pub fn is_valid(&self, ctx: &Secp256k1, msg: [u8; 32], pk: &PublicKey) -> bool {
        unsafe {
            crate::secp256k1_ecdsa_verify(ctx.as_ptr(), self, msg.as_ptr(), pk) == 0
        }
    }

    /// Converts a DER-encoded byte slice to a signature.
    pub fn from_der(data: &[u8]) -> Option<Signature> {
        unsafe {
            let mut sig = Signature::new();
            let res = crate::secp256k1_ecdsa_signature_parse_der(
                secp256k1_context_no_precomp,
                &mut sig,
                data.as_ptr(),
                data.len() as usize,
            );
            if res == 1 { Some(sig) } else { None }
        }
    }

    /// Converts a 64-byte compact-encoded byte slice to a signature
    pub fn from_compact(data: &[u8]) -> Option<Signature> {

        unsafe {
            let mut sig = Signature::new();
            let res = crate::secp256k1_ecdsa_signature_parse_compact(
                secp256k1_context_no_precomp,
                &mut sig,
                data.as_ptr(),
            );
            if res == 1 { Some(sig) } else { None }
        }
    }

    pub fn from_der_lax(data: &[u8]) -> Option<Signature> {
        unsafe {
            let mut sig = Signature::new();
            let res = crate::ecdsa_signature_parse_der_lax(
                secp256k1_context_no_precomp,
                &mut sig,
                data.as_ptr(),
                data.len() as usize,
            );
            if res == 1 { Some(sig) } else { None }
        }

    }

    pub fn normalize_s(&mut self) {
        unsafe {
            // Ignore return value, which indicates whether the signature was already normalized.
            crate::secp256k1_ecdsa_signature_normalize(
                secp256k1_context_no_precomp,
                self,
                self,
            );
        }
    }

    /// Serializes the signature in DER format.
    ///
    /// # Returns
    ///
    /// The serialization of this [`Signature`] in DER format as well as the length. `None` if
    /// serialization fails.
    pub fn serialize_der(&self) -> Option<([u8; 72], usize)> {
        let mut data = [0u8; 72];
        let mut len = 72;
        let res = unsafe {
            crate::secp256k1_ecdsa_signature_serialize_der(
                secp256k1_context_no_precomp,
                data.as_mut_ptr(),
                &mut len,
                self,
            )
        };
        if res == 1 { Some((data, len)) } else { None }
    }

    /// Serializes the signature in compact format
    pub fn serialize_compact(&self) -> Option<[u8; 64]> {
        let mut buf = [0u8; 64];
        let res = unsafe {
            crate::secp256k1_ecdsa_signature_serialize_compact(
                secp256k1_context_no_precomp,
                buf.as_mut_ptr(),
                self,
            )
        };
        if res == 1 { Some(buf) } else { None }
    }
}
