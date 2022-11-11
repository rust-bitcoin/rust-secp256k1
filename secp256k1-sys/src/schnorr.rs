//! The schnorr digital signature algorithm.
//!

use core::ptr;

use crate::types::*;
use crate::{impl_array_newtype, impl_raw_debug, KeyPair, XOnlyPublicKey, Secp256k1};

/// Signs `msg` with `sk` using the schnoor.
pub fn sign(ctx: &Secp256k1, msg: [u8; 32], kp: &KeyPair, noncedata: Option<&[u8; 32]>) -> Option<Signature> {
    unsafe {
        let mut sig = Signature::new();
        let noncedata_ptr = match noncedata {
            Some(arr) => arr.as_ptr() as *const _,
            None => ptr::null(),
        };

        let res = crate::secp256k1_schnorrsig_sign(
            ctx.as_ptr(),
            sig.as_mut_ptr(),
            msg.as_ptr(),
            kp,
            noncedata_ptr,
        );
        if res == 1 { Some(sig) } else { None }
    }
}

/// Library-internal representation of a schnorr signature.
#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Signature([c_uchar; 64]);
impl_array_newtype!(Signature, c_uchar, 64);
impl_raw_debug!(Signature);

impl Signature {
    /// Checks that `self` is a valid schnoor signature for `msg` using `pk`.
    pub fn is_valid(&self, ctx: &Secp256k1, msg: [u8; 32], pk: &XOnlyPublicKey) -> bool {
        let res = unsafe {
            crate::secp256k1_schnorrsig_verify(
                ctx.as_ptr(),
                self.as_ptr(),
                msg.as_ptr(),
                32,
                pk,
            )
        };
        res == 1
    }

    /// Constructs a [`Signature`] from `bytes`.
    pub fn from_bytes(bytes: [u8; 64]) -> Self {
        Signature(bytes)
    }
}
