// Bitcoin secp256k1 bindings
// Written in 2014 by
//   Dawid Ciężarkiewicz
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

//! # FFI of the recovery module

use core::{fmt, ptr};

use crate::types::*;
use crate::{impl_array_newtype, secp256k1_context_no_precomp, SecretKey, PublicKey, NonceFn, Secp256k1};
use crate::ecdsa::Signature;
use crate::context::Context;

/// TODO: Document this.
pub fn sign(ctx: &Secp256k1, msg: [u8; 32], sk: &SecretKey, noncedata: Option<&[u8; 32]>) -> Option<RecoverableSignature> {
    unsafe {
        let mut sig = RecoverableSignature::new();
        let noncedata_ptr = match noncedata {
            Some(arr) => arr.as_ptr() as *const _,
            None => ptr::null(),
        };

        let res = secp256k1_ecdsa_sign_recoverable(
            ctx.as_ptr(),
            &mut sig,
            msg.as_ptr(),
            sk.as_ptr(),
            crate::secp256k1_nonce_function_rfc6979,
            noncedata_ptr,
        );
        if res == 1 { Some(sig) } else { None }
    }
}

/// Determines the public key for which `sig` is a valid signature for
/// `msg`. Requires a verify-capable context.
pub fn recover(ctx: &Secp256k1, msg: [u8; 32], sig: &RecoverableSignature) -> Option<PublicKey> {
    unsafe {
        let mut pk = PublicKey::new();

        let res = secp256k1_ecdsa_recover(
            ctx.as_ptr(),
            &mut pk,
            sig,
            msg.as_ptr()
        );
        if res == 1 { Some(pk) } else { None }
    }
}

/// Library-internal representation of a Secp256k1 signature + recovery ID
#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RecoverableSignature([c_uchar; 65]);
impl_array_newtype!(RecoverableSignature, c_uchar, 65);

impl RecoverableSignature {
    /// Converts a compact-encoded byte slice to a signature. This
    /// representation is nonstandard and defined by the libsecp256k1 library.
    pub fn from_compact(data: &[u8; 64], recid: i32) -> Option<RecoverableSignature> {
        unsafe {
            let mut sig = RecoverableSignature::new();

            let res = secp256k1_ecdsa_recoverable_signature_parse_compact(
                secp256k1_context_no_precomp,
                &mut sig,
                data.as_ptr(),
                recid,
            );
            if res == 1 { Some(sig) } else { None }
        }
    }

    #[inline]
    /// Serializes the recoverable signature in compact format.
    pub fn serialize_compact(&self) -> Option<(i32, [u8; 64])> {
        let mut buf = [0u8; 64];
        let mut recid = 0i32;

        let res = unsafe {
            secp256k1_ecdsa_recoverable_signature_serialize_compact(
                secp256k1_context_no_precomp,
                buf.as_mut_ptr(),
                &mut recid,
                self,
            )
        };
        if res == 1 { Some((recid, buf)) } else { None }
    }

    /// Converts a recoverable signature to a non-recoverable one (this is needed
    /// for verification).
    #[inline]
    pub fn to_standard(&self) -> Option<Signature> {
        unsafe {
            let mut sig = Signature::new();
            let res = secp256k1_ecdsa_recoverable_signature_convert(
                secp256k1_context_no_precomp,
                &mut sig,
                self,
            );
            if res == 1 { Some(sig) } else { None }
        }
    }
}

impl fmt::Debug for RecoverableSignature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut ret = [0u8; 64];
        let mut recid = 0i32;

        unsafe {
            let err = secp256k1_ecdsa_recoverable_signature_serialize_compact(
                super::secp256k1_context_no_precomp,
                ret.as_mut_ptr(),
                &mut recid,
                self,
            );
            assert!(err == 1);
        }

        for byte in ret.iter() {
            write!(f, "{:02x}", byte)?;
        }
        write!(f, "{:02x}", recid as u8)?;

        Ok(())
    }
}

extern "C" {
    #[cfg_attr(not(rust_secp_no_symbol_renaming), link_name = "rustsecp256k1_v0_6_1_ecdsa_recoverable_signature_parse_compact")]
    pub fn secp256k1_ecdsa_recoverable_signature_parse_compact(cx: *const Context, sig: *mut RecoverableSignature,
                                                               input64: *const c_uchar, recid: c_int)
                                                               -> c_int;

    #[cfg_attr(not(rust_secp_no_symbol_renaming), link_name = "rustsecp256k1_v0_6_1_ecdsa_recoverable_signature_serialize_compact")]
    pub fn secp256k1_ecdsa_recoverable_signature_serialize_compact(cx: *const Context, output64: *mut c_uchar,
                                                                   recid: *mut c_int, sig: *const RecoverableSignature)
                                                                   -> c_int;

    #[cfg_attr(not(rust_secp_no_symbol_renaming), link_name = "rustsecp256k1_v0_6_1_ecdsa_recoverable_signature_convert")]
    pub fn secp256k1_ecdsa_recoverable_signature_convert(cx: *const Context, sig: *mut Signature,
                                                         input: *const RecoverableSignature)
                                                         -> c_int;
}

#[cfg(not(fuzzing))]
extern "C" {
    #[cfg_attr(not(rust_secp_no_symbol_renaming), link_name = "rustsecp256k1_v0_6_1_ecdsa_sign_recoverable")]
    pub fn secp256k1_ecdsa_sign_recoverable(cx: *const Context,
                                            sig: *mut RecoverableSignature,
                                            msg32: *const c_uchar,
                                            sk: *const c_uchar,
                                            noncefn: NonceFn,
                                            noncedata: *const c_void)
                                            -> c_int;

    #[cfg_attr(not(rust_secp_no_symbol_renaming), link_name = "rustsecp256k1_v0_6_1_ecdsa_recover")]
    pub fn secp256k1_ecdsa_recover(cx: *const Context,
                                   pk: *mut PublicKey,
                                   sig: *const RecoverableSignature,
                                   msg32: *const c_uchar)
                                   -> c_int;
}


#[cfg(fuzzing)]
mod fuzz_dummy {
    use core::slice;

    use crate::{secp256k1_ec_pubkey_create, secp256k1_ec_pubkey_parse, secp256k1_ec_pubkey_serialize, SECP256K1_SER_COMPRESSED};
    use super::*;

    /// Sets sig to msg32||full pk
    pub unsafe fn secp256k1_ecdsa_sign_recoverable(
        cx: *const Context,
        sig: *mut RecoverableSignature,
        msg32: *const c_uchar,
        sk: *const c_uchar,
        _noncefn: NonceFn,
        _noncedata: *const c_void,
    ) -> c_int {
        // Check context is built for signing (and compute pk)
        let mut new_pk = PublicKey::new();
        if secp256k1_ec_pubkey_create(cx, &mut new_pk, sk) != 1 {
            return 0;
        }
        // Sign
        let sig_sl = slice::from_raw_parts_mut(sig as *mut u8, 65);
        let msg_sl = slice::from_raw_parts(msg32 as *const u8, 32);
        sig_sl[..32].copy_from_slice(msg_sl);
        let mut out_len: size_t = 33;
        secp256k1_ec_pubkey_serialize(cx, sig_sl[32..].as_mut_ptr(), &mut out_len, &new_pk, SECP256K1_SER_COMPRESSED);
        // Encode the parity of the pubkey in the final byte as 0/1,
        // which is the same encoding (though the parity is computed
        // differently) as real recoverable signatures.
        sig_sl.swap(32, 64);
        sig_sl[64] -= 2;
        1
    }

    pub unsafe fn secp256k1_ecdsa_recover(
        cx: *const Context,
        pk: *mut PublicKey,
        sig: *const RecoverableSignature,
        msg32: *const c_uchar
    ) -> c_int {
        let sig_sl = slice::from_raw_parts(sig as *const u8, 65);
        let msg_sl = slice::from_raw_parts(msg32 as *const u8, 32);

        if sig_sl[64] >= 4 {
            return 0;
        }
        // Pull the original pk out of the siganture
        let mut pk_ser = [0u8; 33];
        pk_ser.copy_from_slice(&sig_sl[32..]);
        pk_ser.swap(0, 32);
        pk_ser[0] += 2;
        // Check that it parses (in a real sig, this would be the R value,
        // so it is actually required to be a valid point)
        if secp256k1_ec_pubkey_parse(cx, pk, pk_ser.as_ptr(), 33) == 0 {
            return 0;
        }
        // Munge it up so that a different message will give a different pk
        for i in 0..32 {
            pk_ser[i + 1] ^= sig_sl[i] ^ msg_sl[i];
        }
        // If any munging happened, this will fail parsing half the time, so
        // tweak-and-loop until we find a key that works.
        let mut idx = 0;
        while secp256k1_ec_pubkey_parse(cx, pk, pk_ser.as_ptr(), 33) == 0 {
            pk_ser[1 + idx / 8] ^= 1 << (idx % 8);
            idx += 1;
        }
        1
    }
}

#[cfg(fuzzing)]
pub use self::fuzz_dummy::*;
