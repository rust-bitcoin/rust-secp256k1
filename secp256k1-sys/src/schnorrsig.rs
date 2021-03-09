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

//! # FFI of the schnorrsig module

use ::types::*;
use ::extrakeys::{XOnlyPublicKey, KeyPair};
use Context;

///  Same as secp256k1_nonce function with the exception of accepting an
///  additional pubkey argument and not requiring an attempt argument. The pubkey
///  argument can protect signature schemes with key-prefixed challenge hash
///  inputs against reusing the nonce when signing with the wrong precomputed
///  pubkey.
pub type SchnorrNonceFn = Option<unsafe extern "C" fn(
    nonce32: *mut c_uchar,
    msg32: *const c_uchar,
    key32: *const c_uchar,
    xonly_pk32: *const c_uchar,
    algo16: *const c_uchar,
    data: *mut c_void,
) -> c_int>;

extern "C" {
    #[cfg_attr(not(rust_secp_no_symbol_renaming), link_name = "rustsecp256k1_v0_4_0_nonce_function_bip340")]
    pub static secp256k1_nonce_function_bip340: SchnorrNonceFn;
}

#[cfg(not(fuzzing))]
extern "C" {
    // Schnorr Signatures
    #[cfg_attr(not(rust_secp_no_symbol_renaming), link_name = "rustsecp256k1_v0_4_0_schnorrsig_sign")]
    pub fn secp256k1_schnorrsig_sign(
        cx: *const Context,
        sig: *mut c_uchar,
        msg32: *const c_uchar,
        keypair: *const KeyPair,
        noncefp: SchnorrNonceFn,
        noncedata: *const c_void
    ) -> c_int;

    #[cfg_attr(not(rust_secp_no_symbol_renaming), link_name = "rustsecp256k1_v0_4_0_schnorrsig_verify")]
    pub fn secp256k1_schnorrsig_verify(
        cx: *const Context,
        sig64: *const c_uchar,
        msg32: *const c_uchar,
        pubkey: *const XOnlyPublicKey,
    ) -> c_int;
}

#[cfg(fuzzing)]
mod fuzz_dummy {
    use super::*;
    use super::{secp256k1_xonly_pubkey_tweak_add, secp256k1_keypair_create};

    /// Verifies that sig is msg32||pk[32..]
    pub unsafe fn secp256k1_schnorrsig_verify(
        cx: *const Context,
        sig64: *const c_uchar,
        msg32: *const c_uchar,
        pubkey: *const XOnlyPublicKey,
    ) -> c_int {
        // Check context is built for verification
        let mut new_pk = PublicKey::new();
        let _ = secp256k1_xonly_pubkey_tweak_add(cx, &mut new_pk, pubkey, msg32);
        // Actually verify
        let sig_sl = slice::from_raw_parts(sig64 as *const u8, 64);
        let msg_sl = slice::from_raw_parts(msg32 as *const u8, 32);
        if &sig_sl[..32] == msg_sl && sig_sl[32..] == (*pubkey).0[..32] {
            1
        } else {
            0
        }
    }

    /// Sets sig to msg32||pk[..32]
    pub unsafe fn secp256k1_schnorrsig_sign(
        cx: *const Context,
        sig64: *mut c_uchar,
        msg32: *const c_uchar,
        keypair: *const KeyPair,
        noncefp: SchnorrNonceFn,
        noncedata: *const c_void
    ) -> c_int {
        // Check context is built for signing
        let mut new_kp = KeyPair::new();
        if secp256k1_keypair_create(cx, &mut new_kp, (*keypair).0.as_ptr()) != 1 {
            return 0;
        }
        assert_eq!(new_kp, *keypair);
        // Sign
        let sig_sl = slice::from_raw_parts_mut(sig64 as *mut u8, 64);
        let msg_sl = slice::from_raw_parts(msg32 as *const u8, 32);
        sig_sl[..32].copy_from_slice(msg_sl);
        sig_sl[32..].copy_from_slice(&new_kp.0[32..64]);
        1
    }
}

#[cfg(fuzzing)]
pub use self::fuzz_dummy::*;
