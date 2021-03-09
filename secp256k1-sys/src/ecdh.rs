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

//! # FFI of the ecdh module

use ::types::*;
use {Context, PublicKey};

/// Hash function to use to post-process an ECDH point to get
/// a shared secret.
pub type EcdhHashFn = Option<unsafe extern "C" fn(
    output: *mut c_uchar,
    x: *const c_uchar,
    y: *const c_uchar,
    data: *mut c_void,
) -> c_int>;

extern "C" {
    /// Default ECDH hash function
    #[cfg_attr(not(rust_secp_no_symbol_renaming), link_name = "rustsecp256k1_v0_4_0_ecdh_hash_function_default")]
    pub static secp256k1_ecdh_hash_function_default: EcdhHashFn;

    #[cfg(feature = "ecdh")]
    #[cfg_attr(not(rust_secp_no_symbol_renaming), link_name = "rustsecp256k1_v0_4_0_ecdh")]
    pub fn secp256k1_ecdh(
        cx: *const Context,
        output: *mut c_uchar,
        pubkey: *const PublicKey,
        seckey: *const c_uchar,
        hashfp: EcdhHashFn,
        data: *mut c_void,
    ) -> c_int;
}
