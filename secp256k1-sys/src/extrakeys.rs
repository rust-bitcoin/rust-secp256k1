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

//! # FFI of the extrakeys module

use ::types::*;
use {Context, PublicKey};

use core::hash;

#[repr(C)]
pub struct XOnlyPublicKey([c_uchar; 64]);
impl_array_newtype!(XOnlyPublicKey, c_uchar, 64);
impl_raw_debug!(XOnlyPublicKey);

impl XOnlyPublicKey {
    /// Creates an "uninitialized" FFI x-only public key which is zeroed out
    ///
    /// If you pass this to any FFI functions, except as an out-pointer,
    /// the result is likely to be an assertation failure and process
    /// termination.
    pub unsafe fn new() -> Self {
        Self::from_array_unchecked([0; 64])
    }

    /// Create a new x-only public key usable for the FFI interface from raw bytes
    ///
    /// Does not check the validity of the underlying representation. If it is
    /// invalid the result may be assertation failures (and process aborts) from
    /// the underlying library. You should not use this method except with data
    /// that you obtained from the FFI interface of the same version of this
    /// library.
    pub unsafe fn from_array_unchecked(data: [c_uchar; 64]) -> Self {
        XOnlyPublicKey(data)
    }

    /// Returns the underlying FFI opaque representation of the x-only public key
    ///
    /// You should not use this unless you really know what you are doing. It is
    /// essentially only useful for extending the FFI interface itself.
    pub fn underlying_bytes(self) -> [c_uchar; 64] {
        self.0
    }
}

impl hash::Hash for XOnlyPublicKey {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        state.write(&self.0)
    }
}

#[repr(C)]
pub struct KeyPair([c_uchar; 96]);
impl_array_newtype!(KeyPair, c_uchar, 96);
impl_raw_debug!(KeyPair);

impl KeyPair {
    /// Creates an "uninitialized" FFI keypair which is zeroed out
    ///
    /// If you pass this to any FFI functions, except as an out-pointer,
    /// the result is likely to be an assertation failure and process
    /// termination.
    pub unsafe fn new() -> Self {
        Self::from_array_unchecked([0; 96])
    }

    /// Create a new keypair usable for the FFI interface from raw bytes
    ///
    /// Does not check the validity of the underlying representation. If it is
    /// invalid the result may be assertation failures (and process aborts) from
    /// the underlying library. You should not use this method except with data
    /// that you obtained from the FFI interface of the same version of this
    /// library.
    pub unsafe fn from_array_unchecked(data: [c_uchar; 96]) -> Self {
        KeyPair(data)
    }

    /// Returns the underlying FFI opaque representation of the x-only public key
    ///
    /// You should not use this unless you really know what you are doing. It is
    /// essentially only useful for extending the FFI interface itself.
    pub fn underlying_bytes(self) -> [c_uchar; 96] {
        self.0
    }
}

impl hash::Hash for KeyPair {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        state.write(&self.0)
    }
}

extern "C" {
    #[cfg_attr(not(rust_secp_no_symbol_renaming), link_name = "rustsecp256k1_v0_4_0_keypair_create")]
    pub fn secp256k1_keypair_create(
        cx: *const Context,
        keypair: *mut KeyPair,
        seckey: *const c_uchar,
    ) -> c_int;

    #[cfg_attr(not(rust_secp_no_symbol_renaming), link_name = "rustsecp256k1_v0_4_0_xonly_pubkey_parse")]
    pub fn secp256k1_xonly_pubkey_parse(
        cx: *const Context,
        pubkey: *mut XOnlyPublicKey,
        input32: *const c_uchar,
    ) -> c_int;

    #[cfg_attr(not(rust_secp_no_symbol_renaming), link_name = "rustsecp256k1_v0_4_0_xonly_pubkey_serialize")]
    pub fn secp256k1_xonly_pubkey_serialize(
        cx: *const Context,
        output32: *mut c_uchar,
        pubkey: *const XOnlyPublicKey,
    ) -> c_int;

    #[cfg_attr(not(rust_secp_no_symbol_renaming), link_name = "rustsecp256k1_v0_4_0_xonly_pubkey_from_pubkey")]
    pub fn secp256k1_xonly_pubkey_from_pubkey(
        cx: *const Context,
        xonly_pubkey: *mut XOnlyPublicKey,
        pk_parity: *mut c_int,
        pubkey: *const PublicKey,
    ) -> c_int;

    #[cfg_attr(not(rust_secp_no_symbol_renaming), link_name = "rustsecp256k1_v0_4_0_xonly_pubkey_tweak_add")]
    pub fn secp256k1_xonly_pubkey_tweak_add(
        cx: *const Context,
        output_pubkey: *mut PublicKey,
        internal_pubkey: *const XOnlyPublicKey,
        tweak32: *const c_uchar,
    ) -> c_int;

    #[cfg_attr(not(rust_secp_no_symbol_renaming), link_name = "rustsecp256k1_v0_4_0_keypair_xonly_pub")]
    pub fn secp256k1_keypair_xonly_pub(
        cx: *const Context,
        pubkey: *mut XOnlyPublicKey,
        pk_parity: *mut c_int,
        keypair: *const KeyPair
    ) -> c_int;

    #[cfg_attr(not(rust_secp_no_symbol_renaming), link_name = "rustsecp256k1_v0_4_0_keypair_xonly_tweak_add")]
    pub fn secp256k1_keypair_xonly_tweak_add(
        cx: *const Context,
        keypair: *mut KeyPair,
        tweak32: *const c_uchar,
    ) -> c_int;

    #[cfg_attr(not(rust_secp_no_symbol_renaming), link_name = "rustsecp256k1_v0_4_0_xonly_pubkey_tweak_add_check")]
    pub fn secp256k1_xonly_pubkey_tweak_add_check(
        cx: *const Context,
        tweaked_pubkey32: *const c_uchar,
        tweaked_pubkey_parity: c_int,
        internal_pubkey: *const XOnlyPublicKey,
        tweak32: *const c_uchar,
    ) -> c_int;
}
