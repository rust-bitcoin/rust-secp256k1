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

//! # FFI bindings
//! Direct bindings to the underlying C library functions. These should
//! not be needed for most users.

// Coding conventions
#![deny(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
#![warn(missing_docs)]

#![cfg_attr(feature = "dev", allow(unstable_features))]
#![cfg_attr(feature = "dev", feature(plugin))]
#![cfg_attr(feature = "dev", plugin(clippy))]

extern crate libc;
extern crate rustc_serialize as serialize;
extern crate serde;
extern crate serde_json as json;

#[macro_use]
mod macros;

use std::mem;
use std::hash;

use libc::{c_int, c_uchar, c_uint, c_void, size_t};

/// Flag for context to enable no precomputation
pub const SECP256K1_CONTEXT_NONE: c_uint = (1 << 0) | 0;
/// Flag for context to enable verification precomputation
pub const SECP256K1_CONTEXT_VERIFY: c_uint = (1 << 0) | (1 << 8);
/// Flag for context to enable signing precomputation
pub const SECP256K1_CONTEXT_SIGN: c_uint = (1 << 0) | (1 << 9);
/// Flag for keys to indicate uncompressed serialization format
pub const SECP256K1_EC_UNCOMPRESSED: c_uint = (1 << 1) | 0;
/// Flag for keys to indicate compressed serialization format
pub const SECP256K1_EC_COMPRESSED: c_uint = (1 << 1) | (1 << 8);

/// A nonce generation function. Ordinary users of the library
/// never need to see this type; only if you need to control
/// nonce generation do you need to use it. I have deliberately
/// made this hard to do: you have to write your own wrapper
/// around the FFI functions to use it. And it's an unsafe type.
/// Nonces are generated deterministically by RFC6979 by
/// default; there should be no need to ever change this.
pub type secp256k1_nonce_function = unsafe extern "C" fn(nonce32: *mut c_uchar,
                                        msg32: *const c_uchar,
                                        key32: *const c_uchar,
                                        algo16: *const c_uchar,
                                        attempt: c_uint,
                                        data: *const c_void);


/// A Secp256k1 context, containing various precomputed values and such
/// needed to do elliptic curve computations. If you create one of these
/// with `secp256k1_context_create` you MUST destroy it with
/// `secp256k1_context_destroy`, or else you will have a memory leak.
#[derive(Clone, Debug)]
#[repr(C)] pub struct secp256k1_context(c_int);

/// Library-internal representation of a Secp256k1 public key
#[repr(C)]
pub struct secp256k1_pubkey([c_uchar; 64]);
impl_array_newtype!(secp256k1_pubkey, c_uchar, 64);
impl_raw_debug!(secp256k1_pubkey);

impl secp256k1_pubkey {
    /// Create a new (zeroed) public key usable for the FFI interface
    pub fn new() -> secp256k1_pubkey { secp256k1_pubkey([0; 64]) }
    /// Create a new (uninitialized) public key usable for the FFI interface
    pub unsafe fn blank() -> secp256k1_pubkey { mem::uninitialized() }
}

impl hash::Hash for secp256k1_pubkey {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        state.write(&self.0)
    }
}

/// Library-internal representation of a Secp256k1 signature
#[repr(C)]
pub struct secp256k1_ecdsa_signature([c_uchar; 64]);
impl_array_newtype!(secp256k1_ecdsa_signature, c_uchar, 64);
impl_raw_debug!(secp256k1_ecdsa_signature);

/// Library-internal representation of a Secp256k1 signature + recovery ID
#[repr(C)]
pub struct secp256k1_ecdsa_recoverable_signature([c_uchar; 65]);
impl_array_newtype!(secp256k1_ecdsa_recoverable_signature, c_uchar, 65);
impl_raw_debug!(secp256k1_ecdsa_recoverable_signature);

impl secp256k1_ecdsa_signature {
    /// Create a new (zeroed) signature usable for the FFI interface
    pub fn new() -> secp256k1_ecdsa_signature { secp256k1_ecdsa_signature([0; 64]) }
    /// Create a new (uninitialized) signature usable for the FFI interface
    pub unsafe fn blank() -> secp256k1_ecdsa_signature { mem::uninitialized() }
}

impl secp256k1_ecdsa_recoverable_signature {
    /// Create a new (zeroed) signature usable for the FFI interface
    pub fn new() -> secp256k1_ecdsa_recoverable_signature { secp256k1_ecdsa_recoverable_signature([0; 65]) }
    /// Create a new (uninitialized) signature usable for the FFI interface
    pub unsafe fn blank() -> secp256k1_ecdsa_recoverable_signature { mem::uninitialized() }
}

/// Library-internal representation of an ECDH shared secret
#[repr(C)]
pub struct secp256k1_shared_secret([c_uchar; 32]);
impl_array_newtype!(secp256k1_shared_secret, c_uchar, 32);
impl_raw_debug!(secp256k1_shared_secret);

impl secp256k1_shared_secret {
    /// Create a new (zeroed) signature usable for the FFI interface
    pub fn new() -> secp256k1_shared_secret { secp256k1_shared_secret([0; 32]) }
    /// Create a new (uninitialized) signature usable for the FFI interface
    pub unsafe fn blank() -> secp256k1_shared_secret { mem::uninitialized() }
}

extern "C" {
    pub static secp256k1_nonce_function_rfc6979: secp256k1_nonce_function;

    pub static secp256k1_nonce_function_default: secp256k1_nonce_function;

    // secp256k1_contexts
    pub fn secp256k1_context_create(flags: c_uint) -> *mut secp256k1_context;

    pub fn secp256k1_context_clone(cx: *mut secp256k1_context) -> *mut secp256k1_context;

    pub fn secp256k1_context_destroy(cx: *mut secp256k1_context);

    pub fn secp256k1_context_randomize(cx: *mut secp256k1_context,
                                       seed32: *const c_uchar)
                                       -> c_int;

    // TODO secp256k1_context_set_illegal_callback
    // TODO secp256k1_context_set_error_callback
    // (Actually, I don't really want these exposed; if either of these
    // are ever triggered it indicates a bug in rust-secp256k1, since
    // one goal is to use Rust's type system to eliminate all possible
    // bad inputs.)

    // Pubkeys
    pub fn secp256k1_ec_pubkey_parse(cx: *const secp256k1_context, pk: *mut secp256k1_pubkey,
                                     input: *const c_uchar, in_len: size_t)
                                     -> c_int;

    pub fn secp256k1_ec_pubkey_serialize(cx: *const secp256k1_context, output: *const c_uchar,
                                         out_len: *mut size_t, pk: *const secp256k1_pubkey
,                                        compressed: c_uint)
                                         -> c_int;

    // secp256k1_ecdsa_signatures
    pub fn secp256k1_ecdsa_signature_parse_der(cx: *const secp256k1_context, sig: *mut secp256k1_ecdsa_signature,
                                               input: *const c_uchar, in_len: size_t)
                                               -> c_int;

    pub fn secp256k1_ecdsa_signature_parse_der_lax(cx: *const secp256k1_context, sig: *mut secp256k1_ecdsa_signature,
                                                   input: *const c_uchar, in_len: size_t)
                                                   -> c_int;

    pub fn secp256k1_ecdsa_signature_serialize_der(cx: *const secp256k1_context, output: *const c_uchar,
                                                   out_len: *mut size_t, sig: *const secp256k1_ecdsa_signature)
                                                   -> c_int;

    pub fn secp256k1_ecdsa_recoverable_signature_parse_compact(cx: *const secp256k1_context, sig: *mut secp256k1_ecdsa_recoverable_signature,
                                                               input64: *const c_uchar, recid: c_int)
                                                               -> c_int;

    pub fn secp256k1_ecdsa_recoverable_signature_serialize_compact(cx: *const secp256k1_context, output64: *const c_uchar,
                                                                   recid: *mut c_int, sig: *const secp256k1_ecdsa_recoverable_signature)
                                                                   -> c_int;

    pub fn secp256k1_ecdsa_recoverable_signature_convert(cx: *const secp256k1_context, sig: *mut secp256k1_ecdsa_signature,
                                                         input: *const secp256k1_ecdsa_recoverable_signature) 
                                                         -> c_int;

    pub fn secp256k1_ecdsa_signature_normalize(cx: *const secp256k1_context, out_sig: *mut secp256k1_ecdsa_signature,
                                               in_sig: *const secp256k1_ecdsa_signature)
                                               -> c_int;

    // ECDSA
    pub fn secp256k1_ecdsa_verify(cx: *const secp256k1_context,
                                  sig: *const secp256k1_ecdsa_signature,
                                  msg32: *const c_uchar,
                                  pk: *const secp256k1_pubkey)
                                  -> c_int;

    pub fn secp256k1_ecdsa_sign(cx: *const secp256k1_context,
                                sig: *mut secp256k1_ecdsa_signature,
                                msg32: *const c_uchar,
                                sk: *const c_uchar,
                                noncefn: secp256k1_nonce_function,
                                noncedata: *const c_void)
                                -> c_int;

    pub fn secp256k1_ecdsa_sign_recoverable(cx: *const secp256k1_context,
                                            sig: *mut secp256k1_ecdsa_recoverable_signature,
                                            msg32: *const c_uchar,
                                            sk: *const c_uchar,
                                            noncefn: secp256k1_nonce_function,
                                            noncedata: *const c_void)
                                            -> c_int;

    pub fn secp256k1_ecdsa_recover(cx: *const secp256k1_context,
                                   pk: *mut secp256k1_pubkey,
                                   sig: *const secp256k1_ecdsa_recoverable_signature,
                                   msg32: *const c_uchar)
                                   -> c_int;

    // Schnorr
    pub fn secp256k1_schnorr_sign(cx: *const secp256k1_context,
                                  sig64: *mut c_uchar,
                                  msg32: *const c_uchar,
                                  sk: *const c_uchar,
                                  noncefn: secp256k1_nonce_function,
                                  noncedata: *const c_void)
                                  -> c_int;

    pub fn secp256k1_schnorr_verify(cx: *const secp256k1_context,
                                    sig64: *const c_uchar,
                                    msg32: *const c_uchar,
                                    pk: *const secp256k1_pubkey)
                                    -> c_int;

    pub fn secp256k1_schnorr_recover(cx: *const secp256k1_context,
                                     pk: *mut secp256k1_pubkey,
                                     sig64: *const c_uchar,
                                     msg32: *const c_uchar)
                                     -> c_int;

    // EC
    pub fn secp256k1_ec_seckey_verify(cx: *const secp256k1_context,
                                      sk: *const c_uchar) -> c_int;

    pub fn secp256k1_ec_pubkey_create(cx: *const secp256k1_context, pk: *mut secp256k1_pubkey,
                                      sk: *const c_uchar) -> c_int;

//TODO secp256k1_ec_privkey_export
//TODO secp256k1_ec_privkey_import

    pub fn secp256k1_ec_privkey_tweak_add(cx: *const secp256k1_context,
                                          sk: *mut c_uchar,
                                          tweak: *const c_uchar)
                                          -> c_int;

    pub fn secp256k1_ec_pubkey_tweak_add(cx: *const secp256k1_context,
                                         pk: *mut secp256k1_pubkey,
                                         tweak: *const c_uchar)
                                         -> c_int;

    pub fn secp256k1_ec_privkey_tweak_mul(cx: *const secp256k1_context,
                                          sk: *mut c_uchar,
                                          tweak: *const c_uchar)
                                          -> c_int;

    pub fn secp256k1_ec_pubkey_tweak_mul(cx: *const secp256k1_context,
                                         pk: *mut secp256k1_pubkey,
                                         tweak: *const c_uchar)
                                         -> c_int;

    pub fn secp256k1_ec_pubkey_combine(cx: *const secp256k1_context,
                                       out: *mut secp256k1_pubkey,
                                       ins: *const *const secp256k1_pubkey,
                                       n: c_int)
                                       -> c_int;

    pub fn secp256k1_ecdh(cx: *const secp256k1_context,
                          out: *mut secp256k1_shared_secret,
                          point: *const secp256k1_pubkey,
                          scalar: *const c_uchar)
                          -> c_int;
}
