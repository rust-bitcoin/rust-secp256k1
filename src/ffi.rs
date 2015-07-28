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

//! FFI bindings
use std::mem;
use libc::{c_int, c_uchar, c_uint, c_void};

pub const SECP256K1_START_VERIFY: c_uint = 0x1;
pub const SECP256K1_START_SIGN: c_uint = 0x2;

/// A nonce generation function. Ordinary users of the library
/// never need to see this type; only if you need to control
/// nonce generation do you need to use it. I have deliberately
/// made this hard to do: you have to write your own wrapper
/// around the FFI functions to use it. And it's an unsafe type.
/// Nonces are generated deterministically by RFC6979 by
/// default; there should be no need to ever change this.
pub type NonceFn = unsafe extern "C" fn(nonce32: *mut c_uchar,
                                        msg32: *const c_uchar,
                                        key32: *const c_uchar,
                                        algo16: *const c_uchar,
                                        attempt: c_uint,
                                        data: *const c_void);

#[repr(C)] struct ContextInner;

/// A Secp256k1 context, containing various precomputed values and such
/// needed to do elliptic curve computations. If you create one of these
/// with `secp256k1_context_create` you MUST destroy it with
/// `secp256k1_context_destroy`, or else you will have a memory leak.
/// Furthermore, you MUST NOT use this object after destroying it; it is
/// `Copy` so the compiler will not help you to avoid this. There is no
/// need for ordinary users of this library to ever use this type directly.
#[repr(C)]
#[allow(raw_pointer_derive)]
#[derive(Copy, Clone, Debug)]
pub struct Context(*mut ContextInner);

/// Library-internal representation of a Secp256k1 public key
#[repr(C)]
pub struct PublicKey([c_uchar; 64]);
impl_array_newtype!(PublicKey, c_uchar, 64);
impl_raw_debug!(PublicKey);

impl PublicKey {
    /// Create a new (zeroed) public key usable for the FFI interface
    pub fn new() -> PublicKey { PublicKey([0; 64]) }
    /// Create a new (uninitialized) public key usable for the FFI interface
    pub unsafe fn blank() -> PublicKey { mem::uninitialized() }
}

/// Library-internal representation of a Secp256k1 signature
#[repr(C)]
#[allow(raw_pointer_derive)]
pub struct Signature([c_uchar; 65]);
impl_array_newtype!(Signature, c_uchar, 65);
impl_raw_debug!(Signature);

impl Signature {
    /// Create a new (zeroed) public key usable for the FFI interface
    pub fn new() -> Signature { Signature([0; 65]) }
    /// Create a new (uninitialized) public key usable for the FFI interface
    pub unsafe fn blank() -> Signature { mem::uninitialized() }
}

unsafe impl Send for Context {}
unsafe impl Sync for Context {}

#[link(name = "secp256k1")]
extern "C" {
    pub static secp256k1_nonce_function_rfc6979: NonceFn;

    pub static secp256k1_nonce_function_default: NonceFn;

    // Contexts
    pub fn secp256k1_context_create(flags: c_uint) -> Context;

    pub fn secp256k1_context_clone(cx: Context) -> Context;

    pub fn secp256k1_context_destroy(cx: Context);

    pub fn secp256k1_context_randomize(cx: Context,
                                       seed32: *const c_uchar)
                                       -> c_int;

    // Pubkeys
    pub fn secp256k1_ec_pubkey_parse(cx: Context, pk: *mut PublicKey,
                                     input: *const c_uchar, in_len: c_int)
                                     -> c_int;

    pub fn secp256k1_ec_pubkey_serialize(cx: Context, output: *const c_uchar,
                                         out_len: *mut c_int, pk: *const PublicKey
,                                        compressed: c_int)
                                         -> c_int;

    // Signatures
    pub fn secp256k1_ecdsa_signature_parse_der(cx: Context, sig: *mut Signature,
                                               input: *const c_uchar, in_len: c_int)
                                               -> c_int;

    pub fn secp256k1_ecdsa_signature_parse_compact(cx: Context, sig: *mut Signature,
                                                   input64: *const c_uchar, recid: c_int)
                                                   -> c_int;

    pub fn secp256k1_ecdsa_signature_serialize_der(cx: Context, output: *const c_uchar,
                                                   out_len: c_int, sig: *const Signature)
                                                   -> c_int;

    pub fn secp256k1_ecdsa_signature_serialize_compact(cx: Context, output64: *const c_uchar,
                                                       recid: *mut c_int, sig: *const Signature)
                                                       -> c_int;

    // ECDSA
    pub fn secp256k1_ecdsa_verify(cx: Context, msg32: *const c_uchar,
                                  sig: *const Signature, pk: *const PublicKey)
                                  -> c_int;

    pub fn secp256k1_ecdsa_sign(cx: Context, msg32: *const c_uchar,
                                sig: *mut Signature, sk: *const c_uchar,
                                noncefn: NonceFn, noncedata: *const c_void)
                                -> c_int;

    pub fn secp256k1_ecdsa_recover(cx: Context, msg32: *const c_uchar,
                                   sig: *const Signature, pk: *mut PublicKey)
                                   -> c_int;

    // EC
    pub fn secp256k1_ec_seckey_verify(cx: Context,
                                      sk: *const c_uchar) -> c_int;

    pub fn secp256k1_ec_pubkey_create(cx: Context, pk: *mut PublicKey,
                                      sk: *const c_uchar) -> c_int;

//TODO secp256k1_ec_privkey_export
//TODO secp256k1_ec_privkey_import

    pub fn secp256k1_ec_privkey_tweak_add(cx: Context,
                                          sk: *mut c_uchar,
                                          tweak: *const c_uchar)
                                          -> c_int;

    pub fn secp256k1_ec_pubkey_tweak_add(cx: Context,
                                         pk: *mut PublicKey,
                                         tweak: *const c_uchar)
                                         -> c_int;

    pub fn secp256k1_ec_privkey_tweak_mul(cx: Context,
                                          sk: *mut c_uchar,
                                          tweak: *const c_uchar)
                                          -> c_int;

    pub fn secp256k1_ec_pubkey_tweak_mul(cx: Context,
                                         pk: *mut PublicKey,
                                         tweak: *const c_uchar)
                                         -> c_int;

    pub fn secp256k1_ec_pubkey_combine(cx: Context,
                                       out: *mut PublicKey,
                                       n: c_int,
                                       ins: *const *const PublicKey)
                                       -> c_int;
}

