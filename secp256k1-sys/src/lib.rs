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
//! # secp256k1-sys FFI bindings
//! Direct bindings to the underlying C library functions. These should
//! not be needed for most users.

// Coding conventions
#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]

#![cfg_attr(all(not(test), not(feature = "std")), no_std)]
#[cfg(any(test, feature = "std"))]
extern crate core;

#[macro_use]
mod macros;
pub mod types;

#[cfg(feature = "recovery")]
pub mod recovery;

use core::{hash, slice, ptr};
use types::*;

/// Flag for context to enable no precomputation
pub const SECP256K1_START_NONE: c_uint = 1;
/// Flag for context to enable verification precomputation
pub const SECP256K1_START_VERIFY: c_uint = 1 | (1 << 8);
/// Flag for context to enable signing precomputation
pub const SECP256K1_START_SIGN: c_uint = 1 | (1 << 9);
/// Flag for keys to indicate uncompressed serialization format
#[allow(unused_parens)]
pub const SECP256K1_SER_UNCOMPRESSED: c_uint = (1 << 1);
/// Flag for keys to indicate compressed serialization format
pub const SECP256K1_SER_COMPRESSED: c_uint = (1 << 1) | (1 << 8);

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
                                        data: *mut c_void,
                                        attempt: c_uint,
) -> c_int;

/// Hash function to use to post-process an ECDH point to get
/// a shared secret.
pub type EcdhHashFn = unsafe extern "C" fn(
    output: *mut c_uchar,
    x: *const c_uchar,
    y: *const c_uchar,
    data: *mut c_void,
) -> c_int;

///  Same as secp256k1_nonce function with the exception of accepting an
///  additional pubkey argument and not requiring an attempt argument. The pubkey
///  argument can protect signature schemes with key-prefixed challenge hash
///  inputs against reusing the nonce when signing with the wrong precomputed
///  pubkey.
pub type SchnorrNonceFn = unsafe extern "C" fn(
    nonce32: *mut c_uchar,
    msg32: *const c_uchar,
    key32: *const c_uchar,
    xonly_pk32: *const c_uchar,
    algo16: *const c_uchar,
    data: *mut c_void,
) -> c_int;

/// A Secp256k1 context, containing various precomputed values and such
/// needed to do elliptic curve computations. If you create one of these
/// with `secp256k1_context_create` you MUST destroy it with
/// `secp256k1_context_destroy`, or else you will have a memory leak.
#[derive(Clone, Debug)]
#[repr(C)] pub struct Context(c_int);

#[cfg(feature = "fuzztarget")]
impl Context {
    pub fn flags(&self) -> u32 {
        self.0 as u32
    }
}

/// Library-internal representation of a Secp256k1 public key
#[repr(C)]
pub struct PublicKey([c_uchar; 64]);
impl_array_newtype!(PublicKey, c_uchar, 64);
impl_raw_debug!(PublicKey);

impl PublicKey {
    /// Creates an "uninitialized" FFI public key which is zeroed out
    ///
    /// If you pass this to any FFI functions, except as an out-pointer,
    /// the result is likely to be an assertation failure and process
    /// termination.
    pub unsafe fn new() -> Self {
        Self::from_array_unchecked([0; 64])
    }

    /// Create a new public key usable for the FFI interface from raw bytes
    ///
    /// Does not check the validity of the underlying representation. If it is
    /// invalid the result may be assertation failures (and process aborts) from
    /// the underlying library. You should not use this method except with data
    /// that you obtained from the FFI interface of the same version of this
    /// library.
    pub unsafe fn from_array_unchecked(data: [c_uchar; 64]) -> Self {
        PublicKey(data)
    }

    /// Returns the underlying FFI opaque representation of the public key
    ///
    /// You should not use this unless you really know what you are doing. It is
    /// essentially only useful for extending the FFI interface itself.
    pub fn underlying_bytes(self) -> [c_uchar; 64] {
        self.0
    }
}

impl hash::Hash for PublicKey {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        state.write(&self.0)
    }
}

/// Library-internal representation of a Secp256k1 signature
#[repr(C)]
pub struct Signature([c_uchar; 64]);
impl_array_newtype!(Signature, c_uchar, 64);
impl_raw_debug!(Signature);

impl Signature {
    /// Creates an "uninitialized" FFI signature which is zeroed out
    ///
    /// If you pass this to any FFI functions, except as an out-pointer,
    /// the result is likely to be an assertation failure and process
    /// termination.
    pub unsafe fn new() -> Self {
        Self::from_array_unchecked([0; 64])
    }

    /// Create a new signature usable for the FFI interface from raw bytes
    ///
    /// Does not check the validity of the underlying representation. If it is
    /// invalid the result may be assertation failures (and process aborts) from
    /// the underlying library. You should not use this method except with data
    /// that you obtained from the FFI interface of the same version of this
    /// library.
    pub unsafe fn from_array_unchecked(data: [c_uchar; 64]) -> Self {
        Signature(data)
    }

    /// Returns the underlying FFI opaque representation of the signature
    ///
    /// You should not use this unless you really know what you are doing. It is
    /// essentially only useful for extending the FFI interface itself.
    pub fn underlying_bytes(self) -> [c_uchar; 64] {
        self.0
    }
}

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

#[cfg(not(feature = "fuzztarget"))]
extern "C" {
    /// Default ECDH hash function
    #[cfg_attr(not(feature = "external-symbols"), link_name = "rustsecp256k1_v0_3_1_ecdh_hash_function_default")]
    pub static secp256k1_ecdh_hash_function_default: EcdhHashFn;

    #[cfg_attr(not(feature = "external-symbols"), link_name = "rustsecp256k1_v0_3_1_nonce_function_rfc6979")]
    pub static secp256k1_nonce_function_rfc6979: NonceFn;

    #[cfg_attr(not(feature = "external-symbols"), link_name = "rustsecp256k1_v0_3_1_nonce_function_default")]
    pub static secp256k1_nonce_function_default: NonceFn;

    #[cfg_attr(not(feature = "external-symbols"), link_name = "rustsecp256k1_v0_3_1_context_no_precomp")]
    pub static secp256k1_context_no_precomp: *const Context;

    // Contexts
    #[cfg_attr(not(feature = "external-symbols"), link_name = "rustsecp256k1_v0_3_1_context_preallocated_size")]
    pub fn secp256k1_context_preallocated_size(flags: c_uint) -> size_t;

    #[cfg_attr(not(feature = "external-symbols"), link_name = "rustsecp256k1_v0_3_1_context_preallocated_create")]
    pub fn secp256k1_context_preallocated_create(prealloc: *mut c_void, flags: c_uint) -> *mut Context;

    #[cfg_attr(not(feature = "external-symbols"), link_name = "rustsecp256k1_v0_3_1_context_preallocated_destroy")]
    pub fn secp256k1_context_preallocated_destroy(cx: *mut Context);

    #[cfg_attr(not(feature = "external-symbols"), link_name = "rustsecp256k1_v0_3_1_context_preallocated_clone_size")]
    pub fn secp256k1_context_preallocated_clone_size(cx: *const Context) -> size_t;

    #[cfg_attr(not(feature = "external-symbols"), link_name = "rustsecp256k1_v0_3_1_context_preallocated_clone")]
    pub fn secp256k1_context_preallocated_clone(cx: *const Context, prealloc: *mut c_void) -> *mut Context;

    #[cfg_attr(not(feature = "external-symbols"), link_name = "rustsecp256k1_v0_3_1_context_randomize")]
    pub fn secp256k1_context_randomize(cx: *mut Context,
                                       seed32: *const c_uchar)
                                       -> c_int;

    // Pubkeys
    #[cfg_attr(not(feature = "external-symbols"), link_name = "rustsecp256k1_v0_3_1_ec_pubkey_parse")]
    pub fn secp256k1_ec_pubkey_parse(cx: *const Context, pk: *mut PublicKey,
                                     input: *const c_uchar, in_len: size_t)
                                     -> c_int;

    #[cfg_attr(not(feature = "external-symbols"), link_name = "rustsecp256k1_v0_3_1_ec_pubkey_serialize")]
    pub fn secp256k1_ec_pubkey_serialize(cx: *const Context, output: *mut c_uchar,
                                         out_len: *mut size_t, pk: *const PublicKey,
                                         compressed: c_uint)
                                         -> c_int;

    // Signatures
    #[cfg_attr(not(feature = "external-symbols"), link_name = "rustsecp256k1_v0_3_1_ecdsa_signature_parse_der")]
    pub fn secp256k1_ecdsa_signature_parse_der(cx: *const Context, sig: *mut Signature,
                                               input: *const c_uchar, in_len: size_t)
                                               -> c_int;

    #[cfg_attr(not(feature = "external-symbols"), link_name = "rustsecp256k1_v0_3_1_ecdsa_signature_parse_compact")]
    pub fn secp256k1_ecdsa_signature_parse_compact(cx: *const Context, sig: *mut Signature,
                                                   input64: *const c_uchar)
                                                   -> c_int;

    #[cfg_attr(not(feature = "external-symbols"), link_name = "rustsecp256k1_v0_3_1_ecdsa_signature_parse_der_lax")]
    pub fn ecdsa_signature_parse_der_lax(cx: *const Context, sig: *mut Signature,
                                         input: *const c_uchar, in_len: size_t)
                                         -> c_int;

    #[cfg_attr(not(feature = "external-symbols"), link_name = "rustsecp256k1_v0_3_1_ecdsa_signature_serialize_der")]
    pub fn secp256k1_ecdsa_signature_serialize_der(cx: *const Context, output: *mut c_uchar,
                                                   out_len: *mut size_t, sig: *const Signature)
                                                   -> c_int;

    #[cfg_attr(not(feature = "external-symbols"), link_name = "rustsecp256k1_v0_3_1_ecdsa_signature_serialize_compact")]
    pub fn secp256k1_ecdsa_signature_serialize_compact(cx: *const Context, output64: *mut c_uchar,
                                                       sig: *const Signature)
                                                       -> c_int;

    #[cfg_attr(not(feature = "external-symbols"), link_name = "rustsecp256k1_v0_3_1_ecdsa_signature_normalize")]
    pub fn secp256k1_ecdsa_signature_normalize(cx: *const Context, out_sig: *mut Signature,
                                               in_sig: *const Signature)
                                               -> c_int;

    // ECDSA
    #[cfg_attr(not(feature = "external-symbols"), link_name = "rustsecp256k1_v0_3_1_ecdsa_verify")]
    pub fn secp256k1_ecdsa_verify(cx: *const Context,
                                  sig: *const Signature,
                                  msg32: *const c_uchar,
                                  pk: *const PublicKey)
                                  -> c_int;

    #[cfg_attr(not(feature = "external-symbols"), link_name = "rustsecp256k1_v0_3_1_ecdsa_sign")]
    pub fn secp256k1_ecdsa_sign(cx: *const Context,
                                sig: *mut Signature,
                                msg32: *const c_uchar,
                                sk: *const c_uchar,
                                noncefn: NonceFn,
                                noncedata: *const c_void)
                                -> c_int;

    // EC
    #[cfg_attr(not(feature = "external-symbols"), link_name = "rustsecp256k1_v0_3_1_ec_seckey_verify")]
    pub fn secp256k1_ec_seckey_verify(cx: *const Context,
                                      sk: *const c_uchar) -> c_int;

    #[cfg_attr(not(feature = "external-symbols"), link_name = "rustsecp256k1_v0_3_1_ec_pubkey_create")]
    pub fn secp256k1_ec_pubkey_create(cx: *const Context, pk: *mut PublicKey,
                                      sk: *const c_uchar) -> c_int;

//TODO secp256k1_ec_privkey_export
//TODO secp256k1_ec_privkey_import

    #[deprecated(since = "0.2.0",note = "Please use the secp256k1_ec_seckey_tweak_add function instead")]
    #[cfg_attr(not(feature = "external-symbols"), link_name = "rustsecp256k1_v0_3_1_ec_privkey_negate")]
    pub fn secp256k1_ec_privkey_negate(cx: *const Context,
                                       sk: *mut c_uchar) -> c_int;

    #[cfg_attr(not(feature = "external-symbols"), link_name = "rustsecp256k1_v0_3_1_ec_privkey_negate")]
    pub fn secp256k1_ec_seckey_negate(cx: *const Context,
                                      sk: *mut c_uchar) -> c_int;

    #[cfg_attr(not(feature = "external-symbols"), link_name = "rustsecp256k1_v0_3_1_ec_pubkey_negate")]
    pub fn secp256k1_ec_pubkey_negate(cx: *const Context,
                                      pk: *mut PublicKey) -> c_int;

    #[deprecated(since = "0.2.0",note = "Please use the secp256k1_ec_seckey_tweak_add function instead")]
    #[cfg_attr(not(feature = "external-symbols"), link_name = "rustsecp256k1_v0_3_1_ec_privkey_tweak_add")]
    pub fn secp256k1_ec_privkey_tweak_add(cx: *const Context,
                                          sk: *mut c_uchar,
                                          tweak: *const c_uchar)
                                          -> c_int;

    #[cfg_attr(not(feature = "external-symbols"), link_name = "rustsecp256k1_v0_3_1_ec_seckey_tweak_add")]
    pub fn secp256k1_ec_seckey_tweak_add(cx: *const Context,
                                        sk: *mut c_uchar,
                                        tweak: *const c_uchar)
                                        -> c_int;

    #[cfg_attr(not(feature = "external-symbols"), link_name = "rustsecp256k1_v0_3_1_ec_pubkey_tweak_add")]
    pub fn secp256k1_ec_pubkey_tweak_add(cx: *const Context,
                                         pk: *mut PublicKey,
                                         tweak: *const c_uchar)
                                         -> c_int;

    #[deprecated(since = "0.2.0",note = "Please use the secp256k1_ec_seckey_tweak_mul function instead")]
    #[cfg_attr(not(feature = "external-symbols"), link_name = "rustsecp256k1_v0_3_1_ec_privkey_tweak_mul")]
    pub fn secp256k1_ec_privkey_tweak_mul(cx: *const Context,
                                          sk: *mut c_uchar,
                                          tweak: *const c_uchar)
                                          -> c_int;

    #[cfg_attr(not(feature = "external-symbols"), link_name = "rustsecp256k1_v0_3_1_ec_seckey_tweak_mul")]
    pub fn secp256k1_ec_seckey_tweak_mul(cx: *const Context,
                                        sk: *mut c_uchar,
                                        tweak: *const c_uchar)
                                        -> c_int;

    #[cfg_attr(not(feature = "external-symbols"), link_name = "rustsecp256k1_v0_3_1_ec_pubkey_tweak_mul")]
    pub fn secp256k1_ec_pubkey_tweak_mul(cx: *const Context,
                                         pk: *mut PublicKey,
                                         tweak: *const c_uchar)
                                         -> c_int;

    #[cfg_attr(not(feature = "external-symbols"), link_name = "rustsecp256k1_v0_3_1_ec_pubkey_combine")]
    pub fn secp256k1_ec_pubkey_combine(cx: *const Context,
                                       out: *mut PublicKey,
                                       ins: *const *const PublicKey,
                                       n: c_int)
                                       -> c_int;

    #[cfg_attr(not(feature = "external-symbols"), link_name = "rustsecp256k1_v0_3_1_ecdh")]
    pub fn secp256k1_ecdh(
        cx: *const Context,
        output: *mut c_uchar,
        pubkey: *const PublicKey,
        seckey: *const c_uchar,
        hashfp: EcdhHashFn,
        data: *mut c_void,
    ) -> c_int;


    // Schnorr Signatures
    #[cfg_attr(not(feature = "external-symbols"), link_name = "rustsecp256k1_v0_3_1_nonce_function_bip340")]
    pub static secp256k1_nonce_function_bip340: SchnorrNonceFn;

    #[cfg_attr(not(feature = "external-symbols"), link_name = "rustsecp256k1_v0_3_1_schnorrsig_sign")]
    pub fn secp256k1_schnorrsig_sign(
        cx: *const Context,
        sig: *mut c_uchar,
        msg32: *const c_uchar,
        keypair: *const KeyPair,
        noncefp: SchnorrNonceFn,
        noncedata: *const c_void
    ) -> c_int;

    #[cfg_attr(not(feature = "external-symbols"), link_name = "rustsecp256k1_v0_3_1_schnorrsig_verify")]
    pub fn secp256k1_schnorrsig_verify(
        cx: *const Context,
        sig64: *const c_uchar,
        msg32: *const c_uchar,
        pubkey: *const XOnlyPublicKey,
    ) -> c_int;

    // Extra keys

    #[cfg_attr(not(feature = "external-symbols"), link_name = "rustsecp256k1_v0_3_1_keypair_create")]
    pub fn secp256k1_keypair_create(
        cx: *const Context,
        keypair: *mut KeyPair,
        seckey: *const c_uchar,
    ) -> c_int;

    #[cfg_attr(not(feature = "external-symbols"), link_name = "rustsecp256k1_v0_3_1_xonly_pubkey_parse")]
    pub fn secp256k1_xonly_pubkey_parse(
        cx: *const Context,
        pubkey: *mut XOnlyPublicKey,
        input32: *const c_uchar,
    ) -> c_int;

    #[cfg_attr(not(feature = "external-symbols"), link_name = "rustsecp256k1_v0_3_1_xonly_pubkey_serialize")]
    pub fn secp256k1_xonly_pubkey_serialize(
        cx: *const Context,
        output32: *mut c_uchar,
        pubkey: *const XOnlyPublicKey,
    ) -> c_int;

    #[cfg_attr(not(feature = "external-symbols"), link_name = "rustsecp256k1_v0_3_1_xonly_pubkey_from_pubkey")]
    pub fn secp256k1_xonly_pubkey_from_pubkey(
        cx: *const Context,
        xonly_pubkey: *mut XOnlyPublicKey,
        pk_parity: *mut c_int,
        pubkey: *const PublicKey,
    ) -> c_int;

    #[cfg_attr(not(feature = "external-symbols"), link_name = "rustsecp256k1_v0_3_1_xonly_pubkey_tweak_add")]
    pub fn secp256k1_xonly_pubkey_tweak_add(
        cx: *const Context,
        output_pubkey: *mut PublicKey,
        internal_pubkey: *const XOnlyPublicKey,
        tweak32: *const c_uchar,
    ) -> c_int;

    #[cfg_attr(not(feature = "external-symbols"), link_name = "rustsecp256k1_v0_3_1_keypair_xonly_pub")]
    pub fn secp256k1_keypair_xonly_pub(
        cx: *const Context,
        pubkey: *mut XOnlyPublicKey,
        pk_parity: *mut c_int,
        keypair: *const KeyPair
    ) -> c_int;

    #[cfg_attr(not(feature = "external-symbols"), link_name = "rustsecp256k1_v0_3_1_keypair_xonly_tweak_add")]
    pub fn secp256k1_keypair_xonly_tweak_add(
        cx: *const Context,
        keypair: *mut KeyPair,
        tweak32: *const c_uchar,
    ) -> c_int;

    #[cfg_attr(not(feature = "external-symbols"), link_name = "rustsecp256k1_v0_3_1_xonly_pubkey_tweak_add_check")]
    pub fn secp256k1_xonly_pubkey_tweak_add_check(
        cx: *const Context,
        tweaked_pubkey32: *const c_uchar,
        tweaked_pubkey_parity: c_int,
        internal_pubkey: *const XOnlyPublicKey,
        tweak32: *const c_uchar,
    ) -> c_int;
}


/// A reimplementation of the C function `secp256k1_context_create` in rust.
///
/// This function allocates memory, the pointer should be deallocated using `secp256k1_context_destroy`
/// A failure to do so will result in a memory leak.
///
/// This will create a secp256k1 raw context.
// Returns: a newly created context object.
//  In:      flags: which parts of the context to initialize.
#[no_mangle]
#[cfg(all(feature = "std", not(feature = "external-symbols")))]
pub unsafe extern "C" fn rustsecp256k1_v0_3_1_context_create(flags: c_uint) -> *mut Context {
    use core::mem;
    use std::alloc;
    assert!(ALIGN_TO >= mem::align_of::<usize>());
    assert!(ALIGN_TO >= mem::align_of::<&usize>());
    assert!(ALIGN_TO >= mem::size_of::<usize>());

    // We need to allocate `ALIGN_TO` more bytes in order to write the amount of bytes back.
    let bytes = secp256k1_context_preallocated_size(flags) + ALIGN_TO;
    let layout = alloc::Layout::from_size_align(bytes, ALIGN_TO).unwrap();
    let ptr = alloc::alloc(layout);
    (ptr as *mut usize).write(bytes);
    // We must offset a whole ALIGN_TO in order to preserve the same alignment
    // this means we "lose" ALIGN_TO-size_of(usize) for padding.
    let ptr = ptr.add(ALIGN_TO) as *mut c_void;
    secp256k1_context_preallocated_create(ptr, flags)
}

#[cfg(all(feature = "std", not(feature = "external-symbols")))]
pub unsafe fn secp256k1_context_create(flags: c_uint) -> *mut Context {
    rustsecp256k1_v0_3_1_context_create(flags)
}

/// A reimplementation of the C function `secp256k1_context_destroy` in rust.
///
/// This function destroys and deallcates the context created by `secp256k1_context_create`.
///
/// The pointer shouldn't be used after passing to this function, consider it as passing it to `free()`.
///
#[no_mangle]
#[cfg(all(feature = "std", not(feature = "external-symbols")))]
pub unsafe extern "C" fn rustsecp256k1_v0_3_1_context_destroy(ctx: *mut Context) {
    use std::alloc;
    secp256k1_context_preallocated_destroy(ctx);
    let ptr = (ctx as *mut u8).sub(ALIGN_TO);
    let bytes = (ptr as *mut usize).read();
    let layout = alloc::Layout::from_size_align(bytes, ALIGN_TO).unwrap();
    alloc::dealloc(ptr, layout);
}

#[cfg(all(feature = "std", not(feature = "external-symbols")))]
pub unsafe fn secp256k1_context_destroy(ctx: *mut Context) {
    rustsecp256k1_v0_3_1_context_destroy(ctx)
}


/// **This function is an override for the C function, this is the an edited version of the original description:**
///
/// A callback function to be called when an illegal argument is passed to
/// an API call. It will only trigger for violations that are mentioned
/// explicitly in the header. **This will cause a panic**.
///
/// The philosophy is that these shouldn't be dealt with through a
/// specific return value, as calling code should not have branches to deal with
/// the case that this code itself is broken.
///
/// On the other hand, during debug stage, one would want to be informed about
/// such mistakes, and the default (crashing) may be inadvisable.
/// When this callback is triggered, the API function called is guaranteed not
/// to cause a crash, though its return value and output arguments are
/// undefined.
///
/// See also secp256k1_default_error_callback_fn.
///
#[no_mangle]
#[cfg(not(feature = "external-symbols"))]
pub unsafe extern "C" fn rustsecp256k1_v0_3_1_default_illegal_callback_fn(message: *const c_char, _data: *mut c_void) {
    use core::str;
    let msg_slice = slice::from_raw_parts(message as *const u8, strlen(message));
    let msg = str::from_utf8_unchecked(msg_slice);
    panic!("[libsecp256k1] illegal argument. {}", msg);
}

/// **This function is an override for the C function, this is the an edited version of the original description:**
///
/// A callback function to be called when an internal consistency check
/// fails. **This will cause a panic**.
///
/// This can only trigger in case of a hardware failure, miscompilation,
/// memory corruption, serious bug in the library, or other error would can
/// otherwise result in undefined behaviour. It will not trigger due to mere
/// incorrect usage of the API (see secp256k1_default_illegal_callback_fn
/// for that). After this callback returns, anything may happen, including
/// crashing.
///
/// See also secp256k1_default_illegal_callback_fn.
///
#[no_mangle]
#[cfg(not(feature = "external-symbols"))]
pub unsafe extern "C" fn rustsecp256k1_v0_3_1_default_error_callback_fn(message: *const c_char, _data: *mut c_void) {
    use core::str;
    let msg_slice = slice::from_raw_parts(message as *const u8, strlen(message));
    let msg = str::from_utf8_unchecked(msg_slice);
    panic!("[libsecp256k1] internal consistency check failed {}", msg);
}

#[no_mangle]
#[cfg(not(feature = "external-symbols"))]
unsafe fn strlen(mut str_ptr: *const c_char) -> usize {
    let mut ctr = 0;
    while *str_ptr != '\0' as c_char {
        ctr += 1;
        str_ptr = str_ptr.offset(1);
    }
    ctr
}


/// A trait for producing pointers that will always be valid in C. (assuming NULL pointer is a valid no-op)
/// Rust doesn't promise what pointers does it give to ZST (https://doc.rust-lang.org/nomicon/exotic-sizes.html#zero-sized-types-zsts)
/// In case the type is empty this trait will give a NULL pointer, which should be handled in C.
///
pub trait CPtr {
    type Target;
    fn as_c_ptr(&self) -> *const Self::Target;
    fn as_mut_c_ptr(&mut self) -> *mut Self::Target;
}

impl<T> CPtr for [T] {
    type Target = T;
    fn as_c_ptr(&self) -> *const Self::Target {
        if self.is_empty() {
            ptr::null()
        } else {
            self.as_ptr()
        }
    }

    fn as_mut_c_ptr(&mut self) -> *mut Self::Target {
        if self.is_empty() {
            ptr::null_mut::<Self::Target>()
        } else {
            self.as_mut_ptr()
        }
    }
}




#[cfg(feature = "fuzztarget")]
mod fuzz_dummy {
    extern crate std;
    use self::std::{ptr, mem};
    use self::std::boxed::Box;
    use types::*;
    use {Signature, Context, NonceFn, EcdhHashFn, PublicKey,
        SchnorrNonceFn, XOnlyPublicKey, KeyPair,
        SECP256K1_START_NONE, SECP256K1_START_VERIFY, SECP256K1_START_SIGN,
        SECP256K1_SER_COMPRESSED, SECP256K1_SER_UNCOMPRESSED};

    #[allow(non_upper_case_globals)]
    pub static secp256k1_context_no_precomp: &Context = &Context(0);

    extern "C" {
        #[cfg_attr(not(feature = "external-symbols"), link_name = "rustsecp256k1_v0_3_1_ecdh_hash_function_default")]
        pub static secp256k1_ecdh_hash_function_default: EcdhHashFn;
        #[cfg_attr(not(feature = "external-symbols"), link_name = "rustsecp256k1_v0_3_1_nonce_function_rfc6979")]
        pub static secp256k1_nonce_function_rfc6979: NonceFn;
        #[cfg_attr(not(feature = "external-symbols"), link_name = "rustsecp256k1_v0_3_1_nonce_function_bip340")]
        pub static secp256k1_nonce_function_bip340: SchnorrNonceFn;
    }

    // Contexts
    /// Creates a dummy context, tracking flags to ensure proper calling semantics
    pub unsafe fn secp256k1_context_preallocated_create(_ptr: *mut c_void, flags: c_uint) -> *mut Context {
        let b = Box::new(Context(flags as i32));
        Box::into_raw(b)
    }

    /// Return dummy size of context struct.
    pub unsafe fn secp256k1_context_preallocated_size(_flags: c_uint) -> size_t {
        mem::size_of::<Context>()
    }

    /// Return dummy size of context struct.
    pub unsafe fn secp256k1_context_preallocated_clone_size(_cx: *mut Context) -> size_t {
        mem::size_of::<Context>()
    }

    /// Copies a dummy context
    pub unsafe fn secp256k1_context_preallocated_clone(cx: *const Context, prealloc: *mut c_void) -> *mut Context {
        let ret = prealloc as *mut Context;
        *ret = (*cx).clone();
        ret
    }

    /// "Destroys" a dummy context
    pub unsafe fn secp256k1_context_preallocated_destroy(cx: *mut Context) {
        (*cx).0 = 0;
    }

    /// Asserts that cx is properly initialized
    pub unsafe fn secp256k1_context_randomize(cx: *mut Context,
                                              _seed32: *const c_uchar)
                                              -> c_int {
        assert!(!cx.is_null() && (*cx).0 as u32 & !(SECP256K1_START_NONE | SECP256K1_START_VERIFY | SECP256K1_START_SIGN) == 0);
        1
    }

    // Pubkeys
    /// Parse 33/65 byte pubkey into PublicKey, losing compressed information
    pub unsafe fn secp256k1_ec_pubkey_parse(cx: *const Context, pk: *mut PublicKey,
                                            input: *const c_uchar, in_len: size_t)
                                            -> c_int {
        assert!(!cx.is_null() && (*cx).0 as u32 & !(SECP256K1_START_NONE | SECP256K1_START_VERIFY | SECP256K1_START_SIGN) == 0);
        match in_len {
            33 => {
                if (*input.offset(1) > 0x7f && *input != 2) || (*input.offset(1) <= 0x7f && *input != 3) {
                    0
                } else {
                    ptr::copy(input.offset(1), (*pk).0[0..32].as_mut_ptr(), 32);
                    ptr::copy(input.offset(1), (*pk).0[32..64].as_mut_ptr(), 32);
                    test_pk_validate(cx, pk)
                }
            },
            65 => {
                if *input != 4 && *input != 6 && *input != 7 {
                    0
                } else {
                    ptr::copy(input.offset(1), (*pk).0.as_mut_ptr(), 64);
                    test_pk_validate(cx, pk)
                }
            },
            _ => 0
        }
    }

    /// Serialize PublicKey back to 33/65 byte pubkey
    pub unsafe fn secp256k1_ec_pubkey_serialize(cx: *const Context, output: *mut c_uchar,
                                                out_len: *mut size_t, pk: *const PublicKey,
                                                compressed: c_uint)
                                                -> c_int {
        assert!(!cx.is_null() && (*cx).0 as u32 & !(SECP256K1_START_NONE | SECP256K1_START_VERIFY | SECP256K1_START_SIGN) == 0);
        if test_pk_validate(cx, pk) != 1 { return 0; }
        if compressed == SECP256K1_SER_COMPRESSED {
            assert_eq!(*out_len, 33);
            if (*pk).0[0] > 0x7f {
                *output = 2;
            } else {
                *output = 3;
            }
            ptr::copy((*pk).0.as_ptr(), output.offset(1), 32);
        } else if compressed == SECP256K1_SER_UNCOMPRESSED {
            assert_eq!(*out_len, 65);
            *output = 4;
            ptr::copy((*pk).0.as_ptr(), output.offset(1), 64);
        } else {
            panic!("Bad flags");
        }
        1
     }

    // Signatures
    pub unsafe fn secp256k1_ecdsa_signature_parse_der(_cx: *const Context, _sig: *mut Signature,
                                                      _input: *const c_uchar, _in_len: size_t)
                                                      -> c_int {
        unimplemented!();
    }

    /// Copies input64 to sig, checking the pubkey part is valid
    pub unsafe fn secp256k1_ecdsa_signature_parse_compact(cx: *const Context, sig: *mut Signature,
                                                          input64: *const c_uchar)
                                                          -> c_int {
        assert!(!cx.is_null() && (*cx).0 as u32 & !(SECP256K1_START_NONE | SECP256K1_START_VERIFY | SECP256K1_START_SIGN) == 0);
        if secp256k1_ec_seckey_verify(cx, input64.offset(32)) != 1 { return 0; } // sig should be msg32||sk
        ptr::copy(input64, (*sig).0[..].as_mut_ptr(), 64);
        1
    }

    pub unsafe fn ecdsa_signature_parse_der_lax(_cx: *const Context, _sig: *mut Signature,
                                                _input: *const c_uchar, _in_len: size_t)
                                                -> c_int {
        unimplemented!();
    }

    /// Copies up to 72 bytes into output from sig
    pub unsafe fn secp256k1_ecdsa_signature_serialize_der(cx: *const Context, output: *mut c_uchar,
                                                          out_len: *mut size_t, sig: *const Signature)
                                                          -> c_int {
        assert!(!cx.is_null() && (*cx).0 as u32 & !(SECP256K1_START_NONE | SECP256K1_START_VERIFY | SECP256K1_START_SIGN) == 0);

        let mut len_r = 33;
        if *(*sig).0.as_ptr().offset(0) < 0x80 {
            len_r -= 1;
        }
        let mut len_s = 33;
        if *(*sig).0.as_ptr().offset(32) < 0x80 {
            len_s -= 1;
        }

        assert!(*out_len >= (6 + len_s + len_r) as usize);

        *output.offset(0) = 0x30;
        *output.offset(1) = 4 + len_r + len_s;
        *output.offset(2) = 0x02;
        *output.offset(3) = len_r;
        if len_r == 33 {
            *output.offset(4) = 0;
            ptr::copy((*sig).0[..].as_ptr(), output.offset(5), 32);
        } else {
            ptr::copy((*sig).0[..].as_ptr(), output.offset(4), 32);
        }
        *output.offset(4 + len_r as isize) = 0x02;
        *output.offset(5 + len_r as isize) = len_s;
        if len_s == 33 {
            *output.offset(6 + len_r as isize) = 0;
            ptr::copy((*sig).0[..].as_ptr().offset(32), output.offset(7 + len_r as isize), 32);
        } else {
            ptr::copy((*sig).0[..].as_ptr().offset(32), output.offset(6 + len_r as isize), 32);
        }
        1
    }

    /// Copies sig to output64
    pub unsafe fn secp256k1_ecdsa_signature_serialize_compact(cx: *const Context, output64: *mut c_uchar,
                                                              sig: *const Signature)
                                                              -> c_int {
        assert!(!cx.is_null() && (*cx).0 as u32 & !(SECP256K1_START_NONE | SECP256K1_START_VERIFY | SECP256K1_START_SIGN) == 0);
        ptr::copy((*sig).0[..].as_ptr(), output64, 64);
        1
    }

    pub unsafe fn secp256k1_ecdsa_signature_normalize(_cx: *const Context, _out_sig: *mut Signature,
                                                      _in_sig: *const Signature)
                                                      -> c_int {
        unimplemented!();
    }

    // ECDSA
    /// Verifies that sig is msg32||pk[0..32]
    pub unsafe fn secp256k1_ecdsa_verify(cx: *const Context,
                                         sig: *const Signature,
                                         msg32: *const c_uchar,
                                         pk: *const PublicKey)
                                         -> c_int {
        assert!(!cx.is_null() && (*cx).0 as u32 & !(SECP256K1_START_NONE | SECP256K1_START_VERIFY | SECP256K1_START_SIGN) == 0);
        assert!((*cx).0 as u32 & SECP256K1_START_VERIFY == SECP256K1_START_VERIFY);
        if test_pk_validate(cx, pk) != 1 { return 0; }
        for i in 0..32 {
            if (*sig).0[i] != *msg32.offset(i as isize) {
                return 0;
            }
        }
        if (*sig).0[32..64] != (*pk).0[0..32] {
            0
        } else {
            1
        }
    }

    /// Sets sig to msg32||sk
    pub unsafe fn secp256k1_ecdsa_sign(cx: *const Context,
                                       sig: *mut Signature,
                                       msg32: *const c_uchar,
                                       sk: *const c_uchar,
                                       _noncefn: NonceFn,
                                       _noncedata: *const c_void)
                                       -> c_int {
        assert!(!cx.is_null() && (*cx).0 as u32 & !(SECP256K1_START_NONE | SECP256K1_START_VERIFY | SECP256K1_START_SIGN) == 0);
        assert!((*cx).0 as u32 & SECP256K1_START_SIGN == SECP256K1_START_SIGN);
        if secp256k1_ec_seckey_verify(cx, sk) != 1 { return 0; }
        ptr::copy(msg32, (*sig).0[0..32].as_mut_ptr(), 32);
        ptr::copy(sk, (*sig).0[32..64].as_mut_ptr(), 32);
        1
    }

    // EC
    /// Checks that pk != 0xffff...ffff and pk[0..32] == pk[32..64]
    pub unsafe fn test_pk_validate(cx: *const Context,
                                   pk: *const PublicKey) -> c_int {
        assert!(!cx.is_null() && (*cx).0 as u32 & !(SECP256K1_START_NONE | SECP256K1_START_VERIFY | SECP256K1_START_SIGN) == 0);
        if (*pk).0[0..32] != (*pk).0[32..64] || secp256k1_ec_seckey_verify(cx, (*pk).0[0..32].as_ptr()) == 0 {
            0
        } else {
            1
        }
    }

    /// Checks that sk != 0xffff...ffff
    pub unsafe fn secp256k1_ec_seckey_verify(cx: *const Context,
                                             sk: *const c_uchar) -> c_int {
        assert!(!cx.is_null() && (*cx).0 as u32 & !(SECP256K1_START_NONE | SECP256K1_START_VERIFY | SECP256K1_START_SIGN) == 0);
        let mut res = 0;
        for i in 0..32 {
            if *sk.offset(i as isize) != 0xff { res = 1 };
        }
        res
    }

    /// Sets pk to sk||sk
    pub unsafe fn secp256k1_ec_pubkey_create(cx: *const Context, pk: *mut PublicKey,
                                             sk: *const c_uchar) -> c_int {
        assert!(!cx.is_null() && (*cx).0 as u32 & !(SECP256K1_START_NONE | SECP256K1_START_VERIFY | SECP256K1_START_SIGN) == 0);
        if secp256k1_ec_seckey_verify(cx, sk) != 1 { return 0; }
        ptr::copy(sk, (*pk).0[0..32].as_mut_ptr(), 32);
        ptr::copy(sk, (*pk).0[32..64].as_mut_ptr(), 32);
        1
    }

//TODO secp256k1_ec_privkey_export
//TODO secp256k1_ec_privkey_import

    #[deprecated(since = "0.2.0",note = "Please use the secp256k1_ec_seckey_negate function instead")]
    pub unsafe fn secp256k1_ec_privkey_negate(cx: *const Context,
                                              sk: *mut c_uchar) -> c_int {
        secp256k1_ec_seckey_negate(cx, sk)
    }

    pub unsafe fn secp256k1_ec_seckey_negate(cx: *const Context,
                                              sk: *mut c_uchar) -> c_int {
        assert!(!cx.is_null() && (*cx).0 as u32 & !(SECP256K1_START_NONE | SECP256K1_START_VERIFY | SECP256K1_START_SIGN) == 0);
        if secp256k1_ec_seckey_verify(cx, sk) != 1 { return 0; }
        1
    }

    pub unsafe fn secp256k1_ec_pubkey_negate(cx: *const Context,
                                             pk: *mut PublicKey) -> c_int {
        assert!(!cx.is_null() && (*cx).0 as u32 & !(SECP256K1_START_NONE | SECP256K1_START_VERIFY | SECP256K1_START_SIGN) == 0);
        if test_pk_validate(cx, pk) != 1 { return 0; }
        1
    }

    /// Copies the first 16 bytes of tweak into the last 16 bytes of sk
    pub unsafe fn secp256k1_ec_privkey_tweak_add(cx: *const Context,
                                                 sk: *mut c_uchar,
                                                 tweak: *const c_uchar)
                                                 -> c_int {
        secp256k1_ec_seckey_tweak_add(cx, sk, tweak)
    }

    pub unsafe fn secp256k1_ec_seckey_tweak_add(cx: *const Context,
                                                sk: *mut c_uchar,
                                                tweak: *const c_uchar)
                                                -> c_int {
        assert!(!cx.is_null() && (*cx).0 as u32 & !(SECP256K1_START_NONE | SECP256K1_START_VERIFY | SECP256K1_START_SIGN) == 0);
        if secp256k1_ec_seckey_verify(cx, sk) != 1 { return 0; }
        ptr::copy(tweak.offset(16), sk.offset(16), 16);
        *sk.offset(24) = 0x7f; // Ensure sk remains valid no matter what tweak was
        1
    }

    /// The PublicKey equivalent of secp256k1_ec_privkey_tweak_add
    pub unsafe fn secp256k1_ec_pubkey_tweak_add(cx: *const Context,
                                                pk: *mut PublicKey,
                                                tweak: *const c_uchar)
                                                -> c_int {
        assert!(!cx.is_null() && (*cx).0 as u32 & !(SECP256K1_START_NONE | SECP256K1_START_VERIFY | SECP256K1_START_SIGN) == 0);
        if test_pk_validate(cx, pk) != 1 { return 0; }
        ptr::copy(tweak.offset(16), (*pk).0[16..32].as_mut_ptr(), 16);
        ptr::copy(tweak.offset(16), (*pk).0[16+32..64].as_mut_ptr(), 16);
        (*pk).0[24] = 0x7f; // Ensure pk remains valid no matter what tweak was
        (*pk).0[24+32] = 0x7f; // Ensure pk remains valid no matter what tweak was
        1
    }

    /// Copies the last 16 bytes of tweak into the last 16 bytes of sk
    pub unsafe fn secp256k1_ec_privkey_tweak_mul(cx: *const Context,
                                                 sk: *mut c_uchar,
                                                 tweak: *const c_uchar)
                                                 -> c_int {
            secp256k1_ec_seckey_tweak_mul(cx, sk, tweak)
    }

    /// Copies the last 16 bytes of tweak into the last 16 bytes of sk
    pub unsafe fn secp256k1_ec_seckey_tweak_mul(cx: *const Context,
                                                 sk: *mut c_uchar,
                                                 tweak: *const c_uchar)
                                                 -> c_int {
        assert!(!cx.is_null() && (*cx).0 as u32 & !(SECP256K1_START_NONE | SECP256K1_START_VERIFY | SECP256K1_START_SIGN) == 0);
        if secp256k1_ec_seckey_verify(cx, sk) != 1 { return 0; }
        ptr::copy(tweak.offset(16), sk.offset(16), 16);
        *sk.offset(24) = 0x00; // Ensure sk remains valid no matter what tweak was
        1
    }

    /// The PublicKey equivalent of secp256k1_ec_privkey_tweak_mul
    pub unsafe fn secp256k1_ec_pubkey_tweak_mul(cx: *const Context,
                                                pk: *mut PublicKey,
                                                tweak: *const c_uchar)
                                                -> c_int {
        assert!(!cx.is_null() && (*cx).0 as u32 & !(SECP256K1_START_NONE | SECP256K1_START_VERIFY | SECP256K1_START_SIGN) == 0);
        if test_pk_validate(cx, pk) != 1 { return 0; }
        ptr::copy(tweak.offset(16), (*pk).0[16..32].as_mut_ptr(), 16);
        ptr::copy(tweak.offset(16), (*pk).0[16+32..64].as_mut_ptr(), 16);
        (*pk).0[24] = 0x00; // Ensure pk remains valid no matter what tweak was
        (*pk).0[24+32] = 0x00; // Ensure pk remains valid no matter what tweak was
        1
    }

    pub unsafe fn secp256k1_ec_pubkey_combine(cx: *const Context,
                                              out: *mut PublicKey,
                                              ins: *const *const PublicKey,
                                              n: c_int)
                                              -> c_int {
        assert!(!cx.is_null() && (*cx).0 as u32 & !(SECP256K1_START_NONE | SECP256K1_START_VERIFY | SECP256K1_START_SIGN) == 0);
        assert!(n <= 32 && n >= 0); //TODO: Remove this restriction?
        for i in 0..n {
            if test_pk_validate(cx, *ins.offset(i as isize)) != 1 { return 0; }
            (*out).0[(i*32/n) as usize..((i+1)*32/n) as usize].copy_from_slice(&(**ins.offset(i as isize)).0[(i*32/n) as usize..((i+1)*32/n) as usize]);
        }
        ptr::copy((*out).0[0..32].as_ptr(), (*out).0[32..64].as_mut_ptr(), 32);
        (*out).0[24] = 0x7f; // pk should always be valid
        (*out).0[24+32] = 0x7f; // pk should always be valid
        test_pk_validate(cx, out)
    }

    /// Sets out to point[0..16]||scalar[0..16]
    pub unsafe fn secp256k1_ecdh(
        cx: *const Context,
        out: *mut c_uchar,
        point: *const PublicKey,
        scalar: *const c_uchar,
        _hashfp: EcdhHashFn,
        _data: *mut c_void,
    ) -> c_int {
        assert!(!cx.is_null() && (*cx).0 as u32 & !(SECP256K1_START_NONE | SECP256K1_START_VERIFY | SECP256K1_START_SIGN) == 0);
        if secp256k1_ec_seckey_verify(cx, scalar) != 1 { return 0; }

        let mut scalar_prefix = [0; 16];
        ptr::copy(scalar, scalar_prefix[..].as_mut_ptr(), 16);

        if (*point).0[0..16] > scalar_prefix[0..16] {
            ptr::copy((*point).as_ptr(), out, 16);
            ptr::copy(scalar, out.offset(16), 16);
        } else {
            ptr::copy(scalar, out, 16);
            ptr::copy((*point).as_ptr(), out.offset(16), 16);
        }
        (*out.offset(16)) = 0x00; // result should always be a valid secret key
        1
    }

    pub unsafe fn secp256k1_schnorrsig_sign(
        _cx: *const Context,
        _sig: *mut c_uchar,
        _msg32: *const c_uchar,
        _keypair: *const KeyPair,
        _noncefp: SchnorrNonceFn,
        _noncedata: *const c_void
    ) -> c_int {
        unimplemented!();
    }

    pub unsafe fn secp256k1_schnorrsig_verify(
        _cx: *const Context,
        _sig64: *const c_uchar,
        _msg32: *const c_uchar,
        _pubkey: *const XOnlyPublicKey,
    ) -> c_int {
        unimplemented!();
    }

    pub fn secp256k1_xonly_pubkey_parse(
        _cx: *const Context,
        _pubkey: *mut XOnlyPublicKey,
        _input32: *const c_uchar,
    ) -> c_int {
        unimplemented!();
    }

    pub fn secp256k1_xonly_pubkey_serialize(
        _cx: *const Context,
        _output32: *mut c_uchar,
        _pubkey: *const XOnlyPublicKey,
    ) -> c_int {
        unimplemented!();
    }

    pub unsafe fn secp256k1_xonly_pubkey_from_pubkey(
        _cx: *const Context,
        _xonly_pubkey: *mut XOnlyPublicKey,
        _pk_parity: *mut c_int,
        _pubkey: *const PublicKey,
    ) -> c_int {
        unimplemented!();
    }

    pub unsafe fn secp256k1_keypair_create(
        _cx: *const Context,
        _keypair: *mut KeyPair,
        _seckey: *const c_uchar,
    ) -> c_int {
        unimplemented!();
    }

    pub unsafe fn secp256k1_xonly_pubkey_tweak_add(
        _cx: *const Context,
        _output_pubkey: *mut PublicKey,
        _internal_pubkey: *const XOnlyPublicKey,
        _tweak32: *const c_uchar,
    ) -> c_int {
        unimplemented!();
    }

    pub unsafe fn secp256k1_keypair_xonly_pub(
        _cx: *const Context,
        _pubkey: *mut XOnlyPublicKey,
        _pk_parity: *mut c_int,
        _keypair: *const KeyPair
    ) -> c_int {
        unimplemented!();
    }

    pub unsafe fn secp256k1_keypair_xonly_tweak_add(
        _cx: *const Context,
        _keypair: *mut KeyPair,
        _tweak32: *const c_uchar,
    ) -> c_int {
        unimplemented!();
    }

    pub unsafe fn secp256k1_xonly_pubkey_tweak_add_check(
        _cx: *const Context,
        _tweaked_pubkey32: *const c_uchar,
        _tweaked_pubkey_parity: c_int,
        _internal_pubkey: *const XOnlyPublicKey,
        _tweak32: *const c_uchar,
    ) -> c_int {
        unimplemented!();
    }
}
#[cfg(feature = "fuzztarget")]
pub use self::fuzz_dummy::*;


#[cfg(test)]
mod tests {
    #[no_mangle]
    #[cfg(not(feature = "external-symbols"))]
    #[test]
    fn test_strlen() {
        use std::ffi::CString;
        use super::strlen;

        let orig = "test strlen \t \n";
        let test = CString::new(orig).unwrap();

        assert_eq!(orig.len(), unsafe {strlen(test.as_ptr())});
    }
}

