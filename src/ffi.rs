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
                                        attempt: c_uint,
                                        data: *const c_void);

#[link(name = "secp256k1")]
extern "C" {
    pub static secp256k1_nonce_function_rfc6979: NonceFn;

    pub static secp256k1_nonce_function_default: NonceFn;

    pub fn secp256k1_start(flags: c_uint);

    pub fn secp256k1_stop();

    pub fn secp256k1_ecdsa_verify(msg32: *const c_uchar,
                                  sig: *const c_uchar, sig_len: c_int,
                                  pk: *const c_uchar, pk_len: c_int)
                                  -> c_int;

    pub fn secp256k1_ec_pubkey_create(pk: *mut c_uchar, pk_len: *mut c_int,
                                      sk: *const c_uchar, compressed: c_int)
                                      -> c_int;

    pub fn secp256k1_ecdsa_sign(msg32: *const c_uchar,
                                sig: *mut c_uchar, sig_len: *mut c_int,
                                sk: *const c_uchar,
                                noncefn: NonceFn, noncedata: *const c_void)
                                -> c_int;

    pub fn secp256k1_ecdsa_sign_compact(msg: *const c_uchar,
                                        sig64: *mut c_uchar, sk: *const c_uchar,
                                        noncefn: NonceFn, noncedata: *const c_void,
                                        recid: *mut c_int)
                                        -> c_int;

    pub fn secp256k1_ecdsa_recover_compact(msg32: *const c_uchar,
                                           sig64: *const c_uchar, pk: *mut c_uchar,
                                           pk_len: *mut c_int, compressed: c_int,
                                           recid: c_int) -> c_int;

    pub fn secp256k1_ec_seckey_verify(sk: *const c_uchar) -> c_int;

    pub fn secp256k1_ec_pubkey_verify(pk: *const c_uchar,
                                      pk_len: c_int) -> c_int;

//TODO secp256k1_ec_pubkey_decompress
//TODO secp256k1_ec_privkey_export
//TODO secp256k1_ec_privkey_import

    pub fn secp256k1_ec_privkey_tweak_add(sk: *mut c_uchar,
                                          tweak: *const c_uchar)
                                          -> c_int;

    pub fn secp256k1_ec_pubkey_tweak_add(pk: *mut c_uchar,
                                         pk_len: c_int,
                                         tweak: *const c_uchar)
                                         -> c_int;

    pub fn secp256k1_ec_privkey_tweak_mul(sk: *mut c_uchar,
                                          tweak: *const c_uchar)
                                          -> c_int;

    pub fn secp256k1_ec_pubkey_tweak_mul(pk: *mut c_uchar,
                                         pk_len: c_int,
                                         tweak: *const c_uchar)
                                         -> c_int;
}

