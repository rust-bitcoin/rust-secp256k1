
//! FFI bindings
use libc::{c_int, c_uchar};

#[link(name = "secp256k1")]
extern "C" {
    pub fn secp256k1_start();
    pub fn secp256k1_stop();
    pub fn secp256k1_ecdsa_verify(
        msg : *const c_uchar, msglen : c_int,
        sig : *const c_uchar, siglen : c_int,
        pubkey : *const c_uchar, pubkeylen : c_int
        ) -> c_int;

    pub fn secp256k1_ecdsa_pubkey_create(
        pubkey : *mut c_uchar,
        pubkeylen : *mut c_int,
        seckey : *const c_uchar,
        compressed : c_int
        ) -> c_int;

    pub fn secp256k1_ecdsa_sign(
        msg : *const c_uchar, msglen : c_int,
        sig : *mut c_uchar, siglen : *mut c_int,
        seckey : *const c_uchar,
        nonce : *const c_uchar
        ) -> c_int;

    pub fn secp256k1_ecdsa_sign_compact(
        msg : *const c_uchar, msglen : c_int,
        sig64 : *mut c_uchar,
        seckey : *const c_uchar,
        nonce : *const c_uchar,
        recid : *mut c_int
        ) -> c_int;

    pub fn secp256k1_ecdsa_recover_compact(
        msg : *const c_uchar, msglen : c_int,
        sig64 : *const c_uchar,
        pubkey : *mut c_uchar,
        pubkeylen : *mut c_int,
        compressed : c_int,
        recid : c_int
        ) -> c_int;
}

