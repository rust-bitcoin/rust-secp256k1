#![crate_type = "lib"]
#![crate_type = "rlib"]
#![crate_type = "dylib"]
#![crate_id = "github.com/dpc/bitcoin-secp256k1-rs#secp256k1:0.1"]
#![comment = "Bindings and wrapper functions for bitcoin secp256k1 library."]

extern crate libc;
extern crate sync;

use std::rand;
use std::rand::Rng;

use libc::{c_int, c_uchar};
use sync::one::{Once, ONCE_INIT};

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

pub type Nonce = [u8, ..32];
pub type SecKey = [u8, ..32];
pub type PubKeyCompressed = [u8, ..33];
pub type PubKeyUncompressed = [u8, ..65];
pub enum PubKey {
    Compressed(PubKeyCompressed),
    Uncompressed(PubKeyUncompressed)
}
pub type Signature = Vec<u8>;

#[deriving(Show)]
#[deriving(Eq)]
#[deriving(PartialEq)]
pub enum Error {
    InvalidPublicKey,
    InvalidSignature,
    InvalidSecretKey,
    InvalidNonce,
}

#[deriving(Eq)]
#[deriving(PartialEq)]
pub type VerifyResult = Result<bool, Error>;

static mut Secp256k1_init : Once = ONCE_INIT;

pub struct Secp256k1;


impl Secp256k1 {
    pub fn new() -> Secp256k1 {
        unsafe {
            Secp256k1_init.doit(|| {
                secp256k1_start();
            });
        }
        Secp256k1
    }


    pub fn pubkey_create(
        &self,
        pubkey : &mut PubKey,
        seckey : &SecKey
        ) -> Result<(), Error> {

        let (compressed, pub_ptr, pub_len) = match *pubkey {
            Uncompressed(ref mut key) => (false, key.as_mut_ptr(), key.len()),
            Compressed(ref mut key) => (true, key.as_mut_ptr(), key.len()),
        };
        let mut len = pub_len as c_int;
        let res = unsafe {
            secp256k1_ecdsa_pubkey_create(
                pub_ptr, &mut len,
                seckey.as_ptr(),
                if compressed {1} else {0}
                )
        };

        assert_eq!(pub_len as i32, len);

        match res {
            0 => Err(InvalidSecretKey),
            1 => Ok(()),
            _ => fail!("secp256k1_ecdsa_pubkey_create invalid return value"),
        }
    }

    pub fn sign(&self, sig : &mut Signature, msg : &[u8], seckey : &SecKey, nonce : &Nonce) -> Result<(), Error> {

        let origlen = 72u;
        let mut siglen = origlen as c_int;

        if sig.len() != origlen {
            fail!("invalid length of signature buffer");
        }

        let res = unsafe {
            secp256k1_ecdsa_sign(
                msg.as_ptr(), msg.len() as i32,
                sig.as_mut_ptr(), &mut siglen,
                seckey.as_ptr(),
                nonce.as_ptr()
                )
        };

        if (origlen as c_int) < siglen {
            fail!("secp256k1_ecdsa_sign wrong return len");
        }

        match res {
            0 => Err(InvalidNonce),
            1 => { sig.truncate(siglen as uint); Ok(()) },
            _ => fail!("secp256k1_ecdsa_sign invalid return value"),
        }
    }

    pub fn sign_compact(
        &self,
        sig : &mut Signature,
        msg : &[u8],
        seckey : &SecKey,
        nonce : &Nonce
        ) -> Result<i32, Error> {

        let origlen = 64u;

        if sig.len() != origlen {
            fail!("invalid length of signature buffer");
        }

        let mut recid = 0;

        let res = unsafe {
            secp256k1_ecdsa_sign_compact(
                msg.as_ptr(), msg.len() as i32,
                sig.as_mut_ptr(),
                seckey.as_ptr(),
                nonce.as_ptr(),
                &mut recid
                )
        };

        match res {
            0 => Err(InvalidNonce),
            1 => { Ok(recid) },
            _ => fail!("secp256k1_ecdsa_sign_compact invalid return value"),
        }
    }

    pub fn recover_compact(
        &self,
        msg : &[u8],
        sig : &Signature,
        pubkey : &mut PubKey,
        recid : i32
        ) -> Result<(), Error> {

        let (compressed, pub_ptr, pub_len) = match *pubkey {
            Uncompressed(ref mut key) => (false, key.as_mut_ptr(), key.len()),
            Compressed(ref mut key) => (true, key.as_mut_ptr(), key.len()),
        };

        let origlen = 64u;

        if sig.len() != origlen {
            fail!("invalid length of signature buffer");
        }

        let mut len = pub_len as c_int;
        let res = unsafe {
            secp256k1_ecdsa_recover_compact(
                msg.as_ptr(), msg.len() as i32,
                sig.as_ptr(),
                pub_ptr, &mut len,
                if compressed {1} else {0},
                recid
                )
        };

        assert_eq!(pub_len as i32, len);

        match res {
            0 => Err(InvalidSignature),
            1 => Ok(()),
            _ => fail!("secp256k1_ecdsa_recover_compact invalid return value"),
        }
    }


    pub fn verify(&self, msg : &[u8], sig : &Signature, pubkey : &PubKey) -> VerifyResult {

        let (pub_ptr, pub_len) = match *pubkey {
            Uncompressed(ref key) => (key.as_ptr(), key.len()),
            Compressed(ref key) => (key.as_ptr(), key.len()),
        };

        let res = unsafe {
            secp256k1_ecdsa_verify(
                msg.as_ptr(), msg.len() as c_int,
                sig.as_ptr(), sig.len() as c_int,
                pub_ptr, pub_len as c_int
                )
        };

        match res {
            1 => Ok(true),
            0 => Ok(false),
            -1 => Err(InvalidPublicKey),
            -2 => Err(InvalidSignature),
            _ => fail!("secp256k1_ecdsa_verify() invalid return value")
        }
    }
}

#[test]
fn invalid_pubkey() {
    let s = Secp256k1::new();

    let mut msg = Vec::from_elem(32, 0u8);
    let sig = Vec::from_elem(32, 0u8);
    let pubkey = Compressed([0u8, .. 33]);

    rand::task_rng().fill_bytes(msg.as_mut_slice());

    assert_eq!(s.verify(msg.as_mut_slice(), &sig, &pubkey), Err(InvalidPublicKey));
}

#[test]
fn valid_pubkey_uncompressed() {
    let s = Secp256k1::new();

    let seckey = [0u8, ..32];
    let mut pubkey = Uncompressed([0u8, ..65]);
    s.pubkey_create(&mut pubkey, &seckey).unwrap();
    let mut msg = Vec::from_elem(32, 0u8);
    let sig = Vec::from_elem(32, 0u8);

    rand::task_rng().fill_bytes(msg.as_mut_slice());

    assert_eq!(s.verify(msg.as_mut_slice(), &sig, &pubkey), Err(InvalidSignature));
}

#[test]
fn valid_pubkey_compressed() {
    let s = Secp256k1::new();

    let seckey = [0u8, ..32];
    let mut pubkey = Compressed([0u8, .. 33]);
    s.pubkey_create(&mut pubkey, &seckey).unwrap();
    let mut msg = Vec::from_elem(32, 0u8);
    let sig = Vec::from_elem(32, 0u8);

    rand::task_rng().fill_bytes(msg.as_mut_slice());

    assert_eq!(s.verify(msg.as_mut_slice(), &sig, &pubkey), Err(InvalidSignature));
}

#[test]
fn sign() {
    let s = Secp256k1::new();

    let mut msg = [0u8, ..32];
    let mut seckey = [0u8, ..32];
    let mut nonce = [0u8, ..32];
    let mut sig = Vec::from_elem(72, 0u8);
    rand::task_rng().fill_bytes(msg);
    rand::task_rng().fill_bytes(nonce);
    rand::task_rng().fill_bytes(seckey);

    s.sign(&mut sig, msg.as_slice(), &seckey, &nonce).unwrap();
}

#[test]
fn sign_and_verify() {
    let s = Secp256k1::new();

    let mut msg = Vec::from_elem(32, 0u8);
    let mut seckey = [0u8, ..32];
    let mut pubkey = Compressed([0u8, .. 33]);
    let mut nonce = [0u8, ..32];
    let mut sig = Vec::from_elem(72, 0u8);
    rand::task_rng().fill_bytes(msg.as_mut_slice());
    rand::task_rng().fill_bytes(nonce);
    rand::task_rng().fill_bytes(seckey);

    s.pubkey_create(&mut pubkey, &seckey).unwrap();

    s.sign(&mut sig, msg.as_slice(), &seckey, &nonce).unwrap();

    assert_eq!(s.verify(msg.as_slice(), &sig, &pubkey), Ok(true));
}

#[test]
fn sign_and_verify_fail() {
    let s = Secp256k1::new();

    let mut msg = Vec::from_elem(32, 0u8);
    let mut seckey = [0u8, ..32];
    let mut pubkey = Compressed([0u8, .. 33]);
    let mut nonce = [0u8, ..32];
    let mut sig = Vec::from_elem(72, 0u8);
    rand::task_rng().fill_bytes(msg.as_mut_slice());
    rand::task_rng().fill_bytes(nonce);
    rand::task_rng().fill_bytes(seckey);

    s.pubkey_create(&mut pubkey, &seckey).unwrap();
    s.sign(&mut sig, msg.as_slice(), &seckey, &nonce).unwrap();

    rand::task_rng().fill_bytes(msg.as_mut_slice());
    assert_eq!(s.verify(msg.as_slice(), &sig, &pubkey), Ok(false));
}

#[test]
fn sign_compact() {
    let s = Secp256k1::new();

    let mut msg = [0u8, ..32];
    let mut seckey = [0u8, ..32];
    let mut pubkey = Uncompressed([0u8, ..65]);
    let mut nonce = [0u8, ..32];
    let mut sig = Vec::from_elem(64, 0u8);
    rand::task_rng().fill_bytes(msg.as_mut_slice());
    rand::task_rng().fill_bytes(nonce);
    rand::task_rng().fill_bytes(seckey);

    s.pubkey_create(&mut pubkey, &seckey).unwrap();

    let _ = s.sign_compact(&mut sig, msg.as_slice(), &seckey, &nonce).unwrap();

    assert_eq!(s.verify(msg.as_slice(), &sig, &pubkey), Ok(true));
}

#[test]
fn sign_compact_with_recovery() {
    let s = Secp256k1::new();

    let mut msg = [0u8, ..32];
    let mut seckey = [0u8, ..32];
    let mut pubkey = Uncompressed([0u8, ..65]);
    let mut nonce = [0u8, ..32];
    let mut sig = Vec::from_elem(64, 0u8);
    rand::task_rng().fill_bytes(msg.as_mut_slice());
    rand::task_rng().fill_bytes(nonce);
    rand::task_rng().fill_bytes(seckey);

    s.pubkey_create(&mut pubkey, &seckey).unwrap();

    let recid = s.sign_compact(&mut sig, msg.as_slice(), &seckey, &nonce).unwrap();

    s.recover_compact(msg.as_slice(), &sig, &mut pubkey, recid).unwrap();

    assert_eq!(s.verify(msg.as_slice(), &sig, &pubkey), Ok(true));
}


