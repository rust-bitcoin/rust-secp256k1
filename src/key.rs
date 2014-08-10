//! Public/Private keys

use std::fmt;
use std::rand::Rng;
use constants;
use ffi;

use super::Result;

/// Secret 256-bit nonce used as `k` in an ECDSA signature
pub struct Nonce([u8, ..constants::NONCE_SIZE]);

/// Secret 256-bit key used as `x` in an ECDSA signature
pub struct SecretKey([u8, ..constants::SECRET_KEY_SIZE]);

/// Public key
#[deriving(PartialEq, Eq, Show)]
pub struct PublicKey(PublicKeyData);

enum PublicKeyData {
    Compressed([u8, ..constants::COMPRESSED_PUBLIC_KEY_SIZE]),
    Uncompressed([u8, ..constants::UNCOMPRESSED_PUBLIC_KEY_SIZE]),
}

fn random_32_bytes<R:Rng>(rng: &mut R) -> [u8, ..32] {
    [rng.gen(), rng.gen(), rng.gen(), rng.gen(),
     rng.gen(), rng.gen(), rng.gen(), rng.gen(),
     rng.gen(), rng.gen(), rng.gen(), rng.gen(),
     rng.gen(), rng.gen(), rng.gen(), rng.gen(),
     rng.gen(), rng.gen(), rng.gen(), rng.gen(),
     rng.gen(), rng.gen(), rng.gen(), rng.gen(),
     rng.gen(), rng.gen(), rng.gen(), rng.gen(),
     rng.gen(), rng.gen(), rng.gen(), rng.gen()]
}

impl Nonce {
    /// Creates a new random nonce
    #[inline]
    pub fn new<R:Rng>(rng: &mut R) -> Nonce {
        Nonce(random_32_bytes(rng))
    }

    /// Converts the nonce to a raw pointer suitable for use with
    /// the FFI functions
    #[inline]
    pub fn as_ptr(&self) -> *const u8 {
        let &Nonce(ref data) = self;
        data.as_ptr()
    }
}

impl SecretKey {
    /// Creates a new random secret key
    #[inline]
    pub fn new<R:Rng>(rng: &mut R) -> SecretKey {
        SecretKey(random_32_bytes(rng))
    }

    /// Converts the secret key to a raw pointer suitable for use with
    /// the FFI functions
    #[inline]
    pub fn as_ptr(&self) -> *const u8 {
        let &SecretKey(ref data) = self;
        data.as_ptr()
    }
}

impl PublicKey {
    /// Creates a new zeroed out public key
    #[inline]
    pub fn new(compressed: bool) -> PublicKey {
        PublicKey(
            if compressed { Compressed([0, ..constants::COMPRESSED_PUBLIC_KEY_SIZE]) }
            else { Uncompressed([0, ..constants::UNCOMPRESSED_PUBLIC_KEY_SIZE]) }
        )
    }

    /// Creates a new public key from a secret key
    #[inline]
    pub fn from_secret_key(sk: &SecretKey, compressed: bool) -> PublicKey {
        let mut pk = PublicKey::new(compressed);
        let compressed = if compressed {1} else {0};
        unsafe {
            let mut len = 0;
            while ffi::secp256k1_ecdsa_pubkey_create(
                pk.as_mut_ptr(), &mut len,
                sk.as_ptr(), compressed) != 1 {
                // loop
            }
            assert_eq!(len as uint, pk.len()); 
        };
        pk
    }

    /// Returns whether the public key is compressed or uncompressed
    #[inline]
    pub fn is_compressed(&self) -> bool {
        let &PublicKey(ref data) = self;
        match *data {
            Compressed(_) => true,
            Uncompressed(_) => false
        }
    }

    /// Returns the length of the public key
    #[inline]
    pub fn len(&self) -> uint {
        let &PublicKey(ref data) = self;
        match *data {
            Compressed(ref x) => x.len(),
            Uncompressed(ref x) => x.len()
        }
    }

    /// Converts the public key into a byte slice
    #[inline]
    pub fn as_slice<'a>(&'a self) -> &'a [u8] {
        let &PublicKey(ref data) = self;
        data.as_slice()
    }

    /// Converts the public key to a raw pointer suitable for use
    /// with the FFI functions
    #[inline]
    pub fn as_ptr(&self) -> *const u8 {
        let &PublicKey(ref data) = self;
        match *data {
            Compressed(ref x) => x.as_ptr(),
            Uncompressed(ref x) => x.as_ptr()
        }
    }

    /// Converts the public key to a mutable raw pointer suitable for use
    /// with the FFI functions
    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        let &PublicKey(ref mut data) = self;
        match *data {
            Compressed(ref mut x) => x.as_mut_ptr(),
            Uncompressed(ref mut x) => x.as_mut_ptr()
        }
    }
}

impl PublicKeyData {
    #[inline]
    fn as_slice<'a>(&'a self) -> &'a [u8] {
        match *self {
            Compressed(ref x) => x.as_slice(),
            Uncompressed(ref x) => x.as_slice()
        }
    }
}

// We have to do all these impls ourselves as Rust can't derive
// them for arrays
impl PartialEq for PublicKeyData {
    fn eq(&self, other: &PublicKeyData) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl Eq for PublicKeyData {}

impl fmt::Show for PublicKeyData {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.as_slice().fmt(f)
    }
}


