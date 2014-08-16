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

//! Public/Private keys

use std::intrinsics::transmute;
use std::fmt;
use std::rand::Rng;
use constants;
use ffi;

use super::{Result, InvalidNonce, InvalidPublicKey, InvalidSecretKey};

/// Secret 256-bit nonce used as `k` in an ECDSA signature
pub struct Nonce([u8, ..constants::NONCE_SIZE]);

/// Secret 256-bit key used as `x` in an ECDSA signature
pub struct SecretKey([u8, ..constants::SECRET_KEY_SIZE]);

/// Public key
#[deriving(PartialEq, Eq, Show)]
pub enum PublicKey {
    /// Compressed version of the PublicKey
    Compressed(CompressedPublicKey),
    /// Uncompressed version of the PublicKey
    Uncompressed(UncompressedPublicKey),
}

/// Uncompressed Public key
pub struct UncompressedPublicKey([u8, ..constants::UNCOMPRESSED_PUBLIC_KEY_SIZE]);

/// Compressed Public key
pub struct CompressedPublicKey([u8, ..constants::COMPRESSED_PUBLIC_KEY_SIZE]);

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

    /// Converts a `NONCE_SIZE`-byte slice to a nonce
    #[inline]
    pub fn from_slice<'a>(data: &'a [u8]) -> Result<&'a Nonce> {
        match data.len() {
            constants::NONCE_SIZE => {
                Ok(unsafe {
                    transmute(data.as_ptr())
                })
            },
            _ => Err(InvalidNonce)
        }
    }

    /// Converts the nonce into a byte slice
    #[inline]
    pub fn as_slice<'a>(&'a self) -> &'a [u8] {
        let &Nonce(ref data) = self;
        data.as_slice()
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

    /// Converts a `SECRET_KEY_SIZE`-byte slice to a secret key
    #[inline]
    pub fn from_slice<'a>(data: &'a [u8]) -> Result<&'a SecretKey> {
        match data.len() {
            constants::SECRET_KEY_SIZE => {
                Ok(unsafe {
                    transmute(data.as_ptr())
                })
            },
            _ => Err(InvalidSecretKey)
        }
    }

    /// Converts the secret key into a byte slice
    #[inline]
    pub fn as_slice<'a>(&'a self) -> &'a [u8] {
        let &SecretKey(ref data) = self;
        data.as_slice()
    }

    /// Converts the secret key to a raw pointer suitable for use with
    /// the FFI functions
    #[inline]
    pub fn as_ptr(&self) -> *const u8 {
        let &SecretKey(ref data) = self;
        data.as_ptr()
    }
}

/// Trait for generics that want to work on both `CompressedPublicKey` and `UncompressedPublicKey`
pub trait PublicKeyTrait {
    /// Returns whether the public key is compressed or uncompressed
    fn is_compressed(&self) -> bool;

    /// Returns the length of the public key
    fn len(&self) -> uint;

    /// Converts the public key to a raw pointer suitable for use
    /// with the FFI functions
    fn as_ptr(&self) -> *const u8;

    /// Converts the public key to a raw pointer suitable for use
    /// with the FFI functions
    fn as_mut_ptr(&mut self) -> *mut u8;

    /// Converts the public key into a byte slice
    #[inline]
    fn as_slice<'a>(&'a self) -> &'a [u8];
}

impl PublicKey {
    /// Creates a new zeroed out public key
    #[inline]
    pub fn new(compressed: bool) -> PublicKey {
        if compressed {
            Compressed(CompressedPublicKey([0, ..constants::COMPRESSED_PUBLIC_KEY_SIZE]))
        } else {
            Uncompressed(UncompressedPublicKey([0, ..constants::UNCOMPRESSED_PUBLIC_KEY_SIZE]))
        }
    }

    /// Creates a new public key from a secret key. Marked `unsafe` since you must
    /// call `init()` (or construct a `Secp256k1`, which does this for you) before
    /// using this function
    #[inline]
    pub unsafe fn from_secret_key(sk: &SecretKey, compressed: bool) -> PublicKey {
        let mut pk = PublicKey::new(compressed);
        let compressed = if compressed {1} else {0};
        let mut len = 0;

        while ffi::secp256k1_ecdsa_pubkey_create(
            pk.as_mut_ptr(), &mut len,
            sk.as_ptr(), compressed) != 1 {
            // loop
        }
        assert_eq!(len as uint, pk.len());

        pk
    }

}

impl PublicKeyTrait for PublicKey {
    #[inline]
    fn is_compressed(&self) -> bool {
        match *self {
            Compressed(_) => true,
            Uncompressed(_) => false,
        }
    }

    #[inline]
    fn len(&self) -> uint {
        match *self {
            Compressed(CompressedPublicKey(ref x)) => x.len(),
            Uncompressed(UncompressedPublicKey(ref x)) => x.len(),
        }
    }

    #[inline]
    fn as_slice<'a>(&'a self) -> &'a [u8] {
        match *self {
            Compressed(CompressedPublicKey(ref x)) => x.as_slice(),
            Uncompressed(UncompressedPublicKey(ref x)) => x.as_slice(),
        }
    }

    #[inline]
    fn as_ptr(&self) -> *const u8 {
        match *self {
            Compressed(CompressedPublicKey(ref x)) => x.as_ptr(),
            Uncompressed(UncompressedPublicKey(ref x)) => x.as_ptr(),
        }
    }

    #[inline]
    fn as_mut_ptr(&mut self) -> *mut u8 {
        match *self {
            Compressed(CompressedPublicKey(ref mut x)) => x.as_mut_ptr(),
            Uncompressed(UncompressedPublicKey(ref mut x)) => x.as_mut_ptr(),
        }
    }
}

impl UncompressedPublicKey {
    /// Creates a public key directly from a slice
    #[inline]
    pub fn from_slice<'a>(data: &'a [u8]) -> Result<&'a UncompressedPublicKey> {
        match data.len() {
            constants::UNCOMPRESSED_PUBLIC_KEY_SIZE => {
                Ok(unsafe {
                    transmute(data.as_ptr())
                })
            },
            _ => Err(InvalidPublicKey)
        }
    }

    /// Converts the public key into a byte slice
    #[inline]
    pub fn as_slice<'a>(&'a self) -> &'a [u8] {
        match *self {
            UncompressedPublicKey(ref x) => x.as_slice(),
        }
    }
}

impl CompressedPublicKey {
    /// Creates a public key directly from a slice
    #[inline]
    pub fn from_slice<'a>(data: &'a [u8]) -> Result<&'a CompressedPublicKey> {
        match data.len() {
            constants::COMPRESSED_PUBLIC_KEY_SIZE => {
                Ok(unsafe {
                    transmute(data.as_ptr())
                })
            },
            _ => Err(InvalidPublicKey)
        }
    }

    /// Converts the public key into a byte slice
    #[inline]
    pub fn as_slice<'a>(&'a self) -> &'a [u8] {
        match *self {
            CompressedPublicKey(ref x) => x.as_slice(),
        }
    }
}

impl PublicKeyTrait for CompressedPublicKey {
    #[inline]
    fn is_compressed(&self) -> bool {
        true
    }

    #[inline]
    fn len(&self) -> uint {
        constants::COMPRESSED_PUBLIC_KEY_SIZE
    }

    #[inline]
    fn as_slice<'a>(&'a self) -> &'a [u8] {
        match *self {
            CompressedPublicKey(ref x) => x.as_slice(),
        }
    }

    #[inline]
    fn as_ptr(&self) -> *const u8 {
        match *self {
            CompressedPublicKey(ref x) => x.as_ptr(),
        }
    }

    #[inline]
    fn as_mut_ptr(&mut self) -> *mut u8 {
        match *self {
            CompressedPublicKey(ref mut x) => x.as_mut_ptr(),
        }
    }
}

impl PublicKeyTrait for UncompressedPublicKey {
    #[inline]
    fn is_compressed(&self) -> bool {
        false
    }

    #[inline]
    fn len(&self) -> uint {
        constants::UNCOMPRESSED_PUBLIC_KEY_SIZE
    }

    #[inline]
    fn as_slice<'a>(&'a self) -> &'a [u8] {
        match *self {
            UncompressedPublicKey(ref x) => x.as_slice(),
        }
    }

    #[inline]
    fn as_ptr(&self) -> *const u8 {
        match *self {
            UncompressedPublicKey(ref x) => x.as_ptr(),
        }
    }

    #[inline]
    fn as_mut_ptr(&mut self) -> *mut u8 {
        match *self {
            UncompressedPublicKey(ref mut x) => x.as_mut_ptr(),
        }
    }
}

// We have to do all these impls ourselves as Rust can't derive
// them for arrays
impl PartialEq for Nonce {
    fn eq(&self, other: &Nonce) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl Eq for Nonce {}

impl fmt::Show for Nonce {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.as_slice().fmt(f)
    }
}
// TODO: Switch to generics
// impl<T : PublicKeyTrait> PartialEq for T {
// after this is fixed with: https://github.com/rust-lang/rfcs/blob/master/active/0024-traits.md
impl PartialEq for CompressedPublicKey {
    fn eq(&self, other: &CompressedPublicKey) -> bool {
        self.as_slice() == other.as_slice()
    }
}
impl PartialEq for UncompressedPublicKey {
    fn eq(&self, other: &UncompressedPublicKey) -> bool {
        self.as_slice() == other.as_slice()
    }
}
impl Eq for CompressedPublicKey {}
impl Eq for UncompressedPublicKey {}


impl fmt::Show for CompressedPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.as_slice().fmt(f)
    }
}
impl fmt::Show for UncompressedPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.as_slice().fmt(f)
    }
}

impl PartialEq for SecretKey {
    fn eq(&self, other: &SecretKey) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl Eq for SecretKey {}

impl fmt::Show for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.as_slice().fmt(f)
    }
}

#[cfg(test)]
mod test {
    use std::rand::task_rng;

    use super::super::{Secp256k1, InvalidNonce, InvalidPublicKey, InvalidSecretKey};
    use super::*;

    #[test]
    fn nonce_from_slice() {
        let bad_arr = [1, ..31];
        let n = Nonce::from_slice(bad_arr);
        assert_eq!(n, Err(InvalidNonce));

        let good_arr = [1, ..32];
        let n = SecretKey::from_slice(good_arr);
        assert!(n.is_ok());
    }

    #[test]
    fn skey_from_slice() {
        let bad_arr = [1, ..31];
        let sk = SecretKey::from_slice(bad_arr);
        assert_eq!(sk, Err(InvalidSecretKey));

        let good_arr = [1, ..32];
        let sk = SecretKey::from_slice(good_arr);
        assert!(sk.is_ok());
    }

    #[test]
    fn pubkey_from_slice() {
        assert_eq!(UncompressedPublicKey::from_slice([]), Err(InvalidPublicKey));
        assert_eq!(CompressedPublicKey::from_slice([]), Err(InvalidPublicKey));
        assert_eq!(UncompressedPublicKey::from_slice([1, 2, 3]), Err(InvalidPublicKey));
        assert_eq!(CompressedPublicKey::from_slice([1, 2, 3]), Err(InvalidPublicKey));

        let arr = [1, ..65];
        let uncompressed = UncompressedPublicKey::from_slice(arr);
        assert!(uncompressed.is_ok());
        assert!(!uncompressed.unwrap().is_compressed());

        let arr = [1, ..33];
        let compressed = CompressedPublicKey::from_slice(arr);
        assert!(compressed.is_ok());
        assert!(compressed.unwrap().is_compressed());
    }

    #[test]
    fn keypair_slice_round_trip() {
        let mut s = Secp256k1::new();

        let (sk1, pk1) = s.generate_keypair(true).unwrap();
        assert_eq!(*SecretKey::from_slice(sk1.as_slice()).unwrap(), sk1);
        assert_eq!(Compressed(*CompressedPublicKey::from_slice(pk1.as_slice()).unwrap()), pk1);

        let (sk2, pk2) = s.generate_keypair(false).unwrap();
        assert_eq!(*SecretKey::from_slice(sk2.as_slice()).unwrap(), sk2);
        assert_eq!(Uncompressed(*UncompressedPublicKey::from_slice(pk2.as_slice()).unwrap()), pk2);
    }

    #[test]
    fn nonce_slice_round_trip() {
        let mut rng = task_rng();
        let nonce = Nonce::new(&mut rng);
        assert_eq!(*Nonce::from_slice(nonce.as_slice()).unwrap(), nonce);
    }
}


