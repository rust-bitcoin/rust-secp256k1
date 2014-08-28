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

use std::intrinsics::copy_nonoverlapping_memory;
use std::fmt;
use std::rand::Rng;
use constants;
use ffi;

use super::{Result, InvalidNonce, InvalidPublicKey, InvalidSecretKey, Unknown};

/// Secret 256-bit nonce used as `k` in an ECDSA signature
pub struct Nonce([u8, ..constants::NONCE_SIZE]);
impl_array_newtype!(Nonce, u8, constants::NONCE_SIZE)

/// Secret 256-bit key used as `x` in an ECDSA signature
pub struct SecretKey([u8, ..constants::SECRET_KEY_SIZE]);
impl_array_newtype!(SecretKey, u8, constants::SECRET_KEY_SIZE)

/// Public key
#[deriving(Clone, PartialEq, Eq, Show)]
pub struct PublicKey(PublicKeyData);

enum PublicKeyData {
    Compressed([u8, ..constants::COMPRESSED_PUBLIC_KEY_SIZE]),
    Uncompressed([u8, ..constants::UNCOMPRESSED_PUBLIC_KEY_SIZE]),
}

fn random_32_bytes<R:Rng>(rng: &mut R) -> [u8, ..32] {
    let mut ret = [0u8, ..32];
    rng.fill_bytes(ret);
    ret
}

impl Nonce {
    /// Creates a new random nonce
    #[inline]
    pub fn new<R:Rng>(rng: &mut R) -> Nonce {
        Nonce(random_32_bytes(rng))
    }

    /// Converts a `NONCE_SIZE`-byte slice to a nonce
    #[inline]
    pub fn from_slice(data: &[u8]) -> Result<Nonce> {
        match data.len() {
            constants::NONCE_SIZE => {
                let mut ret = [0, ..constants::NONCE_SIZE];
                unsafe {
                    copy_nonoverlapping_memory(ret.as_mut_ptr(),
                                               data.as_ptr(),
                                               data.len());
                }
                Ok(Nonce(ret))
            }
            _ => Err(InvalidNonce)
        }
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
    pub fn from_slice(data: &[u8]) -> Result<SecretKey> {
        match data.len() {
            constants::SECRET_KEY_SIZE => {
                let mut ret = [0, ..constants::SECRET_KEY_SIZE];
                unsafe {
                    copy_nonoverlapping_memory(ret.as_mut_ptr(),
                                               data.as_ptr(),
                                               data.len());
                    if ffi::secp256k1_ecdsa_seckey_verify(data.as_ptr()) == 0 {
                        return Err(InvalidSecretKey);
                    }
                }
                Ok(SecretKey(ret))
            }
            _ => Err(InvalidSecretKey)
        }
    }

    #[inline]
    /// Adds one secret key to another, modulo the curve order
    pub fn add_assign(&mut self, other: &SecretKey) -> Result<()> {
        unsafe {
            if ffi::secp256k1_ecdsa_privkey_tweak_add(self.as_mut_ptr(), other.as_ptr()) != 1 {
                Err(Unknown)
            } else {
                Ok(())
            }
        }
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

    /// Creates a public key directly from a slice
    #[inline]
    pub fn from_slice(data: &[u8]) -> Result<PublicKey> {
        match data.len() {
            constants::COMPRESSED_PUBLIC_KEY_SIZE => {
                let mut ret = [0, ..constants::COMPRESSED_PUBLIC_KEY_SIZE];
                unsafe {
                    copy_nonoverlapping_memory(ret.as_mut_ptr(),
                                               data.as_ptr(),
                                               data.len());
                }
                Ok(PublicKey(Compressed(ret)))
            }
            constants::UNCOMPRESSED_PUBLIC_KEY_SIZE => {
                let mut ret = [0, ..constants::UNCOMPRESSED_PUBLIC_KEY_SIZE];
                unsafe {
                    copy_nonoverlapping_memory(ret.as_mut_ptr(),
                                               data.as_ptr(),
                                               data.len());
                }
                Ok(PublicKey(Uncompressed(ret)))
            }
            _ => Err(InvalidPublicKey)
        }
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

    #[inline]
    /// Adds the pk corresponding to `other` to the pk `self` in place
    pub fn add_exp_assign(&mut self, other: &SecretKey) -> Result<()> {
        unsafe {
            if ffi::secp256k1_ecdsa_pubkey_tweak_add(self.as_mut_ptr(),
                                                     self.len() as ::libc::c_int,
                                                     other.as_ptr()) != 1 {
                Err(Unknown)
            } else {
                Ok(())
            }
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
impl fmt::Show for Nonce {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.as_slice().fmt(f)
    }
}

impl Clone for PublicKeyData {
    fn clone(&self) -> PublicKeyData { *self }
}

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

impl fmt::Show for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.as_slice().fmt(f)
    }
}

#[cfg(test)]
mod test {
    use std::rand::task_rng;

    use super::super::{Secp256k1, InvalidNonce, InvalidPublicKey, InvalidSecretKey};
    use super::{Nonce, PublicKey, SecretKey};

    #[test]
    fn nonce_from_slice() {
        let n = Nonce::from_slice([1, ..31]);
        assert_eq!(n, Err(InvalidNonce));

        let n = SecretKey::from_slice([1, ..32]);
        assert!(n.is_ok());
    }

    #[test]
    fn skey_from_slice() {
        let sk = SecretKey::from_slice([1, ..31]);
        assert_eq!(sk, Err(InvalidSecretKey));

        let sk = SecretKey::from_slice([1, ..32]);
        assert!(sk.is_ok());
    }

    #[test]
    fn pubkey_from_slice() {
        assert_eq!(PublicKey::from_slice([]), Err(InvalidPublicKey));
        assert_eq!(PublicKey::from_slice([1, 2, 3]), Err(InvalidPublicKey));

        let uncompressed = PublicKey::from_slice([1, ..65]);
        assert!(uncompressed.is_ok());
        assert!(!uncompressed.unwrap().is_compressed());

        let compressed = PublicKey::from_slice([1, ..33]);
        assert!(compressed.is_ok());
        assert!(compressed.unwrap().is_compressed());
    }

    #[test]
    fn keypair_slice_round_trip() {
        let mut s = Secp256k1::new();

        let (sk1, pk1) = s.generate_keypair(true).unwrap();
        assert_eq!(SecretKey::from_slice(sk1.as_slice()), Ok(sk1));
        assert_eq!(PublicKey::from_slice(pk1.as_slice()), Ok(pk1));

        let (sk2, pk2) = s.generate_keypair(false).unwrap();
        assert_eq!(SecretKey::from_slice(sk2.as_slice()), Ok(sk2));
        assert_eq!(PublicKey::from_slice(pk2.as_slice()), Ok(pk2));
    }

    #[test]
    fn nonce_slice_round_trip() {
        let mut rng = task_rng();
        let nonce = Nonce::new(&mut rng);
        assert_eq!(Nonce::from_slice(nonce.as_slice()), Ok(nonce));
    }

    #[test]
    fn invalid_secret_key() {
        // Zero
        assert_eq!(SecretKey::from_slice([0, ..32]), Err(InvalidSecretKey));
        // -1
        assert_eq!(SecretKey::from_slice([0xff, ..32]), Err(InvalidSecretKey));
        // Top of range
        assert!(SecretKey::from_slice([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                       0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
                                       0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
                                       0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x40]).is_ok());
        // One past top of range
        assert!(SecretKey::from_slice([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                       0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
                                       0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
                                       0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41]).is_err());
    }

    #[test]
    fn test_addition() {
        let mut s = Secp256k1::new();

        let (mut sk1, mut pk1) = s.generate_keypair(true).unwrap();
        let (mut sk2, mut pk2) = s.generate_keypair(true).unwrap();

        unsafe {
            assert_eq!(PublicKey::from_secret_key(&sk1, true), pk1);
            assert!(sk1.add_assign(&sk2).is_ok());
            assert!(pk1.add_exp_assign(&sk2).is_ok());
            assert_eq!(PublicKey::from_secret_key(&sk1, true), pk1);

            assert_eq!(PublicKey::from_secret_key(&sk2, true), pk2);
            assert!(sk2.add_assign(&sk1).is_ok());
            assert!(pk2.add_exp_assign(&sk1).is_ok());
            assert_eq!(PublicKey::from_secret_key(&sk2, true), pk2);
        }
    }
}


