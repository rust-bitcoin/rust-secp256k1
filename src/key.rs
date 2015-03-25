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

use std::intrinsics::copy_nonoverlapping;
use std::cmp;
use std::fmt;
use rand::Rng;
use serialize::{Decoder, Decodable, Encoder, Encodable};

use crypto::digest::Digest;
use crypto::sha2::Sha512;
use crypto::hmac::Hmac;
use crypto::mac::Mac;

use super::init;
use super::Result;
use super::Error::{InvalidNonce, InvalidPublicKey, InvalidSecretKey, Unknown};
use constants;
use ffi;

/// Secret 256-bit nonce used as `k` in an ECDSA signature
pub struct Nonce([u8; constants::NONCE_SIZE]);
impl_array_newtype!(Nonce, u8, constants::NONCE_SIZE);

/// Secret 256-bit key used as `x` in an ECDSA signature
pub struct SecretKey([u8; constants::SECRET_KEY_SIZE]);
impl_array_newtype!(SecretKey, u8, constants::SECRET_KEY_SIZE);

/// The number 1 encoded as a secret key
pub static ONE: SecretKey = SecretKey([0, 0, 0, 0, 0, 0, 0, 0,
                                       0, 0, 0, 0, 0, 0, 0, 0,
                                       0, 0, 0, 0, 0, 0, 0, 0,
                                       0, 0, 0, 0, 0, 0, 0, 1]);

/// Public key
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PublicKey(PublicKeyData);
impl Copy for PublicKey {}

enum PublicKeyData {
    Compressed([u8; constants::COMPRESSED_PUBLIC_KEY_SIZE]),
    Uncompressed([u8; constants::UNCOMPRESSED_PUBLIC_KEY_SIZE])
}
impl Copy for PublicKeyData {}

fn random_32_bytes<R:Rng>(rng: &mut R) -> [u8; 32] {
    let mut ret = [0u8; 32];
    rng.fill_bytes(&mut ret);
    ret
}

/// As described in RFC 6979
fn bits2octets(data: &[u8]) -> [u8; 32] {
    let mut ret = [0; 32];
    unsafe {
        copy_nonoverlapping(ret.as_mut_ptr(),
                            data.as_ptr(),
                            cmp::min(data.len(), 32));
    }
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
                let mut ret = [0; constants::NONCE_SIZE];
                unsafe {
                    copy_nonoverlapping(ret.as_mut_ptr(),
                                        data.as_ptr(),
                                        data.len());
                }
                Ok(Nonce(ret))
            }
            _ => Err(InvalidNonce)
        }
    }

    /// Generates a deterministic nonce by RFC6979 with HMAC-SHA512
    #[inline]
    #[allow(non_snake_case)] // so we can match the names in the RFC
    pub fn deterministic(msg: &[u8], key: &SecretKey) -> Nonce {
        const HMAC_SIZE: usize = 64;

        macro_rules! hmac {
            ($res:expr; key $key:expr, data $($data:expr),+) => ({
                let mut hmacker = Hmac::new(Sha512::new(), $key.as_slice());
                $(hmacker.input($data.as_slice());)+
                hmacker.raw_result($res.as_mut_slice());
            })
        }

        // Section 3.2a
        // Goofy block just to avoid marking `msg_hash` as mutable
        let mut hasher = Sha512::new();
        hasher.input(msg);
        let mut x = [0; HMAC_SIZE];
        hasher.result(x.as_mut_slice());
        let msg_hash = bits2octets(x.as_slice());

        // Section 3.2b
        let mut V = [0x01u8; HMAC_SIZE];
        // Section 3.2c
        let mut K = [0x00u8; HMAC_SIZE];

        // Section 3.2d
        hmac!(K; key K, data V, [0x00], key, msg_hash);

        // Section 3.2e
        hmac!(V; key K, data V);

        // Section 3.2f
        hmac!(K; key K, data V, [0x01], key, msg_hash);

        // Section 3.2g
        hmac!(V; key K, data V);

        // Section 3.2
        let mut k = Err(InvalidSecretKey);
        while k.is_err() {
            // Try to generate the nonce
            let mut T = [0x00u8; HMAC_SIZE];
            hmac!(T; key K, data V);

            k = Nonce::from_slice(T.slice_to(constants::NONCE_SIZE));

            // Replace K, V
            if k.is_err() {
                hmac!(K; key K, data V, [0x00]);
                hmac!(V; key K, data V);
            }
        }

        k.unwrap()
    }
}

impl SecretKey {
    /// Creates a new random secret key
    #[inline]
    pub fn new<R:Rng>(rng: &mut R) -> SecretKey {
        init();
        let mut data = random_32_bytes(rng);
        unsafe {
            while ffi::secp256k1_ec_seckey_verify(data.as_ptr()) == 0 {
                data = random_32_bytes(rng);
            }
        }
        SecretKey(data)
    }

    /// Converts a `SECRET_KEY_SIZE`-byte slice to a secret key
    #[inline]
    pub fn from_slice(data: &[u8]) -> Result<SecretKey> {
        init();
        match data.len() {
            constants::SECRET_KEY_SIZE => {
                let mut ret = [0; constants::SECRET_KEY_SIZE];
                unsafe {
                    if ffi::secp256k1_ec_seckey_verify(data.as_ptr()) == 0 {
                        return Err(InvalidSecretKey);
                    }
                    copy_nonoverlapping(ret.as_mut_ptr(),
                                        data.as_ptr(),
                                        data.len());
                }
                Ok(SecretKey(ret))
            }
            _ => Err(InvalidSecretKey)
        }
    }

    #[inline]
    /// Adds one secret key to another, modulo the curve order
    /// Marked `unsafe` since you must
    /// call `init()` (or construct a `Secp256k1`, which does this for you) before
    /// using this function
    pub fn add_assign(&mut self, other: &SecretKey) -> Result<()> {
        init();
        unsafe {
            if ffi::secp256k1_ec_privkey_tweak_add(self.as_mut_ptr(), other.as_ptr()) != 1 {
                Err(Unknown)
            } else {
                Ok(())
            }
        }
    }

    #[inline]
    /// Returns an iterator for the (sk, pk) pairs starting one after this one,
    /// and incrementing by one each time
    pub fn sequence(&self, compressed: bool) -> Sequence {
        Sequence { last_sk: *self, compressed: compressed }
    }
}

/// An iterator of keypairs `(sk + 1, pk*G)`, `(sk + 2, pk*2G)`, ...
pub struct Sequence {
    compressed: bool,
    last_sk: SecretKey,
}
impl Copy for Sequence {}

impl Iterator for Sequence {
    type Item = (SecretKey, PublicKey);

    #[inline]
    fn next(&mut self) -> Option<(SecretKey, PublicKey)> {
        self.last_sk.add_assign(&ONE).unwrap();
        Some((self.last_sk, PublicKey::from_secret_key(&self.last_sk, self.compressed)))
    }
}

impl PublicKey {
    /// Creates a new zeroed out public key
    #[inline]
    pub fn new(compressed: bool) -> PublicKey {
        PublicKey(
            if compressed {
                PublicKeyData::Compressed([0; constants::COMPRESSED_PUBLIC_KEY_SIZE])
            } else {
                PublicKeyData::Uncompressed([0; constants::UNCOMPRESSED_PUBLIC_KEY_SIZE])
            }
        )
    }

    /// Creates a new public key from a secret key.
    #[inline]
    pub fn from_secret_key(sk: &SecretKey, compressed: bool) -> PublicKey {
        let mut pk = PublicKey::new(compressed);
        let compressed = if compressed {1} else {0};
        let mut len = 0;

        init();
        unsafe {
            // We can assume the return value because it's not possible to construct
            // an invalid `SecretKey` without transmute trickery or something
            assert_eq!(ffi::secp256k1_ec_pubkey_create(
                pk.as_mut_ptr(), &mut len,
                sk.as_ptr(), compressed), 1);
        }
        assert_eq!(len as usize, pk.len()); 
        pk
    }

    /// Creates a public key directly from a slice
    #[inline]
    pub fn from_slice(data: &[u8]) -> Result<PublicKey> {
        match data.len() {
            constants::COMPRESSED_PUBLIC_KEY_SIZE => {
                let mut ret = [0; constants::COMPRESSED_PUBLIC_KEY_SIZE];
                unsafe {
                    if ffi::secp256k1_ec_pubkey_verify(data.as_ptr(),
                                                          data.len() as ::libc::c_int) == 0 {
                        return Err(InvalidPublicKey);
                    }
                    copy_nonoverlapping(ret.as_mut_ptr(),
                                        data.as_ptr(),
                                        data.len());
                }
                Ok(PublicKey(PublicKeyData::Compressed(ret)))
            }
            constants::UNCOMPRESSED_PUBLIC_KEY_SIZE => {
                let mut ret = [0; constants::UNCOMPRESSED_PUBLIC_KEY_SIZE];
                unsafe {
                    copy_nonoverlapping(ret.as_mut_ptr(),
                                        data.as_ptr(),
                                        data.len());
                }
                Ok(PublicKey(PublicKeyData::Uncompressed(ret)))
            }
            _ => Err(InvalidPublicKey)
        }
    }

    /// Returns whether the public key is compressed or uncompressed
    #[inline]
    pub fn is_compressed(&self) -> bool {
        let &PublicKey(ref data) = self;
        match *data {
            PublicKeyData::Compressed(_) => true,
            PublicKeyData::Uncompressed(_) => false
        }
    }

    /// Returns the length of the public key
    #[inline]
    pub fn len(&self) -> usize {
        let &PublicKey(ref data) = self;
        match *data {
            PublicKeyData::Compressed(ref x) => x.len(),
            PublicKeyData::Uncompressed(ref x) => x.len()
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
            PublicKeyData::Compressed(ref x) => x.as_ptr(),
            PublicKeyData::Uncompressed(ref x) => x.as_ptr()
        }
    }

    /// Converts the public key to a mutable raw pointer suitable for use
    /// with the FFI functions
    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        let &mut PublicKey(ref mut data) = self;
        match *data {
            PublicKeyData::Compressed(ref mut x) => x.as_mut_ptr(),
            PublicKeyData::Uncompressed(ref mut x) => x.as_mut_ptr()
        }
    }

    #[inline]
    /// Adds the pk corresponding to `other` to the pk `self` in place
    pub fn add_exp_assign(&mut self, other: &SecretKey) -> Result<()> {
        init();
        unsafe {
            if ffi::secp256k1_ec_pubkey_tweak_add(self.as_mut_ptr(),
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
            PublicKeyData::Compressed(ref x) => x.as_slice(),
            PublicKeyData::Uncompressed(ref x) => x.as_slice()
        }
    }
}

// We have to do all these impls ourselves as Rust can't derive
// them for arrays
impl fmt::Debug for Nonce {
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

impl fmt::Debug for PublicKeyData {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.as_slice().fmt(f)
    }
}

impl Decodable for PublicKey {
    fn decode<D: Decoder>(d: &mut D) -> ::std::result::Result<PublicKey, D::Error> {
        d.read_seq(|d, len| {
            if len == constants::UNCOMPRESSED_PUBLIC_KEY_SIZE {
                unsafe {
                    use std::mem;
                    let mut ret: [u8; constants::UNCOMPRESSED_PUBLIC_KEY_SIZE] = mem::uninitialized();
                    for i in 0..len {
                        ret[i] = try!(d.read_seq_elt(i, |d| Decodable::decode(d)));
                    }
                    Ok(PublicKey(PublicKeyData::Uncompressed(ret)))
                }
            } else if len == constants::COMPRESSED_PUBLIC_KEY_SIZE {
                unsafe {
                    use std::mem;
                    let mut ret: [u8; constants::COMPRESSED_PUBLIC_KEY_SIZE] = mem::uninitialized();
                    for i in 0..len {
                        ret[i] = try!(d.read_seq_elt(i, |d| Decodable::decode(d)));
                    }
                    Ok(PublicKey(PublicKeyData::Compressed(ret)))
                }
            } else {
                Err(d.error("Invalid length"))
            }
        })
    }
}

impl Encodable for PublicKey {
    fn encode<S: Encoder>(&self, s: &mut S) -> ::std::result::Result<(), S::Error> {
        self.as_slice().encode(s)
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.as_slice().fmt(f)
    }
}

#[cfg(test)]
mod test {
    use serialize::hex::FromHex;
    use std::rand::thread_rng;

    use test::Bencher;

    use super::super::Secp256k1;
    use super::super::Error::{InvalidNonce, InvalidPublicKey, InvalidSecretKey};
    use super::{Nonce, PublicKey, SecretKey};

    #[test]
    fn nonce_from_slice() {
        let n = Nonce::from_slice(&[1; 31]);
        assert_eq!(n, Err(InvalidNonce));

        let n = SecretKey::from_slice(&[1; 32]);
        assert!(n.is_ok());
    }

    #[test]
    fn skey_from_slice() {
        let sk = SecretKey::from_slice(&[1; 31]);
        assert_eq!(sk, Err(InvalidSecretKey));

        let sk = SecretKey::from_slice(&[1; 32]);
        assert!(sk.is_ok());
    }

    #[test]
    fn pubkey_from_slice() {
        assert_eq!(PublicKey::from_slice(&[]), Err(InvalidPublicKey));
        assert_eq!(PublicKey::from_slice(&[1, 2, 3]), Err(InvalidPublicKey));

        let uncompressed = PublicKey::from_slice(&[4, 54, 57, 149, 239, 162, 148, 175, 246, 254, 239, 75, 154, 152, 10, 82, 234, 224, 85, 220, 40, 100, 57, 121, 30, 162, 94, 156, 135, 67, 74, 49, 179, 57, 236, 53, 162, 124, 149, 144, 168, 77, 74, 30, 72, 211, 229, 110, 111, 55, 96, 193, 86, 227, 183, 152, 195, 155, 51, 247, 123, 113, 60, 228, 188]);
        assert!(uncompressed.is_ok());
        assert!(!uncompressed.unwrap().is_compressed());

        let compressed = PublicKey::from_slice(&[3, 23, 183, 225, 206, 31, 159, 148, 195, 42, 67, 115, 146, 41, 248, 140, 11, 3, 51, 41, 111, 180, 110, 143, 114, 134, 88, 73, 198, 174, 52, 184, 78]);
        assert!(compressed.is_ok());
        assert!(compressed.unwrap().is_compressed());
    }

    #[test]
    fn keypair_slice_round_trip() {
        let mut s = Secp256k1::new().unwrap();

        let (sk1, pk1) = s.generate_keypair(true);
        assert_eq!(SecretKey::from_slice(sk1.as_slice()), Ok(sk1));
        assert_eq!(PublicKey::from_slice(pk1.as_slice()), Ok(pk1));

        let (sk2, pk2) = s.generate_keypair(false);
        assert_eq!(SecretKey::from_slice(sk2.as_slice()), Ok(sk2));
        assert_eq!(PublicKey::from_slice(pk2.as_slice()), Ok(pk2));
    }

    #[test]
    fn nonce_slice_round_trip() {
        let mut rng = thread_rng();
        let nonce = Nonce::new(&mut rng);
        assert_eq!(Nonce::from_slice(nonce.as_slice()), Ok(nonce));
    }

    #[test]
    fn invalid_secret_key() {
        // Zero
        assert_eq!(SecretKey::from_slice(&[0; 32]), Err(InvalidSecretKey));
        // -1
        assert_eq!(SecretKey::from_slice(&[0xff; 32]), Err(InvalidSecretKey));
        // Top of range
        assert!(SecretKey::from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
                                        0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
                                        0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x40]).is_ok());
        // One past top of range
        assert!(SecretKey::from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
                                        0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
                                        0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41]).is_err());
    }

    #[test]
    fn test_addition() {
        let mut s = Secp256k1::new().unwrap();

        let (mut sk1, mut pk1) = s.generate_keypair(true);
        let (mut sk2, mut pk2) = s.generate_keypair(true);

        assert_eq!(PublicKey::from_secret_key(&sk1, true), pk1);
        assert!(sk1.add_assign(&sk2).is_ok());
        assert!(pk1.add_exp_assign(&sk2).is_ok());
        assert_eq!(PublicKey::from_secret_key(&sk1, true), pk1);

        assert_eq!(PublicKey::from_secret_key(&sk2, true), pk2);
        assert!(sk2.add_assign(&sk1).is_ok());
        assert!(pk2.add_exp_assign(&sk1).is_ok());
        assert_eq!(PublicKey::from_secret_key(&sk2, true), pk2);
    }

    #[test]
    fn test_deterministic() {
        // nb code in comments is equivalent python

        // from ecdsa import rfc6979
        // from ecdsa.curves import SECP256k1
        // # This key was generated randomly
        // sk = 0x09e918bbea76205445e9a73eaad2080a135d1e33e9dd1b3ca8a9a1285e7c1f81
        let sk = SecretKey::from_slice(hex_slice!("09e918bbea76205445e9a73eaad2080a135d1e33e9dd1b3ca8a9a1285e7c1f81")).unwrap();

        // "%x" % rfc6979.generate_k(SECP256k1.generator, sk, hashlib.sha512, hashlib.sha512('').digest())
        let nonce = Nonce::deterministic(&[], &sk);
        assert_eq!(nonce.as_slice(),
                   hex_slice!("d954eddd184cac2b60edcd0e6be9ec54d93f633b28b366420d38ed9c346ffe27"));

        // "%x" % rfc6979.generate_k(SECP256k1.generator, sk, hashlib.sha512, hashlib.sha512('test').digest())
        let nonce = Nonce::deterministic(b"test", &sk);
        assert_eq!(nonce.as_slice(),
                   hex_slice!("609cc24acce2f19e46e38a82afc56c1745dee16e04f2b27e24999e1fefeb08bd"));

        // # Decrease the secret key by one
        // sk = 0x09e918bbea76205445e9a73eaad2080a135d1e33e9dd1b3ca8a9a1285e7c1f80
        let sk = SecretKey::from_slice(hex_slice!("09e918bbea76205445e9a73eaad2080a135d1e33e9dd1b3ca8a9a1285e7c1f80")).unwrap();

        // "%x" % rfc6979.generate_k(SECP256k1.generator, sk, hashlib.sha512, hashlib.sha512('').digest())
        let nonce = Nonce::deterministic(&[], &sk);
        assert_eq!(nonce.as_slice(),
                   hex_slice!("9f45f8d0a28e8956673c8da6db3db86ca4f172f0a2dbd62364fdbf786c7d96df"));

        // "%x" % rfc6979.generate_k(SECP256k1.generator, sk, hashlib.sha512, hashlib.sha512('test').digest())
        let nonce = Nonce::deterministic(b"test", &sk);
        assert_eq!(nonce.as_slice(),
                   hex_slice!("355c589ff662c838aee454d62b12c50a87b7e95ede2431c7cfa40b6ba2fddccd"));
    }

    #[bench]
    pub fn sequence_iterate(bh: &mut Bencher) {
        let mut s = Secp256k1::new().unwrap();
        let (sk, _) = s.generate_keypair(true);
        let mut iter = sk.sequence(true);
        bh.iter(|| iter.next())
    }
}


