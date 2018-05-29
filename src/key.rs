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

//! # Public and secret keys

#[cfg(any(test, feature = "rand"))] use rand::Rng;

use std::mem;

use super::{Secp256k1, ContextFlag};
use super::Error::{self, IncapableContext, InvalidPublicKey, InvalidSecretKey};
use constants;
use ffi;

/// Secret 256-bit key used as `x` in an ECDSA signature
pub struct SecretKey([u8; constants::SECRET_KEY_SIZE]);
impl_array_newtype!(SecretKey, u8, constants::SECRET_KEY_SIZE);
impl_pretty_debug!(SecretKey);

/// The number 1 encoded as a secret key
/// Deprecated; `static` is not what I want; use `ONE_KEY` instead
pub static ONE: SecretKey = SecretKey([0, 0, 0, 0, 0, 0, 0, 0,
                                       0, 0, 0, 0, 0, 0, 0, 0,
                                       0, 0, 0, 0, 0, 0, 0, 0,
                                       0, 0, 0, 0, 0, 0, 0, 1]);

/// The number 0 encoded as a secret key
pub const ZERO_KEY: SecretKey = SecretKey([0, 0, 0, 0, 0, 0, 0, 0,
                                           0, 0, 0, 0, 0, 0, 0, 0,
                                           0, 0, 0, 0, 0, 0, 0, 0,
                                           0, 0, 0, 0, 0, 0, 0, 0]);

/// The number 1 encoded as a secret key
pub const ONE_KEY: SecretKey = SecretKey([0, 0, 0, 0, 0, 0, 0, 0,
                                          0, 0, 0, 0, 0, 0, 0, 0,
                                          0, 0, 0, 0, 0, 0, 0, 0,
                                          0, 0, 0, 0, 0, 0, 0, 1]);

/// A Secp256k1 public key, used for verification of signatures
#[derive(Copy, Clone, PartialEq, Eq, Debug, PartialOrd, Ord, Hash)]
pub struct PublicKey(ffi::PublicKey);

#[cfg(any(test, feature = "rand"))]
fn random_32_bytes<R: Rng>(rng: &mut R) -> [u8; 32] {
    let mut ret = [0u8; 32];
    rng.fill_bytes(&mut ret);
    ret
}

impl SecretKey {
    /// Creates a new random secret key
    #[inline]
    #[cfg(any(test, feature = "rand"))]
    pub fn new<R: Rng>(secp: &Secp256k1, rng: &mut R) -> SecretKey {
        let mut data = random_32_bytes(rng);
        unsafe {
            while ffi::secp256k1_ec_seckey_verify(secp.ctx, data.as_ptr()) == 0 {
                data = random_32_bytes(rng);
            }
        }
        SecretKey(data)
    }

    /// Converts a `SECRET_KEY_SIZE`-byte slice to a secret key
    #[inline]
    pub fn from_slice(secp: &Secp256k1, data: &[u8])
                        -> Result<SecretKey, Error> {
        match data.len() {
            constants::SECRET_KEY_SIZE => {
                let mut ret = [0; constants::SECRET_KEY_SIZE];
                unsafe {
                    if ffi::secp256k1_ec_seckey_verify(secp.ctx, data.as_ptr()) == 0 {
                        return Err(InvalidSecretKey);
                    }
                }
                ret[..].copy_from_slice(data);
                Ok(SecretKey(ret))
            }
            _ => Err(InvalidSecretKey)
        }
    }

    #[inline]
    /// Adds one secret key to another, modulo the curve order
    pub fn add_assign(&mut self, secp: &Secp256k1, other: &SecretKey)
                     -> Result<(), Error> {
        unsafe {
            if ffi::secp256k1_ec_privkey_tweak_add(secp.ctx, self.as_mut_ptr(), other.as_ptr()) != 1 {
                Err(InvalidSecretKey)
            } else {
                Ok(())
            }
        }
    }

    #[inline]
    /// Multiplies one secret key by another, modulo the curve order
    pub fn mul_assign(&mut self, secp: &Secp256k1, other: &SecretKey)
                     -> Result<(), Error> {
        unsafe {
            if ffi::secp256k1_ec_privkey_tweak_mul(secp.ctx, self.as_mut_ptr(), other.as_ptr()) != 1 {
                Err(InvalidSecretKey)
            } else {
                Ok(())
            }
        }
    }
}

impl PublicKey {
    /// Creates a new zeroed out public key
    #[inline]
    pub fn new() -> PublicKey {
        PublicKey(ffi::PublicKey::new())
    }

    /// Determines whether a pubkey is valid
    #[inline]
    pub fn is_valid(&self) -> bool {
        // The only invalid pubkey the API should be able to create is
        // the zero one.
        self.0[..].iter().any(|&x| x != 0)
    }

    /// Obtains a raw pointer suitable for use with FFI functions
    #[inline]
    pub fn as_ptr(&self) -> *const ffi::PublicKey {
        &self.0 as *const _
    }

    /// Creates a new public key from a secret key.
    #[inline]
    pub fn from_secret_key(secp: &Secp256k1,
                           sk: &SecretKey)
                           -> Result<PublicKey, Error> {
        if secp.caps == ContextFlag::VerifyOnly || secp.caps == ContextFlag::None {
            return Err(IncapableContext);
        }
        let mut pk = unsafe { ffi::PublicKey::blank() };
        unsafe {
            // We can assume the return value because it's not possible to construct
            // an invalid `SecretKey` without transmute trickery or something
            let res = ffi::secp256k1_ec_pubkey_create(secp.ctx, &mut pk, sk.as_ptr());
            debug_assert_eq!(res, 1);
        }
        Ok(PublicKey(pk))
    }

    /// Creates a public key directly from a slice
    #[inline]
    pub fn from_slice(secp: &Secp256k1, data: &[u8])
                      -> Result<PublicKey, Error> {

        let mut pk = unsafe { ffi::PublicKey::blank() };
        unsafe {
            if ffi::secp256k1_ec_pubkey_parse(secp.ctx, &mut pk, data.as_ptr(),
                                              data.len() as ::libc::size_t) == 1 {
                Ok(PublicKey(pk))
            } else {
                Err(InvalidPublicKey)
            }
        }
    }

    #[inline]
    /// Serialize the key as a byte-encoded pair of values. In compressed form
    /// the y-coordinate is represented by only a single bit, as x determines
    /// it up to one bit.
    pub fn serialize(&self) -> [u8; constants::PUBLIC_KEY_SIZE] {
        let secp = Secp256k1::with_caps(ContextFlag::None);
        let mut ret = [0; constants::PUBLIC_KEY_SIZE];

        unsafe {
            let mut ret_len = constants::PUBLIC_KEY_SIZE as ::libc::size_t;
            let err = ffi::secp256k1_ec_pubkey_serialize(
                secp.ctx,
                ret.as_mut_ptr(),
                &mut ret_len,
                self.as_ptr(),
                ffi::SECP256K1_SER_COMPRESSED,
            );
            debug_assert_eq!(err, 1);
            debug_assert_eq!(ret_len, ret.len());
        }
        ret
    }

    /// Serialize the key as a byte-encoded pair of values, in uncompressed form
    pub fn serialize_uncompressed(&self) -> [u8; constants::UNCOMPRESSED_PUBLIC_KEY_SIZE] {
        let secp = Secp256k1::with_caps(ContextFlag::None);
        let mut ret = [0; constants::UNCOMPRESSED_PUBLIC_KEY_SIZE];

        unsafe {
            let mut ret_len = constants::UNCOMPRESSED_PUBLIC_KEY_SIZE as ::libc::size_t;
            let err = ffi::secp256k1_ec_pubkey_serialize(
                secp.ctx,
                ret.as_mut_ptr(),
                &mut ret_len,
                self.as_ptr(),
                ffi::SECP256K1_SER_UNCOMPRESSED,
            );
            debug_assert_eq!(err, 1);
            debug_assert_eq!(ret_len, ret.len());
        }
        ret
    }

    #[inline]
    /// Adds the pk corresponding to `other` to the pk `self` in place
    pub fn add_exp_assign(&mut self, secp: &Secp256k1, other: &SecretKey)
                         -> Result<(), Error> {
        if secp.caps == ContextFlag::SignOnly || secp.caps == ContextFlag::None {
            return Err(IncapableContext);
        }
        unsafe {
            if ffi::secp256k1_ec_pubkey_tweak_add(secp.ctx, &mut self.0 as *mut _,
                                                  other.as_ptr()) == 1 {
                Ok(())
            } else {
                Err(InvalidSecretKey)
            }
        }
    }

    #[inline]
    /// Muliplies the pk `self` in place by the scalar `other`
    pub fn mul_assign(&mut self, secp: &Secp256k1, other: &SecretKey)
                         -> Result<(), Error> {
        if secp.caps == ContextFlag::SignOnly || secp.caps == ContextFlag::None {
            return Err(IncapableContext);
        }
        unsafe {
            if ffi::secp256k1_ec_pubkey_tweak_mul(secp.ctx, &mut self.0 as *mut _,
                                                  other.as_ptr()) == 1 {
                Ok(())
            } else {
                Err(InvalidSecretKey)
            }
        }
    }

    /// Adds a second key to this one, returning the sum. Returns an error if
    /// the result would be the point at infinity, i.e. we are adding this point
    /// to its own negation
    pub fn combine(&self, secp: &Secp256k1, other: &PublicKey) -> Result<PublicKey, Error> {
        unsafe {
            let mut ret = mem::uninitialized();
            let ptrs = [self.as_ptr(), other.as_ptr()];
            if ffi::secp256k1_ec_pubkey_combine(secp.ctx, &mut ret, ptrs.as_ptr(), 2) == 1 {
                Ok(PublicKey(ret))
            } else {
                Err(InvalidPublicKey)
            }
        }
    }
}

/// Creates a new public key from a FFI public key
impl From<ffi::PublicKey> for PublicKey {
    #[inline]
    fn from(pk: ffi::PublicKey) -> PublicKey {
        PublicKey(pk)
    }
}

#[cfg(test)]
mod test {
    use super::super::{Secp256k1, ContextFlag};
    use super::super::Error::{InvalidPublicKey, InvalidSecretKey, IncapableContext};
    use super::{PublicKey, SecretKey};
    use super::super::constants;

    use rand::{Rng, thread_rng};

    macro_rules! hex {
        ($hex:expr) => {
            {
                let mut vec = Vec::new();
                let mut b = 0;
                for (idx, c) in $hex.as_bytes().iter().enumerate() {
                    b <<= 4;
                    match *c {
                        b'A'...b'F' => b |= c - b'A' + 10,
                        b'a'...b'f' => b |= c - b'a' + 10,
                        b'0'...b'9' => b |= c - b'0',
                        _ => panic!("Bad hex"),
                    }
                    if (idx & 1) == 1 {
                        vec.push(b);
                        b = 0;
                    }
                }
                vec
            }
        }
    }

    #[test]
    fn skey_from_slice() {
        let s = Secp256k1::new();
        let sk = SecretKey::from_slice(&s, &[1; 31]);
        assert_eq!(sk, Err(InvalidSecretKey));

        let sk = SecretKey::from_slice(&s, &[1; 32]);
        assert!(sk.is_ok());
    }

    #[test]
    fn pubkey_from_slice() {
        let s = Secp256k1::new();
        assert_eq!(PublicKey::from_slice(&s, &[]), Err(InvalidPublicKey));
        assert_eq!(PublicKey::from_slice(&s, &[1, 2, 3]), Err(InvalidPublicKey));

        let uncompressed = PublicKey::from_slice(&s, &[4, 54, 57, 149, 239, 162, 148, 175, 246, 254, 239, 75, 154, 152, 10, 82, 234, 224, 85, 220, 40, 100, 57, 121, 30, 162, 94, 156, 135, 67, 74, 49, 179, 57, 236, 53, 162, 124, 149, 144, 168, 77, 74, 30, 72, 211, 229, 110, 111, 55, 96, 193, 86, 227, 183, 152, 195, 155, 51, 247, 123, 113, 60, 228, 188]);
        assert!(uncompressed.is_ok());

        let compressed = PublicKey::from_slice(&s, &[3, 23, 183, 225, 206, 31, 159, 148, 195, 42, 67, 115, 146, 41, 248, 140, 11, 3, 51, 41, 111, 180, 110, 143, 114, 134, 88, 73, 198, 174, 52, 184, 78]);
        assert!(compressed.is_ok());
    }

    #[test]
    fn keypair_slice_round_trip() {
        let s = Secp256k1::new();

        let (sk1, pk1) = s.generate_keypair(&mut thread_rng()).unwrap();
        assert_eq!(SecretKey::from_slice(&s, &sk1[..]), Ok(sk1));
        assert_eq!(PublicKey::from_slice(&s, &pk1.serialize()[..]), Ok(pk1));
        assert_eq!(PublicKey::from_slice(&s, &pk1.serialize_uncompressed()[..]), Ok(pk1));
    }

    #[test]
    fn invalid_secret_key() {
        let s = Secp256k1::new();
        // Zero
        assert_eq!(SecretKey::from_slice(&s, &[0; 32]), Err(InvalidSecretKey));
        // -1
        assert_eq!(SecretKey::from_slice(&s, &[0xff; 32]), Err(InvalidSecretKey));
        // Top of range
        assert!(SecretKey::from_slice(&s,
                                      &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
                                        0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
                                        0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x40]).is_ok());
        // One past top of range
        assert!(SecretKey::from_slice(&s,
                                      &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
                                        0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
                                        0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41]).is_err());
    }

    #[test]
    fn test_pubkey_from_slice_bad_context() {
        let s = Secp256k1::without_caps();
        let sk = SecretKey::new(&s, &mut thread_rng());
        assert_eq!(PublicKey::from_secret_key(&s, &sk), Err(IncapableContext));

        let s = Secp256k1::with_caps(ContextFlag::VerifyOnly);
        assert_eq!(PublicKey::from_secret_key(&s, &sk), Err(IncapableContext));

        let s = Secp256k1::with_caps(ContextFlag::SignOnly);
        assert!(PublicKey::from_secret_key(&s, &sk).is_ok());

        let s = Secp256k1::with_caps(ContextFlag::Full);
        assert!(PublicKey::from_secret_key(&s, &sk).is_ok());
    }

    #[test]
    fn test_add_exp_bad_context() {
        let s = Secp256k1::with_caps(ContextFlag::Full);
        let (sk, mut pk) = s.generate_keypair(&mut thread_rng()).unwrap();

        assert!(pk.add_exp_assign(&s, &sk).is_ok());

        let s = Secp256k1::with_caps(ContextFlag::VerifyOnly);
        assert!(pk.add_exp_assign(&s, &sk).is_ok());

        let s = Secp256k1::with_caps(ContextFlag::SignOnly);
        assert_eq!(pk.add_exp_assign(&s, &sk), Err(IncapableContext));

        let s = Secp256k1::with_caps(ContextFlag::None);
        assert_eq!(pk.add_exp_assign(&s, &sk), Err(IncapableContext));
    }

    #[test]
    fn test_out_of_range() {

        struct BadRng(u8);
        impl Rng for BadRng {
            fn next_u32(&mut self) -> u32 { unimplemented!() }
            // This will set a secret key to a little over the
            // group order, then decrement with repeated calls
            // until it returns a valid key
            fn fill_bytes(&mut self, data: &mut [u8]) {
                let group_order: [u8; 32] = [
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
                    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
                    0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41];
                assert_eq!(data.len(), 32);
                data.copy_from_slice(&group_order[..]);
                data[31] = self.0;
                self.0 -= 1;
            }
        }

        let s = Secp256k1::new();
        s.generate_keypair(&mut BadRng(0xff)).unwrap();
    }

    #[test]
    fn test_pubkey_from_bad_slice() {
        let s = Secp256k1::new();
        // Bad sizes
        assert_eq!(PublicKey::from_slice(&s, &[0; constants::PUBLIC_KEY_SIZE - 1]),
                   Err(InvalidPublicKey));
        assert_eq!(PublicKey::from_slice(&s, &[0; constants::PUBLIC_KEY_SIZE + 1]),
                   Err(InvalidPublicKey));
        assert_eq!(PublicKey::from_slice(&s, &[0; constants::UNCOMPRESSED_PUBLIC_KEY_SIZE - 1]),
                   Err(InvalidPublicKey));
        assert_eq!(PublicKey::from_slice(&s, &[0; constants::UNCOMPRESSED_PUBLIC_KEY_SIZE + 1]),
                   Err(InvalidPublicKey));

        // Bad parse
        assert_eq!(PublicKey::from_slice(&s, &[0xff; constants::UNCOMPRESSED_PUBLIC_KEY_SIZE]),
                   Err(InvalidPublicKey));
        assert_eq!(PublicKey::from_slice(&s, &[0x55; constants::PUBLIC_KEY_SIZE]),
                   Err(InvalidPublicKey));
    }

    #[test]
    fn test_debug_output() {
        struct DumbRng(u32);
        impl Rng for DumbRng {
            fn next_u32(&mut self) -> u32 {
                self.0 = self.0.wrapping_add(1);
                self.0
            }
        }

        let s = Secp256k1::new();
        let (sk, _) = s.generate_keypair(&mut DumbRng(0)).unwrap();

        assert_eq!(&format!("{:?}", sk),
                   "SecretKey(0200000001000000040000000300000006000000050000000800000007000000)");
    }

    #[test]
    fn test_pubkey_serialize() {
        struct DumbRng(u32);
        impl Rng for DumbRng {
            fn next_u32(&mut self) -> u32 {
                self.0 = self.0.wrapping_add(1);
                self.0
            }
        }

        let s = Secp256k1::new();
        let (_, pk1) = s.generate_keypair(&mut DumbRng(0)).unwrap();
        assert_eq!(&pk1.serialize_uncompressed()[..],
                   &[4, 149, 16, 196, 140, 38, 92, 239, 179, 65, 59, 224, 230, 183, 91, 238, 240, 46, 186, 252, 175, 102, 52, 249, 98, 178, 123, 72, 50, 171, 196, 254, 236, 1, 189, 143, 242, 227, 16, 87, 247, 183, 162, 68, 237, 140, 92, 205, 151, 129, 166, 58, 111, 96, 123, 64, 180, 147, 51, 12, 209, 89, 236, 213, 206][..]);
        assert_eq!(&pk1.serialize()[..],
                   &[2, 149, 16, 196, 140, 38, 92, 239, 179, 65, 59, 224, 230, 183, 91, 238, 240, 46, 186, 252, 175, 102, 52, 249, 98, 178, 123, 72, 50, 171, 196, 254, 236][..]);
    }

    #[test]
    fn test_addition() {
        let s = Secp256k1::new();

        let (mut sk1, mut pk1) = s.generate_keypair(&mut thread_rng()).unwrap();
        let (mut sk2, mut pk2) = s.generate_keypair(&mut thread_rng()).unwrap();

        assert_eq!(PublicKey::from_secret_key(&s, &sk1).unwrap(), pk1);
        assert!(sk1.add_assign(&s, &sk2).is_ok());
        assert!(pk1.add_exp_assign(&s, &sk2).is_ok());
        assert_eq!(PublicKey::from_secret_key(&s, &sk1).unwrap(), pk1);

        assert_eq!(PublicKey::from_secret_key(&s, &sk2).unwrap(), pk2);
        assert!(sk2.add_assign(&s, &sk1).is_ok());
        assert!(pk2.add_exp_assign(&s, &sk1).is_ok());
        assert_eq!(PublicKey::from_secret_key(&s, &sk2).unwrap(), pk2);
    }

    #[test]
    fn test_multiplication() {
        let s = Secp256k1::new();

        let (mut sk1, mut pk1) = s.generate_keypair(&mut thread_rng()).unwrap();
        let (mut sk2, mut pk2) = s.generate_keypair(&mut thread_rng()).unwrap();

        assert_eq!(PublicKey::from_secret_key(&s, &sk1).unwrap(), pk1);
        assert!(sk1.mul_assign(&s, &sk2).is_ok());
        assert!(pk1.mul_assign(&s, &sk2).is_ok());
        assert_eq!(PublicKey::from_secret_key(&s, &sk1).unwrap(), pk1);

        assert_eq!(PublicKey::from_secret_key(&s, &sk2).unwrap(), pk2);
        assert!(sk2.mul_assign(&s, &sk1).is_ok());
        assert!(pk2.mul_assign(&s, &sk1).is_ok());
        assert_eq!(PublicKey::from_secret_key(&s, &sk2).unwrap(), pk2);
    }

    #[test]
    fn pubkey_hash() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        use std::collections::HashSet;

        fn hash<T: Hash>(t: &T) -> u64 {
            let mut s = DefaultHasher::new();
            t.hash(&mut s);
            s.finish()
        }

        let s = Secp256k1::new();
        let mut set = HashSet::new();
        const COUNT : usize = 1024;
        let count = (0..COUNT).map(|_| {
            let (_, pk) = s.generate_keypair(&mut thread_rng()).unwrap();
            let hash = hash(&pk);
            assert!(!set.contains(&hash));
            set.insert(hash);
        }).count();
        assert_eq!(count, COUNT);
    }

    #[test]
    fn pubkey_combine() {
        let s = Secp256k1::with_caps(ContextFlag::None);
        let compressed1 = PublicKey::from_slice(
            &s,
            &hex!("0241cc121c419921942add6db6482fb36243faf83317c866d2a28d8c6d7089f7ba"),
        ).unwrap();
        let compressed2 = PublicKey::from_slice(
            &s,
            &hex!("02e6642fd69bd211f93f7f1f36ca51a26a5290eb2dd1b0d8279a87bb0d480c8443"),
        ).unwrap();
        let exp_sum = PublicKey::from_slice(
            &s,
            &hex!("0384526253c27c7aef56c7b71a5cd25bebb66dddda437826defc5b2568bde81f07"),
        ).unwrap();

        let sum1 = compressed1.combine(&s, &compressed2);
        assert!(sum1.is_ok());
        let sum2 = compressed2.combine(&s, &compressed1);
        assert!(sum2.is_ok());
        assert_eq!(sum1, sum2);
        assert_eq!(sum1.unwrap(), exp_sum);
    }

    #[test]
    fn pubkey_equal() {
        let s = Secp256k1::new();
        let pk1 = PublicKey::from_slice(
            &s,
            &hex!("0241cc121c419921942add6db6482fb36243faf83317c866d2a28d8c6d7089f7ba"),
        ).unwrap();
        let pk2 = pk1.clone();
        let pk3 = PublicKey::from_slice(
            &s,
            &hex!("02e6642fd69bd211f93f7f1f36ca51a26a5290eb2dd1b0d8279a87bb0d480c8443"),
        ).unwrap();

        assert!(pk1 == pk2);
        assert!(pk1 <= pk2);
        assert!(pk2 <= pk1);
        assert!(!(pk2 < pk1));
        assert!(!(pk1 < pk2));
        
        assert!(pk3 < pk1);
        assert!(pk1 > pk3);
        assert!(pk3 <= pk1);
        assert!(pk1 >= pk3);
    }
}


