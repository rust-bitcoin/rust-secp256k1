// Bitcoin secp256k1 bindings
// Written in 2015 by
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

//! # ECDH
//! Support for shared secret computations
//!

use core::ptr;
use core::ops::{FnMut, Deref};

use key::{SecretKey, PublicKey};
use ffi::{self, CPtr};
use secp256k1_sys::types::{c_int, c_uchar, c_void};
use Error;

/// A tag used for recovering the public key from a compact signature
#[derive(Copy, Clone)]
pub struct SharedSecret {
    data: [u8; 256],
    len: usize,
}
impl_raw_debug!(SharedSecret);


// This implementes `From<N>` for all `[u8; N]` arrays from 128bits(16 byte) to 2048bits allowing known hash lengths.
// Lower than 128 bits isn't resistant to collisions any more.
impl_from_array_len!(SharedSecret, 256, (16 20 28 32 48 64 96 128 256));

impl SharedSecret {

    /// Create an empty SharedSecret
    pub(crate) fn empty() ->  SharedSecret {
        SharedSecret {
            data: [0u8; 256],
            len: 0,
        }
    }

    /// Get a pointer to the underlying data with the specified capacity.
    pub(crate) fn get_data_mut_ptr(&mut self) -> *mut u8 {
        self.data.as_mut_ptr()
    }

    /// Get the capacity of the underlying data buffer.
    pub fn capacity(&self) -> usize {
        self.data.len()
    }

    /// Get the len of the used data.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Set the length of the object.
    pub(crate) fn set_len(&mut self, len: usize) {
        debug_assert!(len <= self.data.len());
        self.len = len;
    }
}

impl PartialEq for SharedSecret {
    fn eq(&self, other: &SharedSecret) -> bool {
        self.as_ref() == other.as_ref()
    }
}

impl AsRef<[u8]> for SharedSecret {
    fn as_ref(&self) -> &[u8] {
        &self.data[..self.len]
    }
}

impl Deref for SharedSecret {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.data[..self.len]
    }
}


#[cfg(feature = "std")]
unsafe extern "C" fn hash_callback<F>(output: *mut c_uchar, x: *const c_uchar, y: *const c_uchar, data: *mut c_void) -> c_int
    where F: FnMut([u8; 32], [u8; 32]) -> SharedSecret {

    use std::panic::catch_unwind;
    let res = catch_unwind(|| {
        let callback: &mut F = &mut *(data as *mut F);

        let mut x_arr = [0; 32];
        let mut y_arr = [0; 32];
        ptr::copy_nonoverlapping(x, x_arr.as_mut_ptr(), 32);
        ptr::copy_nonoverlapping(y, y_arr.as_mut_ptr(), 32);

        let secret = callback(x_arr, y_arr);
        ptr::copy_nonoverlapping(secret.as_ptr(), output as *mut u8, secret.len());

        secret.len() as c_int
    });
    if let Ok(len) = res {
        len
    } else {
        -1
    }
}


impl SharedSecret {
    /// Creates a new shared secret from a pubkey and secret key
    #[inline]
    pub fn new(point: &PublicKey, scalar: &SecretKey) -> SharedSecret {
        let mut ss = SharedSecret::empty();
        let res = unsafe {
             ffi::secp256k1_ecdh(
                ffi::secp256k1_context_no_precomp,
                ss.get_data_mut_ptr(),
                point.as_c_ptr(),
                scalar.as_c_ptr(),
                ffi::secp256k1_ecdh_hash_function_default,
                ptr::null_mut(),
            )
        };
        debug_assert_eq!(res, 1); // The default `secp256k1_ecdh_hash_function_default` should always return 1.
        ss.set_len(32); // The default hash function is SHA256, which is 32 bytes long.
        ss
    }

    /// Creates a new shared secret from a pubkey and secret key with applied custom hash function
    /// # Examples
    /// ```
    /// # use secp256k1::ecdh::SharedSecret;
    /// # use secp256k1::{Secp256k1, PublicKey, SecretKey};
    /// # fn sha2(_a: &[u8], _b: &[u8]) -> [u8; 32] {[0u8; 32]}
    /// # let secp = Secp256k1::signing_only();
    /// # let secret_key = SecretKey::from_slice(&[3u8; 32]).unwrap();
    /// # let secret_key2 = SecretKey::from_slice(&[7u8; 32]).unwrap();
    /// # let public_key = PublicKey::from_secret_key(&secp, &secret_key2);
    ///
    /// let secret = SharedSecret::new_with_hash(&public_key, &secret_key, |x,y| {
    ///     let hash: [u8; 32] = sha2(&x,&y);
    ///     hash.into()
    /// });
    ///
    /// ```
    #[cfg(feature = "std")]
    pub fn new_with_hash<F>(point: &PublicKey, scalar: &SecretKey, mut hash_function: F) -> Result<SharedSecret, Error>
        where F: FnMut([u8; 32], [u8; 32]) -> SharedSecret
    {
        let mut ss = SharedSecret::empty();
        let hashfp: ffi::EcdhHashFn = hash_callback::<F>;

        let res =  unsafe {
            ffi::secp256k1_ecdh(
                ffi::secp256k1_context_no_precomp,
                ss.get_data_mut_ptr(),
                point.as_ptr(),
                scalar.as_ptr(),
                hashfp,
                &mut hash_function as *mut F as *mut c_void,
            )
        };
        if res == -1 {
            return Err(Error::CallbackPanicked);
        }
        debug_assert!(res >= 16); // 128 bit is the minimum for a secure hash function and the minimum we let users.
        ss.set_len(res as usize);
        Ok(ss)
    }
}

#[cfg(test)]
mod tests {
    use rand::thread_rng;
    use super::SharedSecret;
    use super::super::Secp256k1;
    use Error;

    #[test]
    fn ecdh() {
        let s = Secp256k1::signing_only();
        let (sk1, pk1) = s.generate_keypair(&mut thread_rng());
        let (sk2, pk2) = s.generate_keypair(&mut thread_rng());

        let sec1 = SharedSecret::new(&pk1, &sk2);
        let sec2 = SharedSecret::new(&pk2, &sk1);
        let sec_odd = SharedSecret::new(&pk1, &sk1);
        assert_eq!(sec1, sec2);
        assert!(sec_odd != sec2);
    }

    #[test]
    fn ecdh_with_hash() {
        let s = Secp256k1::signing_only();
        let (sk1, pk1) = s.generate_keypair(&mut thread_rng());
        let (sk2, pk2) = s.generate_keypair(&mut thread_rng());
        
        let sec1 = SharedSecret::new_with_hash(&pk1, &sk2, |x,_| x.into()).unwrap();
        let sec2 = SharedSecret::new_with_hash(&pk2, &sk1, |x,_| x.into()).unwrap();
        let sec_odd = SharedSecret::new_with_hash(&pk1, &sk1, |x,_| x.into()).unwrap();
        assert_eq!(sec1, sec2);
        assert_ne!(sec_odd, sec2);
    }

    #[test]
    fn ecdh_with_hash_callback() {
        let s = Secp256k1::signing_only();
        let (sk1, pk1) = s.generate_keypair(&mut thread_rng());
        let expect_result: [u8; 64] = [123; 64];
        let mut x_out = [0u8; 32];
        let mut y_out = [0u8; 32];
        let result = SharedSecret::new_with_hash(&pk1, &sk1, | x, y | {
            x_out = x;
            y_out = y;
            expect_result.into()
        }).unwrap();
        assert_eq!(&expect_result[..], &result[..]);
        assert_ne!(x_out, [0u8; 32]);
        assert_ne!(y_out, [0u8; 32]);
    }

    #[test]
    fn ecdh_with_hash_callback_panic() {
        let s = Secp256k1::signing_only();
        let (sk1, pk1) = s.generate_keypair(&mut thread_rng());
        let mut res = [0u8; 48];
        let result = SharedSecret::new_with_hash(&pk1, &sk1, | x, _ | {
            res.copy_from_slice(&x); // res.len() != x.len(). this will panic.
            res.into()
        });
        assert_eq!(result, Err(Error::CallbackPanicked));
    }
}

#[cfg(all(test, feature = "unstable"))]
mod benches {
    use rand::thread_rng;
    use test::{Bencher, black_box};

    use super::SharedSecret;
    use super::super::Secp256k1;

    #[bench]
    pub fn bench_ecdh(bh: &mut Bencher) {
        let s = Secp256k1::signing_only();
        let (sk, pk) = s.generate_keypair(&mut thread_rng());

        let s = Secp256k1::new();
        bh.iter( || {
            let res = SharedSecret::new(&pk, &sk);
            black_box(res);
        });
    }
}

