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

//! Support for shared secret computations.
//!

use core::ptr;
use core::ops::{FnMut, Deref};

use key::{SecretKey, PublicKey};
use ffi::{self, CPtr};
use secp256k1_sys::types::{c_int, c_uchar, c_void};

/// Enables two parties to create a shared secret without revealing their own secrets.
///
/// # Examples
///
/// ```
/// # #[cfg(all(feature = "std", feature = "rand-std"))] {
/// # use secp256k1::Secp256k1;
/// # use secp256k1::ecdh::SharedSecret;
/// # use secp256k1::rand::thread_rng;
/// let s = Secp256k1::new();
/// let (sk1, pk1) = s.generate_keypair(&mut thread_rng());
/// let (sk2, pk2) = s.generate_keypair(&mut thread_rng());
/// let sec1 = SharedSecret::new(&pk1, &sk2);
/// let sec2 = SharedSecret::new(&pk2, &sk1);
/// assert_eq!(sec1, sec2);
/// # }
// ```
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

    /// Creates an empty `SharedSecret`.
    pub(crate) fn empty() ->  SharedSecret {
        SharedSecret {
            data: [0u8; 256],
            len: 0,
        }
    }

    /// Gets a pointer to the underlying data with the specified capacity.
    pub(crate) fn get_data_mut_ptr(&mut self) -> *mut u8 {
        self.data.as_mut_ptr()
    }

    /// Gets the capacity of the underlying data buffer.
    pub fn capacity(&self) -> usize {
        self.data.len()
    }

    /// Gets the len of the used data.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns true if the underlying data buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Sets the length of the object.
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


unsafe extern "C" fn c_callback(output: *mut c_uchar, x: *const c_uchar, y: *const c_uchar, _data: *mut c_void) -> c_int {
    ptr::copy_nonoverlapping(x, output, 32);
    ptr::copy_nonoverlapping(y, output.offset(32), 32);
    1
}

impl SharedSecret {
    /// Creates a new shared secret from a pubkey and secret key.
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
        // The default `secp256k1_ecdh_hash_function_default` should always return 1.
        // and the scalar was verified to be valid(0 > scalar > group_order) via the type system
        debug_assert_eq!(res, 1);
        ss.set_len(32); // The default hash function is SHA256, which is 32 bytes long.
        ss
    }


    /// Creates a new shared secret from a pubkey and secret key with applied custom hash function.
    /// The custom hash function must be in the form of `fn(x: [u8;32], y: [u8;32]) -> SharedSecret`
    /// `SharedSecret` can be easily created via the `From` impl from arrays.
    /// # Examples
    /// ```
    /// # #[cfg(any(feature = "alloc", features = "std"))] {
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
    /// # }
    /// ```
    pub fn new_with_hash<F>(point: &PublicKey, scalar: &SecretKey, mut hash_function: F) -> SharedSecret
        where F: FnMut([u8; 32], [u8; 32]) -> SharedSecret {
        let mut xy = [0u8; 64];

        let res = unsafe {
            ffi::secp256k1_ecdh(
                ffi::secp256k1_context_no_precomp,
                xy.as_mut_ptr(),
                point.as_ptr(),
                scalar.as_ptr(),
                Some(c_callback),
                ptr::null_mut(),
            )
        };
        // Our callback *always* returns 1.
        // and the scalar was verified to be valid(0 > scalar > group_order) via the type system
        debug_assert_eq!(res, 1);

        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        x.copy_from_slice(&xy[..32]);
        y.copy_from_slice(&xy[32..]);
        hash_function(x, y)
    }
}

#[cfg(test)]
#[allow(unused_imports)]
mod tests {
    use super::*;
    use rand::thread_rng;
    use super::super::Secp256k1;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    #[test]
    #[cfg(all(feature="rand-std", any(feature = "alloc", feature = "std")))]
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
    #[cfg(all(feature="std", feature = "rand-std"))]
    fn ecdh_with_hash() {
        let s = Secp256k1::signing_only();
        let (sk1, pk1) = s.generate_keypair(&mut thread_rng());
        let (sk2, pk2) = s.generate_keypair(&mut thread_rng());

        let sec1 = SharedSecret::new_with_hash(&pk1, &sk2, |x,_| x.into());
        let sec2 = SharedSecret::new_with_hash(&pk2, &sk1, |x,_| x.into());
        let sec_odd = SharedSecret::new_with_hash(&pk1, &sk1, |x,_| x.into());
        assert_eq!(sec1, sec2);
        assert_ne!(sec_odd, sec2);
    }

    #[test]
    #[cfg(all(feature="std", feature = "rand-std"))]
    fn ecdh_with_hash_callback() {
        let s = Secp256k1::signing_only();
        let (sk1, pk1) = s.generate_keypair(&mut thread_rng());
        let expect_result: [u8; 64] = [123; 64];
        let mut x_out = [0u8; 32];
        let mut y_out = [0u8; 32];
        let result = SharedSecret::new_with_hash(&pk1, &sk1, |x, y| {
            x_out = x;
            y_out = y;
            expect_result.into()
        });
        assert_eq!(&expect_result[..], &result[..]);
        assert_ne!(x_out, [0u8; 32]);
        assert_ne!(y_out, [0u8; 32]);
    }

    #[test]
    fn test_c_callback() {
        let x = [5u8; 32];
        let y = [7u8; 32];
        let mut output = [0u8; 64];
        let res = unsafe { super::c_callback(output.as_mut_ptr(), x.as_ptr(), y.as_ptr(), ptr::null_mut()) };
        assert_eq!(res, 1);
        let mut new_x = [0u8; 32];
        let mut new_y = [0u8; 32];
        new_x.copy_from_slice(&output[..32]);
        new_y.copy_from_slice(&output[32..]);
        assert_eq!(x, new_x);
        assert_eq!(y, new_y);
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

        bh.iter( || {
            let res = SharedSecret::new(&pk, &sk);
            black_box(res);
        });
    }
}

