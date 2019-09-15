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

use core::{ops, ptr};
use core::ops::{FnMut};
use core::slice::{from_raw_parts, from_raw_parts_mut};

use key::{SecretKey, PublicKey};
use ffi::{self, CPtr};
use types::{c_int, c_uchar, c_void};

/// A tag used for recovering the public key from a compact signature
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct SharedSecret(ffi::SharedSecret);

impl SharedSecret {
    /// Creates a new shared secret from a pubkey and secret key
    #[inline]
    pub fn new(point: &PublicKey, scalar: &SecretKey) -> SharedSecret {
        unsafe {
            let mut ss = ffi::SharedSecret::new();
            let res = ffi::secp256k1_ecdh(
                ffi::secp256k1_context_no_precomp,
                &mut ss,
                point.as_c_ptr(),
                scalar.as_c_ptr(),
                ffi::secp256k1_ecdh_hash_function_default,
                ptr::null_mut(),
            );
            debug_assert_eq!(res, 1);
            SharedSecret(ss)
        }
    }

    /// Creates a new shared secret from a pubkey and secret key with applied custom hash function
    pub fn new_with_hash<F>(point: &PublicKey, scalar: &SecretKey, hash: &mut F) -> SharedSecret
        where F: FnMut(&mut [u8], &[u8], &[u8]) -> i32
    { 
        extern "C" fn hash_callback<F>(output: *mut c_uchar, x: *const c_uchar, y: *const c_uchar, data: *const c_void) -> c_int 
            where F: FnMut(&mut [u8], &[u8], &[u8]) -> i32
        {
            let callback: &mut F = unsafe { &mut *(data as *mut F) };
            unsafe { (*callback)(from_raw_parts_mut(output, 32), from_raw_parts(x, 32), from_raw_parts(y, 32)) }
        }
        unsafe {
            let mut ss = ffi::SharedSecret::new();
            let res = ffi::secp256k1_ecdh(
                ffi::secp256k1_context_no_precomp,
                &mut ss,
                point.as_ptr(),
                scalar.as_ptr(),
                hash_callback::<F>,
                hash as *mut F as *mut c_void,
            );
            debug_assert_eq!(res, 1);
            SharedSecret::from(ss)
        }
    }

    /// Obtains a raw pointer suitable for use with FFI functions
    #[inline]
    pub fn as_ptr(&self) -> *const ffi::SharedSecret {
        &self.0 as *const _
    }
}

/// Creates a new shared secret from a FFI shared secret
impl From<ffi::SharedSecret> for SharedSecret {
    #[inline]
    fn from(ss: ffi::SharedSecret) -> SharedSecret {
        SharedSecret(ss)
    }
}


impl ops::Index<usize> for SharedSecret {
    type Output = u8;

    #[inline]
    fn index(&self, index: usize) -> &u8 {
        &self.0[index]
    }
}

impl ops::Index<ops::Range<usize>> for SharedSecret {
    type Output = [u8];

    #[inline]
    fn index(&self, index: ops::Range<usize>) -> &[u8] {
        &self.0[index]
    }
}

impl ops::Index<ops::RangeFrom<usize>> for SharedSecret {
    type Output = [u8];

    #[inline]
    fn index(&self, index: ops::RangeFrom<usize>) -> &[u8] {
        &self.0[index.start..]
    }
}

impl ops::Index<ops::RangeFull> for SharedSecret {
    type Output = [u8];

    #[inline]
    fn index(&self, _: ops::RangeFull) -> &[u8] {
        &self.0[..]
    }
}

#[cfg(test)]
mod tests {
    use rand::thread_rng;
    use super::SharedSecret;
    use super::super::Secp256k1;

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

        let sec1 = SharedSecret::new_with_hash(&pk1, &sk2, &mut hash);
        let sec2 = SharedSecret::new_with_hash(&pk2, &sk1, &mut hash);
        let sec_odd = SharedSecret::new_with_hash(&pk1, &sk1, &mut hash);
        assert_eq!(sec1, sec2);
        assert!(sec_odd != sec2);
    }

    fn hash(output: &mut [u8], x: &[u8], _y: &[u8]) -> i32 {
        output.copy_from_slice(x); 
        1
    }

    #[test]
    fn ecdh_with_hash_callback() {
        let s = Secp256k1::signing_only();
        let (sk1, pk1) = s.generate_keypair(&mut thread_rng());
        let expect_result: &[u8] = &[123u8;32];
        let result = SharedSecret::new_with_hash(&pk1, &sk1, &mut |output, _, _ | {
            output.copy_from_slice(expect_result);
            1
        });
        assert_eq!(expect_result, &result[..]);
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

