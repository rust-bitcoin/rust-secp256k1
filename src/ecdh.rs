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
use core::ops::Deref;

use key::{SecretKey, PublicKey};
use ffi::{self, CPtr};

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
        self.len = len;
    }
}

impl PartialEq for SharedSecret {
    fn eq(&self, other: &SharedSecret) -> bool {
        &self.data[..self.len] == &other.data[..other.len]
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

