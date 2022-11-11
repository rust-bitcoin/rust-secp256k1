use core::ptr;

use crate::key::{PublicKey, SecretKey};
use crate::types::*;
use crate::{impl_array_newtype, impl_raw_debug, secp256k1_context_no_precomp};

/// Library-internal representation of a ECDH shared secret.
///
/// The inner array is to be considered opaque, it is passed across the FFI boundary and as such we
/// make no guarantees about the byte layout or stability across library versions or architectures.
#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SharedSecret([c_uchar; 32]);
impl_array_newtype!(SharedSecret, c_uchar, 32);
impl_raw_debug!(SharedSecret);

impl SharedSecret {
    /// FIXME: Should we provide a safe constructor that does not check the data?
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        SharedSecret(bytes)
    }

    pub fn from_point_and_scalar(pk: &PublicKey, sk: &SecretKey) -> Option<SharedSecret> {
        let mut buf = [0u8; 32];
        let res = unsafe {
             crate::secp256k1_ecdh(
                secp256k1_context_no_precomp,
                buf.as_mut_ptr(),
                pk,
                sk.as_ptr(),
                crate::secp256k1_ecdh_hash_function_default,
                ptr::null_mut(),
            )
        };
        if res == 1 { Some(SharedSecret(buf)) } else { None }
    }

    /// Returns the shared secret as a byte value.
    #[inline]
    pub fn secret_bytes(self) -> [u8; 32] {
        // FIXME: Do we need to worry about byte order?
        self.underlying_bytes()
    }
}

/// Creates a shared point from public key and secret key.
///
/// **Important: use of a strong cryptographic hash function may be critical to security! Do NOT use
/// unless you understand cryptographical implications.** If not, use SharedSecret instead.
///
/// Can be used like `SharedSecret` but caller is responsible for then hashing the returned buffer.
/// This allows for the use of a custom hash function since `SharedSecret` uses SHA256.
///
/// # Returns
///
/// 64 bytes representing the (x,y) co-ordinates of a point on the curve (32 bytes each).
pub fn shared_secret_point(point: &PublicKey, scalar: &SecretKey) -> [u8; 64] {
    let mut xy = [0u8; 64];

    let res = unsafe {
        crate::secp256k1_ecdh(
            secp256k1_context_no_precomp,
            xy.as_mut_ptr(),
            point,
            scalar.as_ptr(),
            Some(c_callback),
            ptr::null_mut(),
        )
    };
    // Our callback *always* returns 1.
    // The scalar was verified to be valid (0 > scalar > group_order) via the type system.
    assert_eq!(res, 1);
    xy
}

unsafe extern "C" fn c_callback(output: *mut c_uchar, x: *const c_uchar, y: *const c_uchar, _data: *mut c_void) -> c_int {
    ptr::copy_nonoverlapping(x, output, 32);
    ptr::copy_nonoverlapping(y, output.offset(32), 32);
    1
}
