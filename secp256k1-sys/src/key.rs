use crate::types::*;
use crate::{impl_array_newtype, impl_raw_debug};

/// Library-internal representation of a Secp256k1 secret key.
///
/// The inner array is to be considered opaque, it is passed across the FFI boundary and as such we
/// make no guarantees about the byte layout or stability across library versions or architectures.
#[repr(C)]
pub struct SecretKey([c_uchar; 32]);
impl_array_newtype!(SecretKey, c_uchar, 32);
impl_raw_debug!(SecretKey);

/// Library-internal representation of a Secp256k1 public key.
///
/// The inner array is to be considered opaque, it is passed across the FFI boundary and as such we
/// make no guarantees about the byte layout or stability across library versions or architectures.
#[repr(C)]
pub struct PublicKey([c_uchar; 64]);
impl_array_newtype!(PublicKey, c_uchar, 64);
impl_raw_debug!(PublicKey);

/// Library-internal representation of a Secp256k1 x-only public key.
///
/// The inner array is to be considered opaque, it is passed across the FFI boundary and as such we
/// make no guarantees about the byte layout or stability across library versions or architectures.
#[repr(C)]
pub struct XOnlyPublicKey([c_uchar; 64]);
impl_array_newtype!(XOnlyPublicKey, c_uchar, 64);
impl_raw_debug!(XOnlyPublicKey);

/// Library-internal representation of a Secp256k1 key pair.
///
/// The inner array is to be considered opaque, it is passed across the FFI boundary and as such we
/// make no guarantees about the byte layout or stability across library versions or architectures.
#[repr(C)]
pub struct KeyPair([c_uchar; 96]);
impl_array_newtype!(KeyPair, c_uchar, 96);
impl_raw_debug!(KeyPair);
