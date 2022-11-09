use crate::types::*;
use crate::{impl_array_newtype, impl_raw_debug};

/// Library-internal representation of a Secp256k1 public key
#[repr(C)]
pub struct PublicKey([c_uchar; 64]);
impl_array_newtype!(PublicKey, c_uchar, 64);
impl_raw_debug!(PublicKey);

#[repr(C)]
pub struct XOnlyPublicKey([c_uchar; 64]);
impl_array_newtype!(XOnlyPublicKey, c_uchar, 64);
impl_raw_debug!(XOnlyPublicKey);

#[repr(C)]
pub struct KeyPair([c_uchar; 96]);
impl_array_newtype!(KeyPair, c_uchar, 96);
impl_raw_debug!(KeyPair);
