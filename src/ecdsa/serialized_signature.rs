//! Implements [`SerializedSignature`] and related types.
//!
//! DER-serialized signatures have the issue that they can have different lengths.
//! We want to avoid using `Vec` since that would require allocations making the code slower and
//! unable to run on platforms without allocator. We implement a special type to encapsulate
//! serialized signatures and since it's a bit more complicated it has its own module.

use core::{fmt, ops};
use crate::Error;
use super::Signature;

/// A DER serialized Signature
#[derive(Copy, Clone)]
pub struct SerializedSignature {
    data: [u8; 72],
    len: usize,
}

impl fmt::Debug for SerializedSignature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for SerializedSignature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for v in self.data.iter().take(self.len) {
            write!(f, "{:02x}", v)?;
        }
        Ok(())
    }
}

impl Default for SerializedSignature {
    fn default() -> SerializedSignature {
        SerializedSignature {
            data: [0u8; 72],
            len: 0,
        }
    }
}

impl PartialEq for SerializedSignature {
    fn eq(&self, other: &SerializedSignature) -> bool {
        **self == **other
    }
}

impl AsRef<[u8]> for SerializedSignature {
    fn as_ref(&self) -> &[u8] {
        &*self
    }
}

impl ops::Deref for SerializedSignature {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.data[..self.len]
    }
}

impl Eq for SerializedSignature {}

impl<'a> IntoIterator for &'a SerializedSignature {
    type IntoIter = core::slice::Iter<'a, u8>;
    type Item = &'a u8;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl SerializedSignature {
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

    /// Convert the serialized signature into the Signature struct.
    /// (This DER deserializes it)
    pub fn to_signature(&self) -> Result<Signature, Error> {
        Signature::from_der(self)
    }

    /// Create a SerializedSignature from a Signature.
    /// (this DER serializes it)
    pub fn from_signature(sig: &Signature) -> SerializedSignature {
        sig.serialize_der()
    }

    /// Check if the space is zero.
    pub fn is_empty(&self) -> bool { self.len() == 0 }
}
