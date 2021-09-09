//! Structs and functionality related to the ECDSA signature algorithm.

use core::{fmt, str, ops};
use Error;
use ffi::CPtr;
use ffi;
use from_hex;

#[cfg(feature = "recovery")]
mod recovery;

#[cfg(feature = "recovery")]
pub use self::recovery::{RecoveryId, RecoverableSignature};

/// An ECDSA signature
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct Signature(pub(crate) ffi::Signature);

/// A DER serialized Signature
#[derive(Copy, Clone)]
pub struct SerializedSignature {
    data: [u8; 72],
    len: usize,
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let sig = self.serialize_der();
        for v in sig.iter() {
            write!(f, "{:02x}", v)?;
        }
        Ok(())
    }
}

impl str::FromStr for Signature {
    type Err = Error;
    fn from_str(s: &str) -> Result<Signature, Error> {
        let mut res = [0u8; 72];
        match from_hex(s, &mut res) {
            Ok(x) => Signature::from_der(&res[0..x]),
            _ => Err(Error::InvalidSignature),
        }
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
        self.data[..self.len] == other.data[..other.len]
    }
}

impl AsRef<[u8]> for SerializedSignature {
    fn as_ref(&self) -> &[u8] {
        &self.data[..self.len]
    }
}

impl ops::Deref for SerializedSignature {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.data[..self.len]
    }
}

impl Eq for SerializedSignature {}

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
        Signature::from_der(&self)
    }

    /// Create a SerializedSignature from a Signature.
    /// (this DER serializes it)
    pub fn from_signature(sig: &Signature) -> SerializedSignature {
        sig.serialize_der()
    }

    /// Check if the space is zero.
    pub fn is_empty(&self) -> bool { self.len() == 0 }
}

impl Signature {
    #[inline]
    /// Converts a DER-encoded byte slice to a signature
    pub fn from_der(data: &[u8]) -> Result<Signature, Error> {
        if data.is_empty() {return Err(Error::InvalidSignature);}

        unsafe {
            let mut ret = ffi::Signature::new();
            if ffi::secp256k1_ecdsa_signature_parse_der(
                ffi::secp256k1_context_no_precomp,
                &mut ret,
                data.as_c_ptr(),
                data.len() as usize,
            ) == 1
            {
                Ok(Signature(ret))
            } else {
                Err(Error::InvalidSignature)
            }
        }
    }

    /// Converts a 64-byte compact-encoded byte slice to a signature
    pub fn from_compact(data: &[u8]) -> Result<Signature, Error> {
        if data.len() != 64 {
            return Err(Error::InvalidSignature)
        }

        unsafe {
            let mut ret = ffi::Signature::new();
            if ffi::secp256k1_ecdsa_signature_parse_compact(
                ffi::secp256k1_context_no_precomp,
                &mut ret,
                data.as_c_ptr(),
            ) == 1
            {
                Ok(Signature(ret))
            } else {
                Err(Error::InvalidSignature)
            }
        }
    }

    /// Converts a "lax DER"-encoded byte slice to a signature. This is basically
    /// only useful for validating signatures in the Bitcoin blockchain from before
    /// 2016. It should never be used in new applications. This library does not
    /// support serializing to this "format"
    pub fn from_der_lax(data: &[u8]) -> Result<Signature, Error> {
        if data.is_empty() {return Err(Error::InvalidSignature);}

        unsafe {
            let mut ret = ffi::Signature::new();
            if ffi::ecdsa_signature_parse_der_lax(
                ffi::secp256k1_context_no_precomp,
                &mut ret,
                data.as_c_ptr(),
                data.len() as usize,
            ) == 1
            {
                Ok(Signature(ret))
            } else {
                Err(Error::InvalidSignature)
            }
        }
    }

    /// Normalizes a signature to a "low S" form. In ECDSA, signatures are
    /// of the form (r, s) where r and s are numbers lying in some finite
    /// field. The verification equation will pass for (r, s) iff it passes
    /// for (r, -s), so it is possible to ``modify'' signatures in transit
    /// by flipping the sign of s. This does not constitute a forgery since
    /// the signed message still cannot be changed, but for some applications,
    /// changing even the signature itself can be a problem. Such applications
    /// require a "strong signature". It is believed that ECDSA is a strong
    /// signature except for this ambiguity in the sign of s, so to accommodate
    /// these applications libsecp256k1 will only accept signatures for which
    /// s is in the lower half of the field range. This eliminates the
    /// ambiguity.
    ///
    /// However, for some systems, signatures with high s-values are considered
    /// valid. (For example, parsing the historic Bitcoin blockchain requires
    /// this.) For these applications we provide this normalization function,
    /// which ensures that the s value lies in the lower half of its range.
    pub fn normalize_s(&mut self) {
        unsafe {
            // Ignore return value, which indicates whether the sig
            // was already normalized. We don't care.
            ffi::secp256k1_ecdsa_signature_normalize(
                ffi::secp256k1_context_no_precomp,
                self.as_mut_c_ptr(),
                self.as_c_ptr(),
            );
        }
    }

    /// Obtains a raw pointer suitable for use with FFI functions
    #[inline]
    pub fn as_ptr(&self) -> *const ffi::Signature {
        &self.0
    }

    /// Obtains a raw mutable pointer suitable for use with FFI functions
    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut ffi::Signature {
        &mut self.0
    }

    #[inline]
    /// Serializes the signature in DER format
    pub fn serialize_der(&self) -> SerializedSignature {
        let mut ret = SerializedSignature::default();
        let mut len: usize = ret.capacity();
        unsafe {
            let err = ffi::secp256k1_ecdsa_signature_serialize_der(
                ffi::secp256k1_context_no_precomp,
                ret.get_data_mut_ptr(),
                &mut len,
                self.as_c_ptr(),
            );
            debug_assert!(err == 1);
            ret.set_len(len);
        }
        ret
    }

    #[inline]
    /// Serializes the signature in compact format
    pub fn serialize_compact(&self) -> [u8; 64] {
        let mut ret = [0u8; 64];
        unsafe {
            let err = ffi::secp256k1_ecdsa_signature_serialize_compact(
                ffi::secp256k1_context_no_precomp,
                ret.as_mut_c_ptr(),
                self.as_c_ptr(),
            );
            debug_assert!(err == 1);
        }
        ret
    }
}

impl CPtr for Signature {
    type Target = ffi::Signature;

    fn as_c_ptr(&self) -> *const Self::Target {
        self.as_ptr()
    }

    fn as_mut_c_ptr(&mut self) -> *mut Self::Target {
        self.as_mut_ptr()
    }
}

/// Creates a new signature from a FFI signature
impl From<ffi::Signature> for Signature {
    #[inline]
    fn from(sig: ffi::Signature) -> Signature {
        Signature(sig)
    }
}

#[cfg(feature = "serde")]
impl ::serde::Serialize for Signature {
    fn serialize<S: ::serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.collect_str(self)
        } else {
            s.serialize_bytes(&self.serialize_der())
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> ::serde::Deserialize<'de> for Signature {
    fn deserialize<D: ::serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        if d.is_human_readable() {
            d.deserialize_str(::serde_util::FromStrVisitor::new(
                "a hex string representing a DER encoded Signature"
            ))
        } else {
            d.deserialize_bytes(::serde_util::BytesVisitor::new(
                "raw byte stream, that represents a DER encoded Signature",
                Signature::from_der
            ))
        }
    }
}
