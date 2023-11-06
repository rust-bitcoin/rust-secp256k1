// SPDX-License-Identifier: CC0-1.0

//! Conversion to and from hexadecimal strings.

use core::str;

use crate::error::write_err;

/// Utility function used to parse hex into a target u8 buffer. Returns
/// the number of bytes converted or an error if it encounters an invalid
/// character or unexpected end of string.
pub(crate) fn from_hex(hex: &str, target: &mut [u8]) -> Result<usize, FromHexError> {
    if hex.len() % 2 == 1 {
        return Err(FromHexError::UnevenLength(UnevenLengthError { len: hex.len() }));
    }

    if hex.len() > target.len() * 2 {
        return Err(FromHexError::BufferTooSmall(BufferTooSmallError {
            hex: hex.len(),
            buffer: target.len(),
        }));
    }

    let mut b = 0;
    let mut idx = 0;
    for c in hex.bytes() {
        b <<= 4;
        match c {
            b'A'..=b'F' => b |= c - b'A' + 10,
            b'a'..=b'f' => b |= c - b'a' + 10,
            b'0'..=b'9' => b |= c - b'0',
            byte => return Err(FromHexError::InvalidByte(InvalidByteError { invalid: byte })),
        }
        if (idx & 1) == 1 {
            target[idx / 2] = b;
            b = 0;
        }
        idx += 1;
    }
    Ok(idx / 2)
}

/// Utility function used to encode hex into a target u8 buffer. Returns
/// a reference to the target buffer as an str. Returns an error if the target
/// buffer isn't big enough.
#[inline]
pub(crate) fn to_hex<'a>(src: &[u8], target: &'a mut [u8]) -> Result<&'a str, ToHexError> {
    let hex_len = src.len() * 2;
    if target.len() < hex_len {
        return Err(ToHexError { hex: hex_len, buffer: target.len() });
    }
    const HEX_TABLE: [u8; 16] = *b"0123456789abcdef";

    let mut i = 0;
    for &b in src {
        target[i] = HEX_TABLE[usize::from(b >> 4)];
        target[i + 1] = HEX_TABLE[usize::from(b & 0b00001111)];
        i += 2;
    }
    let result = &target[..hex_len];
    debug_assert!(str::from_utf8(result).is_ok());
    return unsafe { Ok(str::from_utf8_unchecked(result)) };
}

/// Error converting from a hex string.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(missing_copy_implementations)] // Don't implement Copy when we use non_exhaustive.
#[non_exhaustive]
pub enum FromHexError {
    /// Hex string length uneven.
    UnevenLength(UnevenLengthError),
    /// Target data buffer too small to decode hex.
    BufferTooSmall(BufferTooSmallError),
    /// Byte is not valid hex ASCII.
    InvalidByte(InvalidByteError),
}

impl core::fmt::Display for FromHexError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        use FromHexError::*;

        match *self {
            UnevenLength(ref e) => write_err!(f, "uneven length, converting from hex"; e),
            BufferTooSmall(ref e) => write_err!(f, "buffer too small, converting from hex"; e),
            InvalidByte(ref e) => write_err!(f, "invalid byte, convening from hex"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for FromHexError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use FromHexError::*;

        match *self {
            UnevenLength(ref e) => Some(e),
            BufferTooSmall(ref e) => Some(e),
            InvalidByte(ref e) => Some(e),
        }
    }
}

/// Hex string length uneven.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(missing_copy_implementations)] // Don't implement Copy when we use non_exhaustive.
#[non_exhaustive]
pub struct UnevenLengthError {
    len: usize,
}

impl core::fmt::Display for UnevenLengthError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        write!(f, "hex string uneven: {}", self.len)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for UnevenLengthError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}

/// Target data buffer too small to decode hex.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(missing_copy_implementations)] // Don't implement Copy when we use non_exhaustive.
#[non_exhaustive]
pub struct BufferTooSmallError {
    /// Length of the hex string.
    hex: usize,
    /// Size of the target data buffer.
    buffer: usize,
}

impl core::fmt::Display for BufferTooSmallError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        write!(
            f,
            "buffer too small to decode hex (hex length: {}, buffer size: {})",
            self.hex, self.buffer
        )
    }
}

#[cfg(feature = "std")]
impl std::error::Error for BufferTooSmallError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}

/// Byte is not valid hex ASCII.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(missing_copy_implementations)] // Don't implement Copy when we use non_exhaustive.
#[non_exhaustive]
pub struct InvalidByteError {
    invalid: u8,
}

impl core::fmt::Display for InvalidByteError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        write!(f, "byte is not valid hex ASCII: {:x}", self.invalid)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InvalidByteError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}

/// Buffer too small to encode hex data.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[allow(missing_copy_implementations)] // Don't implement Copy when we use non_exhaustive.
pub struct ToHexError {
    /// Required length of the encoded hex string.
    hex: usize,
    /// Size of the buffer (must be equal or larger that hex length).
    buffer: usize,
}

impl core::fmt::Display for ToHexError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        write!(
            f,
            "buffer too small to encode hex (required: {}, buffer: {})",
            self.hex, self.buffer
        )
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ToHexError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}
