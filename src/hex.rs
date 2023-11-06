// SPDX-License-Identifier: CC0-1.0

//! Conversion to and from hexadecimal strings.

use core::str;

/// Utility function used to parse hex into a target u8 buffer. Returns
/// the number of bytes converted or an error if it encounters an invalid
/// character or unexpected end of string.
pub(crate) fn from_hex(hex: &str, target: &mut [u8]) -> Result<usize, ()> {
    if hex.len() % 2 == 1 || hex.len() > target.len() * 2 {
        return Err(());
    }

    let mut b = 0;
    let mut idx = 0;
    for c in hex.bytes() {
        b <<= 4;
        match c {
            b'A'..=b'F' => b |= c - b'A' + 10,
            b'a'..=b'f' => b |= c - b'a' + 10,
            b'0'..=b'9' => b |= c - b'0',
            _ => return Err(()),
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
pub(crate) fn to_hex<'a>(src: &[u8], target: &'a mut [u8]) -> Result<&'a str, ()> {
    let hex_len = src.len() * 2;
    if target.len() < hex_len {
        return Err(());
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
