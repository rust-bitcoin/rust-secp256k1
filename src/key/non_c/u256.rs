#![allow(dead_code)]
use core::fmt;
/// Implementation of unsigned 256-bit integer, copied from `bitcoin`.
// Probably better than constant refactoring
use core::ops::{Add, BitAnd, Div, Mul, Not, Rem, Shl, Shr, Sub};

/// Big-endian 256 bit integer type.
// (high, low): u.0 contains the high bits, u.1 contains the low bits.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub(crate) struct U256(u128, u128);

impl U256 {
    const MAX: U256 =
        U256(0xffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff, 0xffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff);

    pub(crate) const ZERO: U256 = U256(0, 0);

    pub(crate) const ONE: U256 = U256(0, 1);

    /// Creates `U256` from a big-endian array of `u8`s.
    #[cfg_attr(all(test, mutate), mutate)]
    pub(crate) const fn from_be_bytes(a: [u8; 32]) -> U256 {
        let (high, low) = split_in_half(a);
        let big = u128::from_be_bytes(high);
        let little = u128::from_be_bytes(low);
        U256(big, little)
    }

    /// Creates a `U256` from a little-endian array of `u8`s.
    #[cfg_attr(all(test, mutate), mutate)]
    pub(crate) fn from_le_bytes(a: [u8; 32]) -> U256 {
        let (high, low) = split_in_half(a);
        let little = u128::from_le_bytes(high);
        let big = u128::from_le_bytes(low);
        U256(big, little)
    }

    /// Converts `U256` to a big-endian array of `u8`s.
    #[cfg_attr(all(test, mutate), mutate)]
    pub(crate) fn to_be_bytes(self) -> [u8; 32] {
        let mut out = [0; 32];
        out[..16].copy_from_slice(&self.0.to_be_bytes());
        out[16..].copy_from_slice(&self.1.to_be_bytes());
        out
    }

    /// Converts `U256` to a little-endian array of `u8`s.
    #[cfg_attr(all(test, mutate), mutate)]
    pub(crate) fn to_le_bytes(self) -> [u8; 32] {
        let mut out = [0; 32];
        out[..16].copy_from_slice(&self.1.to_le_bytes());
        out[16..].copy_from_slice(&self.0.to_le_bytes());
        out
    }

    #[cfg_attr(all(test, mutate), mutate)]
    pub(crate) fn is_zero(&self) -> bool { self.0 == 0 && self.1 == 0 }

    #[cfg_attr(all(test, mutate), mutate)]
    pub(crate) fn is_one(&self) -> bool { self.0 == 0 && self.1 == 1 }

    #[cfg_attr(all(test, mutate), mutate)]
    pub(crate) fn is_max(&self) -> bool { self.0 == u128::MAX && self.1 == u128::MAX }

    /// Returns the low 32 bits.
    pub(crate) fn low_u32(&self) -> u32 { self.low_u128() as u32 }

    /// Returns the low 64 bits.
    pub(crate) fn low_u64(&self) -> u64 { self.low_u128() as u64 }

    /// Returns the low 128 bits.
    pub(crate) fn low_u128(&self) -> u128 { self.1 }

    /// Returns this `U256` as a `u128` saturating to `u128::MAX` if `self` is too big.
    // Matagen gives false positive because >= and > both return u128::MAX
    pub(crate) fn saturating_to_u128(&self) -> u128 {
        if *self > U256::from(u128::MAX) {
            u128::MAX
        } else {
            self.low_u128()
        }
    }

    /// Returns the least number of bits needed to represent the number.
    #[cfg_attr(all(test, mutate), mutate)]
    pub(crate) fn bits(&self) -> u32 {
        if self.0 > 0 {
            256 - self.0.leading_zeros()
        } else {
            128 - self.1.leading_zeros()
        }
    }

    /// Wrapping multiplication by `u64`.
    ///
    /// # Returns
    ///
    /// The multiplication result along with a boolean indicating whether an arithmetic overflow
    /// occurred. If an overflow occurred then the wrapped value is returned.
    // mutagen false pos mul_u64: replace `|` with `^` (XOR is same as OR when combined with <<)
    // mutagen false pos mul_u64: replace `|` with `^`
    #[cfg_attr(all(test, mutate), mutate)]
    pub(crate) fn mul_u64(self, rhs: u64) -> (U256, bool) {
        let mut carry: u128 = 0;
        let mut split_le =
            [self.1 as u64, (self.1 >> 64) as u64, self.0 as u64, (self.0 >> 64) as u64];

        for word in &mut split_le {
            // This will not overflow, for proof see https://github.com/rust-bitcoin/rust-bitcoin/pull/1496#issuecomment-1365938572
            let n = carry + u128::from(rhs) * u128::from(*word);

            *word = n as u64; // Intentional truncation, save the low bits
            carry = n >> 64; // and carry the high bits.
        }

        let low = u128::from(split_le[0]) | u128::from(split_le[1]) << 64;
        let high = u128::from(split_le[2]) | u128::from(split_le[3]) << 64;
        (Self(high, low), carry != 0)
    }

    /// Calculates quotient and remainder.
    ///
    /// # Returns
    ///
    /// (quotient, remainder)
    ///
    /// # Panics
    ///
    /// If `rhs` is zero.
    #[cfg_attr(all(test, mutate), mutate)]
    pub(crate) fn div_rem(self, rhs: Self) -> (Self, Self) {
        let mut sub_copy = self;
        let mut shift_copy = rhs;
        let mut ret = [0u128; 2];

        let my_bits = self.bits();
        let your_bits = rhs.bits();

        // Check for division by 0
        assert!(your_bits != 0, "attempted to divide {:?} by zero", self);

        // Early return in case we are dividing by a larger number than us
        if my_bits < your_bits {
            return (U256::ZERO, sub_copy);
        }

        // Bitwise long division
        let mut shift = my_bits - your_bits;
        shift_copy = shift_copy << shift;
        loop {
            if sub_copy >= shift_copy {
                ret[1 - (shift / 128) as usize] |= 1 << (shift % 128);
                sub_copy = sub_copy.wrapping_sub(shift_copy);
            }
            shift_copy = shift_copy >> 1;
            if shift == 0 {
                break;
            }
            shift -= 1;
        }

        (U256(ret[0], ret[1]), sub_copy)
    }

    /// Calculates `self` + `rhs`
    ///
    /// Returns a tuple of the addition along with a boolean indicating whether an arithmetic
    /// overflow would occur. If an overflow would have occurred then the wrapped value is returned.
    #[must_use = "this returns the result of the operation, without modifying the original"]
    #[cfg_attr(all(test, mutate), mutate)]
    pub(crate) fn overflowing_add(self, rhs: Self) -> (Self, bool) {
        let mut ret = U256::ZERO;
        let mut ret_overflow = false;

        let (high, overflow) = self.0.overflowing_add(rhs.0);
        ret.0 = high;
        ret_overflow |= overflow;

        let (low, overflow) = self.1.overflowing_add(rhs.1);
        ret.1 = low;
        if overflow {
            let (high, overflow) = ret.0.overflowing_add(1);
            ret.0 = high;
            ret_overflow |= overflow;
        }

        (ret, ret_overflow)
    }

    /// Calculates `self` - `rhs`
    ///
    /// Returns a tuple of the subtraction along with a boolean indicating whether an arithmetic
    /// overflow would occur. If an overflow would have occurred then the wrapped value is returned.
    #[must_use = "this returns the result of the operation, without modifying the original"]
    #[cfg_attr(all(test, mutate), mutate)]
    pub(crate) fn overflowing_sub(self, rhs: Self) -> (Self, bool) {
        let ret = self.wrapping_add(!rhs).wrapping_add(Self::ONE);
        let overflow = rhs > self;
        (ret, overflow)
    }

    /// Calculates the multiplication of `self` and `rhs`.
    ///
    /// Returns a tuple of the multiplication along with a boolean
    /// indicating whether an arithmetic overflow would occur. If an
    /// overflow would have occurred then the wrapped value is returned.
    #[must_use = "this returns the result of the operation, without modifying the original"]
    #[cfg_attr(all(test, mutate), mutate)]
    pub(crate) fn overflowing_mul(self, rhs: Self) -> (Self, bool) {
        let mut ret = U256::ZERO;
        let mut ret_overflow = false;

        for i in 0..3 {
            let to_mul = (rhs >> (64 * i)).low_u64();
            let (mul_res, _) = self.mul_u64(to_mul);
            ret = ret.wrapping_add(mul_res << (64 * i));
        }

        let to_mul = (rhs >> 192).low_u64();
        let (mul_res, overflow) = self.mul_u64(to_mul);
        ret_overflow |= overflow;
        let (sum, overflow) = ret.overflowing_add(mul_res);
        ret = sum;
        ret_overflow |= overflow;

        (ret, ret_overflow)
    }

    /// Wrapping (modular) addition. Computes `self + rhs`, wrapping around at the boundary of the
    /// type.
    #[must_use = "this returns the result of the operation, without modifying the original"]
    pub(crate) fn wrapping_add(self, rhs: Self) -> Self {
        let (ret, _overflow) = self.overflowing_add(rhs);
        ret
    }

    /// Wrapping (modular) subtraction. Computes `self - rhs`, wrapping around at the boundary of
    /// the type.
    #[must_use = "this returns the result of the operation, without modifying the original"]
    pub(crate) fn wrapping_sub(self, rhs: Self) -> Self {
        let (ret, _overflow) = self.overflowing_sub(rhs);
        ret
    }

    /// Wrapping (modular) multiplication. Computes `self * rhs`, wrapping around at the boundary of
    /// the type.
    #[must_use = "this returns the result of the operation, without modifying the original"]
    #[cfg(test)]
    pub(crate) fn wrapping_mul(self, rhs: Self) -> Self {
        let (ret, _overflow) = self.overflowing_mul(rhs);
        ret
    }

    /// Returns `self` incremented by 1 wrapping around at the boundary of the type.
    #[must_use = "this returns the result of the increment, without modifying the original"]
    #[cfg_attr(all(test, mutate), mutate)]
    pub(crate) fn wrapping_inc(&self) -> U256 {
        let mut ret = U256::ZERO;

        ret.1 = self.1.wrapping_add(1);
        if ret.1 == 0 {
            ret.0 = self.0.wrapping_add(1);
        } else {
            ret.0 = self.0;
        }
        ret
    }

    /// Panic-free bitwise shift-left; yields `self << mask(rhs)`, where `mask` removes any
    /// high-order bits of `rhs` that would cause the shift to exceed the bitwidth of the type.
    ///
    /// Note that this is *not* the same as a rotate-left; the RHS of a wrapping shift-left is
    /// restricted to the range of the type, rather than the bits shifted out of the LHS being
    /// returned to the other end. We do not currently support `rotate_left`.
    #[must_use = "this returns the result of the operation, without modifying the original"]
    #[cfg_attr(all(test, mutate), mutate)]
    pub(crate) fn wrapping_shl(self, rhs: u32) -> Self {
        let shift = rhs & 0x000000ff;

        let mut ret = U256::ZERO;
        let word_shift = shift >= 128;
        let bit_shift = shift % 128;

        if word_shift {
            ret.0 = self.1 << bit_shift
        } else {
            ret.0 = self.0 << bit_shift;
            if bit_shift > 0 {
                ret.0 += self.1.wrapping_shr(128 - bit_shift);
            }
            ret.1 = self.1 << bit_shift;
        }
        ret
    }

    /// Panic-free bitwise shift-right; yields `self >> mask(rhs)`, where `mask` removes any
    /// high-order bits of `rhs` that would cause the shift to exceed the bitwidth of the type.
    ///
    /// Note that this is *not* the same as a rotate-right; the RHS of a wrapping shift-right is
    /// restricted to the range of the type, rather than the bits shifted out of the LHS being
    /// returned to the other end. We do not currently support `rotate_right`.
    #[must_use = "this returns the result of the operation, without modifying the original"]
    #[cfg_attr(all(test, mutate), mutate)]
    pub(crate) fn wrapping_shr(self, rhs: u32) -> Self {
        let shift = rhs & 0x000000ff;

        let mut ret = U256::ZERO;
        let word_shift = shift >= 128;
        let bit_shift = shift % 128;

        if word_shift {
            ret.1 = self.0 >> bit_shift
        } else {
            ret.0 = self.0 >> bit_shift;
            ret.1 = self.1 >> bit_shift;
            if bit_shift > 0 {
                ret.1 += self.0.wrapping_shl(128 - bit_shift);
            }
        }
        ret
    }
}

impl<T: Into<u128>> From<T> for U256 {
    fn from(x: T) -> Self { U256(0, x.into()) }
}

impl Add for U256 {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        let (res, overflow) = self.overflowing_add(rhs);
        debug_assert!(!overflow, "Addition of U256 values overflowed");
        res
    }
}

impl Sub for U256 {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        let (res, overflow) = self.overflowing_sub(rhs);
        debug_assert!(!overflow, "Subtraction of U256 values overflowed");
        res
    }
}

impl Mul for U256 {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self {
        let (res, overflow) = self.overflowing_mul(rhs);
        debug_assert!(!overflow, "Multiplication of U256 values overflowed");
        res
    }
}

impl Div for U256 {
    type Output = Self;
    fn div(self, rhs: Self) -> Self { self.div_rem(rhs).0 }
}

impl Rem for U256 {
    type Output = Self;
    fn rem(self, rhs: Self) -> Self { self.div_rem(rhs).1 }
}

impl Not for U256 {
    type Output = Self;

    fn not(self) -> Self { U256(!self.0, !self.1) }
}

impl BitAnd for U256 {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self { U256(self.0 & rhs.0, self.1 & rhs.1) }
}

impl Shl<u32> for U256 {
    type Output = Self;
    fn shl(self, shift: u32) -> U256 { self.wrapping_shl(shift) }
}

impl Shr<u32> for U256 {
    type Output = Self;
    fn shr(self, shift: u32) -> U256 { self.wrapping_shr(shift) }
}

impl fmt::Debug for U256 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for x in &self.to_be_bytes() {
            write!(f, "{:02x}", x)?;
        }
        Ok(())
    }
}

/// Splits a 32 byte array into two 16 byte arrays.
const fn split_in_half(a: [u8; 32]) -> ([u8; 16], [u8; 16]) {
    let mut high = [0_u8; 16];
    let mut low = [0_u8; 16];
    let mut i = 0;
    while i < 16 {
        high[i] = a[i];
        i += 1;
    }
    i = 0;
    while i < 16 {
        low[i] = a[i + 16];
        i += 1;
    }

    (high, low)
}
