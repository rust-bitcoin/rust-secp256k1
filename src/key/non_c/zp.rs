use core::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign};

/// Implementation of field of Z<sub>P</sub>, where P is the secp256k1 paramter.
use super::u256::U256;

const P: U256 = U256::from_be_bytes([
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFC, 0x2F,
]);

/// Implementation of `Z_p` cyclic group where `p` is the size of the field used in secp256k1 - se
/// the `P` constant in this library.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub(crate) struct Zp(U256);

impl Zp {
    pub(crate) const ZERO: Self = Zp(U256::ZERO);
    pub(crate) const ONE: Self = Zp(U256::ONE);

    /// Converts the value % P to Self
    pub(crate) fn wrapping_from(value: U256) -> Self {
        if value >= P {
            Zp(value.wrapping_sub(P))
        } else {
            Zp(value)
        }
    }

    pub(crate) fn checked_from(value: U256) -> Option<Self> {
        if value >= P {
            None
        } else {
            Some(Zp(value))
        }
    }

    pub fn to_be_bytes(&self) -> [u8; 32] { self.0.to_be_bytes() }

    pub fn from_be_bytes(bytes: &[u8; 32]) -> Option<Self> {
        Self::checked_from(U256::from_be_bytes(*bytes))
    }

    pub(crate) fn is_zero(&self) -> bool { self.0.is_zero() }

    pub(crate) fn is_even(&self) -> bool { self.0 < P / 2u128.into() }

    pub(crate) fn parity(&self) -> crate::Parity {
        if self.is_even() {
            crate::Parity::Even
        } else {
            crate::Parity::Odd
        }
    }

    pub(crate) fn pow(mut self, mut exp: U256) -> Self {
        let mut res = Zp::ONE;
        while exp != U256::ZERO {
            if exp & U256::ONE == U256::ONE {
                res = res * self;
            }
            self = self * self;
            exp = exp >> 1;
        }
        res
    }

    pub fn multiplicative_inverse(self) -> Self {
        // refactored from
        // https://github.com/paritytech/bigint/blob/master/src/uint.rs
        let mut mn = (P, self.0);
        let mut xy = (Zp::ZERO, Zp::ONE);

        while mn.1 != U256::ZERO {
            let sb = xy.1 * (mn.0 / mn.1);
            xy = (xy.1, xy.0 - sb);
            mn = (mn.1, mn.0 % mn.1);
        }

        xy.0
    }

    pub(crate) fn sqrt(&self, parity: crate::Parity) -> Option<Self> {
        // Copied from https://github.com/KanoczTomas/ecc-generic
        // and simplified
        if self.is_zero() {
            return Some(*self);
        }
        if !self.is_quadratic_residue() {
            return None;
        }
        let res = self.pow((P + U256::ONE) / 4u128.into());
        if parity == res.parity() {
            Some(res)
        } else {
            Some(-res)
        }
    }

    pub fn is_quadratic_residue(self) -> bool {
        // Copied from https://github.com/KanoczTomas/ecc-generic
        //if self % p == 0
        //As Zp is already mod p, we just have to check if it is 0
        match self.is_zero() {
            true => true,
            false => self.pow((P - U256::ONE) / 2u128.into()) == Zp::ONE,
        }
    }
}

// We use simple subtraction instead of modulo as it should be more efficient
impl Add for Zp {
    type Output = Self;

    fn add(self, rhs: Zp) -> Self::Output {
        let (res, overflow) = self.0.overflowing_add(rhs.0);
        Zp(if overflow || res >= P { res.wrapping_sub(P) } else { res })
    }
}

impl AddAssign for Zp {
    fn add_assign(&mut self, rhs: Self) { *self = *self + rhs; }
}

impl Sub for Zp {
    type Output = Self;

    fn sub(self, rhs: Zp) -> Self::Output {
        let (res, overflow) = self.0.overflowing_sub(rhs.0);
        Zp(if overflow || res >= P { res.wrapping_add(P) } else { res })
    }
}

impl SubAssign for Zp {
    fn sub_assign(&mut self, rhs: Self) { *self = *self - rhs; }
}

impl Mul<U256> for Zp {
    type Output = Zp;

    /// Double-and-add algorithm
    fn mul(self, mut rhs: U256) -> Self::Output {
        let mut res = Zp::ZERO;
        let high = U256::ONE << 255;

        for _ in 0..256 {
            // Can't use *= 2 - that would cause infinite recursion.
            // Don't ask how I know.
            res += res;
            if rhs & high != U256::ZERO {
                res += self;
            }
            rhs = rhs.wrapping_shl(1);
        }

        res
    }
}

impl Mul<u64> for Zp {
    type Output = Zp;

    fn mul(self, rhs: u64) -> Self::Output { self * U256::from(rhs) }
}

impl MulAssign<u64> for Zp {
    fn mul_assign(&mut self, rhs: u64) { *self = *self * rhs; }
}

impl Mul for Zp {
    type Output = Zp;

    fn mul(self, rhs: Zp) -> Self::Output { self * rhs.0 }
}

impl MulAssign for Zp {
    fn mul_assign(&mut self, rhs: Self) { *self = *self * rhs; }
}

impl Div for Zp {
    type Output = Zp;

    fn div(self, rhs: Zp) -> Self::Output { self * rhs.multiplicative_inverse() }
}

impl DivAssign for Zp {
    fn div_assign(&mut self, rhs: Self) { *self = *self / rhs; }
}

impl Neg for Zp {
    type Output = Zp;

    fn neg(self) -> Self::Output {
        if self.is_zero() {
            self
        } else {
            Zp(P - self.0)
        }
    }
}
