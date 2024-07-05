//! Pure Rust implementation of basic secp256k1-related checks.
//!
//! It can be useful to have the key types provided by this library without full cryptography and
//! implied compilation/linking of C. However for compatibility, we must check the keys when
//! deserializing. Therefore we need at least some basic secp256k1 math to do that.
//!
//! We explicitly do **not** implement point operations or similarly advanced features.

pub(crate) mod u256;
pub(crate) mod zp;

use zp::Zp;

use crate::Parity;

fn is_point_on_curve(x: Zp, y: Zp) -> bool {
    y * y == x * x * x + Zp::wrapping_from(u256::U256::from(7u128))
}

fn compute_y_coord(x: Zp, parity: Parity) -> Option<Zp> {
    (x * x * x + Zp::wrapping_from(u256::U256::from(7u128))).sqrt(parity)
}

#[derive(Copy, Clone, Debug, PartialOrd, Ord, PartialEq, Eq, Hash)]
pub(crate) struct PublicKey {
    x: Zp,
    y: Zp,
}

impl PublicKey {
    pub(crate) fn decode(key: &[u8]) -> Option<Self> {
        match *key.get(0)? {
            0x04 if key.len() == 65 => {
                let x = Zp::from_be_bytes(key[1..33].try_into().expect("static len"))?;
                let y = Zp::from_be_bytes(key[33..].try_into().expect("static len"))?;
                if is_point_on_curve(x, y) {
                    Some(PublicKey { x, y })
                } else {
                    None
                }
            }
            parity @ (0x02 | 0x03) if key.len() == 33 => {
                let x = Zp::from_be_bytes(key[1..33].try_into().expect("static len"))?;
                let y =
                    compute_y_coord(x, if parity == 0x02 { Parity::Even } else { Parity::Odd })?;
                Some(PublicKey { x, y })
            }
            _ => None,
        }
    }

    pub(crate) fn serialize_compressed(&self) -> [u8; 33] {
        let mut buf = [0; 33];
        buf[0] = if self.y.is_even() { 0x02 } else { 0x03 };
        buf[1..].copy_from_slice(&self.x.to_be_bytes());
        buf
    }

    pub(crate) fn serialize_uncompressed(&self) -> [u8; 65] {
        let mut buf = [0; 65];
        buf[0] = 0x04;
        buf[1..33].copy_from_slice(&self.x.to_be_bytes());
        buf[33..].copy_from_slice(&self.y.to_be_bytes());
        buf
    }

    pub(crate) fn to_xonly(&self) -> (XOnlyPublicKey, Parity) {
        let parity = if self.y.is_even() { Parity::Even } else { Parity::Odd };
        (XOnlyPublicKey { x: self.x }, parity)
    }
}

#[derive(Copy, Clone, Debug, PartialOrd, Ord, PartialEq, Eq, Hash)]
pub(crate) struct XOnlyPublicKey {
    x: Zp,
}

impl XOnlyPublicKey {
    pub(crate) fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        let x = Zp::from_be_bytes(bytes)?;
        compute_y_coord(x, Parity::Even)?;
        Some(XOnlyPublicKey { x })
    }

    pub(crate) fn serialize(&self) -> [u8; 32] { self.x.to_be_bytes() }
}

pub(crate) fn is_seckey_valid(scalar: &[u8; 32]) -> bool {
    let sum = scalar.iter().copied().fold(0u8, u8::wrapping_add);
    if launder_u8(sum) == 0 {
        return false;
    }

    // Translated from the C version
    const N: [u32; 8] = [
        0xD0364141, 0xBFD25E8C, 0xAF48A03B, 0xBAAEDCE6, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF,
        0xFFFFFFFF,
    ];
    let mut buf = [0; 8];
    for (chunk, dst) in scalar.chunks_exact(4).rev().zip(&mut buf) {
        *dst = u32::from_be_bytes(chunk.try_into().expect("chunk_exact returns 4-byte slices"));
    }
    let scalar = buf;
    let mut yes = 0u8;
    let mut no = 0u8;
    no |= u8::from(scalar[7] < N[7]); /* No need for a > check. */
    no |= u8::from(scalar[6] < N[6]); /* No need for a > check. */
    no |= u8::from(scalar[5] < N[5]); /* No need for a > check. */
    no |= u8::from(scalar[4] < N[4]);
    yes |= u8::from(scalar[4] > N[4]) & !no;
    no |= u8::from(scalar[3] < N[3]) & !yes;
    yes |= u8::from(scalar[3] > N[3]) & !no;
    no |= u8::from(scalar[2] < N[2]) & !yes;
    yes |= u8::from(scalar[2] > N[2]) & !no;
    no |= u8::from(scalar[1] < N[1]) & !yes;
    yes |= u8::from(scalar[1] > N[1]) & !no;
    yes |= u8::from(scalar[0] >= N[0]) & !no;
    launder_u8(yes) == 0
}

fn launder_u8(val: u8) -> u8 { unsafe { core::ptr::read_volatile(&val) } }
