// SPDX-License-Identifier: CC0-1.0

//! Helpers for displaying secret values

use core::fmt;

use crate::constants::SECRET_KEY_SIZE;
use crate::ecdh::SharedSecret;
use crate::key::{Keypair, SecretKey};
use crate::to_hex;

macro_rules! impl_display_secret {
    ($thing:ident) => {
        impl ::core::fmt::Debug for $thing {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                use crate::ffi;
                use secp256k1_sys::CPtr;

                let mut finger_print = [0; 32];
                let msg = b"rust-secp256k1-DEBUG-MESSAGE-000";
                unsafe {
                    let nonce_fn= ffi::secp256k1_nonce_function_rfc6979.expect("nonce fn");
                    let ret = nonce_fn(
                        finger_print.as_mut_c_ptr(),
                        msg.as_c_ptr(),
                        self.as_c_ptr(),
                        core::ptr::null(),
                        core::ptr::null_mut(),
                        0
                    );
                    debug_assert_eq!(ret, 1)
                }
                f.debug_tuple(stringify!($thing)).field(&format_args!("{:?}", finger_print)).finish()
            }
        }
    };
}

/// Helper struct for safely printing secrets (like [`SecretKey`] value).
/// Formats the explicit byte value of the secret kept inside the type as a
/// little-endian hexadecimal string using the provided formatter.
///
/// Secrets should not implement neither [`Debug`] and [`Display`] traits directly,
/// and instead provide `fn display_secret<'a>(&'a self) -> DisplaySecret<'a>`
/// function to be used in different display contexts (see "examples" below).
///
/// [`Display`]: fmt::Display
/// [`Debug`]: fmt::Debug
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DisplaySecret {
    secret: [u8; SECRET_KEY_SIZE],
}
impl_non_secure_erase!(DisplaySecret, secret, [0u8; SECRET_KEY_SIZE]);

impl fmt::Debug for DisplaySecret {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut slice = [0u8; SECRET_KEY_SIZE * 2];
        let hex = to_hex(&self.secret, &mut slice).expect("fixed-size hex serializer failed");
        f.debug_tuple("DisplaySecret").field(&hex).finish()
    }
}

impl fmt::Display for DisplaySecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.secret {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

impl SecretKey {
    /// Formats the explicit byte value of the secret key kept inside the type as a
    /// little-endian hexadecimal string using the provided formatter.
    ///
    /// This is the only method that outputs the actual secret key value, and, thus,
    /// should be used with extreme caution.
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(feature = "std")] {
    /// # use std::str::FromStr;
    /// use secp256k1::SecretKey;
    /// let key = SecretKey::from_str("0000000000000000000000000000000000000000000000000000000000000001").unwrap();
    ///
    /// // Normal debug hides value (`Display` is not implemented for `SecretKey`).
    /// // E.g., `format!("{:?}", key)` prints "SecretKey(#2518682f7819fb2d)".
    ///
    /// // Here we explicitly display the secret value:
    /// assert_eq!(
    ///     "0000000000000000000000000000000000000000000000000000000000000001",
    ///     format!("{}", key.display_secret())
    /// );
    /// // Also, we can explicitly display with `Debug`:
    /// assert_eq!(
    ///     format!("{:?}", key.display_secret()),
    ///     format!("DisplaySecret(\"{}\")", key.display_secret())
    /// );
    /// # }
    /// ```
    #[inline]
    pub fn display_secret(&self) -> DisplaySecret { DisplaySecret { secret: self.secret_bytes() } }
}

impl Keypair {
    /// Formats the explicit byte value of the secret key kept inside the type as a
    /// little-endian hexadecimal string using the provided formatter.
    ///
    /// This is the only method that outputs the actual secret key value, and, thus,
    /// should be used with extreme precaution.
    ///
    /// # Example
    ///
    /// ```
    /// # #[cfg(feature = "std")] {
    /// # use std::str::FromStr;
    /// use secp256k1::{Keypair, Secp256k1, SecretKey};
    ///
    /// let secp = Secp256k1::new();
    /// let key = SecretKey::from_str("0000000000000000000000000000000000000000000000000000000000000001").unwrap();
    /// let key = Keypair::from_secret_key(&secp, &key);
    /// // Here we explicitly display the secret value:
    /// assert_eq!(
    ///     "0000000000000000000000000000000000000000000000000000000000000001",
    ///     format!("{}", key.display_secret())
    /// );
    /// // Also, we can explicitly display with `Debug`:
    /// assert_eq!(
    ///     format!("{:?}", key.display_secret()),
    ///     format!("DisplaySecret(\"{}\")", key.display_secret())
    /// );
    /// # }
    /// ```
    #[inline]
    pub fn display_secret(&self) -> DisplaySecret { DisplaySecret { secret: self.secret_bytes() } }
}

impl SharedSecret {
    /// Formats the explicit byte value of the shared secret kept inside the type as a
    /// little-endian hexadecimal string using the provided formatter.
    ///
    /// This is the only method that outputs the actual shared secret value, and, thus,
    /// should be used with extreme caution.
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(not(secp256k1_fuzz))]
    /// # #[cfg(feature = "std")] {
    /// # use std::str::FromStr;
    /// use secp256k1::{SecretKey, PublicKey};
    /// use secp256k1::ecdh::SharedSecret;
    ///
    /// # let pk = PublicKey::from_slice(&[3, 23, 183, 225, 206, 31, 159, 148, 195, 42, 67, 115, 146, 41, 248, 140, 11, 3, 51, 41, 111, 180, 110, 143, 114, 134, 88, 73, 198, 174, 52, 184, 78]).expect("hard coded slice should parse correctly");
    /// # let sk = SecretKey::from_str("57f0148f94d13095cfda539d0da0d1541304b678d8b36e243980aab4e1b7cead").unwrap();
    ///
    /// let secret = SharedSecret::new(&pk, &sk);
    /// // Here we explicitly display the secret value:
    /// assert_eq!(
    ///     format!("{}", secret.display_secret()),
    ///     "cf05ae7da039ddce6d56dd57d3000c6dd91c6f1695eae47e05389f11e2467043"
    /// );
    /// // Also, we can explicitly display with `Debug`:
    /// assert_eq!(
    ///     format!("{:?}", secret.display_secret()),
    ///     format!("DisplaySecret(\"{}\")", secret.display_secret())
    /// );
    /// # }
    /// ```
    #[inline]
    pub fn display_secret(&self) -> DisplaySecret { DisplaySecret { secret: self.secret_bytes() } }
}
