// Bitcoin secp256k1 bindings
// Written in 2021 by
//   Maxim Orlovsky <orlovsky@pandoracore.com>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! Helpers for displaying secret values

use core::fmt;
use crate::{to_hex, constants::SECRET_KEY_SIZE, key::{SecretKey, KeyPair}, ecdh::SharedSecret};
macro_rules! impl_display_secret {
    // Default hasher exists only in standard library and not alloc
    ($thing:ident) => {
        #[cfg(feature = "std")]
        #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
        impl core::fmt::Debug for $thing {
            fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                use core::hash::Hasher;
                const DEBUG_HASH_TAG: &[u8] = &[
                    0x66, 0xa6, 0x77, 0x1b, 0x9b, 0x6d, 0xae, 0xa1, 0xb2, 0xee, 0x4e, 0x07, 0x49,
                    0x4a, 0xac, 0x87, 0xa9, 0xb8, 0x5b, 0x4b, 0x35, 0x02, 0xaa, 0x6d, 0x0f, 0x79,
                    0xcb, 0x63, 0xe6, 0xf8, 0x66, 0x22
                ]; // =SHA256(b"rust-secp256k1DEBUG");

                let mut hasher = std::collections::hash_map::DefaultHasher::new();

                hasher.write(DEBUG_HASH_TAG);
                hasher.write(DEBUG_HASH_TAG);
                hasher.write(&self.secret_bytes());
                let hash = hasher.finish();

                f.debug_tuple(stringify!($thing))
                    .field(&format_args!("#{:016x}", hash))
                    .finish()
            }
        }

        #[cfg(all(not(feature = "std"), feature = "bitcoin_hashes"))]
        impl ::core::fmt::Debug for $thing {
            fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                use crate::hashes::{sha256, Hash, HashEngine};

                let tag = "rust-secp256k1DEBUG";

                let mut engine = sha256::Hash::engine();
                let tag_hash = sha256::Hash::hash(tag.as_bytes());
                engine.input(&tag_hash[..]);
                engine.input(&tag_hash[..]);
                engine.input(&self.secret_bytes());
                let hash = sha256::Hash::from_engine(engine);

                f.debug_tuple(stringify!($thing))
                    .field(&format_args!("#{:016x}", hash))
                    .finish()
            }
        }

        #[cfg(all(not(feature = "std"), not(feature = "bitcoin_hashes")))]
        impl ::core::fmt::Debug for $thing {
            fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                write!(f, "<secret requires std or bitcoin_hashes feature to display>")
            }
        }
     }
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
    secret: [u8; SECRET_KEY_SIZE]
}

impl fmt::Debug for DisplaySecret {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut slice = [0u8; SECRET_KEY_SIZE * 2];
        let hex = to_hex(&self.secret, &mut slice).expect("fixed-size hex serializer failed");
        f.debug_tuple("DisplaySecret")
            .field(&hex)
            .finish()
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
    /// let key = secp256k1::ONE_KEY;
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
    pub fn display_secret(&self) -> DisplaySecret {
        DisplaySecret { secret: self.secret_bytes() }
    }
}

impl KeyPair {
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
    /// use secp256k1::ONE_KEY;
    /// use secp256k1::KeyPair;
    /// use secp256k1::Secp256k1;
    ///
    /// let secp = Secp256k1::new();
    /// let key = ONE_KEY;
    /// let key = KeyPair::from_secret_key(&secp, &key);
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
    pub fn display_secret(&self) -> DisplaySecret {
        DisplaySecret { secret: self.secret_bytes() }
    }
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
    /// # #[cfg(not(fuzzing))]
    /// # #[cfg(feature = "std")] {
    /// # use std::str::FromStr;
    /// # use secp256k1::{SecretKey, PublicKey};
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
    pub fn display_secret(&self) -> DisplaySecret {
        DisplaySecret { secret: self.secret_bytes() }
    }
}
