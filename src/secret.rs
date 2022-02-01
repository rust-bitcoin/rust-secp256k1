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

use ::core::fmt;
use ::{SecretKey, KeyPair, to_hex};
use constants::SECRET_KEY_SIZE;

macro_rules! impl_display_secret {
    // Default hasher exists only in standard library and not alloc
    ($thing:ident) => {
        #[cfg(feature = "std")]
        impl ::core::fmt::Debug for $thing {
            fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                use ::core::hash::Hasher;
                const DEBUG_HASH_TAG: &[u8] = &[
                    0x66, 0xa6, 0x77, 0x1b, 0x9b, 0x6d, 0xae, 0xa1, 0xb2, 0xee, 0x4e, 0x07, 0x49,
                    0x4a, 0xac, 0x87, 0xa9, 0xb8, 0x5b, 0x4b, 0x35, 0x02, 0xaa, 0x6d, 0x0f, 0x79,
                    0xcb, 0x63, 0xe6, 0xf8, 0x66, 0x22
                ]; // =SHA256(b"rust-secp256k1DEBUG");

                let mut hasher = ::std::collections::hash_map::DefaultHasher::new();

                hasher.write(DEBUG_HASH_TAG);
                hasher.write(DEBUG_HASH_TAG);
                hasher.write(&self.serialize_secret());
                let hash = hasher.finish();

                f.debug_tuple(stringify!($thing))
                    .field(&format_args!("#{:016x}", hash))
                    .finish()
            }
        }

        #[cfg(all(not(feature = "std"), feature = "bitcoin_hashes"))]
        impl ::core::fmt::Debug for $thing {
            fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                use hashes::{sha256, Hash, HashEngine};

                let tag = "rust-secp256k1DEBUG";

                let mut engine = sha256::Hash::engine();
                let tag_hash = sha256::Hash::hash(tag.as_bytes());
                engine.input(&tag_hash[..]);
                engine.input(&tag_hash[..]);
                engine.input(&self.serialize_secret());
                let hash = sha256::Hash::from_engine(engine);

                f.debug_tuple(stringify!($thing))
                    .field(&format_args!("#{:016x}", hash))
                    .finish()
            }
        }

        #[cfg(all(not(feature = "std"), not(feature = "bitcoin_hashes")))]
        impl ::core::fmt::Debug for $thing {
            fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                write!(f, "<secret requires std feature to display>")
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
        let mut slice = [0u8; 64];
        let hex = to_hex(&self.secret, &mut slice).expect("fixed-size hex serializer failed");
        f.debug_tuple("DisplaySecret")
            .field(&hex)
            .finish()
    }
}

impl fmt::Display for DisplaySecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for i in &self.secret {
            write!(f, "{:02x}", i)?;
        }
        Ok(())
    }
}

impl SecretKey {
    /// Formats the explicit byte value of the secret key kept inside the type as a
    /// little-endian hexadecimal string using the provided formatter.
    ///
    /// This is the only method that outputs the actual secret key value, and, thus,
    /// should be used with extreme precaution.
    ///
    /// # Example
    ///
    /// ```
    /// # #[cfg(all(feature = "std", not(feature = "bitcoin_hashes")))] {
    /// use secp256k1::ONE_KEY;
    /// let key = ONE_KEY;
    /// // Normal display hides value
    /// assert_eq!(
    ///     "SecretKey(#2518682f7819fb2d)",
    ///     format!("{:?}", key)
    /// );
    /// // Here we explicitly display the secret value:
    /// assert_eq!(
    ///     "0000000000000000000000000000000000000000000000000000000000000001",
    ///     format!("{}", key.display_secret())
    /// );
    /// assert_eq!(
    ///     "DisplaySecret(\"0000000000000000000000000000000000000000000000000000000000000001\")",
    ///     format!("{:?}", key.display_secret())
    /// );
    /// # }
    /// ```
    #[inline]
    pub fn display_secret(&self) -> DisplaySecret {
        DisplaySecret { secret: self.serialize_secret() }
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
    /// # #[cfg(all(feature = "std", not(feature = "bitcoin_hashes")))] {
    /// use secp256k1::ONE_KEY;
    /// use secp256k1::KeyPair;
    /// use secp256k1::Secp256k1;
    ///
    /// let secp = Secp256k1::new();
    /// let key = ONE_KEY;
    /// let key = KeyPair::from_secret_key(&secp, key);
    ///
    /// // Normal display hides value
    /// assert_eq!(
    ///     "KeyPair(#2518682f7819fb2d)",
    ///     format!("{:?}", key)
    /// );
    /// // Here we explicitly display the secret value:
    /// assert_eq!(
    ///     "0000000000000000000000000000000000000000000000000000000000000001",
    ///     format!("{}", key.display_secret())
    /// );
    /// assert_eq!(
    ///     "DisplaySecret(\"0000000000000000000000000000000000000000000000000000000000000001\")",
    ///     format!("{:?}", key.display_secret())
    /// );
    /// # }
    /// ```
    #[inline]
    pub fn display_secret(&self) -> DisplaySecret {
        DisplaySecret { secret: self.serialize_secret() }
    }
}
