// Bitcoin secp256k1 bindings
// Written in 2014 by
//   Dawid Ciężarkiewicz
//   Andrew Poelstra
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

macro_rules! impl_pretty_debug {
    ($thing:ident) => {
        impl ::core::fmt::Debug for $thing {
            fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                write!(f, "{}(", stringify!($thing))?;
                for i in &self[..] {
                    write!(f, "{:02x}", i)?;
                }
                f.write_str(")")
            }
        }
     }
}

macro_rules! impl_safe_debug {
    ($thing:ident) => {
        #[cfg(feature = "bitcoin_hashes")]
        impl ::core::fmt::Debug for $thing {
            fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                use ::bitcoin_hashes::{Hash, sha256};
                write!(f, "{}(#", stringify!($thing))?;
                let hash = sha256::Hash::hash(&self.0[..]);
                for i in &hash[..4] {
                    write!(f, "{:02x}", i)?;
                }
                f.write_str("...")?;
                for i in &hash[28..] {
                    write!(f, "{:02x}", i)?;
                }
                f.write_str(")")
            }
        }

        #[cfg(all(not(feature = "bitcoin_hashes"), feature = "std"))]
        impl ::core::fmt::Debug for $thing {
            fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                use ::core::hash::Hasher;
                let mut hasher = ::std::collections::hash_map::DefaultHasher::new();

                hasher.write(&self.0[..]);
                let hash = hasher.finish();

                write!(f, "{}(#{:016x})", stringify!($thing), hash)
            }
        }

        impl $thing {
            /// Formats the explicit byte value of the secret key kept inside the type as a
            /// little-endian hexadecimal string using the provided formatter.
            ///
            /// This is the only method that outputs the actual secret key value, and, thus,
            /// should be used with extreme precaution.
            #[deprecated(
                note = "Caution: you are explicitly outputting secret key value! This can be done
                only in debug environment and that's why always considered as ``deprecated''"
            )]
            pub fn fmt_secret_key(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                for i in &self.0[..] {
                    write!(f, "{:02x}", i)?;
                }
                Ok(())
            }

            /// Formats the explicit byte value of the secret key kept inside the type as a
            /// little-endian hexadecimal string.
            ///
            /// This is the only method that outputs the actual secret key value, and, thus,
            /// should be used with extreme precaution.
            #[deprecated(
                note = "Caution: you are explicitly outputting secret key value! This can be done
                only in debug environment and that's why always considered as ``deprecated''"
            )]
            #[cfg(feature = "std")]
            pub fn format_secret_key(&self) -> String {
                let mut s = Vec::with_capacity(self.0.len() * 2);
                for i in &self.0[..] {
                    s.push(format!("{:02x}", i));
                }
                s.join("")
            }
        }
     }
}

macro_rules! impl_from_array_len {
    ($thing:ident, $capacity:tt, ($($N:tt)+)) => {
        $(
            impl From<[u8; $N]> for $thing {
                fn from(arr: [u8; $N]) -> Self {
                    let mut data = [0u8; $capacity];
                    data[..$N].copy_from_slice(&arr);
                    $thing {
                        data,
                        len: $N,
                    }
                }
            }
        )+
    }
}
