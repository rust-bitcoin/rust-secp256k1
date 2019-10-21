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
                for i in self[..].iter().cloned() {
                    write!(f, "{:02x}", i)?;
                }
                write!(f, ")")
            }
        }
     }
}

#[cfg(feature="serde")]
/// Implements `Serialize` and `Deserialize` for a type `$t` which represents
/// a newtype over a byte-slice over length `$len`. Type `$t` must implement
/// the `FromStr` and `Display` trait.
macro_rules! serde_impl(
    ($t:ident, $len:expr) => (
        impl ::serde::Serialize for $t {
            fn serialize<S: ::serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                if s.is_human_readable() {
                    s.collect_str(self)
                } else {
                    s.serialize_bytes(&self[..])
                }
            }
        }

        impl<'de> ::serde::Deserialize<'de> for $t {
            fn deserialize<D: ::serde::Deserializer<'de>>(d: D) -> Result<$t, D::Error> {
                use ::serde::de::Error;
                use core::str::FromStr;

                if d.is_human_readable() {
                    let sl: &str = ::serde::Deserialize::deserialize(d)?;
                    SecretKey::from_str(sl).map_err(D::Error::custom)
                } else {
                    let sl: &[u8] = ::serde::Deserialize::deserialize(d)?;
                    if sl.len() != $len {
                        Err(D::Error::invalid_length(sl.len(), &stringify!($len)))
                    } else {
                        let mut ret = [0; $len];
                        ret.copy_from_slice(sl);
                        Ok($t(ret))
                    }
                }
            }
        }
    )
);

#[cfg(not(feature="serde"))]
macro_rules! serde_impl(
    ($t:ident, $len:expr) => ()
);
