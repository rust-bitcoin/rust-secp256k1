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
