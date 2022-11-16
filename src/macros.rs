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
        impl core::fmt::Debug for $thing {
            fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                write!(f, "{}(", stringify!($thing))?;
                for i in &self[..] {
                    write!(f, "{:02x}", i)?;
                }
                f.write_str(")")
            }
        }
     }
}

/// Formats error. If `std` feature is OFF appends error source (delimited by `: `). We do this
/// because `e.source()` is only available in std builds, without this macro the error source is
/// lost for no-std builds.
macro_rules! write_err {
    ($writer:expr, $string:literal $(, $args:expr),*; $source:expr) => {
        {
            #[cfg(feature = "std")]
            {
                let _ = &$source;   // Prevents clippy warnings.
                write!($writer, $string $(, $args)*)
            }
            #[cfg(not(feature = "std"))]
            {
                write!($writer, concat!($string, ": {}") $(, $args)*, $source)
            }
        }
    }
}

/// Implements fast unstable versions of Ord, PartialOrd, Eq, PartialEq, and Hash.
macro_rules! impl_fast_comparisons {
    ($ty:ident) => {
        impl $ty {
            /// Equivalent to `Ord` but faster and not stable across library versions.
            ///
            /// The `Ord` implementation for `Self` is stable but slow because we first serialize
            /// `self` and `other` before comparing them. The `Ord` implementation for FFI types
            /// compares the inner bytes directly. The inner bytes are passed across the FFI boundry
            /// and as such there are no guarantees to the layout of the bytes. The layout may
            /// change unexpectedly between versions of the library, even minor versions.
            pub fn cmp_fast_unstable(&self, other: &Self) -> core::cmp::Ordering {
                self.0.cmp(&other.0)
            }

            /// Equivalent to `Eq` but faster and not stable across library versions.
            ///
            /// The `Eq` implementation for `Self` is stable but slow because we first serialize
            /// `self` and `other` before comparing them. The `Eq` implementation for FFI types
            /// compares the inner bytes directly. The inner bytes are passed across the FFI boundry
            /// and as such there are no guarantees to the layout of the bytes. The layout may
            /// change unexpectedly between versions of the library, even minor versions.
            pub fn eq_fast_unstable(&self, other: &Self) -> bool {
                self.0.eq(&other.0)
            }
        }
    }
}
