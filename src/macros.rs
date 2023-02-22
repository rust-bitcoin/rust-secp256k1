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

/// Implement methods and traits for types that contain an inner array.
#[macro_export]
macro_rules! impl_array_newtype {
    ($thing:ident, $ty:ty, $len:expr) => {
        // We cannot derive these traits because Rust 1.41.1 requires `std::array::LengthAtMost32`.

        impl PartialEq for $thing {
            #[inline]
            fn eq(&self, other: &$thing) -> bool { &self[..] == &other[..] }
        }

        impl Eq for $thing {}

        impl core::hash::Hash for $thing {
            fn hash<H: core::hash::Hasher>(&self, state: &mut H) { (&self[..]).hash(state) }
        }

        impl PartialOrd for $thing {
            #[inline]
            fn partial_cmp(&self, other: &$thing) -> Option<core::cmp::Ordering> {
                self[..].partial_cmp(&other[..])
            }
        }

        impl Ord for $thing {
            #[inline]
            fn cmp(&self, other: &$thing) -> core::cmp::Ordering { self[..].cmp(&other[..]) }
        }

        impl AsRef<[$ty; $len]> for $thing {
            #[inline]
            /// Gets a reference to the underlying array
            fn as_ref(&self) -> &[$ty; $len] {
                let &$thing(ref dat) = self;
                dat
            }
        }

        impl<I> core::ops::Index<I> for $thing
        where
            [$ty]: core::ops::Index<I>,
        {
            type Output = <[$ty] as core::ops::Index<I>>::Output;

            #[inline]
            fn index(&self, index: I) -> &Self::Output { &self.0[index] }
        }

        impl $crate::ffi::CPtr for $thing {
            type Target = $ty;

            fn as_c_ptr(&self) -> *const Self::Target {
                let &$thing(ref dat) = self;
                dat.as_ptr()
            }

            fn as_mut_c_ptr(&mut self) -> *mut Self::Target {
                let &mut $thing(ref mut dat) = self;
                dat.as_mut_ptr()
            }
        }
    };
}

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
    };
}

macro_rules! impl_non_secure_erase {
    ($thing:ident, $target:tt, $value:expr) => {
        impl $thing {
            /// Attempts to erase the contents of the underlying array.
            ///
            /// Note, however, that the compiler is allowed to freely copy or move the
            /// contents of this array to other places in memory. Preventing this behavior
            /// is very subtle. For more discussion on this, please see the documentation
            /// of the [`zeroize`](https://docs.rs/zeroize) crate.
            #[inline]
            pub fn non_secure_erase(&mut self) {
                secp256k1_sys::non_secure_erase_impl(&mut self.$target, $value);
            }
        }
    };
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

/// Implements fast unstable comparison methods for `$ty`.
macro_rules! impl_fast_comparisons {
    ($ty:ident) => {
        impl $ty {
            /// Like `cmp::Cmp` but faster and with no guarantees across library versions.
            ///
            /// The `Cmp` implementation for FFI types is stable but slow because it first
            /// serializes `self` and `other` before comparing them. This function provides a faster
            /// comparison if you know that your types come from the same library version.
            pub fn cmp_fast_unstable(&self, other: &Self) -> core::cmp::Ordering {
                self.0.cmp_fast_unstable(&other.0)
            }

            /// Like `cmp::Eq` but faster and with no guarantees across library versions.
            ///
            /// The `Eq` implementation for FFI types is stable but slow because it first serializes
            /// `self` and `other` before comparing them. This function provides a faster equality
            /// check if you know that your types come from the same library version.
            pub fn eq_fast_unstable(&self, other: &Self) -> bool {
                self.0.eq_fast_unstable(&other.0)
            }
        }
    };
}
