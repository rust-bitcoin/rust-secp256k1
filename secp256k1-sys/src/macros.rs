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
        impl $thing {
            /// Like `cmp::Ord` but faster and with no guarantees across library versions.
            ///
            /// The inner byte array of `Self` is passed across the FFI boundry, as such there are
            /// no guarantees on its layout and it is subject to change across library versions,
            /// even minor versions. For this reason comparison function implementations (e.g.
            /// `Ord`, `PartialEq`) take measures to ensure the data will remain constant (e.g., by
            /// serializing it to a guaranteed format). This means they may be slow, this function
            /// provides a faster comparison if you know that your types come from the same library
            /// version.
            pub fn cmp_fast_unstable(&self, other: &Self) -> core::cmp::Ordering {
                self[..].cmp(&other[..])
            }

            /// Like `cmp::Eq` but faster and with no guarantees across library versions.
            ///
            /// The inner byte array of `Self` is passed across the FFI boundry, as such there are
            /// no guarantees on its layout and it is subject to change across library versions,
            /// even minor versions. For this reason comparison function implementations (e.g.
            /// `Ord`, `PartialEq`) take measures to ensure the data will remain constant (e.g., by
            /// serializing it to a guaranteed format). This means they may be slow, this function
            /// provides a faster equality check if you know that your types come from the same
            /// library version.
            pub fn eq_fast_unstable(&self, other: &Self) -> bool {
                self[..].eq(&other[..])
            }
        }

        // We cannot derive these traits because Rust 1.41.1 requires `std::array::LengthAtMost32`.

       #[cfg(fuzzing)]
        impl PartialEq for $thing {
            #[inline]
            fn eq(&self, other: &$thing) -> bool {
                &self[..] == &other[..]
            }
        }

        #[cfg(fuzzing)]
        impl Eq for $thing {}

        #[cfg(fuzzing)]
        impl core::hash::Hash for $thing {
            fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
                (&self[..]).hash(state)
            }
        }

        #[cfg(fuzzing)]
        impl PartialOrd for $thing {
            #[inline]
            fn partial_cmp(&self, other: &$thing) -> Option<core::cmp::Ordering> {
                self[..].partial_cmp(&other[..])
            }
        }

        #[cfg(fuzzing)]
        impl Ord for $thing {
            #[inline]
            fn cmp(&self, other: &$thing) -> core::cmp::Ordering {
                self[..].cmp(&other[..])
            }
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

        impl $crate::CPtr for $thing {
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
    }
}

#[macro_export]
macro_rules! impl_raw_debug {
    ($thing:ident) => {
        impl core::fmt::Debug for $thing {
            fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                for i in self[..].iter().cloned() {
                    write!(f, "{:02x}", i)?;
                }
                Ok(())
            }
        }
     }
}
