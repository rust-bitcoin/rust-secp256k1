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
            /// Creates a new "uninitialized" FFI type which is zeroed out.
            ///
            /// # Safety
            ///
            /// If you pass this to any FFI functions, except as an out-pointer,
            /// the result is likely to be an assertation failure and process
            /// termination.
            pub unsafe fn new() -> Self {
                Self::from_array_unchecked([0; $len])
            }

            /// Create a new type usable for the FFI interface from raw bytes.
            ///
            /// # Safety
            ///
            /// Does not check the validity of the underlying representation. If it is
            /// invalid the result may be assertation failures (and process aborts) from
            /// the underlying library. You should not use this method except with data
            /// that you obtained from the FFI interface of the same version of this
            /// library.
            pub unsafe fn from_array_unchecked(data: [c_uchar; $len]) -> Self {
                $thing(data)
            }

            /// Returns the underlying FFI opaque representation.
            ///
            /// You should not use this unless you really know what you are doing. It is
            /// essentially only useful for extending the FFI interface itself.
            pub fn underlying_bytes(self) -> [c_uchar; $len] {
                self.0
            }

            // FIXME: Should we be providing to/from_be/le_bytes
            // FIXME: Should we be providing as/to_bytes

            /// Converts the object to a raw pointer for FFI interfacing.
            #[inline]
            pub fn as_ptr(&self) -> *const $ty {
                let &$thing(ref dat) = self;
                dat.as_ptr()
            }

            /// Converts the object to a mutable raw pointer for FFI interfacing.
            #[inline]
            pub fn as_mut_ptr(&mut self) -> *mut $ty {
                let &mut $thing(ref mut dat) = self;
                dat.as_mut_ptr()
            }

            /// Returns the length of the object as an array.
            #[inline]
            pub fn len(&self) -> usize { $len }

            /// Returns whether the object as an array is empty.
            #[inline]
            pub fn is_empty(&self) -> bool { false }
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
