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

            /// Returns a reference the underlying bytes.
            #[inline]
            pub fn as_bytes(&self) -> &[$ty; $len] { &self.0 }

            /// Returns a clone of the underlying bytes.
            #[inline]
            pub fn to_bytes(self) -> [$ty; $len] { self.0.clone() }

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
                if self.is_empty() {
                    core::ptr::null()
                } else {
                    self.as_ptr()
                }
            }

            fn as_mut_c_ptr(&mut self) -> *mut Self::Target {
                if self.is_empty() {
                    core::ptr::null::<Self::Target>() as *mut _
                } else {
                    self.as_mut_ptr()
                }
            }
        }
    }
}

#[macro_export]
macro_rules! impl_raw_debug {
    ($thing:ident) => {
        impl core::fmt::Debug for $thing {
            fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                for i in self.to_bytes().iter() {
                    write!(f, "{:02x}", i)?;
                }
                Ok(())
            }
        }
     }
}
