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

#![macro_escape]

// This is a macro that routinely comes in handy
macro_rules! impl_array_newtype(
    ($thing:ident, $ty:ty, $len:expr) => {
        impl $thing {
            #[inline]
            /// Provides an immutable view into the object
            pub fn as_slice<'a>(&'a self) -> &'a [$ty] {
                let &$thing(ref dat) = self;
                dat.as_slice()
            }

            #[inline]
            /// Provides an immutable view into the object from index `s` inclusive to `e` exclusive
            pub fn slice<'a>(&'a self, s: uint, e: uint) -> &'a [$ty] {
                let &$thing(ref dat) = self;
                dat.slice(s, e)
            }

            #[inline]
            /// Provides an immutable view into the object, up to index `n` exclusive
            pub fn slice_to<'a>(&'a self, n: uint) -> &'a [$ty] {
                let &$thing(ref dat) = self;
                dat.slice_to(n)
            }

            #[inline]
            /// Provides an immutable view into the object, starting from index `n`
            pub fn slice_from<'a>(&'a self, n: uint) -> &'a [$ty] {
                let &$thing(ref dat) = self;
                dat.slice_from(n)
            }

            #[inline]
            /// Converts the object to a raw pointer for FFI interfacing
            pub fn as_ptr(&self) -> *const $ty {
                let &$thing(ref dat) = self;
                dat.as_ptr()
            }

            #[inline]
            /// Converts the object to a mutable raw pointer for FFI interfacing
            pub fn as_mut_ptr(&mut self) -> *mut $ty {
                let &$thing(ref mut dat) = self;
                dat.as_mut_ptr()
            }

            #[inline]
            /// Returns the length of the object as an array
            pub fn len(&self) -> uint { $len }
        }

        impl PartialEq for $thing {
            #[inline]
            fn eq(&self, other: &$thing) -> bool {
                self.as_slice() == other.as_slice()
            }
        }

        impl Eq for $thing {}

        impl Clone for $thing {
            #[inline]
            fn clone(&self) -> $thing {
                unsafe {
                    use std::intrinsics::copy_nonoverlapping_memory;
                    use std::mem;
                    let mut ret: $thing = mem::uninitialized();
                    copy_nonoverlapping_memory(ret.as_mut_ptr(),
                                               self.as_ptr(),
                                               mem::size_of::<$thing>());
                    ret
                }
            }
        }

        impl<D: ::serialize::Decoder<E>, E> ::serialize::Decodable<D, E> for $thing {
            fn decode(d: &mut D) -> ::std::prelude::Result<$thing, E> {
                use serialize::Decodable;

                ::assert_type_is_copy::<$ty>();

                d.read_seq(|d, len| {
                    if len != $len {
                        Err(d.error("Invalid length"))
                    } else {
                        unsafe {
                            use std::mem;
                            let mut ret: [$ty, ..$len] = mem::uninitialized();
                            for i in range(0, len) {
                                ret[i] = try!(d.read_seq_elt(i, |d| Decodable::decode(d)));
                            }
                            Ok($thing(ret))
                        }
                    }
                })
            }
        }

        impl<E: ::serialize::Encoder<S>, S> ::serialize::Encodable<E, S> for $thing {
            fn encode(&self, e: &mut E) -> ::std::prelude::Result<(), S> {
                self.as_slice().encode(e)
             }
        }
    }
)


// for testing
macro_rules! hex_slice(
  ($s:expr) => (
    $s.from_hex().unwrap().as_slice()
  )
)

