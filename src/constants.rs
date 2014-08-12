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

//! Constants

/// The size (in bytes) of a nonce
pub static NONCE_SIZE: uint = 32;

/// The size (in bytes) of a secret key
pub static SECRET_KEY_SIZE: uint = 32;

/// The size (in bytes) of an uncompressed public key
pub static UNCOMPRESSED_PUBLIC_KEY_SIZE: uint = 65;

/// The size (in bytes) of a compressed public key
pub static COMPRESSED_PUBLIC_KEY_SIZE: uint = 33;

/// The maximum size of a signature
pub static MAX_SIGNATURE_SIZE: uint = 72;

/// The maximum size of a compact signature
pub static MAX_COMPACT_SIGNATURE_SIZE: uint = 64;

