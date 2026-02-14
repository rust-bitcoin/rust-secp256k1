// SPDX-License-Identifier: CC0-1.0

#![allow(dead_code)]
#![allow(unused_imports)]

use secp256k1::{
    ecdh, ecdsa, ellswift, schnorr, Keypair, Message, Parity, PublicKey, Scalar, SecretKey,
    XOnlyPublicKey,
};

/// A struct that includes all public non-error enums.
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
struct Enums {
    a: Parity,
    b: ellswift::Party,
    #[cfg(feature = "recovery")]
    c: ecdsa::RecoveryId,
}

/// A struct that includes all "public" (i.e. not secret key material) structures.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Copy, Clone)]
struct PublicStructs {
    a: Message,
    b: PublicKey,
    c: XOnlyPublicKey,
    d: ecdsa::Signature,
    e: ecdsa::SerializedSignature,
    #[cfg(feature = "recovery")]
    f: ecdsa::RecoverableSignature,
    g: ellswift::ElligatorSwift,
    h: Scalar,
    i: schnorr::Signature,
}

/// A struct that includes all "secret" structures.
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
struct SecretStructs {
    a: SecretKey,
    b: ecdh::SharedSecret,
    c: Keypair,
    // FIXME should be renamed
    d: ellswift::ElligatorSwiftSharedSecret,
}

macro_rules! bytes_rtt_test {
    ($name: ident, $ty:ty) => {
        fn $name(obj: &$ty) {
            let x = obj.to_byte_array();
            let y = <$ty>::from_byte_array(x);
            assert_eq!(*obj, y);
        }
    };
}

// Message is special because its to/from methods havve the name "digest" in them
// PublicKey is special because it has two serialization forms with different names (but maybe I should rename them?)
// FIXME XOnlyPublicKey should pass this
// ecdsa::Signature and SerializedSignature and RecoverableSignature are variable-length
// Scalar has to_be_bytes and to_le_bytes (and corresponding froms)
bytes_rtt_test!(rtt_i, schnorr::Signature);
bytes_rtt_test!(rtt_g, ellswift::ElligatorSwift);

macro_rules! secret_bytes_rtt_test {
    ($name: ident, $ty:ty) => {
        fn $name(obj: &$ty) {
            let x = obj.to_secret_bytes();
            let y = obj.as_secret_bytes();
            let z = obj.as_ref();
            let _ = y == z;
            let _ = <$ty>::from_secret_bytes(x);
            obj.clone().non_secure_erase();
        }
    };
}
secret_bytes_rtt_test!(secret_rtt_a, SecretKey);
secret_bytes_rtt_test!(secret_rtt_d, ellswift::ElligatorSwiftSharedSecret);
// FIXME ecdh::SharedSecret should pass this
// FIXME unsure about Keypair -- it currently only roundtrips through secret keys
