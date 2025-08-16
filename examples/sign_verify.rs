//! Signing and Verification Example
//!
//! In this example we directly sign the "output of a hash function"
//! as represented by a 32-byte array. In practice, when signing with
//! the ECDSA API, you should not sign an arbitrary hash like this,
//! whether it is typed as a `[u8; 32]` or a `sha2::Sha256` or whatever.
//!
//! Instead, you should have a dedicated signature hash type, which has
//! constructors ensuring that it represents an (ideally) domain-separated
//! hash of the data you intend to sign. This type should implement
//! `Into<Message>` so it can be passed to `sign_ecdsa` as a message.
//!
//! An example of such a type is `bitcoin::LegacySighash` from rust-bitcoin.
//!

extern crate secp256k1;

use secp256k1::{ecdsa, Error, Message, PublicKey, Secp256k1, SecretKey, Signing, Verification};

fn verify<C: Verification>(
    secp: &Secp256k1<C>,
    msg_digest: [u8; 32],
    sig: [u8; 64],
    pubkey: [u8; 33],
) -> Result<bool, Error> {
    let msg = Message::from_digest(msg_digest);
    let sig = ecdsa::Signature::from_compact(&sig)?;
    let pubkey = PublicKey::from_slice(&pubkey)?;

    Ok(secp.verify_ecdsa(&sig, msg, &pubkey).is_ok())
}

fn sign<C: Signing>(
    secp: &Secp256k1<C>,
    msg_digest: [u8; 32],
    seckey: [u8; 32],
) -> Result<ecdsa::Signature, Error> {
    let msg = Message::from_digest(msg_digest);
    let seckey = SecretKey::from_byte_array(seckey)?;
    Ok(secp.sign_ecdsa(msg, &seckey))
}

fn main() {
    let secp = Secp256k1::new();

    let seckey = [
        59, 148, 11, 85, 134, 130, 61, 253, 2, 174, 59, 70, 27, 180, 51, 107, 94, 203, 174, 253,
        102, 39, 170, 146, 46, 252, 4, 143, 236, 12, 136, 28,
    ];
    let pubkey = [
        2, 29, 21, 35, 7, 198, 183, 43, 14, 208, 65, 139, 14, 112, 205, 128, 231, 245, 41, 91, 141,
        134, 245, 114, 45, 63, 82, 19, 251, 210, 57, 79, 54,
    ];
    let msg_digest = *b"this must be secure hash output.";

    let signature = sign(&secp, msg_digest, seckey).unwrap();

    let serialize_sig = signature.serialize_compact();

    assert!(verify(&secp, msg_digest, serialize_sig, pubkey).unwrap());
}
