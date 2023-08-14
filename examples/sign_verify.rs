extern crate hashes;
extern crate secp256k1;

use hashes::{sha256, Hash};
use secp256k1::{ecdsa, Error, Message, PublicKey, Secp256k1, SecretKey, Signing, Verification};

fn verify<C: Verification>(
    secp: &Secp256k1<C>,
    msg: &[u8],
    sig: [u8; 64],
    pubkey: [u8; 33],
) -> Result<bool, Error> {
    let msg = sha256::Hash::hash(msg);
    let msg = Message::from_digest_slice(msg.as_ref())?;
    let sig = ecdsa::Signature::from_compact(&sig)?;
    let pubkey = PublicKey::from_slice(&pubkey)?;

    Ok(secp.verify_ecdsa(&msg, &sig, &pubkey).is_ok())
}

fn sign<C: Signing>(
    secp: &Secp256k1<C>,
    msg: &[u8],
    seckey: [u8; 32],
) -> Result<ecdsa::Signature, Error> {
    let msg = sha256::Hash::hash(msg);
    let msg = Message::from_digest_slice(msg.as_ref())?;
    let seckey = SecretKey::from_slice(&seckey)?;
    Ok(secp.sign_ecdsa(&msg, &seckey))
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
    let msg = b"This is some message";

    let signature = sign(&secp, msg, seckey).unwrap();

    let serialize_sig = signature.serialize_compact();

    assert!(verify(&secp, msg, serialize_sig, pubkey).unwrap());
}
