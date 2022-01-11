#![cfg(feature = "rand")]

extern crate bitcoin_hashes;
extern crate secp256k1;

use bitcoin_hashes::{sha256, Hash};
use secp256k1::rand::thread_rng;
use secp256k1::rand::rngs::OsRng;
use secp256k1::{Secp256k1, Error, Message, PublicKey, SecretKey, ecdsa, Signing, Verification};

fn keys<C: Signing>(secp: &Secp256k1<C>) -> (SecretKey, PublicKey) {
    let mut rng = thread_rng();
    secp.generate_keypair(&mut rng)
}

fn sign<C: Signing>(secp: &Secp256k1<C>, msg: &[u8], sk: &SecretKey) -> Result<ecdsa::Signature, Error> {
    let msg = sha256::Hash::hash(msg);
    let msg = Message::from_slice(&msg)?;
    Ok(secp.sign_ecdsa(&msg, &sk))
}

fn verify<C: Verification>(secp: &Secp256k1<C>, msg: &[u8], sig: &[u8; 64], pk: PublicKey) -> Result<bool, Error> {
    let msg = sha256::Hash::hash(msg);
    let msg = Message::from_slice(&msg)?;
    let sig = ecdsa::Signature::from_compact(sig)?;

    Ok(secp.verify_ecdsa(&msg, &sig, &pk).is_ok())
}

#[test]
fn generate_keys() {
    let secp = Secp256k1::new();
    let mut rng = OsRng::new().unwrap();
    let (sk, pk) = secp.generate_keypair(&mut rng);

    assert_eq!(pk, PublicKey::from_secret_key(&secp, &sk))
}

#[test]
#[cfg(feature = "global-context")]
fn generate_keys_with_global() {
    use secp256k1::global::SECP256K1;

    let secp = SECP256K1;
    let mut rng = OsRng::new().unwrap();

    let sk = SecretKey::new(&mut rng);
    let _pk = PublicKey::from_secret_key(&secp, &sk);
}

#[test]
fn ecdsa_sign_and_verify() {
    let secp = Secp256k1::new();
    let (sk, pk) = keys(&secp);

    let msg = b"super top secret message";
    let sig = sign(&secp, msg, &sk).expect("signing failed");
    let compact = sig.serialize_compact();

    assert!(verify(&secp, msg, &compact, pk).is_ok());
}

#[test]
#[cfg(feature = "recovery")]
fn ecdsa_sign_and_recover() {
    let secp = Secp256k1::new();
    let (sk, pk) = keys(&secp);
    let msg = sha256::Hash::hash(b"super top secret message");
    let msg = Message::from_slice(&msg).expect("failed ");

    let sig = secp.sign_ecdsa_recoverable(&msg, &sk);
    let recovered_pk = secp.recover_ecdsa(&msg, &sig).expect("recovery failed");
    assert_eq!(recovered_pk, pk)
}

#[test]
#[cfg(feature = "rand-std")]
fn schnorr_sign_and_verify() {
    use secp256k1::{KeyPair, XOnlyPublicKey};

    let secp = Secp256k1::new();
    let (sk, _pk) = keys(&secp);
    let kp = KeyPair::from_secret_key(&secp, sk);

    let msg = sha256::Hash::hash(b"super top secret message");
    let msg = Message::from_slice(&msg).expect("failed ");

    let sig = secp.sign_schnorr(&msg, &kp);
    let xonly = XOnlyPublicKey::from_keypair(&kp);
    assert!(secp.verify_schnorr(&sig, &msg, &xonly).is_ok())
}
