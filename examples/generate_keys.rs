extern crate secp256k1;

use secp256k1::{PublicKey, SecretKey};

fn main() {
    let mut rng = rand::rng();
    // First option:
    let (seckey, pubkey) = secp256k1::generate_keypair(&mut rng);

    assert_eq!(pubkey, PublicKey::from_secret_key(&seckey));

    // Second option:
    let seckey = SecretKey::new(&mut rng);
    let _pubkey = PublicKey::from_secret_key(&seckey);
}
