extern crate secp256k1;

use secp256k1::{PublicKey, Secp256k1, SecretKey};

fn main() {
    let secp = Secp256k1::new();
    let mut rng = rand::thread_rng();
    // First option:
    let (seckey, pubkey) = secp.generate_keypair(&mut rng);

    assert_eq!(pubkey, PublicKey::from_secret_key(&secp, &seckey));

    // Second option:
    let seckey = SecretKey::new(&mut rng);
    let _pubkey = PublicKey::from_secret_key(&secp, &seckey);
}
