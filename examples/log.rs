//! An example showing debug logging.
//!

use log::info;
use secp256k1::{rand, KeyPair, SECP256K1, SecretKey};

fn main() {
    env_logger::init();
    info!("Running the logging example");

    keys();
}

fn keys() {
    let secp = SECP256K1;
    info!("Using global secp context");

    let _ = SecretKey::new(&mut rand::thread_rng());

    let sec_bytes = [59, 148, 11, 85, 134, 130, 61, 253, 2, 174, 59, 70, 27, 180, 51, 107, 94, 203, 174, 253, 102, 39, 170, 146, 46, 252, 4, 143, 236, 12, 136, 28];
    let sk = SecretKey::from_slice(&sec_bytes).expect("failed to parse seckey bytes for SecretKey");

    let ser = bincode::serialize(&sk).expect("failed to serialize sk");
    let _: SecretKey = bincode::deserialize(&ser).expect("failed to deserialize sk");

    // FIXME: KeyPair overflows the stack?
    //
    // let kp = KeyPair::from_secret_key(&secp, &sk);
    // let _ = SecretKey::from_keypair(&kp);
    // let _ = KeyPair::from_seckey_slice(&secp, &sec_bytes).expect("failed to parse seckey bytes for KeyPair");
    // let _ = KeyPair::new(&secp, &mut rand::thread_rng());

    // let ser = bincode::serialize(&kp).expect("failed to serialize sk");
    // let _: SecretKey = bincode::deserialize(&ser).expect("failed to deserialize sk");
}
