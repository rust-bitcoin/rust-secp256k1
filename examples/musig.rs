extern crate secp256k1;

use secp256k1::{Keypair, Message, PublicKey, Scalar, Secp256k1, SecretKey };
use secp256k1::musig::{MusigKeyAggCache, MusigPubNonce, MusigSessionId, MusigPartialSignature, new_musig_nonce_pair, MusigAggNonce, MusigSession};

fn main() {

    let secp = Secp256k1::new();
    let mut rng = rand::thread_rng();

    let (seckey1, pubkey1) = secp.generate_keypair(&mut rng);

    let seckey2 = SecretKey::new(&mut rng);
    let pubkey2 = PublicKey::from_secret_key(&secp, &seckey2);

    let pubkeys = [pubkey1, pubkey2];
    let pubkeys_ref: Vec<&PublicKey> = pubkeys.iter().collect();
    let pubkeys_ref = pubkeys_ref.as_slice();

    let mut musig_key_agg_cache = MusigKeyAggCache::new(&secp, pubkeys_ref);

    let plain_tweak: [u8; 32] = *b"this could be a BIP32 tweak....\0";
    let xonly_tweak: [u8; 32] = *b"this could be a Taproot tweak..\0";

    let plain_tweak = Scalar::from_be_bytes(plain_tweak).unwrap();
    musig_key_agg_cache.pubkey_ec_tweak_add(&secp, &plain_tweak).unwrap();

    let xonly_tweak = Scalar::from_be_bytes(xonly_tweak).unwrap();
    let tweaked_agg_pk = musig_key_agg_cache.pubkey_xonly_tweak_add(&secp, &xonly_tweak).unwrap();

    let agg_pk = musig_key_agg_cache.agg_pk();

    assert_eq!(agg_pk, tweaked_agg_pk.x_only_public_key().0);

    let msg_bytes: [u8; 32] = *b"this_could_be_the_hash_of_a_msg!";
    let msg = Message::from_digest_slice(&msg_bytes).unwrap();

    let musig_session_id1 = MusigSessionId::new(&mut rng);

    let nonce_pair1 = 
        new_musig_nonce_pair(&secp, musig_session_id1, Some(&musig_key_agg_cache), Some(seckey1), pubkey1, Some(msg), None).unwrap();

    let musig_session_id2 = MusigSessionId::new(&mut rng);

    let nonce_pair2 = 
        new_musig_nonce_pair(&secp, musig_session_id2, Some(&musig_key_agg_cache), Some(seckey2), pubkey2, Some(msg), None).unwrap();

    let sec_nonce1 = nonce_pair1.0;
    let pub_nonce1 = nonce_pair1.1;

    let sec_nonce2 = nonce_pair2.0;
    let pub_nonce2 = nonce_pair2.1;

    let nonces = [pub_nonce1, pub_nonce2];
    let nonces_ref: Vec<&MusigPubNonce> = nonces.iter().collect();
    let nonces_ref = nonces_ref.as_slice();

    let agg_nonce = MusigAggNonce::new(&secp, nonces_ref);

    let session = MusigSession::new(&secp, &musig_key_agg_cache, agg_nonce, msg);

    let keypair1 = Keypair::from_secret_key(&secp, &seckey1);
    let partial_sign1 = session.partial_sign(&secp, sec_nonce1, &keypair1, &musig_key_agg_cache).unwrap();

    let keypair2 = Keypair::from_secret_key(&secp, &seckey2);
    let partial_sign2 = session.partial_sign(&secp, sec_nonce2, &keypair2, &musig_key_agg_cache).unwrap();

    let is_partial_signature_valid = session.partial_verify(&secp, &musig_key_agg_cache, partial_sign1, pub_nonce1, pubkey1);
    assert!(is_partial_signature_valid);

    let is_partial_signature_valid = session.partial_verify(&secp, &musig_key_agg_cache, partial_sign2, pub_nonce2, pubkey2);
    assert!(is_partial_signature_valid);

    let partial_sigs = [partial_sign1, partial_sign2];
    let partial_sigs_ref: Vec<&MusigPartialSignature> = partial_sigs.iter().collect();
    let partial_sigs_ref = partial_sigs_ref.as_slice();

    let sig64 = session.partial_sig_agg(partial_sigs_ref);

    assert!(secp.verify_schnorr(&sig64, &msg_bytes, &agg_pk).is_ok());
}
