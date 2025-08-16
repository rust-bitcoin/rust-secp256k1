extern crate secp256k1;

use secp256k1::{ecdsa, Error, Message, PublicKey, Secp256k1, SecretKey, Signing, Verification};

fn recover<C: Verification>(
    secp: &Secp256k1<C>,
    msg_digest: [u8; 32],
    sig: [u8; 64],
    recovery_id: u8,
) -> Result<PublicKey, Error> {
    let msg = Message::from_digest(msg_digest);
    let id = ecdsa::RecoveryId::try_from(i32::from(recovery_id))?;
    let sig = ecdsa::RecoverableSignature::from_compact(&sig, id)?;

    secp.recover_ecdsa(msg, &sig)
}

fn sign_recovery<C: Signing>(
    secp: &Secp256k1<C>,
    msg_digest: [u8; 32],
    seckey: [u8; 32],
) -> Result<ecdsa::RecoverableSignature, Error> {
    let msg = Message::from_digest(msg_digest);
    let seckey = SecretKey::from_byte_array(seckey)?;
    Ok(secp.sign_ecdsa_recoverable(msg, &seckey))
}

fn main() {
    let secp = Secp256k1::new();

    let seckey = [
        59, 148, 11, 85, 134, 130, 61, 253, 2, 174, 59, 70, 27, 180, 51, 107, 94, 203, 174, 253,
        102, 39, 170, 146, 46, 252, 4, 143, 236, 12, 136, 28,
    ];
    let pubkey = PublicKey::from_slice(&[
        2, 29, 21, 35, 7, 198, 183, 43, 14, 208, 65, 139, 14, 112, 205, 128, 231, 245, 41, 91, 141,
        134, 245, 114, 45, 63, 82, 19, 251, 210, 57, 79, 54,
    ])
    .unwrap();
    let msg_digest = *b"this must be secure hash output.";

    let signature = sign_recovery(&secp, msg_digest, seckey).unwrap();

    let (recovery_id, serialize_sig) = signature.serialize_compact();

    assert_eq!(recover(&secp, msg_digest, serialize_sig, recovery_id.to_u8()), Ok(pubkey));
}
