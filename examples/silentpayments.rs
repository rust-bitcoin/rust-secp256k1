use std::collections::HashMap;

use secp256k1::{silentpayments, Keypair, PublicKey, Scalar, SecretKey, XOnlyPublicKey};

const N_INPUTS: usize = 2;
const N_OUTPUTS: usize = 3;

/* Static data for Bob and Carol's silent payment addresses */
static SMALLEST_OUTPOINT: [u8; 36] = [
    0x16, 0x9e, 0x1e, 0x83, 0xe9, 0x30, 0x85, 0x33, 0x91, 0xbc, 0x6f, 0x35, 0xf6, 0x05, 0xc6, 0x75,
    0x4c, 0xfe, 0xad, 0x57, 0xcf, 0x83, 0x87, 0x63, 0x9d, 0x3b, 0x40, 0x96, 0xc5, 0x4f, 0x18, 0xf4,
    0x00, 0x00, 0x00, 0x00,
];

static BOB_SCAN_KEY: [u8; 32] = [
    0xa8, 0x90, 0x54, 0xc9, 0x5b, 0xe3, 0xc3, 0x01, 0x56, 0x65, 0x74, 0xf2, 0xaa, 0x93, 0xad, 0xe0,
    0x51, 0x85, 0x09, 0x03, 0xa6, 0x9c, 0xbd, 0xd1, 0xd4, 0x7e, 0xae, 0x26, 0x3d, 0x7b, 0xc0, 0x31,
];

static BOB_SPEND_KEY: [u8; 32] = [
    0x9d, 0x6a, 0xd8, 0x55, 0xce, 0x34, 0x17, 0xef, 0x84, 0xe8, 0x36, 0x89, 0x2e, 0x5a, 0x56, 0x39,
    0x2b, 0xfb, 0xa0, 0x5f, 0xa5, 0xd9, 0x7c, 0xce, 0xa3, 0x0e, 0x26, 0x6f, 0x54, 0x0e, 0x08, 0xb3,
];

static BOB_SCAN_AND_SPEND_PUBKEYS: [[u8; 33]; 2] = [
    [
        0x02, 0x15, 0x40, 0xae, 0xa8, 0x97, 0x54, 0x7a, 0xd4, 0x39, 0xb4, 0xe0, 0xf6, 0x09, 0xe5,
        0xf0, 0xfa, 0x63, 0xde, 0x89, 0xab, 0x11, 0xed, 0xe3, 0x1e, 0x8c, 0xde, 0x4b, 0xe2, 0x19,
        0x42, 0x5f, 0x23,
    ],
    [
        0x02, 0x5c, 0xc9, 0x85, 0x6d, 0x6f, 0x83, 0x75, 0x35, 0x0e, 0x12, 0x39, 0x78, 0xda, 0xac,
        0x20, 0x0c, 0x26, 0x0c, 0xb5, 0xb5, 0xae, 0x83, 0x10, 0x6c, 0xab, 0x90, 0x48, 0x4d, 0xcd,
        0x8f, 0xcf, 0x36,
    ],
];

static CAROL_SCAN_KEY: [u8; 32] = [
    0x04, 0xb2, 0xa4, 0x11, 0x63, 0x5c, 0x09, 0x77, 0x59, 0xaa, 0xcd, 0x0f, 0x00, 0x5a, 0x4c, 0x82,
    0xc8, 0xc9, 0x28, 0x62, 0xc6, 0xfc, 0x28, 0x4b, 0x80, 0xb8, 0xef, 0xeb, 0xc2, 0x0c, 0x3d, 0x17,
];

static CAROL_ADDRESS: [[u8; 33]; 2] = [
    [
        0x03, 0xbb, 0xc6, 0x3f, 0x12, 0x74, 0x5d, 0x3b, 0x9e, 0x9d, 0x24, 0xc6, 0xcd, 0x7a, 0x1e,
        0xfe, 0xba, 0xd0, 0xa7, 0xf4, 0x69, 0x23, 0x2f, 0xbe, 0xcf, 0x31, 0xfb, 0xa7, 0xb4, 0xf7,
        0xdd, 0xed, 0xa8,
    ],
    [
        0x03, 0x81, 0xeb, 0x9a, 0x9a, 0x9e, 0xc7, 0x39, 0xd5, 0x27, 0xc1, 0x63, 0x1b, 0x31, 0xb4,
        0x21, 0x56, 0x6f, 0x5c, 0x2a, 0x47, 0xb4, 0xab, 0x5b, 0x1f, 0x6a, 0x68, 0x6d, 0xfb, 0x68,
        0xea, 0xb7, 0x16,
    ],
];

fn main() {
    let mut sender_keypairs = Vec::<Keypair>::new();
    let mut recipients = Vec::<silentpayments::sender::Recipient>::new();

    let unlabeled_spend_pubkey =
        PublicKey::from_byte_array_compressed(BOB_SCAN_AND_SPEND_PUBKEYS[1])
            .expect("reading from constant, should not fail");

    let (bob_address, label_context) = {
        let bob_scan_key = SecretKey::from_secret_bytes(BOB_SCAN_KEY)
            .expect("reading from constant, should not fail");

        let m = 1;
        let (label, label_tweak) = silentpayments::recipient::Label::create(&bob_scan_key, m)
            .expect("transitively deterministic, should not fail");

        let mut tweak_map = HashMap::<[u8; 33], [u8; 32]>::new();

        tweak_map.insert(label.serialize(), label_tweak);

        let labeled_spend_pubkey =
            silentpayments::recipient::create_labeled_spend_pubkey(&unlabeled_spend_pubkey, &label)
                .expect("transitively deterministic, should not fail");

        let bob_address: [[u8; 33]; 2] =
            [BOB_SCAN_AND_SPEND_PUBKEYS[0], labeled_spend_pubkey.serialize()];

        (bob_address, tweak_map)
    };

    let (tx_inputs, tx_outputs) = {
        let mut tx_inputs = Vec::<XOnlyPublicKey>::new();

        for _ in 0..N_INPUTS {
            let rand_keypair = Keypair::new(&mut rand::rng());
            sender_keypairs.push(rand_keypair);
            tx_inputs.push(rand_keypair.x_only_public_key().0);
        }

        let sp_addresses = [&CAROL_ADDRESS, &bob_address, &CAROL_ADDRESS];

        for (index, address) in (0u32..).zip(sp_addresses.iter()) {
            let scan_pubkey = PublicKey::from_byte_array_compressed(address[0])
                .expect("reading from constant, should not fail");
            let spend_pubkey = PublicKey::from_byte_array_compressed(address[1])
                .expect("reading from constant, should not fail");

            let silentpayment_recipient =
                silentpayments::sender::Recipient::new(&scan_pubkey, &spend_pubkey, index);

            recipients.push(silentpayment_recipient);
        }

        let sender_keypairs: Vec<&_> = sender_keypairs.iter().collect();

        let tx_outputs = silentpayments::sender::create_outputs(
            &recipients,
            &SMALLEST_OUTPOINT,
            Some(&sender_keypairs),
            None,
        )
        .expect("negligible probability of error, should not fail");

        assert_eq!(tx_outputs.len(), N_OUTPUTS);

        println!("Alice created the following outputs for Bob and Carol:");
        for tx_output in tx_outputs.iter() {
            println!("\t0x{}", &tx_output.to_string());
        }
        println!();

        (tx_inputs, tx_outputs)
    };

    let tx_inputs_ref: Vec<&XOnlyPublicKey> = tx_inputs.iter().collect();
    let tx_outputs_ref: Vec<&XOnlyPublicKey> = tx_outputs.iter().collect();

    let prevouts_summary = silentpayments::recipient::PrevoutsSummary::create(
        &SMALLEST_OUTPOINT,
        Some(&tx_inputs_ref),
        None,
    )
    .expect("all arguments are valid and and all inputs are xonly inputs, should not fail");

    let bob_scan_key =
        SecretKey::from_secret_bytes(BOB_SCAN_KEY).expect("reading from constant, should not fail");

    let label_lookup = |key: &[u8; 33]| -> Option<[u8; 32]> { label_context.get(key).copied() };
    let found_outputs = silentpayments::recipient::scan_outputs(
        &tx_outputs_ref,
        &bob_scan_key,
        &prevouts_summary,
        &unlabeled_spend_pubkey,
        Some(&label_lookup),
    )
    .expect("all arguments are valid, should not fail");

    if !found_outputs.is_empty() {
        println!("Bob found the following outputs:");
        for xonly_output in found_outputs {
            println!("\t0x{}", &xonly_output.to_string());
            let bob_spend_key = SecretKey::from_secret_bytes(BOB_SPEND_KEY)
                .expect("reading from constant, should not fail");
            let bob_tweaked_key = bob_spend_key
                .add_tweak(
                    &Scalar::from_be_bytes(xonly_output.tweak())
                        .expect("generated by sender, should be less than curve"),
                )
                .expect("negligible probability of error, should not fail");
            let bob_spend_keypair = Keypair::from_secret_key(&bob_tweaked_key);
            let (bob_tweaked_xonly_pubkey, _parity) = bob_spend_keypair.x_only_public_key();
            assert_eq!(xonly_output.output(), bob_tweaked_xonly_pubkey);
        }
        println!();
    } else {
        println!("Bob did not find any outputs in this transaction.\n");
    }

    let unlabeled_spend_pubkey = PublicKey::from_byte_array_compressed(CAROL_ADDRESS[1])
        .expect("reading from constant, should not fail");

    let carol_scan_key = SecretKey::from_secret_bytes(CAROL_SCAN_KEY)
        .expect("reading from constant, should not fail");

    let found_outputs = silentpayments::recipient::scan_outputs(
        &tx_outputs_ref,
        &carol_scan_key,
        &prevouts_summary,
        &unlabeled_spend_pubkey,
        None::<fn(&[u8; 33]) -> Option<[u8; 32]>>,
    )
    .expect("arguments are valid and tx outputs are silent payment outputs, should not fail");

    if !found_outputs.is_empty() {
        println!("Carol found the following outputs:");
        for xonly_output in found_outputs {
            println!("\t0x{}", &xonly_output.to_string());
        }
    } else {
        println!("Carol did not find any outputs in this transaction.\n");
    }
}
