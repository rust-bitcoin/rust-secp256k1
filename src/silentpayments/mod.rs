//! This module implements high-level Rust bindings for the libsecp256k1 implementation for Silent
//! Payments, as specified in BIP352.
//!
//! This particularly involves the creation of input tweak data by summing up secret or public keys
//! and the derivation of a shared secret using Elliptic Curve Diffie-Hellman. Combined are either:
//!
//!   - spender's secret keys and recipient's public key (a * B, sender side)
//!   - spender's public keys and recipient's secret key (A * b, recipient side)
//!
//! With this result, the necessary key material for ultimately creating/scanning
//! or spending Silent Payment outputs can be determined.
//!
//! Note that the underlying module this crate is binding is _not_ a full implementation of BIP352,
//! as it inherently doesn't deal with higher-level concepts like addresses, output script types or
//! transactions. The intent is to provide bindings to the libsecp256k1 module for abstracting away
//! the elliptic-curve operations required for the protocol. For any wallet software already using
//! this crate, this API should provide all the functions needed for a Silent Payments
//! implementation without requiring any further elliptic-curve operations from the wallet.
pub mod recipient;
pub mod sender;

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use crate::silentpayments::{recipient as sp_rx, sender as sp_tx};
    use crate::{Keypair, PublicKey, SecretKey, XOnlyPublicKey};

    const SENDER_SECRET_KEYS: [[u8; 32]; 2] = [
        [
            0x34, 0x18, 0x5f, 0xd2, 0xc0, 0xc3, 0x71, 0x19, 0x73, 0x46, 0x2e, 0xc7, 0x7b, 0x65,
            0x69, 0x95, 0x43, 0x20, 0x5a, 0xee, 0x4f, 0x30, 0xf4, 0xee, 0x32, 0x5b, 0xd8, 0x37,
            0x6a, 0x1b, 0x36, 0xf3,
        ],
        [
            0xcf, 0x3e, 0x69, 0x66, 0x58, 0xa9, 0x6e, 0x45, 0x70, 0x96, 0xcb, 0x2e, 0xc9, 0xa9,
            0x7c, 0x27, 0x8c, 0x1b, 0xf0, 0xc6, 0x0d, 0x1d, 0xc3, 0x13, 0x92, 0x7d, 0xef, 0xac,
            0xc2, 0x86, 0xae, 0x88,
        ],
    ];

    const SMALLEST_OUTPOINT: [u8; 36] = [
        0x16, 0x9e, 0x1e, 0x83, 0xe9, 0x30, 0x85, 0x33, 0x91, 0xbc, 0x6f, 0x35, 0xf6, 0x05, 0xc6,
        0x75, 0x4c, 0xfe, 0xad, 0x57, 0xcf, 0x83, 0x87, 0x63, 0x9d, 0x3b, 0x40, 0x96, 0xc5, 0x4f,
        0x18, 0xf4, 0x00, 0x00, 0x00, 0x00,
    ];

    const BOB_SCAN_SECKEY: [u8; 32] = [
        0xa8, 0x90, 0x54, 0xc9, 0x5b, 0xe3, 0xc3, 0x01, 0x56, 0x65, 0x74, 0xf2, 0xaa, 0x93, 0xad,
        0xe0, 0x51, 0x85, 0x09, 0x03, 0xa6, 0x9c, 0xbd, 0xd1, 0xd4, 0x7e, 0xae, 0x26, 0x3d, 0x7b,
        0xc0, 0x31,
    ];

    const BOB_SPEND_PUBKEY: [u8; 33] = [
        0x02, 0xee, 0x97, 0xdf, 0x83, 0xb2, 0x54, 0x6a, 0xf5, 0xa7, 0xd0, 0x62, 0x15, 0xd9, 0x8b,
        0xcb, 0x63, 0x7f, 0xe0, 0x5d, 0xd0, 0xfa, 0x37, 0x3b, 0xd8, 0x20, 0xe6, 0x64, 0xd3, 0x72,
        0xde, 0x9a, 0x01,
    ];

    const BOB_ADDRESS: [[u8; 33]; 2] = [
        [
            0x02, 0x15, 0x40, 0xae, 0xa8, 0x97, 0x54, 0x7a, 0xd4, 0x39, 0xb4, 0xe0, 0xf6, 0x09,
            0xe5, 0xf0, 0xfa, 0x63, 0xde, 0x89, 0xab, 0x11, 0xed, 0xe3, 0x1e, 0x8c, 0xde, 0x4b,
            0xe2, 0x19, 0x42, 0x5f, 0x23,
        ],
        [
            0x02, 0x3e, 0xff, 0xf8, 0x18, 0x51, 0x65, 0xea, 0x63, 0xa9, 0x92, 0xb3, 0x9f, 0x31,
            0xd8, 0xfd, 0x8e, 0x0e, 0x64, 0xae, 0xf9, 0xd3, 0x88, 0x07, 0x34, 0x97, 0x37, 0x14,
            0xa5, 0x3d, 0x83, 0x11, 0x8d,
        ],
    ];

    const CAROL_SCAN_KEY: [u8; 32] = [
        0x04, 0xb2, 0xa4, 0x11, 0x63, 0x5c, 0x09, 0x77, 0x59, 0xaa, 0xcd, 0x0f, 0x00, 0x5a, 0x4c,
        0x82, 0xc8, 0xc9, 0x28, 0x62, 0xc6, 0xfc, 0x28, 0x4b, 0x80, 0xb8, 0xef, 0xeb, 0xc2, 0x0c,
        0x3d, 0x17,
    ];

    const CAROL_ADDRESS: [[u8; 33]; 2] = [
        [
            0x03, 0xbb, 0xc6, 0x3f, 0x12, 0x74, 0x5d, 0x3b, 0x9e, 0x9d, 0x24, 0xc6, 0xcd, 0x7a,
            0x1e, 0xfe, 0xba, 0xd0, 0xa7, 0xf4, 0x69, 0x23, 0x2f, 0xbe, 0xcf, 0x31, 0xfb, 0xa7,
            0xb4, 0xf7, 0xdd, 0xed, 0xa8,
        ],
        [
            0x03, 0x81, 0xeb, 0x9a, 0x9a, 0x9e, 0xc7, 0x39, 0xd5, 0x27, 0xc1, 0x63, 0x1b, 0x31,
            0xb4, 0x21, 0x56, 0x6f, 0x5c, 0x2a, 0x47, 0xb4, 0xab, 0x5b, 0x1f, 0x6a, 0x68, 0x6d,
            0xfb, 0x68, 0xea, 0xb7, 0x16,
        ],
    ];

    #[test]
    fn full_silentpayment_flow_one_sender_two_receivers() {
        // Assign references to the addresses
        let sp_addresses: [&[[u8; 33]; 2]; 3] = [
            &CAROL_ADDRESS, // 1.0 BTC
            &BOB_ADDRESS,   // 2.0 BTC
            &CAROL_ADDRESS, // 3.0 BTC
        ];

        let mut recipients = Vec::<sp_tx::Recipient>::new();
        for (index, [scan_pubkey, spend_pubkey]) in (0u32..).zip(sp_addresses.iter()) {
            let scan_pubkey =
                PublicKey::from_slice(scan_pubkey).expect("deterministic, shouldn't fail");
            let spend_pubkey =
                PublicKey::from_slice(spend_pubkey).expect("deterministic, shouldn't fail");

            let silentpayment_recipient = sp_tx::Recipient::new(&scan_pubkey, &spend_pubkey, index);

            recipients.push(silentpayment_recipient);
        }

        let mut taproot_seckeys = Vec::<Keypair>::new();
        let mut tx_inputs = Vec::<XOnlyPublicKey>::new();

        for &key in SENDER_SECRET_KEYS.iter() {
            let seckey: [u8; 32] = key;

            let keypair =
                Keypair::from_seckey_byte_array(seckey).expect("deterministic, shouldn't fail");

            taproot_seckeys.push(keypair);

            tx_inputs.push(keypair.x_only_public_key().0);
        }

        let taproot_seckeys: Vec<&Keypair> = taproot_seckeys.iter().collect();

        let tx_outputs =
            sp_tx::create_outputs(&recipients, &SMALLEST_OUTPOINT, Some(&taproot_seckeys), None)
                .expect("deterministic, shouldn't fail");

        assert_eq!(
            "dfb7b9b4414bd084041a83bba20d8a7d36263d5dc26489a8da0bcaa881a07340",
            format!("{}", tx_outputs[0])
        );
        assert_eq!(
            "9d5aa1cb80d9d7433ed0c8287297d4f76e52de2a930f011417311716d6a933cc",
            format!("{}", tx_outputs[1])
        );
        assert_eq!(
            "249d9a68bf413c9edddc6b48db0a912bc475b4da9a9b53fc755edf9b06bec69d",
            format!("{}", tx_outputs[2])
        );

        let bob_scan_seckey =
            SecretKey::from_secret_bytes(BOB_SCAN_SECKEY).expect("deterministic, shouldn't fail");
        let m: u32 = 1;

        let (label, label_tweak32) =
            sp_rx::Label::create(&bob_scan_seckey, m).expect("deterministic, shouldn't fail");

        let bob_spend_pubkey =
            PublicKey::from_slice(&BOB_SPEND_PUBKEY).expect("deterministic, shouldn't fail");

        let _labeled_spend_pubkey = sp_rx::create_labeled_spend_pubkey(&bob_spend_pubkey, &label)
            .expect("deterministic, shouldn't fail");

        let tx_inputs_ref: Vec<&XOnlyPublicKey> = tx_inputs.iter().collect();
        let tx_inputs_ref = tx_inputs_ref.as_slice();

        let public_data: sp_rx::PrevoutsSummary =
            sp_rx::PrevoutsSummary::create(&SMALLEST_OUTPOINT, Some(tx_inputs_ref), None)
                .expect("deterministic, shouldn't fail");

        let mut tweak_map = HashMap::<[u8; 33], [u8; 32]>::new();

        tweak_map.insert(label.serialize(), label_tweak32);

        let tx_outputs_ref: Vec<_> = tx_outputs.iter().collect();

        let label_lookup = |key: &[u8; 33]| -> Option<[u8; 32]> { tweak_map.get(key).copied() };

        assert_eq!(label_lookup(&label.serialize()), Some(label_tweak32));

        let found_outputs = sp_rx::scan_outputs(
            &tx_outputs_ref,
            &bob_scan_seckey,
            &public_data,
            &bob_spend_pubkey,
            Some(label_lookup),
        )
        .expect("deterministic, shouldn't fail");

        assert_eq!(
            found_outputs.len(),
            1,
            "First receiver should find one output after full scanning"
        );
        assert_eq!(
            "9d5aa1cb80d9d7433ed0c8287297d4f76e52de2a930f011417311716d6a933cc",
            format!("{}", found_outputs[0])
        );

        let carol_scan_key =
            SecretKey::from_secret_bytes(CAROL_SCAN_KEY).expect("deterministic, shouldn't fail");

        let carol_spend_pubkey =
            PublicKey::from_slice(&CAROL_ADDRESS[1]).expect("deterministic, shouldn't fail");

        let found_outputs = sp_rx::scan_outputs(
            &tx_outputs_ref,
            &carol_scan_key,
            &public_data,
            &carol_spend_pubkey,
            None::<fn(&[u8; 33]) -> Option<[u8; 32]>>,
        )
        .expect("deterministic, shouldn't fail");

        assert_eq!(
            found_outputs.len(),
            2,
            "Second receiver should find two outputs after full scanning"
        );
        assert_eq!(
            "dfb7b9b4414bd084041a83bba20d8a7d36263d5dc26489a8da0bcaa881a07340",
            format!("{}", found_outputs[0])
        );
        assert_eq!(
            "249d9a68bf413c9edddc6b48db0a912bc475b4da9a9b53fc755edf9b06bec69d",
            format!("{}", found_outputs[1])
        );
    }
}
