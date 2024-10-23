extern crate secp256k1;

use secp256k1::{Keypair, PublicKey, Secp256k1, SecretKey, XOnlyPublicKey};
use secp256k1::silentpayments::{
    silentpayments_recipient_create_label_tweak, 
    silentpayments_sender_create_outputs, 
    SilentpaymentsRecipient, 
    silentpayments_recipient_scan_outputs,
    SilentpaymentsPublicData,
    silentpayments_recipient_create_output_pubkey,
    silentpayments_recipient_create_labelled_spend_pubkey
};

use libc::{c_uchar, c_void, size_t};
use std::slice;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct LabelCacheEntry {
    label: [u8; 33],
    label_tweak: [u8; 32],
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct LabelsCache {
    entries_used: size_t,
    entries: [LabelCacheEntry; 5],
}

#[no_mangle]
pub extern "C" fn rust_secp256k1_silentpayments_label_lookup(
    label33: *const c_uchar,
    cache_ptr: *const c_void,
) -> *const c_uchar {
    // Safety checks
    if label33.is_null() || cache_ptr.is_null() {
        return std::ptr::null();
    }

    unsafe {
        let cache = &*(cache_ptr as *const LabelsCache);
        let label33_slice = slice::from_raw_parts(label33, 33);

        for i in 0..cache.entries_used {
            if cache.entries[i].label == *label33_slice {
                return cache.entries[i].label_tweak.as_ptr();
            }
        }

        std::ptr::null()
    }
}

fn main() {

    let secp = Secp256k1::new();

    let sender_secret_keys: [[u8; 32]; 2] = [
        [
            0x34, 0x18, 0x5f, 0xd2, 0xc0, 0xc3, 0x71, 0x19,
            0x73, 0x46, 0x2e, 0xc7, 0x7b, 0x65, 0x69, 0x95,
            0x43, 0x20, 0x5a, 0xee, 0x4f, 0x30, 0xf4, 0xee,
            0x32, 0x5b, 0xd8, 0x37, 0x6a, 0x1b, 0x36, 0xf3
        ],
        [
            0xcf, 0x3e, 0x69, 0x66, 0x58, 0xa9, 0x6e, 0x45,
            0x70, 0x96, 0xcb, 0x2e, 0xc9, 0xa9, 0x7c, 0x27,
            0x8c, 0x1b, 0xf0, 0xc6, 0x0d, 0x1d, 0xc3, 0x13,
            0x92, 0x7d, 0xef, 0xac, 0xc2, 0x86, 0xae, 0x88
        ]
    ];

    let smallest_outpoint: [u8; 36] = [
        0x16, 0x9e, 0x1e, 0x83, 0xe9, 0x30, 0x85, 0x33, 0x91,
        0xbc, 0x6f, 0x35, 0xf6, 0x05, 0xc6, 0x75, 0x4c, 0xfe,
        0xad, 0x57, 0xcf, 0x83, 0x87, 0x63, 0x9d, 0x3b, 0x40,
        0x96, 0xc5, 0x4f, 0x18, 0xf4, 0x00, 0x00, 0x00, 0x00
    ];

    let bob_scan_seckey: [u8; 32] = [
        0xa8, 0x90, 0x54, 0xc9, 0x5b, 0xe3, 0xc3, 0x01,
        0x56, 0x65, 0x74, 0xf2, 0xaa, 0x93, 0xad, 0xe0,
        0x51, 0x85, 0x09, 0x03, 0xa6, 0x9c, 0xbd, 0xd1,
        0xd4, 0x7e, 0xae, 0x26, 0x3d, 0x7b, 0xc0, 0x31
    ];

    let bob_spend_pubkey: [u8; 33] = [
        0x02, 0xee, 0x97, 0xdf, 0x83, 0xb2, 0x54, 0x6a,
        0xf5, 0xa7, 0xd0, 0x62, 0x15, 0xd9, 0x8b, 0xcb,
        0x63, 0x7f, 0xe0, 0x5d, 0xd0, 0xfa, 0x37, 0x3b,
        0xd8, 0x20, 0xe6, 0x64, 0xd3, 0x72, 0xde, 0x9a, 0x01
    ];

    let bob_address: [[u8; 33]; 2] = [
        [
            0x02, 0x15, 0x40, 0xae, 0xa8, 0x97, 0x54, 0x7a,
            0xd4, 0x39, 0xb4, 0xe0, 0xf6, 0x09, 0xe5, 0xf0,
            0xfa, 0x63, 0xde, 0x89, 0xab, 0x11, 0xed, 0xe3,
            0x1e, 0x8c, 0xde, 0x4b, 0xe2, 0x19, 0x42, 0x5f, 0x23
        ],
        [
            0x02, 0x3e, 0xff, 0xf8, 0x18, 0x51, 0x65, 0xea,
            0x63, 0xa9, 0x92, 0xb3, 0x9f, 0x31, 0xd8, 0xfd,
            0x8e, 0x0e, 0x64, 0xae, 0xf9, 0xd3, 0x88, 0x07,
            0x34, 0x97, 0x37, 0x14, 0xa5, 0x3d, 0x83, 0x11, 0x8d
        ]
    ];

    let carol_scan_key: [u8; 32] = [
        0x04, 0xb2, 0xa4, 0x11, 0x63, 0x5c, 0x09, 0x77,
        0x59, 0xaa, 0xcd, 0x0f, 0x00, 0x5a, 0x4c, 0x82,
        0xc8, 0xc9, 0x28, 0x62, 0xc6, 0xfc, 0x28, 0x4b,
        0x80, 0xb8, 0xef, 0xeb, 0xc2, 0x0c, 0x3d, 0x17
    ];

    let carol_address: [[u8; 33]; 2] = [
        [
            0x03, 0xbb, 0xc6, 0x3f, 0x12, 0x74, 0x5d, 0x3b,
            0x9e, 0x9d, 0x24, 0xc6, 0xcd, 0x7a, 0x1e, 0xfe,
            0xba, 0xd0, 0xa7, 0xf4, 0x69, 0x23, 0x2f, 0xbe,
            0xcf, 0x31, 0xfb, 0xa7, 0xb4, 0xf7, 0xdd, 0xed, 0xa8
        ],
        [
            0x03, 0x81, 0xeb, 0x9a, 0x9a, 0x9e, 0xc7, 0x39,
            0xd5, 0x27, 0xc1, 0x63, 0x1b, 0x31, 0xb4, 0x21,
            0x56, 0x6f, 0x5c, 0x2a, 0x47, 0xb4, 0xab, 0x5b,
            0x1f, 0x6a, 0x68, 0x6d, 0xfb, 0x68, 0xea, 0xb7, 0x16
        ]
    ];

    let address_amounts = ["1.0 BTC", "2.0 BTC", "3.0 BTC"];

    let n_tx_outputs = 3;

    let mut sp_addresses: [&[[u8; 33]; 2]; 3] = [&[[0; 33]; 2]; 3];

    // Assign references to the addresses
    sp_addresses[0] = &carol_address; // : 1.0 BTC
    sp_addresses[1] = &bob_address;   // : 2.0 BTC
    sp_addresses[2] = &carol_address;

    let mut recipients = Vec::<SilentpaymentsRecipient>::new();

    let mut tx_inputs = Vec::<XOnlyPublicKey>::new();

    for i in 0..n_tx_outputs {
        let recipient_index = i;

        let recipient_scan_pubkey = PublicKey::from_slice(&sp_addresses[i][0]).unwrap();
        let recipient_spend_pubkey = PublicKey::from_slice(&sp_addresses[i][1]).unwrap();

        let silentpayment_recipient = SilentpaymentsRecipient::new(
            &recipient_scan_pubkey, 
            &recipient_spend_pubkey, 
            recipient_index
        );

        recipients.push(silentpayment_recipient);
    }

    let recipients = recipients.as_slice();
    let mut recipients_ref: Vec<&SilentpaymentsRecipient> = recipients.iter().collect();
    let recipients_ref = recipients_ref.as_mut_slice();

    let mut taproot_seckeys = Vec::<Keypair>::new();

    for &key in sender_secret_keys.iter() {
        let seckey: [u8; 32] = key;

        let keypair = Keypair::from_seckey_slice(&secp, &seckey).unwrap();

        taproot_seckeys.push(keypair);

        tx_inputs.push(keypair.x_only_public_key().0);
    }

    let taproot_seckeys = taproot_seckeys.as_slice();
    let taproot_seckeys_ref: Vec<&Keypair> = taproot_seckeys.iter().collect();
    let taproot_seckeys_ref = taproot_seckeys_ref.as_slice();

    let mut tx_outputs: Vec<XOnlyPublicKey> = Vec::new();

    let out_pubkeys = silentpayments_sender_create_outputs(
        &secp, 
        recipients_ref,
        &smallest_outpoint,
        Some(taproot_seckeys_ref),
        None
    ).unwrap();

    println!("{}:", "Alice created the following outputs for Bob and Carol:");
    for (i, out_pubkey)  in out_pubkeys.iter().enumerate() {
        print!("\t{} : 0x", address_amounts[i]);
        for byte in out_pubkey.serialize().iter().cloned() {
            print!("{:02x}", byte);
        }
        println!();

        tx_outputs.push(out_pubkey.clone());
    }

    let bob_scan_secretkey = SecretKey::from_slice(&bob_scan_seckey).unwrap();
    let m: u32 = 1;

    let label_tweak_result = silentpayments_recipient_create_label_tweak(&secp, &bob_scan_secretkey, m).unwrap();

    let bob_spend_publickey = PublicKey::from_slice(&bob_spend_pubkey).unwrap();

    let _labelled_spend_pubkey = silentpayments_recipient_create_labelled_spend_pubkey(
        &secp,
        &bob_spend_publickey,
        &label_tweak_result.pubkey
    ).unwrap();

    let tx_inputs_ref: Vec<&XOnlyPublicKey> = tx_inputs.iter().collect();
    let tx_inputs_ref = tx_inputs_ref.as_slice();

    let public_data: SilentpaymentsPublicData = SilentpaymentsPublicData::create(
        &secp,
        &smallest_outpoint,
        Some(tx_inputs_ref),
        None
    ).unwrap();

    let mut cache = LabelsCache {
        entries_used: 0,
        entries: [LabelCacheEntry {
            label: [0; 33],
            label_tweak: [0; 32]
        }; 5]
    };

    cache.entries[0].label = label_tweak_result.pubkey.serialize();
    cache.entries[0].label_tweak = label_tweak_result.label_tweak;
    cache.entries_used += 1;
    
    let _label_tweak = rust_secp256k1_silentpayments_label_lookup(
        label_tweak_result.pubkey.serialize().as_ptr(),
        &cache as *const LabelsCache as *const c_void
    );

    let tx_outputs_slice_ref: Vec<&XOnlyPublicKey> = tx_outputs.iter().collect();
    let tx_outputs_slice_ref = tx_outputs_slice_ref.as_slice();

    let bob_spend_publickey = PublicKey::from_slice(&bob_spend_pubkey).unwrap();

    let found_output = silentpayments_recipient_scan_outputs(
        &secp,
        tx_outputs_slice_ref,
        &bob_scan_secretkey,
        &public_data,
        &bob_spend_publickey,
        rust_secp256k1_silentpayments_label_lookup,
        cache
    ).unwrap();

    println!();
    println!("{} :", "Bob found the following outputs:");
    for output in found_output.iter() {
        println!("\t{}", output);
    }

    let light_client_data33 = public_data.serialize(&secp).unwrap();

    let carol_public_data = SilentpaymentsPublicData::parse(&secp, &light_client_data33).unwrap();

    let carol_scan_seckey = SecretKey::from_slice(&carol_scan_key).unwrap();

    let shared_secret = carol_public_data.recipient_create_shared_secret(&secp, &carol_scan_seckey).unwrap();

    let mut found: bool;
    let mut k: u32 = 0;
    let mut ser_found_outputs: Vec<XOnlyPublicKey> = Vec::new();

    let carol_spend_pubkey = PublicKey::from_slice(&carol_address[1]).unwrap();

    println!();

    loop {

        let potential_output = 
            silentpayments_recipient_create_output_pubkey(&secp, &shared_secret, &carol_spend_pubkey, k).unwrap();

        found = false;
        for i in 0..n_tx_outputs {
            if tx_outputs[i] == potential_output {
                ser_found_outputs.push(potential_output);
                found = true;
                k += 1;
                break;
            }
        }

        if !found {
            break;
        }
    }

    println!("{}:", "Carol found the following outputs");
    for output in ser_found_outputs.iter() {
        print!("\t{}", "0x");
        for byte in output.serialize().iter().cloned() {
            print!("{:02x}", byte);
        }
        println!();
    }
}