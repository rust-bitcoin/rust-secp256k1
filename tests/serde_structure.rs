extern crate secp256k1;
extern crate serde_test;

use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use serde_test::{Configure, Token, assert_tokens};

#[test]
fn test_serde_structure() {

    let s = Secp256k1::new();

    let msg = Message::from_slice(&[1; 32]).unwrap();
    let sk = SecretKey::from_slice(&[2; 32]).unwrap();
    let sig = s.sign(&msg, &sk);
    static SIG_BYTES: [u8; 71] = [
        48, 69, 2, 33, 0, 157, 11, 173, 87, 103, 25, 211, 42, 231, 107, 237,
        179, 76, 119, 72, 102, 103, 60, 189, 227, 244, 225, 41, 81, 85, 92, 148,
        8, 230, 206, 119, 75, 2, 32, 40, 118, 231, 16, 47, 32, 79, 107, 254,
        226, 108, 150, 124, 57, 38, 206, 112, 44, 249, 125, 75, 1, 0, 98, 225,
        147, 247, 99, 25, 15, 103, 118
    ];
    static SIG_STR: &'static str = "\
        30450221009d0bad576719d32ae76bedb34c774866673cbde3f4e12951555c9408e6ce77\
        4b02202876e7102f204f6bfee26c967c3926ce702cf97d4b010062e193f763190f6776\
    ";

    assert_tokens(&sig.compact(), &[Token::BorrowedBytes(&SIG_BYTES[..])]);
    assert_tokens(&sig.readable(), &[Token::BorrowedStr(SIG_STR)]);
}

#[test]
fn test_secret_key_serde_structure() {
    static SK_BYTES: [u8; 32] = [
        1, 1, 1, 1, 1, 1, 1, 1,
        0, 1, 2, 3, 4, 5, 6, 7,
        0xff, 0xff, 0, 0, 0xff, 0xff, 0, 0,
        99, 99, 99, 99, 99, 99, 99, 99
    ];
    static SK_STR: &'static str = "\
        01010101010101010001020304050607ffff0000ffff00006363636363636363\
    ";
    static PK_BYTES: [u8; 33] = [
        0x02,
        0x18, 0x84, 0x57, 0x81, 0xf6, 0x31, 0xc4, 0x8f,
        0x1c, 0x97, 0x09, 0xe2, 0x30, 0x92, 0x06, 0x7d,
        0x06, 0x83, 0x7f, 0x30, 0xaa, 0x0c, 0xd0, 0x54,
        0x4a, 0xc8, 0x87, 0xfe, 0x91, 0xdd, 0xd1, 0x66,
    ];
    static PK_STR: &'static str = "\
        0218845781f631c48f1c9709e23092067d06837f30aa0cd0544ac887fe91ddd166\
    ";

    let s = Secp256k1::new();

    let sk = SecretKey::from_slice(&SK_BYTES).unwrap();
    let pk = PublicKey::from_secret_key(&s, &sk);

    assert_tokens(&sk.compact(), &[Token::BorrowedBytes(&SK_BYTES[..])]);
    assert_tokens(&sk.readable(), &[Token::BorrowedStr(SK_STR)]);
    assert_tokens(&pk.compact(), &[Token::BorrowedBytes(&PK_BYTES[..])]);
    assert_tokens(&pk.readable(), &[Token::BorrowedStr(PK_STR)]);
}

