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
