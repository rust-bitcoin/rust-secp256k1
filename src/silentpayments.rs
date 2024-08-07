//! This module implements high-level Rust bindings for silent payments

use core::ffi::c_void;
use core::fmt;

#[cfg(feature = "std")]
use std;

use core;

use secp256k1_sys::{secp256k1_silentpayments_recipient_create_output_pubkey, secp256k1_silentpayments_recipient_create_shared_secret, secp256k1_silentpayments_recipient_public_data_create, secp256k1_silentpayments_recipient_public_data_parse, secp256k1_silentpayments_recipient_public_data_serialize, secp256k1_silentpayments_recipient_scan_outputs, secp256k1_silentpayments_sender_create_outputs, SilentpaymentsLabelLookupFunction};

use crate::ffi::{self, CPtr};
use crate::{constants, Keypair, PublicKey, SecretKey, XOnlyPublicKey};
use crate::Secp256k1;
use crate::Verification;

fn copy_to_ffi_pubkey(pubkey: &PublicKey) -> ffi::PublicKey {

    unsafe {
        // Get a pointer to the inner ffi::PublicKey
        let ffi_pubkey_ptr: *const ffi::PublicKey = pubkey.as_c_ptr();
        
        // Dereference the pointer to get the ffi::PublicKey
        // Then create a copy of it
        (*ffi_pubkey_ptr).clone()
    }
}


/// Struct to store recipient data
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct SilentpaymentsRecipient(ffi::SilentpaymentsRecipient);

impl SilentpaymentsRecipient {

    /// Get a new SilentpaymentsRecipient
    pub fn new(scan_pubkey: &PublicKey,  spend_pubkey: &PublicKey, index: usize) -> Self {

        Self(ffi::SilentpaymentsRecipient::new(
            &copy_to_ffi_pubkey(scan_pubkey),
            &copy_to_ffi_pubkey(spend_pubkey),
            index
        ))
    }

    /// Get a const pointer to the inner SilentpaymentsRecipient
    pub fn as_ptr(&self) -> *const ffi::SilentpaymentsRecipient {
        &self.0
    }

    /// Get a mut pointer to the inner SilentpaymentsRecipient
    pub fn as_mut_ptr(&mut self) -> *mut ffi::SilentpaymentsRecipient {
        &mut self.0
    }
}

impl CPtr for SilentpaymentsRecipient {
    type Target = ffi::SilentpaymentsRecipient;
    fn as_c_ptr(&self) -> *const Self::Target { &self.0 }

    fn as_mut_c_ptr(&mut self) -> *mut Self::Target { &mut self.0 }
}

/// Sender Output creation errors
#[derive(Debug, Clone, Copy, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub enum SenderOutputCreationError {
    /// Unexpected failures
    Failure,
}

#[cfg(feature = "std")]
impl std::error::Error for SenderOutputCreationError {}

impl fmt::Display for SenderOutputCreationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match self {
            SenderOutputCreationError::Failure => write!(f, "Failed to create silent payments outputs"),
        }
    }
}

/// Create Silent Payment outputs for recipient(s).
pub fn silentpayments_sender_create_outputs<C: Verification>(
    secp: &Secp256k1<C>,
    recipients: &[SilentpaymentsRecipient],
    smallest_outpoint: &[u8; 36],
    taproot_seckeys: Option<&[Keypair]>,
    plain_seckeys: Option<&[SecretKey]>,
) -> Result<Vec<XOnlyPublicKey>, SenderOutputCreationError> {
    let cx = secp.ctx().as_ptr();
    let n_tx_outputs = recipients.len();

    let ffi_recipients: Vec<ffi::SilentpaymentsRecipient> = recipients.iter().map(|r| r.0.clone()).collect();
    let mut ffi_recipients_ptrs: Vec<_> = ffi_recipients.iter().map(|r| r as *const _).collect();

    // Create vectors to hold the data, ensuring it stays in scope
    let mut ffi_taproot_seckeys = Vec::new();
    let mut ffi_taproot_seckeys_ptrs = Vec::new();
    let mut plain_seckeys_u8_array = Vec::new();
    let mut plain_seckeys_ptrs = Vec::new();

    // Populate taproot seckeys if provided
    if let Some(taproot_seckeys) = taproot_seckeys {
        ffi_taproot_seckeys = taproot_seckeys
            .iter()
            .map(|tap_keypair| unsafe { (*tap_keypair.as_c_ptr()).clone() })
            .collect();
        ffi_taproot_seckeys_ptrs = ffi_taproot_seckeys
            .iter()
            .map(|keypair| keypair as *const ffi::Keypair)
            .collect();
    }

    // Populate plain seckeys if provided
    if let Some(plain_seckeys) = plain_seckeys {
        plain_seckeys_u8_array = plain_seckeys
            .iter()
            .map(|k| k.secret_bytes())
            .collect();
        plain_seckeys_ptrs = plain_seckeys_u8_array
            .iter()
            .map(|k| k.as_ptr())
            .collect();
    }

    let n_taproot_seckeys = ffi_taproot_seckeys.len();
    let n_plain_seckeys = plain_seckeys_u8_array.len();

    let result = unsafe {
        let mut out_pubkeys = vec![ffi::XOnlyPublicKey::new(); n_tx_outputs];
        let mut out_pubkeys_ptrs: Vec<_> = out_pubkeys.iter_mut().map(|k| k as *mut _).collect();

        let res = secp256k1_silentpayments_sender_create_outputs(
            cx,
            out_pubkeys_ptrs.as_mut_ptr(),
            ffi_recipients_ptrs.as_mut_ptr(),
            n_tx_outputs,
            smallest_outpoint.as_ptr(),
            if !ffi_taproot_seckeys_ptrs.is_empty() { ffi_taproot_seckeys_ptrs.as_ptr() } else { std::ptr::null() },
            n_taproot_seckeys,
            if !plain_seckeys_ptrs.is_empty() { plain_seckeys_ptrs.as_ptr() } else { std::ptr::null() },
            n_plain_seckeys,
        );

        if res == 1 {
            Ok(out_pubkeys.into_iter().map(XOnlyPublicKey::from).collect())
        } else {
            Err(SenderOutputCreationError::Failure)
        }
    };

    result
}

/// Struct to store label tweak result
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LabelTweakResult {
    /// Public key
    pub pubkey: PublicKey,
    /// Label tweak
    pub label_tweak: [u8; 32],
}

/// Create Silent Payment label tweak and label.
pub fn silentpayments_recipient_create_label_tweak<C: Verification>(
    secp: &Secp256k1<C>,
    recipient_scan_key: &SecretKey,
    m: u32,
) -> Result<LabelTweakResult, &'static str> {

    let cx = secp.ctx().as_ptr();
    unsafe {

        let mut pubkey = ffi::PublicKey::new();
        let mut label_tweak32 = [0u8; 32];

        let res = ffi::secp256k1_silentpayments_recipient_create_label_tweak(
            cx,
            &mut pubkey,
            label_tweak32.as_mut_c_ptr(),
            recipient_scan_key.as_c_ptr(),
            m,
        );

        if res == 1 {
            let pubkey = PublicKey::from(pubkey);
            let label_tweak = label_tweak32;

            return Ok(LabelTweakResult { pubkey, label_tweak });
        } else {
            return Err("Failed to create label tweak");
        }
    }
}

/// Struct to store public data
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SilentpaymentsPublicData(ffi::SilentpaymentsPublicData);

impl CPtr for SilentpaymentsPublicData {
    type Target = ffi::SilentpaymentsPublicData;

    /// Obtains a const pointer suitable for use with FFI functions.
    fn as_c_ptr(&self) -> *const Self::Target { &self.0 }

    /// Obtains a mutable pointer suitable for use with FFI functions.
    fn as_mut_c_ptr(&mut self) -> *mut Self::Target { &mut self.0 }
}

impl SilentpaymentsPublicData {
    /// Create a new `SilentpaymentsPublicData` object.
    pub fn new() -> SilentpaymentsPublicData {
        let empty_data = [0u8; constants::SILENT_PAYMENTS_PUBLIC_DATA_SIZE];
        SilentpaymentsPublicData(ffi::SilentpaymentsPublicData::from_array(empty_data))
    }

    /// Creates an `SilentpaymentsPublicData` object from a 98-byte array.
    pub fn from_array(data: [u8; 98]) -> SilentpaymentsPublicData {
        SilentpaymentsPublicData(ffi::SilentpaymentsPublicData::from_array(data))
    }

    /// Returns the 64-byte array representation of this `SilentpaymentsPublicData` object.
    pub fn to_array(&self) -> [u8; 98] { self.0.to_array() }

    /// Serialize a `silentpayments_public_data object`` into a 33-byte sequence.
    pub fn serialize<C: Verification>(&self,
        secp: &Secp256k1<C>) -> Result<[u8; 33], &'static str> {

        let mut output33 = [0u8; 33];

        let res = unsafe {
            secp256k1_silentpayments_recipient_public_data_serialize(
                secp.ctx().as_ptr(),
                output33.as_mut_c_ptr(),
                self.as_c_ptr(),
            )
        };

        if res == 1 {
            Ok(output33)
        } else {
            Err("Failed to serialize silent payments public data")
        }
    }

    /// Parse a 33-byte sequence into a silent_payments_public_data object.
    pub fn parse<C: Verification>(secp: &Secp256k1<C>, input33: &[u8; 33]) -> Result<Self, &'static str> {

        let empty_data = [0u8; constants::SILENT_PAYMENTS_PUBLIC_DATA_SIZE];
        let mut silentpayments_public_data = ffi::SilentpaymentsPublicData::from_array(empty_data);

        let res = unsafe {
            secp256k1_silentpayments_recipient_public_data_parse(
                secp.ctx().as_ptr(),
                &mut silentpayments_public_data,
                input33.as_c_ptr(),
            )
        };

        if res == 1 {
            let silentpayments_public_data = SilentpaymentsPublicData(silentpayments_public_data);
            Ok(silentpayments_public_data)
        } else {
            Err("Failed to parse silent payments public data")
        }
    }

    /// Create Silent Payment shared secret.
    pub fn recipient_create_shared_secret<C: Verification>(&self, secp: &Secp256k1<C>, recipient_scan_key: &SecretKey) -> Result<[u8; 33], &'static str> {
        let mut output33 = [0u8; 33];

        let res = unsafe {
            secp256k1_silentpayments_recipient_create_shared_secret(
                secp.ctx().as_ptr(),
                output33.as_mut_c_ptr(),
                recipient_scan_key.as_c_ptr(),
                self.as_c_ptr(),
            )
        };

        if res == 1 {
            Ok(output33)
        } else {
            Err("Failed to parse silent payments public data")
        }
    }
}

/// Compute Silent Payment public data from input public keys and transaction inputs
pub fn silentpayments_recipient_public_data_create<C: Verification>(
    secp: &Secp256k1<C>,
    smallest_outpoint: &[u8; 36],
    xonly_pubkeys: Option<&[XOnlyPublicKey]>,
    plain_pubkeys: Option<&[PublicKey]>,
) -> Result<SilentpaymentsPublicData, &'static str> {

    let cx = secp.ctx().as_ptr();

    // Create vectors to hold the data, ensuring it stays in scope
    let mut ffi_xonly_pubkeys = Vec::new();
    let mut ffi_xonly_pubkeys_ptrs = Vec::new();
    let mut ffi_plain_pubkeys = Vec::new();
    let mut ffi_plain_pubkeys_ptrs = Vec::new();

    // Populate xonly pubkeys if provided
    if let Some(xonly_pubkeys) = xonly_pubkeys {
        ffi_xonly_pubkeys = xonly_pubkeys
            .iter()
            .map(|xonly_pubkey| unsafe { (*xonly_pubkey.as_c_ptr()).clone() })
            .collect();
        ffi_xonly_pubkeys_ptrs = ffi_xonly_pubkeys
            .iter()
            .map(|keypair| keypair as *const ffi::XOnlyPublicKey)
            .collect();
    }

    // Populate taproot seckeys if provided
    if let Some(plain_pubkeys) = plain_pubkeys {
        ffi_plain_pubkeys = plain_pubkeys
            .iter()
            .map(|plain_pubkey| unsafe { (*plain_pubkey.as_c_ptr()).clone() })
            .collect();
        ffi_plain_pubkeys_ptrs = ffi_plain_pubkeys
            .iter()
            .map(|keypair| keypair as *const ffi::PublicKey)
            .collect();
    }

    let n_xonly_pubkeys = ffi_xonly_pubkeys.len();
    let n_plain_pubkeys = ffi_plain_pubkeys.len();

    unsafe {
        
        let empty_data = [0u8; constants::SILENT_PAYMENTS_PUBLIC_DATA_SIZE];
        let mut silentpayments_public_data = ffi::SilentpaymentsPublicData::from_array(empty_data);

        let res = secp256k1_silentpayments_recipient_public_data_create(
            cx,
            &mut silentpayments_public_data,
            smallest_outpoint.as_c_ptr(),
            if !ffi_xonly_pubkeys_ptrs.is_empty() { ffi_xonly_pubkeys_ptrs.as_ptr() } else { std::ptr::null() },
            n_xonly_pubkeys,
            if !ffi_plain_pubkeys_ptrs.is_empty() { ffi_plain_pubkeys_ptrs.as_ptr() } else { std::ptr::null() },
            n_plain_pubkeys,
        );

        if res == 1 {
            let silentpayments_public_data = SilentpaymentsPublicData(silentpayments_public_data);
            Ok(silentpayments_public_data)
        } else {
            Err("Failed to create silent payments public data")
        }
    }
}

/// Found outputs struct
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SilentpaymentsFoundOutput(ffi::SilentpaymentsFoundOutput);

impl CPtr for SilentpaymentsFoundOutput {
    type Target = ffi::SilentpaymentsFoundOutput;

    /// Obtains a const pointer suitable for use with FFI functions.
    fn as_c_ptr(&self) -> *const Self::Target { &self.0 }

    /// Obtains a mutable pointer suitable for use with FFI functions.
    fn as_mut_c_ptr(&mut self) -> *mut Self::Target { &mut self.0 }
}

impl fmt::Display for SilentpaymentsFoundOutput {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {

        let pubkey = XOnlyPublicKey::from(self.0.output.clone());

        let buffer_str = pubkey.serialize()
            .iter()
            .map(|byte| format!("{:02x}", byte))
            .collect::<String>();

        write!(f, "{}", buffer_str)
    }
}

impl SilentpaymentsFoundOutput {
    /// Create a new `SilentpaymentsFoundOutput` object from a ffi::SilentpaymentsFoundOutput.
    pub fn empty() -> SilentpaymentsFoundOutput {
        SilentpaymentsFoundOutput(ffi::SilentpaymentsFoundOutput::empty())
    }
}

/// Scan for Silent Payment transaction outputs.
pub fn silentpayments_recipient_scan_outputs<C: Verification, L>(
    secp: &Secp256k1<C>,
    tx_outputs: &[XOnlyPublicKey],
    recipient_scan_key: &SecretKey,
    public_data: &SilentpaymentsPublicData,
    recipient_spend_pubkey: &PublicKey,
    label_lookup: SilentpaymentsLabelLookupFunction,
    label_context: L,
) -> Result<Vec<SilentpaymentsFoundOutput>, &'static str>
{

    let cx = secp.ctx().as_ptr();

    let n_tx_outputs = tx_outputs.len();

    let mut out_found_output = vec![ffi::SilentpaymentsFoundOutput::empty(); n_tx_outputs];
    let mut out_found_output_ptrs: Vec<_> = out_found_output.iter_mut().map(|k| k as *mut _).collect();

    let ffi_tx_outputs: Vec<ffi::XOnlyPublicKey>  = tx_outputs
            .iter()
            .map(|tx_output| unsafe { (*tx_output.as_c_ptr()).clone() })
            .collect();

    let ffi_tx_outputs_ptrs: Vec<_> = ffi_tx_outputs
            .iter()
            .map(|tx_output| tx_output as *const ffi::XOnlyPublicKey)
            .collect();

    let mut n_found_outputs: usize = 0;

    let res = unsafe {

        secp256k1_silentpayments_recipient_scan_outputs(
            cx,
            out_found_output_ptrs.as_mut_c_ptr(),
            &mut n_found_outputs,
            ffi_tx_outputs_ptrs.as_c_ptr(),
            n_tx_outputs,
            recipient_scan_key.as_c_ptr(),
            public_data.as_c_ptr(),
            recipient_spend_pubkey.as_c_ptr(),
            label_lookup,
            &label_context as *const L as *const c_void,
        )
    };

    if res == 1 {

        let mut result = vec![SilentpaymentsFoundOutput::empty(); n_found_outputs];
        
        for i in 0..n_found_outputs {
            result[i] = SilentpaymentsFoundOutput(out_found_output[i]);

        }
        
        Ok(result)
    } else {
        Err("Failed to scan outputs")
    }
}

/// Create Silent Payment output public key.
pub fn silentpayments_recipient_create_output_pubkey(
    secp: &Secp256k1<crate::All>,
    shared_secret33: &[u8; 33],
    recipient_spend_pubkey: &PublicKey,
    k: u32,
) -> Result<XOnlyPublicKey, &'static str> {

    let cx = secp.ctx().as_ptr();
    unsafe {

        let mut pubkey = ffi::XOnlyPublicKey::new();

        let res = secp256k1_silentpayments_recipient_create_output_pubkey(
            cx,
            &mut pubkey,
            shared_secret33.as_c_ptr(),
            recipient_spend_pubkey.as_c_ptr(),
            k,
        );

        if res == 1 {
            let pubkey = XOnlyPublicKey::from(pubkey);
            Ok(pubkey)
        } else {
            Err("Failed to create output pubkey")
        }
    }
}

/// Create Silent Payment labelled spend public key.
pub fn silentpayments_recipient_create_labelled_spend_pubkey(
    secp: &Secp256k1<crate::All>,
    recipient_spend_pubkey: &PublicKey,
    label: &PublicKey,
) -> Result<PublicKey, &'static str> {

    let cx = secp.ctx().as_ptr();
    unsafe {

        let mut pubkey = ffi::PublicKey::new();

        let res = ffi::secp256k1_silentpayments_recipient_create_labelled_spend_pubkey(
            cx,
            &mut pubkey,
            recipient_spend_pubkey.as_c_ptr(),
            label.as_c_ptr(),
        );

        if res == 1 {
            let pubkey = PublicKey::from(pubkey);
            Ok(pubkey)
        } else {
            Err("Failed to create labelled spend pubkey")
        }
    }
}
