//! Provide all the binding functions and methods to be used from the perspective of the
//! silentpayments sender.
use crate::ffi::{self, CPtr};
use crate::{Keypair, PublicKey, Secp256k1, SecretKey, XOnlyPublicKey};

/// Struct to store recipient data.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct Recipient(ffi::silentpayments::Recipient);

impl CPtr for Recipient {
    type Target = ffi::silentpayments::Recipient;
    fn as_c_ptr(&self) -> *const Self::Target { &self.0 }

    fn as_mut_c_ptr(&mut self) -> *mut Self::Target { &mut self.0 }
}

impl Recipient {
    /// Get a new [`Recipient`]
    pub fn new(scan_pubkey: &PublicKey, spend_pubkey: &PublicKey, index: u32) -> Self {
        unsafe {
            Self(ffi::silentpayments::Recipient::new(
                &*scan_pubkey.as_c_ptr(),
                &*spend_pubkey.as_c_ptr(),
                index,
            ))
        }
    }
}

/// Error produced while creating silent payment outputs
#[derive(Debug, Clone, Copy, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub enum CreateOutputError {
    /// Error creating silent payment ouput x-only public keys.
    DerivationError,
    /// Number of recipients does not fit within an unsigned 32-bit integer
    TooManyRecipientsError,
}

#[cfg(feature = "std")]
impl std::error::Error for CreateOutputError {}

impl core::fmt::Display for CreateOutputError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        match self {
            Self::DerivationError => {
                write!(f, "Failed while deriving silent payment output x-only public keys")
            }
            Self::TooManyRecipientsError => {
                write!(f, "Number of recipients must fit within an unsigned 32-bit integer")
            }
        }
    }
}

/// Create Silent Payment outputs for recipient(s).
///
/// Given a list of n secret keys a_1...a_n (one for each silent payment
/// eligible input to spend), a serialized outpoint, and a list of recipients,
/// create the taproot outputs. Inputs with conditional branches or multiple
/// public keys are excluded from silent payments eligible inputs; see BIP352
/// for more information.
///
/// `lexmin_outpoint` refers to the smallest outpoint lexicographically
/// from the transaction inputs (both silent payments eligible and non-eligible
/// inputs). This value MUST be the smallest outpoint out of ALL of the
/// transaction inputs, otherwise the recipient will be unable to find the
/// payment. Determining the smallest outpoint from the list of transaction
/// inputs is the responsibility of the caller. It is strongly recommended
/// that implementations ensure they are doing this correctly by using the
/// test vectors from BIP352.
///
/// When creating more than one generated output, all of the generated outputs
/// MUST be included in the final transaction. Dropping any of the generated
/// outputs from the final transaction may make all or some of the outputs
/// unfindable by the recipient.
///
/// # Arguments
/// * `recipients` - slice of [`Recipient`] mutable references. The index indicates
///   its position in the original ordering. The recipients will be grouped by scan public key in
///   place (as specified in BIP0352), but generated outputs are saved in the `generated_outputs`
///   array to match the original ordering (using the index field). This ensures the caller is able
///   to match the generated outputs to the correct silent payment addresses. The same recipient can
///   be passed multiple times to create multiple outputs for the same recipient.
/// * `lexmin_outpoint` - serialized (36-byte) smallest outpoint (lexicographically) from the transaction inputs
/// * `taproot_seckeys` - optionally a slice of [`Keypair`] references of taproot inputs.
/// * `plain_seckeys` - optionally a slice of [`SecretKey`] references of non-taproot inputs.
///
/// # Returns
/// A vector to xonly public keys, one per recipient. Outputs are ordered to match the original
/// ordering of the recipient objects, i.e., the vector element zero is the generated output for
/// the [`Recipient`] struct with index = 0.
///
/// # Errors
/// * [`CreateOutputError`] - This is expected only with an adversarially chosen
///   recipient spend key. Specifically, failure occurs when:
///   - Input secret keys sum to 0 or the negation of a spend key (negligible probability if at least
///     one of the input secret keys is uniformly random and independent of all other keys).
///   - A hash output is not a valid scalar (negligible probability per hash evaluation).
pub fn create_outputs(
    recipients: &[Recipient],
    lexmin_outpoint: &[u8; 36],
    taproot_seckeys: Option<&[&Keypair]>,
    plain_seckeys: Option<&[&SecretKey]>,
) -> Result<Vec<XOnlyPublicKey>, CreateOutputError> {
    let n_recipients = match core::convert::TryInto::<u32>::try_into(recipients.len()) {
        Ok(n_recipients) => n_recipients,
        Err(_) => return Err(CreateOutputError::TooManyRecipientsError),
    };

    let mut seed = [0u8; 32];

    let ffi_taproot_seckeys_ptrs = taproot_seckeys.map(|keys| {
        for key in keys {
            for (this, that) in seed.iter_mut().zip(key.to_secret_bytes().iter()) {
                *this ^= *that;
            }
        }

        let ptrs: Vec<*const ffi::Keypair> = keys.iter().map(|key| key.as_c_ptr()).collect();
        ptrs
    });

    let (ffi_taproot_seckeys, n_taproot_seckeys) =
        if let Some(ref seckeys) = ffi_taproot_seckeys_ptrs {
            (seckeys.as_c_ptr(), seckeys.len())
        } else {
            (core::ptr::null::<*const ffi::Keypair>(), 0_usize)
        };

    let (ffi_plain_seckeys, n_plain_seckeys) = match plain_seckeys {
        Some(keys) => {
            for key in keys {
                for (this, that) in seed.iter_mut().zip(key.to_secret_bytes().iter()) {
                    *this ^= *that;
                }
            }
            (
                keys.iter()
                    .map(|key| key.to_secret_bytes().as_c_ptr())
                    .collect::<Vec<*const u8>>()
                    .as_c_ptr(),
                keys.len(),
            )
        }
        None => (core::ptr::null::<*const *const u8>() as *const *const u8, 0_usize),
    };

    let mut ffi_generated_outputs = unsafe { vec![ffi::XOnlyPublicKey::new(); recipients.len()] };
    let mut ffi_generated_outputs_refs =
        ffi_generated_outputs.iter_mut().map(|k| k as *mut _).collect::<Vec<_>>();

    let mut local_recipients = recipients.to_vec();
    let ffi_recipients = local_recipients
        .iter_mut()
        .map(|recipient| recipient.as_mut_c_ptr())
        .collect::<Vec<*mut ffi::silentpayments::Recipient>>();

    let res = crate::with_global_context(
        |secp: &Secp256k1<crate::AllPreallocated>| unsafe {
            ffi::silentpayments::secp256k1_silentpayments_sender_create_outputs(
                secp.ctx().as_ptr(),
                ffi_generated_outputs_refs.as_mut_c_ptr(),
                ffi_recipients.as_c_ptr(),
                n_recipients,
                lexmin_outpoint.as_c_ptr(),
                ffi_taproot_seckeys,
                n_taproot_seckeys,
                ffi_plain_seckeys,
                n_plain_seckeys,
            )
        },
        Some(&seed),
    );

    if res == 1 {
        Ok(ffi_generated_outputs.into_iter().map(XOnlyPublicKey::from).collect())
    } else {
        Err(CreateOutputError::DerivationError)
    }
}
