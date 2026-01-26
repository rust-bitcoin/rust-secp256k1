//! Provide all the binding functions and methods to be used from the perspective of the
//! silentpayments recipient.
use crate::ffi::types::c_void;
use crate::ffi::{self, CPtr};
use crate::{from_hex, PublicKey, Secp256k1, SecretKey, XOnlyPublicKey};

/// Failed to create labeled spend pubkey.
#[derive(Debug, Clone, Copy, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub struct LabeledSpendPubkeyCreationError;

#[cfg(feature = "std")]
impl std::error::Error for LabeledSpendPubkeyCreationError {}

impl core::fmt::Display for LabeledSpendPubkeyCreationError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        write!(f, "Failed to create labeled spend pubkey")
    }
}

/// Create Silent Payment labeled spend public key.
///
/// Given a recipient's spend public key and a label, calculate the
/// corresponding labeled spend public key:
///
/// ```text
///     labeled_spend_pubkey = unlabeled_spend_pubkey + label
/// ```
///
/// The result is used by the recipient to create a Silent Payment address,
/// consisting of the serialized and concatenated scan public key and
/// (labeled) spend public key.
///
/// # Arguments:
/// * `unlabeled_spend_pubkey` - the recipient's unlabeled spend public key to label.
/// * `label` - the recipient's label public key.
///
/// # Returns
/// The resulting labeled [`PublicKey`].
///
/// # Errors
/// * [`LabeledSpendPubkeyCreationError`] - if spend pubkey and label sum to zero (negligible probability for labels created according to BIP352).
pub fn create_labeled_spend_pubkey(
    unlabeled_spend_pubkey: &PublicKey,
    label: &Label,
) -> Result<PublicKey, LabeledSpendPubkeyCreationError> {
    unsafe {
        let mut pubkey = ffi::PublicKey::new();

        let res = crate::with_global_context(
            |secp: &Secp256k1<crate::AllPreallocated>| {
                ffi::silentpayments::secp256k1_silentpayments_recipient_create_labeled_spend_pubkey(
                    secp.ctx().as_ptr(),
                    &mut pubkey,
                    unlabeled_spend_pubkey.as_c_ptr(),
                    label.as_c_ptr(),
                )
            },
            None,
        );

        if res == 1 {
            let pubkey = PublicKey::from(pubkey);
            Ok(pubkey)
        } else {
            Err(LabeledSpendPubkeyCreationError)
        }
    }
}

/// Struct to store silent payments label data.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Label(ffi::silentpayments::Label);

impl CPtr for Label {
    type Target = ffi::silentpayments::Label;

    /// Obtains a const pointer suitable for use with FFI functions.
    fn as_c_ptr(&self) -> *const Self::Target { &self.0 }

    /// Obtains a mutable pointer suitable for use with FFI functions.
    fn as_mut_c_ptr(&mut self) -> *mut Self::Target { &mut self.0 }
}

impl core::fmt::LowerHex for Label {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        for b in self.serialize() {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

impl core::fmt::Display for Label {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        core::fmt::LowerHex::fmt(self, f)
    }
}

impl core::str::FromStr for Label {
    type Err = LabelError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut res = [0u8; 33];
        match from_hex(s, &mut res) {
            Ok(33) => Label::parse(&res),
            _ => Err(LabelError::ParseFailure),
        }
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Label {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.collect_str(self)
        } else {
            s.serialize_bytes(&self.serialize()[..])
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Label {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        if d.is_human_readable() {
            use crate::serde_util::FromStrVisitor;

            d.deserialize_str(FromStrVisitor::new(
                "a hex string representing a Silent Payment Label",
            ))
        } else {
            use crate::serde_util::BytesVisitor;

            d.deserialize_bytes(BytesVisitor::new("a raw Silent Payment Label", |slice| {
                let bytes: &[u8; 33] = slice.try_into().map_err(|_| LabelError::ParseFailure)?;

                Self::parse(bytes)
            }))
        }
    }
}

/// Label errors.
#[derive(Debug, Clone, Copy, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub enum LabelError {
    /// Failed to create the label and label tweak.
    CreationFailure,
    /// Failed to parse the serialized label.
    ParseFailure,
}

#[cfg(feature = "std")]
impl std::error::Error for LabelError {}

impl core::fmt::Display for LabelError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        match self {
            LabelError::CreationFailure => {
                write!(f, "Failed to create the label and label tweak")
            }
            LabelError::ParseFailure => {
                write!(f, "Failed to parse the serialized label")
            }
        }
    }
}

impl Label {
    /// Create Silent Payment label tweak and label.
    ///
    /// Given a recipient's scan [`SecretKey`] and a label integer m, calculate the
    /// corresponding label tweak and label:
    ///
    /// ```text
    ///     label_tweak = hash(scan_key || m)
    ///           label = label_tweak * G
    /// ```
    ///
    /// # Arguments
    /// * `scan_seckey` - the recipient's scan [`SecretKey`].
    /// * `m` - a label integer for the m-th label (0 is used for change outputs).
    ///
    /// # Returns
    /// A tuple ([`PublicKey`], [u8; 32]) where the first element is the label public key and the
    /// second is the label tweak.
    ///
    /// # Errors
    /// * [`LabelError`] - if label tweak is not a valid scalar (negligible probability per hash evaluation).
    pub fn create(scan_seckey: &SecretKey, m: u32) -> Result<(Self, [u8; 32]), LabelError> {
        unsafe {
            let mut label = core::mem::MaybeUninit::<ffi::silentpayments::Label>::uninit();
            let mut label_tweak32 = [0u8; 32];

            let res = crate::with_global_context(
                |secp: &Secp256k1<crate::AllPreallocated>| {
                    ffi::silentpayments::secp256k1_silentpayments_recipient_label_create(
                        secp.ctx().as_ptr(),
                        label.as_mut_ptr(),
                        label_tweak32.as_mut_c_ptr(),
                        scan_seckey.as_c_ptr(),
                        m,
                    )
                },
                None,
            );

            if res == 1 {
                let label = Self(label.assume_init());
                Ok((label, label_tweak32))
            } else {
                Err(LabelError::CreationFailure)
            }
        }
    }

    /// Parse a Silent Payments label.
    ///
    /// # Arguments:
    /// * `in33` - the 33-byte slice of the label to be parsed
    ///
    /// # Returns
    /// The resulting [`Label`].
    ///
    /// # Errors
    /// * [`LabelError::ParseFailure`] - if the label could not be parsed.
    pub fn parse(in33: &[u8; 33]) -> Result<Self, LabelError> {
        let mut ffi_label = core::mem::MaybeUninit::<ffi::silentpayments::Label>::uninit();

        let res = unsafe {
            crate::with_global_context(
                |secp: &Secp256k1<crate::AllPreallocated>| {
                    ffi::silentpayments::secp256k1_silentpayments_recipient_label_parse(
                        secp.ctx().as_ptr(),
                        ffi_label.as_mut_ptr(),
                        in33.as_c_ptr(),
                    )
                },
                None,
            )
        };

        if res == 1 {
            Ok(unsafe { Label(ffi_label.assume_init()) })
        } else {
            Err(LabelError::ParseFailure)
        }
    }

    /// Serialize a Silent Payments label.
    ///
    /// This method is infallible.
    ///
    /// # Returns
    /// A 33-byte array with the serialized label.
    pub fn serialize(&self) -> [u8; 33] {
        let mut output = [0u8; 33];

        let _res = unsafe {
            crate::with_global_context(
                |secp: &Secp256k1<crate::AllPreallocated>| {
                    ffi::silentpayments::secp256k1_silentpayments_recipient_label_serialize(
                        secp.ctx().as_ptr(),
                        output.as_mut_c_ptr(),
                        self.as_c_ptr(),
                    )
                },
                None,
            )
        };

        output
    }
}

/// Struct to store silent payments prevouts summary data.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PrevoutsSummary(ffi::silentpayments::PrevoutsSummary);

impl PrevoutsSummary {
    /// Transform a byte array into a PrevoutsSummary.
    pub fn from_byte_array(arr: [u8; ffi::silentpayments::PREVOUTS_SUMMARY_SIZE]) -> Self {
        let ffi_prevouts_sumary = ffi::silentpayments::PrevoutsSummary::from_byte_array(arr);
        Self(ffi_prevouts_sumary)
    }

    /// Transform a PrevoutsSummary back into a byte array.
    pub fn to_byte_array(self) -> [u8; ffi::silentpayments::PREVOUTS_SUMMARY_SIZE] {
        self.0.to_byte_array()
    }
}

impl CPtr for PrevoutsSummary {
    type Target = ffi::silentpayments::PrevoutsSummary;

    /// Obtains a const pointer suitable for use with FFI functions.
    fn as_c_ptr(&self) -> *const Self::Target { &self.0 }

    /// Obtains a mutable pointer suitable for use with FFI functions.
    fn as_mut_c_ptr(&mut self) -> *mut Self::Target { &mut self.0 }
}

impl core::fmt::LowerHex for PrevoutsSummary {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        for b in self.0.to_byte_array() {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

impl core::fmt::Display for PrevoutsSummary {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        core::fmt::LowerHex::fmt(self, f)
    }
}

impl core::str::FromStr for PrevoutsSummary {
    type Err = PrevoutsSummaryError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut res = [0u8; ffi::silentpayments::PREVOUTS_SUMMARY_SIZE];
        match from_hex(s, &mut res) {
            Ok(ffi::silentpayments::PREVOUTS_SUMMARY_SIZE) =>
                Ok(PrevoutsSummary::from_byte_array(res)),
            _ => Err(PrevoutsSummaryError::ParseFailure),
        }
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for PrevoutsSummary {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.collect_str(self)
        } else {
            s.serialize_bytes(&self.to_byte_array())
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for PrevoutsSummary {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        if d.is_human_readable() {
            use crate::serde_util::FromStrVisitor;

            d.deserialize_str(FromStrVisitor::new(
                "a hex string representing a Silent Payment PrevoutsSummary",
            ))
        } else {
            use crate::serde_util::BytesVisitor;

            d.deserialize_bytes(BytesVisitor::new(
                "a raw Silent Payment PrevoutsSummary",
                |slice| {
                    let bytes: [u8; ffi::silentpayments::PREVOUTS_SUMMARY_SIZE] =
                        slice.try_into().map_err(|_| PrevoutsSummaryError::ParseFailure)?;

                    Ok::<PrevoutsSummary, PrevoutsSummaryError>(Self::from_byte_array(bytes))
                },
            ))
        }
    }
}

/// PrevoutsSummary errors.
#[derive(Debug, Clone, Copy, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum PrevoutsSummaryError {
    /// Failed to create the prevouts summary.
    CreationFailure,
    /// Failed to parse the prevouts summary.
    ParseFailure,
}

#[cfg(feature = "std")]
impl std::error::Error for PrevoutsSummaryError {}

impl core::fmt::Display for PrevoutsSummaryError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        match self {
            PrevoutsSummaryError::CreationFailure => {
                write!(f, "Failed to create the prevouts summary")
            }
            PrevoutsSummaryError::ParseFailure => {
                write!(f, "Failed to read the prevouts summary")
            }
        }
    }
}

impl PrevoutsSummary {
    /// Create [`PrevoutsSummary`] from prevout public keys and transaction inputs.
    ///
    /// Given a list of n public keys A_1...A_n (one for each silent payment eligible input to
    /// spend) and a serialized `lexmin_outpoint`, create a `prevouts_summary` object. This object
    /// summarizes the prevout data from the transaction inputs needed for scanning.
    ///
    /// `lexmin_outpoint` refers to the smallest outpoint lexicographically
    /// from the transaction inputs (both silent payments eligible and non-eligible
    /// inputs). This value MUST be the smallest outpoint out of ALL of the
    /// transaction inputs, otherwise the recipient will be unable to find the
    /// payment.
    ///
    /// The public keys have to be passed in via two different parameter pairs, one
    /// for regular and one for x-only public keys, in order to avoid the need of
    /// users converting to a common public key format before calling this function.
    /// The resulting data can be used for scanning on the recipient side, or
    /// stored in an index for later use (e.g., wallet rescanning, sending data to
    /// light clients).
    ///
    /// # Arguments
    /// * `lexmin_outpoint` - serialized smallest outpoint (lexicographically)
    ///   from the transaction inputs.
    /// * `xonly_pubkeys` - pointer to an array of pointers to taproot x-only
    ///   public keys (can be [`Option::None`] if no taproot inputs are used).
    /// * `plain_pubkeys` - pointer to an array of pointers to non-taproot
    ///   public keys (can be [`Option::None`] if no non-taproot inputs are used).
    ///
    /// # Returns
    /// A [`PrevoutsSummary`] struct, containing the summed public keys and the input hash.
    ///
    /// # Errors
    /// * [`PrevoutsSummaryError::CreationFailure] - the prevout summary could not be created
    ///   because arguments are invalid or transaction is not a silent payment transaction (no inputs
    ///   for shared secret derivation).
    pub fn create(
        lexmin_outpoint: &[u8; 36],
        xonly_pubkeys: Option<&[&XOnlyPublicKey]>,
        plain_pubkeys: Option<&[&PublicKey]>,
    ) -> Result<Self, PrevoutsSummaryError> {
        let mut prevouts_summary =
            core::mem::MaybeUninit::<ffi::silentpayments::PrevoutsSummary>::uninit();

        let (ffi_xonly_pubkeys, n_xonly_pubkeys) = match xonly_pubkeys {
            Some(keys) => (keys.as_c_ptr() as *mut *const ffi::XOnlyPublicKey, keys.len()),
            None => (
                core::ptr::null::<*mut *const ffi::XOnlyPublicKey>()
                    as *mut *const ffi::XOnlyPublicKey,
                0_usize,
            ),
        };

        let (ffi_plain_pubkeys, n_plain_pubkeys) = match plain_pubkeys {
            Some(keys) => (keys.as_c_ptr() as *mut *const ffi::PublicKey, keys.len()),
            None => (
                core::ptr::null::<*mut *const ffi::PublicKey>() as *mut *const ffi::PublicKey,
                0_usize,
            ),
        };

        let res = crate::with_global_context(
            |secp: &Secp256k1<crate::AllPreallocated>| unsafe {
                ffi::silentpayments::secp256k1_silentpayments_recipient_prevouts_summary_create(
                    secp.ctx().as_ptr(),
                    prevouts_summary.as_mut_ptr(),
                    lexmin_outpoint.as_c_ptr(),
                    ffi_xonly_pubkeys,
                    n_xonly_pubkeys,
                    ffi_plain_pubkeys,
                    n_plain_pubkeys,
                )
            },
            None,
        );

        if res == 1 {
            Ok(unsafe { PrevoutsSummary(prevouts_summary.assume_init()) })
        } else {
            Err(PrevoutsSummaryError::CreationFailure)
        }
    }
}

/// Struct for holding a found output along with data needed to spend it later.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FoundOutput(ffi::silentpayments::FoundOutput);

impl CPtr for FoundOutput {
    type Target = ffi::silentpayments::FoundOutput;

    /// Obtains a const pointer suitable for use with FFI functions.
    fn as_c_ptr(&self) -> *const Self::Target { &self.0 }

    /// Obtains a mutable pointer suitable for use with FFI functions.
    fn as_mut_c_ptr(&mut self) -> *mut Self::Target { &mut self.0 }
}

impl FoundOutput {
    /// The 32-byte tweak needed to spend the output.
    pub fn tweak(self) -> [u8; 32] { self.0.tweak }

    /// The x-only public key for the taproot output.
    pub fn output(self) -> XOnlyPublicKey { self.0.output.into() }

    /// If this outputs was sent to a labeled address, returns the label used encoded as a group
    /// element [`Option::None`] otherwise.
    pub fn label(self) -> Option<Label> {
        if self.0.found_with_label != 0 {
            Some(Label(self.0.label))
        } else {
            None
        }
    }
}

impl core::fmt::Display for FoundOutput {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "{}", self.output())
    }
}

/// Error while scanning silent payment outputs
#[derive(Debug, Clone, Copy, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub struct ScanningError;

#[cfg(feature = "std")]
impl std::error::Error for ScanningError {}

impl core::fmt::Display for ScanningError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        write!(f, "Failed while scanning silent payment outputs")
    }
}

/// Scan for Silent Payment transaction outputs.
///
/// Given a [`PrevoutsSummary`] object, a recipient's scan [`SecretKey`] and unlabeled spend
/// [`PublicKey`], and the relevant transaction outputs, scan for outputs belonging to the
/// recipient and return the tweak(s) needed for spending the output(s). An optional
/// [`ffi::silentpayments::LabelLookup`] callback function and `label_context` can be passed if the recipient uses labels.
/// This allows for checking if a label exists in the recipients label cache and retrieving the
/// label tweak during scanning.
///
/// If used, the `label_lookup` function must return a pointer to a 32-byte label
/// tweak if the label is found, or NULL otherwise. The returned pointer must remain
/// valid until the next call to `label_lookup` or until the function returns,
/// whichever comes first. It is not retained beyond that.
///
/// For creating the labels cache, [`Label::create`] can be used.
///
/// # Arguments
/// * `tx_outputs` -  a slice of references to the transactions x-only public keys.
/// * `scan_seckey` - the recipient's [`SecretKey`].
/// * `prevouts_summary` - a reference to the transaction [`PrevoutsSummary`].
/// * `unlabeled_spend_pubkey` - a reference to the recipient's unlabeled spend [`PublicKey`].
/// * `label_lookup` - a closure that wraps the label cache. This function takes a label public key
///   as an argument and returns the label tweak if it exists. Should be [`Option::None`] if labels
///   are not used.
///
/// # Returns
/// A vector of [`FoundOutput`]s.
///
/// # Errors
/// * [`ScanningError`] - if the transaction is not a valid silent payment transaction
///   or the arguments are invalid.
pub fn scan_outputs<F>(
    tx_outputs: &[&XOnlyPublicKey],
    scan_seckey: &SecretKey,
    prevouts_summary: &PrevoutsSummary,
    unlabeled_spend_pubkey: &PublicKey,
    label_lookup: Option<F>,
) -> Result<Vec<FoundOutput>, ScanningError>
where
    F: for<'a> FnMut(&'a [u8; 33]) -> Option<[u8; 32]>,
{
    type Context<F> = (F, [u8; 32]);

    // # Safety
    //
    // This callback prevents panics from crossing FFI boundaries by catching any panics from the
    // user-provided function and aborting the process. This is required for safety on Rust < 1.81
    // and maintains consistent behavior across all Rust versions.
    unsafe extern "C" fn safe_callback<F>(
        label33: *const u8,
        label_context: *const c_void,
    ) -> *const u8
    where
        F: for<'a> FnMut(&'a [u8; 33]) -> Option<[u8; 32]>,
    {
        let label33 = unsafe { &*label33.cast::<[u8; 33]>() };
        let (f, storage) = unsafe { &mut *(label_context as *mut c_void).cast::<Context<F>>() };
        match std::panic::catch_unwind(core::panic::AssertUnwindSafe(|| f(label33))) {
            Ok(Some(tweak)) => {
                // Cannot return a pointer to `tweak` as that lives in this function's
                // (the callback) stack frame
                // on the other hand, `storage` remains valid for the duration of
                // secp256k1_silentpayments_recipient_scan_outputs.
                *storage = tweak;
                storage.as_ptr()
            }
            Ok(None) => core::ptr::null(),
            Err(_) => std::process::abort(), // mimics Rust 1.81+ behavior
        }
    }

    let mut context: Context<F>;
    let (label_lookup, label_context): (ffi::silentpayments::LabelLookup, _) =
        if let Some(label_lookup) = label_lookup {
            context = (label_lookup, [0u8; 32]);
            (Some(safe_callback::<F>), &mut context as *mut Context<F> as *const c_void)
        } else {
            (None, core::ptr::null())
        };

    let ffi_tx_output_refs: Vec<*const ffi::XOnlyPublicKey> =
        tx_outputs.iter().map(|pubkey| pubkey.as_c_ptr()).collect();

    let mut ffi_found_outputs =
        vec![FoundOutput(ffi::silentpayments::FoundOutput::default()); tx_outputs.len()];
    let mut ffi_found_outputs_refs: Vec<_> =
        ffi_found_outputs.iter_mut().map(|k| k.as_mut_c_ptr()).collect();
    let mut n_found_outputs: u32 = 0;

    let n_tx_outputs = match core::convert::TryInto::<u32>::try_into(tx_outputs.len()) {
        Ok(n_tx_outputs) => n_tx_outputs,
        Err(_) => return Err(ScanningError),
    };

    let res = crate::with_global_context(
        |secp: &Secp256k1<crate::AllPreallocated>| unsafe {
            ffi::silentpayments::secp256k1_silentpayments_recipient_scan_outputs(
                secp.ctx().as_ptr(),
                ffi_found_outputs_refs.as_mut_c_ptr(),
                &mut n_found_outputs,
                ffi_tx_output_refs.as_c_ptr(),
                n_tx_outputs,
                scan_seckey.to_secret_bytes().as_c_ptr(),
                prevouts_summary.as_c_ptr(),
                unlabeled_spend_pubkey.as_c_ptr(),
                label_lookup,
                label_context,
            )
        },
        None,
    );

    if res == 1 {
        let n_found_outputs_usize = core::convert::TryInto::<usize>::try_into(n_found_outputs)
            .expect("usize is at least 4 bytes wide");
        let found_outputs: Vec<FoundOutput> =
            ffi_found_outputs.iter().take(n_found_outputs_usize).copied().collect();

        Ok(found_outputs)
    } else {
        Err(ScanningError)
    }
}
