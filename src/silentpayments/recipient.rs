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
