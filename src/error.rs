// SPDX-License-Identifier: CC0-1.0

//! Error types and conversion functions.

use core::fmt;

use crate::context::NotEnoughMemoryError;
use crate::hex::{FromHexError, ToHexError};
use crate::key::error::{
    ParityValueError, PublicKeyError, PublicKeySumError, SecretKeyError, TweakError,
    XOnlyTweakError,
};
use crate::{ecdh, ecdsa, ellswift, scalar, schnorr, MessageLengthError};

/// Implements `From<E> for $error` for all the errors in this crate.
///
/// Either pass in the variant to use or have a variant `Secp256k1` on `$error`.
///
/// # Examples
///
/// ```
/// # #[cfg(feature =  "rand-std")] {
/// use secp256k1::{PublicKey, SecretKey, Secp256k1};
///
/// // Use the a general `secp256k1::Error`.
///
/// /// Foo error.
/// pub struct FooError;
///
/// // A custom error enum in your application.
/// pub enum Error {
///     Foo(FooError),
///     Secp256k1(secp256k1::Error),
/// }
/// secp256k1::impl_from_for_all_crate_errors_for!(Error);
///
/// impl From<FooError> for Error {
///     fn from(e: FooError) -> Self { Self::Foo(e) }
/// }
///
/// /// Some useful function.
/// pub fn foo() -> Result<(), FooError> {
///     // Do some stuff.
///     Err(FooError)
/// }
///
/// // Call any secp256k1 function and convert to a single general error variant.
/// fn bar() -> Result<(), Error> {
///     let secp = Secp256k1::new();
///     let key_data = [0_u8; 32]; // Dummy data.
///     let _ = SecretKey::from_slice(&key_data)?;
///     let _ = PublicKey::from_slice(&key_data)?;
///     let _ = foo()?;
///     Ok(())
/// }
/// # }
/// ```
// To find all errors in this crate use (note: -v 'git grep' to remove this comment):
//
//   git grep -e 'impl std::error' | grep -v 'git grep' | cut -d ' ' -f 4 | sort
//
#[macro_export]
macro_rules! impl_from_for_all_crate_errors_for {
    ($error:ty) => {
        $crate::impl_from_for_all_crate_errors_for!($error, Secp256k1);
    };
    ($error:ty, $variant:ident) => {
        impl From<$crate::Error> for $error {
            fn from(e: $crate::Error) -> Self { Self::$variant(e) }
        }

        #[cfg(feature = "recovery")]
        impl From<$crate::ecdsa::InvalidRecoveryIdError> for $error {
            fn from(e: $crate::ecdsa::InvalidRecoveryIdError) -> Self { Self::$variant(e.into()) }
        }

        impl From<$crate::MessageLengthError> for $error {
            fn from(e: $crate::MessageLengthError) -> Self { Self::$variant(e.into()) }
        }

        impl From<$crate::NotEnoughMemoryError> for $error {
            fn from(e: $crate::NotEnoughMemoryError) -> Self { Self::$variant(e.into()) }
        }

        impl From<$crate::scalar::OutOfRangeError> for $error {
            fn from(e: $crate::scalar::OutOfRangeError) -> Self { Self::$variant(e.into()) }
        }

        impl From<$crate::ParityValueError> for $error {
            fn from(e: $crate::ParityValueError) -> Self { Self::$variant(e.into()) }
        }

        impl From<$crate::PublicKeyError> for $error {
            fn from(e: $crate::PublicKeyError) -> Self { Self::$variant(e.into()) }
        }

        impl From<$crate::PublicKeySumError> for $error {
            fn from(e: $crate::PublicKeySumError) -> Self { Self::$variant(e.into()) }
        }

        impl From<$crate::SecretKeyError> for $error {
            fn from(e: $crate::SecretKeyError) -> Self { Self::$variant(e.into()) }
        }

        impl From<$crate::schnorr::SignatureError> for $error {
            fn from(e: $crate::schnorr::SignatureError) -> Self { Self::$variant(e.into()) }
        }

        impl From<$crate::ecdsa::SignatureError> for $error {
            fn from(e: $crate::ecdsa::SignatureError) -> Self { Self::$variant(e.into()) }
        }

        impl From<$crate::ecdsa::SignatureParseError> for $error {
            fn from(e: $crate::ecdsa::SignatureParseError) -> Self { Self::$variant(e.into()) }
        }

        impl From<$crate::SysError> for $error {
            fn from(e: $crate::SysError) -> Self { Self::$variant(e.into()) }
        }

        impl From<$crate::FromHexError> for $error {
            fn from(e: $crate::FromHexError) -> Self { Self::$variant(e.into()) }
        }

        impl From<$crate::ToHexError> for $error {
            fn from(e: $crate::ToHexError) -> Self { Self::$variant(e.into()) }
        }

        impl From<$crate::TweakError> for $error {
            fn from(e: $crate::TweakError) -> Self { Self::$variant(e.into()) }
        }

        impl From<$crate::XOnlyTweakError> for $error {
            fn from(e: $crate::XOnlyTweakError) -> Self { Self::$variant(e.into()) }
        }

        impl From<$crate::ellswift::ParseError> for $error {
            fn from(e: $crate::ellswift::ParseError) -> Self { Self::$variant(e.into()) }
        }
    };
}

/// This is a general purpose error type that can be used to wrap all the errors in this crate.
///
/// Every error types in this crate can be converted (using `?`) to this type. We also support
/// converting from any of the inner error types to this type, irrespective of the level of nesting.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(missing_copy_implementations)] // For forward compatibility (combined with non_exhaustive).
#[non_exhaustive]
pub enum Error {
    /// Error decoding from hex string.
    FromHex(FromHexError),
    /// Invalid recovery ID (ECDSA).
    #[cfg(feature = "recovery")]
    RecoveryId(ecdsa::InvalidRecoveryIdError),
    /// Messages must be 32 bytes long.
    MessageLength(MessageLengthError),
    /// Not enough preallocated memory for the requested buffer size.
    NotEnoughMemory(NotEnoughMemoryError),
    /// Value of scalar is invalid - larger than the curve order.
    InvalidScalar(scalar::OutOfRangeError),
    /// Invalid value for parity - must be 0 or 1.
    ParityValue(ParityValueError),
    /// Public key is invalid.
    PublicKey(PublicKeyError),
    /// Public key summation is invalid.
    PublicKeySum(PublicKeySumError),
    /// Secret key is invalid.
    SecretKey(SecretKeyError),
    /// Schnorr signature is invalid.
    SchnorrSignature(schnorr::SignatureError),
    /// ECDSA signature is invalid.
    EcdsaSignature(ecdsa::SignatureError),
    /// ECDSA signature string invalid.
    EcdsaSignatureParse(ecdsa::SignatureParseError),
    /// Error calling into the FFI layer.
    Sys(SysError),
    /// Error encoding as hex string.
    ToHex(ToHexError),
    /// Invalid key tweak.
    Tweak(TweakError),
    /// X-only pubic key tweak failed.
    XOnlyTweak(XOnlyTweakError),
    /// Error converting hex string to ellswift.
    Ellswift(ellswift::ParseError),
    /// Invalid slice length.
    InvalidSliceLength(InvalidSliceLengthError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use Error::*;

        // TODO: Check what gets out put in std and no-std builds an verify it is
        // useful and does not contain redundant content.
        match *self {
            FromHex(ref e) => write_err!(f, "from hex"; e),
            #[cfg(feature = "recovery")]
            RecoveryId(ref e) => write_err!(f, "invalid recovery ID (ECDSA)"; e),
            MessageLength(ref e) => write_err!(f, "invalid message length"; e),
            NotEnoughMemory(ref e) => write_err!(f, "not enough memory"; e),
            InvalidScalar(ref e) => write_err!(f, ""; e),
            ParityValue(ref e) => write_err!(f, "invalid parity"; e),
            PublicKey(ref e) => write_err!(f, "invalid public key"; e),
            PublicKeySum(ref e) => write_err!(f, "invalid public key sum"; e),
            SecretKey(ref e) => write_err!(f, "invalid secret key"; e),
            SchnorrSignature(ref e) => write_err!(f, "invalid schnorr sig"; e),
            EcdsaSignature(ref e) => write_err!(f, "invalid ECDSA sig"; e),
            EcdsaSignatureParse(ref e) => write_err!(f, "invalid ECDSA sig string"; e),
            Sys(ref e) => write_err!(f, "sys"; e),
            ToHex(ref e) => write_err!(f, "to hex"; e),
            Tweak(ref e) => write_err!(f, "invalid tweak"; e),
            XOnlyTweak(ref e) => write_err!(f, "x-only tweak error"; e),
            Ellswift(ref e) => write_err!(f, "ellswift error"; e),
            InvalidSliceLength(ref e) => write_err!(f, "invalid slice"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use Error::*;

        match *self {
            FromHex(ref e) => Some(e),
            #[cfg(feature = "recovery")]
            RecoveryId(ref e) => Some(e),
            MessageLength(ref e) => Some(e),
            NotEnoughMemory(ref e) => Some(e),
            InvalidScalar(ref e) => Some(e),
            ParityValue(ref e) => Some(e),
            PublicKey(ref e) => Some(e),
            PublicKeySum(ref e) => Some(e),
            SecretKey(ref e) => Some(e),
            SchnorrSignature(ref e) => Some(e),
            EcdsaSignature(ref e) => Some(e),
            EcdsaSignatureParse(ref e) => Some(e),
            Sys(ref e) => Some(e),
            ToHex(ref e) => Some(e),
            Tweak(ref e) => Some(e),
            XOnlyTweak(ref e) => Some(e),
            Ellswift(ref e) => Some(e),
            InvalidSliceLength(ref e) => Some(e),
        }
    }
}

impl From<FromHexError> for Error {
    fn from(e: FromHexError) -> Self { Self::FromHex(e) }
}

#[cfg(feature = "recovery")]
impl From<ecdsa::InvalidRecoveryIdError> for Error {
    fn from(e: ecdsa::InvalidRecoveryIdError) -> Self { Self::RecoveryId(e) }
}

impl From<MessageLengthError> for Error {
    fn from(e: MessageLengthError) -> Self { Self::MessageLength(e) }
}

impl From<NotEnoughMemoryError> for Error {
    fn from(e: NotEnoughMemoryError) -> Self { Self::NotEnoughMemory(e) }
}

impl From<scalar::OutOfRangeError> for Error {
    fn from(e: scalar::OutOfRangeError) -> Self { Self::InvalidScalar(e) }
}

impl From<ParityValueError> for Error {
    fn from(e: ParityValueError) -> Self { Self::ParityValue(e) }
}

impl From<PublicKeyError> for Error {
    fn from(e: PublicKeyError) -> Self { Self::PublicKey(e) }
}

impl From<PublicKeySumError> for Error {
    fn from(e: PublicKeySumError) -> Self { Self::PublicKeySum(e) }
}

impl From<SecretKeyError> for Error {
    fn from(e: SecretKeyError) -> Self { Self::SecretKey(e) }
}

impl From<schnorr::SignatureError> for Error {
    fn from(e: schnorr::SignatureError) -> Self { Self::SchnorrSignature(e) }
}

impl From<ecdsa::SignatureError> for Error {
    fn from(e: ecdsa::SignatureError) -> Self { Self::EcdsaSignature(e) }
}

impl From<ecdsa::SignatureParseError> for Error {
    fn from(e: ecdsa::SignatureParseError) -> Self { Self::EcdsaSignatureParse(e) }
}

impl From<SysError> for Error {
    fn from(e: SysError) -> Self { Self::Sys(e) }
}

impl From<ToHexError> for Error {
    fn from(e: ToHexError) -> Self { Self::ToHex(e) }
}

impl From<TweakError> for Error {
    fn from(e: TweakError) -> Self { Self::Tweak(e) }
}

impl From<XOnlyTweakError> for Error {
    fn from(e: XOnlyTweakError) -> Self { Self::XOnlyTweak(e) }
}

impl From<ellswift::ParseError> for Error {
    fn from(e: ellswift::ParseError) -> Self { Self::Ellswift(e) }
}

impl From<ecdh::InvalidSliceLengthError> for Error {
    fn from(e: ecdh::InvalidSliceLengthError) -> Self { Self::InvalidSliceLength(e) }
}

/// Error parsing a slice.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[allow(missing_copy_implementations)] // Don't implement Copy when we use non_exhaustive.
pub struct InvalidSliceLengthError {
    pub(crate) got: usize,
    pub(crate) expected: usize,
}

impl core::fmt::Display for InvalidSliceLengthError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        write!(f, "invalid slice length {}, expected {}", self.got, self.expected)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InvalidSliceLengthError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}

/// Error calling into the FFI layer.
// TODO: Do we want to include the error code returned for C function calls?
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[allow(missing_copy_implementations)] // Don't implement Copy when we use non_exhaustive.
pub struct SysError {}

impl core::fmt::Display for SysError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        f.write_str("FFI call failed")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SysError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}

/// Formats error. If `std` feature is OFF appends error source (delimited by `: `). We do this
/// because `e.source()` is only available in std builds, without this macro the error source is
/// lost for no-std builds.
macro_rules! write_err {
    ($writer:expr, $string:literal $(, $args:expr),*; $source:expr) => {
        {
            #[cfg(feature = "std")]
            {
                let _ = &$source;   // Prevents clippy warnings.
                write!($writer, $string $(, $args)*)
            }
            #[cfg(not(feature = "std"))]
            {
                write!($writer, concat!($string, ": {}") $(, $args)*, $source)
            }
        }
    }
}
pub(crate) use write_err;
