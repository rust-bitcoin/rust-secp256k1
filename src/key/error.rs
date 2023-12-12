// SPDX-License-Identifier: CC0-1.0

//! Error types for the `key` module.

use core::fmt;

use crate::error::write_err;

/// X-only public key tweak is invalid.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum XOnlyTweakError {
    /// Invalid tweak.
    Tweak(TweakError),
    /// Invalid public key.
    PublicKey(PublicKeyError),
    /// Invalid parity value.
    ParityValue(ParityValueError),
}

impl fmt::Display for XOnlyTweakError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use XOnlyTweakError::*;

        // TODO: Check what gets out put in std and no-std builds an verify it useful and does not
        // contain redundant content.
        match *self {
            Tweak(ref e) => write_err!(f, "invalid tweak"; e),
            PublicKey(ref e) => write_err!(f, "invalid public key"; e),
            ParityValue(ref e) => write_err!(f, "invalid parity value"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for XOnlyTweakError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use XOnlyTweakError::*;

        match *self {
            Tweak(ref e) => Some(e),
            PublicKey(ref e) => Some(e),
            ParityValue(ref e) => Some(e),
        }
    }
}

impl From<TweakError> for XOnlyTweakError {
    fn from(e: TweakError) -> Self { Self::Tweak(e) }
}

impl From<PublicKeyError> for XOnlyTweakError {
    fn from(e: PublicKeyError) -> Self { Self::PublicKey(e) }
}

impl From<ParityValueError> for XOnlyTweakError {
    fn from(e: ParityValueError) -> Self { Self::ParityValue(e) }
}

/// Secret key is invalid.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[allow(missing_copy_implementations)] // Don't implement Copy when we use non_exhaustive.
pub struct SecretKeyError;

impl core::fmt::Display for SecretKeyError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        f.write_str("secret key is invalid")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SecretKeyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}

/// Public key is invalid.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[allow(missing_copy_implementations)] // Don't implement Copy when we use non_exhaustive.
pub struct PublicKeyError;

impl core::fmt::Display for PublicKeyError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        f.write_str("public key is invalid")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PublicKeyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}

/// Public key summation is invalid.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[allow(missing_copy_implementations)] // Don't implement Copy when we use non_exhaustive.
pub struct PublicKeySumError;

impl core::fmt::Display for PublicKeySumError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        f.write_str("public key summation is invalid")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PublicKeySumError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}

/// Invalid key tweak.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[allow(missing_copy_implementations)] // Don't implement Copy when we use non_exhaustive.
pub struct TweakError;

impl core::fmt::Display for TweakError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        f.write_str("invalid key tweak")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for TweakError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}

/// Invalid value for parity - must be 0 or 1.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[allow(missing_copy_implementations)] // Don't implement Copy when we use non_exhaustive.
pub struct ParityValueError(pub i32);

impl fmt::Display for ParityValueError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "invalid value {} for parity - must be 0 or 1", self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ParityValueError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}
