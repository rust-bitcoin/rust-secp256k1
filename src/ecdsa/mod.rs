//! Structs and functionality related to the ECDSA signature algorithm.

use core::{fmt, str};

use crate::{Signing, Verification, Message, PublicKey, Secp256k1, SecretKey, from_hex, Error};
use crate::ffi::CPtr;
use crate::ffi::ecdsa as ffi;

pub mod serialized_signature;

#[cfg(feature = "recovery")]
mod recovery;

#[cfg(feature = "recovery")]
#[cfg_attr(docsrs, doc(cfg(feature = "recovery")))]
pub use self::recovery::{RecoveryId, RecoverableSignature};

pub use serialized_signature::SerializedSignature;

#[cfg(feature = "global-context")]
use crate::SECP256K1;

/// An ECDSA signature
#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct Signature(ffi::Signature);

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let sig = self.serialize_der();
        sig.fmt(f)
    }
}

impl str::FromStr for Signature {
    type Err = Error;
    fn from_str(s: &str) -> Result<Signature, Error> {
        let mut res = [0u8; 72];
        match from_hex(s, &mut res) {
            Ok(x) => Signature::from_der(&res[0..x]),
            _ => Err(Error::InvalidSignature),
        }
    }
}

impl Signature {
    #[inline]
    /// Converts a DER-encoded byte slice to a signature
    pub fn from_der(data: &[u8]) -> Result<Signature, Error> {
        if data.is_empty() {return Err(Error::InvalidSignature);}

        ffi::Signature::from_der(data)
            .map(Signature)
            .ok_or(Error::InvalidSignature)
    }

    /// Converts a 64-byte compact-encoded byte slice to a signature
    pub fn from_compact(data: &[u8]) -> Result<Signature, Error> {
        if data.len() != 64 {
            return Err(Error::InvalidSignature)
        }

        ffi::Signature::from_compact(data)
            .map(Signature)
            .ok_or(Error::InvalidSignature)
    }

    /// Converts a "lax DER"-encoded byte slice to a signature. This is basically
    /// only useful for validating signatures in the Bitcoin blockchain from before
    /// 2016. It should never be used in new applications. This library does not
    /// support serializing to this "format"
    pub fn from_der_lax(data: &[u8]) -> Result<Signature, Error> {
        if data.is_empty() {return Err(Error::InvalidSignature);}

        ffi::Signature::from_der_lax(data)
            .map(Signature)
            .ok_or(Error::InvalidSignature)
    }

    /// Normalizes a signature to a "low S" form. In ECDSA, signatures are
    /// of the form (r, s) where r and s are numbers lying in some finite
    /// field. The verification equation will pass for (r, s) iff it passes
    /// for (r, -s), so it is possible to ``modify'' signatures in transit
    /// by flipping the sign of s. This does not constitute a forgery since
    /// the signed message still cannot be changed, but for some applications,
    /// changing even the signature itself can be a problem. Such applications
    /// require a "strong signature". It is believed that ECDSA is a strong
    /// signature except for this ambiguity in the sign of s, so to accommodate
    /// these applications libsecp256k1 will only accept signatures for which
    /// s is in the lower half of the field range. This eliminates the
    /// ambiguity.
    ///
    /// However, for some systems, signatures with high s-values are considered
    /// valid. (For example, parsing the historic Bitcoin blockchain requires
    /// this.) For these applications we provide this normalization function,
    /// which ensures that the s value lies in the lower half of its range.
    pub fn normalize_s(&mut self) {
        self.0.normalize_s()
    }

    #[inline]
    /// Serializes the signature in DER format.
    pub fn serialize_der(&self) -> SerializedSignature {
        self.0.serialize_der()
            .map(|(buf, len)| SerializedSignature::from_raw_parts(buf, len))
            .expect("FIXME: Can this fail?")
    }

    #[inline]
    /// Serializes the signature in compact format
    pub fn serialize_compact(&self) -> [u8; 64] {
        self.0.serialize_compact()
            .expect("FIXME: Can this fail?")
    }

    /// Verifies an ECDSA signature for `msg` using `pk` and the global [`SECP256K1`] context.
    #[inline]
    #[cfg(feature = "global-context")]
    #[cfg_attr(docsrs, doc(cfg(feature = "global-context")))]
    pub fn verify(&self, msg: &Message, pk: &PublicKey) -> Result<(), Error> {
        SECP256K1.verify_ecdsa(msg, self, pk)
    }
}

impl CPtr for Signature {
    type Target = ffi::Signature;

    fn as_c_ptr(&self) -> *const Self::Target {
        &self.0
    }

    fn as_mut_c_ptr(&mut self) -> *mut Self::Target {
        &mut self.0
    }
}

/// Creates a new signature from a FFI signature
impl From<ffi::Signature> for Signature {
    #[inline]
    fn from(sig: ffi::Signature) -> Signature {
        Signature(sig)
    }
}

#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
impl serde::Serialize for Signature {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.collect_str(self)
        } else {
            s.serialize_bytes(&self.serialize_der())
        }
    }
}

#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
impl<'de> serde::Deserialize<'de> for Signature {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        if d.is_human_readable() {
            d.deserialize_str(crate::serde_util::FromStrVisitor::new(
                "a hex string representing a DER encoded Signature"
            ))
        } else {
            d.deserialize_bytes(crate::serde_util::BytesVisitor::new(
                "raw byte stream, that represents a DER encoded Signature",
                Signature::from_der
            ))
        }
    }
}

impl<C: Signing> Secp256k1<C> {
    /// Constructs a signature for `msg` using the secret key `sk` and RFC6979 nonce
    /// Requires a signing-capable context.
    pub fn sign_ecdsa(&self, msg: &Message, sk: &SecretKey) -> Signature {
        ffi::sign(&self.ctx, msg.to_bytes(), &sk.into(), None)
            .map(Signature::from)
            // FIXME: This is allegedly true but it means we are at the mercy of libsecp256k1,
            // should we return an error instead?
            .expect("infallible since msg an sk are valid")
    }

    /// Constructs a signature for `msg` using the secret key `sk` and RFC6979 nonce
    /// and includes 32 bytes of noncedata in the nonce generation via inclusion in
    /// one of the hash operations during nonce generation. This is useful when multiple
    /// signatures are needed for the same Message and SecretKey while still using RFC6979.
    /// Requires a signing-capable context.
    pub fn sign_ecdsa_with_noncedata(
        &self,
        msg: &Message,
        sk: &SecretKey,
        noncedata: &[u8; 32],
    ) -> Signature {
        ffi::sign(&self.ctx, msg.to_bytes(), &sk.into(), Some(noncedata))
            .map(Signature::from)
            // FIXME: Same as above.
            .expect("infallible since msg an sk are valid")
    }

    /// Constructs a signature for `msg` using the secret key `sk`, RFC6979 nonce
    /// and "grinds" the nonce by passing extra entropy if necessary to produce
    /// a signature that is less than 71 - `bytes_to_grind` bytes. The number
    /// of signing operation performed by this function is exponential in the
    /// number of bytes grinded.
    /// Requires a signing capable context.
    pub fn sign_ecdsa_grind_r(&self, msg: &Message, sk: &SecretKey, bytes_to_grind: usize) -> Signature {
        let len_check = |s : &Signature| der_length_check(s, 71 - bytes_to_grind);
        self.sign_grind_with_check(msg, sk, len_check)
    }

    /// Constructs a signature for `msg` using the secret key `sk`, RFC6979 nonce
    /// and "grinds" the nonce by passing extra entropy if necessary to produce
    /// a signature that is less than 71 bytes and compatible with the low r
    /// signature implementation of bitcoin core. In average, this function
    /// will perform two signing operations.
    /// Requires a signing capable context.
    pub fn sign_ecdsa_low_r(&self, msg: &Message, sk: &SecretKey) -> Signature {
        self.sign_grind_with_check(msg, sk, compact_sig_has_zero_first_bit)
    }

    fn sign_grind_with_check<F>(&self, msg: &Message, sk: &SecretKey, check: F) -> Signature
    where
        F: Fn(&Signature) -> bool
    {
        let mut counter : u32 = 0;
        let mut extra_entropy = [0u8; 32];

        loop {
            let sig = self.sign_ecdsa_with_noncedata(msg, sk, &extra_entropy);

            // When fuzzing, these checks will usually spinloop forever, so just short-circuit them.
            if cfg!(fuzzing) {
                return Signature::from(sig);
            }

            if check(&sig) {
                return Signature::from(sig);
            }

            counter += 1;
            // FIXME: Shouldn't this be `to_ne_bytes`? More efficient no obvious down side.
            extra_entropy[..4].copy_from_slice(&counter.to_le_bytes());
        }
    }
}

impl<C: Verification> Secp256k1<C> {
    /// Checks that `sig` is a valid ECDSA signature for `msg` using the public
    /// key `pubkey`. Returns `Ok(())` on success. Note that this function cannot
    /// be used for Bitcoin consensus checking since there may exist signatures
    /// which OpenSSL would verify but not libsecp256k1, or vice-versa. Requires a
    /// verify-capable context.
    ///
    /// ```rust
    /// # #[cfg(all(feature = "std", feature = "rand-std"))] {
    /// # use secp256k1::rand::thread_rng;
    /// # use secp256k1::{Secp256k1, Message, Error};
    /// #
    /// # let secp = Secp256k1::new();
    /// # let (secret_key, public_key) = secp.generate_keypair(&mut thread_rng());
    /// #
    /// let message = Message::from_slice(&[0xab; 32]).expect("32 bytes");
    /// let sig = secp.sign_ecdsa(&message, &secret_key);
    /// assert_eq!(secp.verify_ecdsa(&message, &sig, &public_key), Ok(()));
    ///
    /// let message = Message::from_slice(&[0xcd; 32]).expect("32 bytes");
    /// assert_eq!(secp.verify_ecdsa(&message, &sig, &public_key), Err(Error::IncorrectSignature));
    /// # }
    /// ```
    #[inline]
    pub fn verify_ecdsa(&self, msg: &Message, sig: &Signature, pk: &PublicKey) -> Result<(), Error> {
        if sig.0.is_valid(&self.ctx, msg.to_bytes(), &pk.into()) {
            Ok(())
        } else {
            Err(Error::IncorrectSignature)
        }
    }
}

pub(crate) fn compact_sig_has_zero_first_bit(sig: &Signature) -> bool {
    match sig.0.serialize_compact() {
        Some(bytes) => bytes[0] < 0x80,
        None => false,
    }
}

pub(crate) fn der_length_check(sig: &Signature, max_len: usize) -> bool {
    match sig.0.serialize_der() {
        Some((_bytes, len)) => len <= max_len,
        // FIXME: What to do if serialization fails?
        None => panic!("serialization failed"),
    }
}
