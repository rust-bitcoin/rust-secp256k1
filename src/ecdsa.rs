// Bitcoin secp256k1 bindings
// Written in 2015 by
//   Andrew Poelstra
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! ECDSA signature implementation

use core::str::FromStr;
use core::ops::Deref;
use core::{mem, fmt, ptr};
#[cfg(any(test, feature = "rand"))] use rand::Rng;

use ffi::{self, CPtr};
use ::{Secp256k1, from_hex, Message, Error, key, serde_util};
use ::{Verification, Signing};

/// An ECDSA signature
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct Signature(pub(crate) ffi::Signature);

/// A DER serialized Signature
#[derive(Copy, Clone)]
pub struct SerializedSignature {
    data: [u8; 72],
    len: usize,
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let sig = self.serialize_der();
        for v in sig.iter() {
            write!(f, "{:02x}", v)?;
        }
        Ok(())
    }
}

impl FromStr for Signature {
    type Err = Error;
    fn from_str(s: &str) -> Result<Signature, Error> {
        let mut res = [0; 72];
        match from_hex(s, &mut res) {
            Ok(x) => Signature::from_der(&res[0..x]),
            _ => Err(Error::InvalidSignature),
        }
    }
}

impl SerializedSignature {
    /// Get a pointer to the underlying data with the specified capacity.
    pub(crate) fn get_data_mut_ptr(&mut self) -> *mut u8 {
        self.data.as_mut_ptr()
    }

    /// Get the capacity of the underlying data buffer.
    pub fn capacity(&self) -> usize {
        self.data.len()
    }

    /// Get the len of the used data.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Set the length of the object.
    pub(crate) fn set_len(&mut self, len: usize) {
        self.len = len;
    }

    /// Convert the serialized signature into the Signature struct.
    /// (This DER deserializes it)
    pub fn to_signature(&self) -> Result<Signature, Error> {
        Signature::from_der(&self)
    }

    /// Create a SerializedSignature from a Signature.
    /// (this DER serializes it)
    pub fn from_signature(sig: &Signature) -> SerializedSignature {
        sig.serialize_der()
    }

    /// Check if the space is zero.
    pub fn is_empty(&self) -> bool { self.len() == 0 }
}

impl Signature {
    #[inline]
    /// Converts a DER-encoded byte slice to a signature
    pub fn from_der(data: &[u8]) -> Result<Signature, Error> {
        if data.is_empty() {return Err(Error::InvalidSignature);}

        unsafe {
            let mut ret = ffi::Signature::new();
            if ffi::secp256k1_ecdsa_signature_parse_der(
                ffi::secp256k1_context_no_precomp,
                &mut ret,
                data.as_c_ptr(),
                data.len() as usize,
            ) == 1
            {
                Ok(Signature(ret))
            } else {
                Err(Error::InvalidSignature)
            }
        }
    }

    /// Converts a 64-byte compact-encoded byte slice to a signature
    pub fn from_compact(data: &[u8]) -> Result<Signature, Error> {
        if data.len() != 64 {
            return Err(Error::InvalidSignature)
        }

        unsafe {
            let mut ret = ffi::Signature::new();
            if ffi::secp256k1_ecdsa_signature_parse_compact(
                ffi::secp256k1_context_no_precomp,
                &mut ret,
                data.as_c_ptr(),
            ) == 1
            {
                Ok(Signature(ret))
            } else {
                Err(Error::InvalidSignature)
            }
        }
    }

    /// Converts a "lax DER"-encoded byte slice to a signature. This is basically
    /// only useful for validating signatures in the Bitcoin blockchain from before
    /// 2016. It should never be used in new applications. This library does not
    /// support serializing to this "format"
    pub fn from_der_lax(data: &[u8]) -> Result<Signature, Error> {
        if data.is_empty() {return Err(Error::InvalidSignature);}

        unsafe {
            let mut ret = ffi::Signature::new();
            if ffi::ecdsa_signature_parse_der_lax(
                ffi::secp256k1_context_no_precomp,
                &mut ret,
                data.as_c_ptr(),
                data.len() as usize,
            ) == 1
            {
                Ok(Signature(ret))
            } else {
                Err(Error::InvalidSignature)
            }
        }
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
        unsafe {
            // Ignore return value, which indicates whether the sig
            // was already normalized. We don't care.
            ffi::secp256k1_ecdsa_signature_normalize(
                ffi::secp256k1_context_no_precomp,
                self.as_mut_c_ptr(),
                self.as_c_ptr(),
            );
        }
    }

    /// Obtains a raw pointer suitable for use with FFI functions
    #[inline]
    pub fn as_ptr(&self) -> *const ffi::Signature {
        &self.0
    }

    /// Obtains a raw mutable pointer suitable for use with FFI functions
    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut ffi::Signature {
        &mut self.0
    }

    #[inline]
    /// Serializes the signature in DER format
    pub fn serialize_der(&self) -> SerializedSignature {
        let mut ret = SerializedSignature::default();
        let mut len: usize = ret.capacity();
        unsafe {
            let err = ffi::secp256k1_ecdsa_signature_serialize_der(
                ffi::secp256k1_context_no_precomp,
                ret.get_data_mut_ptr(),
                &mut len,
                self.as_c_ptr(),
            );
            debug_assert!(err == 1);
            ret.set_len(len);
        }
        ret
    }

    #[inline]
    /// Serializes the signature in compact format
    pub fn serialize_compact(&self) -> [u8; 64] {
        let mut ret = [0; 64];
        unsafe {
            let err = ffi::secp256k1_ecdsa_signature_serialize_compact(
                ffi::secp256k1_context_no_precomp,
                ret.as_mut_c_ptr(),
                self.as_c_ptr(),
            );
            debug_assert!(err == 1);
        }
        ret
    }
}

impl CPtr for Signature {
    type Target = ffi::Signature;
    fn as_c_ptr(&self) -> *const Self::Target {
        self.as_ptr()
    }

    fn as_mut_c_ptr(&mut self) -> *mut Self::Target {
        self.as_mut_ptr()
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
impl ::serde::Serialize for Signature {
    fn serialize<S: ::serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.collect_str(self)
        } else {
            s.serialize_bytes(&self.serialize_der())
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> ::serde::Deserialize<'de> for Signature {
    fn deserialize<D: ::serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        if d.is_human_readable() {
            d.deserialize_str(serde_util::FromStrVisitor::new(
                "a hex string representing a DER encoded Signature"
            ))
        } else {
            d.deserialize_bytes(serde_util::BytesVisitor::new(
                "raw byte stream, that represents a DER encoded Signature",
                Signature::from_der
            ))
        }
    }
}


impl Default for SerializedSignature {
    fn default() -> SerializedSignature {
        SerializedSignature {
            data: [0u8; 72],
            len: 0,
        }
    }
}

impl PartialEq for SerializedSignature {
    fn eq(&self, other: &SerializedSignature) -> bool {
        self.data[..self.len] == other.data[..other.len]
    }
}

impl AsRef<[u8]> for SerializedSignature {
    fn as_ref(&self) -> &[u8] {
        &self.data[..self.len]
    }
}

impl Deref for SerializedSignature {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.data[..self.len]
    }
}

impl Eq for SerializedSignature {}


fn der_length_check(sig: &ffi::Signature, max_len: usize) -> bool {
    let mut ser_ret = [0; 72];
    let mut len: usize = ser_ret.len();
    unsafe {
        let err = ffi::secp256k1_ecdsa_signature_serialize_der(
            ffi::secp256k1_context_no_precomp,
            ser_ret.as_mut_c_ptr(),
            &mut len,
            sig,
        );
        debug_assert!(err == 1);
    }
    len <= max_len
}

fn compact_sig_has_zero_first_bit(sig: &ffi::Signature) -> bool {
    let mut compact = [0; 64];
    unsafe {
        let err = ffi::secp256k1_ecdsa_signature_serialize_compact(
            ffi::secp256k1_context_no_precomp,
            compact.as_mut_c_ptr(),
            sig,
        );
        debug_assert!(err == 1);
    }
    compact[0] < 0x80
}

impl<C: Signing> Secp256k1<C> {

    /// Constructs a signature for `msg` using the secret key `sk` and RFC6979 nonce
    /// Requires a signing-capable context.
    pub fn sign(&self, msg: &Message, sk: &key::SecretKey)
                -> Signature {

        unsafe {
            let mut ret = ffi::Signature::new();
            // We can assume the return value because it's not possible to construct
            // an invalid signature from a valid `Message` and `SecretKey`
            assert_eq!(ffi::secp256k1_ecdsa_sign(self.ctx, &mut ret, msg.as_c_ptr(),
                                                 sk.as_c_ptr(), ffi::secp256k1_nonce_function_rfc6979,
                                                 ptr::null()), 1);
            Signature::from(ret)
        }
    }

    fn sign_grind_with_check(
        &self, msg: &Message,
        sk: &key::SecretKey,
        check: impl Fn(&ffi::Signature) -> bool) -> Signature {
        let mut entropy_p : *const ffi::types::c_void = ptr::null();
        let mut counter : u32 = 0;
        let mut extra_entropy = [0u8; 32];
        loop {
            unsafe {
                let mut ret = ffi::Signature::new();
                // We can assume the return value because it's not possible to construct
                // an invalid signature from a valid `Message` and `SecretKey`
                assert_eq!(ffi::secp256k1_ecdsa_sign(self.ctx, &mut ret, msg.as_c_ptr(),
                                                     sk.as_c_ptr(), ffi::secp256k1_nonce_function_rfc6979,
                                                     entropy_p), 1);
                if check(&ret) {
                    return Signature::from(ret);
                }

                counter += 1;
                // From 1.32 can use `to_le_bytes` instead
                let le_counter = counter.to_le();
                let le_counter_bytes : [u8; 4] = mem::transmute(le_counter);
                for (i, b) in le_counter_bytes.iter().enumerate() {
                    extra_entropy[i] = *b;
                }

                entropy_p = extra_entropy.as_ptr() as *const ffi::types::c_void;

                // When fuzzing, these checks will usually spinloop forever, so just short-circuit them.
                #[cfg(fuzzing)]
                    return Signature::from(ret);
            }
        }
    }

    /// Constructs a signature for `msg` using the secret key `sk`, RFC6979 nonce
    /// and "grinds" the nonce by passing extra entropy if necessary to produce
    /// a signature that is less than 71 - bytes_to_grund bytes. The number
    /// of signing operation performed by this function is exponential in the
    /// number of bytes grinded.
    /// Requires a signing capable context.
    pub fn sign_grind_r(&self, msg: &Message, sk: &key::SecretKey, bytes_to_grind: usize) -> Signature {
        let len_check = |s : &ffi::Signature| der_length_check(s, 71 - bytes_to_grind);
        return self.sign_grind_with_check(msg, sk, len_check);
    }

    /// Constructs a signature for `msg` using the secret key `sk`, RFC6979 nonce
    /// and "grinds" the nonce by passing extra entropy if necessary to produce
    /// a signature that is less than 71 bytes and compatible with the low r
    /// signature implementation of bitcoin core. In average, this function
    /// will perform two signing operations.
    /// Requires a signing capable context.
    pub fn sign_low_r(&self, msg: &Message, sk: &key::SecretKey) -> Signature {
        return self.sign_grind_with_check(msg, sk, compact_sig_has_zero_first_bit)
    }

    /// Generates a random keypair. Convenience function for `key::SecretKey::new`
    /// and `key::PublicKey::from_secret_key`; call those functions directly for
    /// batch key generation. Requires a signing-capable context. Requires compilation
    /// with the "rand" feature.
    #[inline]
    #[cfg(any(test, feature = "rand"))]
    pub fn generate_keypair<R: Rng + ?Sized>(&self, rng: &mut R)
                                             -> (key::SecretKey, key::PublicKey) {
        let sk = key::SecretKey::new(rng);
        let pk = key::PublicKey::from_secret_key(self, &sk);
        (sk, pk)
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
    /// # #[cfg(feature="rand")] {
    /// # use secp256k1::rand::rngs::OsRng;
    /// # use secp256k1::{Secp256k1, Message, Error};
    /// #
    /// # let secp = Secp256k1::new();
    /// # let mut rng = OsRng::new().expect("OsRng");
    /// # let (secret_key, public_key) = secp.generate_keypair(&mut rng);
    /// #
    /// let message = Message::from_slice(&[0xab; 32]).expect("32 bytes");
    /// let sig = secp.sign(&message, &secret_key);
    /// assert_eq!(secp.verify(&message, &sig, &public_key), Ok(()));
    ///
    /// let message = Message::from_slice(&[0xcd; 32]).expect("32 bytes");
    /// assert_eq!(secp.verify(&message, &sig, &public_key), Err(Error::IncorrectSignature));
    /// # }
    /// ```
    #[inline]
    pub fn verify(&self, msg: &Message, sig: &Signature, pk: &key::PublicKey) -> Result<(), Error> {
        unsafe {
            if ffi::secp256k1_ecdsa_verify(self.ctx, sig.as_c_ptr(), msg.as_c_ptr(), pk.as_c_ptr()) == 0 {
                Err(Error::IncorrectSignature)
            } else {
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod test {
    use rand::{RngCore, thread_rng};
    use std::str::FromStr;

    use key::{SecretKey, PublicKey};
    use super::Signature;
    use from_hex;
    use constants;
    use Secp256k1;
    use Message;
    use Error;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    #[test]
    fn signature_serialize_roundtrip() {
        let mut s = Secp256k1::new();
        s.randomize(&mut thread_rng());

        let mut msg = [0; 32];
        for _ in 0..100 {
            thread_rng().fill_bytes(&mut msg);
            let msg = Message::from_slice(&msg).unwrap();

            let (sk, _) = s.generate_keypair(&mut thread_rng());
            let sig1 = s.sign(&msg, &sk);
            let der = sig1.serialize_der();
            let sig2 = Signature::from_der(&der[..]).unwrap();
            assert_eq!(sig1, sig2);

            let compact = sig1.serialize_compact();
            let sig2 = Signature::from_compact(&compact[..]).unwrap();
            assert_eq!(sig1, sig2);

            assert!(Signature::from_compact(&der[..]).is_err());
            assert!(Signature::from_compact(&compact[0..4]).is_err());
            assert!(Signature::from_der(&compact[..]).is_err());
            assert!(Signature::from_der(&der[0..4]).is_err());
        }
    }

    #[test]
    fn signature_display() {
        let hex_str = "3046022100839c1fbc5304de944f697c9f4b1d01d1faeba32d751c0f7acb21ac8a0f436a72022100e89bd46bb3a5a62adc679f659b7ce876d83ee297c7a5587b2011c4fcc72eab45";
        let byte_str = hex!(hex_str);

        assert_eq!(
            Signature::from_der(&byte_str).expect("byte str decode"),
            Signature::from_str(&hex_str).expect("byte str decode")
        );

        let sig = Signature::from_str(&hex_str).expect("byte str decode");
        assert_eq!(&sig.to_string(), hex_str);
        assert_eq!(&format!("{:?}", sig), hex_str);

        assert!(Signature::from_str(
            "3046022100839c1fbc5304de944f697c9f4b1d01d1faeba32d751c0f7acb21ac8a0f436a\
             72022100e89bd46bb3a5a62adc679f659b7ce876d83ee297c7a5587b2011c4fcc72eab4"
        ).is_err());
        assert!(Signature::from_str(
            "3046022100839c1fbc5304de944f697c9f4b1d01d1faeba32d751c0f7acb21ac8a0f436a\
             72022100e89bd46bb3a5a62adc679f659b7ce876d83ee297c7a5587b2011c4fcc72eab"
        ).is_err());
        assert!(Signature::from_str(
            "3046022100839c1fbc5304de944f697c9f4b1d01d1faeba32d751c0f7acb21ac8a0f436a\
             72022100e89bd46bb3a5a62adc679f659b7ce876d83ee297c7a5587b2011c4fcc72eabxx"
        ).is_err());
        assert!(Signature::from_str(
            "3046022100839c1fbc5304de944f697c9f4b1d01d1faeba32d751c0f7acb21ac8a0f436a\
             72022100e89bd46bb3a5a62adc679f659b7ce876d83ee297c7a5587b2011c4fcc72eab45\
             72022100e89bd46bb3a5a62adc679f659b7ce876d83ee297c7a5587b2011c4fcc72eab45\
             72022100e89bd46bb3a5a62adc679f659b7ce876d83ee297c7a5587b2011c4fcc72eab45\
             72022100e89bd46bb3a5a62adc679f659b7ce876d83ee297c7a5587b2011c4fcc72eab45\
             72022100e89bd46bb3a5a62adc679f659b7ce876d83ee297c7a5587b2011c4fcc72eab45"
        ).is_err());

        // 71 byte signature
        let hex_str = "30450221009d0bad576719d32ae76bedb34c774866673cbde3f4e12951555c9408e6ce774b02202876e7102f204f6bfee26c967c3926ce702cf97d4b010062e193f763190f6776";
        let sig = Signature::from_str(&hex_str).expect("byte str decode");
        assert_eq!(&format!("{}", sig), hex_str);
    }

    #[test]
    fn signature_lax_der() {
        macro_rules! check_lax_sig(
            ($hex:expr) => ({
                let sig = hex!($hex);
                assert!(Signature::from_der_lax(&sig[..]).is_ok());
            })
        );

        check_lax_sig!("304402204c2dd8a9b6f8d425fcd8ee9a20ac73b619906a6367eac6cb93e70375225ec0160220356878eff111ff3663d7e6bf08947f94443845e0dcc54961664d922f7660b80c");
        check_lax_sig!("304402202ea9d51c7173b1d96d331bd41b3d1b4e78e66148e64ed5992abd6ca66290321c0220628c47517e049b3e41509e9d71e480a0cdc766f8cdec265ef0017711c1b5336f");
        check_lax_sig!("3045022100bf8e050c85ffa1c313108ad8c482c4849027937916374617af3f2e9a881861c9022023f65814222cab09d5ec41032ce9c72ca96a5676020736614de7b78a4e55325a");
        check_lax_sig!("3046022100839c1fbc5304de944f697c9f4b1d01d1faeba32d751c0f7acb21ac8a0f436a72022100e89bd46bb3a5a62adc679f659b7ce876d83ee297c7a5587b2011c4fcc72eab45");
        check_lax_sig!("3046022100eaa5f90483eb20224616775891397d47efa64c68b969db1dacb1c30acdfc50aa022100cf9903bbefb1c8000cf482b0aeeb5af19287af20bd794de11d82716f9bae3db1");
        check_lax_sig!("3045022047d512bc85842ac463ca3b669b62666ab8672ee60725b6c06759e476cebdc6c102210083805e93bd941770109bcc797784a71db9e48913f702c56e60b1c3e2ff379a60");
        check_lax_sig!("3044022023ee4e95151b2fbbb08a72f35babe02830d14d54bd7ed1320e4751751d1baa4802206235245254f58fd1be6ff19ca291817da76da65c2f6d81d654b5185dd86b8acf");
    }

    #[test]
    fn sign_and_verify() {
        let mut s = Secp256k1::new();
        s.randomize(&mut thread_rng());

        let mut msg = [0; 32];
        for _ in 0..100 {
            thread_rng().fill_bytes(&mut msg);
            let msg = Message::from_slice(&msg).unwrap();

            let (sk, pk) = s.generate_keypair(&mut thread_rng());
            let sig = s.sign(&msg, &sk);
            assert_eq!(s.verify(&msg, &sig, &pk), Ok(()));
            let low_r_sig = s.sign_low_r(&msg, &sk);
            assert_eq!(s.verify(&msg, &low_r_sig, &pk), Ok(()));
            let grind_r_sig = s.sign_grind_r(&msg, &sk, 1);
            assert_eq!(s.verify(&msg, &grind_r_sig, &pk), Ok(()));
            let compact = sig.serialize_compact();
            if compact[0] < 0x80 {
                assert_eq!(sig, low_r_sig);
            } else {
                #[cfg(not(fuzzing))]  // mocked sig generation doesn't produce low-R sigs
                assert_ne!(sig, low_r_sig);
            }
            #[cfg(not(fuzzing))]  // mocked sig generation doesn't produce low-R sigs
            assert!(super::compact_sig_has_zero_first_bit(&low_r_sig.0));
            #[cfg(not(fuzzing))]  // mocked sig generation doesn't produce low-R sigs
            assert!(super::der_length_check(&grind_r_sig.0, 70));
        }
    }

    #[test]
    fn sign_and_verify_extreme() {
        let mut s = Secp256k1::new();
        s.randomize(&mut thread_rng());

        // Wild keys: 1, CURVE_ORDER - 1
        // Wild msgs: 1, CURVE_ORDER - 1
        let mut wild_keys = [[0; 32]; 2];
        let mut wild_msgs = [[0; 32]; 2];

        wild_keys[0][0] = 1;
        wild_msgs[0][0] = 1;

        use constants;
        wild_keys[1][..].copy_from_slice(&constants::CURVE_ORDER[..]);
        wild_msgs[1][..].copy_from_slice(&constants::CURVE_ORDER[..]);

        wild_keys[1][0] -= 1;
        wild_msgs[1][0] -= 1;

        for key in wild_keys.iter().map(|k| SecretKey::from_slice(&k[..]).unwrap()) {
            for msg in wild_msgs.iter().map(|m| Message::from_slice(&m[..]).unwrap()) {
                let sig = s.sign(&msg, &key);
                let low_r_sig = s.sign_low_r(&msg, &key);
                let grind_r_sig = s.sign_grind_r(&msg, &key, 1);
                let pk = PublicKey::from_secret_key(&s, &key);
                assert_eq!(s.verify(&msg, &sig, &pk), Ok(()));
                assert_eq!(s.verify(&msg, &low_r_sig, &pk), Ok(()));
                assert_eq!(s.verify(&msg, &grind_r_sig, &pk), Ok(()));
            }
        }
    }

    #[test]
    fn sign_and_verify_fail() {
        let mut s = Secp256k1::new();
        s.randomize(&mut thread_rng());

        let mut msg = [0u8; 32];
        thread_rng().fill_bytes(&mut msg);
        let msg = Message::from_slice(&msg).unwrap();

        let (sk, pk) = s.generate_keypair(&mut thread_rng());

        let sig = s.sign(&msg, &sk);

        let mut msg = [0u8; 32];
        thread_rng().fill_bytes(&mut msg);
        let msg = Message::from_slice(&msg).unwrap();
        assert_eq!(s.verify(&msg, &sig, &pk), Err(Error::IncorrectSignature));
    }

    #[test]
    fn test_bad_slice() {
        assert_eq!(Signature::from_der(&[0; constants::MAX_SIGNATURE_SIZE + 1]),
                   Err(Error::InvalidSignature));
        assert_eq!(Signature::from_der(&[0; constants::MAX_SIGNATURE_SIZE]),
                   Err(Error::InvalidSignature));

        assert_eq!(Message::from_slice(&[0; constants::MESSAGE_SIZE - 1]),
                   Err(Error::InvalidMessage));
        assert_eq!(Message::from_slice(&[0; constants::MESSAGE_SIZE + 1]),
                   Err(Error::InvalidMessage));
        assert!(Message::from_slice(&[0; constants::MESSAGE_SIZE]).is_ok());
        assert!(Message::from_slice(&[1; constants::MESSAGE_SIZE]).is_ok());
    }

    #[test]
    #[cfg(not(fuzzing))]  // fixed sig vectors can't work with fuzz-sigs
    fn test_low_s() {
        // nb this is a transaction on testnet
        // txid 8ccc87b72d766ab3128f03176bb1c98293f2d1f85ebfaf07b82cc81ea6891fa9
        //      input number 3
        let sig = hex!("3046022100839c1fbc5304de944f697c9f4b1d01d1faeba32d751c0f7acb21ac8a0f436a72022100e89bd46bb3a5a62adc679f659b7ce876d83ee297c7a5587b2011c4fcc72eab45");
        let pk = hex!("031ee99d2b786ab3b0991325f2de8489246a6a3fdb700f6d0511b1d80cf5f4cd43");
        let msg = hex!("a4965ca63b7d8562736ceec36dfa5a11bf426eb65be8ea3f7a49ae363032da0d");

        let secp = Secp256k1::new();
        let mut sig = Signature::from_der(&sig[..]).unwrap();
        let pk = PublicKey::from_slice(&pk[..]).unwrap();
        let msg = Message::from_slice(&msg[..]).unwrap();

        // without normalization we expect this will fail
        assert_eq!(secp.verify(&msg, &sig, &pk), Err(Error::IncorrectSignature));
        // after normalization it should pass
        sig.normalize_s();
        assert_eq!(secp.verify(&msg, &sig, &pk), Ok(()));
    }

    #[test]
    #[cfg(not(fuzzing))]  // fuzz-sigs have fixed size/format
    fn test_low_r() {
        let secp = Secp256k1::new();
        let msg = hex!("887d04bb1cf1b1554f1b268dfe62d13064ca67ae45348d50d1392ce2d13418ac");
        let msg = Message::from_slice(&msg).unwrap();
        let sk = SecretKey::from_str("57f0148f94d13095cfda539d0da0d1541304b678d8b36e243980aab4e1b7cead").unwrap();
        let expected_sig = hex!("047dd4d049db02b430d24c41c7925b2725bcd5a85393513bdec04b4dc363632b1054d0180094122b380f4cfa391e6296244da773173e78fc745c1b9c79f7b713");
        let expected_sig = Signature::from_compact(&expected_sig).unwrap();

        let sig = secp.sign_low_r(&msg, &sk);

        assert_eq!(expected_sig, sig);
    }

    #[test]
    #[cfg(not(fuzzing))]  // fuzz-sigs have fixed size/format
    fn test_grind_r() {
        let secp = Secp256k1::new();
        let msg = hex!("ef2d5b9a7c61865a95941d0f04285420560df7e9d76890ac1b8867b12ce43167");
        let msg = Message::from_slice(&msg).unwrap();
        let sk = SecretKey::from_str("848355d75fe1c354cf05539bb29b2015f1863065bcb6766b44d399ab95c3fa0b").unwrap();
        let expected_sig = Signature::from_str("304302202ffc447100d518c8ba643d11f3e6a83a8640488e7d2537b1954b942408be6ea3021f26e1248dd1e52160c3a38af9769d91a1a806cab5f9d508c103464d3c02d6e1").unwrap();

        let sig = secp.sign_grind_r(&msg, &sk, 2);

        assert_eq!(expected_sig, sig);
    }

    #[cfg(feature = "serde")]
    #[cfg(not(fuzzing))]  // fixed sig vectors can't work with fuzz-sigs
    #[test]
    fn test_serde() {
        use serde_test::{Configure, Token, assert_tokens};

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
        assert_tokens(&sig.compact(), &[Token::Bytes(&SIG_BYTES)]);
        assert_tokens(&sig.compact(), &[Token::ByteBuf(&SIG_BYTES)]);

        assert_tokens(&sig.readable(), &[Token::BorrowedStr(SIG_STR)]);
        assert_tokens(&sig.readable(), &[Token::Str(SIG_STR)]);
        assert_tokens(&sig.readable(), &[Token::String(SIG_STR)]);

    }
}

#[cfg(all(test, feature = "unstable"))]
mod benches {
    use rand::{thread_rng, RngCore};
    use test::{Bencher, black_box};

    use super::{Secp256k1, Message};

    #[bench]
    pub fn generate(bh: &mut Bencher) {
        struct CounterRng(u64);
        impl RngCore for CounterRng {
            fn next_u32(&mut self) -> u32 {
                self.next_u64() as u32
            }

            fn next_u64(&mut self) -> u64 {
                self.0 += 1;
                self.0
            }

            fn fill_bytes(&mut self, dest: &mut [u8]) {
                for chunk in dest.chunks_mut(64/8) {
                    let rand: [u8; 64/8] = unsafe {std::mem::transmute(self.next_u64())};
                    chunk.copy_from_slice(&rand[..chunk.len()]);
                }
            }

            fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
                Ok(self.fill_bytes(dest))
            }
        }


        let s = Secp256k1::new();
        let mut r = CounterRng(0);
        bh.iter( || {
            let (sk, pk) = s.generate_keypair(&mut r);
            black_box(sk);
            black_box(pk);
        });
    }

    #[bench]
    pub fn bench_sign(bh: &mut Bencher) {
        let s = Secp256k1::new();
        let mut msg = [0u8; 32];
        thread_rng().fill_bytes(&mut msg);
        let msg = Message::from_slice(&msg).unwrap();
        let (sk, _) = s.generate_keypair(&mut thread_rng());

        bh.iter(|| {
            let sig = s.sign(&msg, &sk);
            black_box(sig);
        });
    }

    #[bench]
    pub fn bench_verify(bh: &mut Bencher) {
        let s = Secp256k1::new();
        let mut msg = [0u8; 32];
        thread_rng().fill_bytes(&mut msg);
        let msg = Message::from_slice(&msg).unwrap();
        let (sk, pk) = s.generate_keypair(&mut thread_rng());
        let sig = s.sign(&msg, &sk);

        bh.iter(|| {
            let res = s.verify(&msg, &sig, &pk).unwrap();
            black_box(res);
        });
    }
}
