use core::ptr;

use crate::types::*;
use crate::{impl_array_newtype, impl_raw_debug, secp256k1_context_no_precomp, Secp256k1};

/// Library-internal representation of a Secp256k1 secret key.
///
/// The inner array is to be considered opaque, it is passed across the FFI boundary and as such we
/// make no guarantees about the byte layout or stability across library versions or architectures.
#[repr(C)]
// TODO: Work out if libsecp provides a way to compare secret keys or is the derived traits ok?
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SecretKey([c_uchar; 32]);
impl_array_newtype!(SecretKey, c_uchar, 32);
impl_raw_debug!(SecretKey);

impl SecretKey {
    /// Creates a new `SecretKey`.
    ///
    /// # Returns
    ///
    /// Returns `None` if the resulting key would be invalid.
    #[inline]
    pub fn from_checked(data: [u8; 32]) -> Option<Self> {
        let res = unsafe {
            crate::secp256k1_ec_seckey_verify(secp256k1_context_no_precomp, data.as_ptr())
        };
        if res == 1 { Some(SecretKey(data)) } else { None }
    }

    /// Creates a new secret key using data from BIP-340 [`KeyPair`].
    ///
    /// # Returns
    ///
    /// Returns `None` if the resulting key would be invalid.
    #[inline]
    pub fn from_keypair(keypair: &KeyPair) -> Option<Self> {
        let mut sk = [0u8; 32];

        let res = unsafe {
            crate::secp256k1_keypair_sec(
                secp256k1_context_no_precomp,
                sk.as_mut_ptr(),
                keypair,
            )
        };
        if res == 1 { Some(SecretKey(sk)) } else { None }
    }

    /// Returns the [`SecretKey`] as a byte value.
    #[inline]
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.underlying_bytes()
    }

    /// Negates the secret key.
    ///
    /// # Returns
    ///
    /// Returns `None` if the resulting key would be invalid.
    #[inline]
    #[must_use = "this returns the result of the operation, without modifying the original"]
    pub fn negate(mut self) -> Option<Self> {
        let res = unsafe {
            crate::secp256k1_ec_seckey_negate(
                secp256k1_context_no_precomp,
                self.as_mut_ptr()
            )
        };
        if res == 1 { Some(self) } else { None }
    }

    /// Tweaks a [`SecretKey`] by adding `tweak` modulo the curve order.
    ///
    /// # Returns
    ///
    /// Returns `None` if the resulting key would be invalid.
    #[inline]
    #[must_use = "this returns the result of the operation, without modifying the original"]
    pub fn add_tweak(mut self, tweak: [u8; 32]) -> Option<SecretKey> {
        let res = unsafe {
            crate::secp256k1_ec_seckey_tweak_add(
                secp256k1_context_no_precomp,
                self.as_mut_ptr(),
                tweak.as_ptr(),
            )
        };
        if res == 1 { Some(self) } else { None }
    }

    /// Tweaks a [`SecretKey`] by multiplying by `tweak` modulo the curve order.
    ///
    /// # Returns
    ///
    /// Returns `None` if the resulting key would be invalid.
    #[inline]
    #[must_use = "this returns the result of the operation, without modifying the original"]
    pub fn mul_tweak(mut self, tweak: &[u8; 32]) -> Option<SecretKey> {
        let res = unsafe {
            crate::secp256k1_ec_seckey_tweak_mul(
                secp256k1_context_no_precomp,
                self.as_mut_ptr(),
                tweak.as_ptr(),
            )
        };
        if res == 1 { Some(self) } else { None }
    }
}

/// Library-internal representation of a Secp256k1 public key.
///
/// The inner array is to be considered opaque, it is passed across the FFI boundary and as such we
/// make no guarantees about the byte layout or stability across library versions or architectures.
#[repr(C)]
// TODO: Use rustsecp256k1_ec_pubkey_cmp instead of deriving [Partial]Ord/[aPartial]Eq
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PublicKey([c_uchar; 64]);
impl_array_newtype!(PublicKey, c_uchar, 64);
impl_raw_debug!(PublicKey);

impl PublicKey {
    #[inline]
    pub fn from_secret_key(ctx: &Secp256k1, sk: &SecretKey) -> Option<PublicKey> {
        unsafe {
            let mut pk = PublicKey::new();
            let res = crate::secp256k1_ec_pubkey_create(ctx.as_ptr(), &mut pk, sk.as_ptr());
            if res == 1 { Some(pk) } else { None }
        }
    }

    /// Creates a `PublicKey` directly from a slice.
    #[inline]
    pub fn from_slice(data: &[u8]) -> Option<PublicKey> {
        if data.is_empty() {
            return None;
        }

        unsafe {
            let mut pk = PublicKey::new();
            let res = crate::secp256k1_ec_pubkey_parse(
                secp256k1_context_no_precomp,
                &mut pk,
                data.as_ptr(),
                data.len() as usize,
            );
            if res == 1 { Some(pk) } else { None }
        }
    }

    /// Creates a new `PublicKey` using data from BIP-340 [`KeyPair`].
    #[inline]
    pub fn from_keypair(keypair: &KeyPair) -> Option<PublicKey> {
        unsafe {
            let mut pk = PublicKey::new();
            let res = crate::secp256k1_keypair_pub(
                secp256k1_context_no_precomp,
                &mut pk,
                keypair,
            );
            if res == 1 { Some(pk) } else { None }
        }
    }

    /// Serializes the key as a byte-encoded pair of values. In compressed form the y-coordinate is
    /// represented by only a single bit, as x determines it up to one bit.
    ///
    /// `flag` is either SECP256K1_SER_UNCOMPRESSED or SECP256K1_SER_COMPRESSED
    pub fn serialize(&self, buf: &mut [u8], flag: c_uint)  {
        let mut buf_len = buf.len();
        let res = unsafe {
            crate::secp256k1_ec_pubkey_serialize(
                secp256k1_context_no_precomp,
                buf.as_mut_ptr(),
                &mut buf_len,
                self,
                flag,
            )
        };
        // TODO: Do error handling.
        assert_eq!(res, 1);
        assert_eq!(buf_len, buf.len());
    }

    /// Negates the `PublicKey`.
    ///
    /// # Returns
    ///
    /// Returns `None` if the resulting key would be invalid.
    #[inline]
    #[must_use = "this returns the result of the operation, without modifying the original"]
    pub fn negate(mut self, ctx: &Secp256k1) -> Option<PublicKey> {
        let res = unsafe {
            crate::secp256k1_ec_pubkey_negate(ctx.as_ptr(), &mut self)
        };
        if res == 1 { Some(self) } else { None }
    }

    /// Tweaks a [`PublicKey`] by adding `tweak * G` modulo the curve order.
    ///
    /// # Returns
    ///
    /// Returns `None` if the resulting key would be invalid.
    #[inline]
    #[must_use = "this returns the result of the operation, without modifying the original"]
    pub fn add_exp_tweak(mut self, ctx: &Secp256k1, tweak: &[u8; 32]) -> Option<PublicKey> {
        let res = unsafe {
            crate::secp256k1_ec_pubkey_tweak_add(ctx.as_ptr(), &mut self, tweak.as_ptr())
        };
        if res == 1 { Some(self) } else { None }
    }

    /// Tweaks a [`PublicKey`] by multiplying by `tweak` modulo the curve order.
    ///
    /// # Returns
    ///
    /// Returns `None` if the resulting key would be invalid.
    #[must_use = "this returns the result of the operation, without modifying the original"]
    pub fn mul_tweak(mut self, ctx: &Secp256k1, tweak: &[u8; 32]) -> Option<PublicKey> {
        let res = unsafe {
            crate::secp256k1_ec_pubkey_tweak_mul(ctx.as_ptr(), &mut self, tweak.as_ptr())
        };
        if res == 1 { Some(self) } else { None }
    }

    /// TODO: Write docs.
    ///
    /// Caller must guarantee that `keys` is non-empty and less than `core::i32::MAX`;
    ///
    /// # Returns
    ///
    /// Returns `None` if the resulting key would be invalid. TODO: Check this claim.
    pub fn combine_keys(keys: &[&PublicKey]) -> Option<PublicKey> {
        // TODO: Refactor this whole method.

        fn const_ptr(k: &PublicKey) -> *const PublicKey {
            k
        }

        let keys_len = keys.len() as i32;
        let ffi_keys: Vec<*const PublicKey> = keys.iter().map(|k| const_ptr(k)).collect();

        unsafe {
            let mut pk = crate::PublicKey::new();
            let res = crate::secp256k1_ec_pubkey_combine(
                secp256k1_context_no_precomp,
                &mut pk,
                ffi_keys.as_ptr(),
                keys_len,
            );
            if res == 1 { Some(pk) } else { None }
        }
    }

    /// Returns the [`XOnlyPublicKey`] (and it's [`Parity`]) for this [`PublicKey`].
    ///
    /// TODO: Work out and document error path.
    #[inline]
    pub fn x_only_public_key(&self) -> Option<(XOnlyPublicKey, i32)> {
        unsafe {
            let mut xonly = XOnlyPublicKey::new();
            let mut parity = 0;

            let res = crate::secp256k1_xonly_pubkey_from_pubkey(
                secp256k1_context_no_precomp,
                &mut xonly,
                &mut parity,
                self,           // FIXME: Check this.
            );
            if res == 1 { Some((xonly, parity)) } else { None }
        }
    }
}

/// Library-internal representation of a Secp256k1 x-only public key.
///
/// The inner array is to be considered opaque, it is passed across the FFI boundary and as such we
/// make no guarantees about the byte layout or stability across library versions or architectures.
#[repr(C)]
// TODO: Use rustsecp256k1_xonly_pubkey_cmp instead of deriving [Partial]Ord/[aPartial]Eq/Hash
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct XOnlyPublicKey([c_uchar; 64]);
impl_array_newtype!(XOnlyPublicKey, c_uchar, 64);
impl_raw_debug!(XOnlyPublicKey);

impl XOnlyPublicKey {
    /// Returns the [`XOnlyPublicKey`] from [`PublicKey`].
    pub fn from_pubkey(pk: &PublicKey) -> Option<XOnlyPublicKey> {
        unsafe {
            let mut xonly = XOnlyPublicKey::new();
            let res = crate::secp256k1_xonly_pubkey_from_pubkey(
                    secp256k1_context_no_precomp,
                    &mut xonly,
                    ptr::null_mut(),
                    pk,
            );
            if res == 1 { Some(xonly) } else { None }
        }
    }

    /// Returns the [`XOnlyPublicKey`] and it's parity for `keypair`.
    #[inline]
    pub fn from_keypair(keypair: &KeyPair) -> Option<(XOnlyPublicKey, i32)> {
        let mut parity = 0;
        unsafe {
            let mut xonly = XOnlyPublicKey::new();
            let res = crate::secp256k1_keypair_xonly_pub(
                secp256k1_context_no_precomp,
                &mut xonly,
                &mut parity,
                keypair,
            );
            if res == 1 { Some((xonly, parity)) } else { None }
        }
    }

    /// Creates a Schnorr public key directly from a slice.
    ///
    /// # Returns
    ///
    /// Returns `None` if `data` does not represent a valid Secp256k1 point x coordinate.
    #[inline]
    pub fn from_slice(data: &[u8; 32]) -> Option<XOnlyPublicKey> {
        unsafe {
            let mut xonly = XOnlyPublicKey::new();
            let res = crate::secp256k1_xonly_pubkey_parse(
                secp256k1_context_no_precomp,
                &mut xonly,
                data.as_ptr(),
            );
            if res == 1 { Some(xonly) } else { None }
        }
    }

    /// Serializes the key as a byte-encoded x coordinate value (32 bytes).
    ///
    /// # Panics
    ///
    /// Panics if serialization fails.
    pub fn serialize(&self, buf: &mut [u8]) {
        unsafe {
            let res = crate::secp256k1_xonly_pubkey_serialize(
                secp256k1_context_no_precomp,
                buf.as_mut_ptr(),
                self,
            );
            assert_eq!(res, 1); // TODO: Better error handling.
        }
    }

    /// Tweaks an [`XOnlyPublicKey`] by adding the generator multiplied with the given tweak to it.
    ///
    /// # Returns
    ///
    /// The newly tweaked key plus an opaque type representing the parity of the tweaked key, this
    /// should be provided to `tweak_add_check` which can be used to verify a tweak more efficiently
    /// than regenerating it and checking equality.
    ///
    /// `None` if the resulting tweaked key is invalid.
    #[must_use = "this returns the result of the operation, without modifying the original"]
    pub fn add_tweak(mut self, ctx: &Secp256k1, tweak: &[u8; 32]) -> Option<(XOnlyPublicKey, i32)> {
        let mut parity = 0;
        unsafe {
            let mut pk = PublicKey::new();
            let res= crate::secp256k1_xonly_pubkey_tweak_add(
                ctx.as_ptr(),
                &mut pk,
                &self,
                tweak.as_ptr(),
            );
            // TODO: Add better error handling?
            if res != 1 {
                return None
            }

            let res = crate::secp256k1_xonly_pubkey_from_pubkey(
                ctx.as_ptr(),
                &mut self,
                &mut parity,
                &pk,
            );
            if res == 1 { Some((self, parity)) } else { None }
        }
    }

    /// Verifies that a tweak produced by [`XOnlyPublicKey::tweak_add_assign`] was computed correctly.
    ///
    /// Should be called on the original untweaked key. Takes the tweaked key and output parity from
    /// [`XOnlyPublicKey::tweak_add_assign`] as input.
    ///
    /// Currently this is not much more efficient than just recomputing the tweak and checking
    /// equality. However, in future this API will support batch verification, which is
    /// significantly faster, so it is wise to design protocols with this in mind.
    ///
    /// # Returns
    ///
    /// True if tweak and check is successful, false otherwise.
    pub fn tweak_add_check(
        &self,
        ctx: &Secp256k1,
        tweaked_key: &XOnlyPublicKey,
        tweaked_parity: i32,
        tweak: &[u8; 32],
    ) -> bool {
        let mut tweaked_key_ser = [0_u8; 32];
        tweaked_key.serialize(&mut tweaked_key_ser);
        let res = unsafe {
            crate::secp256k1_xonly_pubkey_tweak_add_check(
                ctx.as_ptr(),
                tweaked_key_ser.as_ptr(),
                tweaked_parity,
                self,
                tweak.as_ptr(),
            )
        };
        res == 1
    }
}

/// Library-internal representation of a Secp256k1 key pair.
///
/// The inner array is to be considered opaque, it is passed across the FFI boundary and as such we
/// make no guarantees about the byte layout or stability across library versions or architectures.
#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyPair([c_uchar; 96]);
impl_array_newtype!(KeyPair, c_uchar, 96);
impl_raw_debug!(KeyPair);

impl KeyPair {
    /// Creates a [`KeyPair`] directly from a [`SecretKey`].
    #[inline]
    pub fn from_secret_key(ctx: &Secp256k1, sk: &SecretKey) -> Option<KeyPair> {
        KeyPair::from_seckey_slice(ctx, &sk.0)
    }

    /// Creates a [`KeyPair`] directly from a [`SecretKey`].
    #[inline]
    pub fn from_seckey_slice(ctx: &Secp256k1, sk: &[u8]) -> Option<KeyPair> {
        unsafe {
            let mut kp = KeyPair::new();
            let res = crate::secp256k1_keypair_create(ctx.as_ptr(), &mut kp, sk.as_ptr());
            if res == 1 { Some(kp) } else { None }
        }
    }

    /// Tweaks a keypair by first converting the public key to an xonly key and tweaking it.
    ///
    /// # Returns
    ///
    /// Returns `None` if the resulting key would be invalid.
    #[inline]
    #[must_use = "this returns the result of the operation, without modifying the original"]
    pub fn add_xonly_tweak(mut self, ctx: &Secp256k1, tweak: &[u8]) -> Option<KeyPair> {
        let res = unsafe {
            crate::secp256k1_keypair_xonly_tweak_add(ctx.as_ptr(), &mut self, tweak.as_ptr())
        };
        if res == 1 { Some(self) } else { None }
    }
}
