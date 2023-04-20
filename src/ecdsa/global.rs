//! Drop in replacement for all the methods currently implemented on the global context (SECP256K1).

use core::ptr;

use super::Signature;
use crate::ffi::CPtr;
use crate::{ffi, Error, Message, PublicKey, SecretKey};

/// Constructs a signature for `msg` using the secret key `sk` and RFC6979 nonce
pub fn sign_ecdsa(msg: &Message, sk: &SecretKey) -> Signature {
    sign_ecdsa_with_noncedata_pointer(msg, sk, None)
}

/// Constructs a signature for `msg` using the secret key `sk` and RFC6979 nonce
/// and includes 32 bytes of noncedata in the nonce generation via inclusion in
/// one of the hash operations during nonce generation. This is useful when multiple
/// signatures are needed for the same Message and SecretKey while still using RFC6979.
/// Requires a signing-capable context.
pub fn sign_ecdsa_with_noncedata(msg: &Message, sk: &SecretKey, noncedata: &[u8; 32]) -> Signature {
    sign_ecdsa_with_noncedata_pointer(msg, sk, Some(noncedata))
}

/// Checks that `sig` is a valid ECDSA signature for `msg` using the public
/// key `pubkey`. Returns `Ok(())` on success. Note that this function cannot
/// be used for Bitcoin consensus checking since there may exist signatures
/// which OpenSSL would verify but not libsecp256k1, or vice-versa. Requires a
/// verify-capable context.
///
/// ```rust
/// # #[cfg(feature = "rand-std")] {
/// # use secp256k1::{rand, Secp256k1, Message, Error};
/// #
/// # let secp = Secp256k1::new();
/// # let (secret_key, public_key) = secp.generate_keypair(&mut rand::thread_rng());
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
pub fn verify_ecdsa(msg: &Message, sig: &Signature, pk: &PublicKey) -> Result<(), Error> {
    unsafe {
        crate::context::_global::with_global_verify_context(|ctx| {
            if ffi::secp256k1_ecdsa_verify(ctx, sig.as_c_ptr(), msg.as_c_ptr(), pk.as_c_ptr()) == 0
            {
                Err(Error::IncorrectSignature)
            } else {
                Ok(())
            }
        })
    }
}

fn sign_ecdsa_with_noncedata_pointer(
    msg: &Message,
    sk: &SecretKey,
    noncedata: Option<&[u8; 32]>,
) -> Signature {
    unsafe {
        let mut ret = ffi::Signature::new();
        let noncedata_ptr = match noncedata {
            Some(arr) => arr.as_c_ptr() as *const _,
            None => ptr::null(),
        };
        crate::context::_global::with_global_signing_context(|ctx| {
            // We can assume the return value because it's not possible to construct
            // an invalid signature from a valid `Message` and `SecretKey`
            assert_eq!(
                ffi::secp256k1_ecdsa_sign(
                    ctx,
                    &mut ret,
                    msg.as_c_ptr(),
                    sk.as_c_ptr(),
                    ffi::secp256k1_nonce_function_rfc6979,
                    noncedata_ptr
                ),
                1
            );
        });
        Signature::from(ret)
    }
}
