use core::marker::PhantomData;
use {ffi, types::{c_uint, c_void}, Error, Secp256k1, };

#[cfg(feature = "std")]
pub use self::std_only::*;

/// A trait for all kinds of Context's that let's you define the exact flags and a function to deallocate memory.
/// * DO NOT * implement it for your own types.
pub unsafe trait Context {
    /// Flags for the ffi.
    const FLAGS: c_uint;
    /// A constant description of the context.
    const DESCRIPTION: &'static str;
    /// A function to deallocate the memory when the context is dropped.
    fn deallocate(ptr: *mut [u8]);
}

/// Marker trait for indicating that an instance of `Secp256k1` can be used for signing.
pub trait Signing: Context {}

/// Marker trait for indicating that an instance of `Secp256k1` can be used for verification.
pub trait Verification: Context {}


#[cfg(feature = "std")]
mod std_only {
    use super::*;

    /// Represents the set of capabilities needed for signing.
    pub enum SignOnly {}

    /// Represents the set of capabilities needed for verification.
    pub enum VerifyOnly {}

    /// Represents the set of all capabilities.
    pub enum All {}

    impl Signing for SignOnly {}
    impl Signing for All {}

    impl Verification for VerifyOnly {}
    impl Verification for All {}

    unsafe impl Context for SignOnly {
        const FLAGS: c_uint = ffi::SECP256K1_START_SIGN;
        const DESCRIPTION: &'static str = "signing only";

        fn deallocate(ptr: *mut [u8]) {
            let _ = unsafe { Box::from_raw(ptr) };
        }
    }

    unsafe impl Context for VerifyOnly {
        const FLAGS: c_uint = ffi::SECP256K1_START_VERIFY;
        const DESCRIPTION: &'static str = "verification only";

        fn deallocate(ptr: *mut [u8]) {
            let _ = unsafe { Box::from_raw(ptr) };
        }
    }

    unsafe impl Context for All {
        const FLAGS: c_uint = VerifyOnly::FLAGS | SignOnly::FLAGS;
        const DESCRIPTION: &'static str = "all capabilities";

        fn deallocate(ptr: *mut [u8]) {
            let _ = unsafe { Box::from_raw(ptr) };
        }
    }

    impl<C: Context> Secp256k1<C> {
        fn gen_new() -> Secp256k1<C> {
            let buf = vec![0u8; Self::preallocate_size()].into_boxed_slice();
            let ptr = Box::into_raw(buf);
            Secp256k1 {
                ctx: unsafe { ffi::secp256k1_context_preallocated_create(ptr as *mut c_void, C::FLAGS) },
                phantom: PhantomData,
                buf: ptr,
            }
        }
    }

    impl Secp256k1<All> {
        /// Creates a new Secp256k1 context with all capabilities
        pub fn new() -> Secp256k1<All> {
            Secp256k1::gen_new()
        }
    }

    impl Secp256k1<SignOnly> {
        /// Creates a new Secp256k1 context that can only be used for signing
        pub fn signing_only() -> Secp256k1<SignOnly> {
            Secp256k1::gen_new()
        }
    }

    impl Secp256k1<VerifyOnly> {
        /// Creates a new Secp256k1 context that can only be used for verification
        pub fn verification_only() -> Secp256k1<VerifyOnly> {
            Secp256k1::gen_new()
        }
    }

    impl Default for Secp256k1<All> {
        fn default() -> Self {
            Self::new()
        }
    }

    impl<C: Context> Clone for Secp256k1<C> {
        fn clone(&self) -> Secp256k1<C> {
            let buf = vec![0u8; unsafe { (&*self.buf).len() }].into_boxed_slice();
            let ptr = Box::into_raw(buf);
            Secp256k1 {
                ctx: unsafe { ffi::secp256k1_context_preallocated_create(ptr as *mut c_void, C::FLAGS) },
                phantom: PhantomData,
                buf: ptr,
            }
        }
    }

}
