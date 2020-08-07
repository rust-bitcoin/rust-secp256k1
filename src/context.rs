use core::marker::PhantomData;
use core::mem::ManuallyDrop;
use ptr;
use ffi::{self, CPtr};
use ffi::types::{c_uint, c_void};
use Error;
use Secp256k1;

#[cfg(feature = "std")]
pub use self::std_only::*;

#[cfg(feature = "global-context")]
/// Module implementing a singleton pattern for a global `Secp256k1` context
pub mod global {
    use std::ops::Deref;
    use std::sync::Once;
    use ::{Secp256k1, All};

    /// Proxy struct for global `SECP256K1` context
    pub struct GlobalContext {
        __private: (),
    }

    /// A global, static context to avoid repeatedly creating contexts where one can't be passed
    pub static SECP256K1: &GlobalContext = &GlobalContext { __private: () };

    impl Deref for GlobalContext {
        type Target = Secp256k1<All>;

        fn deref(&self) -> &Self::Target {
            static ONCE: Once = Once::new();
            static mut CONTEXT: Option<Secp256k1<All>> = None;
            ONCE.call_once(|| unsafe {
                let mut ctx = Secp256k1::new();
                ctx.randomize(&mut rand::thread_rng());
                CONTEXT = Some(ctx);
            });
            unsafe { CONTEXT.as_ref().unwrap() }
        }
    }
}


/// A trait for all kinds of Context's that Lets you define the exact flags and a function to deallocate memory.
/// It shouldn't be possible to implement this for types outside this crate.
pub unsafe trait Context : private::Sealed {
    /// Flags for the ffi.
    const FLAGS: c_uint;
    /// A constant description of the context.
    const DESCRIPTION: &'static str;
    /// A function to deallocate the memory when the context is dropped.
    unsafe fn deallocate(ptr: *mut [u8]);
}

/// Marker trait for indicating that an instance of `Secp256k1` can be used for signing.
pub trait Signing: Context {}

/// Marker trait for indicating that an instance of `Secp256k1` can be used for verification.
pub trait Verification: Context {}

/// Represents the set of capabilities needed for signing with a user preallocated memory.
pub struct SignOnlyPreallocated<'buf> {
    phantom: PhantomData<&'buf ()>,
}

/// Represents the set of capabilities needed for verification with a user preallocated memory.
pub struct VerifyOnlyPreallocated<'buf> {
    phantom: PhantomData<&'buf ()>,
}

/// Represents the set of all capabilities with a user preallocated memory.
pub struct AllPreallocated<'buf> {
    phantom: PhantomData<&'buf ()>,
}

mod private {
    use super::*;
    // A trick to prevent users from implementing a trait.
    // on one hand this trait is public, on the other it's in a private module
    // so it's not visible to anyone besides it's parent (the context module)
    pub trait Sealed {}

    impl<'buf> Sealed for AllPreallocated<'buf> {}
    impl<'buf> Sealed for VerifyOnlyPreallocated<'buf> {}
    impl<'buf> Sealed for SignOnlyPreallocated<'buf> {}
}

#[cfg(feature = "std")]
mod std_only {
    impl private::Sealed for SignOnly {}
    impl private::Sealed for All {}
    impl private::Sealed for VerifyOnly {}

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

        unsafe fn deallocate(ptr: *mut [u8]) {
            let _ = Box::from_raw(ptr);
        }
    }

    unsafe impl Context for VerifyOnly {
        const FLAGS: c_uint = ffi::SECP256K1_START_VERIFY;
        const DESCRIPTION: &'static str = "verification only";

        unsafe fn deallocate(ptr: *mut [u8]) {
            let _ = Box::from_raw(ptr);
        }
    }

    unsafe impl Context for All {
        const FLAGS: c_uint = VerifyOnly::FLAGS | SignOnly::FLAGS;
        const DESCRIPTION: &'static str = "all capabilities";

        unsafe fn deallocate(ptr: *mut [u8]) {
            let _ = Box::from_raw(ptr);
        }
    }

    impl<C: Context> Secp256k1<C> {
        /// Lets you create a context in a generic manner(sign/verify/all)
        pub fn gen_new() -> Secp256k1<C> {
            #[cfg(target_arch = "wasm32")]
            ffi::types::sanity_checks_for_wasm();

            let buf = vec![0u8; Self::preallocate_size_gen()].into_boxed_slice();
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
            let clone_size = unsafe {ffi::secp256k1_context_preallocated_clone_size(self.ctx)};
            let ptr_buf = Box::into_raw(vec![0u8; clone_size].into_boxed_slice());
            Secp256k1 {
                ctx: unsafe { ffi::secp256k1_context_preallocated_clone(self.ctx, ptr_buf as *mut c_void) },
                phantom: PhantomData,
                buf: ptr_buf,
            }
        }
    }
}

impl<'buf> Signing for SignOnlyPreallocated<'buf> {}
impl<'buf> Signing for AllPreallocated<'buf> {}

impl<'buf> Verification for VerifyOnlyPreallocated<'buf> {}
impl<'buf> Verification for AllPreallocated<'buf> {}

unsafe impl<'buf> Context for SignOnlyPreallocated<'buf> {
    const FLAGS: c_uint = ffi::SECP256K1_START_SIGN;
    const DESCRIPTION: &'static str = "signing only";

    unsafe fn deallocate(_ptr: *mut [u8]) {
        // Allocated by the user
    }
}

unsafe impl<'buf> Context for VerifyOnlyPreallocated<'buf> {
    const FLAGS: c_uint = ffi::SECP256K1_START_VERIFY;
    const DESCRIPTION: &'static str = "verification only";

    unsafe fn deallocate(_ptr: *mut [u8]) {
        // Allocated by the user
    }
}

unsafe impl<'buf> Context for AllPreallocated<'buf> {
    const FLAGS: c_uint = SignOnlyPreallocated::FLAGS | VerifyOnlyPreallocated::FLAGS;
    const DESCRIPTION: &'static str = "all capabilities";

    unsafe fn deallocate(_ptr: *mut [u8]) {
        // Allocated by the user
    }
}

impl<'buf, C: Context + 'buf> Secp256k1<C> {
    /// Lets you create a context with preallocated buffer in a generic manner(sign/verify/all)
    pub fn preallocated_gen_new(buf: &'buf mut [u8]) -> Result<Secp256k1<C>, Error> {
        #[cfg(target_arch = "wasm32")]
        ffi::types::sanity_checks_for_wasm();

        if buf.len() < Self::preallocate_size_gen() {
            return Err(Error::NotEnoughMemory);
        }
        Ok(Secp256k1 {
            ctx: unsafe {
                ffi::secp256k1_context_preallocated_create(
                    buf.as_mut_c_ptr() as *mut c_void,
                    C::FLAGS)
            },
            phantom: PhantomData,
            buf: buf as *mut [u8],
        })
    }
}

impl<'buf> Secp256k1<AllPreallocated<'buf>> {
    /// Creates a new Secp256k1 context with all capabilities
    pub fn preallocated_new(buf: &'buf mut [u8]) -> Result<Secp256k1<AllPreallocated<'buf>>, Error> {
        Secp256k1::preallocated_gen_new(buf)
    }
    /// Uses the ffi `secp256k1_context_preallocated_size` to check the memory size needed for a context
    pub fn preallocate_size() -> usize {
        Self::preallocate_size_gen()
    }

    /// Create a context from a raw context.
    ///
    /// # Safety
    /// This is highly unsafe, due to the number of conditions that aren't checked.
    /// * `raw_ctx` needs to be a valid Secp256k1 context pointer.
    /// that was generated by *exactly* the same code/version of the libsecp256k1 used here.
    /// * The capabilities (All/SignOnly/VerifyOnly) of the context *must* match the flags passed to libsecp256k1
    /// when generating the context.
    /// * The user must handle the freeing of the context(using the correct functions) by himself.
    /// * Violating these may lead to Undefined Behavior.
    ///
    pub unsafe fn from_raw_all(raw_ctx: *mut ffi::Context) -> ManuallyDrop<Secp256k1<AllPreallocated<'buf>>> {
        ManuallyDrop::new(Secp256k1 {
            ctx: raw_ctx,
            phantom: PhantomData,
            buf: ptr::null_mut::<[u8;0]>() as *mut [u8] ,
        })
    }
}

impl<'buf> Secp256k1<SignOnlyPreallocated<'buf>> {
    /// Creates a new Secp256k1 context that can only be used for signing
    pub fn preallocated_signing_only(buf: &'buf mut [u8]) -> Result<Secp256k1<SignOnlyPreallocated<'buf>>, Error> {
        Secp256k1::preallocated_gen_new(buf)
    }

    /// Uses the ffi `secp256k1_context_preallocated_size` to check the memory size needed for the context
    #[inline]
    pub fn preallocate_signing_size() -> usize {
        Self::preallocate_size_gen()
    }

    /// Create a context from a raw context.
    ///
    /// # Safety
    /// This is highly unsafe, due to the number of conditions that aren't checked.
    /// * `raw_ctx` needs to be a valid Secp256k1 context pointer.
    /// that was generated by *exactly* the same code/version of the libsecp256k1 used here.
    /// * The capabilities (All/SignOnly/VerifyOnly) of the context *must* match the flags passed to libsecp256k1
    /// when generating the context.
    /// * The user must handle the freeing of the context(using the correct functions) by himself.
    /// * This list *is not* exhaustive, and any violation may lead to Undefined Behavior.,
    ///
    pub unsafe fn from_raw_signining_only(raw_ctx: *mut ffi::Context) -> ManuallyDrop<Secp256k1<SignOnlyPreallocated<'buf>>> {
        ManuallyDrop::new(Secp256k1 {
            ctx: raw_ctx,
            phantom: PhantomData,
            buf: ptr::null_mut::<[u8;0]>() as *mut [u8] ,
        })
    }
}

impl<'buf> Secp256k1<VerifyOnlyPreallocated<'buf>> {
    /// Creates a new Secp256k1 context that can only be used for verification
    pub fn preallocated_verification_only(buf: &'buf mut [u8]) -> Result<Secp256k1<VerifyOnlyPreallocated<'buf>>, Error> {
        Secp256k1::preallocated_gen_new(buf)
    }

    /// Uses the ffi `secp256k1_context_preallocated_size` to check the memory size needed for the context
    #[inline]
    pub fn preallocate_verification_size() -> usize {
        Self::preallocate_size_gen()
    }

    /// Create a context from a raw context.
    ///
    /// # Safety
    /// This is highly unsafe, due to the number of conditions that aren't checked.
    /// * `raw_ctx` needs to be a valid Secp256k1 context pointer.
    /// that was generated by *exactly* the same code/version of the libsecp256k1 used here.
    /// * The capabilities (All/SignOnly/VerifyOnly) of the context *must* match the flags passed to libsecp256k1
    /// when generating the context.
    /// * The user must handle the freeing of the context(using the correct functions) by himself.
    /// * This list *is not* exhaustive, and any violation may lead to Undefined Behavior.,
    ///
    pub unsafe fn from_raw_verification_only(raw_ctx: *mut ffi::Context) -> ManuallyDrop<Secp256k1<VerifyOnlyPreallocated<'buf>>> {
        ManuallyDrop::new(Secp256k1 {
            ctx: raw_ctx,
            phantom: PhantomData,
            buf: ptr::null_mut::<[u8;0]>() as *mut [u8] ,
        })
    }
}