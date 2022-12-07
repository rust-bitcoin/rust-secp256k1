use core::marker::PhantomData;
use core::mem::ManuallyDrop;

use crate::{Error, Secp256k1};
use crate::ffi::{self, CPtr, types::AlignedType};
use crate::ffi::types::{c_uint, c_void};

#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
pub use self::alloc_only::*;

#[cfg(all(feature = "global-context", feature = "std"))]
#[cfg_attr(docsrs, doc(cfg(all(feature = "global-context", feature = "std"))))]
/// Module implementing a singleton pattern for a global `Secp256k1` context.
pub mod global {

    use std::ops::Deref;
    use std::sync::Once;

    use crate::{All, Secp256k1};

    /// Proxy struct for global `SECP256K1` context.
    #[derive(Debug, Copy, Clone)]
    pub struct GlobalContext {
        __private: (),
    }

    /// A global static context to avoid repeatedly creating contexts.
    ///
    /// If `rand-std` feature is enabled, context will have been randomized using `thread_rng`.
    ///
    /// ```
    /// # #[cfg(all(feature = "global-context", feature = "rand-std"))] {
    /// use secp256k1::{PublicKey, SECP256K1};
    /// use secp256k1::rand::thread_rng;
    /// let _ = SECP256K1.generate_keypair(&mut thread_rng());
    /// # }
    /// ```
    pub static SECP256K1: &GlobalContext = &GlobalContext { __private: () };

    impl Deref for GlobalContext {
        type Target = Secp256k1<All>;

        #[allow(unused_mut)]    // Unused when `rand-std` is not enabled.
        fn deref(&self) -> &Self::Target {
            static ONCE: Once = Once::new();
            static mut CONTEXT: Option<Secp256k1<All>> = None;
            ONCE.call_once(|| unsafe {
                let mut ctx = Secp256k1::new();
                #[cfg(all(not(target_arch = "wasm32"), feature = "rand-std", not(feature = "global-context-less-secure")))]
                {
                    ctx.randomize(&mut rand::thread_rng());
                }
                CONTEXT = Some(ctx);
            });
            unsafe { CONTEXT.as_ref().unwrap() }
        }
    }
}


/// A trait for all kinds of contexts that lets you define the exact flags and a function to
/// deallocate memory. It isn't possible to implement this for types outside this crate.
pub unsafe trait Context : private::Sealed {
    /// Flags for the ffi.
    const FLAGS: c_uint;
    /// A constant description of the context.
    const DESCRIPTION: &'static str;
    /// A function to deallocate the memory when the context is dropped.
    unsafe fn deallocate(ptr: *mut u8, size: usize);
}

/// Marker trait for indicating that an instance of `Secp256k1` can be used for signing.
pub trait Signing: Context {}

/// Marker trait for indicating that an instance of `Secp256k1` can be used for verification.
pub trait Verification: Context {}

/// Represents the set of capabilities needed for signing with a user preallocated memory.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SignOnlyPreallocated<'buf> {
    phantom: PhantomData<&'buf ()>,
}

/// Represents the set of capabilities needed for verification with a user preallocated memory.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VerifyOnlyPreallocated<'buf> {
    phantom: PhantomData<&'buf ()>,
}

/// Represents the set of all capabilities with a user preallocated memory.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AllPreallocated<'buf> {
    phantom: PhantomData<&'buf ()>,
}

mod private {
    use super::*;
    pub trait Sealed {}

    impl<'buf> Sealed for AllPreallocated<'buf> {}
    impl<'buf> Sealed for VerifyOnlyPreallocated<'buf> {}
    impl<'buf> Sealed for SignOnlyPreallocated<'buf> {}
}

#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(any(feature = "alloc"))))]
mod alloc_only {
    use crate::alloc::alloc;

    use core::marker::PhantomData;

    use super::private;
    use crate::ffi::{self, types::{c_uint, c_void}};
    use crate::{Secp256k1, Signing, Verification, Context, AlignedType};

    impl private::Sealed for SignOnly {}
    impl private::Sealed for All {}
    impl private::Sealed for VerifyOnly {}

    const ALIGN_TO: usize = core::mem::align_of::<AlignedType>();

    /// Represents the set of capabilities needed for signing.
    #[cfg_attr(docsrs, doc(cfg(any(feature = "std", feature = "alloc"))))]
    #[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub enum SignOnly {}

    /// Represents the set of capabilities needed for verification.
    #[cfg_attr(docsrs, doc(cfg(any(feature = "std", feature = "alloc"))))]
    #[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub enum VerifyOnly {}

    /// Represents the set of all capabilities.
    #[cfg_attr(docsrs, doc(cfg(any(feature = "std", feature = "alloc"))))]
    #[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub enum All {}

    impl Signing for SignOnly {}
    impl Signing for All {}

    impl Verification for VerifyOnly {}
    impl Verification for All {}

    unsafe impl Context for SignOnly {
        const FLAGS: c_uint = ffi::SECP256K1_START_SIGN;
        const DESCRIPTION: &'static str = "signing only";

        unsafe fn deallocate(ptr: *mut u8, size: usize) {
            let layout = alloc::Layout::from_size_align(size, ALIGN_TO).unwrap();
            alloc::dealloc(ptr, layout);
        }
    }

    unsafe impl Context for VerifyOnly {
        const FLAGS: c_uint = ffi::SECP256K1_START_VERIFY;
        const DESCRIPTION: &'static str = "verification only";

        unsafe fn deallocate(ptr: *mut u8, size: usize) {
            let layout = alloc::Layout::from_size_align(size, ALIGN_TO).unwrap();
            alloc::dealloc(ptr, layout);
        }
    }

    unsafe impl Context for All {
        const FLAGS: c_uint = VerifyOnly::FLAGS | SignOnly::FLAGS;
        const DESCRIPTION: &'static str = "all capabilities";

        unsafe fn deallocate(ptr: *mut u8, size: usize) {
            let layout = alloc::Layout::from_size_align(size, ALIGN_TO).unwrap();
            alloc::dealloc(ptr, layout);
        }
    }

    impl<C: Context> Secp256k1<C> {
        /// Lets you create a context in a generic manner (sign/verify/all).
        ///
        /// If `rand-std` feature is enabled, context will have been randomized using `thread_rng`.
        /// If `rand-std` feature is not enabled please consider randomizing the context as follows:
        /// ```
        /// # #[cfg(all(feature = "std", feature = "rand-std"))] {
        /// # use secp256k1::Secp256k1;
        /// # use secp256k1::rand::{thread_rng, RngCore};
        /// let mut ctx = Secp256k1::new();
        /// # let mut rng = thread_rng();
        /// # let mut seed = [0u8; 32];
        /// # rng.fill_bytes(&mut seed);
        /// // let seed = <32 bytes of random data>
        /// ctx.seeded_randomize(&seed);
        /// # }
        /// ```
        #[cfg_attr(not(feature = "rand-std"), allow(clippy::let_and_return, unused_mut))]
        pub fn gen_new() -> Secp256k1<C> {
            #[cfg(target_arch = "wasm32")]
            ffi::types::sanity_checks_for_wasm();

            let size = unsafe { ffi::secp256k1_context_preallocated_size(C::FLAGS) };
            let layout = alloc::Layout::from_size_align(size, ALIGN_TO).unwrap();
            let ptr = unsafe {alloc::alloc(layout)};

            #[allow(unused_mut)] // ctx is not mutated under some feature combinations.
            let mut ctx = Secp256k1 {
                ctx: unsafe { ffi::secp256k1_context_preallocated_create(ptr as *mut c_void, C::FLAGS) },
                phantom: PhantomData,
                size,
            };

            #[cfg(all(not(target_arch = "wasm32"), feature = "rand-std", not(feature = "global-context-less-secure")))]
            {
                ctx.randomize(&mut rand::thread_rng());
            }

            #[allow(clippy::let_and_return)] // as for unusted_mut
            ctx
        }
    }

    impl Secp256k1<All> {
        /// Creates a new Secp256k1 context with all capabilities.
        ///
        /// If `rand-std` feature is enabled, context will have been randomized using `thread_rng`.
        /// If `rand-std` feature is not enabled please consider randomizing the context (see docs
        /// for `Secp256k1::gen_new()`).
        pub fn new() -> Secp256k1<All> {
            Secp256k1::gen_new()
        }
    }

    impl Secp256k1<SignOnly> {
        /// Creates a new Secp256k1 context that can only be used for signing.
        ///
        /// If `rand-std` feature is enabled, context will have been randomized using `thread_rng`.
        /// If `rand-std` feature is not enabled please consider randomizing the context (see docs
        /// for `Secp256k1::gen_new()`).
        pub fn signing_only() -> Secp256k1<SignOnly> {
            Secp256k1::gen_new()
        }
    }

    impl Secp256k1<VerifyOnly> {
        /// Creates a new Secp256k1 context that can only be used for verification.
        ///
        /// If `rand-std` feature is enabled, context will have been randomized using `thread_rng`.
        /// If `rand-std` feature is not enabled please consider randomizing the context (see docs
        /// for `Secp256k1::gen_new()`).
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
            let size = unsafe {ffi::secp256k1_context_preallocated_clone_size(self.ctx as _)};
            let layout = alloc::Layout::from_size_align(size, ALIGN_TO).unwrap();
            let ptr = unsafe {alloc::alloc(layout)};
            Secp256k1 {
                ctx: unsafe { ffi::secp256k1_context_preallocated_clone(self.ctx, ptr as *mut c_void) },
                phantom: PhantomData,
                size,
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

    unsafe fn deallocate(_ptr: *mut u8, _size: usize) {
        // Allocated by the user
    }
}

unsafe impl<'buf> Context for VerifyOnlyPreallocated<'buf> {
    const FLAGS: c_uint = ffi::SECP256K1_START_VERIFY;
    const DESCRIPTION: &'static str = "verification only";

    unsafe fn deallocate(_ptr: *mut u8, _size: usize) {
        // Allocated by the user.
    }
}

unsafe impl<'buf> Context for AllPreallocated<'buf> {
    const FLAGS: c_uint = SignOnlyPreallocated::FLAGS | VerifyOnlyPreallocated::FLAGS;
    const DESCRIPTION: &'static str = "all capabilities";

    unsafe fn deallocate(_ptr: *mut u8, _size: usize) {
        // Allocated by the user.
    }
}

/// Trait marking that a particular context object internally points to
/// memory that must outlive `'a`
///
/// # Safety
///
/// This trait is used internally to gate which context markers can safely
/// be used with the `preallocated_gen_new` function. Do not implement it
/// on your own structures.
pub unsafe trait PreallocatedContext<'a> {}

unsafe impl<'buf> PreallocatedContext<'buf> for AllPreallocated<'buf> {}
unsafe impl<'buf> PreallocatedContext<'buf> for SignOnlyPreallocated<'buf> {}
unsafe impl<'buf> PreallocatedContext<'buf> for VerifyOnlyPreallocated<'buf> {}

impl<'buf, C: Context + PreallocatedContext<'buf>> Secp256k1<C> {
    /// Lets you create a context with a preallocated buffer in a generic manner (sign/verify/all).
    pub fn preallocated_gen_new(buf: &'buf mut [AlignedType]) -> Result<Secp256k1<C>, Error> {
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
            size: 0, // We don't care about the size because it's the caller responsibility to deallocate.
        })
    }
}

impl<'buf> Secp256k1<AllPreallocated<'buf>> {
    /// Creates a new Secp256k1 context with all capabilities
    pub fn preallocated_new(buf: &'buf mut [AlignedType]) -> Result<Secp256k1<AllPreallocated<'buf>>, Error> {
        Secp256k1::preallocated_gen_new(buf)
    }
    /// Uses the ffi `secp256k1_context_preallocated_size` to check the memory size needed for a context.
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
            size: 0, // We don't care about the size because it's the caller responsibility to deallocate.
        })
    }
}

impl<'buf> Secp256k1<SignOnlyPreallocated<'buf>> {
    /// Creates a new Secp256k1 context that can only be used for signing.
    pub fn preallocated_signing_only(buf: &'buf mut [AlignedType]) -> Result<Secp256k1<SignOnlyPreallocated<'buf>>, Error> {
        Secp256k1::preallocated_gen_new(buf)
    }

    /// Uses the ffi `secp256k1_context_preallocated_size` to check the memory size needed for the context.
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
    /// * This list *is not* exhaustive, and any violation may lead to Undefined Behavior.
    ///
    pub unsafe fn from_raw_signining_only(raw_ctx: *mut ffi::Context) -> ManuallyDrop<Secp256k1<SignOnlyPreallocated<'buf>>> {
        ManuallyDrop::new(Secp256k1 {
            ctx: raw_ctx,
            phantom: PhantomData,
            size: 0, // We don't care about the size because it's the caller responsibility to deallocate.
        })
    }
}

impl<'buf> Secp256k1<VerifyOnlyPreallocated<'buf>> {
    /// Creates a new Secp256k1 context that can only be used for verification
    pub fn preallocated_verification_only(buf: &'buf mut [AlignedType]) -> Result<Secp256k1<VerifyOnlyPreallocated<'buf>>, Error> {
        Secp256k1::preallocated_gen_new(buf)
    }

    /// Uses the ffi `secp256k1_context_preallocated_size` to check the memory size needed for the context.
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
    /// * This list *is not* exhaustive, and any violation may lead to Undefined Behavior.
    ///
    pub unsafe fn from_raw_verification_only(raw_ctx: *mut ffi::Context) -> ManuallyDrop<Secp256k1<VerifyOnlyPreallocated<'buf>>> {
        ManuallyDrop::new(Secp256k1 {
            ctx: raw_ctx,
            phantom: PhantomData,
            size: 0, // We don't care about the size because it's the caller responsibility to deallocate.
        })
    }
}
