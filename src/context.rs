// SPDX-License-Identifier: CC0-1.0

use core::marker::PhantomData;
use core::mem::ManuallyDrop;
use core::ptr::NonNull;

#[cfg(feature = "alloc")]
pub use self::alloc_only::{All, SignOnly, VerifyOnly};
use crate::ffi::types::{c_uint, c_void, AlignedType};
use crate::ffi::{self, CPtr};
use crate::{Error, Secp256k1};

#[cfg(feature = "std")]
mod internal {
    use std::cell::RefCell;
    use std::marker::PhantomData;
    use std::mem::ManuallyDrop;
    use std::ptr::NonNull;

    use secp256k1_sys as ffi;

    use crate::{All, Context, Secp256k1};

    thread_local! {
        static SECP256K1: RefCell<Secp256k1<All>> = RefCell::new(Secp256k1::new());
        static RAND_SEED: RefCell<[u8; 32]> = const { RefCell::new([0; 32]) };
    }

    /// Borrows the global context and do some operation on it.
    ///
    /// If provided, after the operation is complete, [`rerandomize_global_context`]
    /// is called on the context. If you have some random data available,
    pub fn with_global_context<T, Ctx: Context, F: FnOnce(&Secp256k1<Ctx>) -> T>(
        f: F,
        rerandomize_seed: Option<&[u8; 32]>,
    ) -> T {
        with_raw_global_context(
            |ctx| {
                let secp = ManuallyDrop::new(Secp256k1 { ctx, phantom: PhantomData });
                f(&*secp)
            },
            rerandomize_seed,
        )
    }

    /// Borrows the global context as a raw pointer and do some operation on it.
    ///
    /// If provided, after the operation is complete, [`rerandomize_global_context`]
    /// is called on the context. If you have some random data available,
    pub fn with_raw_global_context<T, F: FnOnce(NonNull<ffi::Context>) -> T>(
        f: F,
        rerandomize_seed: Option<&[u8; 32]>,
    ) -> T {
        SECP256K1.with(|secp| {
            let borrow = secp.borrow();
            let ret = f(borrow.ctx);
            drop(borrow);

            if let Some(seed) = rerandomize_seed {
                rerandomize_global_context(seed);
            }
            ret
        })
    }

    /// Rerandomize the global context, using the given data as a seed.
    ///
    /// The provided data will be mixed with the entropy from previous calls in a timing
    /// analysis resistant way. It is safe to directly pass secret data to this function.
    pub fn rerandomize_global_context(seed: &[u8; 32]) {
        SECP256K1.with(|secp| {
            RAND_SEED.with(|rand_seed| {
                let mut old_seed = rand_seed.borrow_mut();
                let mut new_seed = [0; 32];
                // We don't have direct access to sha256 except through the default nonce
                // functions. The ECDSA one uses RFC6979 which is absurdly slow, but the
                // Schnorr one is not too bad.
                unsafe {
                    assert_eq!(
                        (ffi::secp256k1_nonce_function_bip340.unwrap())(
                            new_seed.as_mut_ptr(),
                            seed.as_ptr(),     // msg
                            seed.len(),        // msg len
                            old_seed.as_ptr(), // key32
                            old_seed.as_ptr(), // xonly_pk32
                            b"rust-secp-randomize".as_ptr(),
                            b"rust-secp-randomize".len(),
                            core::ptr::null_mut(),
                        ),
                        1,
                        "calling bip340 nonce function failed",
                    );
                }

                // If we have access to the thread rng then use it as well.
                #[cfg(feature = "rand")]
                {
                    let mask: [u8; 32] = rand::random();
                    for (byte, mask) in new_seed.iter_mut().zip(mask.iter()) {
                        *byte ^= *mask;
                    }
                }

                // Actual rerandomization
                let mut borrow = secp.borrow_mut();
                borrow.seeded_randomize(&new_seed);
                old_seed.copy_from_slice(&new_seed);
            });
        });
    }
}
#[cfg(feature = "std")]
pub use internal::{rerandomize_global_context, with_global_context, with_raw_global_context};

#[cfg(all(feature = "global-context", feature = "std"))]
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
    /// If `rand` and `std` feature is enabled, context will have been randomized using
    /// `rng`.
    ///
    /// ```
    /// # #[cfg(all(feature = "global-context", feature = "rand", feature = "std"))] {
    /// use secp256k1::{PublicKey, SECP256K1};
    /// let _ = SECP256K1.generate_keypair(&mut rand::rng());
    /// # }
    /// ```
    pub static SECP256K1: &GlobalContext = &GlobalContext { __private: () };

    impl Deref for GlobalContext {
        type Target = Secp256k1<All>;

        #[allow(unused_mut)] // Unused when `rand` + `std` is not enabled.
        #[allow(static_mut_refs)] // The "proper" way to do this is with OnceLock (MSRV 1.70) or LazyLock (MSRV 1.80)
                                  // See https://doc.rust-lang.org/nightly/edition-guide/rust-2024/static-mut-references.html
        fn deref(&self) -> &Self::Target {
            static ONCE: Once = Once::new();
            static mut CONTEXT: Option<Secp256k1<All>> = None;
            ONCE.call_once(|| unsafe {
                CONTEXT = Some(Secp256k1::new());
            });
            unsafe { CONTEXT.as_ref().unwrap() }
        }
    }
}

/// A trait for all kinds of contexts that lets you define the exact flags and a function to
/// deallocate memory. It isn't possible to implement this for types outside this crate.
///
/// # Safety
///
/// This trait is marked unsafe to allow unsafe implementations of `deallocate`.
pub unsafe trait Context: private::Sealed {
    /// Flags for the ffi.
    const FLAGS: c_uint;
    /// A constant description of the context.
    const DESCRIPTION: &'static str;
    /// A function to deallocate the memory when the context is dropped.
    ///
    /// # Safety
    ///
    /// `ptr` must be valid. Further safety constraints may be imposed by [`std::alloc::dealloc`].
    unsafe fn deallocate(ptr: *mut u8, size: usize);
}

/// Marker trait for indicating that an instance of [`Secp256k1`] can be used for signing.
pub trait Signing: Context {}

/// Marker trait for indicating that an instance of [`Secp256k1`] can be used for verification.
pub trait Verification: Context {}

/// Represents the set of capabilities needed for signing (preallocated memory).
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SignOnlyPreallocated<'buf> {
    phantom: PhantomData<&'buf ()>,
}

/// Represents the set of capabilities needed for verification (preallocated memory).
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VerifyOnlyPreallocated<'buf> {
    phantom: PhantomData<&'buf ()>,
}

/// Represents the set of all capabilities (preallocated memory).
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AllPreallocated<'buf> {
    phantom: PhantomData<&'buf ()>,
}

mod private {
    use super::*;
    pub trait Sealed {}

    impl Sealed for AllPreallocated<'_> {}
    impl Sealed for VerifyOnlyPreallocated<'_> {}
    impl Sealed for SignOnlyPreallocated<'_> {}
}

#[cfg(feature = "alloc")]
mod alloc_only {
    use core::marker::PhantomData;
    use core::ptr::NonNull;

    use super::private;
    use crate::alloc::alloc;
    use crate::ffi::types::{c_uint, c_void};
    use crate::ffi::{self};
    use crate::{AlignedType, Context, Secp256k1, Signing, Verification};

    impl private::Sealed for SignOnly {}
    impl private::Sealed for All {}
    impl private::Sealed for VerifyOnly {}

    const ALIGN_TO: usize = core::mem::align_of::<AlignedType>();

    /// Represents the set of capabilities needed for signing.
    #[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub enum SignOnly {}

    /// Represents the set of capabilities needed for verification.
    #[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub enum VerifyOnly {}

    /// Represents the set of all capabilities.
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
        /// If `rand` and `std` feature is enabled, context will have been randomized using
        /// `rng`.
        /// If `rand` or `std` feature is not enabled please consider randomizing the context as
        /// follows:
        /// ```
        /// # #[cfg(all(feature = "rand", feature = "std"))] {
        /// # use secp256k1::Secp256k1;
        /// # use secp256k1::rand::{rng, RngCore};
        /// let mut ctx = Secp256k1::new();
        /// # let mut rng = rng();
        /// # let mut seed = [0u8; 32];
        /// # rng.fill_bytes(&mut seed);
        /// // let seed = <32 bytes of random data>
        /// ctx.seeded_randomize(&seed);
        /// # }
        /// ```
        #[cfg_attr(
            not(all(feature = "rand", feature = "std")),
            allow(clippy::let_and_return, unused_mut)
        )]
        pub fn gen_new() -> Secp256k1<C> {
            #[cfg(target_arch = "wasm32")]
            ffi::types::sanity_checks_for_wasm();

            let size = unsafe { ffi::secp256k1_context_preallocated_size(C::FLAGS) };
            let layout = alloc::Layout::from_size_align(size, ALIGN_TO).unwrap();
            let ptr = unsafe { alloc::alloc(layout) };
            let ptr = NonNull::new(ptr as *mut c_void)
                .unwrap_or_else(|| alloc::handle_alloc_error(layout));

            #[allow(unused_mut)] // ctx is not mutated under some feature combinations.
            let mut ctx = Secp256k1 {
                ctx: unsafe { ffi::secp256k1_context_preallocated_create(ptr, C::FLAGS) },
                phantom: PhantomData,
            };

            #[cfg(all(
                not(target_arch = "wasm32"),
                feature = "rand",
                feature = "std",
                not(feature = "global-context-less-secure")
            ))]
            {
                ctx.randomize(&mut rand::rng());
            }

            #[allow(clippy::let_and_return)] // as for unusted_mut
            ctx
        }
    }

    impl Secp256k1<All> {
        /// Creates a new Secp256k1 context with all capabilities.
        ///
        /// If `rand` and `std` feature is enabled, context will have been randomized using
        /// `rng`.
        /// If `rand` or `std` feature is not enabled please consider randomizing the context (see
        /// docs for `Secp256k1::gen_new()`).
        pub fn new() -> Secp256k1<All> { Secp256k1::gen_new() }
    }

    impl Secp256k1<SignOnly> {
        /// Creates a new Secp256k1 context that can only be used for signing.
        ///
        /// If `rand` and `std` feature is enabled, context will have been randomized using
        /// `rng`.
        /// If `rand` or `std` feature is not enabled please consider randomizing the context (see
        /// docs for `Secp256k1::gen_new()`).
        pub fn signing_only() -> Secp256k1<SignOnly> { Secp256k1::gen_new() }
    }

    impl Secp256k1<VerifyOnly> {
        /// Creates a new Secp256k1 context that can only be used for verification.
        ///
        /// If `rand` and `std` feature is enabled, context will have been randomized using
        /// `rng`.
        /// If `rand` or `std` feature is not enabled please consider randomizing the context (see
        /// docs for `Secp256k1::gen_new()`).
        pub fn verification_only() -> Secp256k1<VerifyOnly> { Secp256k1::gen_new() }
    }

    impl Default for Secp256k1<All> {
        fn default() -> Self { Self::new() }
    }

    impl<C: Context> Clone for Secp256k1<C> {
        fn clone(&self) -> Secp256k1<C> {
            let size = unsafe { ffi::secp256k1_context_preallocated_clone_size(self.ctx.as_ptr()) };
            let layout = alloc::Layout::from_size_align(size, ALIGN_TO).unwrap();
            let ptr = unsafe { alloc::alloc(layout) };
            let ptr = NonNull::new(ptr as *mut c_void)
                .unwrap_or_else(|| alloc::handle_alloc_error(layout));

            Secp256k1 {
                ctx: unsafe { ffi::secp256k1_context_preallocated_clone(self.ctx.as_ptr(), ptr) },
                phantom: PhantomData,
            }
        }
    }
}

impl Signing for SignOnlyPreallocated<'_> {}
impl Signing for AllPreallocated<'_> {}

impl Verification for VerifyOnlyPreallocated<'_> {}
impl Verification for AllPreallocated<'_> {}

unsafe impl Context for SignOnlyPreallocated<'_> {
    const FLAGS: c_uint = ffi::SECP256K1_START_SIGN;
    const DESCRIPTION: &'static str = "signing only";

    unsafe fn deallocate(_ptr: *mut u8, _size: usize) {
        // Allocated by the user
    }
}

unsafe impl Context for VerifyOnlyPreallocated<'_> {
    const FLAGS: c_uint = ffi::SECP256K1_START_VERIFY;
    const DESCRIPTION: &'static str = "verification only";

    unsafe fn deallocate(_ptr: *mut u8, _size: usize) {
        // Allocated by the user.
    }
}

unsafe impl Context for AllPreallocated<'_> {
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
        // Safe because buf is not null since it is not empty.
        let buf = unsafe { NonNull::new_unchecked(buf.as_mut_c_ptr() as *mut c_void) };

        Ok(Secp256k1 {
            ctx: unsafe { ffi::secp256k1_context_preallocated_create(buf, AllPreallocated::FLAGS) },
            phantom: PhantomData,
        })
    }
}

impl<'buf> Secp256k1<AllPreallocated<'buf>> {
    /// Creates a new Secp256k1 context with all capabilities.
    pub fn preallocated_new(
        buf: &'buf mut [AlignedType],
    ) -> Result<Secp256k1<AllPreallocated<'buf>>, Error> {
        Secp256k1::preallocated_gen_new(buf)
    }
    /// Uses the ffi `secp256k1_context_preallocated_size` to check the memory size needed for a context.
    pub fn preallocate_size() -> usize { Self::preallocate_size_gen() }

    /// Creates a context from a raw context.
    ///
    /// The returned [`core::mem::ManuallyDrop`] context will never deallocate the memory pointed to
    /// by `raw_ctx` nor destroy the context. This may lead to memory leaks. `ManuallyDrop::drop`
    /// (or [`core::ptr::drop_in_place`]) will only destroy the context; the caller is required to
    /// free the memory.
    ///
    /// # Safety
    ///
    /// This is highly unsafe due to a number of conditions that aren't checked, specifically:
    ///
    /// * `raw_ctx` must be a valid pointer (live, aligned...) to memory that was initialized by
    ///   `secp256k1_context_preallocated_create` (either called directly or from this library by
    ///   one of the context creation methods - all of which call it internally).
    /// * The version of `libsecp256k1` used to create `raw_ctx` must be **exactly the one linked
    ///   into this library**.
    /// * The lifetime of the `raw_ctx` pointer must outlive `'buf`.
    /// * `raw_ctx` must point to writable memory (cannot be `ffi::secp256k1_context_no_precomp`).
    pub unsafe fn from_raw_all(
        raw_ctx: NonNull<ffi::Context>,
    ) -> ManuallyDrop<Secp256k1<AllPreallocated<'buf>>> {
        ManuallyDrop::new(Secp256k1 { ctx: raw_ctx, phantom: PhantomData })
    }
}

impl<'buf> Secp256k1<SignOnlyPreallocated<'buf>> {
    /// Creates a new Secp256k1 context that can only be used for signing.
    pub fn preallocated_signing_only(
        buf: &'buf mut [AlignedType],
    ) -> Result<Secp256k1<SignOnlyPreallocated<'buf>>, Error> {
        Secp256k1::preallocated_gen_new(buf)
    }

    /// Uses the ffi `secp256k1_context_preallocated_size` to check the memory size needed for the context.
    #[inline]
    pub fn preallocate_signing_size() -> usize { Self::preallocate_size_gen() }

    /// Creates a context from a raw context that can only be used for signing.
    ///
    /// # Safety
    ///
    /// Please see [`Secp256k1::from_raw_all`] for full documentation and safety requirements.
    pub unsafe fn from_raw_signing_only(
        raw_ctx: NonNull<ffi::Context>,
    ) -> ManuallyDrop<Secp256k1<SignOnlyPreallocated<'buf>>> {
        ManuallyDrop::new(Secp256k1 { ctx: raw_ctx, phantom: PhantomData })
    }
}

impl<'buf> Secp256k1<VerifyOnlyPreallocated<'buf>> {
    /// Creates a new Secp256k1 context that can only be used for verification
    pub fn preallocated_verification_only(
        buf: &'buf mut [AlignedType],
    ) -> Result<Secp256k1<VerifyOnlyPreallocated<'buf>>, Error> {
        Secp256k1::preallocated_gen_new(buf)
    }

    /// Uses the ffi `secp256k1_context_preallocated_size` to check the memory size needed for the context.
    #[inline]
    pub fn preallocate_verification_size() -> usize { Self::preallocate_size_gen() }

    /// Creates a context from a raw context that can only be used for verification.
    ///
    /// # Safety
    ///
    /// Please see [`Secp256k1::from_raw_all`] for full documentation and safety requirements.
    pub unsafe fn from_raw_verification_only(
        raw_ctx: NonNull<ffi::Context>,
    ) -> ManuallyDrop<Secp256k1<VerifyOnlyPreallocated<'buf>>> {
        ManuallyDrop::new(Secp256k1 { ctx: raw_ctx, phantom: PhantomData })
    }
}
