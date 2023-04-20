// SPDX-License-Identifier: CC0-1.0

use core::marker::PhantomData;
use core::mem::ManuallyDrop;
use core::ptr::NonNull;

#[cfg(feature = "alloc")]
pub use self::alloc_only::*;
use crate::ffi::types::{c_uint, c_void, AlignedType};
use crate::ffi::{self, CPtr};
use crate::{Error, Secp256k1};

/// TODO: Rename to global and remove the other one.
#[cfg(feature = "std")]
pub mod _global {
    use core::convert::TryFrom;
    use core::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
    use std::ops::Deref;
    use std::sync::Once;

    use super::alloc_only::{SignOnly, VerifyOnly};
    use crate::ffi::CPtr;
    use crate::{ffi, Secp256k1};

    struct GlobalVerifyContext {
        __private: (),
    }

    impl Deref for GlobalVerifyContext {
        type Target = Secp256k1<VerifyOnly>;

        fn deref(&self) -> &Self::Target {
            static ONCE: Once = Once::new();
            static mut CONTEXT: Option<Secp256k1<VerifyOnly>> = None;
            ONCE.call_once(|| unsafe {
                let ctx = Secp256k1::verification_only();
                CONTEXT = Some(ctx);
            });
            unsafe { CONTEXT.as_ref().unwrap() }
        }
    }

    struct GlobalSignContext {
        __private: (),
    }

    impl Deref for GlobalSignContext {
        type Target = Secp256k1<SignOnly>;

        fn deref(&self) -> &Self::Target {
            static ONCE: Once = Once::new();
            static mut CONTEXT: Option<Secp256k1<SignOnly>> = None;
            ONCE.call_once(|| unsafe {
                let ctx = Secp256k1::signing_only();
                CONTEXT = Some(ctx);
            });
            unsafe { CONTEXT.as_ref().unwrap() }
        }
    }

    static GLOBAL_VERIFY_CONTEXT: &GlobalVerifyContext = &GlobalVerifyContext { __private: () };

    static GLOBAL_SIGN_CONTEXTS: [&GlobalSignContext; 2] =
        [&GlobalSignContext { __private: () }, &GlobalSignContext { __private: () }];

    static SIGN_CONTEXTS_DIRTY: [AtomicBool; 2] = [AtomicBool::new(false), AtomicBool::new(false)];

    /// The sign contexts semaphore, stores two flags in the lowest bits and the reader count
    /// in the remaining bits. Thus adding or subtracting 4 increments/decrements the counter.
    ///
    /// The two flags are:
    /// * Active context bit - least significant (0b1)
    /// * Swap bit - second least significant (0b10) (see [`needs_swap`]).
    static SIGN_CONTEXTS_SEM: AtomicUsize = AtomicUsize::new(0);

    /// Re-randomization lock, true==locked, false==unlocked.
    static RERAND_LOCK: AtomicBool = AtomicBool::new(false);

    /// Stores the seed for RNG. Notably it doesn't matter that a thread may read "inconsistent"
    /// content because it's all random data. If the array is being overwritten while being read it
    /// cannot worsen entropy and the exact data doesn't matter.
    ///
    /// We still have to use atomics because multiple mutable accesses is undefined behavior in Rust.
    static GLOBAL_SEED: [AtomicU8; 32] = init_seed_buffer();

    /// Rerandomizes inactive context using first half of `seed` and stores the second half in the
    /// global seed buffer used for later rerandomizations.
    pub fn reseed(seed: &[u8; 64]) {
        if rerand_lock() {
            let last = sign_contexts_inc();
            let other = 1 - active_context(last);

            _rerandomize(other, <&[u8; 32]>::try_from(&seed[0..32]).expect("32 bytes"));
            clear_context_dirty(other);
            rerand_unlock();

            sign_contexts_dec();

            // We unlock before setting the swap bit so that soon as another
            // reader sees the swap bit set they can grab the rand lock.
            sign_contexts_set_swap_bit();
        }
        write_global_seed(<&[u8; 32]>::try_from(&seed[32..64]).expect("32 bytes"));
    }

    /// Perform function using the current active global verification context.
    ///
    /// # Safety
    ///
    /// TODO: Write safety docs.
    pub unsafe fn with_global_verify_context<F: FnOnce(*const ffi::Context) -> R, R>(f: F) -> R {
        f(GLOBAL_VERIFY_CONTEXT.ctx.as_ptr())
    }

    /// Perform function using the current active global signing context.
    ///
    /// # Safety
    ///
    /// TODO: Write safety docs.
    pub unsafe fn with_global_signing_context<F: FnOnce(*const ffi::Context) -> R, R>(f: F) -> R {
        let last = sign_contexts_inc();

        // Shift 2 for the 2 flag bits.
        if last >= usize::MAX >> 2 {
            // Having this many threads should be impossible so if this happens it's because of a bug.
            panic!("too many readers");
        }

        let active = active_context(last);

        let res = f(GLOBAL_SIGN_CONTEXTS[active].ctx.as_ptr());
        set_context_dirty(active);

        let last = sign_contexts_dec();

        // No readers and needs swap.
        if last & !1 == 0b10 {
            if let Some(ctx) = sign_contexts_swap(last) {
                rerandomize_with_global_seed(ctx);
            }
        }
        res
    }

    /// Returns the index (into GLOBAL_SIGN_CONTEXTS) of the active context.
    fn active_context(sem: usize) -> usize { sem & 1 }

    /// Attempts to lock the rerand lock.
    ///
    /// # Returns
    ///
    /// `true` if lock was acquired, false otherwise.
    fn rerand_lock() -> bool {
        RERAND_LOCK.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).is_ok()
    }

    /// Attempts to unlock the rerand lock.
    ///
    /// # Returns
    ///
    /// `true` if the lock was unlocked by this operation.
    fn rerand_unlock() -> bool {
        RERAND_LOCK.compare_exchange(true, false, Ordering::Acquire, Ordering::Relaxed).is_ok()
    }

    /// Increments the sign-contexts reader semaphore.
    // FIXME: What happens if we have more than usize::MAX >> 2 readers i.e., overflow?
    fn sign_contexts_inc() -> usize { SIGN_CONTEXTS_SEM.fetch_add(4, Ordering::Acquire) }

    /// Decrements the sign-contexts reader semaphore.
    fn sign_contexts_dec() -> usize { SIGN_CONTEXTS_SEM.fetch_sub(4, Ordering::Acquire) }

    /// Swap the active context and clear the swap bit.
    ///
    /// # Panics
    ///
    /// If `lock` has count > 0.
    ///
    /// # Returns
    ///
    /// The now-inactive context index (ie, the index of the context swapped out).
    fn sign_contexts_swap(sem: usize) -> Option<usize> {
        assert!(sem & !0b11 == 0); // reader count == 0
        let new = (sem & !0b10) ^ 0b01; // turn off swap bit, toggle active bit.
        match SIGN_CONTEXTS_SEM.compare_exchange(sem, new, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(last) => Some(active_context(last)),
            // Another reader signaled before we had a chance to swap.
            Err(_) => None,
        }
    }

    /// Unconditionally turns on the "needs swap" bit.
    fn sign_contexts_set_swap_bit() { SIGN_CONTEXTS_SEM.fetch_or(0b10, Ordering::Relaxed); }

    fn set_context_dirty(ctx: usize) {
        assert!(ctx < 2);
        SIGN_CONTEXTS_DIRTY[ctx].store(true, Ordering::Relaxed);
    }

    fn clear_context_dirty(ctx: usize) {
        assert!(ctx < 2);
        SIGN_CONTEXTS_DIRTY[ctx].store(true, Ordering::Relaxed);
    }

    fn write_global_seed(seed: &[u8; 32]) {
        for (i, b) in seed.iter().enumerate() {
            GLOBAL_SEED[i].store(*b, Ordering::Relaxed);
        }
    }

    /// Rerandomize the global signing context using randomness in the global seed.
    fn rerandomize_with_global_seed(ctx: usize) {
        let mut buf = [0_u8; 32];
        for (i, b) in buf.iter_mut().enumerate() {
            let atomic = &GLOBAL_SEED[i];
            *b = atomic.load(Ordering::Relaxed);
        }
        rerandomize(ctx, &buf)
    }

    /// Rerandomize global context index `ctx` using randomness in `seed`.
    fn rerandomize(ctx: usize, seed: &[u8; 32]) {
        assert!(ctx < 2);
        if rerand_lock() {
            _rerandomize(ctx, seed);
            clear_context_dirty(ctx);
            rerand_unlock();

            // We unlock before setting the swap bit so that soon as another
            // reader sees the swap bit set they can grab the rand lock.
            sign_contexts_set_swap_bit();
        }
    }

    /// Should be called with the RERAND_LOCK held.
    fn _rerandomize(ctx: usize, seed: &[u8; 32]) {
        let secp = GLOBAL_SIGN_CONTEXTS[ctx];
        unsafe {
            let err = ffi::secp256k1_context_randomize(secp.ctx, seed.as_c_ptr());
            // This function cannot fail; it has an error return for future-proofing.
            // We do not expose this error since it is impossible to hit, and we have
            // precedent for not exposing impossible errors (for example in
            // `PublicKey::from_secret_key` where it is impossible to create an invalid
            // secret key through the API.)
            // However, if this DOES fail, the result is potentially weaker side-channel
            // resistance, which is deadly and undetectable, so we take out the entire
            // thread to be on the safe side.
            assert_eq!(err, 1);
        }
    }

    // TODO: Find better way to do this.
    #[rustfmt::skip]
    const fn init_seed_buffer() -> [AtomicU8; 32] {
        let buf: [AtomicU8; 32] = [
            AtomicU8::new(0), AtomicU8::new(0), AtomicU8::new(0), AtomicU8::new(0), AtomicU8::new(0), AtomicU8::new(0), AtomicU8::new(0), AtomicU8::new(0),
            AtomicU8::new(0), AtomicU8::new(0), AtomicU8::new(0), AtomicU8::new(0), AtomicU8::new(0), AtomicU8::new(0), AtomicU8::new(0), AtomicU8::new(0),
            AtomicU8::new(0), AtomicU8::new(0), AtomicU8::new(0), AtomicU8::new(0), AtomicU8::new(0), AtomicU8::new(0), AtomicU8::new(0), AtomicU8::new(0),
            AtomicU8::new(0), AtomicU8::new(0), AtomicU8::new(0), AtomicU8::new(0), AtomicU8::new(0), AtomicU8::new(0), AtomicU8::new(0), AtomicU8::new(0),
        ];
        buf
    }
}

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
    /// If `rand-std` feature is enabled, context will have been randomized using `thread_rng`.
    ///
    /// ```
    /// # #[cfg(all(feature = "global-context", feature = "rand-std"))] {
    /// use secp256k1::{PublicKey, SECP256K1};
    /// let _ = SECP256K1.generate_keypair(&mut rand::thread_rng());
    /// # }
    /// ```
    pub static SECP256K1: &GlobalContext = &GlobalContext { __private: () };

    impl Deref for GlobalContext {
        type Target = Secp256k1<All>;

        #[allow(unused_mut)] // Unused when `rand-std` is not enabled.
        fn deref(&self) -> &Self::Target {
            static ONCE: Once = Once::new();
            static mut CONTEXT: Option<Secp256k1<All>> = None;
            ONCE.call_once(|| unsafe {
                let mut ctx = Secp256k1::new();
                #[cfg(all(
                    not(target_arch = "wasm32"),
                    feature = "rand-std",
                    not(feature = "global-context-less-secure")
                ))]
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

    impl<'buf> Sealed for AllPreallocated<'buf> {}
    impl<'buf> Sealed for VerifyOnlyPreallocated<'buf> {}
    impl<'buf> Sealed for SignOnlyPreallocated<'buf> {}
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
        /// If `rand-std` feature is enabled, context will have been randomized using `thread_rng`.
        /// If `rand-std` feature is not enabled please consider randomizing the context as follows:
        /// ```
        /// # #[cfg(feature = "rand-std")] {
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
                feature = "rand-std",
                not(feature = "global-context-less-secure")
            ))]
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
        pub fn new() -> Secp256k1<All> { Secp256k1::gen_new() }
    }

    impl Secp256k1<SignOnly> {
        /// Creates a new Secp256k1 context that can only be used for signing.
        ///
        /// If `rand-std` feature is enabled, context will have been randomized using `thread_rng`.
        /// If `rand-std` feature is not enabled please consider randomizing the context (see docs
        /// for `Secp256k1::gen_new()`).
        pub fn signing_only() -> Secp256k1<SignOnly> { Secp256k1::gen_new() }
    }

    impl Secp256k1<VerifyOnly> {
        /// Creates a new Secp256k1 context that can only be used for verification.
        ///
        /// * If `rand-std` feature is enabled, context will have been randomized using `thread_rng`.
        /// * If `rand-std` feature is not enabled please consider randomizing the context (see docs
        /// for `Secp256k1::gen_new()`).
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
