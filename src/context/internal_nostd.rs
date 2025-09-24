// SPDX-License-Identifier: CC0-1.0

use core::marker::PhantomData;
use core::mem::ManuallyDrop;
use core::ptr::NonNull;

use crate::context::spinlock::SpinLock;
use crate::{ffi, Context, Secp256k1};

mod self_contained_context {
    use core::mem::MaybeUninit;
    use core::ptr::NonNull;

    use crate::ffi::types::{c_void, AlignedType};
    use crate::{ffi, AllPreallocated, Context as _};

    const MAX_PREALLOC_SIZE: usize = 16; // measured at 208 bytes on Andrew's 64-bit system

    /// A secp256k1 context object which can be allocated on the stack or in static storage.
    pub struct SelfContainedContext(
        [MaybeUninit<AlignedType>; MAX_PREALLOC_SIZE],
        Option<NonNull<ffi::Context>>,
    );

    // SAFETY: the context object owns all its own data.
    unsafe impl Send for SelfContainedContext {}

    impl SelfContainedContext {
        /// Creates a new uninitialized self-contained context.
        pub const fn new_uninitialized() -> Self {
            Self([MaybeUninit::uninit(); MAX_PREALLOC_SIZE], None)
        }

        /// Accessor for the underlying raw context pointer
        fn buf(&mut self) -> NonNull<c_void> {
            NonNull::new(self.0.as_mut_ptr() as *mut c_void).unwrap()
        }

        pub fn clone_into(&mut self, other: &mut SelfContainedContext) {
            // SAFETY: just FFI calls
            unsafe {
                let other = other.raw_ctx().as_ptr();
                assert!(
                    ffi::secp256k1_context_preallocated_clone_size(other)
                        <= core::mem::size_of::<[AlignedType; MAX_PREALLOC_SIZE]>(),
                    "prealloc size exceeds our guessed compile-time upper bound",
                );
                ffi::secp256k1_context_preallocated_clone(other, self.buf());
            }
        }

        /// Accessor for the context as a raw context pointer.
        ///
        /// On the first call, this will create the context.
        pub fn raw_ctx(&mut self) -> NonNull<ffi::Context> {
            let buf = self.buf();
            *self.1.get_or_insert_with(|| {
                // SAFETY: just FFI calls
                unsafe {
                    assert!(
                        ffi::secp256k1_context_preallocated_size(AllPreallocated::FLAGS)
                            <= core::mem::size_of::<[AlignedType; MAX_PREALLOC_SIZE]>(),
                        "prealloc size exceeds our guessed compile-time upper bound",
                    );
                    ffi::secp256k1_context_preallocated_create(buf, AllPreallocated::FLAGS)
                }
            })
        }
    }
}
// Needs to be pub(super) so that we can define a constructor for
// SpinLock<SelfContainedContext> in the spinlock module. (We cannot do so generically
// because we need a const constructor.)
pub(super) use self_contained_context::SelfContainedContext;

/// A global static context to avoid repeatedly creating contexts.
pub static SECP256K1: SpinLock<SelfContainedContext> = SpinLock::<SelfContainedContext>::new();

/// Borrows the global context and does some operation on it.
///
/// If `randomize_seed` is provided, it is used to rerandomize the context after the
/// operation is complete. If it is not provided, randomization is skipped.
///
/// Only a bit or two per signing operation is needed; if you have any entropy at all,
/// you should provide it, even if you can't provide 32 random bytes.
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

/// Borrows the global context as a raw pointer and does some operation on it.
///
/// If `randomize_seed` is provided, it is used to rerandomize the context after the
/// operation is complete. If it is not provided, randomization is skipped.
///
/// Only a bit or two per signing operation is needed; if you have any entropy at all,
/// you should provide it, even if you can't provide 32 random bytes.
pub fn with_raw_global_context<T, F: FnOnce(NonNull<ffi::Context>) -> T>(
    f: F,
    rerandomize_seed: Option<&[u8; 32]>,
) -> T {
    // Our function may be expensive, so before calling it, we copy the global
    // context into this local buffer on the stack. Then we can release it,
    // allowing other callers to use it simultaneously.
    let mut ctx = SelfContainedContext::new_uninitialized();
    let mut have_global_ctx = false;
    if let Some(mut guard) = SECP256K1.try_lock() {
        let global_ctx = &mut *guard;
        ctx.clone_into(global_ctx);
        have_global_ctx = true;
        // (the lock is now dropped)
    }

    // Obtain a raw pointer to the context, creating one if it has not been already,
    // and call the function.
    let ctx_ptr = ctx.raw_ctx();
    let ret = f(ctx_ptr);

    // ...then rerandomize the local copy, and try to replace the global one
    // with this. Note that even if we got the lock above, we may fail to get
    // it now; in that case, we don't rerandomize and leave the contexct in
    // the state that we found it in.
    //
    // We do this, rather than holding the lock continuously through the call
    // to `f`, to minimize the likelihood of contention. If we fail to randomize,
    // that really isn't a big deal since this is a "defense in depth" measure
    // whose value is likely to obtain even if it only succeeds a small fraction
    // of the time.
    //
    // Contention, meanwhile, will lead to users using a stack-local copy of
    // the context rather than the global one, which aside from being inefficient,
    // means that the context they use won't be rerandomized at all. So there
    // isn't even any benefit.
    if have_global_ctx {
        if let Some(seed) = rerandomize_seed {
            // SAFETY: just a FFI call
            unsafe {
                assert_eq!(ffi::secp256k1_context_randomize(ctx_ptr, seed.as_ptr()), 1);
            }
            if let Some(ref mut guard) = SECP256K1.try_lock() {
                guard.clone_into(&mut ctx);
            }
        }
    }
    ret
}

/// Rerandomize the global context, using the given data as a seed.
///
/// The provided data will be mixed with the entropy from previous calls in a timing
/// analysis resistant way. It is safe to directly pass secret data to this function.
pub fn rerandomize_global_context(seed: &[u8; 32]) { with_raw_global_context(|_| {}, Some(seed)) }
