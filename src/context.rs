use core::marker::PhantomData;

use crate::{ffi, AlignedType, Error, Secp256k1};

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
    const FLAGS: u32;
    /// A constant description of the context.
    const DESCRIPTION: &'static str;
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
    use core::marker::PhantomData;

    use super::private;
    use crate::ffi;
    use crate::{Secp256k1, Signing, Verification, Context};

    impl private::Sealed for SignOnly {}
    impl private::Sealed for All {}
    impl private::Sealed for VerifyOnly {}

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
        const FLAGS: u32 = ffi::SECP256K1_START_SIGN;
        const DESCRIPTION: &'static str = "signing only";
    }

    unsafe impl Context for VerifyOnly {
        const FLAGS: u32 = ffi::SECP256K1_START_VERIFY;
        const DESCRIPTION: &'static str = "verification only";
    }

    unsafe impl Context for All {
        const FLAGS: u32 = VerifyOnly::FLAGS | SignOnly::FLAGS;
        const DESCRIPTION: &'static str = "all capabilities";
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

            #[allow(unused_mut)] // ctx not mutated for all feature combinations.
            let mut ctx = Secp256k1 {
                ctx: ffi::Secp256k1::gen_new(C::FLAGS),
                phantom: PhantomData,
            };

            #[cfg(all(not(target_arch = "wasm32"), feature = "rand-std", not(feature = "global-context-less-secure")))]
            {
                ctx.randomize(&mut rand::thread_rng());
            }

            #[allow(clippy::let_and_return)] // as for unused_mut
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
}

impl<'buf> Signing for SignOnlyPreallocated<'buf> {}
impl<'buf> Signing for AllPreallocated<'buf> {}

impl<'buf> Verification for VerifyOnlyPreallocated<'buf> {}
impl<'buf> Verification for AllPreallocated<'buf> {}

unsafe impl<'buf> Context for SignOnlyPreallocated<'buf> {
    const FLAGS: u32 = ffi::SECP256K1_START_SIGN;
    const DESCRIPTION: &'static str = "signing only";
}

unsafe impl<'buf> Context for VerifyOnlyPreallocated<'buf> {
    const FLAGS: u32 = ffi::SECP256K1_START_VERIFY;
    const DESCRIPTION: &'static str = "verification only";
}

unsafe impl<'buf> Context for AllPreallocated<'buf> {
    const FLAGS: u32 = SignOnlyPreallocated::FLAGS | VerifyOnlyPreallocated::FLAGS;
    const DESCRIPTION: &'static str = "all capabilities";
}

impl<'buf, C: Context + 'buf> Secp256k1<C> {
    /// Lets you create a context with preallocated buffer in a generic manner(sign/verify/all)
    pub fn preallocated_gen_new(buf: &'buf mut [AlignedType]) -> Result<Secp256k1<C>, Error> {
        #[cfg(target_arch = "wasm32")]
        ffi::types::sanity_checks_for_wasm();

        if buf.len() < Self::preallocate_size_gen() {
            return Err(Error::NotEnoughMemory);
        }
        Ok(Secp256k1 {
            ctx: ffi::Secp256k1::preallocated_gen_new(buf, C::FLAGS),
            phantom: PhantomData,
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

    // TODO: What about all the from_raw_ctx methods, the ffi::Context is private now.
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
}
