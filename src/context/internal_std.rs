// SPDX-License-Identifier: CC0-1.0

use std::cell::RefCell;
use std::marker::PhantomData;
use std::mem::ManuallyDrop;
use std::ptr::NonNull;

use secp256k1_sys as ffi;

use crate::{All, Context, Secp256k1};

thread_local! {
    static SECP256K1: RefCell<Secp256k1<All>> = RefCell::new(Secp256k1::new());
}

/// Borrows the global context and does some operation on it.
///
/// If `rerandomize_seed` is provided, then [`rerandomize_global_context`] is called on the context
/// after the operation. This argument should be provided alongside any operation that uses secret
/// data (e.g. signing, but not verification). If you have random data available, it should be
/// provided here; it will be mixed with the current random state as well as the system RNG if it is
/// available. If you do not have any random data, it is fine to provide all zeros, or a counter, or
/// a weak source of entropy. This is a defense-in-depth measure to protect against side-channel
/// attacks, and anything helps (and nothing will hurt).
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
/// If `rerandomize_seed` is provided, then [`rerandomize_global_context`] is called on the context
/// after the operation. This argument should be provided alongside any operation that uses secret
/// data (e.g. signing, but not verification). If you have random data available, it should be
/// provided here; it will be mixed with the current random state as well as the system RNG if it is
/// available. If you do not have any random data, it is fine to provide all zeros, or a counter, or
/// a weak source of entropy. This is a defense-in-depth measure to protect against side-channel
/// attacks, and anything helps (and nothing will hurt).
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
        let mut borrow = secp.borrow_mut();

        // If we have access to the thread rng then use it as well.
        #[cfg(feature = "rand")]
        {
            let mut new_seed: [u8; 32] = rand::random();
            for (new, byte) in new_seed.iter_mut().zip(seed.iter()) {
                *new ^= *byte;
            }
            borrow.seeded_randomize(&new_seed);
        }
        #[cfg(not(feature = "rand"))]
        {
            borrow.seeded_randomize(seed);
        }
    });
}
