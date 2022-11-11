use core::mem;

use crate::alloc::alloc;
use crate::types::*;

const ALIGN_TO: usize = mem::align_of::<AlignedType>();

/// The secp256k1 engine, used to execute all signature operations.
#[derive(Debug)]
pub struct Secp256k1 {
    ctx: *mut Context,
    size: usize,
    prealloc: bool,
}

// FIXME: Should the `c_uint` args be u32?

impl Secp256k1 {
    /// Gets the raw pointer to the underlying secp256k1 context.
    ///
    /// This shouldn't be needed with normal usage of the library. It enables extending the
    /// Secp256k1 with more cryptographic algorithms outside of this crate.
    pub fn as_ptr(&self) -> *mut Context {
        self.ctx
    }

    /// Returns the required memory for a preallocated context buffer in a generic manner(sign/verify/all).
    pub fn preallocate_size_gen(flags: c_uint) -> usize {
        let word_size = mem::size_of::<AlignedType>();
        let bytes = unsafe { crate::secp256k1_context_preallocated_size(flags) };

        (bytes + word_size - 1) / word_size
    }

    /// Creates a context by allocating memory.
    pub fn gen_new(flags: c_uint) -> Secp256k1 {
        let size = Secp256k1::preallocate_size_gen(flags);
        let layout = alloc::Layout::from_size_align(size, ALIGN_TO).unwrap();
        let ptr = unsafe { alloc::alloc(layout) };

        Secp256k1 {
            ctx: unsafe { crate::secp256k1_context_preallocated_create(ptr as *mut c_void, flags) },
            size,
            prealloc: false,
        }
    }

    /// Creates a context with preallocated buffer.
    pub fn preallocated_gen_new(buf: &mut [AlignedType], flags: c_uint) -> Secp256k1 {
        Secp256k1 {
            ctx: unsafe {
                crate::secp256k1_context_preallocated_create(
                    buf.as_mut_ptr() as *mut c_void,
                    flags
                )
            },
            size: 0, // We don't need size for caller controlled memory.
            prealloc: true,
        }
    }

    /// TOOD: Write docs.
    pub fn from_raw(raw_ctx: *mut Context) -> Secp256k1 {
        Secp256k1 {
            ctx: raw_ctx,
            size: 0, // We don't need size for caller controlled memory.
            prealloc: true,
        }
    }

    /// (Re)randomizes the Secp256k1 context for extra sidechannel resistance given 32 bytes of
    /// cryptographically-secure random data;
    /// see comment in libsecp256k1 commit d2275795f by Gregory Maxwell.
    pub fn seeded_randomize(&mut self, seed: &[u8; 32]) {
        unsafe {
            let err = crate::secp256k1_context_randomize(self.ctx, seed.as_ptr());
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

    pub fn deallocate(&mut self) {
        if self.prealloc {
            return;
        }
        let layout = alloc::Layout::from_size_align(self.size, ALIGN_TO).unwrap();
        unsafe { alloc::dealloc(self.ctx as *mut u8, layout); }
    }
}

// The underlying secp context does not contain any references to memory it does not own.
unsafe impl Send for Secp256k1 {}
// The API does not permit any mutation of `Secp256k1` objects except through `&mut` references.
unsafe impl Sync for Secp256k1 {}

impl Clone for Secp256k1 {
    fn clone(&self) -> Self {
        let size = unsafe { crate::secp256k1_context_preallocated_clone_size(self.ctx as _) };
        let layout = alloc::Layout::from_size_align(size, ALIGN_TO).unwrap();
        let ptr = unsafe { alloc::alloc(layout) };

        Secp256k1 {
            ctx: unsafe { crate::secp256k1_context_preallocated_clone(self.as_ptr(), ptr as *mut c_void) },
            size,
            prealloc: false,
        }
    }
}

impl Drop for Secp256k1 {
    fn drop(&mut self) {
        unsafe {
            crate::secp256k1_context_preallocated_destroy(self.ctx);
            self.deallocate()
        }
    }
}

/// A Secp256k1 context, containing various precomputed values and such
/// needed to do elliptic curve computations. If you create one of these
/// with `secp256k1_context_create` you MUST destroy it with
/// `secp256k1_context_destroy`, or else you will have a memory leak.
#[derive(Clone, Debug)]
#[repr(C)] pub struct Context(c_int);

impl Context {
    pub fn as_ptr(&self) -> *const c_int {
        &self.0
    }

    pub fn as_mut_ptr(&mut self) -> *mut c_int {
        &mut self.0
    }
}
