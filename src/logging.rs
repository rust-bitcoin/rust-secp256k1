//! Provides debug logging.
//!
//! WARNING: Logging leaks secret information and is provided for debugging purposes only.
//!
//! DO NOT ENABLE LOGGING IN PRODUCTION SYSTEMS.
//!

use std::fs::File;
use std::sync::Mutex;

#[allow(dead_code)] // When danger-leak-secret-material not enabled.
pub static LOGFILE: Mutex<Option<File>> = Mutex::new(None);

#[allow(dead_code)] // When danger-leak-secret-material not enabled.
pub const CRYPTO_DEBUG_FILE: &str = "/tmp/rust-secp256k1.log";

/// Logs a format string to `CRYPTO_DEBUG_FILE`.
#[cfg(feature = "danger-leak-secret-material")]
#[macro_export]
macro_rules! log {
    ($fmt:literal, $($args:tt),*) => {
        log::info!($fmt, $($args),*)
    }
}

/// No-op when `danger-leak-secret-material` feature is not enabled.
#[cfg(not(feature = "danger-leak-secret-material"))]
#[macro_export]
macro_rules! log {
    ($fmt:literal, $($args:tt),*) => {}
}
