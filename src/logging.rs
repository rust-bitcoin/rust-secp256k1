//! Provides debug logging.
//!
//! WARNING: Logging leaks secret information and is provided for debugging purposes only.
//!
//! DO NOT ENABLE LOGGING IN PRODUCTION SYSTEMS.
//!

use std::fs::File;
use std::sync::Mutex;

#[allow(dead_code)] // When danger_leak_secret_material not enabled.
pub static LOGFILE: Mutex<Option<File>> = Mutex::new(None);

#[allow(dead_code)] // When danger_leak_secret_material not enabled.
pub const CRYPTO_DEBUG_FILE: &str = "/tmp/rust-secp256k1.log";

/// Logs a format string to `CRYPTO_DEBUG_FILE`.
#[cfg(feature = "danger_leak_secret_material")]
#[macro_export]
macro_rules! log {
    ($fmt:literal, $($args:tt),*) => {
        use std::io::Write;

        let mut guard = $crate::logging::LOGFILE.lock().expect("poisoned mutex");

        if guard.is_none() {
            let file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .append(true)
                .open($crate::logging::CRYPTO_DEBUG_FILE)
                .expect("failed to create/open log file");

            *guard = Some(file);
        }

        match *guard {
            Some(ref mut file) => {
                let _ = writeln!(file, $fmt, $($args),*);
            },
            None => panic!("log file missing"),
        }
    }
}

/// No-op when `danger_leak_secret_material` feature is not enabled.
#[cfg(not(feature = "danger_leak_secret_material"))]
#[macro_export]
macro_rules! log {
    ($fmt:literal, $($args:tt),*) => {}
}
