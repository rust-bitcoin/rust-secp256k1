use std::{error::Error, fmt};

#[derive(Debug, Clone)]
pub(crate) struct UnavailableError;

impl fmt::Display for UnavailableError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "not implemented")
    }
}

impl Error for UnavailableError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        // Generic error, underlying cause isn't tracked.
        None
    }
}

#[cfg(feature = "std")]
impl From<UnavailableError> for rand::Error {
    fn from(e: UnavailableError) -> Self {
        rand::Error::new(e)
    }
}
