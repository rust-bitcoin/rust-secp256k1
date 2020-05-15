use core::fmt;
use core::marker::PhantomData;
use core::str::{self, FromStr};
use serde::de;

pub struct HexVisitor<T> {
    expectation: &'static str,
    _pd: PhantomData<T>,
}

impl<T> HexVisitor<T> {
    pub fn new(expectation: &'static str) -> Self {
        HexVisitor {
            expectation,
            _pd: PhantomData,
        }
    }
}

impl<'de, T> de::Visitor<'de> for HexVisitor<T>
where
    T: FromStr,
    <T as FromStr>::Err: fmt::Display,
{
    type Value = T;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str(self.expectation)
    }

    fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
        if let Ok(hex) = str::from_utf8(v) {
            FromStr::from_str(hex).map_err(E::custom)
        } else {
            Err(E::invalid_value(de::Unexpected::Bytes(v), &self))
        }
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
        FromStr::from_str(v).map_err(E::custom)
    }
}

pub struct BytesVisitor<F> {
    expectation: &'static str,
    parse_fn: F,
}

impl<F, T, Err> BytesVisitor<F>
where
    F: FnOnce(&[u8]) -> Result<T, Err>,
    Err: fmt::Display,
{
    pub fn new(expectation: &'static str, parse_fn: F) -> Self {
        BytesVisitor {
            expectation,
            parse_fn,
        }
    }
}

impl<'de, F, T, Err> de::Visitor<'de> for BytesVisitor<F>
where
    F: FnOnce(&[u8]) -> Result<T, Err>,
    Err: fmt::Display,
{
    type Value = T;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str(self.expectation)
    }

    fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
        (self.parse_fn)(v).map_err(E::custom)
    }
}
