use core::fmt;
use core::marker::PhantomData;
use core::str::{self, FromStr};
use serde::de;

/// A serde visitor that works for `T`s implementing `FromStr`.
pub struct FromStrVisitor<T> {
    expectation: &'static str,
    _pd: PhantomData<T>,
}

impl<T> FromStrVisitor<T> {
    pub fn new(expectation: &'static str) -> Self {
        FromStrVisitor {
            expectation,
            _pd: PhantomData,
        }
    }
}

impl<'de, T> de::Visitor<'de> for FromStrVisitor<T>
where
    T: FromStr,
    <T as FromStr>::Err: fmt::Display,
{
    type Value = T;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str(self.expectation)
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
