//! Concrete format implementations.
//!
//! A module here owns exactly one format and knows nothing about the others:
//! it projects onto a pivot model ([`crate::model`]) or emits from one.

pub mod coverage;
pub mod quality;
pub mod sbom;
pub mod security;
pub mod tests;
