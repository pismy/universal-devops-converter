//! Core of `udc`: pivot models, format readers and writers, and the registry
//! that ties them together.
//!
//! Exposed as a library so integration tests can enumerate [`registry::FORMATS`]
//! and drive readers and writers directly — that is what lets the conversion
//! matrix in `tests/conversion.rs` discover formats instead of hard-coding them.
//! The `udc` binary is a thin CLI on top of this.

pub mod detect;
pub mod error;
pub mod formats;
pub mod hash;
pub mod model;
pub mod paths;
pub mod registry;
pub mod warn;
pub mod xml;
