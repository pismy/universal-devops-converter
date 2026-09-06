//! Pivot models — one canonical representation per report category.
//!
//! Readers project a concrete format onto a pivot; writers project a pivot onto
//! a concrete format. Formats never see each other, which keeps the number of
//! implementations at 2N instead of N² (SPECS.md §3.1).

pub mod coverage;
pub mod findings;
pub mod tests;
