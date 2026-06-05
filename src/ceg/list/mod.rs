//! Listing (cursor-paged) read primitives.
//!
//! v4.0 (FSD §3.3) topic home for the v3.x `read::{trace,task,llm,
//! federation}` list-shaped types. Aggregate-shaped siblings live under
//! [`crate::ceg::aggregates`].

pub mod federation;
pub mod llm;
pub mod tasks;
pub mod traces;
