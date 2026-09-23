//! Listing (cursor-paged) read primitives.
//!
//! v4.0 (FSD §3.3) topic home for the v3.x `read::{trace,task,llm,
//! federation}` list-shaped types. Aggregate-shaped siblings live under
//! [`crate::ceg::aggregates`].

/// v46.4.0 (CIRISPersist#891) — the drive query's witnesses.
#[cfg(any(test, feature = "test-anchor"))]
pub mod drive_query_invariants;
pub mod federation;
pub mod llm;
pub mod tasks;
/// v47.1.0 (CIRISPersist#844) — I148: a trace's admission instant, per trace
/// and as a pushed-down window.
#[cfg(any(test, feature = "test-anchor"))]
pub mod trace_admission_invariants;
pub mod traces;
