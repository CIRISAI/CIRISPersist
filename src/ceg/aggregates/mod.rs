//! Aggregate (rolled-up statistics) read primitives.
//!
//! v4.0 (FSD §3.3) topic home for the v3.x `read::{scoring,llm,scrub,
//! corpus}` aggregate-shaped types, plus the section-F Coherence-Ratchet
//! input rows that previously lived in `read::trace`. List-shaped
//! siblings live under [`crate::ceg::list`].
//!
//! The `repository.rs` (`get_repository_statistics`) primitive the FSD
//! §3.1 names lands in a LATER v4.0 commit; this commit only re-homes
//! the existing aggregate shapes.

pub mod corpus;
pub mod llm;
pub mod repository;
pub mod scoring;
pub mod scrub;
