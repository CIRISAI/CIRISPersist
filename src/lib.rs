// THREAT_MODEL.md §6 #6 / SECURITY_AUDIT_v0.1.2.md §4.1 — no
// `unsafe` blocks in our code, gated at the crate level. PyO3 +
// redb + tokio-postgres etc. have transitive `unsafe` (which is
// fine and out of our scope); `forbid` here only applies to this
// crate.
#![forbid(unsafe_code)]
// SECURITY_AUDIT_v0.1.4.md §4 §4.4 — v0.1.6 hygiene batch.
// Every public item gets a doc comment. CI fails on any addition
// that ships without one. The intent is operator-readable:
// row-shaped types, error variants, and trait surfaces are the
// substrate's contract; "what does this column mean" should never
// require digging through the migration SQL alongside the source.
#![deny(missing_docs)]

//! ciris-persist — unified Rust persistence for the CIRIS federation.
//!
//! Mission: see [`MISSION.md`](https://github.com/CIRISAI/CIRISPersist/blob/main/MISSION.md).
//! `ciris-persist` is the substrate on which CIRIS Accord Meta-Goal M-1
//! becomes durable. The agent reasons; the lens scores; persistence is
//! what makes either of those evidence rather than ephemera.
//!
//! Owns: signed-event persistence (with Ed25519 hash chain), time-series
//! storage, and (Phase 3) the agent's runtime-state, memory-graph, and
//! governance tables. The destination is a single persistence binary
//! shared by both lens and agent, per the Proof-of-Benefit Federation
//! FSD §3.1.
//!
//! Status: Phase 1 in flight. See `FSD/CIRIS_PERSIST.md` for scope, and
//! `FSD/PLATFORM_ARCHITECTURE.md` for the layered shape this module
//! tree implements.

pub mod federation;
pub mod ffi;
pub mod ingest;
pub mod journal;
pub mod manifest;
pub mod outbound;
pub mod prelude;
pub mod queue;
pub mod schema;
pub mod scrub;
#[cfg(feature = "server")]
pub mod server;
pub mod signing;
pub mod store;
pub mod verify;

pub use ingest::{BatchSummary, IngestError, IngestPipeline};
pub use journal::{Journal, JournalError};
pub use queue::{
    shutdown_signal, spawn_persister, IngestHandle, PersisterHandle, QueueError,
    DEFAULT_QUEUE_DEPTH,
};

// Phase 1 surfaces still pending implementation:
//   #[cfg(feature = "server")] pub mod server;
//   #[cfg(feature = "pyo3")]   pub mod ffi;

/// Crate-wide error type.
///
/// Mission constraint (MISSION.md §3 anti-pattern #4): typed errors via
/// `thiserror`. Every fallible operation has a defined failure mode;
/// no `.unwrap()` / `.expect()` in non-test paths.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Schema-layer failure (parse, validation, depth, range).
    #[error("schema: {0}")]
    Schema(#[from] schema::Error),

    /// Signature verification failure.
    #[error("verify: {0}")]
    Verify(#[from] verify::Error),

    /// PII-scrubber failure.
    #[error("scrub: {0}")]
    Scrub(#[from] scrub::ScrubError),

    /// Storage backend failure (Postgres / SQLite / in-memory).
    #[error("store: {0}")]
    Store(#[from] store::Error),
}

/// Crate-wide `Result` alias.
pub type Result<T> = std::result::Result<T, Error>;
