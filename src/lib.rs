//! ciris-persist — unified Rust persistence for the CIRIS Trinity.
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

pub mod ingest;
pub mod journal;
pub mod queue;
pub mod schema;
pub mod scrub;
#[cfg(feature = "server")]
pub mod server;
pub mod store;
pub mod verify;

pub use ingest::{BatchSummary, IngestError, IngestPipeline};
pub use journal::{Journal, JournalError};
pub use queue::{spawn_persister, IngestHandle, QueueError, DEFAULT_QUEUE_DEPTH};

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
    #[error("schema: {0}")]
    Schema(#[from] schema::Error),

    #[error("verify: {0}")]
    Verify(#[from] verify::Error),

    #[error("scrub: {0}")]
    Scrub(#[from] scrub::ScrubError),

    #[error("store: {0}")]
    Store(#[from] store::Error),
}

/// Crate-wide `Result` alias.
pub type Result<T> = std::result::Result<T, Error>;
