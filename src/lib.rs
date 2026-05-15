// THREAT_MODEL.md §6 #6 / SECURITY_AUDIT_v0.1.2.md §4.1 — no
// `unsafe` blocks in our code, gated at the crate level. PyO3 +
// redb + tokio-postgres etc. have transitive `unsafe` (which is
// fine and out of our scope); `deny` here only applies to this
// crate.
//
// v0.6.0-α4 (CIRISPersist#19) — relaxed from `forbid` to `deny` so
// that the feature-gated NER backends (`scrub-ner` / `scrub-ort`)
// can selectively allow unsafe ONLY at the `safetensors::mmap` call
// sites. The mmap path is unavoidable in the ML ecosystem — every
// candle / ort example uses it identically. Non-NER code stays
// hard-locked: every `#[allow(unsafe_code)]` must appear at the
// top of a module file and be visible to security audits.
#![deny(unsafe_code)]
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

#[cfg(feature = "cirisaudit")]
pub mod audit;
#[cfg(feature = "cirisnode")]
pub mod cirisnode;
pub mod derived;
pub mod engine;
pub mod federation;
pub mod ffi;
#[cfg(feature = "cirisgraph")]
pub mod graph;
#[cfg(feature = "cirisincident")]
pub mod incident;
pub mod ingest;
pub mod journal;
#[cfg(any(feature = "postgres", feature = "sqlite"))]
pub mod maintenance;
pub mod manifest;
pub mod outbound;
pub mod pipeline;
pub mod prelude;
pub mod queue;
pub mod read;
pub mod schema;
pub mod scrub;
#[cfg(feature = "secrets")]
pub mod secrets;
#[cfg(feature = "server")]
pub mod server;
pub mod signing;
pub mod store;
#[cfg(feature = "telemetry")]
pub mod telemetry;
pub mod verify;

pub use engine::{BackendDispatch, Engine, EngineError};
#[cfg(feature = "sqlite")]
pub use federation::FederationDirectorySqlite;
pub use ingest::{BatchSummary, IngestError, IngestPipeline};
pub use journal::{Journal, JournalError};
#[cfg(feature = "sqlite")]
pub use outbound::EdgeOutboundQueueSqlite;
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

/// Outcome of an atomic-claim attempt (v1.0.0; CIRISAgent#756 concern #2).
///
/// The atomic-claim primitive — `SecretsService::try_claim_secret` and
/// `AuditService::try_claim_event` — lets N concurrent workers process
/// the same envelope without writing N rows. The first caller to land
/// the INSERT receives `Stored(ref)`; every subsequent caller hashing
/// to the same content-key receives `AlreadyClaimed(ref)` carrying the
/// EXISTING row's reference (not a new one). Either way the caller
/// gets a stable identifier to attach downstream work to.
///
/// Both arms carry the same reference type so callers don't branch
/// on the outcome unless they specifically care which worker won
/// (e.g., for "who emitted this audit event first" attribution).
///
/// # Determinism guarantee
///
/// Implementations MUST be atomic at the database level: a concurrent
/// race between two workers running the same content key resolves to
/// exactly one inserted row + one `AlreadyClaimed` return. Both
/// backends (PG `ON CONFLICT DO NOTHING` + follow-up SELECT; SQLite
/// `INSERT OR IGNORE` + follow-up SELECT) satisfy this under the
/// content-hash UNIQUE constraint added in V017.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimResult<R> {
    /// This caller's INSERT landed first. The embedded reference
    /// points to the row this caller just wrote.
    Stored(R),
    /// Another caller already wrote a row with this content hash;
    /// the embedded reference points to the EXISTING row. The
    /// caller's INSERT was suppressed (PG `ON CONFLICT DO NOTHING`
    /// or SQLite `INSERT OR IGNORE`) — no row was created by this
    /// call.
    AlreadyClaimed(R),
}

impl<R> ClaimResult<R> {
    /// Borrow the embedded reference regardless of outcome — useful
    /// when the caller doesn't care who won the race.
    pub fn reference(&self) -> &R {
        match self {
            ClaimResult::Stored(r) | ClaimResult::AlreadyClaimed(r) => r,
        }
    }

    /// Consume into the embedded reference regardless of outcome.
    pub fn into_reference(self) -> R {
        match self {
            ClaimResult::Stored(r) | ClaimResult::AlreadyClaimed(r) => r,
        }
    }

    /// `true` when THIS caller's INSERT landed (the race winner).
    pub fn was_stored(&self) -> bool {
        matches!(self, ClaimResult::Stored(_))
    }
}
