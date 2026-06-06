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
// v4.0 (FSD V4.0 §7, Commit C) — generic substrate caching primitive.
// TTL + LRU bounded, scope-disjoint keys, window-overlap bucket
// invalidation (CIRISPersist#160 comment 2). Additive; wiring into the
// aggregate read primitives is Commit G.
pub mod cache;
#[cfg(feature = "cirisnode")]
pub mod cirisnode;
// v4.0 (FSD §3) — CEG topic-namespace read surface. The v3.x `read`
// modules rehome here; `pub mod read` below stays as a façade shim
// re-exporting `ceg` until the later v4.0 commit removes it.
pub mod ceg;
// v3.12.x (CIRISPersist#156) — diagnostic harness panic hook.
// Compiled only under `--features debug-tools`; release wheels ship
// without this module. See src/debug/mod.rs + tools/README.md.
#[cfg(feature = "cirislens_continuity_awareness")]
pub mod continuity_awareness;
#[cfg(feature = "cirislens_correlations")]
pub mod correlations;
#[cfg(feature = "cirislens_creation_ceremonies")]
pub mod creation_ceremonies;
#[cfg(feature = "debug-tools")]
pub mod debug;
#[cfg(feature = "cirislens_deferral_reports")]
pub mod deferral_reports;
pub mod derived;
pub mod engine;
pub mod federation;
#[cfg(feature = "cirislens_feedback_mappings")]
pub mod feedback_mappings;
pub mod ffi;
#[cfg(feature = "cirisgraph")]
pub mod graph;
#[cfg(feature = "cirisincident")]
pub mod incident;
pub mod ingest;
pub mod journal;
#[cfg(feature = "cirislens_legacy_migration")]
pub mod legacy_migration;
#[cfg(any(feature = "postgres", feature = "sqlite"))]
pub mod maintenance;
#[cfg(feature = "cirislens_maintenance_locks")]
pub mod maintenance_locks;
pub mod manifest;
#[cfg(feature = "cirislens_occurrence")]
pub mod occurrence;
pub mod outbound;
pub mod pipeline;
pub mod prelude;
pub mod queue;
pub mod read;
#[cfg(any(feature = "postgres", feature = "sqlite"))]
pub mod retention;
#[cfg(feature = "cirislens_scheduled_tasks")]
pub mod scheduled_tasks;
pub mod schema;
pub mod scope;
pub mod scrub;
#[cfg(feature = "secrets")]
pub mod secrets;
#[cfg(feature = "cirislens_sequence")]
pub mod sequence;
#[cfg(feature = "server")]
pub mod server;
#[cfg(feature = "cirislens_service_token_revocation")]
pub mod service_token_revocation;
pub mod signing;
pub mod store;
#[cfg(feature = "cirislens_tasks")]
pub mod tasks;
#[cfg(feature = "telemetry")]
pub mod telemetry;
#[cfg(feature = "cirislens_thoughts")]
pub mod thoughts;
#[cfg(feature = "cirislens_tickets")]
pub mod tickets;
pub mod verify;
#[cfg(feature = "cirislens_wa_cert")]
pub mod wa_cert;

#[cfg(all(feature = "cirisaudit", any(feature = "postgres", feature = "sqlite")))]
pub use engine::AuditDispatch;
#[cfg(all(feature = "cirisnode", any(feature = "postgres", feature = "sqlite")))]
pub use engine::NodeCoreDispatch;
pub use engine::{BackendDispatch, Engine, EngineError};
// v2.13.0 (CIRISPersist#113) — Engine detection-events read + subscribe
// facade. Re-export the filter / row types + the derived Error at the
// crate root so consumers can `use ciris_persist::{Engine,
// EventFilter, EdgeEventFilter, DetectionEvent, EdgeDetectionEvent}`
// alongside the existing surface.
pub use derived::{
    DetectionEvent, EdgeDetectionEvent, EdgeEventFilter, Error as DerivedError, EventFilter,
};
// v1.13.0 (CIRISPersist#92) — process-singleton accessors for
// co-resident Rust consumers (CIRISEdge resolver, CIRISLensCore
// `LensCore::relay`). Built only when the PyO3 surface — which owns
// the `ENGINE_SINGLETON` — is compiled in.
// v2.6.0 (CIRISPersist#106) — re-export the FederationDirectory trait
// from the crate root so consumers can `use ciris_persist::FederationDirectory;`
// alongside `use ciris_persist::Engine;` without two imports. Pairs with
// the new object-safe `Engine::federation_directory() -> Arc<dyn
// FederationDirectory>` accessor.
pub use federation::FederationDirectory;
#[cfg(feature = "sqlite")]
pub use federation::FederationDirectorySqlite;
#[cfg(feature = "pyo3")]
pub use ffi::pyo3::{current_runtime_handle, current_rust_engine};
pub use ingest::{BatchSummary, IngestError, IngestPipeline};
pub use journal::{Journal, JournalError};
#[cfg(feature = "sqlite")]
pub use outbound::EdgeOutboundQueueSqlite;
pub use queue::{
    shutdown_signal, spawn_persister, IngestHandle, PersisterHandle, QueueError,
    DEFAULT_QUEUE_DEPTH,
};
// v2.7.0 (CIRISPersist#107) — retention primitive types. The three
// Engine methods (`storage_summary`, `delete_traces_older_than`,
// `archive_audit_range`) consume these; re-export at the crate root
// so callers can `use ciris_persist::{StorageSummary, TableUsage,
// ArchiveHandle}` alongside the Engine type.
#[cfg(any(feature = "postgres", feature = "sqlite"))]
pub use retention::{ArchiveHandle, RetentionError, StorageSummary, TableUsage};

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
