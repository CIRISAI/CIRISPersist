//! Storage backends and the trait that abstracts them.
//!
//! # Mission alignment (MISSION.md §2 — `store/`)
//!
//! Same persistence trait surface, regardless of whether the substrate
//! is Postgres on a datacenter, SQLite on an iPhone, or redb on a
//! 4GB-RAM solar-LoRa node. The Backend trait shape is sealed in
//! Phase 1; later phases fill in surfaces, never restructure the
//! contract.

pub mod backend;
pub mod decompose;
pub mod memory;
// v3.12.x (CIRISPersist#156) — always-compiled migration-timing
// diagnostic. Sibling to the `debug-tools`-gated panic hook in
// `crate::debug`. Gated on `postgres` OR `sqlite` since the type
// references `refinery::Report`.
#[cfg(any(feature = "postgres", feature = "sqlite"))]
pub mod migration_timing;
#[cfg(feature = "postgres")]
pub mod postgres;
#[cfg(any(feature = "postgres", feature = "sqlite"))]
pub(crate) mod scope_bind;
#[cfg(feature = "sqlite")]
pub mod sqlite;
pub mod types;

pub use backend::{Backend, InsertReport, PublicKeySample};
pub use decompose::{decompose, dedup_key, Decomposed};
pub use memory::MemoryBackend;
#[cfg(feature = "postgres")]
pub use postgres::PostgresBackend;
#[cfg(feature = "sqlite")]
pub use sqlite::SqliteBackend;
pub use types::{
    accord_key_fingerprint, classify_key_registration, AuditEntry, ClaimParams, GraphNode,
    KeyRegistrationOutcome, ServiceCorrelation, Task, TraceEventRow, TraceLlmCallRow,
    VerificationSource,
};

/// Store-layer errors.
///
/// Mission constraint (MISSION.md §3 anti-pattern #4): every fallible
/// store op returns `Result<_, Error>` with a typed variant; no
/// `.unwrap()` / `.expect()` in production paths.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Schema-layer error propagated through decomposition.
    #[error("schema: {0}")]
    Schema(crate::schema::Error),

    /// Backend op not yet implemented for this phase. Variant carries
    /// a `'static` description so the caller can surface a helpful
    /// reason rather than treating the absence as a bug.
    #[error("not implemented: {0}")]
    NotImplemented(&'static str),

    /// Backend-specific error (DB connection, IO, etc.). The variant
    /// carries a string because each backend has its own error tree;
    /// future variants can be added per-backend.
    #[error("backend: {0}")]
    Backend(String),

    /// v8.0.0 (CIRISPersist#227) — a fountain content admission was
    /// rejected (the #225 hybrid hard cut on the manifest, a per-symbol
    /// SHA-256 mismatch, or a structural-invariant violation). Carries
    /// the [`crate::fountain::FountainAdmitError`] — its `kind()` token
    /// is preserved via [`Error::kind`]. Verify-before-mutation (AV-9):
    /// nothing was written.
    #[error("fountain admission rejected: {0}")]
    FountainAdmit(#[from] crate::fountain::FountainAdmitError),

    /// v8.0.0 (CIRISPersist#227) — a fountain content INTEGRITY error
    /// surfaced on READ: a stored symbol's SHA-256 no longer matches the
    /// signed `symbol_hashes`. This is corruption, not graceful
    /// degradation; the read fails loudly rather than returning
    /// unauthenticated bytes.
    #[error("fountain integrity: {0}")]
    FountainIntegrity(String),

    /// v8.4.0 (§19.7.1 / CIRISPersist#230) — an aggregation tier's
    /// `aggregation_meta` failed the PQC-mandatory store-path gate
    /// (§10.1.5.1.1): the §19.7.1 bound-hybrid signature did not verify, the
    /// ML-DSA-65 half was missing/invalid, the aggregator pubkeys were absent,
    /// or the stored commitment did not match the signed one. Carries the
    /// [`crate::fountain::AggregationMetaError`] (its `kind()` is preserved via
    /// [`Error::kind`]). Verify-before-mutation: NOTHING was written.
    #[error("aggregation meta rejected: {0}")]
    AggregationMetaRejected(#[from] crate::fountain::AggregationMetaError),

    /// Migration phase error. v0.1.5: the `sqlstate` is extracted from
    /// the underlying tokio-postgres error chain when available so
    /// lens-side callers can distinguish 40P01 (deadlock detected),
    /// 42P07 (relation already exists — multi-worker boot race
    /// signature pre-advisory-lock), 08006 (connection lost), etc.
    /// without parsing display strings. THREAT_MODEL.md AV-26.
    #[error("migration: {detail}")]
    Migration {
        /// Postgres SQLSTATE class+code (e.g. "42P07"), if the
        /// underlying error chain surfaced one. `None` for non-
        /// Postgres errors (refinery internal, IO, etc.).
        sqlstate: Option<String>,
        /// Operator-readable detail. Includes the SQLSTATE in
        /// brackets when present; safe for tracing logs.
        detail: String,
    },
}

// Bridge schema errors into the store layer.
impl From<crate::schema::Error> for Error {
    fn from(e: crate::schema::Error) -> Self {
        Error::Schema(e)
    }
}

impl Error {
    /// Stable string-token identifying the error variant.
    /// THREAT_MODEL.md AV-15: HTTP / PyO3 sanitization. The verbose
    /// `Display` form (which may include Postgres error context)
    /// goes to tracing logs only.
    pub fn kind(&self) -> &'static str {
        match self {
            Error::Schema(s) => s.kind(),
            Error::NotImplemented(_) => "store_not_implemented",
            Error::Backend(_) => "store_backend",
            Error::Migration { .. } => "store_migration",
            Error::FountainAdmit(e) => e.kind(),
            Error::FountainIntegrity(_) => "fountain_integrity",
            Error::AggregationMetaRejected(e) => e.kind(),
        }
    }
}
