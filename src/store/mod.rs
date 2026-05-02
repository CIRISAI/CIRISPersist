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
#[cfg(feature = "postgres")]
pub mod postgres;
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
    AuditEntry, ClaimParams, GraphNode, ServiceCorrelation, Task, TraceEventRow, TraceLlmCallRow,
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
        }
    }
}
