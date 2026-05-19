//! cirisgraph — typed graph substrate (v0.8.0, CIRISPersist#34).
//!
//! Absorbs CIRISAgent's `LocalGraphMemoryService` (and the graph-
//! backed services that ride on it — `GraphConfigService`, future
//! `TelemetryService` / `TSDBConsolidationService`) off the agent's
//! homegrown SQLite/Postgres + hand-rolled SQL onto persist.
//!
//! # Why Postgres + recursive CTEs (and not an embedded graph DB)
//!
//! Verified via deepwiki against CIRISAgent's live query patterns:
//! the actual workload is point lookup by `(node_id, scope)`,
//! time-window scans on `updated_at`, predicate filters on JSONB
//! attributes, direct-edge retrieval per node, and **procedural
//! bounded k-hop traversal** (max_depth in [1..16]). No Cypher /
//! Datalog requirement; no full-graph reads.
//!
//! Postgres handles every observed pattern: B-tree index on
//! `(node_type, scope)` + `(updated_at)`; GIN on JSONB attributes
//! for predicate push-down; recursive CTE for k-hop. Deployment
//! stays single-Postgres (matches the existing CIRISLens / CIRISNode
//! schema track); no embedded DB engine, no separate backup story,
//! no FFI to C++ graph cores. Dep weight: zero new.
//!
//! # Schema parity with CIRISAgent
//!
//! Column shapes (node_id, scope, node_type, attributes_json,
//! version, updated_by, updated_at, created_at) mirror the agent's
//! existing schema exactly so the Phase 1B cutover can read agent-
//! written rows via a one-shot ETL without shape translation.
//! Persist-side adds audit-envelope columns (signature,
//! signing_key_id, signature_verified, original_content_hash,
//! persist_row_hash); agent writes via the new Rust API populate
//! them, legacy rows leave them NULL.
//!
//! # Scope per release
//!
//! - **v0.8.0** (this release): V013 migration, wire types,
//!   `GraphService` trait surface (7 methods), `PostgresBackend`
//!   impl with recursive-CTE k-hop, PyO3 wraps, integration tests.
//! - **v0.8.1+**: AuditService (separate track), then TelemetryService
//!   plus TSDBConsolidationService (depend on the cirisgraph schema
//!   for SUMMARIZES / TEMPORAL_NEXT edges).

#[cfg(feature = "postgres")]
pub mod postgres;
pub mod service;
#[cfg(feature = "sqlite")]
pub mod sqlite;
pub mod types;

pub use service::GraphService;
pub use types::{
    AttributeMatch, EdgeDirection, GraphEdge, GraphNode, GraphScope, KhopEntry, ListCursor,
    NodeExcludeRule, NodeFilter, NodeListPage, TraversalConfig,
};

/// cirisgraph-layer errors.
///
/// THREAT_MODEL.md AV-15: stable `kind()` tokens for HTTP / PyO3
/// sanitization. Verbose `Display` messages stay in tracing only.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Caller passed invalid arguments — unknown scope, depth
    /// exceeds [`MAX_KHOP_DEPTH`], missing required fields, etc.
    /// AV-45 attribute-size violations are surfaced via the more
    /// specific [`Error::AttributesTooLarge`] variant.
    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    /// v1.3.2 (CIRISPersist#50): caller supplied attributes whose
    /// serialized JSON exceeds the AV-45 cap. Typed so callers can
    /// branch on it without string-matching the InvalidArgument
    /// detail. Migration paths can either retry with
    /// `bulk_import=true` or partition the row.
    #[error("attributes too large: {bytes} bytes exceeds cap of {cap}")]
    AttributesTooLarge {
        /// Serialized attribute size in bytes.
        bytes: usize,
        /// Configured cap (DEFAULT_MAX_ATTRIBUTES_BYTES unless
        /// overridden by CIRIS_PERSIST_GRAPH_MAX_ATTRIBUTES_BYTES).
        cap: usize,
    },

    /// Authorization layer rejected — caller's scope claim does
    /// not entitle access to the requested row's scope.
    #[error("not authorized: {0}")]
    NotAuthorized(String),

    /// Optimistic-concurrency conflict (AV-48): caller's
    /// `expected_version` did not match the current row's
    /// `version`. Caller must read-modify-write again.
    #[error("conflict: {0}")]
    Conflict(String),

    /// Row not found.
    #[error("not found: {0}")]
    NotFound(String),

    /// Backend-level error (DB connection, JSONB serialization).
    #[error("backend: {0}")]
    Backend(String),

    /// Surface declared on the trait but the backend doesn't
    /// implement it (memory + sqlite backends return this for
    /// the cirisgraph methods).
    #[error("not implemented: {0}")]
    NotImplemented(&'static str),

    /// Internal serialization / type-conversion bug. Indicates a
    /// persist bug; operators should file an issue.
    #[error("internal: {0}")]
    Internal(String),
}

impl Error {
    /// Stable string-token for telemetry / structured logging.
    /// Mirrors the kind() convention from
    /// `crate::secrets::SecretsError` / `crate::cirisnode::Error` /
    /// `crate::pipeline::Error`.
    pub fn kind(&self) -> &'static str {
        match self {
            Error::InvalidArgument(_) => "cirisgraph_invalid_argument",
            Error::AttributesTooLarge { .. } => "cirisgraph_attributes_too_large",
            Error::NotAuthorized(_) => "cirisgraph_not_authorized",
            Error::Conflict(_) => "cirisgraph_conflict",
            Error::NotFound(_) => "cirisgraph_not_found",
            Error::Backend(_) => "cirisgraph_backend",
            Error::NotImplemented(_) => "cirisgraph_not_implemented",
            Error::Internal(_) => "cirisgraph_internal",
        }
    }
}

/// AV-46: absolute k-hop traversal depth cap. Caller-supplied
/// `max_depth` above this rejects as `Error::InvalidArgument` —
/// no silent clamp; caller sees the rejection so a misconfigured
/// query surfaces at debug time, not as a slow query.
pub const MAX_KHOP_DEPTH: usize = 16;

/// AV-45: default attributes-JSONB size cap (per node). Bytes.
/// Configurable per deployment via
/// `CIRIS_PERSIST_GRAPH_MAX_ATTRIBUTES_BYTES` env (read by the PG
/// impl at connect time).
pub const DEFAULT_MAX_ATTRIBUTES_BYTES: usize = 1024 * 1024;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_kind_tokens_stable() {
        assert_eq!(
            Error::InvalidArgument("x".into()).kind(),
            "cirisgraph_invalid_argument"
        );
        assert_eq!(
            Error::NotAuthorized("x".into()).kind(),
            "cirisgraph_not_authorized"
        );
        assert_eq!(Error::Conflict("x".into()).kind(), "cirisgraph_conflict");
        assert_eq!(Error::NotFound("x".into()).kind(), "cirisgraph_not_found");
        assert_eq!(Error::Backend("x".into()).kind(), "cirisgraph_backend");
        assert_eq!(
            Error::NotImplemented("x").kind(),
            "cirisgraph_not_implemented"
        );
        assert_eq!(Error::Internal("x".into()).kind(), "cirisgraph_internal");
    }

    #[test]
    fn khop_depth_bound_is_16() {
        // AV-46 — locked at v0.8.0; any change is a threat-model
        // event (revisit AV-46 entry before bumping).
        assert_eq!(MAX_KHOP_DEPTH, 16);
    }
}
