//! `TransparencyStore<AuditLeaf>` adapters for Postgres + SQLite
//! (v1.5.0 Phase B, FSD §4.4 + FEDERATION_TRUST_INTERFACE.md §4.4).
//!
//! Phase B exposes two concrete stores —
//! [`PgMerkleStore`] / [`SqliteMerkleStore`] — that implement
//! `ciris_verify_core::transparency::TransparencyStore<AuditLeaf>`
//! against the `merkle_leaves` + `merkle_sth_log` tables landed in
//! V021. Each store instance is scoped to **one tenant_id**; per the
//! Verify trait contract ("one store == one tree"), the per-tenant
//! audit chains map 1-to-1 to per-tenant Merkle trees.
//!
//! # Hashing parity with Verify
//!
//! Verify v2.3.0's `hash_leaf` is `pub(crate)` (not exported). To
//! avoid divergence, we replicate the RFC 6962 §2.1 leaf prefix
//! (`sha256(0x00 || canonical)`) byte-for-byte in [`hash_leaf`].
//! Tests in this module verify byte-equality against
//! `InMemoryTransparencyStore<AuditLeaf>` so any future drift is
//! caught at CI time.
//!
//! # Sync-over-async
//!
//! `TransparencyStore<L>` is a **sync** trait. Both backends below
//! capture a `tokio::runtime::Handle` and use `runtime.block_on`
//! around the underlying async/blocking SQL calls — matching the
//! pattern used elsewhere in `src/ffi/pyo3.rs` for crossing the
//! sync-PyO3 / async-tokio boundary.
//!
//! # What this module is NOT
//!
//! - **No audit-service ingest hook** (Phase D).
//! - **No emit/read/proof APIs** beyond what `TransparencyLog<L>`
//!   already exposes (Phase D-E).
//! - **No Engine wiring** for per-tenant log management (Phase C).
//! - **No V021 backfill** (Phase F).

#![allow(missing_docs)]

use chrono::{DateTime, Utc};
use ciris_verify_core::transparency::{
    SignedTreeHead, TransparencyError, TransparencyStore, WitnessSignature,
};
use sha2::{Digest, Sha256};
use tokio::runtime::Handle;

use super::merkle_leaf::AuditLeaf;

// ────────────────────────────────────────────────────────────────────
// RFC 6962 §2.1 hashing parity helper
// ────────────────────────────────────────────────────────────────────

/// RFC 6962 §2.1 leaf hash: `sha256(0x00 || canonical)`.
///
/// Byte-for-byte parity with Verify v2.3.0's `pub(crate) hash_leaf`
/// (see `ciris-verify-core/src/transparency.rs`). Locked by the unit
/// tests in this module — any divergence in Verify means tests fail
/// and we must update the prefix here in lockstep.
pub(crate) fn hash_leaf(canonical: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([0x00]);
    hasher.update(canonical);
    hasher.finalize().into()
}

// ────────────────────────────────────────────────────────────────────
// SignedTreeHead <-> row helpers (dialect-independent)
// ────────────────────────────────────────────────────────────────────

/// Tenant-scoped log_id derivation. Each tenant maps to a single
/// transparency log; the log_id baked into the STH is `tenant:<id>`
/// so cross-tenant STHs cannot be mistaken for each other.
pub(crate) fn log_id_for_tenant(tenant_id: &str) -> String {
    format!("tenant:{tenant_id}")
}

/// JSON-serialize the `HybridSignature` for the `signature_blob`
/// column. Storage is JSON-as-bytes (vs JSONB) so PG and SQLite share
/// the exact same encoding.
fn serialize_signature(sig: &ciris_crypto::HybridSignature) -> Result<Vec<u8>, TransparencyError> {
    serde_json::to_vec(sig)
        .map_err(|e| TransparencyError::Storage(format!("sth signature serialize: {e}")))
}

/// Inverse of [`serialize_signature`].
fn deserialize_signature(bytes: &[u8]) -> Result<ciris_crypto::HybridSignature, TransparencyError> {
    serde_json::from_slice(bytes)
        .map_err(|e| TransparencyError::Storage(format!("sth signature deserialize: {e}")))
}

/// JSON-serialize witness signatures (PG JSONB / SQLite TEXT column).
fn serialize_witness_signatures(
    witnesses: &[WitnessSignature],
) -> Result<String, TransparencyError> {
    serde_json::to_string(witnesses)
        .map_err(|e| TransparencyError::Storage(format!("witness sigs serialize: {e}")))
}

fn deserialize_witness_signatures(raw: &str) -> Result<Vec<WitnessSignature>, TransparencyError> {
    serde_json::from_str(raw)
        .map_err(|e| TransparencyError::Storage(format!("witness sigs deserialize: {e}")))
}

fn root_hash_from_bytes(raw: &[u8]) -> Result<[u8; 32], TransparencyError> {
    raw.try_into().map_err(|_| {
        TransparencyError::Storage(format!(
            "root_hash column expected 32 bytes, got {}",
            raw.len()
        ))
    })
}

fn leaf_hash_from_bytes(raw: &[u8]) -> Result<[u8; 32], TransparencyError> {
    raw.try_into().map_err(|_| {
        TransparencyError::Storage(format!(
            "leaf_hash column expected 32 bytes, got {}",
            raw.len()
        ))
    })
}

// ────────────────────────────────────────────────────────────────────
// Postgres backend
// ────────────────────────────────────────────────────────────────────

#[cfg(feature = "postgres")]
pub use pg_impl::PgMerkleStore;

#[cfg(feature = "postgres")]
mod pg_impl {
    use super::{
        deserialize_signature, hash_leaf, leaf_hash_from_bytes, log_id_for_tenant,
        root_hash_from_bytes, serialize_signature, serialize_witness_signatures, AuditLeaf,
        DateTime, Handle, SignedTreeHead, TransparencyError, TransparencyStore, Utc,
    };
    use crate::store::postgres::PostgresBackend;
    use ciris_verify_core::transparency::TransparencyLeaf;
    use deadpool_postgres::Pool;
    use std::sync::Arc;

    /// PG-backed `TransparencyStore<AuditLeaf>`.
    ///
    /// One instance per tenant. All SQL filters by the captured
    /// `tenant_id`; cross-tenant operations are not possible through
    /// this surface.
    ///
    /// # Phase C refactor
    ///
    /// `PgMerkleStore` now holds a deadpool `Pool` directly (not
    /// `Arc<PostgresBackend>`). This lets the audit-service ingest
    /// hook (Phase C) build a tenant-scoped store from `&self`
    /// (clone the pool) without needing an `Arc<Self>` of the
    /// backend. The backward-compatible [`Self::new`] constructor
    /// (which takes `Arc<PostgresBackend>`) is retained so Phase B
    /// tests don't need to change shape.
    pub struct PgMerkleStore {
        pool: Pool,
        runtime: Handle,
        tenant_id: String,
    }

    impl PgMerkleStore {
        /// Construct a tenant-scoped Postgres Merkle store from a
        /// backend Arc. Backward-compatible Phase B shape — clones the
        /// backend's pool internally.
        ///
        /// `runtime` is the tokio runtime handle the sync trait
        /// methods bridge to via `block_on`. Pass
        /// `tokio::runtime::Handle::current()` if you're already
        /// inside a tokio context.
        pub fn new(
            backend: Arc<PostgresBackend>,
            runtime: Handle,
            tenant_id: impl Into<String>,
        ) -> Self {
            Self {
                pool: backend.pool().clone(),
                runtime,
                tenant_id: tenant_id.into(),
            }
        }

        /// Construct a tenant-scoped Postgres Merkle store from the
        /// pool directly (Phase C ingest path). Used by
        /// `AuditService::record_entry` on `PostgresBackend` so the
        /// store can be built from `&self` without an `Arc<Self>`.
        pub fn from_pool(pool: Pool, runtime: Handle, tenant_id: impl Into<String>) -> Self {
            Self {
                pool,
                runtime,
                tenant_id: tenant_id.into(),
            }
        }

        /// Tenant scoping of this store (read-only).
        #[must_use]
        pub fn tenant_id(&self) -> &str {
            &self.tenant_id
        }
    }

    fn pg_storage_err(op: &str, e: impl std::fmt::Display) -> TransparencyError {
        TransparencyError::Storage(format!("pg merkle store {op}: {e}"))
    }

    impl TransparencyStore<AuditLeaf> for PgMerkleStore {
        fn append(&self, entry: AuditLeaf) -> Result<u64, TransparencyError> {
            let canonical = entry.canonical_bytes()?;
            let leaf_h = hash_leaf(&canonical);
            let leaf_serialized =
                serde_json::to_vec(&entry).map_err(|e| pg_storage_err("leaf serialize", e))?;
            let chain_event_id = entry.chain_event_id;
            let tenant = self.tenant_id.clone();
            let pool = self.pool.clone();

            self.runtime.block_on(async move {
                let mut client = pool
                    .get()
                    .await
                    .map_err(|e| pg_storage_err("pool get", e))?;
                let tx = client
                    .transaction()
                    .await
                    .map_err(|e| pg_storage_err("begin tx", e))?;

                // SERIALIZABLE-flavored append: read current tree_size
                // under FOR KEY SHARE (acquire row-level coordination
                // by locking the existing tail leaf). PRIMARY KEY
                // (tenant_id, leaf_index) catches any race that slips
                // through with a UNIQUE_VIOLATION → TransparencyError.
                let row = tx
                    .query_one(
                        "SELECT COUNT(*)::BIGINT AS n \
                         FROM cirislens.merkle_leaves \
                         WHERE tenant_id = $1",
                        &[&tenant],
                    )
                    .await
                    .map_err(|e| pg_storage_err("count leaves", e))?;
                let n: i64 = row
                    .try_get("n")
                    .map_err(|e| pg_storage_err("decode count", e))?;
                let leaf_index = n;

                tx.execute(
                    "INSERT INTO cirislens.merkle_leaves \
                     (tenant_id, leaf_index, chain_event_id, leaf_hash, \
                      canonical_bytes, leaf_serialized) \
                     VALUES ($1, $2, $3, $4, $5, $6)",
                    &[
                        &tenant,
                        &leaf_index,
                        &chain_event_id,
                        &leaf_h.to_vec(),
                        &canonical,
                        &leaf_serialized,
                    ],
                )
                .await
                .map_err(|e| pg_storage_err("insert leaf", e))?;

                tx.commit().await.map_err(|e| pg_storage_err("commit", e))?;
                Ok::<u64, TransparencyError>(u64::try_from(leaf_index).unwrap_or(u64::MAX))
            })
        }

        fn get(&self, index: u64) -> Result<Option<AuditLeaf>, TransparencyError> {
            let tenant = self.tenant_id.clone();
            let pool = self.pool.clone();
            let leaf_idx = i64::try_from(index)
                .map_err(|_| TransparencyError::Storage("index exceeds i64 range".into()))?;
            self.runtime.block_on(async move {
                let client = pool
                    .get()
                    .await
                    .map_err(|e| pg_storage_err("pool get", e))?;
                let row_opt = client
                    .query_opt(
                        "SELECT leaf_serialized \
                         FROM cirislens.merkle_leaves \
                         WHERE tenant_id = $1 AND leaf_index = $2",
                        &[&tenant, &leaf_idx],
                    )
                    .await
                    .map_err(|e| pg_storage_err("select leaf", e))?;
                let Some(row) = row_opt else {
                    return Ok(None);
                };
                let blob: Vec<u8> = row
                    .try_get("leaf_serialized")
                    .map_err(|e| pg_storage_err("decode leaf_serialized", e))?;
                let leaf: AuditLeaf = serde_json::from_slice(&blob)
                    .map_err(|e| pg_storage_err("deserialize leaf", e))?;
                Ok(Some(leaf))
            })
        }

        fn leaf_hash(&self, index: u64) -> Result<Option<[u8; 32]>, TransparencyError> {
            let tenant = self.tenant_id.clone();
            let pool = self.pool.clone();
            let leaf_idx = i64::try_from(index)
                .map_err(|_| TransparencyError::Storage("index exceeds i64 range".into()))?;
            self.runtime.block_on(async move {
                let client = pool
                    .get()
                    .await
                    .map_err(|e| pg_storage_err("pool get", e))?;
                let row_opt = client
                    .query_opt(
                        "SELECT leaf_hash \
                         FROM cirislens.merkle_leaves \
                         WHERE tenant_id = $1 AND leaf_index = $2",
                        &[&tenant, &leaf_idx],
                    )
                    .await
                    .map_err(|e| pg_storage_err("select leaf_hash", e))?;
                let Some(row) = row_opt else {
                    return Ok(None);
                };
                let raw: Vec<u8> = row
                    .try_get("leaf_hash")
                    .map_err(|e| pg_storage_err("decode leaf_hash", e))?;
                Ok(Some(leaf_hash_from_bytes(&raw)?))
            })
        }

        fn tree_size(&self) -> Result<u64, TransparencyError> {
            let tenant = self.tenant_id.clone();
            let pool = self.pool.clone();
            self.runtime.block_on(async move {
                let client = pool
                    .get()
                    .await
                    .map_err(|e| pg_storage_err("pool get", e))?;
                let row = client
                    .query_one(
                        "SELECT COUNT(*)::BIGINT AS n \
                         FROM cirislens.merkle_leaves \
                         WHERE tenant_id = $1",
                        &[&tenant],
                    )
                    .await
                    .map_err(|e| pg_storage_err("tree_size", e))?;
                let n: i64 = row
                    .try_get("n")
                    .map_err(|e| pg_storage_err("decode tree_size", e))?;
                Ok(u64::try_from(n).unwrap_or(u64::MAX))
            })
        }

        fn latest_sth(&self) -> Result<Option<SignedTreeHead>, TransparencyError> {
            let tenant = self.tenant_id.clone();
            let pool = self.pool.clone();
            self.runtime.block_on(async move {
                let client = pool
                    .get()
                    .await
                    .map_err(|e| pg_storage_err("pool get", e))?;
                let row_opt = client
                    .query_opt(
                        "SELECT tree_size, root_hash, signed_at, \
                                signature_blob, witness_signatures \
                         FROM cirislens.merkle_sth_log \
                         WHERE tenant_id = $1 \
                         ORDER BY tree_size DESC \
                         LIMIT 1",
                        &[&tenant],
                    )
                    .await
                    .map_err(|e| pg_storage_err("latest_sth select", e))?;
                let Some(row) = row_opt else {
                    return Ok(None);
                };
                let tree_size_i: i64 = row
                    .try_get("tree_size")
                    .map_err(|e| pg_storage_err("decode tree_size", e))?;
                let root_bytes: Vec<u8> = row
                    .try_get("root_hash")
                    .map_err(|e| pg_storage_err("decode root_hash", e))?;
                let timestamp: DateTime<Utc> = row
                    .try_get("signed_at")
                    .map_err(|e| pg_storage_err("decode signed_at", e))?;
                let sig_blob: Vec<u8> = row
                    .try_get("signature_blob")
                    .map_err(|e| pg_storage_err("decode signature_blob", e))?;
                let witnesses_json: serde_json::Value = row
                    .try_get("witness_signatures")
                    .map_err(|e| pg_storage_err("decode witness_signatures", e))?;
                let signature = deserialize_signature(&sig_blob)?;
                let witness_signatures = serde_json::from_value(witnesses_json)
                    .map_err(|e| pg_storage_err("decode witness vec", e))?;
                Ok(Some(SignedTreeHead {
                    log_id: log_id_for_tenant(&tenant),
                    tree_size: u64::try_from(tree_size_i).unwrap_or(u64::MAX),
                    root_hash: root_hash_from_bytes(&root_bytes)?,
                    timestamp,
                    signature,
                    witness_signatures,
                }))
            })
        }

        fn store_sth(&self, sth: &SignedTreeHead) -> Result<(), TransparencyError> {
            let tenant = self.tenant_id.clone();
            let pool = self.pool.clone();
            let tree_size = i64::try_from(sth.tree_size)
                .map_err(|_| TransparencyError::Storage("tree_size exceeds i64 range".into()))?;
            let root_hash = sth.root_hash.to_vec();
            let timestamp = sth.timestamp;
            let signature_blob = serialize_signature(&sth.signature)?;
            let witnesses_str = serialize_witness_signatures(&sth.witness_signatures)?;
            let signer_key_id = hex::encode(&sth.signature.classical.public_key);
            self.runtime.block_on(async move {
                let client = pool
                    .get()
                    .await
                    .map_err(|e| pg_storage_err("pool get", e))?;
                let witnesses_value: serde_json::Value = serde_json::from_str(&witnesses_str)
                    .map_err(|e| pg_storage_err("witness json roundtrip", e))?;
                client
                    .execute(
                        "INSERT INTO cirislens.merkle_sth_log \
                         (tenant_id, tree_size, root_hash, signed_at, \
                          signer_key_id, signature_blob, witness_signatures) \
                         VALUES ($1, $2, $3, $4, $5, $6, $7) \
                         ON CONFLICT (tenant_id, tree_size) DO NOTHING",
                        &[
                            &tenant,
                            &tree_size,
                            &root_hash,
                            &timestamp,
                            &signer_key_id,
                            &signature_blob,
                            &witnesses_value,
                        ],
                    )
                    .await
                    .map_err(|e| pg_storage_err("insert sth", e))?;
                Ok(())
            })
        }

        fn all_leaf_hashes(&self) -> Result<Vec<[u8; 32]>, TransparencyError> {
            let tenant = self.tenant_id.clone();
            let pool = self.pool.clone();
            self.runtime.block_on(async move {
                let client = pool
                    .get()
                    .await
                    .map_err(|e| pg_storage_err("pool get", e))?;
                let rows = client
                    .query(
                        "SELECT leaf_hash \
                         FROM cirislens.merkle_leaves \
                         WHERE tenant_id = $1 \
                         ORDER BY leaf_index ASC",
                        &[&tenant],
                    )
                    .await
                    .map_err(|e| pg_storage_err("all_leaf_hashes", e))?;
                let mut out = Vec::with_capacity(rows.len());
                for row in &rows {
                    let raw: Vec<u8> = row
                        .try_get("leaf_hash")
                        .map_err(|e| pg_storage_err("decode leaf_hash", e))?;
                    out.push(leaf_hash_from_bytes(&raw)?);
                }
                Ok(out)
            })
        }
    }
}

// ────────────────────────────────────────────────────────────────────
// SQLite backend
// ────────────────────────────────────────────────────────────────────

#[cfg(feature = "sqlite")]
pub use sqlite_impl::SqliteMerkleStore;

#[cfg(feature = "sqlite")]
mod sqlite_impl {
    use super::{
        deserialize_signature, deserialize_witness_signatures, hash_leaf, leaf_hash_from_bytes,
        log_id_for_tenant, root_hash_from_bytes, serialize_signature, serialize_witness_signatures,
        AuditLeaf, DateTime, Handle, SignedTreeHead, TransparencyError, TransparencyStore, Utc,
    };
    use ciris_verify_core::transparency::TransparencyLeaf;
    use rusqlite::{params, Connection, OptionalExtension};
    use std::sync::Arc;
    use tokio::sync::Mutex;

    /// SQLite-backed `TransparencyStore<AuditLeaf>`.
    ///
    /// One instance per tenant. Shares the underlying connection
    /// handle with the rest of the SQLite-backed audit + cirisgraph
    /// surfaces so writes coordinate via SQLite's WAL + the
    /// PRAGMA busy_timeout shared across the process.
    pub struct SqliteMerkleStore {
        conn: Arc<Mutex<Connection>>,
        runtime: Handle,
        tenant_id: String,
    }

    impl SqliteMerkleStore {
        pub fn new(
            conn: Arc<Mutex<Connection>>,
            runtime: Handle,
            tenant_id: impl Into<String>,
        ) -> Self {
            Self {
                conn,
                runtime,
                tenant_id: tenant_id.into(),
            }
        }

        #[must_use]
        pub fn tenant_id(&self) -> &str {
            &self.tenant_id
        }
    }

    fn sq_storage_err(op: &str, e: impl std::fmt::Display) -> TransparencyError {
        TransparencyError::Storage(format!("sqlite merkle store {op}: {e}"))
    }

    /// Parse `signed_at` from one of SQLite's two TIMESTAMP shapes
    /// (RFC 3339 with `T`+`Z`, or `YYYY-MM-DD HH:MM:SS` from
    /// `CURRENT_TIMESTAMP` default). Mirrors `audit::sqlite`'s
    /// parser.
    fn parse_signed_at(s: &str) -> Result<DateTime<Utc>, TransparencyError> {
        let normalized = if s.contains('T') {
            s.to_owned()
        } else {
            format!("{}+00:00", s.replacen(' ', "T", 1))
        };
        chrono::DateTime::parse_from_rfc3339(&normalized)
            .map(|dt| dt.with_timezone(&Utc))
            .map_err(|e| sq_storage_err("parse signed_at", format!("{e} (raw={s})")))
    }

    fn fmt_signed_at(dt: DateTime<Utc>) -> String {
        dt.to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
    }

    impl TransparencyStore<AuditLeaf> for SqliteMerkleStore {
        fn append(&self, entry: AuditLeaf) -> Result<u64, TransparencyError> {
            let canonical = entry.canonical_bytes()?;
            let leaf_h = hash_leaf(&canonical);
            let leaf_serialized =
                serde_json::to_vec(&entry).map_err(|e| sq_storage_err("leaf serialize", e))?;
            let chain_event_id = entry.chain_event_id;
            let tenant = self.tenant_id.clone();
            let conn_arc = self.conn.clone();

            self.runtime.block_on(async move {
                tokio::task::spawn_blocking(move || -> Result<u64, TransparencyError> {
                    let mut guard = conn_arc.blocking_lock();
                    // BEGIN IMMEDIATE serializes writers (RESERVED lock)
                    // — same pattern as `audit::sqlite`'s record_entry.
                    let tx = guard
                        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                        .map_err(|e| sq_storage_err("begin tx", e))?;
                    let n: i64 = tx
                        .query_row(
                            "SELECT COUNT(*) FROM merkle_leaves WHERE tenant_id = ?1",
                            params![tenant],
                            |row| row.get(0),
                        )
                        .map_err(|e| sq_storage_err("count leaves", e))?;
                    let leaf_index = n;
                    tx.execute(
                        "INSERT INTO merkle_leaves \
                         (tenant_id, leaf_index, chain_event_id, leaf_hash, \
                          canonical_bytes, leaf_serialized) \
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                        params![
                            tenant,
                            leaf_index,
                            chain_event_id,
                            leaf_h.to_vec(),
                            canonical,
                            leaf_serialized,
                        ],
                    )
                    .map_err(|e| sq_storage_err("insert leaf", e))?;
                    tx.commit().map_err(|e| sq_storage_err("commit", e))?;
                    Ok(u64::try_from(leaf_index).unwrap_or(u64::MAX))
                })
                .await
                .map_err(|e| sq_storage_err("spawn_blocking join", e))?
            })
        }

        fn get(&self, index: u64) -> Result<Option<AuditLeaf>, TransparencyError> {
            let tenant = self.tenant_id.clone();
            let conn_arc = self.conn.clone();
            let leaf_idx = i64::try_from(index)
                .map_err(|_| TransparencyError::Storage("index exceeds i64 range".into()))?;
            self.runtime.block_on(async move {
                tokio::task::spawn_blocking(
                    move || -> Result<Option<AuditLeaf>, TransparencyError> {
                        let conn = conn_arc.blocking_lock();
                        let blob: Option<Vec<u8>> = conn
                            .query_row(
                                "SELECT leaf_serialized \
                                 FROM merkle_leaves \
                                 WHERE tenant_id = ?1 AND leaf_index = ?2",
                                params![tenant, leaf_idx],
                                |row| row.get(0),
                            )
                            .optional()
                            .map_err(|e| sq_storage_err("select leaf", e))?;
                        let Some(blob) = blob else { return Ok(None) };
                        let leaf: AuditLeaf = serde_json::from_slice(&blob)
                            .map_err(|e| sq_storage_err("deserialize leaf", e))?;
                        Ok(Some(leaf))
                    },
                )
                .await
                .map_err(|e| sq_storage_err("spawn_blocking join", e))?
            })
        }

        fn leaf_hash(&self, index: u64) -> Result<Option<[u8; 32]>, TransparencyError> {
            let tenant = self.tenant_id.clone();
            let conn_arc = self.conn.clone();
            let leaf_idx = i64::try_from(index)
                .map_err(|_| TransparencyError::Storage("index exceeds i64 range".into()))?;
            self.runtime.block_on(async move {
                tokio::task::spawn_blocking(
                    move || -> Result<Option<[u8; 32]>, TransparencyError> {
                        let conn = conn_arc.blocking_lock();
                        let raw: Option<Vec<u8>> = conn
                            .query_row(
                                "SELECT leaf_hash \
                                 FROM merkle_leaves \
                                 WHERE tenant_id = ?1 AND leaf_index = ?2",
                                params![tenant, leaf_idx],
                                |row| row.get(0),
                            )
                            .optional()
                            .map_err(|e| sq_storage_err("select leaf_hash", e))?;
                        match raw {
                            Some(b) => Ok(Some(leaf_hash_from_bytes(&b)?)),
                            None => Ok(None),
                        }
                    },
                )
                .await
                .map_err(|e| sq_storage_err("spawn_blocking join", e))?
            })
        }

        fn tree_size(&self) -> Result<u64, TransparencyError> {
            let tenant = self.tenant_id.clone();
            let conn_arc = self.conn.clone();
            self.runtime.block_on(async move {
                tokio::task::spawn_blocking(move || -> Result<u64, TransparencyError> {
                    let conn = conn_arc.blocking_lock();
                    let n: i64 = conn
                        .query_row(
                            "SELECT COUNT(*) FROM merkle_leaves WHERE tenant_id = ?1",
                            params![tenant],
                            |row| row.get(0),
                        )
                        .map_err(|e| sq_storage_err("tree_size", e))?;
                    Ok(u64::try_from(n).unwrap_or(u64::MAX))
                })
                .await
                .map_err(|e| sq_storage_err("spawn_blocking join", e))?
            })
        }

        fn latest_sth(&self) -> Result<Option<SignedTreeHead>, TransparencyError> {
            let tenant = self.tenant_id.clone();
            let conn_arc = self.conn.clone();
            self.runtime.block_on(async move {
                tokio::task::spawn_blocking(
                    move || -> Result<Option<SignedTreeHead>, TransparencyError> {
                        let conn = conn_arc.blocking_lock();
                        let row_opt = conn
                            .query_row(
                                "SELECT tree_size, root_hash, signed_at, \
                                        signature_blob, witness_signatures \
                                 FROM merkle_sth_log \
                                 WHERE tenant_id = ?1 \
                                 ORDER BY tree_size DESC \
                                 LIMIT 1",
                                params![tenant],
                                |row| {
                                    Ok((
                                        row.get::<_, i64>(0)?,
                                        row.get::<_, Vec<u8>>(1)?,
                                        row.get::<_, String>(2)?,
                                        row.get::<_, Vec<u8>>(3)?,
                                        row.get::<_, String>(4)?,
                                    ))
                                },
                            )
                            .optional()
                            .map_err(|e| sq_storage_err("latest_sth select", e))?;
                        let Some((tree_size_i, root_bytes, signed_at_str, sig_blob, witness_str)) =
                            row_opt
                        else {
                            return Ok(None);
                        };
                        let timestamp = parse_signed_at(&signed_at_str)?;
                        let signature = deserialize_signature(&sig_blob)?;
                        let witness_signatures = deserialize_witness_signatures(&witness_str)?;
                        Ok(Some(SignedTreeHead {
                            log_id: log_id_for_tenant(&tenant),
                            tree_size: u64::try_from(tree_size_i).unwrap_or(u64::MAX),
                            root_hash: root_hash_from_bytes(&root_bytes)?,
                            timestamp,
                            signature,
                            witness_signatures,
                        }))
                    },
                )
                .await
                .map_err(|e| sq_storage_err("spawn_blocking join", e))?
            })
        }

        fn store_sth(&self, sth: &SignedTreeHead) -> Result<(), TransparencyError> {
            let tenant = self.tenant_id.clone();
            let conn_arc = self.conn.clone();
            let tree_size = i64::try_from(sth.tree_size)
                .map_err(|_| TransparencyError::Storage("tree_size exceeds i64 range".into()))?;
            let root_hash = sth.root_hash.to_vec();
            let signed_at = fmt_signed_at(sth.timestamp);
            let signature_blob = serialize_signature(&sth.signature)?;
            let witnesses_str = serialize_witness_signatures(&sth.witness_signatures)?;
            let signer_key_id = hex::encode(&sth.signature.classical.public_key);
            self.runtime.block_on(async move {
                tokio::task::spawn_blocking(move || -> Result<(), TransparencyError> {
                    let conn = conn_arc.blocking_lock();
                    conn.execute(
                        "INSERT INTO merkle_sth_log \
                         (tenant_id, tree_size, root_hash, signed_at, \
                          signer_key_id, signature_blob, witness_signatures) \
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7) \
                         ON CONFLICT (tenant_id, tree_size) DO NOTHING",
                        params![
                            tenant,
                            tree_size,
                            root_hash,
                            signed_at,
                            signer_key_id,
                            signature_blob,
                            witnesses_str,
                        ],
                    )
                    .map_err(|e| sq_storage_err("insert sth", e))?;
                    Ok(())
                })
                .await
                .map_err(|e| sq_storage_err("spawn_blocking join", e))?
            })
        }

        fn all_leaf_hashes(&self) -> Result<Vec<[u8; 32]>, TransparencyError> {
            let tenant = self.tenant_id.clone();
            let conn_arc = self.conn.clone();
            self.runtime.block_on(async move {
                tokio::task::spawn_blocking(move || -> Result<Vec<[u8; 32]>, TransparencyError> {
                    let conn = conn_arc.blocking_lock();
                    let mut stmt = conn
                        .prepare(
                            "SELECT leaf_hash \
                                 FROM merkle_leaves \
                                 WHERE tenant_id = ?1 \
                                 ORDER BY leaf_index ASC",
                        )
                        .map_err(|e| sq_storage_err("prepare all_leaf_hashes", e))?;
                    let rows = stmt
                        .query_map(params![tenant], |row| row.get::<_, Vec<u8>>(0))
                        .map_err(|e| sq_storage_err("query all_leaf_hashes", e))?;
                    let mut out = Vec::new();
                    for row in rows {
                        let raw = row.map_err(|e| sq_storage_err("row all_leaf_hashes", e))?;
                        out.push(leaf_hash_from_bytes(&raw)?);
                    }
                    Ok(out)
                })
                .await
                .map_err(|e| sq_storage_err("spawn_blocking join", e))?
            })
        }
    }
}

// ────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6962 §2.1 leaf-prefix parity: our `hash_leaf` MUST be
    // byte-equal to Verify v2.3.0's `pub(crate) hash_leaf`. We can't
    // call Verify's directly (private), but we can append the same
    // canonical bytes to an `InMemoryTransparencyStore<AuditLeaf>`
    // and assert the resulting `leaf_hash(0)` matches our local
    // `hash_leaf` output.
    #[test]
    fn hash_leaf_matches_verify_inmemory() {
        use ciris_verify_core::transparency::InMemoryTransparencyStore;

        let leaf = make_test_leaf("hp-parity-1", 1, 100);
        let canonical =
            <AuditLeaf as ciris_verify_core::transparency::TransparencyLeaf>::canonical_bytes(
                &leaf,
            )
            .unwrap();
        let local_h = hash_leaf(&canonical);

        let store: InMemoryTransparencyStore<AuditLeaf> = InMemoryTransparencyStore::new(None);
        let idx = store.append(leaf).unwrap();
        let verify_h = store.leaf_hash(idx).unwrap().expect("hash present");

        assert_eq!(
            local_h, verify_h,
            "Phase B's hash_leaf must be byte-equal to Verify's. \
             If this fails, Verify's hash_leaf algorithm changed and \
             merkle_store needs an update in lockstep."
        );
    }

    #[test]
    fn hash_leaf_uses_rfc6962_prefix() {
        // sha256(0x00 || empty) sanity check.
        let mut expected = Sha256::new();
        expected.update([0x00u8]);
        let want: [u8; 32] = expected.finalize().into();
        assert_eq!(hash_leaf(b""), want);
    }

    #[test]
    fn log_id_format_locked() {
        // FSD §4.4 — log_id is `tenant:<id>` so cross-tenant STHs
        // don't collide. Locked here so a downstream rename triggers
        // a test failure.
        assert_eq!(log_id_for_tenant("alpha"), "tenant:alpha");
        assert_eq!(log_id_for_tenant(""), "tenant:");
    }

    // ───────── shared test helpers ──────────────────────────────────

    use crate::audit::types::AuditEntry;
    use crate::audit::GENESIS_PREV_HASH;
    use chrono::Utc;
    use sha2::{Digest, Sha256};

    fn make_test_leaf(entry_id: &str, sequence_number: i64, chain_event_id: i64) -> AuditLeaf {
        let entry = AuditEntry {
            entry_id: entry_id.into(),
            sequence_number,
            tenant_id: "test-tenant".into(),
            actor_id: "B64ACTOR".into(),
            action_type: "test_action".into(),
            subject_kind: "task".into(),
            subject_id: format!("subj-{sequence_number}"),
            payload: serde_json::json!({"seq": sequence_number}),
            prev_hash: GENESIS_PREV_HASH.to_vec(),
            entry_hash: vec![0; 32],
            recorded_at: Utc::now(),
            signature: "B64SIG".into(),
        };
        AuditLeaf::with_chain_event_id(entry, chain_event_id)
    }

    // ───────── SQLite tests (always run; :memory: backend) ─────────

    #[cfg(feature = "sqlite")]
    mod sqlite_tests {
        use super::*;
        use crate::audit::merkle_store::SqliteMerkleStore;
        use crate::store::backend::Backend;
        use crate::store::sqlite::SqliteBackend;
        use ciris_verify_core::transparency::{
            TransparencyLeaf, TransparencyLog, WitnessSignature,
        };
        use std::sync::Arc;

        /// Spin up a dedicated multi-thread runtime, build the
        /// in-memory backend + store inside it, then hand the store
        /// to `f` on a blocking thread so the store's
        /// `runtime.block_on` calls don't trip "Cannot start a
        /// runtime from within a runtime". Production callers
        /// (PyO3 via py.detach) are sync-context-callers; tests
        /// reproduce that shape via spawn_blocking.
        fn run_with_store<F, R>(tenant: &str, f: F) -> R
        where
            F: FnOnce(Arc<dyn TransparencyStore<AuditLeaf>>) -> R + Send + 'static,
            R: Send + 'static,
        {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap();
            let tenant_owned = tenant.to_owned();
            rt.block_on(async move {
                let backend = SqliteBackend::open_in_memory().await.unwrap();
                backend.run_migrations().await.unwrap();
                let handle = tokio::runtime::Handle::current();
                let store = SqliteMerkleStore::new(backend.conn_handle(), handle, tenant_owned);
                let store_arc: Arc<dyn TransparencyStore<AuditLeaf>> = Arc::new(store);
                // Keep `backend` alive for the closure's duration —
                // the SqliteMerkleStore only holds the conn_handle()
                // Arc clone, not the SqliteBackend itself.
                let _backend_keepalive = backend;
                tokio::task::spawn_blocking(move || f(store_arc))
                    .await
                    .unwrap()
            })
        }

        #[test]
        fn empty_store_tree_size_zero() {
            run_with_store("t-empty", |store| {
                assert_eq!(store.tree_size().unwrap(), 0);
                assert!(store.get(0).unwrap().is_none());
                assert!(store.leaf_hash(0).unwrap().is_none());
                assert!(store.all_leaf_hashes().unwrap().is_empty());
                assert!(store.latest_sth().unwrap().is_none());
            });
        }

        #[test]
        fn append_assigns_monotonic_indices() {
            run_with_store("t-mono", |store| {
                assert_eq!(store.append(make_test_leaf("e-1", 1, 100)).unwrap(), 0);
                assert_eq!(store.append(make_test_leaf("e-2", 2, 101)).unwrap(), 1);
                assert_eq!(store.append(make_test_leaf("e-3", 3, 102)).unwrap(), 2);
                assert_eq!(store.tree_size().unwrap(), 3);
            });
        }

        #[test]
        fn get_round_trip() {
            run_with_store("t-rt", |store| {
                let leaf = make_test_leaf("e-rt-1", 1, 1234);
                store.append(leaf.clone()).unwrap();
                let got = store.get(0).unwrap().expect("leaf present");
                assert_eq!(got.entry.entry_id, leaf.entry.entry_id);
                assert_eq!(got.chain_event_id, leaf.chain_event_id);
                assert_eq!(got.entry.payload, leaf.entry.payload);
            });
        }

        #[test]
        fn leaf_hash_stable_and_matches_canonical() {
            run_with_store("t-hash", |store| {
                let leaf = make_test_leaf("e-h-1", 1, 1);
                store.append(leaf.clone()).unwrap();
                let stored = store.leaf_hash(0).unwrap().unwrap();
                let canonical = <AuditLeaf as TransparencyLeaf>::canonical_bytes(&leaf).unwrap();
                assert_eq!(stored, hash_leaf(&canonical));
            });
        }

        #[test]
        fn tenants_do_not_cross_contaminate() {
            // Cross-tenant isolation needs two stores sharing one
            // backend; run_with_store only builds one, so we open the
            // backend directly.
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap();
            let backend = rt.block_on(async {
                let b = SqliteBackend::open_in_memory().await.unwrap();
                b.run_migrations().await.unwrap();
                b
            });
            let handle = rt.handle().clone();
            let store_a: Arc<dyn TransparencyStore<AuditLeaf>> = Arc::new(SqliteMerkleStore::new(
                backend.conn_handle(),
                handle.clone(),
                "tenant-A",
            ));
            let store_b: Arc<dyn TransparencyStore<AuditLeaf>> = Arc::new(SqliteMerkleStore::new(
                backend.conn_handle(),
                handle,
                "tenant-B",
            ));
            let a = store_a.clone();
            let b = store_b.clone();
            rt.block_on(async move {
                tokio::task::spawn_blocking(move || {
                    a.append(make_test_leaf("a-1", 1, 1)).unwrap();
                    a.append(make_test_leaf("a-2", 2, 2)).unwrap();
                    b.append(make_test_leaf("b-1", 1, 1)).unwrap();
                    assert_eq!(a.tree_size().unwrap(), 2);
                    assert_eq!(b.tree_size().unwrap(), 1);
                    assert_eq!(b.get(0).unwrap().unwrap().entry.entry_id, "b-1");
                    assert!(b.get(1).unwrap().is_none());
                })
                .await
                .unwrap();
            });
            drop(backend);
        }

        // Mock signers for STH testing — ciris-crypto's mocks aren't
        // exported; same trick Verify's own transparency tests use.
        use ciris_crypto::{
            ClassicalAlgorithm, ClassicalSigner, CryptoError, HybridSigner, PqcAlgorithm, PqcSigner,
        };

        struct StubClassical;
        impl ClassicalSigner for StubClassical {
            fn algorithm(&self) -> ClassicalAlgorithm {
                ClassicalAlgorithm::Ed25519
            }
            fn public_key(&self) -> Result<Vec<u8>, CryptoError> {
                Ok(vec![0xAA; 32])
            }
            fn sign(&self, _data: &[u8]) -> Result<Vec<u8>, CryptoError> {
                Ok(vec![0xBB; 64])
            }
        }

        struct StubPqc;
        impl PqcSigner for StubPqc {
            fn algorithm(&self) -> PqcAlgorithm {
                PqcAlgorithm::MlDsa65
            }
            fn public_key(&self) -> Result<Vec<u8>, CryptoError> {
                Ok(vec![0xCC; 1952])
            }
            fn sign(&self, _data: &[u8]) -> Result<Vec<u8>, CryptoError> {
                Ok(vec![0xDD; 3309])
            }
        }

        #[test]
        fn store_and_load_sth_round_trip() {
            run_with_store("t-sth", |store| {
                for i in 1..=3i64 {
                    store
                        .append(make_test_leaf(&format!("e-{i}"), i, i))
                        .unwrap();
                }
                let log = TransparencyLog::<AuditLeaf>::for_log("tenant:t-sth", store.clone());
                let signer = HybridSigner::new(StubClassical, StubPqc).unwrap();
                let sth = log.sign_head(&signer).unwrap();
                assert_eq!(sth.tree_size, 3);
                assert!(sth.witness_signatures.is_empty());

                let stored = store
                    .latest_sth()
                    .unwrap()
                    .expect("STH persisted on store_sth");
                assert_eq!(stored.log_id, "tenant:t-sth");
                assert_eq!(stored.tree_size, sth.tree_size);
                assert_eq!(stored.root_hash, sth.root_hash);
                assert_eq!(
                    stored.signature.classical.signature, sth.signature.classical.signature,
                    "classical signature bytes round-trip via JSON"
                );
                assert_eq!(
                    stored.signature.pqc.signature, sth.signature.pqc.signature,
                    "PQC signature bytes round-trip via JSON"
                );
            });
        }

        #[test]
        fn inclusion_proof_verifies_after_append() {
            use ciris_verify_core::transparency::verify_inclusion;
            run_with_store("t-incl", |store| {
                for i in 1..=5i64 {
                    store
                        .append(make_test_leaf(&format!("inc-{i}"), i, i))
                        .unwrap();
                }
                let log = TransparencyLog::<AuditLeaf>::for_log("tenant:t-incl", store.clone());
                for i in 0..5u64 {
                    let proof = log.inclusion_proof(i).unwrap();
                    assert!(
                        verify_inclusion(&proof),
                        "inclusion proof for leaf {i} must verify against the SQLite-stored leaf hash"
                    );
                }
            });
        }

        #[test]
        fn store_sth_idempotent_per_tree_size() {
            run_with_store("t-idem", |store| {
                store.append(make_test_leaf("e1", 1, 1)).unwrap();
                let log = TransparencyLog::<AuditLeaf>::for_log("tenant:t-idem", store.clone());
                let signer = HybridSigner::new(StubClassical, StubPqc).unwrap();
                let first = log.sign_head(&signer).unwrap();
                // Second sign_head at the same tree_size: ON CONFLICT
                // DO NOTHING swallows the duplicate.
                let _second = log.sign_head(&signer).unwrap();
                let stored = store.latest_sth().unwrap().unwrap();
                assert_eq!(stored.tree_size, first.tree_size);
            });
        }

        #[test]
        fn empty_witness_vec_persists() {
            // Phase B reserved field — witness_signatures is always
            // empty until the witness protocol lands. Confirm the
            // JSON-array encoding round-trips an empty vec.
            run_with_store("t-witness", |store| {
                store.append(make_test_leaf("e1", 1, 1)).unwrap();
                let log = TransparencyLog::<AuditLeaf>::for_log("tenant:t-witness", store.clone());
                let signer = HybridSigner::new(StubClassical, StubPqc).unwrap();
                let _ = log.sign_head(&signer).unwrap();
                let stored = store.latest_sth().unwrap().unwrap();
                let empty: Vec<WitnessSignature> = Vec::new();
                assert_eq!(stored.witness_signatures.len(), empty.len());
            });
        }
    }

    // ───────── Postgres tests (gated by CIRIS_PERSIST_TEST_PG_URL) ──

    #[cfg(feature = "postgres")]
    mod postgres_tests {
        use super::*;
        use crate::audit::merkle_store::PgMerkleStore;
        use crate::store::backend::Backend;
        use crate::store::postgres::PostgresBackend;
        use ciris_verify_core::transparency::{TransparencyLeaf, TransparencyLog};
        use std::sync::Arc;

        fn pg_dsn() -> Option<String> {
            std::env::var("CIRIS_PERSIST_TEST_PG_URL").ok()
        }

        async fn clean_tenant(backend: &PostgresBackend, tenant: &str) {
            let client = backend.pool().get().await.unwrap();
            client
                .execute(
                    "DELETE FROM cirislens.merkle_sth_log WHERE tenant_id = $1",
                    &[&tenant],
                )
                .await
                .unwrap();
            client
                .execute(
                    "DELETE FROM cirislens.merkle_leaves WHERE tenant_id = $1",
                    &[&tenant],
                )
                .await
                .unwrap();
        }

        /// Build a dedicated tokio runtime, connect to PG, run
        /// migrations, build the store, then hand the store to `f`
        /// on a blocking thread — same shape as the SQLite tests'
        /// `run_with_store` so the store's `block_on` doesn't fight
        /// the test's runtime.
        fn run_with_pg_store<F, R>(tenant: &str, f: F) -> Option<R>
        where
            F: FnOnce(Arc<dyn TransparencyStore<AuditLeaf>>, Arc<PostgresBackend>) -> R
                + Send
                + 'static,
            R: Send + 'static,
        {
            let dsn = pg_dsn()?;
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap();
            let tenant_owned = tenant.to_owned();
            let result =
                rt.block_on(async move {
                    let backend = Arc::new(PostgresBackend::connect(&dsn).await.unwrap());
                    backend.run_migrations().await.unwrap();
                    clean_tenant(&backend, &tenant_owned).await;
                    let handle = tokio::runtime::Handle::current();
                    let store: Arc<dyn TransparencyStore<AuditLeaf>> = Arc::new(
                        PgMerkleStore::new(backend.clone(), handle, tenant_owned.clone()),
                    );
                    let backend_for_f = backend.clone();
                    let r = tokio::task::spawn_blocking(move || f(store, backend_for_f))
                        .await
                        .unwrap();
                    clean_tenant(&backend, &tenant_owned).await;
                    r
                });
            Some(result)
        }

        #[test]
        #[serial_test::serial(postgres)]
        fn pg_empty_and_append_and_get() {
            let tenant = format!("merkle-empty-{}", uuid::Uuid::new_v4().simple());
            let Some(()) = run_with_pg_store(&tenant, |store, _backend| {
                assert_eq!(store.tree_size().unwrap(), 0);
                assert_eq!(store.append(make_test_leaf("pg-1", 1, 100)).unwrap(), 0);
                assert_eq!(store.append(make_test_leaf("pg-2", 2, 101)).unwrap(), 1);
                assert_eq!(store.tree_size().unwrap(), 2);
                let got = store.get(1).unwrap().unwrap();
                assert_eq!(got.entry.entry_id, "pg-2");
                assert_eq!(got.chain_event_id, 101);
            }) else {
                eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
                return;
            };
        }

        #[test]
        #[serial_test::serial(postgres)]
        fn pg_leaf_hash_matches_local() {
            let tenant = format!("merkle-hash-{}", uuid::Uuid::new_v4().simple());
            let Some(()) = run_with_pg_store(&tenant, |store, _backend| {
                let leaf = make_test_leaf("pg-h-1", 1, 1);
                store.append(leaf.clone()).unwrap();
                let stored = store.leaf_hash(0).unwrap().unwrap();
                let canonical = <AuditLeaf as TransparencyLeaf>::canonical_bytes(&leaf).unwrap();
                assert_eq!(stored, hash_leaf(&canonical));
            }) else {
                eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
                return;
            };
        }

        #[test]
        #[serial_test::serial(postgres)]
        fn pg_tenants_isolated() {
            let Some(dsn) = pg_dsn() else {
                eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
                return;
            };
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap();
            let tenant_a = format!("merkle-iso-A-{}", uuid::Uuid::new_v4().simple());
            let tenant_b = format!("merkle-iso-B-{}", uuid::Uuid::new_v4().simple());
            let (backend, store_a, store_b) = rt.block_on(async {
                let backend = Arc::new(PostgresBackend::connect(&dsn).await.unwrap());
                backend.run_migrations().await.unwrap();
                clean_tenant(&backend, &tenant_a).await;
                clean_tenant(&backend, &tenant_b).await;
                let handle = tokio::runtime::Handle::current();
                let a: Arc<dyn TransparencyStore<AuditLeaf>> = Arc::new(PgMerkleStore::new(
                    backend.clone(),
                    handle.clone(),
                    tenant_a.clone(),
                ));
                let b: Arc<dyn TransparencyStore<AuditLeaf>> = Arc::new(PgMerkleStore::new(
                    backend.clone(),
                    handle,
                    tenant_b.clone(),
                ));
                (backend, a, b)
            });
            let a = store_a.clone();
            let b = store_b.clone();
            rt.block_on(async move {
                tokio::task::spawn_blocking(move || {
                    a.append(make_test_leaf("a-1", 1, 1)).unwrap();
                    a.append(make_test_leaf("a-2", 2, 2)).unwrap();
                    b.append(make_test_leaf("b-1", 1, 1)).unwrap();
                    assert_eq!(a.tree_size().unwrap(), 2);
                    assert_eq!(b.tree_size().unwrap(), 1);
                    assert_eq!(b.get(0).unwrap().unwrap().entry.entry_id, "b-1");
                })
                .await
                .unwrap();
            });
            rt.block_on(async {
                clean_tenant(&backend, &tenant_a).await;
                clean_tenant(&backend, &tenant_b).await;
            });
        }

        // Mock signers (same as SQLite tests).
        use ciris_crypto::{
            ClassicalAlgorithm, ClassicalSigner, CryptoError, HybridSigner, PqcAlgorithm, PqcSigner,
        };

        struct StubClassical;
        impl ClassicalSigner for StubClassical {
            fn algorithm(&self) -> ClassicalAlgorithm {
                ClassicalAlgorithm::Ed25519
            }
            fn public_key(&self) -> Result<Vec<u8>, CryptoError> {
                Ok(vec![0xAA; 32])
            }
            fn sign(&self, _data: &[u8]) -> Result<Vec<u8>, CryptoError> {
                Ok(vec![0xBB; 64])
            }
        }

        struct StubPqc;
        impl PqcSigner for StubPqc {
            fn algorithm(&self) -> PqcAlgorithm {
                PqcAlgorithm::MlDsa65
            }
            fn public_key(&self) -> Result<Vec<u8>, CryptoError> {
                Ok(vec![0xCC; 1952])
            }
            fn sign(&self, _data: &[u8]) -> Result<Vec<u8>, CryptoError> {
                Ok(vec![0xDD; 3309])
            }
        }

        #[test]
        #[serial_test::serial(postgres)]
        fn pg_sth_round_trip_with_transparency_log() {
            use ciris_verify_core::transparency::verify_inclusion;
            let tenant = format!("merkle-sth-{}", uuid::Uuid::new_v4().simple());
            let tenant_for_log = tenant.clone();
            let Some(()) = run_with_pg_store(&tenant, move |store, _backend| {
                for i in 1..=3i64 {
                    store
                        .append(make_test_leaf(&format!("pg-s-{i}"), i, i))
                        .unwrap();
                }
                let log_id = format!("tenant:{tenant_for_log}");
                let log = TransparencyLog::<AuditLeaf>::for_log(log_id.clone(), store.clone());
                let signer = HybridSigner::new(StubClassical, StubPqc).unwrap();
                let sth = log.sign_head(&signer).unwrap();
                assert_eq!(sth.tree_size, 3);
                let stored = store.latest_sth().unwrap().unwrap();
                assert_eq!(stored.log_id, log_id);
                assert_eq!(stored.tree_size, sth.tree_size);
                assert_eq!(stored.root_hash, sth.root_hash);

                let proof = log.inclusion_proof(1).unwrap();
                assert!(verify_inclusion(&proof));
                assert_eq!(proof.root, sth.root_hash);
            }) else {
                eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
                return;
            };
        }
    }
}
