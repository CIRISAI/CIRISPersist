//! Engine retention primitives (v2.7.0, CIRISPersist#107).
//!
//! Three Rust-public substrate operations on [`Engine`](crate::Engine)
//! that CIRISLensCore#13 composes against for v0.4 RetentionPolicy
//! enforcement:
//!
//! 1. [`Engine::storage_summary`](crate::Engine::storage_summary) —
//!    read-only disk + row + age snapshot across the cohabitation
//!    store. Lens-core's eviction scheduler uses this to decide
//!    "do we need to evict, and how much".
//! 2. [`Engine::delete_traces_older_than`](crate::Engine::delete_traces_older_than) —
//!    bounded-batch DELETE for `trace_events` older than a threshold.
//!    Returns rows deleted; caller drives bounded-eviction loops
//!    ("delete 1000, sleep, delete 1000") with predictable
//!    transaction sizes.
//! 3. [`Engine::archive_audit_range`](crate::Engine::archive_audit_range) —
//!    chain-anchored archive blob + truncate of `audit_log` over a
//!    time range. The audit hash chain (V014; `prev_hash` linking
//!    adjacent rows by `entry_hash`) cannot tolerate a plain DELETE:
//!    the live row after the archived range keeps its `prev_hash`
//!    pointing at the (now-archived) last row, so verifiers can walk
//!    `seq[k+1]` -> `archive[seq_k]` without breaking the chain.
//!
//! Lens-core owns retention *policy* (max_disk_gb, max_age_days,
//! per-level retention); persist owns these *primitives* — same
//! ownership split as the v1.11.0 #89 ingest facade.
//!
//! # Why the chain-anchored archive matters
//!
//! Without preserving the chain anchor a delete would orphan
//! `seq[k+1].prev_hash` — it would reference a now-absent row, and a
//! verifier walking the live tail backwards would hit a wall at
//! "prev_hash references unknown entry". With the anchor, the
//! verifier can either:
//!
//! - Stop the walk at `seq[k+1]` (the oldest live row), trusting the
//!   archive blob as opaque chain-tail, or
//! - Retrieve `chain_anchor`'s archive blob via
//!   [`Engine::lookup_audit_archive`](crate::Engine::lookup_audit_archive)
//!   and continue the walk backwards through the archived rows.
//!
//! Either way the chain stays cryptographically intact.
#![allow(clippy::redundant_closure_call)]
// v3.14.0 (CIRISPersist#158) — inline-sync rewrite of all
// tokio::task::spawn_blocking sites uses (closure)() to invoke
// the closure inline. Clippy's redundant_closure_call lint flags
// this; we allow it because the mechanical transformation kept
// each closure's typed return signature load-bearing for error
// propagation and any other refactor would be a much larger diff.
// each closure's typed return signature load-bearing for error

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[cfg(feature = "postgres")]
pub mod postgres;
#[cfg(feature = "sqlite")]
pub mod sqlite;

/// v2.7.0 (CIRISPersist#107) — snapshot of per-table disk + row + age
/// usage across the cohabitation store.
///
/// Returned by
/// [`Engine::storage_summary`](crate::Engine::storage_summary). Each
/// field is a [`TableUsage`] reporting bytes, row count, and
/// oldest/newest timestamp bounds for one table. Tables that aren't
/// part of the current cargo feature set surface as
/// [`TableUsage::default`] (zeros + `None`s) so the struct shape stays
/// stable across deployment configurations.
///
/// # SQLite per-table-bytes limitation
///
/// On SQLite the per-table `bytes` field is `0` unless the
/// `dbstat` virtual table is available at runtime. Persist's
/// release builds do **not** enable `SQLITE_ENABLE_DBSTAT_VTAB`
/// (it requires a custom compile-time flag on `rusqlite`); the
/// Postgres impl uses `pg_relation_size` for accurate per-table
/// reporting. SQLite consumers should treat per-table `bytes` as
/// `0` and consult [`StorageSummary::total_disk_bytes`] for the
/// whole-DB byte count (from `PRAGMA page_count * page_size`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StorageSummary {
    /// Per-table usage for `trace_events` (the trace ingest table).
    /// Timestamp column: `ts` (the event's broadcast wall-clock).
    pub trace_events: TableUsage,
    /// Per-table usage for `trace_llm_calls` (one row per LLM call,
    /// linked to a parent trace event). Timestamp column: `ts`.
    pub trace_llm_calls: TableUsage,
    /// Per-table usage for `cirislens_derived.detection_events` (lens-
    /// core detection signals). Timestamp column: `ts`. Returns
    /// [`TableUsage::default`] when the table isn't present.
    pub detection_events: TableUsage,
    /// Per-table usage for `audit_log` (V014 hash-chained audit log).
    /// Timestamp column: `recorded_at`. Returns [`TableUsage::default`]
    /// when the `cirisaudit` feature is off.
    pub audit_log: TableUsage,
    /// Per-table usage for `edge_outbound_queue` (V007 outbound
    /// dispatcher queue). Timestamp column: `enqueued_at`.
    pub edge_outbound_queue: TableUsage,
    /// Per-table usage for `federation_keys` (V004 federation
    /// directory). Timestamp column: `valid_from` (the key's
    /// validity-window start).
    pub federation_keys: TableUsage,
    /// Whole-database disk usage in bytes. PG: `pg_database_size`.
    /// SQLite: `page_count * page_size`.
    pub total_disk_bytes: u64,
}

/// v2.7.0 (CIRISPersist#107) — one table's usage breakdown.
///
/// `bytes` is the on-disk size of the table including indexes/TOAST
/// (PG) or `0` on SQLite (see [`StorageSummary`] for the SQLite caveat).
/// `rows` is the exact row count via `SELECT count(*)`.
/// `oldest_ts` / `newest_ts` are `MIN` / `MAX` of the table's primary
/// time-series column (`ts` / `recorded_at` / `enqueued_at` /
/// `valid_from` depending on the table — see [`StorageSummary`]
/// field docs).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TableUsage {
    /// On-disk size in bytes. Includes indexes/TOAST on PG; `0` on
    /// SQLite (the dbstat virtual table is not compiled in by
    /// default — see [`StorageSummary`] docs).
    pub bytes: u64,
    /// Exact row count via `SELECT count(*)`.
    pub rows: u64,
    /// `MIN(<time_column>)` — the oldest row's timestamp. `None`
    /// when the table is empty.
    pub oldest_ts: Option<DateTime<Utc>>,
    /// `MAX(<time_column>)` — the newest row's timestamp. `None`
    /// when the table is empty.
    pub newest_ts: Option<DateTime<Utc>>,
}

/// v2.7.0 (CIRISPersist#107) — handle returned by
/// [`Engine::archive_audit_range`](crate::Engine::archive_audit_range).
///
/// Identifies the archive blob written and carries the
/// `chain_anchor` — the `entry_hash` of the last archived row,
/// which is the value that the next live row's `prev_hash` already
/// references. The anchor lets verifiers walk the chain across the
/// archive: from the oldest live row, follow `prev_hash` into the
/// archive blob keyed by this `chain_anchor`.
///
/// On an archive of an EMPTY range (`rows_archived = 0`), the
/// `chain_anchor` is all-zero (`[0; 32]`) and no archive blob row
/// is written — the call is a no-op, returned for caller
/// idempotency.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveHandle {
    /// Content-addressable archive identifier — SHA-256 of the
    /// archive bytes, packed into a UUID (first 16 bytes of the
    /// hash; the full SHA lives in the archive_bytes column itself).
    /// Empty-range archives return `Uuid::nil()`.
    pub archive_id: Uuid,
    /// Inclusive lower bound on `recorded_at` (the value passed to
    /// `archive_audit_range`).
    pub from_ts: DateTime<Utc>,
    /// Exclusive upper bound on `recorded_at`.
    pub to_ts: DateTime<Utc>,
    /// Number of rows captured into this archive (and deleted from
    /// the live `audit_log`).
    pub rows_archived: u64,
    /// `entry_hash` of the LAST archived row. The value the next
    /// live row's `prev_hash` references — the link that keeps the
    /// chain unbroken across the archive. All-zero on empty-range
    /// archives.
    pub chain_anchor: [u8; 32],
}

/// v2.7.0 (CIRISPersist#107) — errors from the retention primitives.
///
/// THREAT_MODEL.md AV-15: stable `kind()` tokens for telemetry / PyO3
/// sanitization.
#[derive(Debug, thiserror::Error)]
pub enum RetentionError {
    /// Caller passed invalid arguments — empty tenant_id, inverted
    /// time range, etc.
    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    /// `archive_audit_range` was called with a range spanning more
    /// than one `tenant_id`. The audit chain is per-tenant; archives
    /// MUST be single-tenant. Caller should issue one
    /// `archive_audit_range` per tenant.
    #[error("multi-tenant archive range: {0}")]
    MultiTenant(String),

    /// Backend-level error (DB connection, serialization).
    #[error("backend: {0}")]
    Backend(String),
}

impl RetentionError {
    /// Stable string-token for telemetry / structured logging.
    pub fn kind(&self) -> &'static str {
        match self {
            RetentionError::InvalidArgument(_) => "retention_invalid_argument",
            RetentionError::MultiTenant(_) => "retention_multi_tenant",
            RetentionError::Backend(_) => "retention_backend",
        }
    }
}

/// v2.7.0 (CIRISPersist#107) — canonical serialization of the
/// archived `AuditEntry` rows.
///
/// JSON via `serde_json::to_vec` over the `Vec<AuditEntry>`. The
/// SHA-256 of these bytes IS the archive's content identity (the
/// first 16 bytes are packed into `archive_id`).
///
/// Stable: AuditEntry's wire shape is locked at v0.8.1; the archive
/// bytes are byte-stable across releases as long as that wire
/// shape doesn't change.
#[cfg(feature = "cirisaudit")]
pub(crate) fn canonical_archive_bytes(
    entries: &[crate::audit::AuditEntry],
) -> Result<Vec<u8>, RetentionError> {
    serde_json::to_vec(entries)
        .map_err(|e| RetentionError::Backend(format!("archive serialize: {e}")))
}

/// v2.7.0 (CIRISPersist#107) — deserialize archived rows from the
/// canonical bytes written by the `archive_audit_range` primitive.
/// Inverse of the crate-internal `canonical_archive_bytes`
/// serializer.
#[cfg(feature = "cirisaudit")]
pub fn decode_archive_bytes(bytes: &[u8]) -> Result<Vec<crate::audit::AuditEntry>, RetentionError> {
    serde_json::from_slice(bytes)
        .map_err(|e| RetentionError::Backend(format!("archive deserialize: {e}")))
}

/// v2.7.0 (CIRISPersist#107) — pack the archive's SHA-256 into a
/// UUID. Takes the first 16 bytes of the hash; the full SHA lives in
/// the archive_bytes themselves (so collisions are detectable by
/// re-hashing).
#[cfg(feature = "cirisaudit")]
pub(crate) fn archive_id_from_sha(sha: &[u8; 32]) -> Uuid {
    let mut id = [0u8; 16];
    id.copy_from_slice(&sha[..16]);
    Uuid::from_bytes(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_usage_default_is_empty() {
        let u = TableUsage::default();
        assert_eq!(u.bytes, 0);
        assert_eq!(u.rows, 0);
        assert!(u.oldest_ts.is_none());
        assert!(u.newest_ts.is_none());
    }

    #[test]
    fn retention_error_kind_tokens_stable() {
        assert_eq!(
            RetentionError::InvalidArgument("x".into()).kind(),
            "retention_invalid_argument"
        );
        assert_eq!(
            RetentionError::MultiTenant("x".into()).kind(),
            "retention_multi_tenant"
        );
        assert_eq!(
            RetentionError::Backend("x".into()).kind(),
            "retention_backend"
        );
    }

    #[cfg(feature = "cirisaudit")]
    #[test]
    fn archive_id_packs_first_16_sha_bytes() {
        let sha = [0xABu8; 32];
        let id = archive_id_from_sha(&sha);
        let bytes = id.as_bytes();
        assert_eq!(bytes, &[0xAB; 16]);
    }

    // ── Chain-preservation tests (CIRISPersist#107 acceptance) ──
    //
    // Seed 10 audit entries (sequence 1..10); archive a middle range
    // (seq 3..6 inclusive); assert:
    //
    // 1. ArchiveHandle.chain_anchor == entry_hash(seq6).
    // 2. The archive blob contains seq3..6 in canonical form.
    // 3. Live audit_log retains seq1, 2, 7, 8, 9, 10.
    // 4. Live seq7.prev_hash == entry_hash(seq6) — chain unbroken;
    //    verifiers walk seq7 → seq6 via the archive blob.

    #[cfg(all(feature = "cirisaudit", feature = "sqlite"))]
    #[tokio::test]
    async fn archive_audit_range_preserves_chain_sqlite() {
        use crate::audit::verify::{compute_entry_hash, truncate_to_micros};
        use crate::audit::{AuditEntry, AuditService, GENESIS_PREV_HASH};
        use crate::engine::Engine;
        use crate::signing::LocalSigner;
        use crate::store::sqlite::SqliteBackend;
        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine as _;
        use ed25519_dalek::{Signer as _, SigningKey};
        use std::sync::Arc;
        use uuid::Uuid;

        let backend = SqliteBackend::open_in_memory().await.unwrap();
        crate::store::Backend::run_migrations(&backend)
            .await
            .unwrap();
        let backend_arc = Arc::new(backend);
        let audit = crate::audit::sqlite::SqliteAuditBackend::new(backend_arc.conn_handle());

        // Build + sign 10 chained entries under one tenant. recorded_at
        // is set deterministically so the archive range can target the
        // middle slice.
        let key = SigningKey::from_bytes(&[0xA7; 32]);
        let actor = B64.encode(key.verifying_key().to_bytes());
        let tenant = format!("retention-{}", Uuid::new_v4().simple());
        let base_ts = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);

        let mut entries: Vec<AuditEntry> = Vec::new();
        let mut prev_hash = GENESIS_PREV_HASH.to_vec();
        for seq in 1..=10i64 {
            let ts = base_ts + chrono::Duration::seconds(seq * 10);
            let mut entry = AuditEntry {
                entry_id: Uuid::new_v4().to_string(),
                sequence_number: seq,
                tenant_id: tenant.clone(),
                actor_id: actor.clone(),
                action_type: "handler_action_task_complete".into(),
                subject_kind: "task".into(),
                subject_id: format!("subj-{seq}"),
                payload: serde_json::json!({"seq": seq}),
                prev_hash: prev_hash.clone(),
                entry_hash: vec![],
                recorded_at: truncate_to_micros(ts),
                signature: String::new(),
            };
            let hash = compute_entry_hash(&entry).unwrap();
            entry.entry_hash = hash.to_vec();
            let canonical = crate::audit::verify::canonical_bytes_for_entry(&entry).unwrap();
            entry.signature = B64.encode(key.sign(&canonical).to_bytes());
            audit.record_entry(entry.clone()).await.unwrap();
            prev_hash = entry.entry_hash.clone();
            entries.push(entry);
        }

        // Build an Engine over the same backend so archive_audit_range
        // is exercised through the public Engine surface.
        let signer = Arc::new(LocalSigner::from_parts(
            SigningKey::from_bytes(&[0x01; 32]),
            "test-retention".into(),
            None,
            None,
        ));
        let signer_dyn: Arc<dyn ciris_keyring::HardwareSigner> =
            Arc::new(crate::signing::LocalSignerHardwareAdapter::new(signer));
        let engine = Engine::from_shared(
            crate::engine::BackendDispatch::Sqlite(backend_arc.clone()),
            signer_dyn,
        );

        // Archive seq3..6: from = seq3.ts, to = seq7.ts (half-open).
        let from_ts = entries[2].recorded_at;
        let to_ts = entries[6].recorded_at;
        let handle = engine
            .archive_audit_range(from_ts, to_ts)
            .await
            .expect("archive_audit_range succeeds");
        assert_eq!(handle.rows_archived, 4, "seq3..6 = 4 rows");
        assert_eq!(
            handle.chain_anchor.as_slice(),
            entries[5].entry_hash.as_slice(),
            "chain_anchor == entry_hash(seq6) (last archived row)"
        );
        assert_eq!(handle.from_ts, from_ts);
        assert_eq!(handle.to_ts, to_ts);
        assert_ne!(handle.archive_id, Uuid::nil(), "non-empty archive id");

        // Archive blob round-trips: contains seq3..6.
        let bytes = engine
            .lookup_audit_archive(handle.archive_id)
            .await
            .expect("lookup")
            .expect("archive present");
        let archived: Vec<AuditEntry> = super::decode_archive_bytes(&bytes).unwrap();
        assert_eq!(archived.len(), 4);
        for (i, e) in archived.iter().enumerate() {
            assert_eq!(e.sequence_number, (i + 3) as i64);
            assert_eq!(e.entry_hash, entries[i + 2].entry_hash);
        }

        // Live audit_log retains seq 1, 2, 7, 8, 9, 10.
        let live_seqs: Vec<i64> = {
            let conn = backend_arc.conn_handle();
            let tenant_q = tenant.clone();
            (move || -> Vec<i64> {
                let guard = conn.lock();
                let mut stmt = guard
                    .prepare(
                        "SELECT sequence_number FROM cirislens_audit_log \
                         WHERE tenant_id = ?1 ORDER BY sequence_number",
                    )
                    .unwrap();
                let it = stmt
                    .query_map(rusqlite::params![tenant_q], |row| row.get::<_, i64>(0))
                    .unwrap();
                it.map(|r| r.unwrap()).collect()
            })()
        };
        assert_eq!(live_seqs, vec![1, 2, 7, 8, 9, 10]);

        // CRITICAL: seq7's prev_hash still equals entry_hash(seq6) —
        // chain unbroken. The verifier walks seq7 → seq6 via the
        // archive blob.
        let seq7_prev: Vec<u8> = {
            let conn = backend_arc.conn_handle();
            let tenant_q = tenant.clone();
            (move || -> Vec<u8> {
                let guard = conn.lock();
                guard
                    .query_row(
                        "SELECT prev_hash FROM cirislens_audit_log \
                         WHERE tenant_id = ?1 AND sequence_number = 7",
                        rusqlite::params![tenant_q],
                        |row| row.get::<_, Vec<u8>>(0),
                    )
                    .unwrap()
            })()
        };
        assert_eq!(
            seq7_prev, entries[5].entry_hash,
            "seq7.prev_hash == entry_hash(seq6); chain unbroken across archive"
        );
        assert_eq!(
            seq7_prev,
            handle.chain_anchor.to_vec(),
            "seq7.prev_hash == chain_anchor"
        );

        // Edge case: empty range returns a no-op handle.
        let empty = engine
            .archive_audit_range(
                base_ts - chrono::Duration::days(1),
                base_ts - chrono::Duration::hours(1),
            )
            .await
            .expect("empty range archive succeeds");
        assert_eq!(empty.rows_archived, 0);
        assert_eq!(empty.archive_id, Uuid::nil());
        assert_eq!(empty.chain_anchor, [0u8; 32]);
    }

    #[cfg(all(feature = "cirisaudit", feature = "postgres"))]
    #[tokio::test]
    async fn archive_audit_range_preserves_chain_postgres() {
        use crate::audit::verify::{compute_entry_hash, truncate_to_micros};
        use crate::audit::{AuditEntry, AuditService, GENESIS_PREV_HASH};
        use crate::engine::Engine;
        use crate::signing::LocalSigner;
        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine as _;
        use ed25519_dalek::{Signer as _, SigningKey};
        use std::sync::Arc;
        use uuid::Uuid;

        let Ok(dsn) = std::env::var("CIRIS_PERSIST_TEST_PG_URL") else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };

        let signer = Arc::new(LocalSigner::from_parts(
            SigningKey::from_bytes(&[0x02; 32]),
            "test-retention-pg".into(),
            None,
            None,
        ));
        let engine = Engine::with_signer(signer, &dsn)
            .await
            .expect("construct PG engine");
        let audit = engine.audit_service();

        // Each test run uses a unique tenant so concurrent runs / re-
        // runs don't tread on each other's rows.
        let key = SigningKey::from_bytes(&[0xB7; 32]);
        let actor = B64.encode(key.verifying_key().to_bytes());
        let tenant = format!("retention-pg-{}", Uuid::new_v4().simple());
        let base_ts = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc)
            + chrono::Duration::minutes(rand_minutes());

        let mut entries: Vec<AuditEntry> = Vec::new();
        let mut prev_hash = GENESIS_PREV_HASH.to_vec();
        for seq in 1..=10i64 {
            let ts = base_ts + chrono::Duration::seconds(seq * 10);
            let mut entry = AuditEntry {
                entry_id: Uuid::new_v4().to_string(),
                sequence_number: seq,
                tenant_id: tenant.clone(),
                actor_id: actor.clone(),
                action_type: "handler_action_task_complete".into(),
                subject_kind: "task".into(),
                subject_id: format!("subj-{seq}"),
                payload: serde_json::json!({"seq": seq}),
                prev_hash: prev_hash.clone(),
                entry_hash: vec![],
                recorded_at: truncate_to_micros(ts),
                signature: String::new(),
            };
            let hash = compute_entry_hash(&entry).unwrap();
            entry.entry_hash = hash.to_vec();
            let canonical = crate::audit::verify::canonical_bytes_for_entry(&entry).unwrap();
            entry.signature = B64.encode(key.sign(&canonical).to_bytes());
            match &audit {
                crate::engine::AuditDispatch::Postgres(b) => {
                    b.record_entry(entry.clone()).await.unwrap();
                }
                #[cfg(feature = "sqlite")]
                crate::engine::AuditDispatch::Sqlite(_) => {
                    panic!("expected postgres dispatch");
                }
            }
            prev_hash = entry.entry_hash.clone();
            entries.push(entry);
        }

        let from_ts = entries[2].recorded_at;
        let to_ts = entries[6].recorded_at;
        let handle = engine
            .archive_audit_range(from_ts, to_ts)
            .await
            .expect("archive_audit_range succeeds");
        assert_eq!(handle.rows_archived, 4);
        assert_eq!(
            handle.chain_anchor.as_slice(),
            entries[5].entry_hash.as_slice()
        );

        let bytes = engine
            .lookup_audit_archive(handle.archive_id)
            .await
            .expect("lookup")
            .expect("archive present");
        let archived: Vec<AuditEntry> = super::decode_archive_bytes(&bytes).unwrap();
        assert_eq!(archived.len(), 4);
        for (i, e) in archived.iter().enumerate() {
            assert_eq!(e.sequence_number, (i + 3) as i64);
        }

        // Verify live rows + chain unbroken via PG client.
        let pg = engine.postgres_backend().expect("pg backend");
        let client = pg.pool().get().await.unwrap();
        let live_seqs_rows = client
            .query(
                "SELECT sequence_number FROM cirislens.audit_log \
                 WHERE tenant_id = $1 ORDER BY sequence_number",
                &[&tenant],
            )
            .await
            .unwrap();
        let live_seqs: Vec<i64> = live_seqs_rows
            .iter()
            .map(|r| r.try_get::<_, i64>("sequence_number").unwrap())
            .collect();
        assert_eq!(live_seqs, vec![1, 2, 7, 8, 9, 10]);

        let seq7_prev: Vec<u8> = client
            .query_one(
                "SELECT prev_hash FROM cirislens.audit_log \
                 WHERE tenant_id = $1 AND sequence_number = 7",
                &[&tenant],
            )
            .await
            .unwrap()
            .try_get("prev_hash")
            .unwrap();
        assert_eq!(seq7_prev, entries[5].entry_hash);
        assert_eq!(seq7_prev, handle.chain_anchor.to_vec());
    }

    // Cheap pseudo-random offset so concurrent test runs don't share
    // a base_ts (avoids `recorded_at` collisions on PG `TIMESTAMPTZ`).
    // We don't want a fresh dep on `rand`; pull from
    // `SystemTime::now()`'s nanos.
    #[cfg(all(feature = "cirisaudit", feature = "postgres"))]
    fn rand_minutes() -> i64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        (nanos % 1_000_000) as i64
    }

    // ── delete_traces_older_than + storage_summary smoke tests ──

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn delete_traces_older_than_caps_rows_sqlite() {
        use crate::engine::Engine;
        use crate::signing::LocalSigner;
        use ed25519_dalek::SigningKey;
        use std::sync::Arc;

        let signer = Arc::new(LocalSigner::from_parts(
            SigningKey::from_bytes(&[0x03; 32]),
            "test-delete".into(),
            None,
            None,
        ));
        let engine = Engine::with_signer(signer, "sqlite::memory:")
            .await
            .expect("construct engine");
        let sq = engine.sqlite_backend().expect("sqlite backend");

        // Seed 20 trace_events rows by hand (the schema requires only
        // trace_id / thought_id / event_type / trace_level / payload
        // / ts as NOT NULL).
        let conn = sq.conn_handle();
        (move || {
            let guard = conn.lock();
            for i in 0..20 {
                guard
                    .execute(
                        "INSERT INTO trace_events (\
                            trace_id, thought_id, event_type, attempt_index, \
                            ts, trace_level, payload\
                         ) VALUES (?1, ?2, 'observation', 0, ?3, 'generic', '{}')",
                        rusqlite::params![
                            format!("tr-{i}"),
                            format!("th-{i}"),
                            format!("2026-01-01T00:00:{:02}.000000Z", i),
                        ],
                    )
                    .unwrap();
            }
        })();

        // Delete with threshold > newest_ts and max_rows=5 → exactly 5.
        let threshold = chrono::DateTime::parse_from_rfc3339("2026-12-31T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let n = engine
            .delete_traces_older_than(threshold, 5)
            .await
            .expect("delete succeeds");
        assert_eq!(n, 5, "max_rows cap respected");

        // Storage summary after partial delete: 15 rows.
        let summary = engine
            .storage_summary()
            .await
            .expect("storage_summary succeeds");
        assert_eq!(summary.trace_events.rows, 15);
        // SQLite per-table-bytes is 0 (dbstat not compiled in).
        assert_eq!(summary.trace_events.bytes, 0);
        // total_disk_bytes is >0 (in-memory DB still has pages).
        assert!(summary.total_disk_bytes > 0);

        // Idempotent: another delete with max_rows=100 wipes the
        // remaining 15.
        let n2 = engine
            .delete_traces_older_than(threshold, 100)
            .await
            .expect("second delete");
        assert_eq!(n2, 15);

        let summary2 = engine.storage_summary().await.expect("storage_summary 2");
        assert_eq!(summary2.trace_events.rows, 0);
        assert!(summary2.trace_events.oldest_ts.is_none());
        assert!(summary2.trace_events.newest_ts.is_none());
    }

    #[cfg(all(feature = "cirisaudit", feature = "sqlite"))]
    #[tokio::test]
    async fn archive_audit_range_rejects_multi_tenant_sqlite() {
        use crate::audit::verify::{compute_entry_hash, truncate_to_micros};
        use crate::audit::{AuditEntry, AuditService, GENESIS_PREV_HASH};
        use crate::engine::Engine;
        use crate::signing::LocalSigner;
        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine as _;
        use ed25519_dalek::{Signer as _, SigningKey};
        use std::sync::Arc;
        use uuid::Uuid;

        let signer = Arc::new(LocalSigner::from_parts(
            SigningKey::from_bytes(&[0x04; 32]),
            "test-mt".into(),
            None,
            None,
        ));
        let engine = Engine::with_signer(signer, "sqlite::memory:")
            .await
            .expect("construct engine");
        let sq = engine.sqlite_backend().expect("sqlite backend");
        let audit = crate::audit::sqlite::SqliteAuditBackend::new(sq.conn_handle());

        let key = SigningKey::from_bytes(&[0xC9; 32]);
        let actor = B64.encode(key.verifying_key().to_bytes());
        let base_ts = chrono::DateTime::parse_from_rfc3339("2026-02-01T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        for tenant in &["tnt-a", "tnt-b"] {
            let mut entry = AuditEntry {
                entry_id: Uuid::new_v4().to_string(),
                sequence_number: 1,
                tenant_id: (*tenant).to_owned(),
                actor_id: actor.clone(),
                action_type: "handler_action_task_complete".into(),
                subject_kind: "task".into(),
                subject_id: "subj-1".into(),
                payload: serde_json::json!({"t": *tenant}),
                prev_hash: GENESIS_PREV_HASH.to_vec(),
                entry_hash: vec![],
                recorded_at: truncate_to_micros(base_ts),
                signature: String::new(),
            };
            entry.entry_hash = compute_entry_hash(&entry).unwrap().to_vec();
            let canonical = crate::audit::verify::canonical_bytes_for_entry(&entry).unwrap();
            entry.signature = B64.encode(key.sign(&canonical).to_bytes());
            audit.record_entry(entry).await.unwrap();
        }

        // Both tenants' genesis rows have the same recorded_at —
        // archiving the whole window pulls in both → MultiTenant.
        let from_ts = base_ts - chrono::Duration::hours(1);
        let to_ts = base_ts + chrono::Duration::hours(1);
        let err = engine
            .archive_audit_range(from_ts, to_ts)
            .await
            .expect_err("multi-tenant range must error");
        assert!(matches!(err, RetentionError::MultiTenant(_)), "got {err:?}");
    }
}
