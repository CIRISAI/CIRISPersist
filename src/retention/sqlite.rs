//! SQLite impl of the retention primitives (v2.7.0, CIRISPersist#107).
//!
//! Mirrors the Postgres impl ([`super::postgres`]) with SQLite-dialect
//! translations:
//!
//! - `pg_relation_size` → `0` (the `dbstat` virtual table is not
//!   compiled into stock rusqlite; per-table bytes aren't available).
//!   Total DB bytes come from `PRAGMA page_count * page_size`.
//! - `tenant_id = ANY($1)` → bulk IN list via `params_from_iter`.
//! - PG `DELETE ... WHERE (col1, col2) IN (SELECT ...)` becomes
//!   SQLite `DELETE ... WHERE rowid IN (SELECT rowid ...)` —
//!   semantically equivalent.
//! - Transaction is `BEGIN IMMEDIATE` (matches audit/sqlite.rs
//!   for write paths).

use std::sync::Arc;

use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension};
#[cfg(feature = "cirisaudit")]
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;

#[cfg(feature = "cirisaudit")]
use super::ArchiveHandle;
use super::{RetentionError, StorageSummary, TableUsage};
use crate::store::sqlite::SqliteBackend;

/// v2.7.0 — [`StorageSummary`] for a `SqliteBackend`.
///
/// Per-table reporting: rows + ts bounds via `SELECT count(*) /
/// MIN / MAX`. Per-table BYTES is `0` on SQLite (the `dbstat`
/// virtual table is not compiled into stock rusqlite). Whole-DB
/// bytes via `PRAGMA page_count * PRAGMA page_size`.
pub async fn storage_summary_sqlite(
    backend: &SqliteBackend,
) -> Result<StorageSummary, RetentionError> {
    let conn = backend.conn_handle();
    tokio::task::spawn_blocking(move || storage_summary_blocking(&conn))
        .await
        .map_err(|e| RetentionError::Backend(format!("spawn_blocking join: {e}")))?
}

fn storage_summary_blocking(
    conn: &Arc<Mutex<Connection>>,
) -> Result<StorageSummary, RetentionError> {
    let guard = conn.blocking_lock();

    // Whole-DB bytes via PRAGMA.
    let page_count: i64 = guard
        .query_row("PRAGMA page_count", [], |row| row.get(0))
        .map_err(|e| RetentionError::Backend(format!("pragma page_count: {e}")))?;
    let page_size: i64 = guard
        .query_row("PRAGMA page_size", [], |row| row.get(0))
        .map_err(|e| RetentionError::Backend(format!("pragma page_size: {e}")))?;
    let total_disk_bytes = u64::try_from(page_count.saturating_mul(page_size)).unwrap_or(0);

    let trace_events = table_usage_sqlite(&guard, "trace_events", "ts")?;
    let trace_llm_calls = table_usage_sqlite(&guard, "trace_llm_calls", "ts")?;
    let detection_events = table_usage_sqlite(&guard, "cirislens_derived_detection_events", "ts")?;

    let audit_log = {
        #[cfg(feature = "cirisaudit")]
        {
            table_usage_sqlite(&guard, "cirislens_audit_log", "recorded_at")?
        }
        #[cfg(not(feature = "cirisaudit"))]
        {
            TableUsage::default()
        }
    };

    let edge_outbound_queue = table_usage_sqlite(&guard, "edge_outbound_queue", "enqueued_at")?;
    let federation_keys = table_usage_sqlite(&guard, "federation_keys", "valid_from")?;

    Ok(StorageSummary {
        trace_events,
        trace_llm_calls,
        detection_events,
        audit_log,
        edge_outbound_queue,
        federation_keys,
        total_disk_bytes,
    })
}

fn table_usage_sqlite(
    conn: &Connection,
    table: &str,
    ts_column: &str,
) -> Result<TableUsage, RetentionError> {
    // Bytes is 0 on SQLite (no dbstat compiled in). See module docs.
    let bytes = 0u64;

    // Table-existence check via sqlite_master — non-existing tables
    // soft-fail with default TableUsage (matches the PG soft-fail
    // for 42P01).
    let exists: bool = conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name = ?1",
            params![table],
            |_| Ok(true),
        )
        .optional()
        .map_err(|e| RetentionError::Backend(format!("table existence {table}: {e}")))?
        .unwrap_or(false);
    if !exists {
        return Ok(TableUsage::default());
    }

    let stats_sql = format!(
        "SELECT count(*), MIN({col}), MAX({col}) FROM {tbl}",
        col = ts_column,
        tbl = table,
    );
    let (rows_i, oldest_raw, newest_raw): (i64, Option<String>, Option<String>) = conn
        .query_row(&stats_sql, [], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })
        .map_err(|e| RetentionError::Backend(format!("stats query {table}: {e}")))?;
    let rows = u64::try_from(rows_i).unwrap_or(0);

    let oldest_ts = match oldest_raw {
        Some(s) => Some(parse_rfc3339(&s)?),
        None => None,
    };
    let newest_ts = match newest_raw {
        Some(s) => Some(parse_rfc3339(&s)?),
        None => None,
    };

    Ok(TableUsage {
        bytes,
        rows,
        oldest_ts,
        newest_ts,
    })
}

fn parse_rfc3339(s: &str) -> Result<DateTime<Utc>, RetentionError> {
    DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| RetentionError::Backend(format!("ts parse: {e} (raw={s})")))
}

fn fmt_rfc3339(dt: DateTime<Utc>) -> String {
    dt.to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
}

/// v2.7.0 — bounded-batch DELETE on `trace_events` for rows whose
/// `ts < threshold`, capped at `max_rows`. Returns the actual rows
/// deleted.
///
/// `DELETE FROM trace_events WHERE rowid IN (SELECT rowid ... ORDER
/// BY ts LIMIT ?2)` honors the row cap.
pub async fn delete_traces_older_than_sqlite(
    backend: &SqliteBackend,
    ts: DateTime<Utc>,
    max_rows: usize,
) -> Result<usize, RetentionError> {
    if max_rows == 0 {
        return Ok(0);
    }
    let ts_str = fmt_rfc3339(ts);
    let limit_i64 = i64::try_from(max_rows)
        .map_err(|_| RetentionError::InvalidArgument(format!("max_rows {max_rows} > i64::MAX")))?;
    let conn = backend.conn_handle();
    let deleted = tokio::task::spawn_blocking(move || -> Result<usize, RetentionError> {
        let guard = conn.blocking_lock();
        let n = guard
            .execute(
                "DELETE FROM trace_events \
                 WHERE rowid IN ( \
                     SELECT rowid FROM trace_events \
                     WHERE ts < ?1 \
                     ORDER BY ts \
                     LIMIT ?2 \
                 )",
                params![ts_str, limit_i64],
            )
            .map_err(|e| RetentionError::Backend(format!("delete_traces_older_than: {e}")))?;
        Ok(n)
    })
    .await
    .map_err(|e| RetentionError::Backend(format!("spawn_blocking join: {e}")))??;
    Ok(deleted)
}

/// v2.7.0 — chain-anchored archive + truncate on
/// `cirislens_audit_log`. Postgres parity — see
/// [`super::postgres::archive_audit_range_pg`] for the
/// step-by-step rationale.
#[cfg(feature = "cirisaudit")]
pub async fn archive_audit_range_sqlite(
    backend: &SqliteBackend,
    from_ts: DateTime<Utc>,
    to_ts: DateTime<Utc>,
) -> Result<ArchiveHandle, RetentionError> {
    use crate::audit::AuditEntry;
    use uuid::Uuid;

    if from_ts >= to_ts {
        return Err(RetentionError::InvalidArgument(format!(
            "from_ts ({from_ts}) must be < to_ts ({to_ts})"
        )));
    }
    let from_str = fmt_rfc3339(from_ts);
    let to_str = fmt_rfc3339(to_ts);

    let conn = backend.conn_handle();

    tokio::task::spawn_blocking(move || -> Result<ArchiveHandle, RetentionError> {
        let mut guard = conn.blocking_lock();
        let tx = guard
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|e| RetentionError::Backend(format!("begin tx: {e}")))?;

        // 1. SELECT archived rows.
        let mut stmt = tx
            .prepare(
                "SELECT entry_id, sequence_number, tenant_id, actor_id, action_type, \
                        subject_kind, subject_id, payload, prev_hash, entry_hash, \
                        recorded_at, signature \
                 FROM cirislens_audit_log \
                 WHERE recorded_at >= ?1 AND recorded_at < ?2 \
                 ORDER BY tenant_id, sequence_number",
            )
            .map_err(|e| RetentionError::Backend(format!("archive select prepare: {e}")))?;
        let rows_iter = stmt
            .query_map(params![from_str, to_str], |row| {
                let payload_str: String = row.get("payload")?;
                let payload: serde_json::Value =
                    serde_json::from_str(&payload_str).map_err(|e| {
                        rusqlite::Error::FromSqlConversionFailure(
                            7,
                            rusqlite::types::Type::Text,
                            Box::new(e),
                        )
                    })?;
                let recorded_at_str: String = row.get("recorded_at")?;
                let recorded_at = chrono::DateTime::parse_from_rfc3339(&recorded_at_str)
                    .map(|dt| dt.with_timezone(&Utc))
                    .map_err(|e| {
                        rusqlite::Error::FromSqlConversionFailure(
                            10,
                            rusqlite::types::Type::Text,
                            Box::new(e),
                        )
                    })?;
                Ok(AuditEntry {
                    entry_id: row.get("entry_id")?,
                    sequence_number: row.get("sequence_number")?,
                    tenant_id: row.get("tenant_id")?,
                    actor_id: row.get("actor_id")?,
                    action_type: row.get("action_type")?,
                    subject_kind: row.get("subject_kind")?,
                    subject_id: row.get("subject_id")?,
                    payload,
                    prev_hash: row.get("prev_hash")?,
                    entry_hash: row.get("entry_hash")?,
                    recorded_at,
                    signature: row.get("signature")?,
                })
            })
            .map_err(|e| RetentionError::Backend(format!("archive select query: {e}")))?;

        let mut entries: Vec<AuditEntry> = Vec::new();
        for row in rows_iter {
            let e = row.map_err(|e| RetentionError::Backend(format!("archive row: {e}")))?;
            entries.push(e);
        }
        drop(stmt);

        if entries.is_empty() {
            tx.commit()
                .map_err(|e| RetentionError::Backend(format!("commit: {e}")))?;
            return Ok(ArchiveHandle {
                archive_id: Uuid::nil(),
                from_ts,
                to_ts,
                rows_archived: 0,
                chain_anchor: [0u8; 32],
            });
        }

        // 2. Single-tenant guard.
        let first_tenant = entries[0].tenant_id.clone();
        for e in entries.iter().skip(1) {
            if e.tenant_id != first_tenant {
                return Err(RetentionError::MultiTenant(format!(
                    "range spans tenants {first_tenant:?} and {:?}; issue one call per tenant",
                    e.tenant_id
                )));
            }
        }

        // 3. chain_anchor + canonical bytes.
        let last = entries.last().expect("non-empty");
        if last.entry_hash.len() != 32 {
            return Err(RetentionError::Backend(format!(
                "last archived entry_hash is {} bytes, expected 32",
                last.entry_hash.len()
            )));
        }
        let mut chain_anchor = [0u8; 32];
        chain_anchor.copy_from_slice(&last.entry_hash);

        let archive_bytes = super::canonical_archive_bytes(&entries)?;
        let mut hasher = Sha256::new();
        hasher.update(&archive_bytes);
        let sha: [u8; 32] = hasher.finalize().into();
        let archive_id = super::archive_id_from_sha(&sha);
        let archive_id_str = archive_id.to_string();
        let rows_archived = entries.len() as u64;
        let rows_archived_i = entries.len() as i64;

        // 4. INSERT archive row.
        tx.execute(
            "INSERT INTO cirislens_audit_archives (\
                archive_id, tenant_id, from_ts, to_ts, \
                rows_archived, chain_anchor, archive_bytes\
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                archive_id_str,
                first_tenant,
                from_str,
                to_str,
                rows_archived_i,
                chain_anchor.as_slice(),
                archive_bytes,
            ],
        )
        .map_err(|e| RetentionError::Backend(format!("archive insert: {e}")))?;

        // 5. DELETE archived rows by entry_id (PK).
        {
            let mut del_stmt = tx
                .prepare("DELETE FROM cirislens_audit_log WHERE entry_id = ?1")
                .map_err(|e| RetentionError::Backend(format!("delete prepare: {e}")))?;
            for entry in &entries {
                del_stmt
                    .execute(params![entry.entry_id])
                    .map_err(|e| RetentionError::Backend(format!("delete row: {e}")))?;
            }
        }

        tx.commit()
            .map_err(|e| RetentionError::Backend(format!("commit: {e}")))?;

        Ok(ArchiveHandle {
            archive_id,
            from_ts,
            to_ts,
            rows_archived,
            chain_anchor,
        })
    })
    .await
    .map_err(|e| RetentionError::Backend(format!("spawn_blocking join: {e}")))?
}

/// v2.7.0 — read an archive blob by `archive_id`. Used by tests +
/// offline verifiers. Returns `Ok(None)` when no archive with that
/// id exists.
#[cfg(feature = "cirisaudit")]
pub async fn lookup_audit_archive_sqlite(
    backend: &SqliteBackend,
    archive_id: uuid::Uuid,
) -> Result<Option<Vec<u8>>, RetentionError> {
    let conn = backend.conn_handle();
    let id_str = archive_id.to_string();
    tokio::task::spawn_blocking(move || -> Result<Option<Vec<u8>>, RetentionError> {
        let guard = conn.blocking_lock();
        let bytes: Option<Vec<u8>> = guard
            .query_row(
                "SELECT archive_bytes FROM cirislens_audit_archives WHERE archive_id = ?1",
                params![id_str],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| RetentionError::Backend(format!("lookup_audit_archive: {e}")))?;
        Ok(bytes)
    })
    .await
    .map_err(|e| RetentionError::Backend(format!("spawn_blocking join: {e}")))?
}
