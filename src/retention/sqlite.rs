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
#![allow(clippy::redundant_closure_call)]
// v3.14.0 (CIRISPersist#158) — inline-sync rewrite of all
// tokio::task::spawn_blocking sites uses (closure)() to invoke
// the closure inline. Clippy's redundant_closure_call lint flags
// this; we allow it because the mechanical transformation kept
// each closure's typed return signature load-bearing for error
// propagation and any other refactor would be a much larger diff.
// each closure's typed return signature load-bearing for error

use std::sync::Arc;

use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use rusqlite::{params, Connection, OptionalExtension};
/// v38.4.0 (CIRISPersist#767 Ask 2) — **bounded, age-based prune for the two
/// OBSERVATION tables.**
///
/// `announced_peers` and `transport_destinations` are not evidence — they are
/// this node's running notes about who it has heard from and where. They grow
/// with every announce and nothing ever removed a row: a production node held
/// 10,460 destinations for ~700 keys, and the intake that produced them is
/// unbounded by construction (CIRISPersist#672).
///
/// Deliberately NOT a general attestation prune. #767 asked for exactly this
/// and explicitly did not ask for attestation deletion: an attestation is
/// signed evidence, and a node that deletes evidence to save disk is deleting
/// the corpus. Expiry is a different question with a different door
/// (CIRISPersist#768) and it goes through the purge gate, not here.
///
/// Batching mirrors [`delete_traces_older_than_sqlite`] so the retention loop
/// drives all three the same way: bounded rows per pass, oldest first, caller
/// re-invokes until it returns less than `max_rows`.
pub async fn prune_announced_peers_not_seen_since_sqlite(
    backend: &SqliteBackend,
    cutoff: DateTime<Utc>,
    max_rows: usize,
) -> Result<usize, RetentionError> {
    prune_observation_table_sqlite(backend, "announced_peers", "last_seen_at", cutoff, max_rows)
        .await
}

/// v38.4.0 (#767 Ask 2) — the `transport_destinations` twin.
///
/// Ordered by `COALESCE(last_seen_at, asserted_at)`: `last_seen_at` is
/// advisory and nullable on this table (V078), so a row that was never
/// re-seen falls back to when it was asserted rather than being immortal
/// because its advisory column is NULL — the exact shape that lets a prune
/// silently skip the oldest rows it exists to remove.
pub async fn prune_transport_destinations_not_seen_since_sqlite(
    backend: &SqliteBackend,
    cutoff: DateTime<Utc>,
    max_rows: usize,
) -> Result<usize, RetentionError> {
    prune_observation_table_sqlite(
        backend,
        "transport_destinations",
        "COALESCE(last_seen_at, asserted_at)",
        cutoff,
        max_rows,
    )
    .await
}

/// The one prune body both observation tables share. `age_expr` is a column
/// or expression, never caller-supplied — both call sites are literals above.
async fn prune_observation_table_sqlite(
    backend: &SqliteBackend,
    table: &'static str,
    age_expr: &'static str,
    cutoff: DateTime<Utc>,
    max_rows: usize,
) -> Result<usize, RetentionError> {
    if max_rows == 0 {
        return Ok(0);
    }
    // v38.4.0 (#767) — format the cutoff the way the WRITER formats the
    // column, not the way retention formats its own timestamps.
    //
    // These rows are stored with chrono's plain `to_rfc3339()`, which spells
    // UTC as `+00:00`; `fmt_rfc3339` here spells it `Z` and pads micros. The
    // comparison below is a STRING comparison, so mixing the two compares
    // `...00:00+00:00` against `...00:00.000000Z` and decides the boundary on
    // the punctuation ('+' sorts before '.'), quietly pruning rows AT the
    // cutoff that `<` should keep. Same spelling on both sides makes the
    // lexicographic order agree with the chronological one, and keeps the
    // predicate index-usable — which `datetime()` on the column would not.
    let cutoff_str = cutoff.to_rfc3339();
    let limit_i64 = i64::try_from(max_rows)
        .map_err(|_| RetentionError::InvalidArgument(format!("max_rows {max_rows} > i64::MAX")))?;
    let conn = backend.conn_handle();
    let deleted = (move || -> Result<usize, RetentionError> {
        let guard = conn.lock();
        let sql = format!(
            "DELETE FROM {table} \
             WHERE rowid IN ( \
                 SELECT rowid FROM {table} \
                 WHERE {age_expr} < ?1 \
                 ORDER BY {age_expr} \
                 LIMIT ?2 \
             )"
        );
        let n = guard
            .execute(&sql, params![cutoff_str, limit_i64])
            .map_err(|e| RetentionError::Backend(format!("prune {table}: {e}")))?;
        Ok(n)
    })()?;
    Ok(deleted)
}

#[cfg(feature = "cirisaudit")]
use sha2::{Digest, Sha256};

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
    (move || storage_summary_blocking(&conn))()
}

fn storage_summary_blocking(
    conn: &Arc<Mutex<Connection>>,
) -> Result<StorageSummary, RetentionError> {
    let guard = conn.lock();

    // Whole-DB bytes via PRAGMA.
    let page_count: i64 = guard
        .query_row("PRAGMA page_count", [], |row| row.get(0))
        .map_err(|e| RetentionError::Backend(format!("pragma page_count: {e}")))?;
    let page_size: i64 = guard
        .query_row("PRAGMA page_size", [], |row| row.get(0))
        .map_err(|e| RetentionError::Backend(format!("pragma page_size: {e}")))?;
    let total_disk_bytes = u64::try_from(page_count.saturating_mul(page_size)).unwrap_or(0);

    // v38.4.0 (#767) — probe ONCE per summary, and report the answer.
    let dbstat_ok = guard
        .query_row("SELECT COALESCE(SUM(pgsize),0) FROM dbstat", [], |r| {
            r.get::<_, i64>(0)
        })
        .is_ok();

    let trace_events = table_usage_sqlite(
        &guard,
        "trace_events",
        Some("ts"),
        Some("admitted_at"),
        dbstat_ok,
    )?;
    let trace_llm_calls =
        table_usage_sqlite(&guard, "trace_llm_calls", Some("ts"), None, dbstat_ok)?;
    let detection_events = table_usage_sqlite(
        &guard,
        "cirislens_derived_detection_events",
        Some("ts"),
        None,
        dbstat_ok,
    )?;

    let audit_log = {
        #[cfg(feature = "cirisaudit")]
        {
            table_usage_sqlite(
                &guard,
                "cirislens_audit_log",
                Some("recorded_at"),
                None,
                dbstat_ok,
            )?
        }
        #[cfg(not(feature = "cirisaudit"))]
        {
            TableUsage::default()
        }
    };

    let edge_outbound_queue = table_usage_sqlite(
        &guard,
        "edge_outbound_queue",
        Some("enqueued_at"),
        None,
        dbstat_ok,
    )?;
    let federation_keys = table_usage_sqlite(
        &guard,
        "federation_keys",
        Some("valid_from"),
        None,
        dbstat_ok,
    )?;

    // v38.4.0 (#767) — EVERY table, enumerated from the catalogue.
    //
    // Ask 1 offered a choice: name the five tables the incident exposed, or
    // add one `unclassified` bucket. Neither closes the CLASS — the next
    // table added is invisible again, exactly as these five were. The
    // catalogue answers permanently: a table cannot be added to this
    // schema without appearing here, and `dark_bytes` below is then a
    // derived residual rather than a hand-maintained list's blind spot.
    let mut tables = std::collections::BTreeMap::new();
    {
        let mut stmt = guard
            .prepare(
                "SELECT name FROM sqlite_master WHERE type='table' \
                 AND name NOT LIKE 'sqlite_%' ORDER BY name",
            )
            .map_err(|e| RetentionError::Backend(format!("catalogue: {e}")))?;
        let names: Vec<String> = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|e| RetentionError::Backend(format!("catalogue rows: {e}")))?
            .collect::<Result<_, _>>()
            .map_err(|e| RetentionError::Backend(format!("catalogue collect: {e}")))?;
        drop(stmt);
        for name in names {
            let usage =
                table_usage_sqlite(&guard, &name, super::ts_column_for(&name), None, dbstat_ok)?;
            tables.insert(name, usage);
        }
    }
    let dark_bytes = total_disk_bytes.saturating_sub(tables.values().map(|u| u.bytes).sum());

    Ok(StorageSummary {
        trace_events,
        trace_llm_calls,
        detection_events,
        audit_log,
        edge_outbound_queue,
        federation_keys,
        tables,
        dark_bytes,
        bytes_measurable: dbstat_ok,
        total_disk_bytes,
    })
}

/// v32.1.0 (CIRISPersist#606) — `admitted_col` names the node-local admission
/// instant when the table has one (today: `trace_events` only, V128).
///
/// Passed explicitly rather than probed, because a probe that guesses wrong
/// fails toward "no reading" — and a liveness field that is silently always
/// `None` is exactly the shape of a check that cannot fail. A caller that adds
/// the column to another table must say so here, and will notice.
fn table_usage_sqlite(
    conn: &Connection,
    table: &str,
    ts_column: Option<&str>,
    admitted_col: Option<&str>,
    dbstat_ok: bool,
) -> Result<TableUsage, RetentionError> {
    // v38.4.0 (CIRISPersist#767) — **REAL per-table bytes on SQLite.**
    //
    // This was hardcoded `0` for six releases on the stated belief that
    // "the dbstat virtual table is not compiled in by default". MEASURED
    // against this crate's own bundled SQLite: `dbstat` IS available and
    // answers. The belief was never probed, and it cost the operator the
    // one reading that localises disk growth — a production node filled up
    // while the summary reported per-table `bytes: 0` across the board and
    // only `total_disk_bytes` carried the weight.
    //
    // Still soft-failed to 0 rather than erroring: a build genuinely
    // without `SQLITE_ENABLE_DBSTAT_VTAB` must degrade to the old reading,
    // not refuse to report. `dbstat_available()` probes once per summary
    // so the degradation is VISIBLE in `StorageSummary::bytes_measurable`
    // instead of being indistinguishable from an empty table.
    let bytes = if dbstat_ok {
        conn.query_row(
            "SELECT COALESCE(SUM(pgsize), 0) FROM dbstat WHERE name = ?1",
            params![table],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map_err(|e| RetentionError::Backend(format!("dbstat {table}: {e}")))?
        .and_then(|v| u64::try_from(v).ok())
        .unwrap_or(0)
    } else {
        0
    };

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

    // A table with no time-series column (a projection like
    // `attestation_subjects`, a resolver like `signed_wire_index`) still
    // has weight and rows — it just cannot answer "how old". Counting it
    // with `oldest/newest = None` is the honest reading; omitting it
    // entirely is what made the store dark (#767).
    let stats_sql = match ts_column {
        Some(col) => format!("SELECT count(*), MIN({col}), MAX({col}) FROM {table}"),
        None => format!("SELECT count(*), NULL, NULL FROM {table}"),
    };
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

    // v32.1.0 (#606) — a SEPARATE `MAX()`, pushed down and index-served, so a
    // liveness read stays an aggregate rather than becoming a scan of the
    // largest table in the schema. Kept out of the stats query above because
    // most tables have no such column and a NULL there would be
    // indistinguishable from an empty table.
    let newest_admitted_at = match admitted_col {
        Some(col) => {
            let sql = format!("SELECT MAX({col}) FROM {table}");
            let raw: Option<String> = conn
                .query_row(&sql, [], |row| row.get(0))
                .map_err(|e| RetentionError::Backend(format!("admitted stats {table}: {e}")))?;
            match raw {
                Some(s) => Some(parse_rfc3339(&s)?),
                None => None,
            }
        }
        None => None,
    };

    Ok(TableUsage {
        bytes,
        rows,
        oldest_ts,
        newest_ts,
        newest_admitted_at,
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
    let deleted = (move || -> Result<usize, RetentionError> {
        let guard = conn.lock();
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
    })()?;
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

    (move || -> Result<ArchiveHandle, RetentionError> {
        let mut guard = conn.lock();
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
    })()
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
    (move || -> Result<Option<Vec<u8>>, RetentionError> {
        let guard = conn.lock();
        let bytes: Option<Vec<u8>> = guard
            .query_row(
                "SELECT archive_bytes FROM cirislens_audit_archives WHERE archive_id = ?1",
                params![id_str],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| RetentionError::Backend(format!("lookup_audit_archive: {e}")))?;
        Ok(bytes)
    })()
}
