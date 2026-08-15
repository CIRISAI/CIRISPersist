//! PostgreSQL impl of the retention primitives (v2.7.0, CIRISPersist#107).
//!
//! Three operations:
//!
//! - `storage_summary` — per-table introspection via
//!   `pg_relation_size` + `count(*) / MIN / MAX`. Reads only; one
//!   pool connection.
//! - `delete_traces_older_than` — bounded-batch DELETE on
//!   `cirislens.trace_events` keyed by the `ts` column. Uses a CTE
//!   subquery so PG honors the row cap (PG `DELETE` doesn't accept
//!   `ORDER BY ... LIMIT` directly).
//! - `archive_audit_range` — chain-anchored archive + truncate on
//!   `cirislens.audit_log` over a `(tenant_id, from_ts, to_ts)`
//!   range. Single-tenant per call (the audit chain is per-tenant;
//!   archives that span tenants return `RetentionError::MultiTenant`).
//!   All steps run in one transaction; the live row immediately after
//!   the archived range KEEPS its `prev_hash` pointing at the
//!   archived range's last `entry_hash` — that's the `chain_anchor`
//!   on the returned [`ArchiveHandle`], so verifiers can walk the
//!   chain across the archive.

use chrono::{DateTime, Utc};
#[cfg(feature = "cirisaudit")]
use sha2::{Digest, Sha256};

#[cfg(feature = "cirisaudit")]
use super::ArchiveHandle;
use super::{RetentionError, StorageSummary, TableUsage};
use crate::store::postgres::PostgresBackend;

/// v2.7.0 — [`StorageSummary`] for a `PostgresBackend`.
///
/// Per-table reporting via `pg_relation_size` (bytes; includes
/// indexes/TOAST) + `count(*)` + `MIN(<ts>) / MAX(<ts>)` for the
/// oldest/newest rows. Tables that aren't part of the current
/// cargo feature set surface as [`TableUsage::default`] so the
/// struct shape stays stable.
pub async fn storage_summary_pg(
    backend: &PostgresBackend,
) -> Result<StorageSummary, RetentionError> {
    let client = backend
        .pool()
        .get()
        .await
        .map_err(|e| RetentionError::Backend(format!("pool: {e}")))?;

    // Whole-database disk bytes.
    let total_disk_bytes: u64 = {
        let row = client
            .query_one(
                "SELECT pg_database_size(current_database())::BIGINT AS sz",
                &[],
            )
            .await
            .map_err(|e| RetentionError::Backend(format!("pg_database_size: {e}")))?;
        let sz: i64 = row
            .try_get("sz")
            .map_err(|e| RetentionError::Backend(format!("decode db size: {e}")))?;
        u64::try_from(sz).unwrap_or(0)
    };

    let trace_events =
        table_usage_pg(&client, "cirislens.trace_events", "ts", Some("admitted_at")).await?;
    let trace_llm_calls = table_usage_pg(&client, "cirislens.trace_llm_calls", "ts", None).await?;
    // detection_events lives in cirislens_derived (V008). Always
    // built — DerivedSchema is feature-flag-independent.
    let detection_events =
        table_usage_pg(&client, "cirislens_derived.detection_events", "ts", None).await?;

    let audit_log = {
        #[cfg(feature = "cirisaudit")]
        {
            table_usage_pg(&client, "cirislens.audit_log", "recorded_at", None).await?
        }
        #[cfg(not(feature = "cirisaudit"))]
        {
            TableUsage::default()
        }
    };

    let edge_outbound_queue = table_usage_pg(
        &client,
        "cirislens.edge_outbound_queue",
        "enqueued_at",
        None,
    )
    .await?;

    let federation_keys =
        table_usage_pg(&client, "cirislens.federation_keys", "valid_from", None).await?;

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

/// Per-table read helper: bytes (`pg_relation_size`) + row count + ts
/// bounds. `qualified` is the fully-qualified `schema.table` string;
/// `ts_column` is the timestamp column for `MIN` / `MAX`.
///
/// Tables that don't exist (e.g., when a deployment hasn't run V008's
/// derived schema) surface as a default `TableUsage` rather than
/// erroring — the storage summary is best-effort introspection, not
/// a schema invariant.
/// v32.1.0 (CIRISPersist#606) — `admitted_col` names the node-local admission
/// instant when the table has one (today: `trace_events` only, V128).
///
/// Passed explicitly rather than probed: a probe that guesses wrong fails
/// toward "no reading", and a liveness field that is silently always `None` is
/// exactly the shape of a check that cannot fail.
async fn table_usage_pg(
    client: &deadpool_postgres::Client,
    qualified: &str,
    ts_column: &str,
    admitted_col: Option<&str>,
) -> Result<TableUsage, RetentionError> {
    // pg_relation_size accepts a regclass; a missing table errors
    // with `relation "..." does not exist`. We map that to an empty
    // TableUsage rather than failing — the cohabitation store has
    // optional tables.
    let bytes = match client
        .query_one(
            &format!("SELECT pg_relation_size('{}')::BIGINT AS sz", qualified),
            &[],
        )
        .await
    {
        Ok(row) => {
            let sz: i64 = row
                .try_get("sz")
                .map_err(|e| RetentionError::Backend(format!("decode {qualified} size: {e}")))?;
            u64::try_from(sz).unwrap_or(0)
        }
        Err(e) => {
            // 42P01 — undefined_table. Soft-fail with default.
            if let Some(code) = e.code() {
                if code.code() == "42P01" {
                    return Ok(TableUsage::default());
                }
            }
            return Err(RetentionError::Backend(format!(
                "pg_relation_size {qualified}: {e}"
            )));
        }
    };

    let stats_sql = format!(
        "SELECT count(*)::BIGINT AS rows, MIN({col})::TIMESTAMPTZ AS oldest, MAX({col})::TIMESTAMPTZ AS newest FROM {tbl}",
        col = ts_column,
        tbl = qualified,
    );
    let row = client
        .query_one(&stats_sql, &[])
        .await
        .map_err(|e| RetentionError::Backend(format!("stats query {qualified}: {e}")))?;

    let rows_i: i64 = row
        .try_get("rows")
        .map_err(|e| RetentionError::Backend(format!("decode {qualified} rows: {e}")))?;
    let rows = u64::try_from(rows_i).unwrap_or(0);

    let oldest_ts: Option<DateTime<Utc>> = row
        .try_get("oldest")
        .map_err(|e| RetentionError::Backend(format!("decode {qualified} oldest: {e}")))?;
    let newest_ts: Option<DateTime<Utc>> = row
        .try_get("newest")
        .map_err(|e| RetentionError::Backend(format!("decode {qualified} newest: {e}")))?;

    // v32.1.0 (#606) — a SEPARATE `MAX()`, pushed down and index-served, so a
    // liveness read stays an aggregate rather than a scan of the largest table
    // in the schema. Kept out of the stats query above because most tables have
    // no such column and a NULL there would be indistinguishable from an empty
    // table.
    let newest_admitted_at: Option<DateTime<Utc>> = match admitted_col {
        Some(col) => {
            let sql = format!("SELECT MAX({col})::TIMESTAMPTZ AS newest_admitted FROM {qualified}");
            let arow = client
                .query_one(&sql, &[])
                .await
                .map_err(|e| RetentionError::Backend(format!("admitted stats {qualified}: {e}")))?;
            arow.try_get("newest_admitted").map_err(|e| {
                RetentionError::Backend(format!("decode {qualified} newest_admitted: {e}"))
            })?
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

/// v2.7.0 — bounded-batch DELETE on `cirislens.trace_events` for
/// rows whose `ts < threshold`, capped at `max_rows`. Returns the
/// number of rows actually deleted.
///
/// PG doesn't support `ORDER BY ... LIMIT` on DELETE directly; the
/// implementation uses a CTE subquery against the dedup-index'd
/// `(event_id, ts)` PK so the row cap is honored at the planner.
pub async fn delete_traces_older_than_pg(
    backend: &PostgresBackend,
    ts: DateTime<Utc>,
    max_rows: usize,
) -> Result<usize, RetentionError> {
    if max_rows == 0 {
        return Ok(0);
    }
    // The PK is (event_id, ts); we delete by that pair to avoid any
    // ambiguity around partial-row matching on the inner SELECT.
    let limit_i64 = i64::try_from(max_rows)
        .map_err(|_| RetentionError::InvalidArgument(format!("max_rows {max_rows} > i64::MAX")))?;
    let client = backend
        .pool()
        .get()
        .await
        .map_err(|e| RetentionError::Backend(format!("pool: {e}")))?;
    let deleted = client
        .execute(
            "DELETE FROM cirislens.trace_events \
             WHERE (event_id, ts) IN ( \
                 SELECT event_id, ts \
                 FROM cirislens.trace_events \
                 WHERE ts < $1 \
                 ORDER BY ts \
                 LIMIT $2 \
             )",
            &[&ts, &limit_i64],
        )
        .await
        .map_err(|e| RetentionError::Backend(format!("delete_traces_older_than: {e}")))?;
    Ok(deleted as usize)
}

/// v2.7.0 — chain-anchored archive + truncate of `cirislens.audit_log`
/// over `[from_ts, to_ts)`.
///
/// Steps (all in one transaction):
///
/// 1. SELECT the archived rows (`recorded_at >= from_ts AND recorded_at
///    < to_ts`), `ORDER BY tenant_id, sequence_number`.
/// 2. Validate single-tenant. If the range spans multiple tenants
///    return [`RetentionError::MultiTenant`] (the audit chain is
///    per-tenant; archives MUST be single-tenant).
/// 3. Empty range — return an empty handle (no-op).
/// 4. Compute `chain_anchor = entry_hash of last archived row`.
/// 5. Canonicalize the archived rows; compute archive SHA-256;
///    derive `archive_id`.
/// 6. INSERT into `cirislens.audit_archives`.
/// 7. DELETE the archived rows from `cirislens.audit_log` by primary
///    key (`entry_id`).
/// 8. Commit. The live row immediately after the archived range still
///    carries its original `prev_hash` (it was never touched), which
///    equals `chain_anchor` — the chain stays unbroken.
#[cfg(feature = "cirisaudit")]
pub async fn archive_audit_range_pg(
    backend: &PostgresBackend,
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

    let mut client = backend
        .pool()
        .get()
        .await
        .map_err(|e| RetentionError::Backend(format!("pool: {e}")))?;
    let tx = client
        .transaction()
        .await
        .map_err(|e| RetentionError::Backend(format!("begin tx: {e}")))?;

    // 1. SELECT archived rows.
    let rows = tx
        .query(
            "SELECT entry_id, sequence_number, tenant_id, actor_id, action_type, \
                    subject_kind, subject_id, payload, prev_hash, entry_hash, \
                    recorded_at, signature \
             FROM cirislens.audit_log \
             WHERE recorded_at >= $1 AND recorded_at < $2 \
             ORDER BY tenant_id, sequence_number",
            &[&from_ts, &to_ts],
        )
        .await
        .map_err(|e| RetentionError::Backend(format!("archive select: {e}")))?;

    if rows.is_empty() {
        tx.commit()
            .await
            .map_err(|e| RetentionError::Backend(format!("commit: {e}")))?;
        return Ok(ArchiveHandle {
            archive_id: Uuid::nil(),
            from_ts,
            to_ts,
            rows_archived: 0,
            chain_anchor: [0u8; 32],
        });
    }

    // 2. Single-tenant guard. Audit chain is per-tenant; the FSD
    //    bars cross-tenant archives. Caller must issue one
    //    archive_audit_range per tenant.
    let first_tenant: String = rows[0]
        .try_get("tenant_id")
        .map_err(|e| RetentionError::Backend(format!("decode tenant_id: {e}")))?;
    for row in rows.iter().skip(1) {
        let t: String = row
            .try_get("tenant_id")
            .map_err(|e| RetentionError::Backend(format!("decode tenant_id: {e}")))?;
        if t != first_tenant {
            return Err(RetentionError::MultiTenant(format!(
                "range spans tenants {first_tenant:?} and {t:?}; issue one call per tenant"
            )));
        }
    }

    // 3+4. Decode rows + chain_anchor.
    let mut entries: Vec<AuditEntry> = Vec::with_capacity(rows.len());
    for row in &rows {
        let entry_id_uuid: Uuid = row
            .try_get("entry_id")
            .map_err(|e| RetentionError::Backend(format!("decode entry_id: {e}")))?;
        entries.push(AuditEntry {
            entry_id: entry_id_uuid.to_string(),
            sequence_number: row
                .try_get("sequence_number")
                .map_err(|e| RetentionError::Backend(format!("decode sequence_number: {e}")))?,
            tenant_id: row
                .try_get("tenant_id")
                .map_err(|e| RetentionError::Backend(format!("decode tenant_id: {e}")))?,
            actor_id: row
                .try_get("actor_id")
                .map_err(|e| RetentionError::Backend(format!("decode actor_id: {e}")))?,
            action_type: row
                .try_get("action_type")
                .map_err(|e| RetentionError::Backend(format!("decode action_type: {e}")))?,
            subject_kind: row
                .try_get("subject_kind")
                .map_err(|e| RetentionError::Backend(format!("decode subject_kind: {e}")))?,
            subject_id: row
                .try_get("subject_id")
                .map_err(|e| RetentionError::Backend(format!("decode subject_id: {e}")))?,
            payload: row
                .try_get("payload")
                .map_err(|e| RetentionError::Backend(format!("decode payload: {e}")))?,
            prev_hash: row
                .try_get("prev_hash")
                .map_err(|e| RetentionError::Backend(format!("decode prev_hash: {e}")))?,
            entry_hash: row
                .try_get("entry_hash")
                .map_err(|e| RetentionError::Backend(format!("decode entry_hash: {e}")))?,
            recorded_at: row
                .try_get("recorded_at")
                .map_err(|e| RetentionError::Backend(format!("decode recorded_at: {e}")))?,
            signature: row
                .try_get("signature")
                .map_err(|e| RetentionError::Backend(format!("decode signature: {e}")))?,
        });
    }

    let last = entries.last().expect("non-empty (guarded above)");
    if last.entry_hash.len() != 32 {
        return Err(RetentionError::Backend(format!(
            "last archived entry_hash is {} bytes, expected 32",
            last.entry_hash.len()
        )));
    }
    let mut chain_anchor = [0u8; 32];
    chain_anchor.copy_from_slice(&last.entry_hash);

    // 5. Canonical bytes + content-addressed archive_id.
    let archive_bytes = super::canonical_archive_bytes(&entries)?;
    let mut hasher = Sha256::new();
    hasher.update(&archive_bytes);
    let sha: [u8; 32] = hasher.finalize().into();
    let archive_id = super::archive_id_from_sha(&sha);
    let rows_archived = entries.len() as u64;

    // 6. INSERT archive row.
    let rows_archived_i: i64 = rows.len() as i64;
    tx.execute(
        "INSERT INTO cirislens.audit_archives (\
            archive_id, tenant_id, from_ts, to_ts, \
            rows_archived, chain_anchor, archive_bytes\
         ) VALUES ($1, $2, $3, $4, $5, $6, $7)",
        &[
            &archive_id,
            &first_tenant,
            &from_ts,
            &to_ts,
            &rows_archived_i,
            &chain_anchor.as_slice(),
            &archive_bytes,
        ],
    )
    .await
    .map_err(|e| RetentionError::Backend(format!("archive insert: {e}")))?;

    // 7. DELETE the archived rows by entry_id (PK). Sequence numbers
    //    on the live audit_log retain their values; the live row
    //    immediately after the archived range still carries the
    //    prev_hash equal to chain_anchor.
    let mut entry_uuids: Vec<Uuid> = Vec::with_capacity(entries.len());
    for entry in &entries {
        let u = Uuid::parse_str(&entry.entry_id)
            .map_err(|e| RetentionError::Backend(format!("entry_id parse: {e}")))?;
        entry_uuids.push(u);
    }
    tx.execute(
        "DELETE FROM cirislens.audit_log WHERE entry_id = ANY($1)",
        &[&entry_uuids],
    )
    .await
    .map_err(|e| RetentionError::Backend(format!("archive delete: {e}")))?;

    tx.commit()
        .await
        .map_err(|e| RetentionError::Backend(format!("commit: {e}")))?;

    Ok(ArchiveHandle {
        archive_id,
        from_ts,
        to_ts,
        rows_archived,
        chain_anchor,
    })
}

/// v2.7.0 — read an archive blob by `archive_id`. Used by tests +
/// offline verifiers walking the chain across an archive.
///
/// Returns `Ok(None)` when no archive with that id exists.
#[cfg(feature = "cirisaudit")]
pub async fn lookup_audit_archive_pg(
    backend: &PostgresBackend,
    archive_id: uuid::Uuid,
) -> Result<Option<Vec<u8>>, RetentionError> {
    let client = backend
        .pool()
        .get()
        .await
        .map_err(|e| RetentionError::Backend(format!("pool: {e}")))?;
    let row_opt = client
        .query_opt(
            "SELECT archive_bytes FROM cirislens.audit_archives WHERE archive_id = $1",
            &[&archive_id],
        )
        .await
        .map_err(|e| RetentionError::Backend(format!("lookup_audit_archive: {e}")))?;
    match row_opt {
        None => Ok(None),
        Some(row) => {
            let bytes: Vec<u8> = row
                .try_get("archive_bytes")
                .map_err(|e| RetentionError::Backend(format!("decode archive_bytes: {e}")))?;
            Ok(Some(bytes))
        }
    }
}
