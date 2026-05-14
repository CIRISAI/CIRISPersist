//! SQLite impl of [`AuditService`] (v0.8.5, CIRISPersist#38).
//!
//! Mirrors v0.8.1 Postgres impl with SQLite-dialect translations:
//! BYTEA → BLOB for the 32-byte sha256 hashes, JSONB → TEXT JSON
//! for the payload, TIMESTAMPTZ → RFC 3339 TEXT for timestamps.
//! Hash-chain semantics (AV-49/AV-50/AV-51) are unchanged.
//!
//! # Per-tenant tail-lock under SQLite
//!
//! Postgres uses `SELECT … FOR UPDATE` on the tail row. SQLite has
//! no per-row exclusive lock — concurrent writers serialize at the
//! DATABASE level via `BEGIN IMMEDIATE` (acquires the RESERVED
//! lock immediately, preventing any other writer until commit).
//! Slightly coarser-grained than per-tenant, but with the
//! `PRAGMA busy_timeout = 30000` set in `SqliteBackend` connection
//! init, concurrent writers wait up to 30s rather than failing
//! fast — sufficient for the audit-log write workload.

use std::sync::Arc;

use rusqlite::{params, params_from_iter, types::Value as SqlValue, Connection, OptionalExtension};
use tokio::sync::Mutex;

use super::service::AuditService;
use super::types::{
    AuditCursor, AuditEntry, AuditEventRef, AuditFilter, AuditListPage, ChainBreakReason,
    ChainVerification, ChainVerifyOutcome, CorrelationQuery, CORRELATION_QUERY_MAX_LIMIT,
};
use super::verify::{compute_entry_hash, verify_entry_signature};
use super::{Error, GENESIS_PREV_HASH};
use crate::ClaimResult;

/// SQLite-backed [`AuditService`] impl. Wraps an
/// `Arc<Mutex<Connection>>` shared with
/// [`crate::store::sqlite::SqliteBackend`] so the audit-log writes
/// ride the same WAL + PRAGMA settings as the trace-ingest path.
pub struct SqliteAuditBackend {
    conn: Arc<Mutex<Connection>>,
}

impl SqliteAuditBackend {
    /// Construct from a shared connection handle (typically
    /// `SqliteBackend::conn_handle()`).
    pub fn new(conn: Arc<Mutex<Connection>>) -> Self {
        Self { conn }
    }
}

fn map_sqlite_error(e: rusqlite::Error, op: &str) -> Error {
    use rusqlite::ErrorCode;
    if let rusqlite::Error::SqliteFailure(err, _) = &e {
        if let ErrorCode::ConstraintViolation = err.code {
            return Error::Conflict(format!("{op}: {e}"));
        }
    }
    Error::Backend(format!("{op}: {e}"))
}

fn parse_datetime(s: &str) -> Result<chrono::DateTime<chrono::Utc>, Error> {
    let normalized = if s.contains('T') {
        s.to_owned()
    } else {
        format!("{}+00:00", s.replacen(' ', "T", 1))
    };
    chrono::DateTime::parse_from_rfc3339(&normalized)
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .map_err(|e| Error::Backend(format!("datetime parse: {e} (raw={s})")))
}

fn fmt_datetime(dt: chrono::DateTime<chrono::Utc>) -> String {
    dt.to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
}

fn decode_entry_row(row: &rusqlite::Row<'_>) -> Result<AuditEntry, Error> {
    let payload_str: String = row
        .get("payload")
        .map_err(|e| Error::Backend(format!("decode payload: {e}")))?;
    let payload = serde_json::from_str(&payload_str)
        .map_err(|e| Error::Backend(format!("payload JSON decode: {e}")))?;
    let recorded_at_str: String = row
        .get("recorded_at")
        .map_err(|e| Error::Backend(format!("decode recorded_at: {e}")))?;
    Ok(AuditEntry {
        entry_id: row
            .get("entry_id")
            .map_err(|e| Error::Backend(format!("decode entry_id: {e}")))?,
        sequence_number: row
            .get("sequence_number")
            .map_err(|e| Error::Backend(format!("decode seq: {e}")))?,
        tenant_id: row
            .get("tenant_id")
            .map_err(|e| Error::Backend(format!("decode tenant_id: {e}")))?,
        actor_id: row
            .get("actor_id")
            .map_err(|e| Error::Backend(format!("decode actor_id: {e}")))?,
        action_type: row
            .get("action_type")
            .map_err(|e| Error::Backend(format!("decode action_type: {e}")))?,
        subject_kind: row
            .get("subject_kind")
            .map_err(|e| Error::Backend(format!("decode subject_kind: {e}")))?,
        subject_id: row
            .get("subject_id")
            .map_err(|e| Error::Backend(format!("decode subject_id: {e}")))?,
        payload,
        prev_hash: row
            .get("prev_hash")
            .map_err(|e| Error::Backend(format!("decode prev_hash: {e}")))?,
        entry_hash: row
            .get("entry_hash")
            .map_err(|e| Error::Backend(format!("decode entry_hash: {e}")))?,
        recorded_at: parse_datetime(&recorded_at_str)?,
        signature: row
            .get("signature")
            .map_err(|e| Error::Backend(format!("decode signature: {e}")))?,
    })
}

impl AuditService for SqliteAuditBackend {
    async fn record_entry(&self, entry: AuditEntry) -> Result<(), Error> {
        if entry.sequence_number < 1 {
            return Err(Error::InvalidArgument(
                "sequence_number must be >= 1".into(),
            ));
        }
        if entry.tenant_id.is_empty() {
            return Err(Error::InvalidArgument("tenant_id must be non-empty".into()));
        }
        if entry.prev_hash.len() != 32 {
            return Err(Error::InvalidArgument(format!(
                "prev_hash must be 32 bytes, got {}",
                entry.prev_hash.len()
            )));
        }
        if entry.entry_hash.len() != 32 {
            return Err(Error::InvalidArgument(format!(
                "entry_hash must be 32 bytes, got {}",
                entry.entry_hash.len()
            )));
        }

        // AV-49 entry_hash re-derive.
        let derived = compute_entry_hash(&entry)?;
        if derived.as_slice() != entry.entry_hash.as_slice() {
            return Err(Error::ChainIntegrity(
                "entry_hash mismatch: caller-claimed differs from canonical-bytes derivation"
                    .into(),
            ));
        }

        verify_entry_signature(&entry)?;

        let payload_str = serde_json::to_string(&entry.payload)
            .map_err(|e| Error::Internal(format!("payload serialize: {e}")))?;
        let recorded_at = fmt_datetime(entry.recorded_at);
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> Result<(), Error> {
            let mut guard = conn.blocking_lock();
            // BEGIN IMMEDIATE acquires the database-level RESERVED
            // lock — coarser than Postgres FOR UPDATE but combined
            // with PRAGMA busy_timeout=30000 (v0.8.4) it serializes
            // writers safely without deadlock risk.
            let tx = guard
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .map_err(|e| map_sqlite_error(e, "audit record begin tx"))?;
            let tail = tx
                .query_row(
                    "SELECT sequence_number, entry_hash FROM cirislens_audit_log \
                     WHERE tenant_id = ?1 \
                     ORDER BY sequence_number DESC LIMIT 1",
                    params![entry.tenant_id],
                    |row| {
                        let seq: i64 = row.get(0)?;
                        let hash: Vec<u8> = row.get(1)?;
                        Ok((seq, hash))
                    },
                )
                .optional()
                .map_err(|e| map_sqlite_error(e, "audit record tail read"))?;

            if let Some((prev_seq, prev_hash)) = tail {
                if entry.sequence_number != prev_seq + 1 {
                    return Err(Error::ChainIntegrity(format!(
                        "sequence gap: expected {} but got {}",
                        prev_seq + 1,
                        entry.sequence_number
                    )));
                }
                if entry.prev_hash.as_slice() != prev_hash.as_slice() {
                    return Err(Error::ChainIntegrity(format!(
                        "prev_hash mismatch at sequence {} for tenant {}",
                        entry.sequence_number, entry.tenant_id
                    )));
                }
            } else {
                if entry.sequence_number != 1 {
                    return Err(Error::ChainIntegrity(format!(
                        "first entry for tenant {} must have sequence_number=1, got {}",
                        entry.tenant_id, entry.sequence_number
                    )));
                }
                if entry.prev_hash.as_slice() != GENESIS_PREV_HASH.as_slice() {
                    return Err(Error::ChainIntegrity(
                        "first entry must have prev_hash = GENESIS_PREV_HASH (32 zero bytes)"
                            .into(),
                    ));
                }
            }

            tx.execute(
                "INSERT INTO cirislens_audit_log (\
                    entry_id, sequence_number, tenant_id, actor_id, \
                    action_type, subject_kind, subject_id, payload, \
                    prev_hash, entry_hash, recorded_at, \
                    signature, signing_key_id, signature_verified, persist_row_hash\
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, 1, ?14)",
                params![
                    entry.entry_id,
                    entry.sequence_number,
                    entry.tenant_id,
                    entry.actor_id,
                    entry.action_type,
                    entry.subject_kind,
                    entry.subject_id,
                    payload_str,
                    entry.prev_hash,
                    entry.entry_hash,
                    recorded_at,
                    entry.signature,
                    entry.actor_id,  // signing_key_id = actor_id (self-signed)
                    entry.signature, // persist_row_hash placeholder
                ],
            )
            .map_err(|e| map_sqlite_error(e, "audit record insert"))?;
            tx.commit()
                .map_err(|e| map_sqlite_error(e, "audit record commit"))?;
            Ok(())
        })
        .await
        .map_err(|e| Error::Backend(format!("spawn_blocking join: {e}")))?
    }

    async fn list_entries(
        &self,
        filter: AuditFilter,
        cursor: Option<AuditCursor>,
        limit: i64,
    ) -> Result<AuditListPage, Error> {
        if filter.tenant_id.is_empty() {
            return Err(Error::InvalidArgument(
                "tenant_id is required (AV-51 — no cross-tenant reads)".into(),
            ));
        }
        if !(1..=10_000).contains(&limit) {
            return Err(Error::InvalidArgument(format!(
                "limit must be in [1, 10000], got {limit}"
            )));
        }

        let mut where_parts: Vec<String> = vec!["tenant_id = ?".to_string()];
        let mut params: Vec<SqlValue> = vec![SqlValue::Text(filter.tenant_id)];
        if let Some(at) = filter.action_type {
            params.push(SqlValue::Text(at));
            where_parts.push("action_type = ?".to_string());
        }
        if let Some(aid) = filter.actor_id {
            params.push(SqlValue::Text(aid));
            where_parts.push("actor_id = ?".to_string());
        }
        if let Some(sk) = filter.subject_kind {
            params.push(SqlValue::Text(sk));
            where_parts.push("subject_kind = ?".to_string());
        }
        if let Some(sid) = filter.subject_id {
            params.push(SqlValue::Text(sid));
            where_parts.push("subject_id = ?".to_string());
        }
        if let Some(after) = filter.recorded_after {
            params.push(SqlValue::Text(fmt_datetime(after)));
            where_parts.push("recorded_at >= ?".to_string());
        }
        if let Some(before) = filter.recorded_before {
            params.push(SqlValue::Text(fmt_datetime(before)));
            where_parts.push("recorded_at <= ?".to_string());
        }
        if let Some(cur) = &cursor {
            if cur.version != "v1" {
                return Err(Error::InvalidArgument(format!(
                    "AuditCursor version {} unsupported (expected v1)",
                    cur.version
                )));
            }
            params.push(SqlValue::Text(fmt_datetime(cur.last_ts)));
            params.push(SqlValue::Text(cur.last_id.clone()));
            where_parts.push("(recorded_at, entry_id) < (?, ?)".to_string());
        }
        params.push(SqlValue::Integer(limit));
        let where_sql = where_parts.join(" AND ");
        let sql = format!(
            "SELECT entry_id, sequence_number, tenant_id, actor_id, \
                    action_type, subject_kind, subject_id, payload, \
                    prev_hash, entry_hash, recorded_at, signature \
             FROM cirislens_audit_log \
             WHERE {where_sql} \
             ORDER BY recorded_at DESC, entry_id DESC \
             LIMIT ?"
        );
        let conn = self.conn.clone();
        let limit_usize = limit as usize;
        tokio::task::spawn_blocking(move || -> Result<AuditListPage, Error> {
            let guard = conn.blocking_lock();
            let mut stmt = guard
                .prepare(&sql)
                .map_err(|e| map_sqlite_error(e, "list_entries prepare"))?;
            let rows_iter = stmt
                .query_map(params_from_iter(params.iter()), |row| {
                    Ok(decode_entry_row(row))
                })
                .map_err(|e| map_sqlite_error(e, "list_entries query"))?;
            let mut items = Vec::new();
            for r in rows_iter {
                items.push(r.map_err(|e| map_sqlite_error(e, "list_entries row"))??);
            }
            let next_cursor = if items.len() == limit_usize {
                items
                    .last()
                    .map(|last| AuditCursor::from_trailing(last.recorded_at, last.entry_id.clone()))
            } else {
                None
            };
            Ok(AuditListPage { items, next_cursor })
        })
        .await
        .map_err(|e| Error::Backend(format!("spawn_blocking join: {e}")))?
    }

    async fn verify_chain(
        &self,
        tenant_id: &str,
        from_sequence: i64,
        to_sequence: Option<i64>,
    ) -> Result<ChainVerification, Error> {
        if tenant_id.is_empty() {
            return Err(Error::InvalidArgument("tenant_id must be non-empty".into()));
        }
        if from_sequence < 1 {
            return Err(Error::InvalidArgument("from_sequence must be >= 1".into()));
        }
        let conn = self.conn.clone();
        let tenant_id = tenant_id.to_owned();
        tokio::task::spawn_blocking(move || -> Result<ChainVerification, Error> {
            let guard = conn.blocking_lock();

            let to_seq_resolved: i64 = match to_sequence {
                Some(n) => {
                    if n < from_sequence {
                        return Err(Error::InvalidArgument(format!(
                            "to_sequence ({n}) < from_sequence ({from_sequence})"
                        )));
                    }
                    n
                }
                None => guard
                    .query_row(
                        "SELECT COALESCE(MAX(sequence_number), 0) FROM cirislens_audit_log \
                         WHERE tenant_id = ?1",
                        params![tenant_id],
                        |row| row.get::<_, i64>(0),
                    )
                    .map_err(|e| map_sqlite_error(e, "verify_chain tail probe"))?,
            };

            if to_seq_resolved < from_sequence {
                return Ok(ChainVerification {
                    tenant_id: tenant_id.clone(),
                    from_sequence,
                    to_sequence: to_seq_resolved,
                    entries_walked: 0,
                    outcome: ChainVerifyOutcome::Ok,
                });
            }

            let mut stmt = guard
                .prepare(
                    "SELECT entry_id, sequence_number, tenant_id, actor_id, \
                            action_type, subject_kind, subject_id, payload, \
                            prev_hash, entry_hash, recorded_at, signature \
                     FROM cirislens_audit_log \
                     WHERE tenant_id = ?1 \
                       AND sequence_number BETWEEN ?2 AND ?3 \
                     ORDER BY sequence_number ASC",
                )
                .map_err(|e| map_sqlite_error(e, "verify_chain prepare"))?;
            let rows_iter = stmt
                .query_map(params![tenant_id, from_sequence, to_seq_resolved], |row| {
                    Ok(decode_entry_row(row))
                })
                .map_err(|e| map_sqlite_error(e, "verify_chain query"))?;

            let mut prior_hash: Option<Vec<u8>> = None;
            let mut prior_seq: Option<i64> = None;
            let mut walked = 0usize;
            for r in rows_iter {
                let entry = r.map_err(|e| map_sqlite_error(e, "verify_chain row"))??;
                walked += 1;

                match prior_seq {
                    None => {
                        if entry.sequence_number == 1
                            && entry.prev_hash.as_slice() != GENESIS_PREV_HASH.as_slice()
                        {
                            return Ok(ChainVerification {
                                tenant_id: tenant_id.clone(),
                                from_sequence,
                                to_sequence: to_seq_resolved,
                                entries_walked: walked,
                                outcome: ChainVerifyOutcome::Break {
                                    at_sequence: 1,
                                    reason: ChainBreakReason::GenesisPrevHashNotZero,
                                    detail: "genesis entry must have prev_hash = all zeros".into(),
                                },
                            });
                        }
                    }
                    Some(prev_n) => {
                        if entry.sequence_number != prev_n + 1 {
                            return Ok(ChainVerification {
                                tenant_id: tenant_id.clone(),
                                from_sequence,
                                to_sequence: to_seq_resolved,
                                entries_walked: walked,
                                outcome: ChainVerifyOutcome::Break {
                                    at_sequence: entry.sequence_number,
                                    reason: ChainBreakReason::SequenceGap,
                                    detail: format!(
                                        "expected {} got {}",
                                        prev_n + 1,
                                        entry.sequence_number
                                    ),
                                },
                            });
                        }
                        if let Some(ph) = &prior_hash {
                            if entry.prev_hash.as_slice() != ph.as_slice() {
                                return Ok(ChainVerification {
                                    tenant_id: tenant_id.clone(),
                                    from_sequence,
                                    to_sequence: to_seq_resolved,
                                    entries_walked: walked,
                                    outcome: ChainVerifyOutcome::Break {
                                        at_sequence: entry.sequence_number,
                                        reason: ChainBreakReason::PrevHashMismatch,
                                        detail: format!(
                                            "prev_hash at seq {} did not match prior entry's entry_hash",
                                            entry.sequence_number
                                        ),
                                    },
                                });
                            }
                        }
                    }
                }

                let derived = compute_entry_hash(&entry)?;
                if derived.as_slice() != entry.entry_hash.as_slice() {
                    return Ok(ChainVerification {
                        tenant_id: tenant_id.clone(),
                        from_sequence,
                        to_sequence: to_seq_resolved,
                        entries_walked: walked,
                        outcome: ChainVerifyOutcome::Break {
                            at_sequence: entry.sequence_number,
                            reason: ChainBreakReason::EntryHashMismatch,
                            detail: format!(
                                "entry_hash at seq {} does not match canonical-bytes derivation",
                                entry.sequence_number
                            ),
                        },
                    });
                }

                if let Err(e) = verify_entry_signature(&entry) {
                    return Ok(ChainVerification {
                        tenant_id: tenant_id.clone(),
                        from_sequence,
                        to_sequence: to_seq_resolved,
                        entries_walked: walked,
                        outcome: ChainVerifyOutcome::Break {
                            at_sequence: entry.sequence_number,
                            reason: ChainBreakReason::SignatureFailure,
                            detail: format!(
                                "signature failed at seq {}: {e}",
                                entry.sequence_number
                            ),
                        },
                    });
                }

                prior_hash = Some(entry.entry_hash.clone());
                prior_seq = Some(entry.sequence_number);
            }

            Ok(ChainVerification {
                tenant_id: tenant_id.clone(),
                from_sequence,
                to_sequence: to_seq_resolved,
                entries_walked: walked,
                outcome: ChainVerifyOutcome::Ok,
            })
        })
        .await
        .map_err(|e| Error::Backend(format!("spawn_blocking join: {e}")))?
    }

    async fn try_claim_event(
        &self,
        content_hash: [u8; 32],
        entry: AuditEntry,
        accessor: String,
    ) -> Result<ClaimResult<AuditEventRef>, Error> {
        let _ = accessor; // surfaced into tracing only; actor_id is the identity

        // Same input gates as record_entry.
        if entry.sequence_number < 1 {
            return Err(Error::InvalidArgument(
                "sequence_number must be >= 1".into(),
            ));
        }
        if entry.tenant_id.is_empty() {
            return Err(Error::InvalidArgument("tenant_id must be non-empty".into()));
        }
        if entry.prev_hash.len() != 32 {
            return Err(Error::InvalidArgument(format!(
                "prev_hash must be 32 bytes, got {}",
                entry.prev_hash.len()
            )));
        }
        if entry.entry_hash.len() != 32 {
            return Err(Error::InvalidArgument(format!(
                "entry_hash must be 32 bytes, got {}",
                entry.entry_hash.len()
            )));
        }
        let derived = compute_entry_hash(&entry)?;
        if derived.as_slice() != entry.entry_hash.as_slice() {
            return Err(Error::ChainIntegrity(
                "entry_hash mismatch: caller-claimed differs from canonical-bytes derivation"
                    .into(),
            ));
        }
        verify_entry_signature(&entry)?;

        let payload_str = serde_json::to_string(&entry.payload)
            .map_err(|e| Error::Internal(format!("payload serialize: {e}")))?;
        let recorded_at = fmt_datetime(entry.recorded_at);
        let content_hash_vec = content_hash.to_vec();
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> Result<ClaimResult<AuditEventRef>, Error> {
            let mut guard = conn.blocking_lock();
            let tx = guard
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .map_err(|e| map_sqlite_error(e, "try_claim_event begin tx"))?;

            // Already-claimed lookup before chain checks — cheaper
            // than running the full validation path when the row
            // already exists.
            let existing: Option<(String, String, i64)> = tx
                .query_row(
                    "SELECT entry_id, tenant_id, sequence_number \
                     FROM cirislens_audit_log \
                     WHERE content_hash = ?1",
                    params![content_hash_vec],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, i64>(2)?,
                        ))
                    },
                )
                .optional()
                .map_err(|e| map_sqlite_error(e, "try_claim_event lookup"))?;

            if let Some((entry_id, tenant_id, sequence_number)) = existing {
                tx.commit()
                    .map_err(|e| map_sqlite_error(e, "try_claim_event commit"))?;
                return Ok(ClaimResult::AlreadyClaimed(AuditEventRef {
                    entry_id,
                    tenant_id,
                    sequence_number,
                }));
            }

            // Chain gates on first-write path.
            let tail = tx
                .query_row(
                    "SELECT sequence_number, entry_hash FROM cirislens_audit_log \
                     WHERE tenant_id = ?1 \
                     ORDER BY sequence_number DESC LIMIT 1",
                    params![entry.tenant_id],
                    |row| {
                        let seq: i64 = row.get(0)?;
                        let hash: Vec<u8> = row.get(1)?;
                        Ok((seq, hash))
                    },
                )
                .optional()
                .map_err(|e| map_sqlite_error(e, "try_claim_event tail read"))?;

            if let Some((prev_seq, prev_hash)) = tail {
                if entry.sequence_number != prev_seq + 1 {
                    return Err(Error::ChainIntegrity(format!(
                        "sequence gap: expected {} but got {}",
                        prev_seq + 1,
                        entry.sequence_number
                    )));
                }
                if entry.prev_hash.as_slice() != prev_hash.as_slice() {
                    return Err(Error::ChainIntegrity(format!(
                        "prev_hash mismatch at sequence {} for tenant {}",
                        entry.sequence_number, entry.tenant_id
                    )));
                }
            } else {
                if entry.sequence_number != 1 {
                    return Err(Error::ChainIntegrity(format!(
                        "first entry for tenant {} must have sequence_number=1, got {}",
                        entry.tenant_id, entry.sequence_number
                    )));
                }
                if entry.prev_hash.as_slice() != GENESIS_PREV_HASH.as_slice() {
                    return Err(Error::ChainIntegrity(
                        "first entry must have prev_hash = GENESIS_PREV_HASH (32 zero bytes)"
                            .into(),
                    ));
                }
            }

            // Atomic INSERT OR IGNORE on content_hash. SQLite's
            // INSERT OR IGNORE suppresses both UNIQUE failures —
            // the content_hash one (our race-loss case) AND the
            // (tenant_id, sequence_number) one (would happen if a
            // racing writer claimed the same seq under a different
            // content_hash, which is a true chain violation that
            // we DON'T want to swallow).
            //
            // To distinguish: we run a SELECT by content_hash after
            // the INSERT and check whether the entry_id matches our
            // attempted entry_id. If it doesn't, our INSERT was
            // suppressed by the content_hash UNIQUE (race-loss);
            // if no row matches our content_hash at all, the
            // suppression was for (tenant, seq) instead — surface
            // as Conflict.
            tx.execute(
                "INSERT OR IGNORE INTO cirislens_audit_log (\
                    entry_id, sequence_number, tenant_id, actor_id, \
                    action_type, subject_kind, subject_id, payload, \
                    prev_hash, entry_hash, recorded_at, \
                    signature, signing_key_id, signature_verified, persist_row_hash, \
                    content_hash\
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, 1, ?14, ?15)",
                params![
                    entry.entry_id,
                    entry.sequence_number,
                    entry.tenant_id,
                    entry.actor_id,
                    entry.action_type,
                    entry.subject_kind,
                    entry.subject_id,
                    payload_str,
                    entry.prev_hash,
                    entry.entry_hash,
                    recorded_at,
                    entry.signature,
                    entry.actor_id,
                    entry.signature,
                    content_hash_vec,
                ],
            )
            .map_err(|e| map_sqlite_error(e, "try_claim_event insert"))?;

            // Read-back to determine outcome.
            let row = tx
                .query_row(
                    "SELECT entry_id, tenant_id, sequence_number \
                     FROM cirislens_audit_log \
                     WHERE content_hash = ?1",
                    params![content_hash_vec],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, i64>(2)?,
                        ))
                    },
                )
                .optional()
                .map_err(|e| map_sqlite_error(e, "try_claim_event read-back"))?;

            let result = match row {
                None => {
                    // INSERT OR IGNORE swallowed a non-content_hash
                    // constraint failure (most likely (tenant_id,
                    // sequence_number) UNIQUE — a true chain
                    // collision, not our atomic-claim case).
                    return Err(Error::Conflict(
                        "try_claim_event: (tenant_id, sequence_number) already claimed by a different content_hash".into(),
                    ));
                }
                Some((entry_id, tenant_id, sequence_number)) => {
                    let ref_ = AuditEventRef {
                        entry_id: entry_id.clone(),
                        tenant_id,
                        sequence_number,
                    };
                    if entry_id == entry.entry_id {
                        ClaimResult::Stored(ref_)
                    } else {
                        ClaimResult::AlreadyClaimed(ref_)
                    }
                }
            };

            tx.commit()
                .map_err(|e| map_sqlite_error(e, "try_claim_event commit"))?;
            Ok(result)
        })
        .await
        .map_err(|e| Error::Backend(format!("spawn_blocking join: {e}")))?
    }

    async fn query_by_correlation_id(
        &self,
        tenant_id: &str,
        correlation_id: &str,
        filter: CorrelationQuery,
    ) -> Result<Vec<AuditEntry>, Error> {
        if tenant_id.is_empty() {
            return Err(Error::InvalidArgument(
                "tenant_id is required (AV-51 — no cross-tenant reads)".into(),
            ));
        }
        if correlation_id.is_empty() {
            // See PG impl note — empty correlation_id is a defined
            // no-op (returns empty Vec).
            return Ok(Vec::new());
        }
        let limit = filter.limit.clamp(1, CORRELATION_QUERY_MAX_LIMIT) as i64;
        let tenant_id = tenant_id.to_owned();
        let correlation_id = correlation_id.to_owned();
        let start = filter.time_window_start.map(fmt_datetime);
        let end = filter.time_window_end.map(fmt_datetime);
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> Result<Vec<AuditEntry>, Error> {
            let guard = conn.blocking_lock();
            // json_extract returns NULL when the key is absent and a
            // TEXT value when present (payload is stored as TEXT JSON
            // — see V014 SQLite). The equality compare against a
            // non-empty TEXT ? handles missing-key rows correctly
            // (NULL = '...' is NULL, filtered out).
            let mut stmt = guard
                .prepare(
                    "SELECT entry_id, sequence_number, tenant_id, actor_id, \
                            action_type, subject_kind, subject_id, payload, \
                            prev_hash, entry_hash, recorded_at, signature \
                     FROM cirislens_audit_log \
                     WHERE tenant_id = ?1 \
                       AND json_extract(payload, '$.correlation_id') = ?2 \
                       AND (?3 IS NULL OR recorded_at >= ?3) \
                       AND (?4 IS NULL OR recorded_at <= ?4) \
                     ORDER BY recorded_at DESC, sequence_number DESC \
                     LIMIT ?5",
                )
                .map_err(|e| map_sqlite_error(e, "query_by_correlation_id prepare"))?;
            let rows_iter = stmt
                .query_map(
                    params![tenant_id, correlation_id, start, end, limit],
                    |row| Ok(decode_entry_row(row)),
                )
                .map_err(|e| map_sqlite_error(e, "query_by_correlation_id query"))?;
            let mut items = Vec::new();
            for r in rows_iter {
                items.push(r.map_err(|e| map_sqlite_error(e, "query_by_correlation_id row"))??);
            }
            Ok(items)
        })
        .await
        .map_err(|e| Error::Backend(format!("spawn_blocking join: {e}")))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::verify::truncate_to_micros;
    use crate::store::sqlite::SqliteBackend;
    use crate::store::Backend;
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    use ed25519_dalek::{Signer as _, SigningKey};
    use uuid::Uuid;

    async fn fresh_backend() -> (SqliteBackend, SqliteAuditBackend) {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        let audit = SqliteAuditBackend::new(backend.conn_handle());
        (backend, audit)
    }

    fn pubkey_b64(key: &SigningKey) -> String {
        B64.encode(key.verifying_key().to_bytes())
    }

    fn build_and_sign(
        key: &SigningKey,
        tenant_id: &str,
        sequence_number: i64,
        prev_hash: Vec<u8>,
        action_type: &str,
    ) -> AuditEntry {
        let mut entry = AuditEntry {
            entry_id: Uuid::new_v4().to_string(),
            sequence_number,
            tenant_id: tenant_id.to_owned(),
            actor_id: pubkey_b64(key),
            action_type: action_type.to_owned(),
            subject_kind: "task".into(),
            subject_id: format!("subj-{sequence_number}"),
            payload: serde_json::json!({"seq": sequence_number}),
            prev_hash,
            entry_hash: vec![],
            recorded_at: truncate_to_micros(chrono::Utc::now()),
            signature: String::new(),
        };
        let hash = compute_entry_hash(&entry).unwrap();
        entry.entry_hash = hash.to_vec();
        let canonical = crate::audit::verify::canonical_bytes_for_entry(&entry).unwrap();
        let sig = key.sign(&canonical);
        entry.signature = B64.encode(sig.to_bytes());
        entry
    }

    /// v0.8.5 SQLite parity: same lifecycle as the v0.8.1 Postgres
    /// audit test, run against in-memory SQLite.
    #[tokio::test]
    async fn cirisaudit_sqlite_round_trip_full_lifecycle() {
        let (_b, audit) = fresh_backend().await;

        let key = SigningKey::from_bytes(&[0xA1; 32]);
        let tenant = format!("audit-test-{}", Uuid::new_v4().simple());

        // 1. Genesis insert.
        let e1 = build_and_sign(&key, &tenant, 1, GENESIS_PREV_HASH.to_vec(), "task_signed");
        audit.record_entry(e1.clone()).await.unwrap();

        // 2. Replay → rejected (ChainIntegrity OR Conflict).
        let replay = audit.record_entry(e1.clone()).await.unwrap_err();
        assert!(
            matches!(replay, Error::ChainIntegrity(_) | Error::Conflict(_)),
            "expected ChainIntegrity or Conflict on replay, got {replay:?}"
        );

        // 3. Sequence gap.
        let bad_gap = build_and_sign(&key, &tenant, 3, e1.entry_hash.clone(), "task_signed");
        let gap_err = audit.record_entry(bad_gap).await.unwrap_err();
        assert!(matches!(gap_err, Error::ChainIntegrity(_)));

        // 4. Wrong prev_hash.
        let bad_prev = build_and_sign(&key, &tenant, 2, vec![0xff; 32], "task_signed");
        let prev_err = audit.record_entry(bad_prev).await.unwrap_err();
        assert!(matches!(prev_err, Error::ChainIntegrity(_)));

        // 5. Correct continuation.
        let e2 = build_and_sign(&key, &tenant, 2, e1.entry_hash.clone(), "config_changed");
        audit.record_entry(e2.clone()).await.unwrap();
        let e3 = build_and_sign(&key, &tenant, 3, e2.entry_hash.clone(), "task_signed");
        audit.record_entry(e3.clone()).await.unwrap();

        // 6. verify_chain → Ok.
        let verif = audit.verify_chain(&tenant, 1, None).await.unwrap();
        assert_eq!(verif.entries_walked, 3);
        assert_eq!(verif.outcome, ChainVerifyOutcome::Ok);

        // 7. list_entries tenant-scoped.
        let page = audit
            .list_entries(
                AuditFilter {
                    tenant_id: tenant.clone(),
                    action_type: None,
                    actor_id: None,
                    subject_kind: None,
                    subject_id: None,
                    recorded_after: None,
                    recorded_before: None,
                },
                None,
                100,
            )
            .await
            .unwrap();
        assert_eq!(page.items.len(), 3);

        // 8. AV-51 cross-tenant empty.
        let other = audit
            .list_entries(
                AuditFilter {
                    tenant_id: format!("other-tenant-{}", Uuid::new_v4().simple()),
                    action_type: None,
                    actor_id: None,
                    subject_kind: None,
                    subject_id: None,
                    recorded_after: None,
                    recorded_before: None,
                },
                None,
                100,
            )
            .await
            .unwrap();
        assert!(other.items.is_empty());

        // 9. AV-51 empty tenant rejects.
        let no_tenant = audit
            .list_entries(
                AuditFilter {
                    tenant_id: String::new(),
                    action_type: None,
                    actor_id: None,
                    subject_kind: None,
                    subject_id: None,
                    recorded_after: None,
                    recorded_before: None,
                },
                None,
                100,
            )
            .await
            .unwrap_err();
        assert!(matches!(no_tenant, Error::InvalidArgument(_)));

        // 10. Tamper: directly UPDATE a payload, verify_chain surfaces
        //     EntryHashMismatch.
        let conn = _b.conn_handle();
        let guard = conn.lock().await;
        guard
            .execute(
                "UPDATE cirislens_audit_log SET payload = ?1 \
                 WHERE tenant_id = ?2 AND sequence_number = 2",
                params![
                    serde_json::to_string(&serde_json::json!({"TAMPERED": true})).unwrap(),
                    &tenant,
                ],
            )
            .unwrap();
        drop(guard);
        let tampered = audit.verify_chain(&tenant, 1, None).await.unwrap();
        match tampered.outcome {
            ChainVerifyOutcome::Break {
                at_sequence,
                reason,
                ..
            } => {
                assert_eq!(at_sequence, 2);
                assert_eq!(reason, ChainBreakReason::EntryHashMismatch);
            }
            other => panic!("expected Break, got {other:?}"),
        }
    }

    /// v1.0.0 (CIRISAgent#756 #2): two concurrent `try_claim_event`
    /// calls with the same content_hash resolve to one `Stored` +
    /// one `AlreadyClaimed` carrying the same `AuditEventRef`, with
    /// exactly one row landing in the table.
    #[tokio::test]
    async fn try_claim_event_race_dedups_to_one_row() {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        let conn_handle = backend.conn_handle();

        let a = std::sync::Arc::new(SqliteAuditBackend::new(conn_handle.clone()));
        let b = std::sync::Arc::new(SqliteAuditBackend::new(conn_handle.clone()));

        let key = SigningKey::from_bytes(&[0xC3; 32]);
        let tenant = format!("audit-race-{}", Uuid::new_v4().simple());

        // Both callers must build IDENTICAL signed entries — the
        // first writer's seq + prev_hash + entry_hash + signature
        // are what will appear in the row regardless of who wins
        // the race. The agent's pattern is: deterministic envelope
        // canonicalization → same hash → same entry_id and
        // signature on both sides.
        let entry = build_and_sign(&key, &tenant, 1, GENESIS_PREV_HASH.to_vec(), "task_signed");
        // content_hash is caller-computed (sha256 of canonical
        // envelope bytes). For this test we just hash a stable
        // string — the value doesn't matter beyond being identical
        // on both sides.
        let content_hash: [u8; 32] = {
            use sha2::Digest as _;
            let mut h = sha2::Sha256::new();
            h.update(b"shared-envelope-bytes");
            h.finalize().into()
        };

        let entry_a = entry.clone();
        let entry_b = entry.clone();
        let a2 = a.clone();
        let b2 = b.clone();
        let fut_a = async move {
            a2.try_claim_event(content_hash, entry_a, "worker-a".into())
                .await
        };
        let fut_b = async move {
            b2.try_claim_event(content_hash, entry_b, "worker-b".into())
                .await
        };

        let (r_a, r_b) = tokio::join!(fut_a, fut_b);
        let r_a = r_a.expect("a try_claim_event");
        let r_b = r_b.expect("b try_claim_event");

        let stored_count = [&r_a, &r_b]
            .iter()
            .filter(|r| matches!(r, ClaimResult::Stored(_)))
            .count();
        let claimed_count = [&r_a, &r_b]
            .iter()
            .filter(|r| matches!(r, ClaimResult::AlreadyClaimed(_)))
            .count();
        assert_eq!(stored_count, 1, "exactly one Stored expected");
        assert_eq!(claimed_count, 1, "exactly one AlreadyClaimed expected");
        assert_eq!(
            r_a.reference().entry_id,
            r_b.reference().entry_id,
            "both outcomes must reference the same row"
        );
        assert_eq!(r_a.reference().sequence_number, 1);
        assert_eq!(r_a.reference().tenant_id, tenant);

        // List back: exactly one entry for the tenant.
        let page = a
            .list_entries(
                AuditFilter {
                    tenant_id: tenant.clone(),
                    action_type: None,
                    actor_id: None,
                    subject_kind: None,
                    subject_id: None,
                    recorded_after: None,
                    recorded_before: None,
                },
                None,
                100,
            )
            .await
            .unwrap();
        assert_eq!(page.items.len(), 1, "exactly one audit row expected");
    }

    /// Build + sign an entry that carries a `correlation_id` in its
    /// payload, used by the v1.0.0 query_by_correlation_id tests
    /// (CIRISAgent#756 Q4 — graph-node side collapse into persist).
    fn build_with_correlation(
        key: &SigningKey,
        tenant_id: &str,
        sequence_number: i64,
        prev_hash: Vec<u8>,
        correlation_id: &str,
    ) -> AuditEntry {
        let mut entry = AuditEntry {
            entry_id: Uuid::new_v4().to_string(),
            sequence_number,
            tenant_id: tenant_id.to_owned(),
            actor_id: pubkey_b64(key),
            action_type: "task_signed".into(),
            subject_kind: "task".into(),
            subject_id: format!("subj-{sequence_number}"),
            payload: serde_json::json!({"correlation_id": correlation_id}),
            prev_hash,
            entry_hash: vec![],
            recorded_at: truncate_to_micros(chrono::Utc::now()),
            signature: String::new(),
        };
        let hash = compute_entry_hash(&entry).unwrap();
        entry.entry_hash = hash.to_vec();
        let canonical = crate::audit::verify::canonical_bytes_for_entry(&entry).unwrap();
        let sig = key.sign(&canonical);
        entry.signature = B64.encode(sig.to_bytes());
        entry
    }

    /// v1.0.0 (CIRISAgent#756 Q4): `query_by_correlation_id` returns
    /// only entries whose payload carries the matching correlation_id,
    /// newest-first, tenant-scoped.
    #[tokio::test]
    async fn query_by_correlation_id() {
        let (_b, audit) = fresh_backend().await;
        let key = SigningKey::from_bytes(&[0xD4; 32]);
        let tenant = format!("audit-corr-{}", Uuid::new_v4().simple());

        // 3 entries on the same chain: corr-A, corr-A, corr-B.
        let e1 = build_with_correlation(&key, &tenant, 1, GENESIS_PREV_HASH.to_vec(), "corr-A");
        audit.record_entry(e1.clone()).await.unwrap();
        // Force monotonic recorded_at ordering for the newest-first
        // assertion (in-memory SQLite + microsecond truncation can
        // collapse Utc::now() across rapid calls).
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        let e2 = build_with_correlation(&key, &tenant, 2, e1.entry_hash.clone(), "corr-B");
        audit.record_entry(e2.clone()).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        let e3 = build_with_correlation(&key, &tenant, 3, e2.entry_hash.clone(), "corr-A");
        audit.record_entry(e3.clone()).await.unwrap();

        // Query corr-A → 2 entries, newest-first (e3 then e1).
        let hits = audit
            .query_by_correlation_id(&tenant, "corr-A", CorrelationQuery::default())
            .await
            .unwrap();
        assert_eq!(hits.len(), 2, "expected 2 corr-A entries");
        assert_eq!(hits[0].entry_id, e3.entry_id, "newest-first ordering");
        assert_eq!(hits[1].entry_id, e1.entry_id);
        for h in &hits {
            assert_eq!(
                h.payload.get("correlation_id").and_then(|v| v.as_str()),
                Some("corr-A")
            );
        }

        // Query corr-B → 1 entry.
        let hits_b = audit
            .query_by_correlation_id(&tenant, "corr-B", CorrelationQuery::default())
            .await
            .unwrap();
        assert_eq!(hits_b.len(), 1);
        assert_eq!(hits_b[0].entry_id, e2.entry_id);

        // Empty correlation_id → empty Vec (defined no-op).
        let empty = audit
            .query_by_correlation_id(&tenant, "", CorrelationQuery::default())
            .await
            .unwrap();
        assert!(empty.is_empty());

        // Cross-tenant mismatch → empty Vec (AV-51).
        let other_tenant = format!("other-tenant-{}", Uuid::new_v4().simple());
        let cross = audit
            .query_by_correlation_id(&other_tenant, "corr-A", CorrelationQuery::default())
            .await
            .unwrap();
        assert!(cross.is_empty());

        // Empty tenant_id rejects.
        let no_tenant = audit
            .query_by_correlation_id("", "corr-A", CorrelationQuery::default())
            .await
            .unwrap_err();
        assert!(matches!(no_tenant, Error::InvalidArgument(_)));
    }
}
