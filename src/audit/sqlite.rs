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
    AuditCursor, AuditEntry, AuditFilter, AuditListPage, ChainBreakReason, ChainVerification,
    ChainVerifyOutcome,
};
use super::verify::{compute_entry_hash, verify_entry_signature};
use super::{Error, GENESIS_PREV_HASH};

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
}
