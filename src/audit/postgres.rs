//! PostgreSQL impl of [`AuditService`] (v0.8.1, CIRISPersist#35).
//!
//! Per-tenant transactional INSERT: read the current tail under
//! `SELECT ... FOR UPDATE`, validate prev_hash + sequence_number +
//! entry_hash + signature, INSERT. The transaction's
//! row-level lock on the previous tail row serializes concurrent
//! writers within one tenant; the `UNIQUE (tenant_id,
//! sequence_number)` constraint is the secondary gate.

use super::service::AuditService;
use super::types::{
    AuditCursor, AuditEntry, AuditEventRef, AuditFilter, AuditListPage, ChainBreakReason,
    ChainVerification, ChainVerifyOutcome,
};
use super::verify::{compute_entry_hash, verify_entry_signature};
use super::{Error, GENESIS_PREV_HASH};
use crate::store::postgres::PostgresBackend;
use crate::ClaimResult;

fn map_pg_error(e: tokio_postgres::Error, op: &str) -> Error {
    use tokio_postgres::error::SqlState;
    let code = e.as_db_error().map(|d| d.code().clone());
    let detail = e
        .as_db_error()
        .map(|d| d.message().to_owned())
        .unwrap_or_else(|| e.to_string());
    match code {
        Some(c) if c == SqlState::UNIQUE_VIOLATION => Error::Conflict(format!("{op}: {detail}")),
        Some(c) if c == SqlState::CHECK_VIOLATION => {
            Error::InvalidArgument(format!("{op} CHECK: {detail}"))
        }
        _ => Error::Backend(format!("{op}: {detail}")),
    }
}

fn parse_entry_id(s: &str) -> Result<uuid::Uuid, Error> {
    uuid::Uuid::parse_str(s).map_err(|e| Error::InvalidArgument(format!("entry_id parse: {e}")))
}

fn decode_entry_row(row: &tokio_postgres::Row) -> Result<AuditEntry, Error> {
    let entry_uuid: uuid::Uuid = row
        .try_get("entry_id")
        .map_err(|e| Error::Backend(format!("decode entry_id: {e}")))?;
    Ok(AuditEntry {
        entry_id: entry_uuid.to_string(),
        sequence_number: row
            .try_get("sequence_number")
            .map_err(|e| Error::Backend(format!("decode seq: {e}")))?,
        tenant_id: row
            .try_get("tenant_id")
            .map_err(|e| Error::Backend(format!("decode tenant_id: {e}")))?,
        actor_id: row
            .try_get("actor_id")
            .map_err(|e| Error::Backend(format!("decode actor_id: {e}")))?,
        action_type: row
            .try_get("action_type")
            .map_err(|e| Error::Backend(format!("decode action_type: {e}")))?,
        subject_kind: row
            .try_get("subject_kind")
            .map_err(|e| Error::Backend(format!("decode subject_kind: {e}")))?,
        subject_id: row
            .try_get("subject_id")
            .map_err(|e| Error::Backend(format!("decode subject_id: {e}")))?,
        payload: row
            .try_get("payload")
            .map_err(|e| Error::Backend(format!("decode payload: {e}")))?,
        prev_hash: row
            .try_get("prev_hash")
            .map_err(|e| Error::Backend(format!("decode prev_hash: {e}")))?,
        entry_hash: row
            .try_get("entry_hash")
            .map_err(|e| Error::Backend(format!("decode entry_hash: {e}")))?,
        recorded_at: row
            .try_get("recorded_at")
            .map_err(|e| Error::Backend(format!("decode recorded_at: {e}")))?,
        signature: row
            .try_get("signature")
            .map_err(|e| Error::Backend(format!("decode signature: {e}")))?,
    })
}

impl AuditService for PostgresBackend {
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

        // AV-49: re-derive entry_hash from canonical bytes. Caller-
        // claimed value MUST match — protects against a writer that
        // tampers with payload but forgets to update entry_hash.
        let derived = compute_entry_hash(&entry)?;
        if derived.as_slice() != entry.entry_hash.as_slice() {
            return Err(Error::ChainIntegrity(
                "entry_hash mismatch: caller-claimed differs from canonical-bytes derivation"
                    .into(),
            ));
        }

        // Signature verify (self-signed; actor_id IS the pubkey).
        verify_entry_signature(&entry)?;

        let entry_uuid = parse_entry_id(&entry.entry_id)?;

        let mut client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        let tx = client
            .transaction()
            .await
            .map_err(|e| Error::Backend(format!("begin tx: {e}")))?;

        // Read the current tail row for this tenant under FOR UPDATE
        // so concurrent writers serialize. (For tenant-first-entry
        // there is no tail row; the FOR UPDATE is a no-op.)
        let tail = tx
            .query_opt(
                "SELECT sequence_number, entry_hash \
                 FROM cirislens.audit_log \
                 WHERE tenant_id = $1 \
                 ORDER BY sequence_number DESC \
                 LIMIT 1 \
                 FOR UPDATE",
                &[&entry.tenant_id],
            )
            .await
            .map_err(|e| map_pg_error(e, "record_entry tail read"))?;

        if let Some(row) = tail {
            // Existing tenant — validate continuity + prev_hash chain.
            let prev_seq: i64 = row
                .try_get("sequence_number")
                .map_err(|e| Error::Backend(format!("decode prev seq: {e}")))?;
            let prev_hash: Vec<u8> = row
                .try_get("entry_hash")
                .map_err(|e| Error::Backend(format!("decode prev hash: {e}")))?;
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
            // New tenant chain — must be genesis (sequence_number=1
            // + prev_hash=zeros).
            if entry.sequence_number != 1 {
                return Err(Error::ChainIntegrity(format!(
                    "first entry for tenant {} must have sequence_number=1, got {}",
                    entry.tenant_id, entry.sequence_number
                )));
            }
            if entry.prev_hash.as_slice() != GENESIS_PREV_HASH.as_slice() {
                return Err(Error::ChainIntegrity(
                    "first entry must have prev_hash = GENESIS_PREV_HASH (32 zero bytes)".into(),
                ));
            }
        }

        // All gates passed — INSERT with signature_verified=TRUE.
        tx.execute(
            "INSERT INTO cirislens.audit_log (\
                entry_id, sequence_number, tenant_id, actor_id, \
                action_type, subject_kind, subject_id, payload, \
                prev_hash, entry_hash, recorded_at, \
                signature, signing_key_id, signature_verified, persist_row_hash\
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, TRUE, $14)",
            &[
                &entry_uuid,
                &entry.sequence_number,
                &entry.tenant_id,
                &entry.actor_id,
                &entry.action_type,
                &entry.subject_kind,
                &entry.subject_id,
                &entry.payload,
                &entry.prev_hash,
                &entry.entry_hash,
                &entry.recorded_at,
                &entry.signature,
                &entry.actor_id,  // signing_key_id = actor_id (self-signed)
                &entry.signature, // persist_row_hash placeholder
            ],
        )
        .await
        .map_err(|e| map_pg_error(e, "record_entry insert"))?;

        tx.commit()
            .await
            .map_err(|e| Error::Backend(format!("commit: {e}")))?;
        Ok(())
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

        let mut where_parts: Vec<String> = vec!["tenant_id = $1".to_string()];
        let mut params: Vec<Box<dyn tokio_postgres::types::ToSql + Sync + Send>> =
            vec![Box::new(filter.tenant_id)];
        if let Some(at) = filter.action_type {
            params.push(Box::new(at));
            where_parts.push(format!("action_type = ${}", params.len()));
        }
        if let Some(aid) = filter.actor_id {
            params.push(Box::new(aid));
            where_parts.push(format!("actor_id = ${}", params.len()));
        }
        if let Some(sk) = filter.subject_kind {
            params.push(Box::new(sk));
            where_parts.push(format!("subject_kind = ${}", params.len()));
        }
        if let Some(sid) = filter.subject_id {
            params.push(Box::new(sid));
            where_parts.push(format!("subject_id = ${}", params.len()));
        }
        if let Some(after) = filter.recorded_after {
            params.push(Box::new(after));
            where_parts.push(format!("recorded_at >= ${}", params.len()));
        }
        if let Some(before) = filter.recorded_before {
            params.push(Box::new(before));
            where_parts.push(format!("recorded_at <= ${}", params.len()));
        }
        if let Some(cur) = &cursor {
            if cur.version != "v1" {
                return Err(Error::InvalidArgument(format!(
                    "AuditCursor version {} unsupported (expected v1)",
                    cur.version
                )));
            }
            let last_uuid = parse_entry_id(&cur.last_id)?;
            params.push(Box::new(cur.last_ts));
            let p_ts = params.len();
            params.push(Box::new(last_uuid));
            let p_id = params.len();
            where_parts.push(format!("(recorded_at, entry_id) < (${p_ts}, ${p_id})"));
        }
        params.push(Box::new(limit));
        let p_limit = params.len();
        let where_sql = where_parts.join(" AND ");
        let sql = format!(
            "SELECT entry_id, sequence_number, tenant_id, actor_id, \
                    action_type, subject_kind, subject_id, payload, \
                    prev_hash, entry_hash, recorded_at, signature \
             FROM cirislens.audit_log \
             WHERE {where_sql} \
             ORDER BY recorded_at DESC, entry_id DESC \
             LIMIT ${p_limit}"
        );

        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        let params_ref: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> =
            params.iter().map(|p| p.as_ref() as _).collect();
        let rows = client
            .query(&sql, &params_ref[..])
            .await
            .map_err(|e| map_pg_error(e, "list_entries"))?;

        let mut items: Vec<AuditEntry> = Vec::with_capacity(rows.len());
        for row in &rows {
            items.push(decode_entry_row(row)?);
        }
        let next_cursor = if items.len() == limit as usize {
            items
                .last()
                .map(|last| AuditCursor::from_trailing(last.recorded_at, last.entry_id.clone()))
        } else {
            None
        };
        Ok(AuditListPage { items, next_cursor })
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

        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;

        let to_seq_resolved: i64 = match to_sequence {
            Some(n) => {
                if n < from_sequence {
                    return Err(Error::InvalidArgument(format!(
                        "to_sequence ({n}) < from_sequence ({from_sequence})"
                    )));
                }
                n
            }
            None => client
                .query_one(
                    "SELECT COALESCE(MAX(sequence_number), 0) AS tail \
                     FROM cirislens.audit_log WHERE tenant_id = $1",
                    &[&tenant_id],
                )
                .await
                .map_err(|e| map_pg_error(e, "verify_chain tail probe"))?
                .try_get::<_, i64>("tail")
                .map_err(|e| Error::Backend(format!("decode tail: {e}")))?,
        };

        if to_seq_resolved < from_sequence {
            // Empty chain.
            return Ok(ChainVerification {
                tenant_id: tenant_id.to_owned(),
                from_sequence,
                to_sequence: to_seq_resolved,
                entries_walked: 0,
                outcome: ChainVerifyOutcome::Ok,
            });
        }

        let rows = client
            .query(
                "SELECT entry_id, sequence_number, tenant_id, actor_id, \
                        action_type, subject_kind, subject_id, payload, \
                        prev_hash, entry_hash, recorded_at, signature \
                 FROM cirislens.audit_log \
                 WHERE tenant_id = $1 \
                   AND sequence_number BETWEEN $2 AND $3 \
                 ORDER BY sequence_number ASC",
                &[&tenant_id, &from_sequence, &to_seq_resolved],
            )
            .await
            .map_err(|e| map_pg_error(e, "verify_chain scan"))?;

        let mut prior_hash: Option<Vec<u8>> = None;
        let mut prior_seq: Option<i64> = None;
        let mut walked = 0usize;
        for row in &rows {
            let entry = decode_entry_row(row)?;
            walked += 1;

            // Sequence continuity check.
            match prior_seq {
                None => {
                    // First row of the walk. If from_sequence == 1
                    // it must be genesis (prev_hash=zeros). Otherwise
                    // we can't check the chain backwards from this
                    // starting point — caller knows.
                    if entry.sequence_number == 1
                        && entry.prev_hash.as_slice() != GENESIS_PREV_HASH.as_slice()
                    {
                        return Ok(ChainVerification {
                            tenant_id: tenant_id.to_owned(),
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
                            tenant_id: tenant_id.to_owned(),
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
                                tenant_id: tenant_id.to_owned(),
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

            // Re-derive entry_hash.
            let derived = compute_entry_hash(&entry)?;
            if derived.as_slice() != entry.entry_hash.as_slice() {
                return Ok(ChainVerification {
                    tenant_id: tenant_id.to_owned(),
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

            // Signature verify.
            if let Err(e) = verify_entry_signature(&entry) {
                return Ok(ChainVerification {
                    tenant_id: tenant_id.to_owned(),
                    from_sequence,
                    to_sequence: to_seq_resolved,
                    entries_walked: walked,
                    outcome: ChainVerifyOutcome::Break {
                        at_sequence: entry.sequence_number,
                        reason: ChainBreakReason::SignatureFailure,
                        detail: format!("signature failed at seq {}: {e}", entry.sequence_number),
                    },
                });
            }

            prior_hash = Some(entry.entry_hash.clone());
            prior_seq = Some(entry.sequence_number);
        }

        Ok(ChainVerification {
            tenant_id: tenant_id.to_owned(),
            from_sequence,
            to_sequence: to_seq_resolved,
            entries_walked: walked,
            outcome: ChainVerifyOutcome::Ok,
        })
    }

    async fn try_claim_event(
        &self,
        content_hash: [u8; 32],
        entry: AuditEntry,
        accessor: String,
    ) -> Result<ClaimResult<AuditEventRef>, Error> {
        // accessor surfaces into tracing only — actor_id is the
        // cryptographic identity (self-signed model).
        let _ = accessor;

        // Same input gates as record_entry. The first-write path is
        // identical to record_entry; the conflict path short-
        // circuits the chain checks because the EXISTING row was
        // already chain-verified at insert time.
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

        let entry_uuid = parse_entry_id(&entry.entry_id)?;
        let content_hash_vec = content_hash.to_vec();

        let mut client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;

        // Fast path: optimistic claim outside of a transaction.
        // PG ON CONFLICT (content_hash) DO NOTHING gives us the
        // atomic insert-or-skip we need; the conflict path falls
        // through to a SELECT below.
        //
        // On clean insert we still need chain-integrity gates. We
        // do those inside a transaction with FOR UPDATE on the
        // tail; if the gates fail, we ROLLBACK.
        let tx = client
            .transaction()
            .await
            .map_err(|e| Error::Backend(format!("begin tx: {e}")))?;

        // First, check if a row with this content_hash already
        // exists — that's the cheap "already-claimed" path. We do
        // this under the transaction so the result is consistent
        // with the subsequent INSERT attempt.
        let existing = tx
            .query_opt(
                "SELECT entry_id, tenant_id, sequence_number \
                 FROM cirislens.audit_log \
                 WHERE content_hash = $1",
                &[&content_hash_vec],
            )
            .await
            .map_err(|e| map_pg_error(e, "try_claim_event lookup"))?;

        if let Some(row) = existing {
            let existing_uuid: uuid::Uuid = row
                .try_get("entry_id")
                .map_err(|e| Error::Backend(format!("decode entry_id: {e}")))?;
            let reference = AuditEventRef {
                entry_id: existing_uuid.to_string(),
                tenant_id: row
                    .try_get("tenant_id")
                    .map_err(|e| Error::Backend(format!("decode tenant_id: {e}")))?,
                sequence_number: row
                    .try_get("sequence_number")
                    .map_err(|e| Error::Backend(format!("decode seq: {e}")))?,
            };
            tx.commit()
                .await
                .map_err(|e| Error::Backend(format!("commit: {e}")))?;
            return Ok(ClaimResult::AlreadyClaimed(reference));
        }

        // No prior claim — run the same chain gates as record_entry
        // before INSERTing. Tail-read under FOR UPDATE serializes
        // concurrent writers within one tenant.
        let tail = tx
            .query_opt(
                "SELECT sequence_number, entry_hash \
                 FROM cirislens.audit_log \
                 WHERE tenant_id = $1 \
                 ORDER BY sequence_number DESC \
                 LIMIT 1 \
                 FOR UPDATE",
                &[&entry.tenant_id],
            )
            .await
            .map_err(|e| map_pg_error(e, "try_claim_event tail read"))?;

        if let Some(row) = tail {
            let prev_seq: i64 = row
                .try_get("sequence_number")
                .map_err(|e| Error::Backend(format!("decode prev seq: {e}")))?;
            let prev_hash: Vec<u8> = row
                .try_get("entry_hash")
                .map_err(|e| Error::Backend(format!("decode prev hash: {e}")))?;
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
                    "first entry must have prev_hash = GENESIS_PREV_HASH (32 zero bytes)".into(),
                ));
            }
        }

        // Atomic insert. Between the lookup above and this INSERT
        // another transaction could have committed the same
        // content_hash — ON CONFLICT DO NOTHING handles that
        // gracefully (the SELECT below recovers the reference).
        let inserted = tx
            .query_opt(
                "INSERT INTO cirislens.audit_log (\
                    entry_id, sequence_number, tenant_id, actor_id, \
                    action_type, subject_kind, subject_id, payload, \
                    prev_hash, entry_hash, recorded_at, \
                    signature, signing_key_id, signature_verified, persist_row_hash, \
                    content_hash\
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, TRUE, $14, $15) \
                 ON CONFLICT (content_hash) DO NOTHING \
                 RETURNING entry_id, tenant_id, sequence_number",
                &[
                    &entry_uuid,
                    &entry.sequence_number,
                    &entry.tenant_id,
                    &entry.actor_id,
                    &entry.action_type,
                    &entry.subject_kind,
                    &entry.subject_id,
                    &entry.payload,
                    &entry.prev_hash,
                    &entry.entry_hash,
                    &entry.recorded_at,
                    &entry.signature,
                    &entry.actor_id,
                    &entry.signature,
                    &content_hash_vec,
                ],
            )
            .await
            .map_err(|e| map_pg_error(e, "try_claim_event insert"))?;

        let result = if let Some(row) = inserted {
            let returned_uuid: uuid::Uuid = row
                .try_get("entry_id")
                .map_err(|e| Error::Backend(format!("decode entry_id: {e}")))?;
            ClaimResult::Stored(AuditEventRef {
                entry_id: returned_uuid.to_string(),
                tenant_id: row
                    .try_get("tenant_id")
                    .map_err(|e| Error::Backend(format!("decode tenant_id: {e}")))?,
                sequence_number: row
                    .try_get("sequence_number")
                    .map_err(|e| Error::Backend(format!("decode seq: {e}")))?,
            })
        } else {
            // Race-loss: another tx committed the same content_hash
            // between our SELECT and INSERT. Recover the existing
            // reference via a second SELECT.
            let row = tx
                .query_one(
                    "SELECT entry_id, tenant_id, sequence_number \
                     FROM cirislens.audit_log \
                     WHERE content_hash = $1",
                    &[&content_hash_vec],
                )
                .await
                .map_err(|e| map_pg_error(e, "try_claim_event conflict-recovery"))?;
            let returned_uuid: uuid::Uuid = row
                .try_get("entry_id")
                .map_err(|e| Error::Backend(format!("decode entry_id: {e}")))?;
            ClaimResult::AlreadyClaimed(AuditEventRef {
                entry_id: returned_uuid.to_string(),
                tenant_id: row
                    .try_get("tenant_id")
                    .map_err(|e| Error::Backend(format!("decode tenant_id: {e}")))?,
                sequence_number: row
                    .try_get("sequence_number")
                    .map_err(|e| Error::Backend(format!("decode seq: {e}")))?,
            })
        };

        tx.commit()
            .await
            .map_err(|e| Error::Backend(format!("commit: {e}")))?;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    use chrono::Utc;
    use ed25519_dalek::{Signer as _, SigningKey};
    use uuid::Uuid;

    fn pg_dsn() -> Option<String> {
        std::env::var("CIRIS_PERSIST_TEST_PG_URL").ok()
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
            // Truncate to microseconds — Postgres TIMESTAMPTZ
            // precision; ensures pre/post-storage canonical bytes
            // agree (see verify::truncate_to_micros docs).
            recorded_at: super::super::verify::truncate_to_micros(Utc::now()),
            signature: String::new(),
        };
        let hash = compute_entry_hash(&entry).unwrap();
        entry.entry_hash = hash.to_vec();
        let canonical = super::super::verify::canonical_bytes_for_entry(&entry).unwrap();
        let sig = key.sign(&canonical);
        entry.signature = B64.encode(sig.to_bytes());
        entry
    }

    /// v0.8.1 (CIRISPersist#35) — end-to-end audit log lifecycle:
    /// genesis insert, chain extend, verify_chain Ok, replay
    /// rejection, chain-fork rejection, tenant isolation, verify
    /// surfaces a tampered chain.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn audit_round_trip_full_lifecycle() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let key = SigningKey::from_bytes(&[0xA1; 32]);
        let tenant = format!("audit-test-{}", Uuid::new_v4().simple());

        // 1. Genesis insert (seq=1, prev_hash=zeros).
        let e1 = build_and_sign(&key, &tenant, 1, GENESIS_PREV_HASH.to_vec(), "task_signed");
        backend.record_entry(e1.clone()).await.unwrap();

        // 2. Replay genesis → rejected. The chain-integrity gate
        // fires first (tail's sequence_number=1, so re-submitting
        // seq=1 trips the "expected 2 got 1" check before reaching
        // the UNIQUE constraint). Either rejection variant is
        // correct — both prevent the replay from landing.
        let replay = backend.record_entry(e1.clone()).await.unwrap_err();
        assert!(
            matches!(replay, Error::ChainIntegrity(_) | Error::Conflict(_)),
            "expected ChainIntegrity or Conflict on replay, got {replay:?}"
        );

        // 3. Sequence gap → ChainIntegrity (try seq=3 with prev=e1.entry_hash).
        let bad_gap = build_and_sign(&key, &tenant, 3, e1.entry_hash.clone(), "task_signed");
        let gap_err = backend.record_entry(bad_gap).await.unwrap_err();
        assert!(
            matches!(gap_err, Error::ChainIntegrity(_)),
            "expected ChainIntegrity on gap, got {gap_err:?}"
        );

        // 4. Wrong prev_hash → ChainIntegrity (seq=2 with wrong prev).
        let bad_prev = build_and_sign(&key, &tenant, 2, vec![0xff; 32], "task_signed");
        let prev_err = backend.record_entry(bad_prev).await.unwrap_err();
        assert!(
            matches!(prev_err, Error::ChainIntegrity(_)),
            "expected ChainIntegrity on bad prev_hash, got {prev_err:?}"
        );

        // 5. Correct continuation: seq=2 with prev = e1.entry_hash.
        let e2 = build_and_sign(&key, &tenant, 2, e1.entry_hash.clone(), "config_changed");
        backend.record_entry(e2.clone()).await.unwrap();

        // 6. Extend to seq=3.
        let e3 = build_and_sign(&key, &tenant, 3, e2.entry_hash.clone(), "task_signed");
        backend.record_entry(e3.clone()).await.unwrap();

        // 7. verify_chain over full range → Ok.
        let verif = backend.verify_chain(&tenant, 1, None).await.unwrap();
        assert_eq!(verif.entries_walked, 3);
        assert_eq!(verif.outcome, ChainVerifyOutcome::Ok);

        // 8. list_entries scoped to tenant.
        let page = backend
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

        // 9. AV-51 tenant isolation — list under different tenant
        // returns empty (NOT entries from this tenant).
        let other_tenant_page = backend
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
        assert!(other_tenant_page.items.is_empty());

        // 10. AV-51 — empty tenant_id filter rejects.
        let no_tenant = backend
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

        // 11. Tamper detection: directly UPDATE a payload, then
        // verify_chain surfaces an EntryHashMismatch break.
        let client = backend.pool().get().await.unwrap();
        client
            .execute(
                "UPDATE cirislens.audit_log SET payload = $1 \
                 WHERE tenant_id = $2 AND sequence_number = 2",
                &[&serde_json::json!({"TAMPERED": true}), &tenant],
            )
            .await
            .unwrap();
        let tampered = backend.verify_chain(&tenant, 1, None).await.unwrap();
        match tampered.outcome {
            ChainVerifyOutcome::Break {
                at_sequence,
                reason,
                ..
            } => {
                assert_eq!(at_sequence, 2);
                assert_eq!(reason, ChainBreakReason::EntryHashMismatch);
            }
            other => panic!("expected Break on tampered entry, got {other:?}"),
        }
    }
}
