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
    ChainVerification, ChainVerifyOutcome, CorrelationQuery, CORRELATION_QUERY_MAX_LIMIT,
};
use super::verify::{compute_entry_hash, stored_entry_instant_ms, verify_entry_signature};
use super::{Error, GENESIS_PREV_HASH};
use crate::federation::edition2::composite_verify::now_ms;
use crate::store::postgres::PostgresBackend;
use crate::ClaimResult;

use ciris_verify_core::transparency::SignedTreeHead;

use super::merkle_leaf::AuditLeaf;
use super::merkle_store::{log_id_for_tenant, PgMerkleStore};

/// v1.5.0 Phase C — Merkle transparency hook for the audit-service
/// ingest path. Called after the chain commit lands; **gated on the
/// backend's `merkle_signer` being configured** (no signer → no-op).
///
/// # Atomicity
///
/// Chain commit happens **first** in a dedicated transaction (the
/// existing AV-49 path; unchanged). The Merkle hook runs **after**
/// commit on a fresh connection.
///
/// This is option (b) from the Phase C plan: the audit chain is the
/// source of truth; the Merkle tables are a projection. A failure
/// inside this helper is surfaced as `Error::Merkle(_)` but the
/// chain row already stands committed and visible. Phase I's
/// backfill (V021 backfill task) recomputes any missed leaves +
/// re-issues STHs from the chain.
///
/// Option (a) (single transaction spanning chain + Merkle) is not
/// feasible at Phase C: `PgMerkleStore` opens its own pool
/// connection per call, and re-entering the pool while the chain tx
/// holds one connection would deadlock under pool size = 1. A real
/// single-tx implementation requires injecting the existing
/// transaction into the merkle store — out of scope for Phase C.
async fn merkle_hook_pg(
    backend: &PostgresBackend,
    entry: &AuditEntry,
    chain_event_id: i64,
) -> Result<(), Error> {
    let Some(signer) = backend.merkle_signer() else {
        // Signer not configured — no-op. Preserves the pre-Phase-C
        // behavior for CIRIS-RED deployments + tests without a
        // local identity loaded.
        return Ok(());
    };

    // v62.0.0 (P8) — the store is async end to end: append, size and root
    // are three `.await`s on tokio-postgres, in the order Verify's
    // `TransparencyLog` made them (append, tree_size, merkle_root). No
    // blocking-thread hop, no `block_on`.
    let tenant_id = entry.tenant_id.clone();
    let leaf = AuditLeaf::with_chain_event_id(entry.clone(), chain_event_id);
    let log_id = log_id_for_tenant(&tenant_id);
    let store = PgMerkleStore::from_backend(backend, tenant_id.clone());

    // 1. Append the leaf + compute tree_size + merkle_root.
    let head = async {
        let _idx = store.append(leaf).await?;
        let ts = store.tree_size().await?;
        let root = store.root().await?;
        Ok::<_, ciris_verify_core::transparency::TransparencyError>((ts, root))
    };
    let (tree_size, root_hash) = head
        .await
        .map_err(|e| Error::Merkle(format!("append: {e}")))?;

    // 2. Sign the STH: the composite (v62.0.0, CC 2.6.1.7), the only form
    //    a v62 node writes.
    let timestamp = crate::host::clock::now();
    let signing_bytes = SignedTreeHead::signing_bytes(&log_id, tree_size, &root_hash, timestamp);
    let signature = super::sth_form::sign_sth(&signer, &signing_bytes)
        .await
        .map_err(|e| Error::Merkle(format!("sign_sth: {e}")))?;

    let sth = SignedTreeHead {
        log_id,
        tree_size,
        root_hash,
        timestamp,
        signature,
        witness_signatures: Vec::new(),
    };

    // 3. Persist the STH.
    store
        .store_sth(&sth)
        .await
        .map_err(|e| Error::Merkle(format!("store_sth: {e}")))?;

    Ok(())
}

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
        // v62.0.0 (F0-cp8) — the entry's ONE composite, under its signer's
        // live edition-2 key at this node's now.
        verify_entry_signature(self, &entry, now_ms()).await?;

        let entry_uuid = parse_entry_id(&entry.entry_id)?;

        let mut client = self.checkout().await.map_err(Error::from)?;
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
            // v1.5.4 — non-zero prev_hash on sequence_number=1 is a
            // bridge entry per docs/AUDIT_CHAIN_BRIDGE.md §1. The
            // verifier (`AuditService::verify_chain`) surfaces it as
            // `ChainBreakReason::GenesisPrevHashNotZero` so downstream
            // consumers can distinguish clean genesis from bridged-
            // from-legacy chain. Write path permits + logs.
            if entry.prev_hash.as_slice() != GENESIS_PREV_HASH.as_slice() {
                tracing::info!(
                    tenant_id = %entry.tenant_id,
                    prev_hash_hex = %hex::encode(&entry.prev_hash),
                    "audit chain bridge entry — non-zero prev_hash on sequence_number=1"
                );
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
        // v59.1.2 — release the client BEFORE the hooks: the Merkle append
        // and the trust-grant projection each check out their own, and
        // holding this one across them deadlocked two concurrent writers on
        // a pool of two (a 1-vCPU node's whole pool).
        drop(client);
        #[cfg(test)]
        self.test_hooks()
            .barrier_if_armed("audit_record_entry_after_commit")
            .await;

        // v1.5.0 Phase C — Merkle transparency hook. Runs only when a
        // local signer was installed via `set_merkle_signer`;
        // otherwise this is a no-op and the audit chain semantics are
        // unchanged. `sequence_number` is reused as the
        // `chain_event_id` per FSD §4.4.
        merkle_hook_pg(self, &entry, entry.sequence_number).await?;

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
            // An empty `last_id` is the documented "no cursor yet —
            // return the first page" sentinel. Parse it as a UUID and
            // apply the keyset predicate only for a real cursor;
            // otherwise skip the predicate entirely. Matches
            // `task_list` and the SQLite arm (CIRISPersist#86).
            if !cur.last_id.is_empty() {
                let last_uuid = parse_entry_id(&cur.last_id)?;
                params.push(Box::new(cur.last_ts));
                let p_ts = params.len();
                params.push(Box::new(last_uuid));
                let p_id = params.len();
                where_parts.push(format!("(recorded_at, entry_id) < (${p_ts}, ${p_id})"));
            }
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

        let client = self.checkout().await.map_err(Error::from)?;
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

        let client = self.checkout().await.map_err(Error::from)?;

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
        // v62.0.0 (F0-cp8) — the walk verifies each entry's signature through
        // the directory, which checks out its own connection: this one goes
        // back to the pool first.
        drop(client);

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
            if let Err(e) =
                verify_entry_signature(self, &entry, stored_entry_instant_ms(&entry)).await
            {
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
        // v62.0.0 (F0-cp8) — the entry's ONE composite, under its signer's
        // live edition-2 key at this node's now.
        verify_entry_signature(self, &entry, now_ms()).await?;

        let entry_uuid = parse_entry_id(&entry.entry_id)?;
        let content_hash_vec = content_hash.to_vec();

        let mut client = self.checkout().await.map_err(Error::from)?;

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
            // v1.5.4 — non-zero prev_hash on sequence_number=1 is a
            // bridge entry per docs/AUDIT_CHAIN_BRIDGE.md §1. The
            // verifier (`AuditService::verify_chain`) surfaces it as
            // `ChainBreakReason::GenesisPrevHashNotZero` so downstream
            // consumers can distinguish clean genesis from bridged-
            // from-legacy chain. Write path permits + logs.
            if entry.prev_hash.as_slice() != GENESIS_PREV_HASH.as_slice() {
                tracing::info!(
                    tenant_id = %entry.tenant_id,
                    prev_hash_hex = %hex::encode(&entry.prev_hash),
                    "audit chain bridge entry — non-zero prev_hash on sequence_number=1"
                );
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
        // v59.1.2 — release the client before the hooks (see `record_entry`).
        drop(client);

        // v1.5.0 Phase C — Merkle hook on the newly-stored path only.
        // `AlreadyClaimed` returns a reference to a row inserted by a
        // prior call whose Merkle hook already ran (or didn't, if the
        // prior call lacked a signer). Re-running here would
        // double-append.
        if let ClaimResult::Stored(_) = &result {
            merkle_hook_pg(self, &entry, entry.sequence_number).await?;
        }

        Ok(result)
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
            // Empty correlation_id is a defined no-op: returning rows
            // would either be all-rows-with-the-key (high cost) or
            // rows-where-the-key-is-empty-string (caller bug bait).
            // Empty Vec is the unambiguous answer.
            return Ok(Vec::new());
        }
        let limit = filter.limit.clamp(1, CORRELATION_QUERY_MAX_LIMIT) as i64;

        // payload @> jsonb_build_object('correlation_id', $2::text)
        // is the index-friendly containment query — a GIN index on
        // (payload jsonb_path_ops) would accelerate it. None exists
        // on V014 yet; if this query lands on the hot path, add one
        // in a follow-up migration.
        let needle = serde_json::json!({"correlation_id": correlation_id});

        let client = self.checkout().await.map_err(Error::from)?;
        let rows = client
            .query(
                "SELECT entry_id, sequence_number, tenant_id, actor_id, \
                        action_type, subject_kind, subject_id, payload, \
                        prev_hash, entry_hash, recorded_at, signature \
                 FROM cirislens.audit_log \
                 WHERE tenant_id = $1 \
                   AND payload @> $2::jsonb \
                   AND ($3::timestamptz IS NULL OR recorded_at >= $3) \
                   AND ($4::timestamptz IS NULL OR recorded_at <= $4) \
                 ORDER BY recorded_at DESC, sequence_number DESC \
                 LIMIT $5",
                &[
                    &tenant_id,
                    &needle,
                    &filter.time_window_start,
                    &filter.time_window_end,
                    &limit,
                ],
            )
            .await
            .map_err(|e| map_pg_error(e, "query_by_correlation_id"))?;

        let mut items: Vec<AuditEntry> = Vec::with_capacity(rows.len());
        for row in &rows {
            items.push(decode_entry_row(row)?);
        }
        Ok(items)
    }

    async fn next_chain_position(
        &self,
        tenant_id: &str,
    ) -> Result<super::service::ChainPosition, Error> {
        if tenant_id.is_empty() {
            return Err(Error::InvalidArgument("tenant_id must be non-empty".into()));
        }
        let client = self.checkout().await.map_err(Error::from)?;
        let row_opt = client
            .query_opt(
                "SELECT sequence_number, entry_hash \
                 FROM cirislens.audit_log \
                 WHERE tenant_id = $1 \
                 ORDER BY sequence_number DESC \
                 LIMIT 1",
                &[&tenant_id],
            )
            .await
            .map_err(|e| map_pg_error(e, "next_chain_position tail probe"))?;
        if let Some(row) = row_opt {
            let prev_seq: i64 = row
                .try_get("sequence_number")
                .map_err(|e| Error::Backend(format!("decode prev seq: {e}")))?;
            let prev_hash_bytes: Vec<u8> = row
                .try_get("entry_hash")
                .map_err(|e| Error::Backend(format!("decode prev hash: {e}")))?;
            let prev_hash: [u8; 32] = prev_hash_bytes.as_slice().try_into().map_err(|_| {
                Error::Backend(format!(
                    "entry_hash column expected 32 bytes, got {}",
                    prev_hash_bytes.len()
                ))
            })?;
            Ok(super::service::ChainPosition {
                next_sequence_number: prev_seq + 1,
                prev_hash,
            })
        } else {
            Ok(super::service::ChainPosition {
                next_sequence_number: 1,
                prev_hash: GENESIS_PREV_HASH,
            })
        }
    }

    async fn current_sth(&self, tenant_id: &str) -> Result<Option<SignedTreeHead>, Error> {
        if tenant_id.is_empty() {
            return Err(Error::InvalidArgument("tenant_id must be non-empty".into()));
        }
        // v62.0.0 (P8) — a tenant-scoped async store, awaited in place.
        let store = PgMerkleStore::from_backend(self, tenant_id.to_owned());
        let res = store
            .latest_sth()
            .await
            .map_err(|e| Error::Merkle(format!("latest_sth: {e}")))?;
        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use ed25519_dalek::SigningKey;
    use uuid::Uuid;

    fn pg_dsn() -> Option<String> {
        crate::test_pg::dsn()
    }

    /// v62.0.0 (F0-cp8) — an actor whose `key:record` the backend holds: the
    /// seed [`crate::audit::test_support::seal`] signs as.
    async fn audit_seed(backend: &PostgresBackend, byte: u8) -> String {
        let seed = format!("audit-pg-{byte:02x}");
        crate::audit::test_support::put_actor(backend, &seed).await;
        seed
    }

    fn build_and_sign(
        key: &str,
        tenant_id: &str,
        sequence_number: i64,
        prev_hash: Vec<u8>,
        action_type: &str,
    ) -> AuditEntry {
        let entry = AuditEntry {
            entry_id: Uuid::new_v4().to_string(),
            sequence_number,
            tenant_id: tenant_id.to_owned(),
            actor_id: String::new(),
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
        crate::audit::test_support::seal(key, entry)
    }

    /// v10.2.1 (CIRISPersist#283) — the postgres `audit_log.action_type`
    /// CHECK admits the LensAudit `consent_event` (`log_consent_event`) +
    /// `wisdom_based_deferral` (`log_wbd`) vocabulary (V090). These record
    /// fine on SQLite (no CHECK) but were CHECK-rejected on postgres — the
    /// backend-parity gap CIRISConformance `test_320` surfaced.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn audit_admits_lensaudit_consent_and_wbd_283() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let key = audit_seed(&backend, 0xC3).await;
        let tenant = format!("audit-283-{}", Uuid::new_v4().simple());

        let e1 = build_and_sign(
            &key,
            &tenant,
            1,
            GENESIS_PREV_HASH.to_vec(),
            "consent_event",
        );
        backend
            .record_entry(e1.clone())
            .await
            .expect("consent_event must be admitted by the V090 CHECK");
        let e2 = build_and_sign(
            &key,
            &tenant,
            2,
            e1.entry_hash.clone(),
            "wisdom_based_deferral",
        );
        backend
            .record_entry(e2)
            .await
            .expect("wisdom_based_deferral must be admitted by the V090 CHECK");
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

        let key = audit_seed(&backend, 0xA1).await;
        let tenant = format!("audit-test-{}", Uuid::new_v4().simple());

        // 1. Genesis insert (seq=1, prev_hash=zeros).
        let e1 = build_and_sign(
            &key,
            &tenant,
            1,
            GENESIS_PREV_HASH.to_vec(),
            "handler_action_task_complete",
        );
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
        let bad_gap = build_and_sign(
            &key,
            &tenant,
            3,
            e1.entry_hash.clone(),
            "handler_action_task_complete",
        );
        let gap_err = backend.record_entry(bad_gap).await.unwrap_err();
        assert!(
            matches!(gap_err, Error::ChainIntegrity(_)),
            "expected ChainIntegrity on gap, got {gap_err:?}"
        );

        // 4. Wrong prev_hash → ChainIntegrity (seq=2 with wrong prev).
        let bad_prev = build_and_sign(
            &key,
            &tenant,
            2,
            vec![0xff; 32],
            "handler_action_task_complete",
        );
        let prev_err = backend.record_entry(bad_prev).await.unwrap_err();
        assert!(
            matches!(prev_err, Error::ChainIntegrity(_)),
            "expected ChainIntegrity on bad prev_hash, got {prev_err:?}"
        );

        // 5. Correct continuation: seq=2 with prev = e1.entry_hash.
        let e2 = build_and_sign(&key, &tenant, 2, e1.entry_hash.clone(), "config_change");
        backend.record_entry(e2.clone()).await.unwrap();

        // 6. Extend to seq=3.
        let e3 = build_and_sign(
            &key,
            &tenant,
            3,
            e2.entry_hash.clone(),
            "handler_action_task_complete",
        );
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
        let client = backend.checkout().await.unwrap();
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

    /// CIRISPersist#86 — an `AuditCursor` with an empty `last_id` is
    /// the "no cursor yet — first page" sentinel. Postgres used to
    /// parse it unconditionally as a UUID and raise
    /// (`entry_id parse: invalid length`); it must instead skip the
    /// keyset predicate and return the first page, identical to
    /// `task_list` and the SQLite arm.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn list_entries_empty_cursor_returns_first_page() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let key = audit_seed(&backend, 0xB2).await;
        let tenant = format!("audit-cursor-{}", Uuid::new_v4().simple());
        let e1 = build_and_sign(
            &key,
            &tenant,
            1,
            GENESIS_PREV_HASH.to_vec(),
            "handler_action_speak",
        );
        backend.record_entry(e1.clone()).await.unwrap();
        let e2 = build_and_sign(&key, &tenant, 2, e1.entry_hash.clone(), "config_change");
        backend.record_entry(e2.clone()).await.unwrap();

        let filter = AuditFilter {
            tenant_id: tenant.clone(),
            action_type: None,
            actor_id: None,
            subject_kind: None,
            subject_id: None,
            recorded_after: None,
            recorded_before: None,
        };
        let empty_cursor = AuditCursor {
            version: "v1".to_owned(),
            last_ts: chrono::DateTime::parse_from_rfc3339("9999-12-31T23:59:59Z")
                .unwrap()
                .with_timezone(&Utc),
            last_id: String::new(),
        };
        let page = backend
            .list_entries(filter, Some(empty_cursor), 10)
            .await
            .expect("empty last_id must be accepted as the first-page sentinel");
        assert_eq!(page.items.len(), 2, "first page returns all entries");
    }

    /// Build + sign an entry whose payload carries a `correlation_id`.
    /// v1.0.0 (CIRISAgent#756 Q4).
    fn build_with_correlation(
        key: &str,
        tenant_id: &str,
        sequence_number: i64,
        prev_hash: Vec<u8>,
        correlation_id: &str,
    ) -> AuditEntry {
        let entry = AuditEntry {
            entry_id: Uuid::new_v4().to_string(),
            sequence_number,
            tenant_id: tenant_id.to_owned(),
            actor_id: String::new(),
            action_type: "handler_action_task_complete".into(),
            subject_kind: "task".into(),
            subject_id: format!("subj-{sequence_number}"),
            payload: serde_json::json!({"correlation_id": correlation_id}),
            prev_hash,
            entry_hash: vec![],
            recorded_at: super::super::verify::truncate_to_micros(Utc::now()),
            signature: String::new(),
        };
        crate::audit::test_support::seal(key, entry)
    }

    /// v1.0.0 (CIRISAgent#756 Q4) — `query_by_correlation_id` returns
    /// only entries whose payload JSONB contains the matching
    /// `correlation_id`, newest-first, tenant-scoped (AV-51).
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn query_by_correlation_id_round_trip() {
        use crate::audit::CorrelationQuery;
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let key = audit_seed(&backend, 0xD4).await;
        let tenant = format!("audit-corr-{}", Uuid::new_v4().simple());

        // 3 entries on the same chain: corr-A, corr-B, corr-A.
        let e1 = build_with_correlation(&key, &tenant, 1, GENESIS_PREV_HASH.to_vec(), "corr-A");
        backend.record_entry(e1.clone()).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        let e2 = build_with_correlation(&key, &tenant, 2, e1.entry_hash.clone(), "corr-B");
        backend.record_entry(e2.clone()).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        let e3 = build_with_correlation(&key, &tenant, 3, e2.entry_hash.clone(), "corr-A");
        backend.record_entry(e3.clone()).await.unwrap();

        // Query corr-A → 2 entries, newest-first (e3 then e1).
        let hits = backend
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

        // Empty correlation_id → empty Vec (defined no-op).
        let empty = backend
            .query_by_correlation_id(&tenant, "", CorrelationQuery::default())
            .await
            .unwrap();
        assert!(empty.is_empty());

        // Cross-tenant mismatch → empty Vec (AV-51).
        let other = format!("other-tenant-{}", Uuid::new_v4().simple());
        let cross = backend
            .query_by_correlation_id(&other, "corr-A", CorrelationQuery::default())
            .await
            .unwrap();
        assert!(cross.is_empty());

        // Empty tenant_id rejects.
        let no_tenant = backend
            .query_by_correlation_id("", "corr-A", CorrelationQuery::default())
            .await
            .unwrap_err();
        assert!(matches!(no_tenant, Error::InvalidArgument(_)));
    }

    // ────────────────────────────────────────────────────────────────
    // v1.5.0 Phase C — Merkle transparency hook tests (Postgres)
    // ────────────────────────────────────────────────────────────────

    fn merkle_test_signer(seed_byte: u8) -> std::sync::Arc<crate::signing::LocalSigner> {
        use ciris_keyring::MlDsa65SoftwareSigner;
        let signing_key = SigningKey::from_bytes(&[seed_byte; 32]);
        let pqc =
            MlDsa65SoftwareSigner::from_seed_bytes(&[seed_byte ^ 0x55; 32], "test-merkle-pqc")
                .expect("seed bytes");
        let pqc_arc: std::sync::Arc<dyn ciris_keyring::PqcSigner> = std::sync::Arc::new(pqc);
        std::sync::Arc::new(crate::signing::LocalSigner::from_parts(
            signing_key,
            "test-merkle-steward".to_string(),
            Some(pqc_arc),
            Some("test-merkle-pqc".to_string()),
        ))
    }

    /// v59.1.2 (I1483) — the field wedge, reproduced. `record_entry` held its
    /// pooled client past the commit, and the Merkle hook (armed whenever a
    /// signer is installed) then checked out another. Two writers on a pool
    /// of two (a 1-vCPU node's whole pool) each held one and waited for a
    /// third. A barrier after the commit makes both writers hold at once;
    /// the pool's 3 s wait turns the deadlock into an error instead of a
    /// hang. Both writers must land, with their Merkle leaves.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn i1483_two_audit_writers_complete_on_a_pool_of_two() {
        use crate::store::backend::Backend;
        let Some(dsn) = crate::test_pg::isolated_dsn() else {
            eprintln!("i1483: no CIRIS_PERSIST_TEST_PG base DSN — SKIPPED");
            return;
        };
        let backend =
            PostgresBackend::connect_with_pool_for_test(&dsn, 2, std::time::Duration::from_secs(3))
                .await
                .unwrap();
        backend.run_migrations().await.unwrap();
        assert_eq!(
            backend.pool_max_size_for_test(),
            2,
            "the witness's own premise"
        );
        backend.set_merkle_signer(Some(merkle_test_signer(0xB7)));
        backend
            .test_hooks()
            .arm_barrier("audit_record_entry_after_commit", 2);
        let key = audit_seed(&backend, 0xB7).await;
        let tag = Uuid::new_v4().simple().to_string();
        let (ta, tb) = (format!("i1483-a-{tag}"), format!("i1483-b-{tag}"));
        let ea = build_and_sign(&key, &ta, 1, GENESIS_PREV_HASH.to_vec(), "system_event");
        let eb = build_and_sign(&key, &tb, 1, GENESIS_PREV_HASH.to_vec(), "system_event");
        let (ra, rb) = tokio::time::timeout(std::time::Duration::from_secs(60), async {
            tokio::join!(backend.record_entry(ea), backend.record_entry(eb))
        })
        .await
        .expect("I1483 the two writers did not finish within 60 s");
        ra.expect("I1483 writer A");
        rb.expect("I1483 writer B");
        assert_eq!(
            pg_count_merkle_rows(&backend, &ta).await,
            (1, 1),
            "I1483 A's leaf"
        );
        assert_eq!(
            pg_count_merkle_rows(&backend, &tb).await,
            (1, 1),
            "I1483 B's leaf"
        );
    }

    /// v59.1.2 (I1483) — `try_claim_event` carried the same nest (its client
    /// across the Merkle hook): on a one-connection pool it must store and
    /// append its leaf.
    #[tokio::test(flavor = "multi_thread")]
    async fn i1483_try_claim_event_completes_on_one_connection() {
        use crate::store::backend::Backend;
        let Some(dsn) = crate::test_pg::isolated_dsn() else {
            eprintln!("i1483: no CIRIS_PERSIST_TEST_PG base DSN — SKIPPED");
            return;
        };
        let backend =
            PostgresBackend::connect_with_pool_for_test(&dsn, 1, std::time::Duration::from_secs(3))
                .await
                .unwrap();
        backend.run_migrations().await.unwrap();
        backend.set_merkle_signer(Some(merkle_test_signer(0xB8)));
        let key = audit_seed(&backend, 0xB8).await;
        let tenant = format!("i1483-claim-{}", Uuid::new_v4().simple());
        let e1 = build_and_sign(&key, &tenant, 1, GENESIS_PREV_HASH.to_vec(), "system_event");
        let out = tokio::time::timeout(
            std::time::Duration::from_secs(60),
            backend.try_claim_event([0x5A; 32], e1, "i1483".into()),
        )
        .await
        .expect("I1483 try_claim_event did not finish within 60 s")
        .expect("I1483 try_claim_event");
        assert!(matches!(out, ClaimResult::Stored(_)), "I1483 {out:?}");
        assert_eq!(pg_count_merkle_rows(&backend, &tenant).await, (1, 1));
        let e2 = build_and_sign(
            &key,
            &tenant,
            2,
            {
                let c = backend.get_client().await.unwrap();
                c.query_one(
                    "SELECT entry_hash FROM cirislens.audit_log WHERE tenant_id = $1",
                    &[&tenant],
                )
                .await
                .unwrap()
                .get::<_, Vec<u8>>(0)
            },
            "system_event",
        );
        tokio::time::timeout(std::time::Duration::from_secs(60), backend.record_entry(e2))
            .await
            .expect("I1483 record_entry did not finish within 60 s")
            .expect("I1483 record_entry on one connection");
        assert_eq!(pg_count_merkle_rows(&backend, &tenant).await, (2, 2));
    }

    async fn pg_count_merkle_rows(backend: &PostgresBackend, tenant: &str) -> (i64, i64) {
        let client = backend.checkout().await.unwrap();
        let leaves: i64 = client
            .query_one(
                "SELECT COUNT(*)::BIGINT FROM cirislens.merkle_leaves WHERE tenant_id = $1",
                &[&tenant],
            )
            .await
            .unwrap()
            .get(0);
        let sth: i64 = client
            .query_one(
                "SELECT COUNT(*)::BIGINT FROM cirislens.merkle_sth_log WHERE tenant_id = $1",
                &[&tenant],
            )
            .await
            .unwrap()
            .get(0);
        (leaves, sth)
    }

    async fn pg_cleanup_tenant_merkle(backend: &PostgresBackend, tenant: &str) {
        let client = backend.checkout().await.unwrap();

        // v3.5.2 (CIRISPersist#128) — diagnostic instrumentation:
        // when this DELETE fires "relation does not exist", we want
        // a rich snapshot at the failure boundary. The eprintln only
        // produces output on the actual failure path.
        if let Err(e) = client
            .execute(
                "DELETE FROM cirislens.merkle_sth_log WHERE tenant_id = $1",
                &[&tenant],
            )
            .await
        {
            eprintln!("=== #128 RCA: pg_cleanup_tenant_merkle DELETE FAILED ===");
            eprintln!("    tenant={tenant}");
            eprintln!("    error={e:?}");
            // 1. Which tables exist in cirislens matching `merkle%`?
            if let Ok(rows) = client
                .query(
                    "SELECT table_name FROM information_schema.tables \
                     WHERE table_schema = 'cirislens' AND table_name LIKE 'merkle%'",
                    &[],
                )
                .await
            {
                let names: Vec<String> = rows
                    .iter()
                    .map(|r| r.get::<_, String>("table_name"))
                    .collect();
                eprintln!("    cirislens merkle tables: {names:?}");
            }
            // 2. Connection identity: what DB / schema / search_path?
            if let Ok(row) = client
                .query_one(
                    "SELECT current_database(), current_schema(), current_setting('search_path')",
                    &[],
                )
                .await
            {
                let db: String = row.get(0);
                let schema: String = row.get(1);
                let sp: String = row.get(2);
                eprintln!("    current_database={db}, current_schema={schema}, search_path={sp}");
            }
            // 3. Refinery schema_history snapshot.
            if let Ok(rows) = client
                .query(
                    "SELECT version FROM ciris_persist_schema_history ORDER BY version DESC LIMIT 5",
                    &[],
                )
                .await
            {
                let versions: Vec<i32> = rows.iter().map(|r| r.get::<_, i32>(0)).collect();
                eprintln!("    schema_history top 5 versions: {versions:?}");
            } else {
                eprintln!("    ciris_persist_schema_history NOT readable");
            }
            // 4. Are we in a transaction? Could explain visibility.
            if let Ok(row) = client
                .query_one("SELECT (txid_current_if_assigned() IS NOT NULL)::text", &[])
                .await
            {
                let in_tx: String = row.get(0);
                eprintln!("    in_transaction: {in_tx}");
            }
            // 5. Backend connection state.
            if let Ok(row) = client
                .query_one(
                    "SELECT pid, application_name, backend_start::text, state \
                     FROM pg_stat_activity WHERE pid = pg_backend_pid()",
                    &[],
                )
                .await
            {
                let pid: i32 = row.get(0);
                let app: String = row.get(1);
                let bs: String = row.get(2);
                let state: Option<String> = row.get(3);
                eprintln!("    backend pid={pid} app={app} since={bs} state={state:?}");
            }
            eprintln!("=== end #128 RCA ===");
            panic!("merkle_sth_log DELETE failed: {e:?}");
        }
        client
            .execute(
                "DELETE FROM cirislens.merkle_leaves WHERE tenant_id = $1",
                &[&tenant],
            )
            .await
            .unwrap();
    }

    /// v1.5.0 Phase C — signer-absent path is a no-op (PG parity).
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn pg_merkle_hook_disabled_when_signer_absent() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let key = audit_seed(&backend, 0xB0).await;
        let tenant = format!("pg-merk-off-{}", Uuid::new_v4().simple());
        pg_cleanup_tenant_merkle(&backend, &tenant).await;

        let e1 = build_and_sign(&key, &tenant, 1, GENESIS_PREV_HASH.to_vec(), "system_event");
        backend.record_entry(e1.clone()).await.unwrap();
        let e2 = build_and_sign(&key, &tenant, 2, e1.entry_hash.clone(), "system_event");
        backend.record_entry(e2.clone()).await.unwrap();

        let (leaves, sth) = pg_count_merkle_rows(&backend, &tenant).await;
        assert_eq!(leaves, 0);
        assert_eq!(sth, 0);

        pg_cleanup_tenant_merkle(&backend, &tenant).await;
    }

    /// v1.5.0 Phase C — signer-present path appends every entry, signs,
    /// stores STH (PG parity).
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn pg_merkle_hook_enabled_appends_and_signs() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        backend.set_merkle_signer(Some(merkle_test_signer(0xC1)));

        let key = audit_seed(&backend, 0xC1).await;
        let tenant = format!("pg-merk-on-{}", Uuid::new_v4().simple());
        pg_cleanup_tenant_merkle(&backend, &tenant).await;

        let e1 = build_and_sign(&key, &tenant, 1, GENESIS_PREV_HASH.to_vec(), "system_event");
        backend.record_entry(e1.clone()).await.unwrap();
        let (l1, s1) = pg_count_merkle_rows(&backend, &tenant).await;
        assert_eq!((l1, s1), (1, 1));

        let e2 = build_and_sign(&key, &tenant, 2, e1.entry_hash.clone(), "system_event");
        backend.record_entry(e2.clone()).await.unwrap();
        let e3 = build_and_sign(&key, &tenant, 3, e2.entry_hash.clone(), "system_event");
        backend.record_entry(e3.clone()).await.unwrap();
        let (l3, s3) = pg_count_merkle_rows(&backend, &tenant).await;
        assert_eq!((l3, s3), (3, 3));

        // tree_size monotonicity in STH log.
        let client = backend.checkout().await.unwrap();
        let rows = client
            .query(
                "SELECT tree_size FROM cirislens.merkle_sth_log \
                 WHERE tenant_id = $1 ORDER BY tree_size ASC",
                &[&tenant],
            )
            .await
            .unwrap();
        let sizes: Vec<i64> = rows.iter().map(|r| r.get(0)).collect();
        assert_eq!(sizes, vec![1, 2, 3]);

        // Reset signer + cleanup.
        backend.set_merkle_signer(None);
        pg_cleanup_tenant_merkle(&backend, &tenant).await;
    }

    /// v1.5.0 Phase C — multi-tenant isolation (PG parity).
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn pg_merkle_hook_multi_tenant_isolated() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        backend.set_merkle_signer(Some(merkle_test_signer(0xD2)));

        let key_a = audit_seed(&backend, 0xDA).await;
        let key_b = audit_seed(&backend, 0xDB).await;
        let tenant_a = format!("pg-merk-iso-A-{}", Uuid::new_v4().simple());
        let tenant_b = format!("pg-merk-iso-B-{}", Uuid::new_v4().simple());
        pg_cleanup_tenant_merkle(&backend, &tenant_a).await;
        pg_cleanup_tenant_merkle(&backend, &tenant_b).await;

        let a1 = build_and_sign(
            &key_a,
            &tenant_a,
            1,
            GENESIS_PREV_HASH.to_vec(),
            "system_event",
        );
        backend.record_entry(a1.clone()).await.unwrap();
        let a2 = build_and_sign(&key_a, &tenant_a, 2, a1.entry_hash.clone(), "system_event");
        backend.record_entry(a2.clone()).await.unwrap();
        let b1 = build_and_sign(
            &key_b,
            &tenant_b,
            1,
            GENESIS_PREV_HASH.to_vec(),
            "system_event",
        );
        backend.record_entry(b1.clone()).await.unwrap();

        let (la, sa) = pg_count_merkle_rows(&backend, &tenant_a).await;
        let (lb, sb) = pg_count_merkle_rows(&backend, &tenant_b).await;
        assert_eq!((la, sa), (2, 2));
        assert_eq!((lb, sb), (1, 1));

        backend.set_merkle_signer(None);
        pg_cleanup_tenant_merkle(&backend, &tenant_a).await;
        pg_cleanup_tenant_merkle(&backend, &tenant_b).await;
    }

    /// v1.5.0 Phase C — chain integrity (AV-49) preserved alongside
    /// the Merkle hook (PG parity).
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn pg_merkle_hook_does_not_weaken_chain_integrity() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        backend.set_merkle_signer(Some(merkle_test_signer(0xE3)));

        let key = audit_seed(&backend, 0xE3).await;
        let tenant = format!("pg-merk-int-{}", Uuid::new_v4().simple());
        pg_cleanup_tenant_merkle(&backend, &tenant).await;

        let e1 = build_and_sign(&key, &tenant, 1, GENESIS_PREV_HASH.to_vec(), "system_event");
        backend.record_entry(e1.clone()).await.unwrap();
        // Replay → rejected by chain commit, NOT by merkle hook.
        let replay_err = backend.record_entry(e1.clone()).await.unwrap_err();
        assert!(matches!(
            replay_err,
            Error::ChainIntegrity(_) | Error::Conflict(_)
        ));
        let (l, s) = pg_count_merkle_rows(&backend, &tenant).await;
        assert_eq!(l, 1, "exactly one leaf — replay was chain-rejected");
        assert_eq!(s, 1);

        backend.set_merkle_signer(None);
        pg_cleanup_tenant_merkle(&backend, &tenant).await;
    }
}
