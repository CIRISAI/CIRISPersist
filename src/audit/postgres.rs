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
use super::verify::{compute_entry_hash, verify_entry_signature};
use super::{Error, GENESIS_PREV_HASH};
use crate::store::postgres::PostgresBackend;
use crate::ClaimResult;

use ciris_verify_core::transparency::{SignedTreeHead, TransparencyLog, TransparencyStore};
use std::sync::Arc;

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

    // Bridge from the async caller into the sync TransparencyStore
    // trait. The TransparencyLog operations (append / merkle_root /
    // store_sth) all call PgMerkleStore methods which in turn call
    // `runtime.block_on(pool.get())`. Doing that on the current
    // tokio worker would panic; spawn_blocking moves the work to
    // a blocking thread.
    let handle = tokio::runtime::Handle::current();
    let pool = backend.pool().clone();
    let tenant_id = entry.tenant_id.clone();
    let leaf = AuditLeaf::with_chain_event_id(entry.clone(), chain_event_id);
    let log_id = log_id_for_tenant(&tenant_id);

    let store: Arc<dyn TransparencyStore<AuditLeaf>> =
        Arc::new(PgMerkleStore::from_pool(pool, handle, tenant_id.clone()));
    let log = TransparencyLog::<AuditLeaf>::for_log(log_id.clone(), store.clone());

    // 1. Append the leaf + compute tree_size + merkle_root on a
    //    blocking thread (the TransparencyStore trait is sync; its
    //    PgMerkleStore impl uses `runtime.block_on(pool.get())`,
    //    which would panic on a tokio worker — spawn_blocking moves
    //    the work to a blocking thread).
    let log_for_block = log;
    let leaf_for_block = leaf;
    let head_jh: tokio::task::JoinHandle<
        Result<(u64, [u8; 32]), ciris_verify_core::transparency::TransparencyError>,
    > = tokio::task::spawn_blocking(move || {
        let _idx = log_for_block.append(leaf_for_block)?;
        let ts = log_for_block.tree_size()?;
        let root = log_for_block.merkle_root()?;
        Ok((ts, root))
    });
    let (tree_size, root_hash) = head_jh
        .await
        .map_err(|e| Error::Merkle(format!("append join: {e}")))?
        .map_err(|e| Error::Merkle(format!("append: {e}")))?;

    // 2. Sign the STH via LocalSigner::sign_hybrid (async).
    let timestamp = chrono::Utc::now();
    let signing_bytes = SignedTreeHead::signing_bytes(&log_id, tree_size, &root_hash, timestamp);
    let signature = signer
        .sign_hybrid(&signing_bytes)
        .await
        .map_err(|e| Error::Merkle(format!("sign_hybrid: {e}")))?;

    let sth = SignedTreeHead {
        log_id,
        tree_size,
        root_hash,
        timestamp,
        signature,
        witness_signatures: Vec::new(),
    };

    // 3. Persist the STH (sync trait again → spawn_blocking).
    let store_for_store = store;
    let sth_for_store = sth;
    let store_jh: tokio::task::JoinHandle<
        Result<(), ciris_verify_core::transparency::TransparencyError>,
    > = tokio::task::spawn_blocking(move || store_for_store.store_sth(&sth_for_store));
    store_jh
        .await
        .map_err(|e| Error::Merkle(format!("store_sth join: {e}")))?
        .map_err(|e| Error::Merkle(format!("store_sth: {e}")))?;

    Ok(())
}

/// v1.5.0 Phase D — TrustGrant projection hook for the audit-service
/// ingest path. Called after the Merkle hook completes; **gated on
/// `entry.subject_kind == "trust_grant"`** so non-grant entries skip
/// the helper entirely.
///
/// Materializes / refreshes a row in `cirislens.federation_trust_grants`
/// keyed by `(grantee_key, granter_key, purpose, scope)` per FSD §3.6.
/// Re-issuance is a UPSERT on the unique key (refresh chain pointers,
/// `granted_at` from `entry.recorded_at`, and clear revocation columns).
/// Revocation per FSD §3.4 is a re-issuance with `expires_at <= NOW()`;
/// the UPSERT detects that and sets `revoked_at` + `revoked_by`.
///
/// # Atomicity
///
/// Out-of-transaction, matching `merkle_hook_pg`. The audit chain +
/// Merkle leaf are the source of truth (already committed by the time
/// this runs); a projection failure surfaces as `Error::TrustGrant(_)`
/// but the chain row stands. Phase I's V021 backfill walks the chain
/// to re-project any orphaned trust_grant entries.
///
/// # Self-grant rejection
///
/// `granter_key == grantee_key` is rejected here (matches the V021
/// CHECK constraint AND FSD §3.6 integrity rule). The audit entry
/// itself is already on-chain by the time we get here; this is a
/// projection-side belt-and-suspenders that also surfaces the issue
/// earlier than the CHECK violation would.
async fn project_trust_grant_pg(
    backend: &PostgresBackend,
    entry: &AuditEntry,
    chain_event_id: i64,
) -> Result<(), Error> {
    use crate::federation::trust_grant::TrustGrantPayload;

    let payload: TrustGrantPayload = serde_json::from_value(entry.payload.clone())
        .map_err(|e| Error::TrustGrant(format!("payload deserialize: {e}")))?;

    // Granter is envelope-level `actor_id` (FSD §3.1 — granter is
    // author_id; not duplicated in the payload).
    let granter_key = entry.actor_id.as_str();
    let grantee_key = payload.grantee_key.as_str();

    if granter_key == grantee_key {
        return Err(Error::TrustGrant(
            "self-grant rejected (granter == grantee)".into(),
        ));
    }

    let purpose_str = payload.purpose.as_str();
    let chain_event_hash = entry.entry_hash.clone();
    let granted_at = entry.recorded_at;
    let expires_at = payload.expires_at;

    let client = backend
        .pool()
        .get()
        .await
        .map_err(|e| Error::TrustGrant(format!("pool: {e}")))?;
    client
        .execute(
            "INSERT INTO cirislens.federation_trust_grants (\
                grantee_key, granter_key, purpose, scope, \
                granted_at, expires_at, chain_event_id, chain_event_hash, tenant_id\
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
             ON CONFLICT (grantee_key, granter_key, purpose, scope) DO UPDATE SET \
                granted_at = EXCLUDED.granted_at, \
                expires_at = EXCLUDED.expires_at, \
                chain_event_id = EXCLUDED.chain_event_id, \
                chain_event_hash = EXCLUDED.chain_event_hash, \
                tenant_id = EXCLUDED.tenant_id, \
                revoked_at = CASE \
                    WHEN EXCLUDED.expires_at IS NOT NULL \
                     AND EXCLUDED.expires_at <= NOW() \
                    THEN NOW() ELSE NULL END, \
                revoked_by = CASE \
                    WHEN EXCLUDED.expires_at IS NOT NULL \
                     AND EXCLUDED.expires_at <= NOW() \
                    THEN EXCLUDED.granter_key ELSE NULL END",
            &[
                &grantee_key,
                &granter_key,
                &purpose_str,
                &payload.scope,
                &granted_at,
                &expires_at,
                &chain_event_id,
                &chain_event_hash,
                &entry.tenant_id,
            ],
        )
        .await
        .map_err(|e| {
            // CHECK violation (granter == grantee at the DB level) or
            // FK violation (grantee_key/granter_key missing from
            // federation_keys). Both are caller-data integrity issues
            // for the chain; surface as TrustGrant.
            Error::TrustGrant(format!("UPSERT federation_trust_grants: {e}"))
        })?;

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

        // v1.5.0 Phase C — Merkle transparency hook. Runs only when a
        // local signer was installed via `set_merkle_signer`;
        // otherwise this is a no-op and the audit chain semantics are
        // unchanged. `sequence_number` is reused as the
        // `chain_event_id` per FSD §4.4.
        merkle_hook_pg(self, &entry, entry.sequence_number).await?;

        // v1.5.0 Phase D — TrustGrant projection hook. Gated on
        // subject_kind; non-grant entries skip without DB work.
        if entry.subject_kind == crate::federation::trust_grant::TRUST_GRANT_SUBJECT_KIND {
            project_trust_grant_pg(self, &entry, entry.sequence_number).await?;
        }

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

        // v1.5.0 Phase C — Merkle hook on the newly-stored path only.
        // `AlreadyClaimed` returns a reference to a row inserted by a
        // prior call whose Merkle hook already ran (or didn't, if the
        // prior call lacked a signer). Re-running here would
        // double-append.
        //
        // v1.5.0 Phase D — TrustGrant projection same as Merkle:
        // only on the newly-stored path. AlreadyClaimed means the
        // projection already ran (or was a no-op if the prior call
        // happened on a SIDB at a time when this branch did not
        // exist; the V021 backfill will catch any orphans).
        if let ClaimResult::Stored(_) = &result {
            merkle_hook_pg(self, &entry, entry.sequence_number).await?;
            if entry.subject_kind == crate::federation::trust_grant::TRUST_GRANT_SUBJECT_KIND {
                project_trust_grant_pg(self, &entry, entry.sequence_number).await?;
            }
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

        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
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
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
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
        // Build a tenant-scoped PG merkle store on the fly + call its
        // sync `latest_sth()` via spawn_blocking (the store uses
        // `runtime.block_on` internally — calling it directly on a
        // tokio worker would panic).
        let pool = self.pool().clone();
        let handle = tokio::runtime::Handle::current();
        let tenant_owned = tenant_id.to_owned();
        let store: Arc<dyn TransparencyStore<AuditLeaf>> =
            Arc::new(PgMerkleStore::from_pool(pool, handle, tenant_owned));
        let jh: tokio::task::JoinHandle<
            Result<Option<SignedTreeHead>, ciris_verify_core::transparency::TransparencyError>,
        > = tokio::task::spawn_blocking(move || store.latest_sth());
        let res = jh
            .await
            .map_err(|e| Error::Merkle(format!("current_sth join: {e}")))?
            .map_err(|e| Error::Merkle(format!("latest_sth: {e}")))?;
        Ok(res)
    }

    async fn lookup_grant_id_by_chain_event(
        &self,
        chain_event_id: i64,
    ) -> Result<Option<uuid::Uuid>, Error> {
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        let row = client
            .query_opt(
                "SELECT grant_id FROM cirislens.federation_trust_grants \
                 WHERE chain_event_id = $1",
                &[&chain_event_id],
            )
            .await
            .map_err(|e| Error::Backend(format!("lookup_grant_id: {e}")))?;
        match row {
            None => Ok(None),
            Some(r) => {
                let grant_id: uuid::Uuid = r
                    .try_get("grant_id")
                    .map_err(|e| Error::Backend(format!("decode grant_id: {e}")))?;
                Ok(Some(grant_id))
            }
        }
    }

    // ── v1.5.0 Phase F+G — projection reads + Merkle proofs ─────────

    async fn get_trust_grant(
        &self,
        grant_id: uuid::Uuid,
    ) -> Result<Option<crate::federation::trust_grant::TrustGrantRow>, Error> {
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        let row_opt = client
            .query_opt(
                "SELECT grant_id, grantee_key, granter_key, purpose, scope, \
                        granted_at, expires_at, revoked_at, revoked_by, \
                        chain_event_id, chain_event_hash, tenant_id \
                 FROM cirislens.federation_trust_grants \
                 WHERE grant_id = $1",
                &[&grant_id],
            )
            .await
            .map_err(|e| Error::Backend(format!("get_trust_grant: {e}")))?;
        match row_opt {
            None => Ok(None),
            Some(r) => Ok(Some(decode_trust_grant_row_pg(&r)?)),
        }
    }

    async fn lookup_trust_grant(
        &self,
        grantee_key: &str,
        purpose: crate::federation::trust_grant::TrustPurpose,
        scope: &str,
        include_revoked: bool,
        include_expired: bool,
    ) -> Result<Vec<crate::federation::trust_grant::TrustGrantRow>, Error> {
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        // Per FSD §3.3, wildcard scopes are valid and MUST be surfaced
        // alongside exact-match rows — the caller (NodeCore's
        // resolve_trust) decides whether a wildcard satisfies the
        // query.
        let mut sql = String::from(
            "SELECT grant_id, grantee_key, granter_key, purpose, scope, \
                    granted_at, expires_at, revoked_at, revoked_by, \
                    chain_event_id, chain_event_hash, tenant_id \
             FROM cirislens.federation_trust_grants \
             WHERE grantee_key = $1 AND purpose = $2 \
               AND (scope = $3 OR scope = '*')",
        );
        if !include_revoked {
            sql.push_str(" AND revoked_at IS NULL");
        }
        if !include_expired {
            sql.push_str(" AND (expires_at IS NULL OR expires_at > NOW())");
        }
        sql.push_str(" ORDER BY granted_at DESC, grant_id");
        let purpose_str = purpose.as_str();
        let rows = client
            .query(&sql, &[&grantee_key, &purpose_str, &scope])
            .await
            .map_err(|e| Error::Backend(format!("lookup_trust_grant: {e}")))?;
        let mut out = Vec::with_capacity(rows.len());
        for r in &rows {
            out.push(decode_trust_grant_row_pg(r)?);
        }
        Ok(out)
    }

    async fn list_trust_grants(
        &self,
        filter: crate::federation::trust_grant::TrustGrantFilter,
    ) -> Result<Vec<crate::federation::trust_grant::TrustGrantRow>, Error> {
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        // Build the WHERE clause dynamically. params lifetimes here
        // are tricky — pre-stage each binding as a typed local so we
        // can push trait-object references into one Vec.
        let purpose_str_opt = filter.purpose.map(|p| p.as_str().to_owned());
        let scope_like = filter.scope_prefix.as_ref().map(|p| format!("{p}%"));

        let mut where_clauses: Vec<String> = Vec::new();
        let mut params: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> = Vec::new();
        let mut idx = 1usize;
        if let Some(g) = filter.grantee_key.as_ref() {
            where_clauses.push(format!("grantee_key = ${idx}"));
            params.push(g);
            idx += 1;
        }
        if let Some(g) = filter.granter_key.as_ref() {
            where_clauses.push(format!("granter_key = ${idx}"));
            params.push(g);
            idx += 1;
        }
        if let Some(p) = purpose_str_opt.as_ref() {
            where_clauses.push(format!("purpose = ${idx}"));
            params.push(p);
            idx += 1;
        }
        if let Some(s) = scope_like.as_ref() {
            where_clauses.push(format!("scope LIKE ${idx}"));
            params.push(s);
            idx += 1;
        }
        if !filter.include_revoked {
            where_clauses.push("revoked_at IS NULL".to_owned());
        }
        if !filter.include_expired {
            where_clauses.push("(expires_at IS NULL OR expires_at > NOW())".to_owned());
        }
        let _ = idx; // silence unused-assignment lint once params building finishes
        let mut sql = String::from(
            "SELECT grant_id, grantee_key, granter_key, purpose, scope, \
                    granted_at, expires_at, revoked_at, revoked_by, \
                    chain_event_id, chain_event_hash, tenant_id \
             FROM cirislens.federation_trust_grants",
        );
        if !where_clauses.is_empty() {
            sql.push_str(" WHERE ");
            sql.push_str(&where_clauses.join(" AND "));
        }
        sql.push_str(" ORDER BY granted_at DESC, grant_id");
        let rows = client
            .query(&sql, &params)
            .await
            .map_err(|e| Error::Backend(format!("list_trust_grants: {e}")))?;
        let mut out = Vec::with_capacity(rows.len());
        for r in &rows {
            out.push(decode_trust_grant_row_pg(r)?);
        }
        Ok(out)
    }

    async fn leaf_canonical_bytes_for_chain_event(
        &self,
        tenant_id: &str,
        chain_event_id: i64,
    ) -> Result<Option<Vec<u8>>, Error> {
        if tenant_id.is_empty() {
            return Err(Error::InvalidArgument("tenant_id must be non-empty".into()));
        }
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        let row_opt = client
            .query_opt(
                "SELECT canonical_bytes FROM cirislens.merkle_leaves \
                 WHERE tenant_id = $1 AND chain_event_id = $2",
                &[&tenant_id, &chain_event_id],
            )
            .await
            .map_err(|e| Error::Backend(format!("leaf_canonical_bytes: {e}")))?;
        match row_opt {
            None => Ok(None),
            Some(r) => {
                let raw: Vec<u8> = r
                    .try_get("canonical_bytes")
                    .map_err(|e| Error::Backend(format!("decode canonical_bytes: {e}")))?;
                Ok(Some(raw))
            }
        }
    }

    async fn inclusion_proof_for_chain_event(
        &self,
        tenant_id: &str,
        chain_event_id: i64,
    ) -> Result<ciris_verify_core::transparency::MerkleProof, Error> {
        if tenant_id.is_empty() {
            return Err(Error::InvalidArgument("tenant_id must be non-empty".into()));
        }
        // Resolve chain_event_id → leaf_index first.
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        let row_opt = client
            .query_opt(
                "SELECT leaf_index FROM cirislens.merkle_leaves \
                 WHERE tenant_id = $1 AND chain_event_id = $2",
                &[&tenant_id, &chain_event_id],
            )
            .await
            .map_err(|e| Error::Backend(format!("inclusion_proof leaf_index lookup: {e}")))?;
        let row = row_opt.ok_or_else(|| {
            Error::NotFound(format!(
                "no merkle_leaves row for tenant={tenant_id} chain_event_id={chain_event_id}"
            ))
        })?;
        let leaf_idx_i: i64 = row
            .try_get("leaf_index")
            .map_err(|e| Error::Backend(format!("decode leaf_index: {e}")))?;
        let leaf_index =
            u64::try_from(leaf_idx_i).map_err(|_| Error::Backend("leaf_index negative".into()))?;
        drop(client);

        // Build a tenant-scoped store and delegate inclusion_proof on
        // a blocking worker (the store is sync-trait + uses block_on
        // internally). Same shape as `current_sth`.
        let pool = self.pool().clone();
        let handle = tokio::runtime::Handle::current();
        let tenant_owned = tenant_id.to_owned();
        let store: Arc<dyn TransparencyStore<AuditLeaf>> =
            Arc::new(PgMerkleStore::from_pool(pool, handle, tenant_owned.clone()));
        let log_id = log_id_for_tenant(&tenant_owned);
        let jh: tokio::task::JoinHandle<
            Result<
                ciris_verify_core::transparency::MerkleProof,
                ciris_verify_core::transparency::TransparencyError,
            >,
        > = tokio::task::spawn_blocking(move || {
            let log = TransparencyLog::<AuditLeaf>::for_log(log_id, store);
            log.inclusion_proof(leaf_index)
        });
        jh.await
            .map_err(|e| Error::Merkle(format!("inclusion_proof join: {e}")))?
            .map_err(|e| Error::Merkle(format!("inclusion_proof: {e}")))
    }

    async fn consistency_proof(
        &self,
        tenant_id: &str,
        old_size: u64,
        new_size: u64,
    ) -> Result<ciris_verify_core::transparency::ConsistencyProof, Error> {
        if tenant_id.is_empty() {
            return Err(Error::InvalidArgument("tenant_id must be non-empty".into()));
        }
        let pool = self.pool().clone();
        let handle = tokio::runtime::Handle::current();
        let tenant_owned = tenant_id.to_owned();
        let store: Arc<dyn TransparencyStore<AuditLeaf>> =
            Arc::new(PgMerkleStore::from_pool(pool, handle, tenant_owned.clone()));
        let log_id = log_id_for_tenant(&tenant_owned);
        let jh: tokio::task::JoinHandle<
            Result<
                ciris_verify_core::transparency::ConsistencyProof,
                ciris_verify_core::transparency::TransparencyError,
            >,
        > = tokio::task::spawn_blocking(move || {
            let log = TransparencyLog::<AuditLeaf>::for_log(log_id, store);
            log.consistency_proof(old_size, new_size)
        });
        jh.await
            .map_err(|e| Error::Merkle(format!("consistency_proof join: {e}")))?
            .map_err(|e| Error::Merkle(format!("consistency_proof: {e}")))
    }

    // ── v1.5.0 Phase I — V020 → V021 backfill source ────────────────

    async fn read_v020_trust_rows_for_local(
        &self,
        local_pubkey: &str,
    ) -> Result<Vec<crate::federation::trust_grant::V020TrustRow>, Error> {
        use crate::federation::trust_grant::V020TrustRow;

        if local_pubkey.is_empty() {
            return Err(Error::InvalidArgument(
                "local_pubkey must be non-empty".into(),
            ));
        }
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        let rows = client
            .query(
                "SELECT key_id, pubkey_ed25519_base64, trust_type, \
                        trust_relationship, trust_domains, trusted_at, \
                        expires_at \
                 FROM cirislens.federation_keys \
                 WHERE trusted_by = $1 \
                   AND trust_relationship IS NOT NULL \
                 ORDER BY trusted_at ASC, key_id ASC",
                &[&local_pubkey],
            )
            .await
            .map_err(|e| Error::Backend(format!("read_v020_trust_rows: {e}")))?;
        let mut out: Vec<V020TrustRow> = Vec::with_capacity(rows.len());
        for r in &rows {
            let key_id: String = r
                .try_get("key_id")
                .map_err(|e| Error::Backend(format!("decode key_id: {e}")))?;
            let grantee_pubkey: String = r
                .try_get("pubkey_ed25519_base64")
                .map_err(|e| Error::Backend(format!("decode pubkey_ed25519_base64: {e}")))?;
            let trust_type: String = r
                .try_get("trust_type")
                .map_err(|e| Error::Backend(format!("decode trust_type: {e}")))?;
            let trust_relationship: String = r
                .try_get("trust_relationship")
                .map_err(|e| Error::Backend(format!("decode trust_relationship: {e}")))?;
            let trust_domains: Option<Vec<String>> = r
                .try_get("trust_domains")
                .map_err(|e| Error::Backend(format!("decode trust_domains: {e}")))?;
            let trusted_at: chrono::DateTime<chrono::Utc> = r
                .try_get("trusted_at")
                .map_err(|e| Error::Backend(format!("decode trusted_at: {e}")))?;
            let expires_at: Option<chrono::DateTime<chrono::Utc>> = r
                .try_get("expires_at")
                .map_err(|e| Error::Backend(format!("decode expires_at: {e}")))?;
            out.push(V020TrustRow {
                key_id,
                grantee_pubkey,
                trust_type,
                trust_relationship,
                trust_domains,
                trusted_at,
                expires_at,
            });
        }
        Ok(out)
    }
}

/// Decode one `federation_trust_grants` row into a [`TrustGrantRow`].
/// Used by `get_trust_grant`, `lookup_trust_grant`, `list_trust_grants`.
fn decode_trust_grant_row_pg(
    row: &tokio_postgres::Row,
) -> Result<crate::federation::trust_grant::TrustGrantRow, Error> {
    use crate::federation::trust_grant::{TrustGrantRow, TrustPurpose};
    let grant_id: uuid::Uuid = row
        .try_get("grant_id")
        .map_err(|e| Error::Backend(format!("decode grant_id: {e}")))?;
    let grantee_key: String = row
        .try_get("grantee_key")
        .map_err(|e| Error::Backend(format!("decode grantee_key: {e}")))?;
    let granter_key: String = row
        .try_get("granter_key")
        .map_err(|e| Error::Backend(format!("decode granter_key: {e}")))?;
    let purpose_str: String = row
        .try_get("purpose")
        .map_err(|e| Error::Backend(format!("decode purpose: {e}")))?;
    let purpose = TrustPurpose::parse_str(&purpose_str)
        .ok_or_else(|| Error::Backend(format!("unknown purpose: {purpose_str}")))?;
    let scope: String = row
        .try_get("scope")
        .map_err(|e| Error::Backend(format!("decode scope: {e}")))?;
    let granted_at: chrono::DateTime<chrono::Utc> = row
        .try_get("granted_at")
        .map_err(|e| Error::Backend(format!("decode granted_at: {e}")))?;
    let expires_at: Option<chrono::DateTime<chrono::Utc>> = row
        .try_get("expires_at")
        .map_err(|e| Error::Backend(format!("decode expires_at: {e}")))?;
    let revoked_at: Option<chrono::DateTime<chrono::Utc>> = row
        .try_get("revoked_at")
        .map_err(|e| Error::Backend(format!("decode revoked_at: {e}")))?;
    let revoked_by: Option<String> = row
        .try_get("revoked_by")
        .map_err(|e| Error::Backend(format!("decode revoked_by: {e}")))?;
    let chain_event_id: i64 = row
        .try_get("chain_event_id")
        .map_err(|e| Error::Backend(format!("decode chain_event_id: {e}")))?;
    let chain_event_hash: Vec<u8> = row
        .try_get("chain_event_hash")
        .map_err(|e| Error::Backend(format!("decode chain_event_hash: {e}")))?;
    let tenant_id: String = row
        .try_get("tenant_id")
        .map_err(|e| Error::Backend(format!("decode tenant_id: {e}")))?;
    Ok(TrustGrantRow {
        grant_id,
        grantee_key,
        granter_key,
        purpose,
        scope,
        granted_at,
        expires_at,
        revoked_at,
        revoked_by,
        chain_event_id,
        chain_event_hash,
        tenant_id,
    })
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

    /// Build + sign an entry whose payload carries a `correlation_id`.
    /// v1.0.0 (CIRISAgent#756 Q4).
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

        let key = SigningKey::from_bytes(&[0xD4; 32]);
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

    async fn pg_count_merkle_rows(backend: &PostgresBackend, tenant: &str) -> (i64, i64) {
        let client = backend.pool().get().await.unwrap();
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

        let key = SigningKey::from_bytes(&[0xB0; 32]);
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

        let key = SigningKey::from_bytes(&[0xC1; 32]);
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
        let client = backend.pool().get().await.unwrap();
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

        let key_a = SigningKey::from_bytes(&[0xDA; 32]);
        let key_b = SigningKey::from_bytes(&[0xDB; 32]);
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

        let key = SigningKey::from_bytes(&[0xE3; 32]);
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

    // ────────────────────────────────────────────────────────────────
    // v1.5.0 Phase D — TrustGrant projection tests (Postgres)
    // ────────────────────────────────────────────────────────────────

    /// Seed `cirislens.federation_keys` so FK targets exist for the
    /// projection's INSERT. Idempotent — uses ON CONFLICT DO NOTHING.
    async fn pg_seed_federation_key(backend: &PostgresBackend, key_id: &str) {
        let client = backend.pool().get().await.unwrap();
        client
            .execute(
                "INSERT INTO cirislens.federation_keys (\
                    key_id, pubkey_ed25519_base64, algorithm, identity_type, \
                    identity_ref, valid_from, registration_envelope, \
                    original_content_hash, scrub_signature_classical, \
                    scrub_key_id, scrub_timestamp, persist_row_hash\
                 ) VALUES ($1, 'AAAA', 'hybrid', 'agent', $1, NOW(), \
                          '{}'::jsonb, decode('00', 'hex'), '', $1, NOW(), '0') \
                 ON CONFLICT (key_id) DO NOTHING",
                &[&key_id],
            )
            .await
            .unwrap();
    }

    async fn pg_cleanup_trust_grants(backend: &PostgresBackend, tenant: &str) {
        let client = backend.pool().get().await.unwrap();
        client
            .execute(
                "DELETE FROM cirislens.federation_trust_grants WHERE tenant_id = $1",
                &[&tenant],
            )
            .await
            .unwrap();
    }

    #[allow(clippy::too_many_arguments)]
    fn build_trust_grant_entry_pg(
        granter_key: &SigningKey,
        tenant_id: &str,
        sequence_number: i64,
        prev_hash: Vec<u8>,
        grantee_key_b64: &str,
        purpose: crate::federation::trust_grant::TrustPurpose,
        scope: &str,
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> AuditEntry {
        let payload = serde_json::json!({
            "grantee_key": grantee_key_b64,
            "purpose": purpose.as_str(),
            "scope": scope,
            "expires_at": expires_at.map(|t| t.to_rfc3339()),
            "rationale": "phase-D-pg-test",
        });
        let mut entry = AuditEntry {
            entry_id: Uuid::new_v4().to_string(),
            sequence_number,
            tenant_id: tenant_id.to_owned(),
            actor_id: pubkey_b64(granter_key),
            action_type: "trust_granted".into(),
            subject_kind: crate::federation::trust_grant::TRUST_GRANT_SUBJECT_KIND.into(),
            subject_id: grantee_key_b64.to_owned(),
            payload,
            prev_hash,
            entry_hash: vec![],
            recorded_at: super::super::verify::truncate_to_micros(Utc::now()),
            signature: String::new(),
        };
        let hash = compute_entry_hash(&entry).unwrap();
        entry.entry_hash = hash.to_vec();
        let canonical = super::super::verify::canonical_bytes_for_entry(&entry).unwrap();
        let sig = granter_key.sign(&canonical);
        entry.signature = B64.encode(sig.to_bytes());
        entry
    }

    async fn pg_count_grants(backend: &PostgresBackend, tenant: &str) -> i64 {
        let client = backend.pool().get().await.unwrap();
        client
            .query_one(
                "SELECT COUNT(*)::BIGINT FROM cirislens.federation_trust_grants WHERE tenant_id = $1",
                &[&tenant],
            )
            .await
            .unwrap()
            .get(0)
    }

    /// v1.5.0 Phase D — Non-trust-grant entries don't touch the
    /// projection (PG parity).
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn pg_project_skips_non_trust_grant_subject_kinds() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let key = SigningKey::from_bytes(&[0x70; 32]);
        let tenant = format!("pg-pd-skip-{}", Uuid::new_v4().simple());
        pg_cleanup_trust_grants(&backend, &tenant).await;

        // Use action_types from V020's audit_log CHECK whitelist.
        let e1 = build_and_sign(&key, &tenant, 1, GENESIS_PREV_HASH.to_vec(), "system_event");
        backend.record_entry(e1.clone()).await.unwrap();
        let e2 = build_and_sign(&key, &tenant, 2, e1.entry_hash.clone(), "config_change");
        backend.record_entry(e2.clone()).await.unwrap();

        assert_eq!(pg_count_grants(&backend, &tenant).await, 0);
        pg_cleanup_trust_grants(&backend, &tenant).await;
    }

    /// v1.5.0 Phase D — New grant materializes one row with expected
    /// values (PG parity).
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn pg_project_new_grant_materializes_row() {
        use crate::federation::trust_grant::TrustPurpose;
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let granter_signing = SigningKey::from_bytes(&[0x71; 32]);
        let granter_b64 = pubkey_b64(&granter_signing);
        let grantee_b64 = pubkey_b64(&SigningKey::from_bytes(&[0x72; 32]));
        let tenant = format!("pg-pd-new-{}", Uuid::new_v4().simple());
        pg_cleanup_trust_grants(&backend, &tenant).await;
        pg_seed_federation_key(&backend, &granter_b64).await;
        pg_seed_federation_key(&backend, &grantee_b64).await;

        let entry = build_trust_grant_entry_pg(
            &granter_signing,
            &tenant,
            1,
            GENESIS_PREV_HASH.to_vec(),
            &grantee_b64,
            TrustPurpose::Contribution,
            "proposal:registry_vouch",
            None,
        );
        backend.record_entry(entry.clone()).await.unwrap();

        let client = backend.pool().get().await.unwrap();
        let row = client
            .query_one(
                "SELECT grantee_key, granter_key, purpose, scope, \
                        chain_event_id, tenant_id, \
                        revoked_at, revoked_by, expires_at \
                 FROM cirislens.federation_trust_grants \
                 WHERE grantee_key = $1 AND granter_key = $2 \
                   AND purpose = $3 AND scope = $4",
                &[
                    &grantee_b64,
                    &granter_b64,
                    &"contribution",
                    &"proposal:registry_vouch",
                ],
            )
            .await
            .unwrap();
        let chain_event_id: i64 = row.get("chain_event_id");
        let tenant_id: String = row.get("tenant_id");
        let revoked_at: Option<chrono::DateTime<chrono::Utc>> = row.get("revoked_at");
        let revoked_by: Option<String> = row.get("revoked_by");
        let expires_at: Option<chrono::DateTime<chrono::Utc>> = row.get("expires_at");
        assert_eq!(chain_event_id, 1);
        assert_eq!(tenant_id, tenant);
        assert!(revoked_at.is_none());
        assert!(revoked_by.is_none());
        assert!(expires_at.is_none());
        assert_eq!(pg_count_grants(&backend, &tenant).await, 1);

        pg_cleanup_trust_grants(&backend, &tenant).await;
    }

    /// v1.5.0 Phase D — Re-issuance UPSERTs (row count stays 1; chain
    /// pointers refresh).
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn pg_project_re_issuance_updates_existing_row() {
        use crate::federation::trust_grant::TrustPurpose;
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let granter_signing = SigningKey::from_bytes(&[0x73; 32]);
        let granter_b64 = pubkey_b64(&granter_signing);
        let grantee_b64 = pubkey_b64(&SigningKey::from_bytes(&[0x74; 32]));
        let tenant = format!("pg-pd-reissue-{}", Uuid::new_v4().simple());
        pg_cleanup_trust_grants(&backend, &tenant).await;
        pg_seed_federation_key(&backend, &granter_b64).await;
        pg_seed_federation_key(&backend, &grantee_b64).await;

        let e1 = build_trust_grant_entry_pg(
            &granter_signing,
            &tenant,
            1,
            GENESIS_PREV_HASH.to_vec(),
            &grantee_b64,
            TrustPurpose::Technical,
            "manifest:stable",
            None,
        );
        backend.record_entry(e1.clone()).await.unwrap();

        let client = backend.pool().get().await.unwrap();
        let original_grant_id: uuid::Uuid = client
            .query_one(
                "SELECT grant_id FROM cirislens.federation_trust_grants \
                 WHERE grantee_key = $1 AND granter_key = $2 \
                   AND purpose = 'technical' AND scope = 'manifest:stable'",
                &[&grantee_b64, &granter_b64],
            )
            .await
            .unwrap()
            .get("grant_id");

        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        let far_future = chrono::Utc::now() + chrono::Duration::hours(48);
        let e2 = build_trust_grant_entry_pg(
            &granter_signing,
            &tenant,
            2,
            e1.entry_hash.clone(),
            &grantee_b64,
            TrustPurpose::Technical,
            "manifest:stable",
            Some(far_future),
        );
        backend.record_entry(e2.clone()).await.unwrap();

        let row = client
            .query_one(
                "SELECT grant_id, chain_event_id, expires_at, revoked_at, revoked_by \
                 FROM cirislens.federation_trust_grants \
                 WHERE grantee_key = $1 AND granter_key = $2 \
                   AND purpose = 'technical' AND scope = 'manifest:stable'",
                &[&grantee_b64, &granter_b64],
            )
            .await
            .unwrap();
        let new_grant_id: uuid::Uuid = row.get("grant_id");
        let chain_event_id: i64 = row.get("chain_event_id");
        let expires_at: Option<chrono::DateTime<chrono::Utc>> = row.get("expires_at");
        let revoked_at: Option<chrono::DateTime<chrono::Utc>> = row.get("revoked_at");
        let revoked_by: Option<String> = row.get("revoked_by");
        assert_eq!(
            new_grant_id, original_grant_id,
            "grant_id stable across re-issuance"
        );
        assert_eq!(chain_event_id, 2, "chain_event_id refreshed");
        assert!(expires_at.is_some(), "expires_at populated");
        assert!(revoked_at.is_none(), "future expiry is not revocation");
        assert!(revoked_by.is_none());
        assert_eq!(pg_count_grants(&backend, &tenant).await, 1);

        pg_cleanup_trust_grants(&backend, &tenant).await;
    }

    /// v1.5.0 Phase D — Revocation (expires_at <= NOW()) sets
    /// revoked_at + revoked_by (PG parity).
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn pg_project_revocation_sets_revoked_at() {
        use crate::federation::trust_grant::TrustPurpose;
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let granter_signing = SigningKey::from_bytes(&[0x75; 32]);
        let granter_b64 = pubkey_b64(&granter_signing);
        let grantee_b64 = pubkey_b64(&SigningKey::from_bytes(&[0x76; 32]));
        let tenant = format!("pg-pd-revoke-{}", Uuid::new_v4().simple());
        pg_cleanup_trust_grants(&backend, &tenant).await;
        pg_seed_federation_key(&backend, &granter_b64).await;
        pg_seed_federation_key(&backend, &grantee_b64).await;

        let e1 = build_trust_grant_entry_pg(
            &granter_signing,
            &tenant,
            1,
            GENESIS_PREV_HASH.to_vec(),
            &grantee_b64,
            TrustPurpose::Deferral,
            "medical_deferral",
            None,
        );
        backend.record_entry(e1.clone()).await.unwrap();

        let past = chrono::Utc::now() - chrono::Duration::seconds(60);
        let e2 = build_trust_grant_entry_pg(
            &granter_signing,
            &tenant,
            2,
            e1.entry_hash.clone(),
            &grantee_b64,
            TrustPurpose::Deferral,
            "medical_deferral",
            Some(past),
        );
        backend.record_entry(e2.clone()).await.unwrap();

        let client = backend.pool().get().await.unwrap();
        let row = client
            .query_one(
                "SELECT revoked_at, revoked_by \
                 FROM cirislens.federation_trust_grants \
                 WHERE grantee_key = $1 AND granter_key = $2 \
                   AND purpose = 'deferral' AND scope = 'medical_deferral'",
                &[&grantee_b64, &granter_b64],
            )
            .await
            .unwrap();
        let revoked_at: Option<chrono::DateTime<chrono::Utc>> = row.get("revoked_at");
        let revoked_by: Option<String> = row.get("revoked_by");
        assert!(revoked_at.is_some(), "revocation sets revoked_at");
        assert_eq!(
            revoked_by.as_deref(),
            Some(granter_b64.as_str()),
            "revoked_by = granter"
        );
        assert_eq!(pg_count_grants(&backend, &tenant).await, 1);

        pg_cleanup_trust_grants(&backend, &tenant).await;
    }

    /// v1.5.0 Phase D — Cross-tenant collapse via UNIQUE constraint
    /// (PG parity with SQLite `project_cross_tenant_collapses…`).
    /// FSD §3.6: UNIQUE is `(grantee_key, granter_key, purpose, scope)`
    /// — no tenant_id qualifier — so a same-tuple emit under tenant-B
    /// UPDATES the tenant-A row.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn pg_project_cross_tenant_collapses_per_unique_constraint() {
        use crate::federation::trust_grant::TrustPurpose;
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let granter_signing = SigningKey::from_bytes(&[0x79; 32]);
        let granter_b64 = pubkey_b64(&granter_signing);
        let grantee_b64 = pubkey_b64(&SigningKey::from_bytes(&[0x7A; 32]));
        let tenant_a = format!("pg-pd-mt-A-{}", Uuid::new_v4().simple());
        let tenant_b = format!("pg-pd-mt-B-{}", Uuid::new_v4().simple());
        pg_cleanup_trust_grants(&backend, &tenant_a).await;
        pg_cleanup_trust_grants(&backend, &tenant_b).await;
        pg_seed_federation_key(&backend, &granter_b64).await;
        pg_seed_federation_key(&backend, &grantee_b64).await;

        let a1 = build_trust_grant_entry_pg(
            &granter_signing,
            &tenant_a,
            1,
            GENESIS_PREV_HASH.to_vec(),
            &grantee_b64,
            TrustPurpose::Contribution,
            "proposal:registry_vouch",
            None,
        );
        backend.record_entry(a1.clone()).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        let b1 = build_trust_grant_entry_pg(
            &granter_signing,
            &tenant_b,
            1,
            GENESIS_PREV_HASH.to_vec(),
            &grantee_b64,
            TrustPurpose::Contribution,
            "proposal:registry_vouch",
            None,
        );
        backend.record_entry(b1.clone()).await.unwrap();

        let client = backend.pool().get().await.unwrap();
        // One row total — UPSERT collapses both emits.
        let total: i64 = client
            .query_one(
                "SELECT COUNT(*)::BIGINT FROM cirislens.federation_trust_grants \
                 WHERE grantee_key = $1 AND granter_key = $2 \
                   AND purpose = 'contribution' AND scope = 'proposal:registry_vouch'",
                &[&grantee_b64, &granter_b64],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(total, 1, "cross-tenant emits collapse via UPSERT");
        let row_tenant: String = client
            .query_one(
                "SELECT tenant_id FROM cirislens.federation_trust_grants \
                 WHERE grantee_key = $1 AND granter_key = $2 \
                   AND purpose = 'contribution' AND scope = 'proposal:registry_vouch'",
                &[&grantee_b64, &granter_b64],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(row_tenant, tenant_b, "latest emit wins on tenant_id");

        pg_cleanup_trust_grants(&backend, &tenant_a).await;
        pg_cleanup_trust_grants(&backend, &tenant_b).await;
    }

    /// v1.5.0 Phase D — Self-grant rejected with Error::TrustGrant
    /// (PG parity).
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn pg_project_self_grant_rejected() {
        use crate::federation::trust_grant::TrustPurpose;
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let granter_signing = SigningKey::from_bytes(&[0x77; 32]);
        let granter_b64 = pubkey_b64(&granter_signing);
        let tenant = format!("pg-pd-self-{}", Uuid::new_v4().simple());
        pg_cleanup_trust_grants(&backend, &tenant).await;
        pg_seed_federation_key(&backend, &granter_b64).await;

        let entry = build_trust_grant_entry_pg(
            &granter_signing,
            &tenant,
            1,
            GENESIS_PREV_HASH.to_vec(),
            &granter_b64, // grantee == granter
            TrustPurpose::Service,
            "service:llm",
            None,
        );
        let err = backend.record_entry(entry).await.unwrap_err();
        assert!(
            matches!(err, Error::TrustGrant(_)),
            "expected Error::TrustGrant, got {err:?}"
        );
        assert_eq!(
            pg_count_grants(&backend, &tenant).await,
            0,
            "no projection row materialized"
        );
        pg_cleanup_trust_grants(&backend, &tenant).await;
    }

    /// v1.5.0 Phase D — Malformed payload surfaces Error::TrustGrant
    /// while the chain row already stands (PG parity).
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn pg_project_malformed_payload_surfaces_error() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let granter_signing = SigningKey::from_bytes(&[0x78; 32]);
        let tenant = format!("pg-pd-malformed-{}", Uuid::new_v4().simple());
        pg_cleanup_trust_grants(&backend, &tenant).await;

        let mut entry = AuditEntry {
            entry_id: Uuid::new_v4().to_string(),
            sequence_number: 1,
            tenant_id: tenant.clone(),
            actor_id: pubkey_b64(&granter_signing),
            action_type: "trust_granted".into(),
            subject_kind: crate::federation::trust_grant::TRUST_GRANT_SUBJECT_KIND.into(),
            subject_id: "irrelevant".into(),
            payload: serde_json::json!({"junk": "value"}),
            prev_hash: GENESIS_PREV_HASH.to_vec(),
            entry_hash: vec![],
            recorded_at: super::super::verify::truncate_to_micros(Utc::now()),
            signature: String::new(),
        };
        let hash = compute_entry_hash(&entry).unwrap();
        entry.entry_hash = hash.to_vec();
        let canonical = super::super::verify::canonical_bytes_for_entry(&entry).unwrap();
        let sig = granter_signing.sign(&canonical);
        entry.signature = B64.encode(sig.to_bytes());

        let err = backend.record_entry(entry).await.unwrap_err();
        assert!(
            matches!(err, Error::TrustGrant(_)),
            "expected Error::TrustGrant, got {err:?}"
        );

        // Chain row stands (option-(b)).
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
        assert_eq!(page.items.len(), 1);
        pg_cleanup_trust_grants(&backend, &tenant).await;
    }
}
