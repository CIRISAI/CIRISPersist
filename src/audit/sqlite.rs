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
    /// Optional local signer for the v1.5.0 Merkle transparency
    /// hook. Mirror of `PostgresBackend.merkle_signer`. When
    /// configured, every committed audit entry is appended to the
    /// tenant's `TransparencyLog<AuditLeaf>` and an STH is signed +
    /// stored. When `None`, the Merkle hook is a no-op. Wired by the
    /// Engine layer at construction (Phase G/H).
    merkle_signer: std::sync::RwLock<Option<Arc<crate::signing::LocalSigner>>>,
}

impl SqliteAuditBackend {
    /// Construct from a shared connection handle (typically
    /// `SqliteBackend::conn_handle()`). Merkle hook starts disabled
    /// — call [`Self::set_merkle_signer`] to opt in.
    pub fn new(conn: Arc<Mutex<Connection>>) -> Self {
        Self {
            conn,
            merkle_signer: std::sync::RwLock::new(None),
        }
    }

    /// Install the Merkle-hook signer for v1.5.0 audit-service
    /// transparency. Engine layer wires this in at construction with
    /// `Arc::clone(&self.local_signer)`. Passing `None` disables
    /// the hook (no-op path). Idempotent.
    pub fn set_merkle_signer(&self, signer: Option<Arc<crate::signing::LocalSigner>>) {
        let mut guard = self
            .merkle_signer
            .write()
            .unwrap_or_else(|p| p.into_inner());
        *guard = signer;
    }

    /// Snapshot the currently-installed Merkle signer (Phase C
    /// ingest path uses this to gate the hook).
    pub fn merkle_signer(&self) -> Option<Arc<crate::signing::LocalSigner>> {
        let guard = self.merkle_signer.read().unwrap_or_else(|p| p.into_inner());
        guard.clone()
    }

    /// Shared connection handle — exposed so the Phase C Merkle hook
    /// can build a tenant-scoped [`crate::audit::merkle_store::SqliteMerkleStore`]
    /// from `&self`.
    pub(crate) fn conn_handle(&self) -> Arc<Mutex<Connection>> {
        self.conn.clone()
    }
}

/// v1.5.0 Phase C — Merkle transparency hook for the SQLite audit
/// path. Parity with the PG `merkle_hook_pg` in `audit::postgres`:
/// chain commit FIRST, Merkle hook SECOND (option (b) from the
/// Phase C plan). See `merkle_hook_pg` rustdoc for the full
/// atomicity rationale.
async fn merkle_hook_sqlite(
    backend: &SqliteAuditBackend,
    entry: &super::types::AuditEntry,
    chain_event_id: i64,
) -> Result<(), Error> {
    use super::merkle_leaf::AuditLeaf;
    use super::merkle_store::{log_id_for_tenant, SqliteMerkleStore};
    use ciris_verify_core::transparency::{SignedTreeHead, TransparencyLog, TransparencyStore};
    use std::sync::Arc as StdArc;

    let Some(signer) = backend.merkle_signer() else {
        // No signer → no-op. CIRIS-RED / unconfigured-deployment shape.
        return Ok(());
    };

    let conn = backend.conn_handle();
    let handle = tokio::runtime::Handle::current();
    let tenant_id = entry.tenant_id.clone();
    let leaf = AuditLeaf::with_chain_event_id(entry.clone(), chain_event_id);
    let log_id = log_id_for_tenant(&tenant_id);

    let store: StdArc<dyn TransparencyStore<AuditLeaf>> =
        StdArc::new(SqliteMerkleStore::new(conn, handle, tenant_id));
    let log = TransparencyLog::<AuditLeaf>::for_log(log_id.clone(), store.clone());

    // 1. Append + compute tree_size + merkle_root in a blocking
    //    thread (sync TransparencyStore trait calls `runtime.block_on`
    //    inside the SqliteMerkleStore — would panic on a tokio worker).
    let log_for_block = log;
    let leaf_for_block = leaf;
    let head_jh = tokio::task::spawn_blocking(
        move || -> Result<(u64, [u8; 32]), ciris_verify_core::transparency::TransparencyError> {
            let _idx = log_for_block.append(leaf_for_block)?;
            let ts = log_for_block.tree_size()?;
            let root = log_for_block.merkle_root()?;
            Ok((ts, root))
        },
    );
    let (tree_size, root_hash) = head_jh
        .await
        .map_err(|e| Error::Merkle(format!("append join: {e}")))?
        .map_err(|e| Error::Merkle(format!("append: {e}")))?;

    // 2. Sign STH via LocalSigner::sign_hybrid (async).
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

    // 3. Persist the STH (sync trait → spawn_blocking).
    let store_for_store = store;
    let sth_for_store = sth;
    let store_jh = tokio::task::spawn_blocking(
        move || -> Result<(), ciris_verify_core::transparency::TransparencyError> {
            store_for_store.store_sth(&sth_for_store)
        },
    );
    store_jh
        .await
        .map_err(|e| Error::Merkle(format!("store_sth join: {e}")))?
        .map_err(|e| Error::Merkle(format!("store_sth: {e}")))?;

    Ok(())
}

/// v1.5.0 Phase D — TrustGrant projection hook (SQLite parity with
/// `project_trust_grant_pg`). UPSERTs `federation_trust_grants` keyed
/// by `(grantee_key, granter_key, purpose, scope)` per FSD §3.6. On
/// SQLite the table is bare (no `cirislens.` schema prefix). Same
/// out-of-transaction stance as the Merkle hook (option (b) from
/// Phase C).
async fn project_trust_grant_sqlite(
    backend: &SqliteAuditBackend,
    entry: &AuditEntry,
    chain_event_id: i64,
) -> Result<(), Error> {
    use crate::federation::trust_grant::TrustGrantPayload;
    use rusqlite::params;
    use uuid::Uuid;

    let payload: TrustGrantPayload = serde_json::from_value(entry.payload.clone())
        .map_err(|e| Error::TrustGrant(format!("payload deserialize: {e}")))?;

    let granter_key = entry.actor_id.clone();
    let grantee_key = payload.grantee_key.clone();

    if granter_key == grantee_key {
        return Err(Error::TrustGrant(
            "self-grant rejected (granter == grantee)".into(),
        ));
    }

    let purpose_str = payload.purpose.as_str().to_string();
    let scope = payload.scope.clone();
    let chain_event_hash = entry.entry_hash.clone();
    let granted_at = fmt_datetime(entry.recorded_at);
    let expires_at_str = payload.expires_at.map(fmt_datetime);
    let tenant_id = entry.tenant_id.clone();
    // SQLite has no gen_random_uuid(); the V021 SQLite schema marks
    // grant_id as TEXT PRIMARY KEY with caller-generated UUID. On
    // re-issuance we don't actually need the new uuid (UPSERT keeps
    // the existing row's grant_id), but we still need a value to
    // attempt the INSERT half of `INSERT … ON CONFLICT DO UPDATE`.
    let new_grant_id = Uuid::new_v4().to_string();

    let conn = backend.conn_handle();
    tokio::task::spawn_blocking(move || -> Result<(), Error> {
        let guard = conn.blocking_lock();
        // Emulate the Postgres revocation rule:
        //   revoked_at = CASE WHEN expires_at <= NOW() THEN NOW()
        //                ELSE NULL END
        //   revoked_by = CASE WHEN expires_at <= NOW() THEN granter
        //                ELSE NULL END
        // SQLite's strftime returns the format we use for the column
        // (RFC 3339-ish TEXT). `expires_at` is text; lexical
        // comparison works because all timestamps are normalized to
        // UTC `Z`-suffixed RFC 3339 (see `fmt_datetime`).
        // We compute the projected revoked_at / revoked_by values in
        // Rust to keep the SQL portable. `now` is captured once so
        // CHECK (`revoked_at IS NULL OR revoked_by IS NOT NULL`) is
        // satisfied transactionally.
        let now_str = fmt_datetime(chrono::Utc::now());
        let is_revocation = expires_at_str
            .as_deref()
            .map(|e| e <= now_str.as_str())
            .unwrap_or(false);
        let (revoked_at_param, revoked_by_param): (Option<String>, Option<String>) =
            if is_revocation {
                (Some(now_str.clone()), Some(granter_key.clone()))
            } else {
                (None, None)
            };

        guard
            .execute(
                "INSERT INTO federation_trust_grants (\
                    grant_id, grantee_key, granter_key, purpose, scope, \
                    granted_at, expires_at, revoked_at, revoked_by, \
                    chain_event_id, chain_event_hash, tenant_id\
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12) \
                 ON CONFLICT (grantee_key, granter_key, purpose, scope) DO UPDATE SET \
                    granted_at = excluded.granted_at, \
                    expires_at = excluded.expires_at, \
                    chain_event_id = excluded.chain_event_id, \
                    chain_event_hash = excluded.chain_event_hash, \
                    tenant_id = excluded.tenant_id, \
                    revoked_at = excluded.revoked_at, \
                    revoked_by = excluded.revoked_by",
                params![
                    new_grant_id,
                    grantee_key,
                    granter_key,
                    purpose_str,
                    scope,
                    granted_at,
                    expires_at_str,
                    revoked_at_param,
                    revoked_by_param,
                    chain_event_id,
                    chain_event_hash,
                    tenant_id,
                ],
            )
            .map_err(|e| Error::TrustGrant(format!("UPSERT federation_trust_grants: {e}")))?;
        Ok(())
    })
    .await
    .map_err(|e| Error::TrustGrant(format!("spawn_blocking join: {e}")))??;

    Ok(())
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
        // Phase C: clone the entry up-front so the Merkle hook below
        // can use it after the chain-commit closure consumes its
        // copy. The clone is cheap (small AuditEntry; payload is
        // JSON Value).
        let entry_for_chain = entry.clone();
        tokio::task::spawn_blocking(move || -> Result<(), Error> {
            let entry = entry_for_chain;
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
                // v1.5.4 — bridge entry permitted per
                // docs/AUDIT_CHAIN_BRIDGE.md §1 (see PG comment).
                if entry.prev_hash.as_slice() != GENESIS_PREV_HASH.as_slice() {
                    tracing::info!(
                        tenant_id = %entry.tenant_id,
                        prev_hash_hex = %hex::encode(&entry.prev_hash),
                        "audit chain bridge entry — non-zero prev_hash on sequence_number=1"
                    );
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
        .map_err(|e| Error::Backend(format!("spawn_blocking join: {e}")))??;

        // v1.5.0 Phase C — Merkle transparency hook (SQLite parity).
        // Runs only when a local signer is installed; otherwise this
        // is a no-op and chain semantics are unchanged. Same option
        // (b) atomicity stance as PG: chain is source of truth, Merkle
        // is projection (see `merkle_hook_sqlite` rustdoc + the PG
        // sibling helper).
        merkle_hook_sqlite(self, &entry, entry.sequence_number).await?;

        // v1.5.0 Phase D — TrustGrant projection (SQLite parity with
        // `project_trust_grant_pg`). Gated on subject_kind.
        if entry.subject_kind == crate::federation::trust_grant::TRUST_GRANT_SUBJECT_KIND {
            project_trust_grant_sqlite(self, &entry, entry.sequence_number).await?;
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
            // An empty `last_id` is the "no cursor yet — first page"
            // sentinel; skip the keyset predicate entirely rather
            // than emitting a degenerate `< (ts, '')` compare. Keeps
            // the two backends behaviourally identical
            // (CIRISPersist#86).
            if !cur.last_id.is_empty() {
                params.push(SqlValue::Text(fmt_datetime(cur.last_ts)));
                params.push(SqlValue::Text(cur.last_id.clone()));
                where_parts.push("(recorded_at, entry_id) < (?, ?)".to_string());
            }
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
        // Phase C: clone the entry so the Merkle hook below can use it
        // after the chain-commit closure consumes its copy.
        let entry_for_chain = entry.clone();
        let result = tokio::task::spawn_blocking(move || -> Result<ClaimResult<AuditEventRef>, Error> {
            let entry = entry_for_chain;
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
                // v1.5.4 — bridge entry permitted per
                // docs/AUDIT_CHAIN_BRIDGE.md §1 (see PG comment).
                if entry.prev_hash.as_slice() != GENESIS_PREV_HASH.as_slice() {
                    tracing::info!(
                        tenant_id = %entry.tenant_id,
                        prev_hash_hex = %hex::encode(&entry.prev_hash),
                        "audit chain bridge entry — non-zero prev_hash on sequence_number=1"
                    );
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
        .map_err(|e| Error::Backend(format!("spawn_blocking join: {e}")))??;

        // v1.5.0 Phase C — Merkle hook on the newly-stored path only
        // (same gating rule as the PG impl). On `AlreadyClaimed` the
        // existing row's Merkle leaf already landed at the original
        // call; re-appending here would double-count.
        //
        // v1.5.0 Phase D — TrustGrant projection same gating: only
        // on the newly-stored path. AlreadyClaimed → the prior call
        // already ran the projection (or, if Phase D wasn't deployed
        // at that prior time, Phase I's backfill will fill it in).
        if let ClaimResult::Stored(_) = &result {
            merkle_hook_sqlite(self, &entry, entry.sequence_number).await?;
            if entry.subject_kind == crate::federation::trust_grant::TRUST_GRANT_SUBJECT_KIND {
                project_trust_grant_sqlite(self, &entry, entry.sequence_number).await?;
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

    async fn next_chain_position(
        &self,
        tenant_id: &str,
    ) -> Result<super::service::ChainPosition, Error> {
        if tenant_id.is_empty() {
            return Err(Error::InvalidArgument("tenant_id must be non-empty".into()));
        }
        let tenant_owned = tenant_id.to_owned();
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> Result<super::service::ChainPosition, Error> {
            let guard = conn.blocking_lock();
            let row_opt: Option<(i64, Vec<u8>)> = guard
                .query_row(
                    "SELECT sequence_number, entry_hash FROM cirislens_audit_log \
                     WHERE tenant_id = ?1 \
                     ORDER BY sequence_number DESC LIMIT 1",
                    params![tenant_owned],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(|e| map_sqlite_error(e, "next_chain_position tail probe"))?;
            if let Some((prev_seq, prev_hash_vec)) = row_opt {
                let prev_hash: [u8; 32] = prev_hash_vec.as_slice().try_into().map_err(|_| {
                    Error::Backend(format!(
                        "entry_hash column expected 32 bytes, got {}",
                        prev_hash_vec.len()
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
        })
        .await
        .map_err(|e| Error::Backend(format!("spawn_blocking join: {e}")))?
    }

    async fn current_sth(
        &self,
        tenant_id: &str,
    ) -> Result<Option<ciris_verify_core::transparency::SignedTreeHead>, Error> {
        use super::merkle_leaf::AuditLeaf;
        use super::merkle_store::SqliteMerkleStore;
        use ciris_verify_core::transparency::{SignedTreeHead, TransparencyStore};

        if tenant_id.is_empty() {
            return Err(Error::InvalidArgument("tenant_id must be non-empty".into()));
        }
        let conn = self.conn_handle();
        let handle = tokio::runtime::Handle::current();
        let tenant_owned = tenant_id.to_owned();
        let store: Arc<dyn TransparencyStore<AuditLeaf>> =
            Arc::new(SqliteMerkleStore::new(conn, handle, tenant_owned));
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
        tenant_id: &str,
        chain_event_id: i64,
    ) -> Result<Option<uuid::Uuid>, Error> {
        // Lookup is tenant-scoped — matches the Postgres impl. SQLite
        // tests historically passed because each test gets a fresh
        // in-memory DB; cross-tenant collisions are still possible in
        // production once multiple tenants share a SQLite file. The
        // V045 SQLite migration mirrors the PG UNIQUE constraint.
        let conn = self.conn_handle();
        let tenant_owned = tenant_id.to_owned();
        let jh: tokio::task::JoinHandle<Result<Option<String>, rusqlite::Error>> =
            tokio::task::spawn_blocking(move || {
                let guard = conn.blocking_lock();
                guard
                    .query_row(
                        "SELECT grant_id FROM federation_trust_grants \
                         WHERE tenant_id = ?1 AND chain_event_id = ?2",
                        rusqlite::params![tenant_owned, chain_event_id],
                        |row| row.get::<_, String>(0),
                    )
                    .map(Some)
                    .or_else(|e| match e {
                        rusqlite::Error::QueryReturnedNoRows => Ok(None),
                        other => Err(other),
                    })
            });
        let opt_str = jh
            .await
            .map_err(|e| Error::Backend(format!("lookup_grant_id join: {e}")))?
            .map_err(|e| Error::Backend(format!("lookup_grant_id: {e}")))?;
        match opt_str {
            None => Ok(None),
            Some(s) => uuid::Uuid::parse_str(&s)
                .map(Some)
                .map_err(|e| Error::Backend(format!("decode grant_id: {e}"))),
        }
    }

    // ── v1.5.0 Phase F+G — projection reads + Merkle proofs ─────────

    async fn get_trust_grant(
        &self,
        grant_id: uuid::Uuid,
    ) -> Result<Option<crate::federation::trust_grant::TrustGrantRow>, Error> {
        let conn = self.conn_handle();
        let grant_id_str = grant_id.to_string();
        let jh: tokio::task::JoinHandle<
            Result<Option<crate::federation::trust_grant::TrustGrantRow>, Error>,
        > = tokio::task::spawn_blocking(move || {
            let guard = conn.blocking_lock();
            let mut stmt = guard
                .prepare(
                    "SELECT grant_id, grantee_key, granter_key, purpose, scope, \
                            granted_at, expires_at, revoked_at, revoked_by, \
                            chain_event_id, chain_event_hash, tenant_id \
                     FROM federation_trust_grants \
                     WHERE grant_id = ?1",
                )
                .map_err(|e| Error::Backend(format!("prepare get_trust_grant: {e}")))?;
            let row_opt = stmt
                .query_row(
                    rusqlite::params![grant_id_str],
                    decode_trust_grant_row_sqlite,
                )
                .optional()
                .map_err(|e| Error::Backend(format!("query get_trust_grant: {e}")))?;
            match row_opt {
                None => Ok(None),
                Some(r) => Ok(Some(r?)),
            }
        });
        jh.await
            .map_err(|e| Error::Backend(format!("get_trust_grant join: {e}")))?
    }

    async fn lookup_trust_grant(
        &self,
        grantee_key: &str,
        purpose: crate::federation::trust_grant::TrustPurpose,
        scope: &str,
        include_revoked: bool,
        include_expired: bool,
    ) -> Result<Vec<crate::federation::trust_grant::TrustGrantRow>, Error> {
        let conn = self.conn_handle();
        let grantee = grantee_key.to_owned();
        let purpose_str = purpose.as_str().to_owned();
        let scope = scope.to_owned();
        // Lexical comparison against an UTC-Z RFC3339 string is monotonic
        // — see fmt_datetime + parse_datetime locked above.
        let now_str = fmt_datetime(chrono::Utc::now());
        let jh: tokio::task::JoinHandle<
            Result<Vec<crate::federation::trust_grant::TrustGrantRow>, Error>,
        > = tokio::task::spawn_blocking(move || {
            let mut sql = String::from(
                "SELECT grant_id, grantee_key, granter_key, purpose, scope, \
                        granted_at, expires_at, revoked_at, revoked_by, \
                        chain_event_id, chain_event_hash, tenant_id \
                 FROM federation_trust_grants \
                 WHERE grantee_key = ?1 AND purpose = ?2 \
                   AND (scope = ?3 OR scope = '*')",
            );
            if !include_revoked {
                sql.push_str(" AND revoked_at IS NULL");
            }
            if !include_expired {
                sql.push_str(" AND (expires_at IS NULL OR expires_at > ?4)");
            }
            sql.push_str(" ORDER BY granted_at DESC, grant_id");

            let guard = conn.blocking_lock();
            let mut stmt = guard
                .prepare(&sql)
                .map_err(|e| Error::Backend(format!("prepare lookup_trust_grant: {e}")))?;
            let mut out = Vec::new();
            if include_expired {
                let rows = stmt
                    .query_map(
                        rusqlite::params![grantee, purpose_str, scope],
                        decode_trust_grant_row_sqlite,
                    )
                    .map_err(|e| Error::Backend(format!("query lookup_trust_grant: {e}")))?;
                for r in rows {
                    out.push(
                        r.map_err(|e| Error::Backend(format!("row lookup_trust_grant: {e}")))??,
                    );
                }
            } else {
                let rows = stmt
                    .query_map(
                        rusqlite::params![grantee, purpose_str, scope, now_str],
                        decode_trust_grant_row_sqlite,
                    )
                    .map_err(|e| Error::Backend(format!("query lookup_trust_grant: {e}")))?;
                for r in rows {
                    out.push(
                        r.map_err(|e| Error::Backend(format!("row lookup_trust_grant: {e}")))??,
                    );
                }
            }
            Ok(out)
        });
        jh.await
            .map_err(|e| Error::Backend(format!("lookup_trust_grant join: {e}")))?
    }

    async fn list_trust_grants(
        &self,
        filter: crate::federation::trust_grant::TrustGrantFilter,
    ) -> Result<Vec<crate::federation::trust_grant::TrustGrantRow>, Error> {
        let conn = self.conn_handle();
        let now_str = fmt_datetime(chrono::Utc::now());
        let jh: tokio::task::JoinHandle<
            Result<Vec<crate::federation::trust_grant::TrustGrantRow>, Error>,
        > = tokio::task::spawn_blocking(move || {
            let mut sql = String::from(
                "SELECT grant_id, grantee_key, granter_key, purpose, scope, \
                        granted_at, expires_at, revoked_at, revoked_by, \
                        chain_event_id, chain_event_hash, tenant_id \
                 FROM federation_trust_grants",
            );
            let mut where_clauses: Vec<String> = Vec::new();
            let mut params: Vec<SqlValue> = Vec::new();
            if let Some(g) = filter.grantee_key.as_ref() {
                where_clauses.push(format!("grantee_key = ?{}", params.len() + 1));
                params.push(SqlValue::Text(g.clone()));
            }
            if let Some(g) = filter.granter_key.as_ref() {
                where_clauses.push(format!("granter_key = ?{}", params.len() + 1));
                params.push(SqlValue::Text(g.clone()));
            }
            if let Some(p) = filter.purpose {
                where_clauses.push(format!("purpose = ?{}", params.len() + 1));
                params.push(SqlValue::Text(p.as_str().to_owned()));
            }
            if let Some(prefix) = filter.scope_prefix.as_ref() {
                where_clauses.push(format!("scope LIKE ?{}", params.len() + 1));
                params.push(SqlValue::Text(format!("{prefix}%")));
            }
            if !filter.include_revoked {
                where_clauses.push("revoked_at IS NULL".to_owned());
            }
            if !filter.include_expired {
                where_clauses.push(format!(
                    "(expires_at IS NULL OR expires_at > ?{})",
                    params.len() + 1
                ));
                params.push(SqlValue::Text(now_str.clone()));
            }
            if !where_clauses.is_empty() {
                sql.push_str(" WHERE ");
                sql.push_str(&where_clauses.join(" AND "));
            }
            sql.push_str(" ORDER BY granted_at DESC, grant_id");

            let guard = conn.blocking_lock();
            let mut stmt = guard
                .prepare(&sql)
                .map_err(|e| Error::Backend(format!("prepare list_trust_grants: {e}")))?;
            let rows = stmt
                .query_map(params_from_iter(params), decode_trust_grant_row_sqlite)
                .map_err(|e| Error::Backend(format!("query list_trust_grants: {e}")))?;
            let mut out = Vec::new();
            for r in rows {
                out.push(r.map_err(|e| Error::Backend(format!("row list_trust_grants: {e}")))??);
            }
            Ok(out)
        });
        jh.await
            .map_err(|e| Error::Backend(format!("list_trust_grants join: {e}")))?
    }

    async fn leaf_canonical_bytes_for_chain_event(
        &self,
        tenant_id: &str,
        chain_event_id: i64,
    ) -> Result<Option<Vec<u8>>, Error> {
        if tenant_id.is_empty() {
            return Err(Error::InvalidArgument("tenant_id must be non-empty".into()));
        }
        let conn = self.conn_handle();
        let tenant = tenant_id.to_owned();
        let jh: tokio::task::JoinHandle<Result<Option<Vec<u8>>, rusqlite::Error>> =
            tokio::task::spawn_blocking(move || {
                let guard = conn.blocking_lock();
                guard
                    .query_row(
                        "SELECT canonical_bytes FROM merkle_leaves \
                         WHERE tenant_id = ?1 AND chain_event_id = ?2",
                        rusqlite::params![tenant, chain_event_id],
                        |row| row.get::<_, Vec<u8>>(0),
                    )
                    .optional()
            });
        jh.await
            .map_err(|e| Error::Backend(format!("leaf_canonical_bytes join: {e}")))?
            .map_err(|e| Error::Backend(format!("leaf_canonical_bytes: {e}")))
    }

    async fn inclusion_proof_for_chain_event(
        &self,
        tenant_id: &str,
        chain_event_id: i64,
    ) -> Result<ciris_verify_core::transparency::MerkleProof, Error> {
        use super::merkle_leaf::AuditLeaf;
        use super::merkle_store::SqliteMerkleStore;
        use ciris_verify_core::transparency::{TransparencyLog, TransparencyStore};

        if tenant_id.is_empty() {
            return Err(Error::InvalidArgument("tenant_id must be non-empty".into()));
        }
        // Resolve chain_event_id → leaf_index.
        let conn = self.conn_handle();
        let tenant = tenant_id.to_owned();
        let tenant_for_lookup = tenant.clone();
        let leaf_idx_opt: tokio::task::JoinHandle<Result<Option<i64>, rusqlite::Error>> =
            tokio::task::spawn_blocking(move || {
                let guard = conn.blocking_lock();
                guard
                    .query_row(
                        "SELECT leaf_index FROM merkle_leaves \
                         WHERE tenant_id = ?1 AND chain_event_id = ?2",
                        rusqlite::params![tenant_for_lookup, chain_event_id],
                        |row| row.get::<_, i64>(0),
                    )
                    .optional()
            });
        let leaf_idx_i: i64 = leaf_idx_opt
            .await
            .map_err(|e| Error::Backend(format!("leaf_index lookup join: {e}")))?
            .map_err(|e| Error::Backend(format!("leaf_index lookup: {e}")))?
            .ok_or_else(|| {
                Error::NotFound(format!(
                    "no merkle_leaves row for tenant={tenant} chain_event_id={chain_event_id}"
                ))
            })?;
        let leaf_index =
            u64::try_from(leaf_idx_i).map_err(|_| Error::Backend("leaf_index negative".into()))?;

        let conn = self.conn_handle();
        let handle = tokio::runtime::Handle::current();
        let store: Arc<dyn TransparencyStore<AuditLeaf>> =
            Arc::new(SqliteMerkleStore::new(conn, handle, tenant.clone()));
        let log_id = super::merkle_store::log_id_for_tenant(&tenant);
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
        use super::merkle_leaf::AuditLeaf;
        use super::merkle_store::SqliteMerkleStore;
        use ciris_verify_core::transparency::{TransparencyLog, TransparencyStore};

        if tenant_id.is_empty() {
            return Err(Error::InvalidArgument("tenant_id must be non-empty".into()));
        }
        let conn = self.conn_handle();
        let handle = tokio::runtime::Handle::current();
        let tenant_owned = tenant_id.to_owned();
        let store: Arc<dyn TransparencyStore<AuditLeaf>> =
            Arc::new(SqliteMerkleStore::new(conn, handle, tenant_owned.clone()));
        let log_id = super::merkle_store::log_id_for_tenant(&tenant_owned);
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
        let conn = self.conn_handle();
        let local_pubkey = local_pubkey.to_owned();
        let jh: tokio::task::JoinHandle<Result<Vec<V020TrustRow>, Error>> =
            tokio::task::spawn_blocking(move || {
                let guard = conn.blocking_lock();
                let mut stmt = guard
                    .prepare(
                        "SELECT key_id, pubkey_ed25519_base64, trust_type, \
                                trust_relationship, trust_domains, \
                                trusted_at, expires_at \
                         FROM federation_keys \
                         WHERE trusted_by = ?1 \
                           AND trust_relationship IS NOT NULL \
                         ORDER BY trusted_at ASC, key_id ASC",
                    )
                    .map_err(|e| Error::Backend(format!("prepare v020 rows: {e}")))?;
                let rows = stmt
                    .query_map(
                        rusqlite::params![local_pubkey],
                        decode_v020_trust_row_sqlite,
                    )
                    .map_err(|e| Error::Backend(format!("query v020 rows: {e}")))?;
                let mut out: Vec<V020TrustRow> = Vec::new();
                for r in rows {
                    let inner = r.map_err(|e| Error::Backend(format!("row v020 rows: {e}")))??;
                    out.push(inner);
                }
                Ok(out)
            });
        jh.await
            .map_err(|e| Error::Backend(format!("v020 rows join: {e}")))?
    }
}

/// Decode one V020-shape row from `federation_keys` into a
/// [`V020TrustRow`]. Used by [`SqliteAuditBackend::read_v020_trust_rows_for_local`].
///
/// `trust_domains` is stored as a JSON-array string per V020 SQLite
/// dialect notes; `Some("")` and `None` both map to `None`. Empty
/// arrays map to `Some(vec![])` (legal per the SQLite schema, though
/// the API-layer `grant_trust` guard rejects Registry+empty).
fn decode_v020_trust_row_sqlite(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<Result<crate::federation::trust_grant::V020TrustRow, Error>> {
    use crate::federation::trust_grant::V020TrustRow;

    let key_id: String = row.get("key_id")?;
    let grantee_pubkey: String = row.get("pubkey_ed25519_base64")?;
    let trust_type: String = row.get("trust_type")?;
    let trust_relationship: String = row.get("trust_relationship")?;
    let trust_domains_text: Option<String> = row.get("trust_domains")?;
    let trusted_at_text: String = row.get("trusted_at")?;
    let expires_at_text: Option<String> = row.get("expires_at")?;

    Ok((|| {
        let trust_domains: Option<Vec<String>> = match trust_domains_text.as_deref() {
            None | Some("") => None,
            Some(s) => Some(
                serde_json::from_str::<Vec<String>>(s)
                    .map_err(|e| Error::Backend(format!("trust_domains decode: {e}")))?,
            ),
        };
        let trusted_at = parse_datetime(&trusted_at_text)?;
        let expires_at = expires_at_text.as_deref().map(parse_datetime).transpose()?;
        Ok(V020TrustRow {
            key_id,
            grantee_pubkey,
            trust_type,
            trust_relationship,
            trust_domains,
            trusted_at,
            expires_at,
        })
    })())
}

/// Decode one `federation_trust_grants` row into a [`TrustGrantRow`].
/// Used by `get_trust_grant`, `lookup_trust_grant`, `list_trust_grants`.
///
/// Wraps the outer `Result<T, Error>` inside the rusqlite row callback's
/// `Result<T, rusqlite::Error>` — the rusqlite callback can only fail
/// with rusqlite errors, but parse failures (TrustPurpose, UUID,
/// timestamp) are domain-level. We return `Ok(Err(Error))` so the
/// outer call site can `?` the inner error.
fn decode_trust_grant_row_sqlite(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<Result<crate::federation::trust_grant::TrustGrantRow, Error>> {
    use crate::federation::trust_grant::{TrustGrantRow, TrustPurpose};
    let grant_id_str: String = row.get("grant_id")?;
    let grantee_key: String = row.get("grantee_key")?;
    let granter_key: String = row.get("granter_key")?;
    let purpose_str: String = row.get("purpose")?;
    let scope: String = row.get("scope")?;
    let granted_at_str: String = row.get("granted_at")?;
    let expires_at_str: Option<String> = row.get("expires_at")?;
    let revoked_at_str: Option<String> = row.get("revoked_at")?;
    let revoked_by: Option<String> = row.get("revoked_by")?;
    let chain_event_id: i64 = row.get("chain_event_id")?;
    let chain_event_hash: Vec<u8> = row.get("chain_event_hash")?;
    let tenant_id: String = row.get("tenant_id")?;

    Ok((|| {
        let grant_id = uuid::Uuid::parse_str(&grant_id_str)
            .map_err(|e| Error::Backend(format!("decode grant_id: {e}")))?;
        let purpose = TrustPurpose::parse_str(&purpose_str)
            .ok_or_else(|| Error::Backend(format!("unknown purpose: {purpose_str}")))?;
        let granted_at = parse_datetime(&granted_at_str)?;
        let expires_at = expires_at_str.as_deref().map(parse_datetime).transpose()?;
        let revoked_at = revoked_at_str.as_deref().map(parse_datetime).transpose()?;
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
    })())
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
        let e1 = build_and_sign(
            &key,
            &tenant,
            1,
            GENESIS_PREV_HASH.to_vec(),
            "handler_action_task_complete",
        );
        audit.record_entry(e1.clone()).await.unwrap();

        // 2. Replay → rejected (ChainIntegrity OR Conflict).
        let replay = audit.record_entry(e1.clone()).await.unwrap_err();
        assert!(
            matches!(replay, Error::ChainIntegrity(_) | Error::Conflict(_)),
            "expected ChainIntegrity or Conflict on replay, got {replay:?}"
        );

        // 3. Sequence gap.
        let bad_gap = build_and_sign(
            &key,
            &tenant,
            3,
            e1.entry_hash.clone(),
            "handler_action_task_complete",
        );
        let gap_err = audit.record_entry(bad_gap).await.unwrap_err();
        assert!(matches!(gap_err, Error::ChainIntegrity(_)));

        // 4. Wrong prev_hash.
        let bad_prev = build_and_sign(
            &key,
            &tenant,
            2,
            vec![0xff; 32],
            "handler_action_task_complete",
        );
        let prev_err = audit.record_entry(bad_prev).await.unwrap_err();
        assert!(matches!(prev_err, Error::ChainIntegrity(_)));

        // 5. Correct continuation.
        let e2 = build_and_sign(&key, &tenant, 2, e1.entry_hash.clone(), "config_change");
        audit.record_entry(e2.clone()).await.unwrap();
        let e3 = build_and_sign(
            &key,
            &tenant,
            3,
            e2.entry_hash.clone(),
            "handler_action_task_complete",
        );
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

    /// CIRISPersist#86 — an `AuditCursor` with an empty `last_id` is
    /// the "no cursor yet — first page" sentinel (CIRISAgent's audit
    /// service builds exactly this on the first write of a process
    /// to read the chain head). It must return the first page, not
    /// apply a degenerate keyset predicate or raise.
    #[tokio::test]
    async fn list_entries_empty_cursor_returns_first_page() {
        let (_b, audit) = fresh_backend().await;
        let key = SigningKey::from_bytes(&[0xB2; 32]);
        let tenant = format!("audit-cursor-{}", Uuid::new_v4().simple());

        let e1 = build_and_sign(
            &key,
            &tenant,
            1,
            GENESIS_PREV_HASH.to_vec(),
            "handler_action_speak",
        );
        audit.record_entry(e1.clone()).await.unwrap();
        let e2 = build_and_sign(&key, &tenant, 2, e1.entry_hash.clone(), "config_change");
        audit.record_entry(e2.clone()).await.unwrap();

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
                .with_timezone(&chrono::Utc),
            last_id: String::new(),
        };
        let page = audit
            .list_entries(filter, Some(empty_cursor), 10)
            .await
            .expect("empty last_id must be accepted as the first-page sentinel");
        assert_eq!(page.items.len(), 2, "first page returns all entries");
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
        let entry = build_and_sign(
            &key,
            &tenant,
            1,
            GENESIS_PREV_HASH.to_vec(),
            "handler_action_task_complete",
        );
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
            action_type: "handler_action_task_complete".into(),
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

    // ────────────────────────────────────────────────────────────────
    // v1.5.0 Phase C — Merkle transparency hook tests (SQLite)
    // ────────────────────────────────────────────────────────────────

    /// Build a LocalSigner with PQC configured via in-memory seeds.
    /// Phase C's Merkle hook needs `sign_hybrid` (Ed25519 + ML-DSA-65),
    /// which requires a PQC signer; bare Ed25519-only signers trip the
    /// `PqcNotConfigured` path.
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

    async fn count_merkle_rows(audit: &SqliteAuditBackend, tenant: &str) -> (i64, i64) {
        let conn = audit.conn_handle();
        let tenant = tenant.to_owned();
        tokio::task::spawn_blocking(move || {
            let conn = conn.blocking_lock();
            let leaves: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM merkle_leaves WHERE tenant_id = ?1",
                    rusqlite::params![tenant],
                    |row| row.get(0),
                )
                .unwrap();
            let sth: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM merkle_sth_log WHERE tenant_id = ?1",
                    rusqlite::params![tenant],
                    |row| row.get(0),
                )
                .unwrap();
            (leaves, sth)
        })
        .await
        .unwrap()
    }

    /// v1.5.0 Phase C — when no signer is installed (default),
    /// `record_entry` is unchanged from v1.4.x: no rows land in
    /// merkle_leaves or merkle_sth_log. This is the CIRIS-RED /
    /// unconfigured-deployment / test path.
    #[tokio::test]
    async fn merkle_hook_disabled_when_signer_absent() {
        let (_b, audit) = fresh_backend().await;
        let key = SigningKey::from_bytes(&[0xC0; 32]);
        let tenant = format!("audit-merk-off-{}", Uuid::new_v4().simple());

        let e1 = build_and_sign(
            &key,
            &tenant,
            1,
            GENESIS_PREV_HASH.to_vec(),
            "handler_action_task_complete",
        );
        audit.record_entry(e1.clone()).await.unwrap();
        let e2 = build_and_sign(
            &key,
            &tenant,
            2,
            e1.entry_hash.clone(),
            "handler_action_task_complete",
        );
        audit.record_entry(e2.clone()).await.unwrap();

        let (leaves, sth) = count_merkle_rows(&audit, &tenant).await;
        assert_eq!(leaves, 0, "no signer → no merkle leaves");
        assert_eq!(sth, 0, "no signer → no STH rows");
    }

    /// v1.5.0 Phase C — when a signer is installed, every committed
    /// audit entry appends a leaf + signs + stores an STH. tree_size
    /// grows monotonically; one STH per leaf (every-append cadence
    /// per FSD §4.4).
    #[tokio::test]
    async fn merkle_hook_enabled_appends_and_signs() {
        let (_b, audit) = fresh_backend().await;
        audit.set_merkle_signer(Some(merkle_test_signer(0xD1)));
        let key = SigningKey::from_bytes(&[0xD1; 32]);
        let tenant = format!("audit-merk-on-{}", Uuid::new_v4().simple());

        let e1 = build_and_sign(
            &key,
            &tenant,
            1,
            GENESIS_PREV_HASH.to_vec(),
            "handler_action_task_complete",
        );
        audit.record_entry(e1.clone()).await.unwrap();
        let (l1, s1) = count_merkle_rows(&audit, &tenant).await;
        assert_eq!(l1, 1);
        assert_eq!(s1, 1);

        let e2 = build_and_sign(
            &key,
            &tenant,
            2,
            e1.entry_hash.clone(),
            "handler_action_task_complete",
        );
        audit.record_entry(e2.clone()).await.unwrap();
        let (l2, s2) = count_merkle_rows(&audit, &tenant).await;
        assert_eq!(l2, 2);
        assert_eq!(s2, 2);

        let e3 = build_and_sign(
            &key,
            &tenant,
            3,
            e2.entry_hash.clone(),
            "handler_action_task_complete",
        );
        audit.record_entry(e3.clone()).await.unwrap();
        let (l3, s3) = count_merkle_rows(&audit, &tenant).await;
        assert_eq!(l3, 3);
        assert_eq!(s3, 3);

        // tree_size monotonicity — every-append cadence means tree_size
        // grows by 1 per record_entry call.
        let conn = audit.conn_handle();
        let tenant_owned = tenant.clone();
        let sizes: Vec<i64> = tokio::task::spawn_blocking(move || {
            let conn = conn.blocking_lock();
            let mut stmt = conn
                .prepare("SELECT tree_size FROM merkle_sth_log WHERE tenant_id = ?1 ORDER BY tree_size ASC")
                .unwrap();
            let rows = stmt
                .query_map(rusqlite::params![tenant_owned], |row| row.get::<_, i64>(0))
                .unwrap();
            rows.map(|r| r.unwrap()).collect()
        })
        .await
        .unwrap();
        assert_eq!(sizes, vec![1, 2, 3]);
    }

    /// v1.5.0 Phase C — multi-tenant isolation: append under tenant-A
    /// must not change tenant-B's tree_size. Same SQLite connection
    /// hosts both chains.
    #[tokio::test]
    async fn merkle_hook_multi_tenant_isolated() {
        let (_b, audit) = fresh_backend().await;
        audit.set_merkle_signer(Some(merkle_test_signer(0xE2)));

        let key_a = SigningKey::from_bytes(&[0xEA; 32]);
        let key_b = SigningKey::from_bytes(&[0xEB; 32]);
        let tenant_a = format!("audit-merk-iso-A-{}", Uuid::new_v4().simple());
        let tenant_b = format!("audit-merk-iso-B-{}", Uuid::new_v4().simple());

        // Two leaves under tenant_a.
        let a1 = build_and_sign(
            &key_a,
            &tenant_a,
            1,
            GENESIS_PREV_HASH.to_vec(),
            "handler_action_task_complete",
        );
        audit.record_entry(a1.clone()).await.unwrap();
        let a2 = build_and_sign(
            &key_a,
            &tenant_a,
            2,
            a1.entry_hash.clone(),
            "handler_action_task_complete",
        );
        audit.record_entry(a2.clone()).await.unwrap();
        // One leaf under tenant_b.
        let b1 = build_and_sign(
            &key_b,
            &tenant_b,
            1,
            GENESIS_PREV_HASH.to_vec(),
            "handler_action_task_complete",
        );
        audit.record_entry(b1.clone()).await.unwrap();

        let (la, sa) = count_merkle_rows(&audit, &tenant_a).await;
        let (lb, sb) = count_merkle_rows(&audit, &tenant_b).await;
        assert_eq!((la, sa), (2, 2), "tenant_a: 2 leaves, 2 STH rows");
        assert_eq!((lb, sb), (1, 1), "tenant_b: 1 leaf, 1 STH row");
    }

    /// v1.5.0 Phase C — installing a signer mid-chain doesn't
    /// retroactively backfill (Phase I's job). New entries appended
    /// after enablement land in the Merkle tables; pre-enable entries
    /// stay in the audit chain only.
    #[tokio::test]
    async fn merkle_hook_install_mid_chain_only_affects_subsequent() {
        let (_b, audit) = fresh_backend().await;
        let key = SigningKey::from_bytes(&[0xF3; 32]);
        let tenant = format!("audit-merk-mid-{}", Uuid::new_v4().simple());

        // 2 entries with signer OFF.
        let e1 = build_and_sign(
            &key,
            &tenant,
            1,
            GENESIS_PREV_HASH.to_vec(),
            "handler_action_task_complete",
        );
        audit.record_entry(e1.clone()).await.unwrap();
        let e2 = build_and_sign(
            &key,
            &tenant,
            2,
            e1.entry_hash.clone(),
            "handler_action_task_complete",
        );
        audit.record_entry(e2.clone()).await.unwrap();
        let (l_before, _) = count_merkle_rows(&audit, &tenant).await;
        assert_eq!(l_before, 0);

        // Turn signer ON.
        audit.set_merkle_signer(Some(merkle_test_signer(0xF3)));

        // 2 more entries — only these should land in merkle_leaves.
        let e3 = build_and_sign(
            &key,
            &tenant,
            3,
            e2.entry_hash.clone(),
            "handler_action_task_complete",
        );
        audit.record_entry(e3.clone()).await.unwrap();
        let e4 = build_and_sign(
            &key,
            &tenant,
            4,
            e3.entry_hash.clone(),
            "handler_action_task_complete",
        );
        audit.record_entry(e4.clone()).await.unwrap();
        let (l_after, s_after) = count_merkle_rows(&audit, &tenant).await;
        assert_eq!(l_after, 2, "only post-enable entries appear as leaves");
        assert_eq!(s_after, 2);

        // Chain integrity unchanged (AV-50): all 4 entries verify.
        let verif = audit.verify_chain(&tenant, 1, None).await.unwrap();
        assert_eq!(verif.entries_walked, 4);
        assert_eq!(verif.outcome, ChainVerifyOutcome::Ok);
    }

    /// v1.5.0 Phase C — chain integrity (AV-49) preserved when the
    /// Merkle hook is enabled: replay still rejected by the chain
    /// commit phase, never reaches the Merkle step.
    #[tokio::test]
    async fn merkle_hook_does_not_weaken_chain_integrity() {
        let (_b, audit) = fresh_backend().await;
        audit.set_merkle_signer(Some(merkle_test_signer(0xA9)));
        let key = SigningKey::from_bytes(&[0xA9; 32]);
        let tenant = format!("audit-merk-int-{}", Uuid::new_v4().simple());

        let e1 = build_and_sign(
            &key,
            &tenant,
            1,
            GENESIS_PREV_HASH.to_vec(),
            "handler_action_task_complete",
        );
        audit.record_entry(e1.clone()).await.unwrap();
        // Replay → ChainIntegrity (sequence gap) OR Conflict. Either
        // way the chain rejects it BEFORE the Merkle hook runs, so
        // there's no double-append.
        let replay_err = audit.record_entry(e1.clone()).await.unwrap_err();
        assert!(matches!(
            replay_err,
            Error::ChainIntegrity(_) | Error::Conflict(_)
        ));
        let (l, s) = count_merkle_rows(&audit, &tenant).await;
        assert_eq!(l, 1, "exactly one leaf — replay was chain-rejected");
        assert_eq!(s, 1);
    }

    // ────────────────────────────────────────────────────────────────
    // v1.5.0 Phase D — TrustGrant projection tests (SQLite)
    // ────────────────────────────────────────────────────────────────

    /// Seed a row in `federation_keys` for the given `key_id` so the
    /// FK constraints on `federation_trust_grants` (grantee / granter
    /// / revoked_by all reference `federation_keys(key_id)`) are
    /// satisfied. The pubkey + envelope columns get throwaway values;
    /// only the FK shape matters for Phase D's projection tests.
    async fn seed_federation_key(audit: &SqliteAuditBackend, key_id: &str) {
        let conn = audit.conn_handle();
        let key_id = key_id.to_owned();
        tokio::task::spawn_blocking(move || {
            let conn = conn.blocking_lock();
            conn.execute(
                "INSERT OR IGNORE INTO federation_keys (\
                    key_id, pubkey_ed25519_base64, algorithm, \
                    identity_type, identity_ref, valid_from, \
                    registration_envelope, original_content_hash, \
                    scrub_signature_classical, scrub_key_id, \
                    scrub_timestamp, persist_row_hash\
                 ) VALUES (?1, 'AAAA', 'hybrid', 'agent', ?1, \
                          '2026-01-01T00:00:00Z', '{}', \
                          x'00', '', ?1, '2026-01-01T00:00:00Z', '0')",
                rusqlite::params![key_id],
            )
            .unwrap();
        })
        .await
        .unwrap();
    }

    /// Build + sign a trust_grant audit entry. Mirrors `build_and_sign`
    /// but parameterizes the payload + sets `subject_kind="trust_grant"`.
    #[allow(clippy::too_many_arguments)]
    fn build_trust_grant_entry(
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
            "rationale": "phase-D-test",
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
            recorded_at: truncate_to_micros(chrono::Utc::now()),
            signature: String::new(),
        };
        let hash = compute_entry_hash(&entry).unwrap();
        entry.entry_hash = hash.to_vec();
        let canonical = crate::audit::verify::canonical_bytes_for_entry(&entry).unwrap();
        let sig = granter_key.sign(&canonical);
        entry.signature = B64.encode(sig.to_bytes());
        entry
    }

    #[derive(Debug, Clone)]
    struct ProjectedGrantRow {
        grant_id: String,
        grantee_key: String,
        granter_key: String,
        purpose: String,
        scope: String,
        granted_at: String,
        expires_at: Option<String>,
        revoked_at: Option<String>,
        revoked_by: Option<String>,
        chain_event_id: i64,
        tenant_id: String,
    }

    async fn fetch_grant(
        audit: &SqliteAuditBackend,
        grantee: &str,
        granter: &str,
        purpose: &str,
        scope: &str,
    ) -> Option<ProjectedGrantRow> {
        let conn = audit.conn_handle();
        let grantee = grantee.to_owned();
        let granter = granter.to_owned();
        let purpose = purpose.to_owned();
        let scope = scope.to_owned();
        tokio::task::spawn_blocking(move || {
            let conn = conn.blocking_lock();
            conn.query_row(
                "SELECT grant_id, grantee_key, granter_key, purpose, scope, \
                        granted_at, expires_at, revoked_at, revoked_by, \
                        chain_event_id, tenant_id \
                 FROM federation_trust_grants \
                 WHERE grantee_key = ?1 AND granter_key = ?2 \
                   AND purpose = ?3 AND scope = ?4",
                rusqlite::params![grantee, granter, purpose, scope],
                |row| {
                    Ok(ProjectedGrantRow {
                        grant_id: row.get(0)?,
                        grantee_key: row.get(1)?,
                        granter_key: row.get(2)?,
                        purpose: row.get(3)?,
                        scope: row.get(4)?,
                        granted_at: row.get(5)?,
                        expires_at: row.get(6)?,
                        revoked_at: row.get(7)?,
                        revoked_by: row.get(8)?,
                        chain_event_id: row.get(9)?,
                        tenant_id: row.get(10)?,
                    })
                },
            )
            .optional()
            .unwrap()
        })
        .await
        .unwrap()
    }

    async fn count_grants(audit: &SqliteAuditBackend, tenant: &str) -> i64 {
        let conn = audit.conn_handle();
        let tenant = tenant.to_owned();
        tokio::task::spawn_blocking(move || {
            let conn = conn.blocking_lock();
            conn.query_row(
                "SELECT COUNT(*) FROM federation_trust_grants WHERE tenant_id = ?1",
                rusqlite::params![tenant],
                |row| row.get::<_, i64>(0),
            )
            .unwrap()
        })
        .await
        .unwrap()
    }

    /// v1.5.0 Phase D — Non-trust-grant entries do NOT touch
    /// federation_trust_grants. The projection is gated on
    /// `subject_kind == "trust_grant"`; an entry with
    /// `subject_kind="task"` (the default for `build_and_sign`)
    /// must leave the projection empty.
    #[tokio::test]
    async fn project_skips_non_trust_grant_subject_kinds() {
        let (_b, audit) = fresh_backend().await;
        let key = SigningKey::from_bytes(&[0x10; 32]);
        let tenant = format!("audit-pd-skip-{}", Uuid::new_v4().simple());

        let e1 = build_and_sign(
            &key,
            &tenant,
            1,
            GENESIS_PREV_HASH.to_vec(),
            "handler_action_task_complete",
        );
        audit.record_entry(e1.clone()).await.unwrap();
        let e2 = build_and_sign(&key, &tenant, 2, e1.entry_hash.clone(), "config_change");
        audit.record_entry(e2.clone()).await.unwrap();

        assert_eq!(count_grants(&audit, &tenant).await, 0);
    }

    /// v1.5.0 Phase D — A trust_grant entry materializes one row in
    /// federation_trust_grants with the expected values.
    #[tokio::test]
    async fn project_new_grant_materializes_row() {
        use crate::federation::trust_grant::TrustPurpose;
        let (_b, audit) = fresh_backend().await;

        let granter_signing = SigningKey::from_bytes(&[0x11; 32]);
        let granter_b64 = pubkey_b64(&granter_signing);
        let grantee_b64 = pubkey_b64(&SigningKey::from_bytes(&[0x12; 32]));
        let tenant = format!("audit-pd-new-{}", Uuid::new_v4().simple());

        seed_federation_key(&audit, &granter_b64).await;
        seed_federation_key(&audit, &grantee_b64).await;

        let entry = build_trust_grant_entry(
            &granter_signing,
            &tenant,
            1,
            GENESIS_PREV_HASH.to_vec(),
            &grantee_b64,
            TrustPurpose::Contribution,
            "proposal:registry_vouch",
            None,
        );
        audit.record_entry(entry.clone()).await.unwrap();

        let row = fetch_grant(
            &audit,
            &grantee_b64,
            &granter_b64,
            "contribution",
            "proposal:registry_vouch",
        )
        .await
        .expect("grant row materialized");
        assert_eq!(row.grantee_key, grantee_b64);
        assert_eq!(row.granter_key, granter_b64);
        assert_eq!(row.purpose, "contribution");
        assert_eq!(row.scope, "proposal:registry_vouch");
        assert_eq!(row.chain_event_id, 1);
        assert_eq!(row.tenant_id, tenant);
        assert!(row.revoked_at.is_none());
        assert!(row.revoked_by.is_none());
        assert!(row.expires_at.is_none());
        // granted_at follows entry.recorded_at (modulo micro
        // truncation). The exact string match isn't useful; sanity-
        // check that the column is populated.
        assert!(!row.granted_at.is_empty());

        assert_eq!(count_grants(&audit, &tenant).await, 1);
    }

    /// v1.5.0 Phase D — Re-issuance of the same (grantee, granter,
    /// purpose, scope) tuple updates the existing row in place. Row
    /// count stays 1; chain_event_id refreshes to the latest entry's
    /// sequence_number.
    #[tokio::test]
    async fn project_re_issuance_updates_existing_row() {
        use crate::federation::trust_grant::TrustPurpose;
        let (_b, audit) = fresh_backend().await;

        let granter_signing = SigningKey::from_bytes(&[0x21; 32]);
        let granter_b64 = pubkey_b64(&granter_signing);
        let grantee_b64 = pubkey_b64(&SigningKey::from_bytes(&[0x22; 32]));
        let tenant = format!("audit-pd-reissue-{}", Uuid::new_v4().simple());

        seed_federation_key(&audit, &granter_b64).await;
        seed_federation_key(&audit, &grantee_b64).await;

        // Future expiry (well past now).
        let far_future = chrono::Utc::now() + chrono::Duration::hours(48);

        let e1 = build_trust_grant_entry(
            &granter_signing,
            &tenant,
            1,
            GENESIS_PREV_HASH.to_vec(),
            &grantee_b64,
            TrustPurpose::Technical,
            "manifest:stable",
            None,
        );
        audit.record_entry(e1.clone()).await.unwrap();

        // Re-issue with an explicit future expiry — row updates in
        // place. Capture grant_id BEFORE the re-issuance.
        let original = fetch_grant(
            &audit,
            &grantee_b64,
            &granter_b64,
            "technical",
            "manifest:stable",
        )
        .await
        .expect("first grant row");
        let original_grant_id = original.grant_id.clone();

        // Force a recorded_at delta so the granted_at column changes.
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;

        let e2 = build_trust_grant_entry(
            &granter_signing,
            &tenant,
            2,
            e1.entry_hash.clone(),
            &grantee_b64,
            TrustPurpose::Technical,
            "manifest:stable",
            Some(far_future),
        );
        audit.record_entry(e2.clone()).await.unwrap();

        assert_eq!(
            count_grants(&audit, &tenant).await,
            1,
            "re-issuance does not insert a new row"
        );
        let row = fetch_grant(
            &audit,
            &grantee_b64,
            &granter_b64,
            "technical",
            "manifest:stable",
        )
        .await
        .expect("row still present");
        assert_eq!(
            row.grant_id, original_grant_id,
            "grant_id is stable across re-issuance (UPSERT keeps PK)"
        );
        assert_eq!(row.chain_event_id, 2, "chain_event_id refreshed");
        assert!(
            row.expires_at.is_some(),
            "expires_at populated by re-issuance"
        );
        assert!(row.revoked_at.is_none(), "future expiry → not revocation");
        assert!(row.revoked_by.is_none());
    }

    /// v1.5.0 Phase D — Revocation per FSD §3.4 is a re-issuance with
    /// `expires_at <= NOW()`. The projection detects this and sets
    /// `revoked_at` + `revoked_by`.
    #[tokio::test]
    async fn project_revocation_sets_revoked_at() {
        use crate::federation::trust_grant::TrustPurpose;
        let (_b, audit) = fresh_backend().await;

        let granter_signing = SigningKey::from_bytes(&[0x31; 32]);
        let granter_b64 = pubkey_b64(&granter_signing);
        let grantee_b64 = pubkey_b64(&SigningKey::from_bytes(&[0x32; 32]));
        let tenant = format!("audit-pd-revoke-{}", Uuid::new_v4().simple());

        seed_federation_key(&audit, &granter_b64).await;
        seed_federation_key(&audit, &grantee_b64).await;

        // Initial grant: no expiry.
        let e1 = build_trust_grant_entry(
            &granter_signing,
            &tenant,
            1,
            GENESIS_PREV_HASH.to_vec(),
            &grantee_b64,
            TrustPurpose::Deferral,
            "medical_deferral",
            None,
        );
        audit.record_entry(e1.clone()).await.unwrap();

        // Revocation: re-issuance with expires_at = past timestamp.
        let past = chrono::Utc::now() - chrono::Duration::seconds(60);
        let e2 = build_trust_grant_entry(
            &granter_signing,
            &tenant,
            2,
            e1.entry_hash.clone(),
            &grantee_b64,
            TrustPurpose::Deferral,
            "medical_deferral",
            Some(past),
        );
        audit.record_entry(e2.clone()).await.unwrap();

        let row = fetch_grant(
            &audit,
            &grantee_b64,
            &granter_b64,
            "deferral",
            "medical_deferral",
        )
        .await
        .expect("grant row");
        assert!(row.revoked_at.is_some(), "revocation populates revoked_at");
        assert_eq!(
            row.revoked_by.as_deref(),
            Some(granter_b64.as_str()),
            "revoked_by = granter (author-only per §3.4)"
        );
        assert_eq!(count_grants(&audit, &tenant).await, 1);
    }

    /// v1.5.0 Phase D — Self-grant (granter == grantee) is rejected
    /// with Error::TrustGrant. Mirrors the V021 CHECK constraint AND
    /// FSD §3.6 integrity rule.
    #[tokio::test]
    async fn project_self_grant_rejected() {
        use crate::federation::trust_grant::TrustPurpose;
        let (_b, audit) = fresh_backend().await;

        let granter_signing = SigningKey::from_bytes(&[0x41; 32]);
        let granter_b64 = pubkey_b64(&granter_signing);
        let tenant = format!("audit-pd-self-{}", Uuid::new_v4().simple());

        seed_federation_key(&audit, &granter_b64).await;

        let entry = build_trust_grant_entry(
            &granter_signing,
            &tenant,
            1,
            GENESIS_PREV_HASH.to_vec(),
            &granter_b64, // grantee = granter
            TrustPurpose::Service,
            "service:llm",
            None,
        );
        let err = audit.record_entry(entry).await.unwrap_err();
        assert!(
            matches!(err, Error::TrustGrant(_)),
            "expected Error::TrustGrant, got {err:?}"
        );
        assert_eq!(
            count_grants(&audit, &tenant).await,
            0,
            "no projection row materialized on self-grant"
        );
    }

    /// v1.5.0 Phase D — Multi-tenant isolation. The UNIQUE constraint
    /// on `(grantee_key, granter_key, purpose, scope)` intentionally
    /// omits `tenant_id` per FSD §3.6 — the grant identity is the
    /// relationship + purpose + scope, not the audit log location.
    /// So a same-tuple grant under tenant-B UPDATES the tenant-A row
    /// (treating gossip cross-emission as re-issuance), keeping a
    /// single canonical projection per relationship globally.
    ///
    /// This test verifies that semantic: two tenants emitting the
    /// same logical grant resolve to one row whose `tenant_id`
    /// reflects the latest emit.
    #[tokio::test]
    async fn project_cross_tenant_collapses_per_unique_constraint() {
        use crate::federation::trust_grant::TrustPurpose;
        let (_b, audit) = fresh_backend().await;

        let granter_signing = SigningKey::from_bytes(&[0x51; 32]);
        let granter_b64 = pubkey_b64(&granter_signing);
        let grantee_b64 = pubkey_b64(&SigningKey::from_bytes(&[0x52; 32]));
        let tenant_a = format!("audit-pd-mt-A-{}", Uuid::new_v4().simple());
        let tenant_b = format!("audit-pd-mt-B-{}", Uuid::new_v4().simple());

        seed_federation_key(&audit, &granter_b64).await;
        seed_federation_key(&audit, &grantee_b64).await;

        let a1 = build_trust_grant_entry(
            &granter_signing,
            &tenant_a,
            1,
            GENESIS_PREV_HASH.to_vec(),
            &grantee_b64,
            TrustPurpose::Contribution,
            "proposal:registry_vouch",
            None,
        );
        audit.record_entry(a1.clone()).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        let b1 = build_trust_grant_entry(
            &granter_signing,
            &tenant_b,
            1,
            GENESIS_PREV_HASH.to_vec(),
            &grantee_b64,
            TrustPurpose::Contribution,
            "proposal:registry_vouch",
            None,
        );
        audit.record_entry(b1.clone()).await.unwrap();

        let row = fetch_grant(
            &audit,
            &grantee_b64,
            &granter_b64,
            "contribution",
            "proposal:registry_vouch",
        )
        .await
        .expect("grant row");
        // Tenant B emit landed last → row.tenant_id == tenant_b.
        assert_eq!(row.tenant_id, tenant_b);
        // The grants table should hold one row TOTAL across both
        // tenants (UNIQUE constraint per FSD §3.6).
        let total: i64 = {
            let conn = audit.conn_handle();
            tokio::task::spawn_blocking(move || {
                let conn = conn.blocking_lock();
                conn.query_row("SELECT COUNT(*) FROM federation_trust_grants", [], |r| {
                    r.get::<_, i64>(0)
                })
                .unwrap()
            })
            .await
            .unwrap()
        };
        assert_eq!(
            total, 1,
            "cross-tenant same-tuple emits collapse via UPSERT"
        );
    }

    /// v1.5.0 Phase D — A malformed trust_grant payload (subject_kind
    /// is "trust_grant" but the payload doesn't parse as a
    /// TrustGrantPayload) surfaces as Error::TrustGrant. The chain
    /// row already landed at this point — that's the documented
    /// option-(b) atomicity stance (Phase I will reconcile).
    #[tokio::test]
    async fn project_malformed_payload_surfaces_error() {
        let (_b, audit) = fresh_backend().await;
        let granter_signing = SigningKey::from_bytes(&[0x61; 32]);
        let tenant = format!("audit-pd-malformed-{}", Uuid::new_v4().simple());

        let mut entry = AuditEntry {
            entry_id: Uuid::new_v4().to_string(),
            sequence_number: 1,
            tenant_id: tenant.clone(),
            actor_id: pubkey_b64(&granter_signing),
            action_type: "trust_granted".into(),
            subject_kind: crate::federation::trust_grant::TRUST_GRANT_SUBJECT_KIND.into(),
            subject_id: "irrelevant".into(),
            // Missing required fields — won't deserialize.
            payload: serde_json::json!({"junk": "value"}),
            prev_hash: GENESIS_PREV_HASH.to_vec(),
            entry_hash: vec![],
            recorded_at: truncate_to_micros(chrono::Utc::now()),
            signature: String::new(),
        };
        let hash = compute_entry_hash(&entry).unwrap();
        entry.entry_hash = hash.to_vec();
        let canonical = crate::audit::verify::canonical_bytes_for_entry(&entry).unwrap();
        let sig = granter_signing.sign(&canonical);
        entry.signature = B64.encode(sig.to_bytes());

        let err = audit.record_entry(entry).await.unwrap_err();
        assert!(
            matches!(err, Error::TrustGrant(_)),
            "expected Error::TrustGrant, got {err:?}"
        );

        // The chain entry DID land (option-(b)): list_entries finds it.
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
        assert_eq!(
            page.items.len(),
            1,
            "chain row stands even when projection fails (FSD §4.2)"
        );
    }
}
