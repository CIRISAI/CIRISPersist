//! Trust-grant **emit** API (v1.5.0 Phase E, FSD §4.1 + §3.4).
//!
//! Builds a [`TrustGrantPayload`], wraps it in an [`AuditEntry`] with
//! `subject_kind = "trust_grant"`, signs the entry against the
//! steward's Ed25519 identity, and hands it to
//! [`AuditService::record_entry`] — which triggers the Phase C Merkle
//! hook + Phase D projection automatically. The post-emit
//! [`SignedTreeHead`] is fetched via
//! [`AuditService::current_sth`](crate::audit::AuditService::current_sth)
//! and returned on the [`TrustGrantReceipt`].
//!
//! # Design notes
//!
//! - **Sequence number is caller-supplied.** Both backends'
//!   `record_entry` paths re-derive the tail under
//!   `SELECT … FOR UPDATE` / `BEGIN IMMEDIATE` and reject mismatches
//!   as `Error::ChainIntegrity`. Phase E probes the tail via
//!   `AuditService::next_chain_position` once before building the
//!   entry; if the chain advances between probe and commit the caller
//!   sees `Error::Audit(Error::ChainIntegrity(_))` and SHOULD retry
//!   (one retry is sufficient under bounded contention).
//!
//! - **Self-grant rejection happens twice.** The V021 CHECK
//!   constraint + Phase D projection both reject `granter == grantee`.
//!   Phase E adds a third belt-and-suspenders gate at the API
//!   boundary so callers see an `InvalidArgument` error *before*
//!   signing + writing a chain row that the projection would refuse.
//!
//! - **Signer is non-optional.** An emit without a local identity
//!   can't produce a valid `AuditEntry.signature` (the chain rejects
//!   entries with no signature), and the resulting receipt's STH
//!   would be meaningless. Phase E therefore takes a `&LocalSigner`
//!   by reference; callers that don't have one constructed have no
//!   business emitting trust grants.
//!
//! - **STH retrieval is a post-emit query.** The Phase C Merkle hook
//!   has already signed + stored the STH inside `record_entry`'s
//!   call. We read it back via
//!   [`AuditService::current_sth`](crate::audit::AuditService::current_sth)
//!   — the same surface Phase G's "current_sth" read API will use.
//!   See the module rustdoc on `crate::audit::service` for the
//!   atomicity rationale.
#![allow(clippy::redundant_closure_call)]
// v3.14.0 (CIRISPersist#158) — inline-sync rewrite of all
// tokio::task::spawn_blocking sites uses (closure)() to invoke
// the closure inline. Clippy's redundant_closure_call lint flags
// this; we allow it because the mechanical transformation kept
// each closure's typed return signature load-bearing for error
// propagation and any other refactor would be a much larger diff.

use chrono::{DateTime, Utc};
use uuid::Uuid;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;

use super::trust_grant::{
    TrustGrantPayload, TrustGrantReceipt, TrustPurpose, TRUST_GRANT_SUBJECT_KIND,
};
use crate::audit::types::AuditEntry;
use crate::audit::verify::{canonical_bytes_for_entry, compute_entry_hash, truncate_to_micros};
use crate::audit::AuditService;
use crate::signing::LocalSigner;

/// Errors from [`grant_trust`] / [`revoke_trust_grant`].
#[derive(Debug, thiserror::Error)]
pub enum EmitError {
    /// Audit-service-layer error (chain integrity, signature gate,
    /// Merkle hook failure, projection failure, …). Wraps the
    /// underlying [`crate::audit::Error`].
    #[error("audit: {0}")]
    Audit(#[from] crate::audit::Error),

    /// Local signer raised an error (Ed25519 key missing, PQC
    /// seed inconsistent, …).
    #[error("signing: {0}")]
    Signing(String),

    /// Caller-side validation failed (empty tenant_id, self-grant,
    /// empty grantee_key/scope, …) — the entry was never signed nor
    /// submitted.
    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    /// Phase E expected to find a [`SignedTreeHead`] for the tenant
    /// after `record_entry` committed (because the local signer is
    /// configured and the Merkle hook should have signed the STH) but
    /// none was returned. Surfacing this as a typed error lets callers
    /// distinguish "Merkle hook silently disabled mid-flight" from
    /// audit-side errors.
    #[error("post-emit STH missing for tenant {tenant_id} — Merkle hook may be disabled")]
    PostEmitSthMissing {
        /// Tenant the emit targeted.
        tenant_id: String,
    },

    /// Phase E expected to find a `federation_trust_grants` projection
    /// row for the just-committed chain event but the lookup returned
    /// None. This means Phase D's projection materialization didn't
    /// complete (e.g., a malformed payload that the audit chain
    /// accepted but Phase D rejected, or a projection-side failure
    /// after the chain commit). The chain entry is durable; Phase I's
    /// V021 backfill will re-project on next boot.
    #[error("post-emit projection missing for chain_event_id {chain_event_id}")]
    PostEmitProjectionMissing {
        /// The chain event id whose projection row was not found.
        chain_event_id: i64,
    },
}

impl From<crate::signing::LocalSignerError> for EmitError {
    fn from(e: crate::signing::LocalSignerError) -> Self {
        EmitError::Signing(format!("{e}"))
    }
}

/// Emit a `TrustGrant` Contribution to the audit chain (FSD §4.1).
///
/// Flow:
/// 1. Validate inputs (tenant_id non-empty, no self-grant, scope
///    non-empty, grantee_key non-empty).
/// 2. Probe the chain head via
///    [`AuditService::next_chain_position`] to capture
///    `(next_sequence_number, prev_hash)`.
/// 3. Build the [`AuditEntry`] with
///    `subject_kind = "trust_grant"`, `actor_id = signer.public_key_b64()`,
///    `recorded_at` truncated to microseconds (Postgres TIMESTAMPTZ
///    precision; see [`truncate_to_micros`]).
/// 4. Compute `entry_hash` from canonical bytes (entry_hash +
///    signature zeroed during hash; the hash IS part of the signed
///    bytes — see `audit::verify` rustdoc for the binding rationale).
/// 5. Sign the canonical bytes with `signer.sign_ed25519` — audit
///    entries are Ed25519-only, matching the PINNED
///    [`crate::verify::hybrid::HybridPolicy::Ed25519Fallback`] in
///    [`crate::audit::verify::verify_entry_signature`]. That pin is
///    structural, not a pending rollout: `AuditEntry` has no PQC field
///    and no per-actor ML-DSA-65 pubkey exists, so the v37.0.0 Strict
///    sweep deliberately skipped the audit plane (see that function's
///    doc). This step stays Ed25519-only.
/// 6. Call `audit_service.record_entry(entry)` — this triggers the
///    Phase C Merkle hook (which signs + stores the STH) and the
///    Phase D projection (which UPSERTs `federation_trust_grants`).
/// 7. Fetch the post-emit STH via
///    [`AuditService::current_sth`] and assemble the
///    [`TrustGrantReceipt`].
///
/// # Receipt shape
///
/// - `grant_id`: the canonical `federation_trust_grants.grant_id` PK
///   read back via [`AuditService::lookup_grant_id_by_chain_event`]
///   after `record_entry` commits. On re-issuance the UPSERT keeps the
///   original `grant_id` stable, so this matches what Phase F's read
///   API or Phase G's inclusion-proof API will return for the same
///   logical grant.
/// - `chain_event_id`: the per-tenant `sequence_number` (reused as
///   the chain-event id per FSD §4.4 + V021 schema).
/// - `chain_event_hash`: the 32-byte `entry_hash` of the just-stored
///   entry.
/// - `tenant_id`: per the input.
/// - `tree_size_at_emit`: `sth.tree_size` from the post-emit STH.
/// - `sth`: the post-emit `SignedTreeHead` (hybrid-signed by the
///   steward).
///
/// # Retries
///
/// If two emits race and one observes `Error::ChainIntegrity` on the
/// `record_entry` step (the tail advanced between
/// `next_chain_position` and `record_entry`), the caller MAY retry
/// once. Phase E does not retry internally — that's a policy decision
/// the caller composes.
#[allow(clippy::too_many_arguments)]
pub async fn grant_trust<A>(
    audit_service: &A,
    signer: &LocalSigner,
    tenant_id: &str,
    grantee_key: &str,
    purpose: TrustPurpose,
    scope: &str,
    expires_at: Option<DateTime<Utc>>,
    rationale: &str,
) -> Result<TrustGrantReceipt, EmitError>
where
    A: AuditService,
{
    // ── 1. Input validation ────────────────────────────────────────
    if tenant_id.is_empty() {
        return Err(EmitError::InvalidArgument(
            "tenant_id must be non-empty".into(),
        ));
    }
    if grantee_key.is_empty() {
        return Err(EmitError::InvalidArgument(
            "grantee_key must be non-empty".into(),
        ));
    }
    if scope.is_empty() {
        return Err(EmitError::InvalidArgument("scope must be non-empty".into()));
    }
    let granter_key = signer.public_key_b64();
    if granter_key == grantee_key {
        // Matches Phase D projection guard + V021 CHECK constraint.
        // FSD §3.6 integrity rule.
        return Err(EmitError::InvalidArgument(
            "self-grant rejected (granter == grantee)".into(),
        ));
    }

    // ── 2. Probe chain head ────────────────────────────────────────
    let position = audit_service
        .next_chain_position(tenant_id)
        .await
        .map_err(EmitError::Audit)?;

    // ── 3. Build payload + entry ───────────────────────────────────
    let payload = TrustGrantPayload {
        grantee_key: grantee_key.to_owned(),
        purpose,
        scope: scope.to_owned(),
        expires_at,
        rationale: rationale.to_owned(),
    };
    let payload_json = serde_json::to_value(&payload)
        .map_err(|e| EmitError::Signing(format!("payload serialize: {e}")))?;

    let entry_id = Uuid::new_v4().to_string();
    let recorded_at = truncate_to_micros(Utc::now());

    let mut entry = AuditEntry {
        entry_id,
        sequence_number: position.next_sequence_number,
        tenant_id: tenant_id.to_owned(),
        actor_id: granter_key.clone(),
        action_type: "trust_granted".to_owned(),
        subject_kind: TRUST_GRANT_SUBJECT_KIND.to_owned(),
        subject_id: grantee_key.to_owned(),
        payload: payload_json,
        prev_hash: position.prev_hash.to_vec(),
        entry_hash: Vec::new(),
        recorded_at,
        signature: String::new(),
    };

    // ── 4. Compute entry_hash (zeros out entry_hash + signature
    //       internally per `audit::verify::compute_entry_hash`). ────
    let hash = compute_entry_hash(&entry).map_err(EmitError::Audit)?;
    entry.entry_hash = hash.to_vec();

    // ── 5. Sign canonical bytes (entry_hash now resolved → bound
    //       to chain position; signature still empty + stripped by
    //       canonicalizer). Ed25519-only per AV-49. ────────────────
    let canonical = canonical_bytes_for_entry(&entry).map_err(EmitError::Audit)?;
    let sig_bytes = signer.sign_ed25519(&canonical)?;
    entry.signature = B64.encode(sig_bytes);

    // ── 6. Submit to audit service. record_entry triggers Phase C
    //       Merkle hook + Phase D projection inline. ────────────────
    let chain_event_hash = entry.entry_hash.clone();
    let chain_event_id = entry.sequence_number;
    audit_service
        .record_entry(entry)
        .await
        .map_err(EmitError::Audit)?;

    // ── 7. Fetch the post-emit STH. The Phase C hook signed +
    //       stored it on the same tenant; current_sth returns the
    //       latest tree_size, which is exactly what we just appended. ──
    let sth = audit_service
        .current_sth(tenant_id)
        .await
        .map_err(EmitError::Audit)?
        .ok_or_else(|| EmitError::PostEmitSthMissing {
            tenant_id: tenant_id.to_owned(),
        })?;
    let tree_size_at_emit = sth.tree_size;

    // ── 8. Fetch the canonical grant_id from the projection. On
    //       re-issuance, federation_trust_grants UPSERT keeps the
    //       original grant_id stable, so the row's PK is the
    //       authoritative identifier — not a fresh UUID. ───────────
    let grant_id = audit_service
        .lookup_grant_id_by_chain_event(tenant_id, chain_event_id)
        .await
        .map_err(EmitError::Audit)?
        .ok_or(EmitError::PostEmitProjectionMissing { chain_event_id })?;

    Ok(TrustGrantReceipt {
        grant_id,
        chain_event_id,
        chain_event_hash,
        tenant_id: tenant_id.to_owned(),
        tree_size_at_emit,
        sth,
    })
}

/// Revoke a trust grant per FSD §3.4 — re-issuance with
/// `expires_at = now()`. The Phase D projection detects
/// `expires_at <= NOW()` and sets `revoked_at` + `revoked_by` on the
/// row.
///
/// Rationale-text is fixed to `"revocation"` so revocation events
/// are filter-recognizable in `list_entries` without parsing the
/// payload further. Callers that need a free-form revocation
/// rationale can invoke [`grant_trust`] directly with their own
/// `expires_at = Utc::now()` and a custom rationale.
pub async fn revoke_trust_grant<A>(
    audit_service: &A,
    signer: &LocalSigner,
    tenant_id: &str,
    grantee_key: &str,
    purpose: TrustPurpose,
    scope: &str,
) -> Result<TrustGrantReceipt, EmitError>
where
    A: AuditService,
{
    grant_trust(
        audit_service,
        signer,
        tenant_id,
        grantee_key,
        purpose,
        scope,
        Some(Utc::now()),
        "revocation",
    )
    .await
}

// ─────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────

#[cfg(all(test, feature = "sqlite"))]
mod sqlite_tests {
    use super::*;
    use crate::audit::sqlite::SqliteAuditBackend;
    use crate::audit::AuditFilter;
    use crate::signing::LocalSigner;
    use crate::store::sqlite::SqliteBackend;
    use crate::store::Backend;
    use ciris_keyring::MlDsa65SoftwareSigner;
    use ed25519_dalek::SigningKey;
    use rusqlite::OptionalExtension;
    use std::sync::Arc;
    use uuid::Uuid;

    /// Build a LocalSigner with PQC configured. The Phase C Merkle
    /// hook requires `sign_hybrid` (Ed25519 + ML-DSA-65); without PQC
    /// the hook trips `PqcNotConfigured`.
    fn build_signer(seed_byte: u8) -> Arc<LocalSigner> {
        let signing_key = SigningKey::from_bytes(&[seed_byte; 32]);
        let pqc =
            MlDsa65SoftwareSigner::from_seed_bytes(&[seed_byte ^ 0x55; 32], "phase-e-test-pqc")
                .expect("pqc seed");
        let pqc_arc: Arc<dyn ciris_keyring::PqcSigner> = Arc::new(pqc);
        Arc::new(LocalSigner::from_parts(
            signing_key,
            "phase-e-test-steward".to_owned(),
            Some(pqc_arc),
            Some("phase-e-test-pqc".to_owned()),
        ))
    }

    async fn fresh_audit(seed_byte: u8) -> (SqliteBackend, SqliteAuditBackend, Arc<LocalSigner>) {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        let audit = SqliteAuditBackend::new(backend.conn_handle());
        let signer = build_signer(seed_byte);
        audit.set_merkle_signer(Some(signer.clone()));
        (backend, audit, signer)
    }

    /// Seed a federation_keys row for FK satisfaction (Phase D's
    /// projection UPSERTs onto a table whose FKs target
    /// federation_keys(key_id)).
    async fn seed_federation_key(audit: &SqliteAuditBackend, key_id: &str) {
        let conn = audit.conn_handle();
        let key_id = key_id.to_owned();
        (move || {
            let conn = conn.lock();
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
        })();
    }

    /// v1.5.0 Phase E happy path: grant_trust returns a receipt with
    /// the expected shape and the audit + Merkle + projection sides
    /// are all in sync.
    #[tokio::test]
    async fn sqlite_grant_trust_happy_path() {
        let (_b, audit, signer) = fresh_audit(0x11).await;
        let granter_b64 = signer.public_key_b64();
        let grantee_b64 = base64::engine::general_purpose::STANDARD.encode(
            SigningKey::from_bytes(&[0x12; 32])
                .verifying_key()
                .to_bytes(),
        );
        let tenant = format!("phase-e-happy-{}", Uuid::new_v4().simple());
        seed_federation_key(&audit, &granter_b64).await;
        seed_federation_key(&audit, &grantee_b64).await;

        let receipt = grant_trust(
            &audit,
            &signer,
            &tenant,
            &grantee_b64,
            TrustPurpose::Contribution,
            "proposal:registry_vouch",
            None,
            "phase-e-happy",
        )
        .await
        .expect("grant_trust");

        assert_eq!(receipt.tenant_id, tenant);
        assert_eq!(receipt.chain_event_id, 1, "first entry in chain");
        assert_eq!(receipt.chain_event_hash.len(), 32);
        assert_eq!(receipt.tree_size_at_emit, 1, "one leaf after emit");
        assert_eq!(receipt.sth.tree_size, 1);
        assert_eq!(receipt.sth.log_id, format!("tenant:{tenant}"));
    }

    /// v1.5.0 Phase E: the audit chain has the trust_grant entry with
    /// the expected subject_kind, and `list_entries` surfaces it.
    #[tokio::test]
    async fn sqlite_grant_trust_writes_chain_entry() {
        let (_b, audit, signer) = fresh_audit(0x21).await;
        let granter_b64 = signer.public_key_b64();
        let grantee_b64 = base64::engine::general_purpose::STANDARD.encode(
            SigningKey::from_bytes(&[0x22; 32])
                .verifying_key()
                .to_bytes(),
        );
        let tenant = format!("phase-e-chain-{}", Uuid::new_v4().simple());
        seed_federation_key(&audit, &granter_b64).await;
        seed_federation_key(&audit, &grantee_b64).await;

        let _r = grant_trust(
            &audit,
            &signer,
            &tenant,
            &grantee_b64,
            TrustPurpose::Technical,
            "manifest:stable",
            None,
            "phase-e-chain",
        )
        .await
        .expect("grant_trust");

        let page = audit
            .list_entries(
                AuditFilter {
                    tenant_id: tenant.clone(),
                    action_type: None,
                    actor_id: None,
                    subject_kind: Some(TRUST_GRANT_SUBJECT_KIND.to_owned()),
                    subject_id: None,
                    recorded_after: None,
                    recorded_before: None,
                },
                None,
                10,
            )
            .await
            .unwrap();
        assert_eq!(page.items.len(), 1);
        let entry = &page.items[0];
        assert_eq!(entry.subject_kind, TRUST_GRANT_SUBJECT_KIND);
        assert_eq!(entry.action_type, "trust_granted");
        assert_eq!(entry.subject_id, grantee_b64);
        assert_eq!(entry.actor_id, granter_b64);
        assert_eq!(entry.sequence_number, 1);
    }

    /// v1.5.0 Phase E: the Merkle tree has a leaf at index
    /// `tree_size_at_emit - 1`, and the STH log has a row at the
    /// reported `tree_size`.
    #[tokio::test]
    async fn sqlite_grant_trust_writes_merkle_leaf_and_sth() {
        let (_b, audit, signer) = fresh_audit(0x31).await;
        let granter_b64 = signer.public_key_b64();
        let grantee_b64 = base64::engine::general_purpose::STANDARD.encode(
            SigningKey::from_bytes(&[0x32; 32])
                .verifying_key()
                .to_bytes(),
        );
        let tenant = format!("phase-e-merkle-{}", Uuid::new_v4().simple());
        seed_federation_key(&audit, &granter_b64).await;
        seed_federation_key(&audit, &grantee_b64).await;

        let receipt = grant_trust(
            &audit,
            &signer,
            &tenant,
            &grantee_b64,
            TrustPurpose::Deferral,
            "medical_deferral",
            None,
            "phase-e-merkle",
        )
        .await
        .unwrap();

        let conn = audit.conn_handle();
        let tenant_for_query = tenant.clone();
        let (leaves, sth_rows, sth_tree_size): (i64, i64, i64) = (move || {
            let conn = conn.lock();
            let leaves: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM merkle_leaves WHERE tenant_id = ?1",
                    rusqlite::params![tenant_for_query],
                    |row| row.get(0),
                )
                .unwrap();
            let sth_rows: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM merkle_sth_log WHERE tenant_id = ?1",
                    rusqlite::params![tenant_for_query],
                    |row| row.get(0),
                )
                .unwrap();
            let max_size: i64 = conn
                .query_row(
                    "SELECT MAX(tree_size) FROM merkle_sth_log WHERE tenant_id = ?1",
                    rusqlite::params![tenant_for_query],
                    |row| row.get(0),
                )
                .unwrap();
            (leaves, sth_rows, max_size)
        })();
        assert_eq!(leaves, 1);
        assert_eq!(sth_rows, 1);
        assert_eq!(
            sth_tree_size as u64, receipt.tree_size_at_emit,
            "STH log row's tree_size matches the receipt's reported size"
        );
    }

    /// v1.5.0 Phase E: the projection has the row with the expected
    /// (grantee_key, granter_key, purpose, scope).
    #[tokio::test]
    async fn sqlite_grant_trust_writes_projection_row() {
        let (_b, audit, signer) = fresh_audit(0x41).await;
        let granter_b64 = signer.public_key_b64();
        let grantee_b64 = base64::engine::general_purpose::STANDARD.encode(
            SigningKey::from_bytes(&[0x42; 32])
                .verifying_key()
                .to_bytes(),
        );
        let tenant = format!("phase-e-projection-{}", Uuid::new_v4().simple());
        seed_federation_key(&audit, &granter_b64).await;
        seed_federation_key(&audit, &grantee_b64).await;

        let _r = grant_trust(
            &audit,
            &signer,
            &tenant,
            &grantee_b64,
            TrustPurpose::Service,
            "service:llm",
            None,
            "phase-e-projection",
        )
        .await
        .unwrap();

        let conn = audit.conn_handle();
        let grantee_for_query = grantee_b64.clone();
        let granter_for_query = granter_b64.clone();
        let row: Option<(String, String, String, String, Option<String>)> = (move || {
            let conn = conn.lock();
            conn.query_row(
                "SELECT grantee_key, granter_key, purpose, scope, revoked_at \
                     FROM federation_trust_grants \
                     WHERE grantee_key = ?1 AND granter_key = ?2",
                rusqlite::params![grantee_for_query, granter_for_query],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .optional()
            .unwrap()
        })();
        let row = row.expect("projection row materialized");
        assert_eq!(row.0, grantee_b64);
        assert_eq!(row.1, granter_b64);
        assert_eq!(row.2, "service");
        assert_eq!(row.3, "service:llm");
        assert!(row.4.is_none(), "fresh grant is not revoked");
    }

    /// v1.5.0 Phase E + §3.6 re-issuance: emitting the same logical
    /// grant twice keeps the projection's `grant_id` stable across
    /// the UPSERT. The receipt's `grant_id` must reflect the canonical
    /// row PK, not a fresh UUID — that's what makes Phase G's
    /// inclusion-proof-by-grant-id lookup well-defined when callers
    /// later resolve a receipt back to the projection.
    #[tokio::test]
    async fn sqlite_reissuance_preserves_canonical_grant_id() {
        let (_b, audit, signer) = fresh_audit(0x60).await;
        let granter_b64 = signer.public_key_b64();
        let grantee_b64 = base64::engine::general_purpose::STANDARD.encode(
            SigningKey::from_bytes(&[0x61; 32])
                .verifying_key()
                .to_bytes(),
        );
        let tenant = format!("phase-e-reissue-{}", Uuid::new_v4().simple());
        seed_federation_key(&audit, &granter_b64).await;
        seed_federation_key(&audit, &grantee_b64).await;

        let r1 = grant_trust(
            &audit,
            &signer,
            &tenant,
            &grantee_b64,
            TrustPurpose::Deferral,
            "medical_deferral",
            None,
            "phase-e-first",
        )
        .await
        .unwrap();

        let r2 = grant_trust(
            &audit,
            &signer,
            &tenant,
            &grantee_b64,
            TrustPurpose::Deferral,
            "medical_deferral",
            None,
            "phase-e-second",
        )
        .await
        .unwrap();

        assert_eq!(
            r1.grant_id, r2.grant_id,
            "re-issuance must keep the canonical projection grant_id stable"
        );
        assert_ne!(
            r1.chain_event_id, r2.chain_event_id,
            "but each emit gets its own chain entry"
        );
    }

    /// v1.5.0 Phase E + §3.4 revocation: revoke_trust_grant emits
    /// with `expires_at = now()`; projection sets `revoked_at` +
    /// `revoked_by` (revoked_by = granter).
    #[tokio::test]
    async fn sqlite_revoke_trust_grant_populates_revocation_columns() {
        let (_b, audit, signer) = fresh_audit(0x51).await;
        let granter_b64 = signer.public_key_b64();
        let grantee_b64 = base64::engine::general_purpose::STANDARD.encode(
            SigningKey::from_bytes(&[0x52; 32])
                .verifying_key()
                .to_bytes(),
        );
        let tenant = format!("phase-e-revoke-{}", Uuid::new_v4().simple());
        seed_federation_key(&audit, &granter_b64).await;
        seed_federation_key(&audit, &grantee_b64).await;

        // Initial grant.
        let _g = grant_trust(
            &audit,
            &signer,
            &tenant,
            &grantee_b64,
            TrustPurpose::Deferral,
            "medical_deferral",
            None,
            "phase-e-initial",
        )
        .await
        .unwrap();

        // Revocation.
        let r = revoke_trust_grant(
            &audit,
            &signer,
            &tenant,
            &grantee_b64,
            TrustPurpose::Deferral,
            "medical_deferral",
        )
        .await
        .expect("revoke_trust_grant");
        assert_eq!(r.chain_event_id, 2);
        assert_eq!(r.tree_size_at_emit, 2);

        let conn = audit.conn_handle();
        let grantee_for_query = grantee_b64.clone();
        let granter_for_query = granter_b64.clone();
        let (revoked_at, revoked_by): (Option<String>, Option<String>) = (move || {
            let conn = conn.lock();
            conn.query_row(
                "SELECT revoked_at, revoked_by \
                     FROM federation_trust_grants \
                     WHERE grantee_key = ?1 AND granter_key = ?2 \
                       AND purpose = 'deferral' AND scope = 'medical_deferral'",
                rusqlite::params![grantee_for_query, granter_for_query],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap()
        })();
        assert!(revoked_at.is_some(), "revoked_at populated");
        assert_eq!(
            revoked_by.as_deref(),
            Some(granter_b64.as_str()),
            "revoked_by = granter"
        );
    }

    /// v1.5.0 Phase E: self-grant rejected at the API boundary
    /// (BEFORE signing + record_entry).
    #[tokio::test]
    async fn sqlite_self_grant_rejected() {
        let (_b, audit, signer) = fresh_audit(0x61).await;
        let pubkey = signer.public_key_b64();
        let tenant = format!("phase-e-self-{}", Uuid::new_v4().simple());

        let err = grant_trust(
            &audit,
            &signer,
            &tenant,
            &pubkey, // grantee == granter
            TrustPurpose::Service,
            "service:llm",
            None,
            "phase-e-self",
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, EmitError::InvalidArgument(ref m) if m.contains("self-grant")),
            "expected InvalidArgument(self-grant), got {err:?}"
        );

        // No chain row landed.
        let page = audit
            .list_entries(
                AuditFilter {
                    tenant_id: tenant,
                    action_type: None,
                    actor_id: None,
                    subject_kind: None,
                    subject_id: None,
                    recorded_after: None,
                    recorded_before: None,
                },
                None,
                10,
            )
            .await
            .unwrap();
        assert!(page.items.is_empty());
    }

    /// v1.5.0 Phase E: empty tenant_id rejected.
    #[tokio::test]
    async fn sqlite_empty_tenant_rejected() {
        let (_b, audit, signer) = fresh_audit(0x71).await;
        let grantee_b64 = base64::engine::general_purpose::STANDARD.encode(
            SigningKey::from_bytes(&[0x72; 32])
                .verifying_key()
                .to_bytes(),
        );
        let err = grant_trust(
            &audit,
            &signer,
            "",
            &grantee_b64,
            TrustPurpose::Contribution,
            "proposal:registry_vouch",
            None,
            "phase-e-empty-tenant",
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, EmitError::InvalidArgument(ref m) if m.contains("tenant_id")),
            "expected InvalidArgument(tenant_id), got {err:?}"
        );
    }

    /// v1.5.0 Phase E: emitting without a Merkle signer surfaces
    /// `PostEmitSthMissing` (the record_entry call succeeds — chain
    /// row lands — but no STH was signed so `current_sth` returns
    /// None). This is the diagnostic-test path; production emitters
    /// always install a signer.
    #[tokio::test]
    async fn sqlite_emit_without_merkle_signer_surfaces_post_emit_sth_missing() {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        let audit = SqliteAuditBackend::new(backend.conn_handle());
        // Note: signer is constructed but NOT installed on `audit`.
        let signer = build_signer(0x81);
        let granter_b64 = signer.public_key_b64();
        let grantee_b64 = base64::engine::general_purpose::STANDARD.encode(
            SigningKey::from_bytes(&[0x82; 32])
                .verifying_key()
                .to_bytes(),
        );
        let tenant = format!("phase-e-no-merkle-{}", Uuid::new_v4().simple());
        seed_federation_key(&audit, &granter_b64).await;
        seed_federation_key(&audit, &grantee_b64).await;

        let err = grant_trust(
            &audit,
            &signer,
            &tenant,
            &grantee_b64,
            TrustPurpose::Contribution,
            "proposal:registry_vouch",
            None,
            "phase-e-no-merkle",
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, EmitError::PostEmitSthMissing { ref tenant_id } if tenant_id == &tenant),
            "expected PostEmitSthMissing, got {err:?}"
        );
        // Chain row DID land (atomicity is chain-first).
        let page = audit
            .list_entries(
                AuditFilter {
                    tenant_id: tenant.clone(),
                    action_type: None,
                    actor_id: None,
                    subject_kind: Some(TRUST_GRANT_SUBJECT_KIND.to_owned()),
                    subject_id: None,
                    recorded_after: None,
                    recorded_before: None,
                },
                None,
                10,
            )
            .await
            .unwrap();
        assert_eq!(page.items.len(), 1, "chain row lands even when STH missing");
    }
}

#[cfg(all(test, feature = "postgres"))]
mod postgres_tests {
    use super::*;
    use crate::audit::AuditFilter;
    use crate::signing::LocalSigner;
    use crate::store::postgres::PostgresBackend;
    use crate::store::Backend;
    use ciris_keyring::MlDsa65SoftwareSigner;
    use ed25519_dalek::SigningKey;
    use std::sync::Arc;
    use uuid::Uuid;

    fn pg_dsn() -> Option<String> {
        crate::test_pg::dsn()
    }

    fn build_signer(seed_byte: u8) -> Arc<LocalSigner> {
        let signing_key = SigningKey::from_bytes(&[seed_byte; 32]);
        let pqc =
            MlDsa65SoftwareSigner::from_seed_bytes(&[seed_byte ^ 0x55; 32], "phase-e-pg-test-pqc")
                .expect("pqc seed");
        let pqc_arc: Arc<dyn ciris_keyring::PqcSigner> = Arc::new(pqc);
        Arc::new(LocalSigner::from_parts(
            signing_key,
            "phase-e-pg-test-steward".to_owned(),
            Some(pqc_arc),
            Some("phase-e-pg-test-pqc".to_owned()),
        ))
    }

    async fn pg_seed_federation_key(backend: &PostgresBackend, key_id: &str) {
        let client = backend.pool().get().await.unwrap();
        client
            .execute(
                "INSERT INTO cirislens.federation_keys (\
                    key_id, pubkey_ed25519_base64, algorithm, identity_type, \
                    identity_ref, valid_from, registration_envelope, \
                    original_content_hash, scrub_signature_classical, \
                    scrub_key_id, scrub_timestamp, persist_row_hash, admitted_at\
                 ) VALUES ($1, 'AAAA', 'hybrid', 'agent', $1, NOW(), \
                          '{}'::jsonb, decode('00', 'hex'), '', $1, NOW(), '0', NOW()) \
                 ON CONFLICT (key_id) DO NOTHING",
                &[&key_id],
            )
            .await
            .unwrap();
    }

    async fn pg_cleanup(backend: &PostgresBackend, tenant: &str) {
        let client = backend.pool().get().await.unwrap();
        for sql in [
            "DELETE FROM cirislens.federation_trust_grants WHERE tenant_id = $1",
            "DELETE FROM cirislens.merkle_sth_log WHERE tenant_id = $1",
            "DELETE FROM cirislens.merkle_leaves WHERE tenant_id = $1",
            "DELETE FROM cirislens.audit_log WHERE tenant_id = $1",
        ] {
            client.execute(sql, &[&tenant]).await.unwrap();
        }
    }

    /// v1.5.0 Phase E PG happy path.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn pg_grant_trust_happy_path() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        let signer = build_signer(0x91);
        backend.set_merkle_signer(Some(signer.clone()));
        let granter_b64 = signer.public_key_b64();
        let grantee_b64 = base64::engine::general_purpose::STANDARD.encode(
            SigningKey::from_bytes(&[0x92; 32])
                .verifying_key()
                .to_bytes(),
        );
        let tenant = format!("pg-phase-e-happy-{}", Uuid::new_v4().simple());
        pg_cleanup(&backend, &tenant).await;
        pg_seed_federation_key(&backend, &granter_b64).await;
        pg_seed_federation_key(&backend, &grantee_b64).await;

        let receipt = grant_trust(
            &backend,
            &signer,
            &tenant,
            &grantee_b64,
            TrustPurpose::Contribution,
            "proposal:registry_vouch",
            None,
            "phase-e-pg-happy",
        )
        .await
        .expect("grant_trust");

        assert_eq!(receipt.tenant_id, tenant);
        assert_eq!(receipt.chain_event_id, 1);
        assert_eq!(receipt.chain_event_hash.len(), 32);
        assert_eq!(receipt.tree_size_at_emit, 1);
        assert_eq!(receipt.sth.tree_size, 1);
        assert_eq!(receipt.sth.log_id, format!("tenant:{tenant}"));

        // Chain row exists.
        let page = backend
            .list_entries(
                AuditFilter {
                    tenant_id: tenant.clone(),
                    action_type: None,
                    actor_id: None,
                    subject_kind: Some(TRUST_GRANT_SUBJECT_KIND.to_owned()),
                    subject_id: None,
                    recorded_after: None,
                    recorded_before: None,
                },
                None,
                10,
            )
            .await
            .unwrap();
        assert_eq!(page.items.len(), 1);

        // Merkle + STH rows exist.
        let client = backend.pool().get().await.unwrap();
        let leaves: i64 = client
            .query_one(
                "SELECT COUNT(*)::BIGINT FROM cirislens.merkle_leaves WHERE tenant_id = $1",
                &[&tenant],
            )
            .await
            .unwrap()
            .get(0);
        let sth_rows: i64 = client
            .query_one(
                "SELECT COUNT(*)::BIGINT FROM cirislens.merkle_sth_log WHERE tenant_id = $1",
                &[&tenant],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(leaves, 1);
        assert_eq!(sth_rows, 1);

        // Projection row exists with expected values.
        let row = client
            .query_one(
                "SELECT grantee_key, granter_key, purpose, scope, revoked_at \
                 FROM cirislens.federation_trust_grants \
                 WHERE grantee_key = $1 AND granter_key = $2",
                &[&grantee_b64, &granter_b64],
            )
            .await
            .unwrap();
        let purpose: String = row.get("purpose");
        let scope: String = row.get("scope");
        let revoked_at: Option<chrono::DateTime<Utc>> = row.get("revoked_at");
        assert_eq!(purpose, "contribution");
        assert_eq!(scope, "proposal:registry_vouch");
        assert!(revoked_at.is_none());

        pg_cleanup(&backend, &tenant).await;
    }

    /// v1.5.0 Phase E PG: revoke_trust_grant populates revocation
    /// columns.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn pg_revoke_trust_grant_populates_revocation_columns() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        let signer = build_signer(0xA1);
        backend.set_merkle_signer(Some(signer.clone()));
        let granter_b64 = signer.public_key_b64();
        let grantee_b64 = base64::engine::general_purpose::STANDARD.encode(
            SigningKey::from_bytes(&[0xA2; 32])
                .verifying_key()
                .to_bytes(),
        );
        let tenant = format!("pg-phase-e-revoke-{}", Uuid::new_v4().simple());
        pg_cleanup(&backend, &tenant).await;
        pg_seed_federation_key(&backend, &granter_b64).await;
        pg_seed_federation_key(&backend, &grantee_b64).await;

        let _g = grant_trust(
            &backend,
            &signer,
            &tenant,
            &grantee_b64,
            TrustPurpose::Deferral,
            "medical_deferral",
            None,
            "phase-e-pg-initial",
        )
        .await
        .unwrap();

        let r = revoke_trust_grant(
            &backend,
            &signer,
            &tenant,
            &grantee_b64,
            TrustPurpose::Deferral,
            "medical_deferral",
        )
        .await
        .unwrap();
        assert_eq!(r.chain_event_id, 2);
        assert_eq!(r.tree_size_at_emit, 2);

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
        let revoked_at: Option<chrono::DateTime<Utc>> = row.get("revoked_at");
        let revoked_by: Option<String> = row.get("revoked_by");
        assert!(revoked_at.is_some());
        assert_eq!(revoked_by.as_deref(), Some(granter_b64.as_str()));

        pg_cleanup(&backend, &tenant).await;
    }

    /// v1.5.0 Phase E PG: self-grant rejected at API boundary.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn pg_self_grant_rejected() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        let signer = build_signer(0xB1);
        backend.set_merkle_signer(Some(signer.clone()));
        let pubkey = signer.public_key_b64();
        let tenant = format!("pg-phase-e-self-{}", Uuid::new_v4().simple());

        let err = grant_trust(
            &backend,
            &signer,
            &tenant,
            &pubkey,
            TrustPurpose::Service,
            "service:llm",
            None,
            "phase-e-pg-self",
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, EmitError::InvalidArgument(ref m) if m.contains("self-grant")),
            "expected InvalidArgument(self-grant), got {err:?}"
        );
        pg_cleanup(&backend, &tenant).await;
    }
}
