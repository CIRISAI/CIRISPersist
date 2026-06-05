//! V020 → V021 backfill (v1.5.0 Phase I, FSD §6.2).
//!
//! One-shot migration: walks `federation_keys` for rows where
//! `trust_relationship` is non-NULL AND `trusted_by` equals the local
//! signer's pubkey; emits a synthetic `TrustGrant` Contribution per
//! domain (or one with `scope='*'` for direct grants); records each
//! via [`AuditService::record_entry`], which triggers the Phase C
//! Merkle hook + Phase D projection automatically.
//!
//! # Scope constraint (FSD §6.2 + §3.1)
//!
//! The FSD says synthetic grants must be "signed by the recovered
//! `trusted_by` key." Phase I has access only to the local signer's
//! private key — we cannot sign as an arbitrary peer. So the backfill
//! is restricted to rows where `V020.trusted_by == local_signer.public_key_b64()`.
//! Rows granted by *other* peers remain readable from the V020 trust
//! columns during the v1.5.x compat window (FSD §6.3) and are
//! expected to be re-emitted by the *granter's* engine on its own
//! V021 backfill. This matches FSD §3.1's "granter is `author_id` at
//! envelope level" — only the granter can re-emit on the chain.
//!
//! # Mapping rules (FSD §6.2)
//!
//! | V020 shape                                               | V021 emission                                              |
//! |----------------------------------------------------------|------------------------------------------------------------|
//! | `trust_relationship='direct'` (any `trust_type`)         | one TrustGrant: `purpose=Deferral`, `scope='*'`            |
//! | `trust_relationship='registry'`, `trust_domains=[d1, …]` | N TrustGrants: one per `d_i` at `purpose=Deferral, scope=d_i` |
//!
//! `expires_at` is mapped directly; `rationale` carries
//! `"v020-backfill: {trust_type}+{trust_relationship}"` so the chain
//! has provenance.
//!
//! # Idempotency
//!
//! Re-running calls [`AuditService::lookup_trust_grant`] before each
//! emit and skips any row where a projection already exists for the
//! `(grantee, granter, purpose, scope)` quad. Skipping projection-hit
//! rows means the backfill is safe to call multiple times — from a
//! startup hook, an explicit `Engine.backfill_v020_trust_rows()`, and
//! a CI sweep, in any order.
#![allow(clippy::redundant_closure_call)]
// v3.14.0 (CIRISPersist#158) — inline-sync rewrite of all
// tokio::task::spawn_blocking sites uses (closure)() to invoke
// the closure inline. Clippy's redundant_closure_call lint flags
// this; we allow it because the mechanical transformation kept
// each closure's typed return signature load-bearing for error
// propagation and any other refactor would be a much larger diff.

use crate::audit::AuditService;
use crate::federation::emit::{grant_trust, EmitError};
use crate::federation::trust_grant::{TrustPurpose, V020TrustRow};
use crate::signing::LocalSigner;

/// Errors from [`backfill_v020_trust_rows`]. Wraps the underlying
/// audit + emit failure surfaces; the chain commit step in particular
/// can fail with the full [`crate::audit::Error`] tree via
/// [`EmitError::Audit`].
#[derive(Debug, thiserror::Error)]
pub enum BackfillError {
    /// Emit-side failure from [`grant_trust`] (covers signing,
    /// projection materialization, post-emit STH retrieval, …).
    #[error("emit: {0}")]
    Emit(#[from] EmitError),
    /// Backend-side error reading V020 rows or running the
    /// idempotency lookup (the `lookup_trust_grant` call before
    /// each emit).
    #[error("audit: {0}")]
    Audit(#[from] crate::audit::Error),
    /// Caller-side validation failure (empty tenant_id, empty signer
    /// pubkey, …).
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
}

/// Outcome of one backfill run. All counts are over *emissions*, not
/// V020 source rows — a single Registry row with N domains
/// contributes N to `events_emitted` (or N to `already_present` if
/// the corresponding V021 grants are already projected).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BackfillReport {
    /// Total V020 rows considered (those returned by
    /// `AuditService::read_v020_trust_rows_for_local`, i.e., rows
    /// with `trust_relationship IS NOT NULL` AND
    /// `trusted_by = local_pubkey`).
    pub rows_scanned: u64,
    /// `TrustGrant` Contribution events successfully emitted on the
    /// chain (one per direct row, N per registry row).
    pub events_emitted: u64,
    /// Emissions skipped because a `federation_trust_grants` projection
    /// row already existed matching `(grantee, granter, purpose, scope)`
    /// — i.e., a previous backfill (or live emit) already covered the
    /// quad. Idempotent re-run path.
    pub already_present: u64,
}

/// Run the V020 → V021 backfill for one tenant (FSD §6.2).
///
/// Flow:
/// 1. SELECT all `federation_keys` rows where
///    `trusted_by = signer.public_key_b64()` AND
///    `trust_relationship IS NOT NULL` (the
///    [`AuditService::read_v020_trust_rows_for_local`] surface).
/// 2. For each row, expand to one or more
///    `(purpose=Deferral, scope)` tuples:
///       - `direct` → one tuple with `scope='*'`
///       - `registry` → one tuple per `trust_domains` entry (or skip
///         the row with no emissions if `trust_domains` is `None` or
///         empty — these are malformed V020 rows that bypassed the
///         API-layer guard).
/// 3. For each tuple, call [`AuditService::lookup_trust_grant`]
///    (include_revoked=false, include_expired=false) and skip if a
///    row exists matching the granter.
/// 4. Otherwise call [`grant_trust`] — which triggers Phase C +
///    Phase D inline.
/// 5. Return the per-run [`BackfillReport`].
///
/// # Tenant scope
///
/// The `tenant_id` is caller-specified. Backfilled grants land on
/// that tenant's audit chain + Merkle tree. Typical usage: one
/// backfill call per tenant the engine is responsible for. The
/// V020 row's `trusted_at` is informational only — the V021
/// projection's `granted_at` is set to the emission timestamp
/// (audit-chain semantics: state transitions happen when the chain
/// records them).
///
/// # Atomicity
///
/// Each emit is its own audit chain entry; the call is *not*
/// transactional across rows. A failure mid-run leaves the chain
/// with the entries already emitted plus the V020 source rows still
/// readable. The next backfill run picks up where this one left off
/// thanks to the idempotency check.
pub async fn backfill_v020_trust_rows<A>(
    backend: &A,
    signer: &LocalSigner,
    tenant_id: &str,
) -> Result<BackfillReport, BackfillError>
where
    A: AuditService,
{
    if tenant_id.is_empty() {
        return Err(BackfillError::InvalidArgument(
            "tenant_id must be non-empty".into(),
        ));
    }
    let granter_key = signer.public_key_b64();
    if granter_key.is_empty() {
        return Err(BackfillError::InvalidArgument(
            "signer.public_key_b64() returned empty string".into(),
        ));
    }

    // 1. SELECT the V020 rows this engine can re-emit.
    let rows = backend.read_v020_trust_rows_for_local(&granter_key).await?;
    let mut report = BackfillReport {
        rows_scanned: rows.len() as u64,
        ..Default::default()
    };

    for row in rows {
        // 2. Expand each V020 row → one or more
        //    `(purpose, scope)` emission tuples.
        let scopes: Vec<String> = expand_scopes(&row);
        for scope in scopes {
            // 3. Idempotency check — skip if the (grantee, granter,
            //    purpose, scope) quad already has a live projection
            //    row. We pass include_revoked=false +
            //    include_expired=false because we're asking "is this
            //    grant LIVE on V021?" — a revoked-or-expired prior
            //    projection should still trigger a re-emit so the
            //    chain reflects the V020 row's current state.
            //
            //    `lookup_trust_grant` returns rows from ALL granters
            //    plus wildcard rows; we filter to the local granter
            //    in Rust.
            let existing = backend
                .lookup_trust_grant(
                    &row.grantee_pubkey,
                    TrustPurpose::Deferral,
                    &scope,
                    false,
                    false,
                )
                .await?;
            let local_match = existing
                .iter()
                .any(|r| r.granter_key == granter_key && r.scope == scope);
            if local_match {
                report.already_present += 1;
                continue;
            }

            // 4. Emit. The Phase C Merkle hook + Phase D projection
            //    fire inline inside `grant_trust`.
            let rationale = format!(
                "v020-backfill: {}+{}",
                row.trust_type, row.trust_relationship
            );
            grant_trust(
                backend,
                signer,
                tenant_id,
                &row.grantee_pubkey,
                TrustPurpose::Deferral,
                &scope,
                row.expires_at,
                &rationale,
            )
            .await?;
            report.events_emitted += 1;
        }
    }

    Ok(report)
}

/// Per the FSD §6.2 mapping rule, expand one V020 row to the list of
/// scopes that need a `TrustGrant` emission. Returns:
///
/// - `vec!["*".into()]` for `trust_relationship='direct'` rows
///   (irrespective of `trust_type`).
/// - One scope string per `trust_domains` entry for
///   `trust_relationship='registry'` rows.
/// - Empty `vec![]` for malformed rows (Registry with NULL/empty
///   `trust_domains`, or an unknown `trust_relationship` string).
///   Malformed rows shouldn't exist (V020 API-layer + PG CHECKs
///   guard against them) but we tolerate them by skipping rather
///   than erroring out the whole run — Phase I is a best-effort
///   one-shot migration.
fn expand_scopes(row: &V020TrustRow) -> Vec<String> {
    match row.trust_relationship.as_str() {
        "direct" => vec!["*".to_owned()],
        "registry" => row.trust_domains.as_ref().cloned().unwrap_or_default(),
        _ => Vec::new(),
    }
}

// ─────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────

#[cfg(all(test, feature = "sqlite", feature = "cirisaudit"))]
mod sqlite_tests {
    use super::*;
    use crate::audit::sqlite::SqliteAuditBackend;
    use crate::store::sqlite::SqliteBackend;
    use crate::store::Backend;
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    use ciris_keyring::MlDsa65SoftwareSigner;
    use ed25519_dalek::SigningKey;
    use std::sync::Arc;
    use uuid::Uuid;

    /// Build a LocalSigner with PQC configured. The Phase C Merkle
    /// hook requires `sign_hybrid` so the signer must carry both
    /// Ed25519 + ML-DSA-65 material.
    fn build_signer(seed_byte: u8) -> Arc<LocalSigner> {
        let signing_key = SigningKey::from_bytes(&[seed_byte; 32]);
        let pqc =
            MlDsa65SoftwareSigner::from_seed_bytes(&[seed_byte ^ 0x55; 32], "phase-i-test-pqc")
                .expect("pqc seed");
        let pqc_arc: Arc<dyn ciris_keyring::PqcSigner> = Arc::new(pqc);
        Arc::new(LocalSigner::from_parts(
            signing_key,
            "phase-i-test-steward".to_owned(),
            Some(pqc_arc),
            Some("phase-i-test-pqc".to_owned()),
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

    /// Seed a `federation_keys` row so V021's projection FK + the
    /// V020 backfill's SELECT both find the grantee. The row carries
    /// V020 trust columns inline. `pubkey` is used as both `key_id`
    /// and `pubkey_ed25519_base64` (the V004 pattern that the tests
    /// rely on; the Phase E test helper does the same).
    #[allow(clippy::too_many_arguments)]
    async fn seed_federation_key_with_v020(
        audit: &SqliteAuditBackend,
        pubkey: &str,
        trust_type: &str,
        trust_relationship: &str,
        trust_domains: Option<Vec<String>>,
        trusted_by: Option<&str>,
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
    ) {
        let conn = audit.conn_handle();
        let pubkey = pubkey.to_owned();
        let trust_type = trust_type.to_owned();
        let trust_relationship = trust_relationship.to_owned();
        let trust_domains_json: Option<String> =
            trust_domains.map(|d| serde_json::to_string(&d).expect("domains json"));
        let trusted_by = trusted_by.map(|s| s.to_owned());
        let expires_at_str: Option<String> =
            expires_at.map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Micros, true));
        let trusted_at_str =
            chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
        (move || {
            let conn = conn.lock();
            conn.execute(
                "INSERT OR REPLACE INTO federation_keys (\
                    key_id, pubkey_ed25519_base64, algorithm, \
                    identity_type, identity_ref, valid_from, \
                    registration_envelope, original_content_hash, \
                    scrub_signature_classical, scrub_key_id, \
                    scrub_timestamp, persist_row_hash, \
                    trust_type, trust_relationship, trust_domains, \
                    trusted_by, trusted_at, expires_at\
                 ) VALUES (?1, ?1, 'hybrid', 'agent', ?1, \
                          '2026-01-01T00:00:00Z', '{}', x'00', '', ?1, \
                          '2026-01-01T00:00:00Z', '0', \
                          ?2, ?3, ?4, ?5, ?6, ?7)",
                rusqlite::params![
                    pubkey,
                    trust_type,
                    trust_relationship,
                    trust_domains_json,
                    trusted_by,
                    trusted_at_str,
                    expires_at_str,
                ],
            )
            .unwrap();
        })();
    }

    /// Insert a plain `federation_keys` row without V020 trust columns
    /// (used to satisfy the V021 projection FK for the grantee side
    /// when the grantee itself isn't a V020-granted row).
    async fn seed_plain_federation_key(audit: &SqliteAuditBackend, pubkey: &str) {
        let conn = audit.conn_handle();
        let pubkey = pubkey.to_owned();
        (move || {
            let conn = conn.lock();
            conn.execute(
                "INSERT OR IGNORE INTO federation_keys (\
                    key_id, pubkey_ed25519_base64, algorithm, \
                    identity_type, identity_ref, valid_from, \
                    registration_envelope, original_content_hash, \
                    scrub_signature_classical, scrub_key_id, \
                    scrub_timestamp, persist_row_hash\
                 ) VALUES (?1, ?1, 'hybrid', 'agent', ?1, \
                          '2026-01-01T00:00:00Z', '{}', x'00', '', ?1, \
                          '2026-01-01T00:00:00Z', '0')",
                rusqlite::params![pubkey],
            )
            .unwrap();
        })();
    }

    fn pubkey_for(seed_byte: u8) -> String {
        B64.encode(
            SigningKey::from_bytes(&[seed_byte; 32])
                .verifying_key()
                .to_bytes(),
        )
    }

    /// No V020 rows present → report shows zeros across the board.
    #[tokio::test]
    async fn sqlite_backfill_empty_report_when_no_rows() {
        let (_b, audit, signer) = fresh_audit(0x10).await;
        let tenant = format!("phase-i-empty-{}", Uuid::new_v4().simple());
        let report = backfill_v020_trust_rows(&audit, &signer, &tenant)
            .await
            .expect("backfill");
        assert_eq!(report.rows_scanned, 0);
        assert_eq!(report.events_emitted, 0);
        assert_eq!(report.already_present, 0);
    }

    /// One `direct` V020 row → one `(Deferral, '*')` emission.
    #[tokio::test]
    async fn sqlite_backfill_direct_row_emits_wildcard_grant() {
        let (_b, audit, signer) = fresh_audit(0x20).await;
        let granter = signer.public_key_b64();
        let grantee = pubkey_for(0x21);
        seed_plain_federation_key(&audit, &granter).await;
        seed_federation_key_with_v020(
            &audit,
            &grantee,
            "temporary",
            "direct",
            None,
            Some(&granter),
            None,
        )
        .await;

        let tenant = format!("phase-i-direct-{}", Uuid::new_v4().simple());
        let report = backfill_v020_trust_rows(&audit, &signer, &tenant)
            .await
            .expect("backfill");
        assert_eq!(report.rows_scanned, 1);
        assert_eq!(report.events_emitted, 1);
        assert_eq!(report.already_present, 0);

        // Projection row carries scope='*' and purpose='deferral'.
        let rows = audit
            .lookup_trust_grant(&grantee, TrustPurpose::Deferral, "*", false, false)
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].granter_key, granter);
        assert_eq!(rows[0].scope, "*");
        assert_eq!(rows[0].tenant_id, tenant);
    }

    /// One `registry` row with 3 domains → 3 emissions, one per domain.
    #[tokio::test]
    async fn sqlite_backfill_registry_row_emits_per_domain() {
        let (_b, audit, signer) = fresh_audit(0x30).await;
        let granter = signer.public_key_b64();
        let grantee = pubkey_for(0x31);
        seed_plain_federation_key(&audit, &granter).await;
        seed_federation_key_with_v020(
            &audit,
            &grantee,
            "partnered",
            "registry",
            Some(vec![
                "medical_deferral".to_owned(),
                "legal_deferral".to_owned(),
                "ethics_deferral".to_owned(),
            ]),
            Some(&granter),
            None,
        )
        .await;

        let tenant = format!("phase-i-registry-{}", Uuid::new_v4().simple());
        let report = backfill_v020_trust_rows(&audit, &signer, &tenant)
            .await
            .expect("backfill");
        assert_eq!(report.rows_scanned, 1);
        assert_eq!(report.events_emitted, 3);
        assert_eq!(report.already_present, 0);

        // Each domain has its own projection row.
        for scope in ["medical_deferral", "legal_deferral", "ethics_deferral"] {
            let rows = audit
                .lookup_trust_grant(&grantee, TrustPurpose::Deferral, scope, false, false)
                .await
                .unwrap();
            assert_eq!(
                rows.len(),
                1,
                "expected one projection row for scope={scope}; got {rows:?}"
            );
            assert_eq!(rows[0].granter_key, granter);
            assert_eq!(rows[0].scope, scope);
        }
    }

    /// Mixed direct + registry rows: counts add correctly.
    #[tokio::test]
    async fn sqlite_backfill_mixed_direct_and_registry_counts() {
        let (_b, audit, signer) = fresh_audit(0x40).await;
        let granter = signer.public_key_b64();
        let grantee_direct = pubkey_for(0x41);
        let grantee_registry = pubkey_for(0x42);
        seed_plain_federation_key(&audit, &granter).await;
        seed_federation_key_with_v020(
            &audit,
            &grantee_direct,
            "temporary",
            "direct",
            None,
            Some(&granter),
            None,
        )
        .await;
        seed_federation_key_with_v020(
            &audit,
            &grantee_registry,
            "partnered",
            "registry",
            Some(vec![
                "medical_deferral".to_owned(),
                "legal_deferral".to_owned(),
            ]),
            Some(&granter),
            None,
        )
        .await;

        let tenant = format!("phase-i-mixed-{}", Uuid::new_v4().simple());
        let report = backfill_v020_trust_rows(&audit, &signer, &tenant)
            .await
            .expect("backfill");
        assert_eq!(report.rows_scanned, 2);
        assert_eq!(report.events_emitted, 3, "1 direct + 2 registry");
        assert_eq!(report.already_present, 0);
    }

    /// V020 row trusted_by a different peer → NOT in the scan set;
    /// nothing emitted.
    #[tokio::test]
    async fn sqlite_backfill_skips_other_granter_rows() {
        let (_b, audit, signer) = fresh_audit(0x50).await;
        let local_granter = signer.public_key_b64();
        let other_granter = pubkey_for(0x51);
        let grantee = pubkey_for(0x52);
        seed_plain_federation_key(&audit, &local_granter).await;
        seed_plain_federation_key(&audit, &other_granter).await;
        // Row granted by the OTHER peer — not us.
        seed_federation_key_with_v020(
            &audit,
            &grantee,
            "temporary",
            "direct",
            None,
            Some(&other_granter),
            None,
        )
        .await;

        let tenant = format!("phase-i-other-{}", Uuid::new_v4().simple());
        let report = backfill_v020_trust_rows(&audit, &signer, &tenant)
            .await
            .expect("backfill");
        assert_eq!(report.rows_scanned, 0, "row excluded by trusted_by filter");
        assert_eq!(report.events_emitted, 0);
        assert_eq!(report.already_present, 0);

        // No V021 projection row landed.
        let rows = audit
            .lookup_trust_grant(&grantee, TrustPurpose::Deferral, "*", true, true)
            .await
            .unwrap();
        assert!(rows.is_empty());
    }

    /// Run twice: second run shows the same rows_scanned but zero
    /// emissions and the prior count surfaced as `already_present`.
    #[tokio::test]
    async fn sqlite_backfill_is_idempotent_across_reruns() {
        let (_b, audit, signer) = fresh_audit(0x60).await;
        let granter = signer.public_key_b64();
        let grantee_direct = pubkey_for(0x61);
        let grantee_registry = pubkey_for(0x62);
        seed_plain_federation_key(&audit, &granter).await;
        seed_federation_key_with_v020(
            &audit,
            &grantee_direct,
            "temporary",
            "direct",
            None,
            Some(&granter),
            None,
        )
        .await;
        seed_federation_key_with_v020(
            &audit,
            &grantee_registry,
            "partnered",
            "registry",
            Some(vec![
                "medical_deferral".to_owned(),
                "legal_deferral".to_owned(),
            ]),
            Some(&granter),
            None,
        )
        .await;

        let tenant = format!("phase-i-idempotent-{}", Uuid::new_v4().simple());

        let r1 = backfill_v020_trust_rows(&audit, &signer, &tenant)
            .await
            .expect("first backfill");
        assert_eq!(r1.rows_scanned, 2);
        assert_eq!(r1.events_emitted, 3);
        assert_eq!(r1.already_present, 0);

        let r2 = backfill_v020_trust_rows(&audit, &signer, &tenant)
            .await
            .expect("second backfill");
        assert_eq!(r2.rows_scanned, 2, "scan set unchanged");
        assert_eq!(r2.events_emitted, 0, "no fresh emissions");
        assert_eq!(
            r2.already_present, 3,
            "3 prior emissions surface via the idempotency check"
        );
    }

    /// Empty tenant_id rejected at the API boundary.
    #[tokio::test]
    async fn sqlite_backfill_rejects_empty_tenant() {
        let (_b, audit, signer) = fresh_audit(0x70).await;
        let err = backfill_v020_trust_rows(&audit, &signer, "")
            .await
            .unwrap_err();
        assert!(
            matches!(err, BackfillError::InvalidArgument(ref m) if m.contains("tenant_id")),
            "expected InvalidArgument(tenant_id), got {err:?}"
        );
    }
}

#[cfg(all(test, feature = "postgres", feature = "cirisaudit"))]
mod postgres_tests {
    use super::*;
    use crate::store::postgres::PostgresBackend;
    use crate::store::Backend;
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    use ciris_keyring::MlDsa65SoftwareSigner;
    use ed25519_dalek::SigningKey;
    use std::sync::Arc;
    use uuid::Uuid;

    fn pg_dsn() -> Option<String> {
        std::env::var("CIRIS_PERSIST_TEST_PG_URL").ok()
    }

    fn build_signer(seed_byte: u8) -> Arc<LocalSigner> {
        let signing_key = SigningKey::from_bytes(&[seed_byte; 32]);
        let pqc =
            MlDsa65SoftwareSigner::from_seed_bytes(&[seed_byte ^ 0x55; 32], "phase-i-pg-test-pqc")
                .expect("pqc seed");
        let pqc_arc: Arc<dyn ciris_keyring::PqcSigner> = Arc::new(pqc);
        Arc::new(LocalSigner::from_parts(
            signing_key,
            "phase-i-pg-test-steward".to_owned(),
            Some(pqc_arc),
            Some("phase-i-pg-test-pqc".to_owned()),
        ))
    }

    async fn pg_seed_plain_federation_key(backend: &PostgresBackend, pubkey: &str) {
        let client = backend.pool().get().await.unwrap();
        client
            .execute(
                "INSERT INTO cirislens.federation_keys (\
                    key_id, pubkey_ed25519_base64, algorithm, identity_type, \
                    identity_ref, valid_from, registration_envelope, \
                    original_content_hash, scrub_signature_classical, \
                    scrub_key_id, scrub_timestamp, persist_row_hash\
                 ) VALUES ($1, $1, 'hybrid', 'agent', $1, NOW(), \
                          '{}'::jsonb, decode('00', 'hex'), '', $1, NOW(), '0') \
                 ON CONFLICT (key_id) DO NOTHING",
                &[&pubkey],
            )
            .await
            .unwrap();
    }

    async fn pg_seed_federation_key_with_v020(
        backend: &PostgresBackend,
        pubkey: &str,
        trust_type: &str,
        trust_relationship: &str,
        trust_domains: Option<&[&str]>,
        trusted_by: Option<&str>,
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
    ) {
        let client = backend.pool().get().await.unwrap();
        let domains_owned: Vec<String> = trust_domains
            .map(|d| d.iter().map(|s| (*s).to_owned()).collect())
            .unwrap_or_default();
        let domains_param: Option<&Vec<String>> = if trust_domains.is_some() {
            Some(&domains_owned)
        } else {
            None
        };
        client
            .execute(
                "INSERT INTO cirislens.federation_keys (\
                    key_id, pubkey_ed25519_base64, algorithm, identity_type, \
                    identity_ref, valid_from, registration_envelope, \
                    original_content_hash, scrub_signature_classical, \
                    scrub_key_id, scrub_timestamp, persist_row_hash, \
                    trust_type, trust_relationship, trust_domains, \
                    trusted_by, trusted_at, expires_at\
                 ) VALUES ($1, $1, 'hybrid', 'agent', $1, NOW(), \
                          '{}'::jsonb, decode('00', 'hex'), '', $1, NOW(), '0', \
                          $2, $3, $4, $5, NOW(), $6) \
                 ON CONFLICT (key_id) DO UPDATE SET \
                    trust_type = EXCLUDED.trust_type, \
                    trust_relationship = EXCLUDED.trust_relationship, \
                    trust_domains = EXCLUDED.trust_domains, \
                    trusted_by = EXCLUDED.trusted_by, \
                    trusted_at = EXCLUDED.trusted_at, \
                    expires_at = EXCLUDED.expires_at",
                &[
                    &pubkey,
                    &trust_type,
                    &trust_relationship,
                    &domains_param,
                    &trusted_by,
                    &expires_at,
                ],
            )
            .await
            .unwrap();
    }

    // v3.5.1 (CIRISPersist#128) — seed-byte allocation for PG tests in
    // this module. `federation/emit.rs`'s tests claim 0x81/0x91/0xA1/
    // 0xB1; collisions on the shared `federation_keys` row cause FK
    // violations when nextest processes tests from both modules in
    // parallel (`serial_test::serial(postgres)` only serializes within
    // a process). Backfill claims the 0xC0-range to keep the two
    // modules disjoint.
    async fn pg_cleanup(backend: &PostgresBackend, tenant: &str, pubkeys: &[&str]) {
        let client = backend.pool().get().await.unwrap();
        for sql in [
            "DELETE FROM cirislens.federation_trust_grants WHERE tenant_id = $1",
            "DELETE FROM cirislens.merkle_sth_log WHERE tenant_id = $1",
            "DELETE FROM cirislens.merkle_leaves WHERE tenant_id = $1",
            "DELETE FROM cirislens.audit_log WHERE tenant_id = $1",
        ] {
            client.execute(sql, &[&tenant]).await.unwrap();
        }
        for pk in pubkeys {
            client
                .execute(
                    "DELETE FROM cirislens.federation_keys WHERE key_id = $1",
                    &[pk],
                )
                .await
                .unwrap();
        }
    }

    fn pubkey_for(seed_byte: u8) -> String {
        B64.encode(
            SigningKey::from_bytes(&[seed_byte; 32])
                .verifying_key()
                .to_bytes(),
        )
    }

    /// PG happy path: mixed direct + registry rows backfill to the
    /// expected number of V021 projection rows, idempotent re-run
    /// observes them as already_present.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn pg_backfill_mixed_and_idempotent() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        let signer = build_signer(0xC1);
        backend.set_merkle_signer(Some(signer.clone()));
        let granter = signer.public_key_b64();
        let grantee_direct = pubkey_for(0xC2);
        let grantee_registry = pubkey_for(0xC3);
        let tenant = format!("pg-phase-i-mixed-{}", Uuid::new_v4().simple());

        pg_cleanup(
            &backend,
            &tenant,
            &[&granter, &grantee_direct, &grantee_registry],
        )
        .await;
        pg_seed_plain_federation_key(&backend, &granter).await;
        pg_seed_federation_key_with_v020(
            &backend,
            &grantee_direct,
            "temporary",
            "direct",
            None,
            Some(&granter),
            None,
        )
        .await;
        pg_seed_federation_key_with_v020(
            &backend,
            &grantee_registry,
            "partnered",
            "registry",
            Some(&["medical_deferral", "legal_deferral"]),
            Some(&granter),
            None,
        )
        .await;

        let r1 = backfill_v020_trust_rows(&backend, &signer, &tenant)
            .await
            .expect("first backfill");
        assert_eq!(r1.rows_scanned, 2);
        assert_eq!(r1.events_emitted, 3, "1 direct + 2 registry");
        assert_eq!(r1.already_present, 0);

        let r2 = backfill_v020_trust_rows(&backend, &signer, &tenant)
            .await
            .expect("second backfill");
        assert_eq!(r2.rows_scanned, 2);
        assert_eq!(r2.events_emitted, 0);
        assert_eq!(r2.already_present, 3);

        pg_cleanup(
            &backend,
            &tenant,
            &[&granter, &grantee_direct, &grantee_registry],
        )
        .await;
    }

    /// PG: rows trusted_by a different peer are excluded by the
    /// local_pubkey filter.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn pg_backfill_skips_other_granter_rows() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        let signer = build_signer(0xD1);
        backend.set_merkle_signer(Some(signer.clone()));
        let local_granter = signer.public_key_b64();
        let other_granter = pubkey_for(0xD2);
        let grantee = pubkey_for(0xD3);
        let tenant = format!("pg-phase-i-other-{}", Uuid::new_v4().simple());

        pg_cleanup(
            &backend,
            &tenant,
            &[&local_granter, &other_granter, &grantee],
        )
        .await;
        pg_seed_plain_federation_key(&backend, &local_granter).await;
        pg_seed_plain_federation_key(&backend, &other_granter).await;
        pg_seed_federation_key_with_v020(
            &backend,
            &grantee,
            "temporary",
            "direct",
            None,
            Some(&other_granter),
            None,
        )
        .await;

        let report = backfill_v020_trust_rows(&backend, &signer, &tenant)
            .await
            .expect("backfill");
        assert_eq!(report.rows_scanned, 0);
        assert_eq!(report.events_emitted, 0);

        pg_cleanup(
            &backend,
            &tenant,
            &[&local_granter, &other_granter, &grantee],
        )
        .await;
    }
}
