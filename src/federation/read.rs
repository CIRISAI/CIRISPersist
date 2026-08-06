//! Trust-grant read + proof retrieval APIs (v1.5.0 Phase F+G, FSD §4.3 + §4.1).
//!
//! Free functions that compose the new `AuditService` projection
//! queries (Phase F) with the per-tenant
//! `TransparencyStore<AuditLeaf>` proof generators (Phase G). The
//! shape mirrors Phase E's `federation::emit`: a thin functional
//! surface over `&impl AuditService` so consumers (NodeCore's
//! `resolve_trust`, LensCore's verifier, the PyO3 façade landing in
//! Phase H) don't take a backend dependency at the trait level.
//!
//! # Design notes
//!
//! - **Caller decides on wildcards.** Per FSD §3.3, `scope = '*'`
//!   is a valid grant subject. [`lookup_trust_grant`] surfaces both
//!   exact-match and wildcard rows so the caller — the policy layer —
//!   decides whether a wildcard satisfies the specific question
//!   being asked. NodeCore's `resolve_trust` and persist's lower-
//!   level projection are explicitly NOT a policy decision.
//!
//! - **Live grants only by default.** [`lookup_trust_grant`] hides
//!   revoked + expired grants. [`list_trust_grants`] respects the
//!   filter's `include_revoked` / `include_expired` flags. The point
//!   is that the "current trust posture" view is the default and
//!   forensic queries need to opt in.
//!
//! - **Inclusion proof is a 3-tuple, not just a MerkleProof.**
//!   `verify_inclusion(&MerkleProof)` only checks the leaf →
//!   reconstructed-root walk; it doesn't verify the STH's signature
//!   or freshness. A verifier needs all of:
//!     1. the [`ciris_verify_core::transparency::SignedTreeHead`] (whose
//!        signature it verifies against the engine's pubkey + whose
//!        timestamp it checks against its freshness policy);
//!     2. the [`ciris_verify_core::transparency::MerkleProof`] (whose
//!        siblings it walks to reconstruct the root); and
//!     3. the canonical leaf bytes (so it can recompute
//!        `leaf_hash = sha256(0x00 || canonical)` from the audit
//!        entry's identity — not trust the directory's stored hash).
//!
//!   [`TrustGrantInclusionProof`] bundles all three.
//!
//! - **Consistency proof is just a `ConsistencyProof`.** The
//!   verifier already knows the two STHs it's checking; this API
//!   returns the inter-tree hashes RFC 6962 §2.1.2 needs.
//!
//! # Out of scope here
//!
//! - PyO3 wrappers — Phase H.
//! - Witness cosignature reads — reserved by Verify v2.3.0 (always
//!   empty); a dedicated read surface lands when the protocol does.
//! - Cross-tenant correlation — AV-51 forbids it; every read here is
//!   tenant-scoped via the grant's `tenant_id` column.
#![allow(clippy::redundant_closure_call)]
// v3.14.0 (CIRISPersist#158) — inline-sync rewrite of all
// tokio::task::spawn_blocking sites uses (closure)() to invoke
// the closure inline. Clippy's redundant_closure_call lint flags
// this; we allow it because the mechanical transformation kept
// each closure's typed return signature load-bearing for error
// propagation and any other refactor would be a much larger diff.

use ciris_verify_core::transparency::{ConsistencyProof, MerkleProof, SignedTreeHead};

use super::trust_grant::{TrustGrantFilter, TrustGrantRow, TrustPurpose};
use crate::audit::AuditService;

/// Read-side errors for the Phase F+G API.
#[derive(Debug, thiserror::Error)]
pub enum ReadError {
    /// Underlying [`AuditService`] failure (projection query, Merkle
    /// store, …). Wraps [`crate::audit::Error`].
    #[error("audit: {0}")]
    Audit(#[from] crate::audit::Error),

    /// The requested artifact wasn't found (grant_id has no projection
    /// row, tenant has no STH yet, chain event has no merkle leaf, …).
    #[error("not found: {0}")]
    NotFound(String),
}

/// Bundle of artifacts an external verifier needs to confirm a trust
/// grant is in the audit chain without trusting the directory's
/// projection. Per FSD §4.1.
///
/// # Verifier flow
///
/// 1. Verify [`Self::sth`]'s signature (hybrid Ed25519 + ML-DSA-65)
///    against the engine's published pubkey.
/// 2. Check [`Self::sth`]'s `timestamp` against the verifier's
///    freshness policy.
/// 3. Recompute `leaf_hash = sha256(0x00 || self.leaf_canonical_bytes)`.
/// 4. Walk [`Self::merkle_proof`]'s `siblings` from `leaf_hash` to a
///    reconstructed root.
/// 5. Assert reconstructed root equals `self.sth.root_hash` (which
///    equals `self.merkle_proof.root`).
///
/// `ciris_verify_core::transparency::verify_inclusion` performs
/// steps 3-5 on the [`MerkleProof`] directly; steps 1-2 are the
/// verifier's responsibility (they require its STH-signing pubkey
/// + freshness policy).
#[derive(Debug, Clone)]
pub struct TrustGrantInclusionProof {
    /// The current `SignedTreeHead` for the grant's tenant at the
    /// time the proof was generated. The verifier authenticates this
    /// against the engine's STH-signing pubkey.
    pub sth: SignedTreeHead,
    /// RFC 6962 inclusion proof for the grant's chain event against
    /// `sth.root_hash`. Includes the leaf hash + sibling path.
    pub merkle_proof: MerkleProof,
    /// The RFC 6962 §2.1 hashing-form bytes of the audit leaf —
    /// `sha256(0x00 || self.leaf_canonical_bytes)` reproduces
    /// `merkle_proof.leaf_hash`. The verifier recomputes the leaf
    /// hash from these bytes rather than trusting the directory.
    pub leaf_canonical_bytes: Vec<u8>,
}

/// Look up live (non-revoked, non-expired) trust grants for
/// `(grantee_key, purpose, scope)`. Returns rows from every granter
/// that matches plus rows with `scope = '*'` (caller's policy layer
/// decides whether a wildcard satisfies the question).
///
/// FSD §4.3 — the "is K trusted for P/S?" read surface NodeCore's
/// `resolve_trust` composes when walking the transitive grant graph.
pub async fn lookup_trust_grant<A: AuditService>(
    audit_service: &A,
    grantee_key: &str,
    purpose: TrustPurpose,
    scope: &str,
) -> Result<Vec<TrustGrantRow>, ReadError> {
    Ok(audit_service
        .lookup_trust_grant(grantee_key, purpose, scope, false, false)
        .await?)
}

/// Filter query over `federation_trust_grants`. All non-`None`
/// filter fields are AND-intersected; `scope_prefix` matches via
/// SQL `LIKE '<prefix>%'`. Revoked / expired rows are excluded
/// unless the matching `include_*` flag is set.
pub async fn list_trust_grants<A: AuditService>(
    audit_service: &A,
    filter: TrustGrantFilter,
) -> Result<Vec<TrustGrantRow>, ReadError> {
    Ok(audit_service.list_trust_grants(filter).await?)
}

/// Point lookup by canonical PK. Returns `None` if no projection
/// row exists for the `grant_id`. Useful when callers cache a
/// [`super::trust_grant::TrustGrantReceipt`] and later resolve it
/// back to the projection row.
pub async fn get_trust_grant<A: AuditService>(
    audit_service: &A,
    grant_id: uuid::Uuid,
) -> Result<Option<TrustGrantRow>, ReadError> {
    Ok(audit_service.get_trust_grant(grant_id).await?)
}

/// Generate the full inclusion-proof bundle for a grant. See
/// [`TrustGrantInclusionProof`] for the verifier flow.
///
/// Resolves `grant_id` → `(tenant_id, chain_event_id)` via the
/// projection, then fetches the current STH, the RFC 6962 inclusion
/// proof, and the leaf's canonical bytes (stored verbatim in
/// `merkle_leaves.canonical_bytes` per V021).
///
/// Returns [`ReadError::NotFound`] if the grant, the tenant's STH,
/// or the merkle leaf is missing.
pub async fn trust_grant_inclusion_proof<A: AuditService>(
    audit_service: &A,
    grant_id: uuid::Uuid,
) -> Result<TrustGrantInclusionProof, ReadError> {
    let row = audit_service
        .get_trust_grant(grant_id)
        .await?
        .ok_or_else(|| ReadError::NotFound(format!("grant {grant_id}")))?;
    let sth = audit_service
        .current_sth(&row.tenant_id)
        .await?
        .ok_or_else(|| ReadError::NotFound(format!("STH for tenant {}", row.tenant_id)))?;
    let merkle_proof = audit_service
        .inclusion_proof_for_chain_event(&row.tenant_id, row.chain_event_id)
        .await?;
    let leaf_canonical_bytes = audit_service
        .leaf_canonical_bytes_for_chain_event(&row.tenant_id, row.chain_event_id)
        .await?
        .ok_or_else(|| {
            ReadError::NotFound(format!(
                "merkle leaf for tenant={} chain_event_id={}",
                row.tenant_id, row.chain_event_id
            ))
        })?;
    Ok(TrustGrantInclusionProof {
        sth,
        merkle_proof,
        leaf_canonical_bytes,
    })
}

/// Generate an RFC 6962 §2.1.2 consistency proof between two tree
/// sizes for a tenant. Verifier holds `STH(old_size)` +
/// `STH(new_size)` and uses the returned `proof_hashes` plus
/// `ciris_verify_core::transparency::verify_consistency` to confirm
/// the new tree is a legal append of the old one — no retroactive
/// rewrite of historical leaves.
pub async fn trust_grant_consistency_proof<A: AuditService>(
    audit_service: &A,
    tenant_id: &str,
    old_size: u64,
    new_size: u64,
) -> Result<ConsistencyProof, ReadError> {
    Ok(audit_service
        .consistency_proof(tenant_id, old_size, new_size)
        .await?)
}

// ─────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────

#[cfg(all(test, feature = "sqlite", feature = "cirisaudit"))]
mod sqlite_tests {
    use super::*;
    use crate::audit::merkle_store::hash_leaf;
    use crate::audit::sqlite::SqliteAuditBackend;
    use crate::federation::emit::{grant_trust, revoke_trust_grant};
    use crate::federation::trust_grant::{TrustGrantFilter, TrustPurpose};
    use crate::signing::LocalSigner;
    use crate::store::sqlite::SqliteBackend;
    use crate::store::Backend;
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    use ciris_keyring::MlDsa65SoftwareSigner;
    use ciris_verify_core::transparency::{verify_consistency, verify_inclusion};
    use ed25519_dalek::SigningKey;
    use std::sync::Arc;
    use uuid::Uuid;

    fn build_signer(seed_byte: u8) -> Arc<LocalSigner> {
        let signing_key = SigningKey::from_bytes(&[seed_byte; 32]);
        let pqc =
            MlDsa65SoftwareSigner::from_seed_bytes(&[seed_byte ^ 0x55; 32], "phase-fg-test-pqc")
                .expect("pqc seed");
        let pqc_arc: Arc<dyn ciris_keyring::PqcSigner> = Arc::new(pqc);
        Arc::new(LocalSigner::from_parts(
            signing_key,
            "phase-fg-test-steward".to_owned(),
            Some(pqc_arc),
            Some("phase-fg-test-pqc".to_owned()),
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

    /// Seed a federation_keys row so the trust_grant projection's FKs
    /// against federation_keys(key_id) are satisfied. Mirrors Phase E
    /// test helper.
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

    fn grantee_key(seed_byte: u8) -> String {
        B64.encode(
            SigningKey::from_bytes(&[seed_byte; 32])
                .verifying_key()
                .to_bytes(),
        )
    }

    /// Phase F: lookup_trust_grant returns exact-match rows for a
    /// (grantee, purpose, scope) tuple, hiding revoked + expired.
    #[tokio::test]
    async fn sqlite_lookup_trust_grant_exact_match() {
        let (_b, audit, signer) = fresh_audit(0x10).await;
        let granter = signer.public_key_b64();
        let grantee = grantee_key(0x11);
        let tenant = format!("phase-fg-exact-{}", Uuid::new_v4().simple());
        seed_federation_key(&audit, &granter).await;
        seed_federation_key(&audit, &grantee).await;

        grant_trust(
            &audit,
            &signer,
            &tenant,
            &grantee,
            TrustPurpose::Contribution,
            "proposal:registry_vouch",
            None,
            "phase-fg-exact",
        )
        .await
        .unwrap();

        let rows = lookup_trust_grant(
            &audit,
            &grantee,
            TrustPurpose::Contribution,
            "proposal:registry_vouch",
        )
        .await
        .unwrap();
        assert_eq!(rows.len(), 1, "exactly one matching grant");
        assert_eq!(rows[0].grantee_key, grantee);
        assert_eq!(rows[0].granter_key, granter);
        assert_eq!(rows[0].scope, "proposal:registry_vouch");
        assert!(rows[0].revoked_at.is_none());
    }

    /// Phase F + FSD §3.3: a wildcard scope grant is surfaced
    /// alongside exact-match rows; caller decides.
    #[tokio::test]
    async fn sqlite_lookup_trust_grant_wildcard_surfaces_alongside_exact() {
        let (_b, audit, signer) = fresh_audit(0x20).await;
        let granter = signer.public_key_b64();
        let grantee = grantee_key(0x21);
        let tenant = format!("phase-fg-wild-{}", Uuid::new_v4().simple());
        seed_federation_key(&audit, &granter).await;
        seed_federation_key(&audit, &grantee).await;

        // Wildcard grant.
        grant_trust(
            &audit,
            &signer,
            &tenant,
            &grantee,
            TrustPurpose::Technical,
            "*",
            None,
            "phase-fg-wild-star",
        )
        .await
        .unwrap();
        // Exact-match grant by the SAME granter at a different scope:
        // both are live, the wildcard should still surface when we
        // query for a specific subject (FSD §3.3 — caller decides).
        // Note: this is a different (purpose, scope) UNIQUE row so
        // both projections coexist on the same granter/grantee.
        grant_trust(
            &audit,
            &signer,
            &tenant,
            &grantee,
            TrustPurpose::Technical,
            "manifest:stable",
            None,
            "phase-fg-wild-exact",
        )
        .await
        .unwrap();

        let rows = lookup_trust_grant(&audit, &grantee, TrustPurpose::Technical, "manifest:stable")
            .await
            .unwrap();
        let scopes: Vec<&str> = rows.iter().map(|r| r.scope.as_str()).collect();
        assert!(
            scopes.contains(&"*") && scopes.contains(&"manifest:stable"),
            "both wildcard and exact-match rows surface; got scopes={scopes:?}"
        );
        assert_eq!(rows.len(), 2);
    }

    /// Phase F: revoked grants hidden by default.
    #[tokio::test]
    async fn sqlite_lookup_trust_grant_hides_revoked_by_default() {
        let (_b, audit, signer) = fresh_audit(0x30).await;
        let granter = signer.public_key_b64();
        let grantee = grantee_key(0x31);
        let tenant = format!("phase-fg-revoked-{}", Uuid::new_v4().simple());
        seed_federation_key(&audit, &granter).await;
        seed_federation_key(&audit, &grantee).await;

        grant_trust(
            &audit,
            &signer,
            &tenant,
            &grantee,
            TrustPurpose::Deferral,
            "medical_deferral",
            None,
            "phase-fg-pre-revoke",
        )
        .await
        .unwrap();
        revoke_trust_grant(
            &audit,
            &signer,
            &tenant,
            &grantee,
            TrustPurpose::Deferral,
            "medical_deferral",
        )
        .await
        .unwrap();

        // Default lookup hides revoked.
        let rows = lookup_trust_grant(&audit, &grantee, TrustPurpose::Deferral, "medical_deferral")
            .await
            .unwrap();
        assert!(rows.is_empty(), "revoked grant hidden by default");

        // include_revoked surfaces it.
        let rows = audit
            .lookup_trust_grant(
                &grantee,
                TrustPurpose::Deferral,
                "medical_deferral",
                true,
                true,
            )
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert!(rows[0].revoked_at.is_some());
    }

    /// Phase F: list_trust_grants filters compose AND-style.
    #[tokio::test]
    async fn sqlite_list_trust_grants_filters() {
        let (_b, audit, signer) = fresh_audit(0x40).await;
        let granter = signer.public_key_b64();
        let grantee_a = grantee_key(0x41);
        let grantee_b = grantee_key(0x42);
        let tenant = format!("phase-fg-list-{}", Uuid::new_v4().simple());
        seed_federation_key(&audit, &granter).await;
        seed_federation_key(&audit, &grantee_a).await;
        seed_federation_key(&audit, &grantee_b).await;

        grant_trust(
            &audit,
            &signer,
            &tenant,
            &grantee_a,
            TrustPurpose::Service,
            "service:llm",
            None,
            "list-1",
        )
        .await
        .unwrap();
        grant_trust(
            &audit,
            &signer,
            &tenant,
            &grantee_a,
            TrustPurpose::Service,
            "service:embedding",
            None,
            "list-2",
        )
        .await
        .unwrap();
        grant_trust(
            &audit,
            &signer,
            &tenant,
            &grantee_b,
            TrustPurpose::Service,
            "service:llm",
            None,
            "list-3",
        )
        .await
        .unwrap();

        // Grantee filter.
        let only_a = list_trust_grants(
            &audit,
            TrustGrantFilter {
                grantee_key: Some(grantee_a.clone()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(only_a.len(), 2);
        assert!(only_a.iter().all(|r| r.grantee_key == grantee_a));

        // Granter filter.
        let by_granter = list_trust_grants(
            &audit,
            TrustGrantFilter {
                granter_key: Some(granter.clone()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(by_granter.len(), 3);

        // Purpose + scope_prefix filter.
        let svc_llm = list_trust_grants(
            &audit,
            TrustGrantFilter {
                purpose: Some(TrustPurpose::Service),
                scope_prefix: Some("service:llm".to_owned()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(
            svc_llm.len(),
            2,
            "two service:llm grants (grantee_a + grantee_b)"
        );
    }

    /// Phase F: get_trust_grant returns canonical row; matches receipt.
    #[tokio::test]
    async fn sqlite_get_trust_grant_matches_receipt() {
        let (_b, audit, signer) = fresh_audit(0x50).await;
        let granter = signer.public_key_b64();
        let grantee = grantee_key(0x51);
        let tenant = format!("phase-fg-get-{}", Uuid::new_v4().simple());
        seed_federation_key(&audit, &granter).await;
        seed_federation_key(&audit, &grantee).await;

        let receipt = grant_trust(
            &audit,
            &signer,
            &tenant,
            &grantee,
            TrustPurpose::Contribution,
            "vote:proposal:registry_vouch",
            None,
            "phase-fg-get",
        )
        .await
        .unwrap();

        let row = get_trust_grant(&audit, receipt.grant_id).await.unwrap();
        let row = row.expect("projection row");
        assert_eq!(row.grant_id, receipt.grant_id);
        assert_eq!(row.grantee_key, grantee);
        assert_eq!(row.granter_key, granter);
        assert_eq!(row.tenant_id, tenant);
        assert_eq!(row.chain_event_id, receipt.chain_event_id);
        assert_eq!(row.chain_event_hash, receipt.chain_event_hash);
    }

    /// Phase G: inclusion proof round-trip — emit, fetch proof, run
    /// `verify_inclusion`. The leaf_canonical_bytes must hash to the
    /// proof's `leaf_hash`, and the proof must validate against the
    /// STH's root.
    #[tokio::test]
    async fn sqlite_inclusion_proof_round_trip() {
        let (_b, audit, signer) = fresh_audit(0x60).await;
        let granter = signer.public_key_b64();
        let grantee = grantee_key(0x61);
        let tenant = format!("phase-fg-incl-{}", Uuid::new_v4().simple());
        seed_federation_key(&audit, &granter).await;
        seed_federation_key(&audit, &grantee).await;

        // Emit three grants so the leaf at index 0 actually has
        // siblings to walk.
        let r1 = grant_trust(
            &audit,
            &signer,
            &tenant,
            &grantee,
            TrustPurpose::Technical,
            "manifest:a",
            None,
            "incl-1",
        )
        .await
        .unwrap();
        let _r2 = grant_trust(
            &audit,
            &signer,
            &tenant,
            &grantee,
            TrustPurpose::Technical,
            "manifest:b",
            None,
            "incl-2",
        )
        .await
        .unwrap();
        let _r3 = grant_trust(
            &audit,
            &signer,
            &tenant,
            &grantee,
            TrustPurpose::Technical,
            "manifest:c",
            None,
            "incl-3",
        )
        .await
        .unwrap();

        let bundle = trust_grant_inclusion_proof(&audit, r1.grant_id)
            .await
            .unwrap();
        // STH's root matches proof's root.
        assert_eq!(bundle.sth.root_hash, bundle.merkle_proof.root);
        // Tree size at proof time is the latest STH's tree_size = 3.
        assert_eq!(bundle.sth.tree_size, 3);
        // leaf_canonical_bytes recomputes the proof's leaf_hash.
        assert_eq!(
            hash_leaf(&bundle.leaf_canonical_bytes),
            bundle.merkle_proof.leaf_hash
        );
        // The RFC 6962 walk validates against the proof's root.
        assert!(
            verify_inclusion(&bundle.merkle_proof),
            "verify_inclusion must accept the persist-generated proof"
        );
    }

    /// Phase G: consistency proof round-trip — emit N entries, sample
    /// STH(n), emit more, sample STH(m), fetch consistency proof,
    /// `verify_consistency` must accept.
    #[tokio::test]
    async fn sqlite_consistency_proof_round_trip() {
        let (_b, audit, signer) = fresh_audit(0x70).await;
        let granter = signer.public_key_b64();
        let grantee = grantee_key(0x71);
        let tenant = format!("phase-fg-cons-{}", Uuid::new_v4().simple());
        seed_federation_key(&audit, &granter).await;
        seed_federation_key(&audit, &grantee).await;

        for i in 0..3i32 {
            grant_trust(
                &audit,
                &signer,
                &tenant,
                &grantee,
                TrustPurpose::Technical,
                &format!("manifest:c-{i}"),
                None,
                "phase-fg-cons-pre",
            )
            .await
            .unwrap();
        }
        let sth_at_3 = audit.current_sth(&tenant).await.unwrap().unwrap();
        assert_eq!(sth_at_3.tree_size, 3);

        for i in 0..2i32 {
            grant_trust(
                &audit,
                &signer,
                &tenant,
                &grantee,
                TrustPurpose::Technical,
                &format!("manifest:c-post-{i}"),
                None,
                "phase-fg-cons-post",
            )
            .await
            .unwrap();
        }
        let sth_at_5 = audit.current_sth(&tenant).await.unwrap().unwrap();
        assert_eq!(sth_at_5.tree_size, 5);

        let proof = trust_grant_consistency_proof(&audit, &tenant, 3, 5)
            .await
            .unwrap();
        assert_eq!(proof.old_tree_size, 3);
        assert_eq!(proof.new_tree_size, 5);
        let ok = verify_consistency(
            &sth_at_3.root_hash,
            proof.old_tree_size,
            &sth_at_5.root_hash,
            proof.new_tree_size,
            &proof,
        )
        .expect("verify_consistency call");
        assert!(
            ok,
            "verify_consistency must accept the persist-generated proof"
        );
    }

    /// Phase F+G: missing grant_id surfaces NotFound from the
    /// inclusion-proof API.
    #[tokio::test]
    async fn sqlite_inclusion_proof_unknown_grant_id() {
        let (_b, audit, _signer) = fresh_audit(0x80).await;
        let bogus = Uuid::new_v4();
        let err = trust_grant_inclusion_proof(&audit, bogus)
            .await
            .unwrap_err();
        assert!(matches!(err, ReadError::NotFound(_)));
    }
}

#[cfg(all(test, feature = "postgres", feature = "cirisaudit"))]
mod postgres_tests {
    use super::*;
    use crate::audit::merkle_store::hash_leaf;
    use crate::federation::emit::{grant_trust, revoke_trust_grant};
    use crate::federation::trust_grant::{TrustGrantFilter, TrustPurpose};
    use crate::signing::LocalSigner;
    use crate::store::postgres::PostgresBackend;
    use crate::store::Backend;
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    use ciris_keyring::MlDsa65SoftwareSigner;
    use ciris_verify_core::transparency::{verify_consistency, verify_inclusion};
    use ed25519_dalek::SigningKey;
    use std::sync::Arc;
    use uuid::Uuid;

    fn pg_dsn() -> Option<String> {
        crate::test_pg::dsn()
    }

    fn build_signer(seed_byte: u8) -> Arc<LocalSigner> {
        let signing_key = SigningKey::from_bytes(&[seed_byte; 32]);
        let pqc =
            MlDsa65SoftwareSigner::from_seed_bytes(&[seed_byte ^ 0x55; 32], "phase-fg-pg-test-pqc")
                .expect("pqc seed");
        let pqc_arc: Arc<dyn ciris_keyring::PqcSigner> = Arc::new(pqc);
        Arc::new(LocalSigner::from_parts(
            signing_key,
            "phase-fg-pg-test-steward".to_owned(),
            Some(pqc_arc),
            Some("phase-fg-pg-test-pqc".to_owned()),
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
                    scrub_key_id, scrub_timestamp, persist_row_hash\
                 ) VALUES ($1, 'AAAA', 'hybrid', 'agent', $1, NOW(), \
                          '{}'::jsonb, decode('00', 'hex'), '', $1, NOW(), '0') \
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

    fn grantee_key(seed_byte: u8) -> String {
        B64.encode(
            SigningKey::from_bytes(&[seed_byte; 32])
                .verifying_key()
                .to_bytes(),
        )
    }

    /// PG Phase F: exact + wildcard match round-trip.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn pg_lookup_trust_grant_exact_and_wildcard() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        let signer = build_signer(0xC0);
        backend.set_merkle_signer(Some(signer.clone()));
        let granter = signer.public_key_b64();
        let grantee = grantee_key(0xC1);
        let tenant = format!("pg-phase-fg-look-{}", Uuid::new_v4().simple());
        pg_cleanup(&backend, &tenant).await;
        pg_seed_federation_key(&backend, &granter).await;
        pg_seed_federation_key(&backend, &grantee).await;

        grant_trust(
            &backend,
            &signer,
            &tenant,
            &grantee,
            TrustPurpose::Technical,
            "*",
            None,
            "pg-fg-wild",
        )
        .await
        .unwrap();
        grant_trust(
            &backend,
            &signer,
            &tenant,
            &grantee,
            TrustPurpose::Technical,
            "manifest:stable",
            None,
            "pg-fg-exact",
        )
        .await
        .unwrap();

        let rows = lookup_trust_grant(
            &backend,
            &grantee,
            TrustPurpose::Technical,
            "manifest:stable",
        )
        .await
        .unwrap();
        let scopes: Vec<&str> = rows.iter().map(|r| r.scope.as_str()).collect();
        assert!(scopes.contains(&"*"));
        assert!(scopes.contains(&"manifest:stable"));
        assert_eq!(rows.len(), 2);

        pg_cleanup(&backend, &tenant).await;
    }

    /// PG Phase F: list filters intersect; revocation hides by default.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn pg_list_trust_grants_filters_and_revocation() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        let signer = build_signer(0xC2);
        backend.set_merkle_signer(Some(signer.clone()));
        let granter = signer.public_key_b64();
        let grantee = grantee_key(0xC3);
        let tenant = format!("pg-phase-fg-list-{}", Uuid::new_v4().simple());
        pg_cleanup(&backend, &tenant).await;
        pg_seed_federation_key(&backend, &granter).await;
        pg_seed_federation_key(&backend, &grantee).await;

        grant_trust(
            &backend,
            &signer,
            &tenant,
            &grantee,
            TrustPurpose::Service,
            "service:llm",
            None,
            "pg-fg-svc-1",
        )
        .await
        .unwrap();
        grant_trust(
            &backend,
            &signer,
            &tenant,
            &grantee,
            TrustPurpose::Service,
            "service:embedding",
            None,
            "pg-fg-svc-2",
        )
        .await
        .unwrap();
        revoke_trust_grant(
            &backend,
            &signer,
            &tenant,
            &grantee,
            TrustPurpose::Service,
            "service:embedding",
        )
        .await
        .unwrap();

        let live = list_trust_grants(
            &backend,
            TrustGrantFilter {
                purpose: Some(TrustPurpose::Service),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        // service:embedding was revoked → only service:llm remains.
        // BUT also: this list is scoped to all tenants; other test
        // tenants may exist. Filter by tenant-substring on the scope
        // to be safe.
        let in_tenant: Vec<_> = live.iter().filter(|r| r.tenant_id == tenant).collect();
        assert_eq!(
            in_tenant.len(),
            1,
            "only live service:llm row in this tenant"
        );
        assert_eq!(in_tenant[0].scope, "service:llm");

        let all = backend
            .list_trust_grants(TrustGrantFilter {
                purpose: Some(TrustPurpose::Service),
                include_revoked: true,
                include_expired: true,
                ..Default::default()
            })
            .await
            .unwrap();
        let in_tenant: Vec<_> = all.iter().filter(|r| r.tenant_id == tenant).collect();
        assert_eq!(in_tenant.len(), 2, "include_revoked surfaces revocation");

        pg_cleanup(&backend, &tenant).await;
    }

    /// PG Phase G: inclusion proof round-trip.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn pg_inclusion_proof_round_trip() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        let signer = build_signer(0xD0);
        backend.set_merkle_signer(Some(signer.clone()));
        let granter = signer.public_key_b64();
        let grantee = grantee_key(0xD1);
        let tenant = format!("pg-phase-fg-incl-{}", Uuid::new_v4().simple());
        pg_cleanup(&backend, &tenant).await;
        pg_seed_federation_key(&backend, &granter).await;
        pg_seed_federation_key(&backend, &grantee).await;

        let r1 = grant_trust(
            &backend,
            &signer,
            &tenant,
            &grantee,
            TrustPurpose::Technical,
            "pg-manifest:a",
            None,
            "pg-incl-1",
        )
        .await
        .unwrap();
        let _r2 = grant_trust(
            &backend,
            &signer,
            &tenant,
            &grantee,
            TrustPurpose::Technical,
            "pg-manifest:b",
            None,
            "pg-incl-2",
        )
        .await
        .unwrap();
        let _r3 = grant_trust(
            &backend,
            &signer,
            &tenant,
            &grantee,
            TrustPurpose::Technical,
            "pg-manifest:c",
            None,
            "pg-incl-3",
        )
        .await
        .unwrap();

        let bundle = trust_grant_inclusion_proof(&backend, r1.grant_id)
            .await
            .unwrap();
        assert_eq!(bundle.sth.root_hash, bundle.merkle_proof.root);
        assert_eq!(
            hash_leaf(&bundle.leaf_canonical_bytes),
            bundle.merkle_proof.leaf_hash
        );
        assert!(verify_inclusion(&bundle.merkle_proof));

        pg_cleanup(&backend, &tenant).await;
    }

    /// PG Phase G: consistency proof round-trip.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn pg_consistency_proof_round_trip() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        let signer = build_signer(0xE0);
        backend.set_merkle_signer(Some(signer.clone()));
        let granter = signer.public_key_b64();
        let grantee = grantee_key(0xE1);
        let tenant = format!("pg-phase-fg-cons-{}", Uuid::new_v4().simple());
        pg_cleanup(&backend, &tenant).await;
        pg_seed_federation_key(&backend, &granter).await;
        pg_seed_federation_key(&backend, &grantee).await;

        for i in 0..3i32 {
            grant_trust(
                &backend,
                &signer,
                &tenant,
                &grantee,
                TrustPurpose::Technical,
                &format!("pg-c-{i}"),
                None,
                "pg-cons-pre",
            )
            .await
            .unwrap();
        }
        let sth_at_3 = backend.current_sth(&tenant).await.unwrap().unwrap();
        for i in 0..2i32 {
            grant_trust(
                &backend,
                &signer,
                &tenant,
                &grantee,
                TrustPurpose::Technical,
                &format!("pg-c-post-{i}"),
                None,
                "pg-cons-post",
            )
            .await
            .unwrap();
        }
        let sth_at_5 = backend.current_sth(&tenant).await.unwrap().unwrap();

        let proof = trust_grant_consistency_proof(&backend, &tenant, 3, 5)
            .await
            .unwrap();
        let ok = verify_consistency(
            &sth_at_3.root_hash,
            proof.old_tree_size,
            &sth_at_5.root_hash,
            proof.new_tree_size,
            &proof,
        )
        .expect("pg verify_consistency call");
        assert!(ok);

        pg_cleanup(&backend, &tenant).await;
    }
}
