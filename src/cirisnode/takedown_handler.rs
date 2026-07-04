//! Takedown-admission orchestration (CIRISPersist#134, v3.6.0).
//!
//! Once a `takedown_notice` Contribution has cleared
//! [`extract_takedown_notice_payload`](super::media_sharing::extract_takedown_notice_payload)
//! and landed via `put_contribution`, the orchestrator side runs:
//!
//!   1. [`list_holders`](crate::federation::BlobStorage::list_holders)
//!      to discover the currently-live holders of the content_sha256.
//!   2. For each holder: emit a `withdraws` attestation against the
//!      holder's `holds_bytes` row (via [`emit_withdraws_attestation_helper`]).
//!   3. If [`LegalBasis::requires_immediate_eviction`] is true: also
//!      call [`evict_actor`](crate::federation::BlobStorage::evict_actor)
//!      for each holder.
//!   4. If [`LegalBasis::admits_counter_notice`] is true: schedule the
//!      delayed eviction (the persist-side hook lives at the
//!      `cirisnode.scheduled_takedown_actions` table; this module
//!      reports the deadline; the EvictionSweeper consumes the table).
//!
//! # AdmissionGate non-bypass (architect ambiguity #3)
//!
//! The handler does NOT bypass the existing
//! [`AdmissionGate`](crate::federation::AdmissionGate) at
//! `put_contribution`. The takedown row goes through the same
//! trust-threshold check every other Contribution does. The architect's
//! brief identified a "substrate-protective override" question
//! (whether a takedown_signer should be able to bypass the gate);
//! persist defers to upstream on this.
//!
//! # TODO(CIRISNodeCore#24)
//!
//! When upstream locks the operator-config carrier for
//! takedown-signer bypass, the handler grows an explicit override
//! surface. Persist ships the no-bypass default.

use chrono::{DateTime, Utc};

use super::media_sharing::{MultimediaConfig, TakedownNoticePayload};
use super::Error;
use crate::federation::{BlobError, BlobStorage, FederationDirectory};

/// Report from [`process_takedown_admission`]. Counts withdraws +
/// evictions + (when scheduled) the deadline the sweeper applies.
///
/// CEG 0.3 §11.4 takedown-isn't-a-coup: the holder's
/// `federation_keys` row is NEVER touched by the handler. Only the
/// holder's `holds_bytes` attestation is withdrawn, and (for
/// immediate-removal bases) the holder's `federation_blobs` row is
/// evicted. Key revocation is a separate, distinct primitive.
#[derive(Debug, Clone, Default)]
pub struct TakedownReport {
    /// Holders identified by `list_holders` at the time of the
    /// admission call.
    pub holders_seen: usize,
    /// `withdraws` attestations the handler emitted.
    pub withdraws_emitted: usize,
    /// `withdraws` emissions that failed (signer / FK).
    pub withdraws_failed: usize,
    /// Holder evictions the handler ran (immediate-eviction bases
    /// only).
    pub holders_evicted: usize,
    /// Holder evictions that failed.
    pub holders_evict_failed: usize,
    /// The deadline the EvictionSweeper will use to apply a delayed
    /// eviction. `Some` iff the basis admits a counter notice; persist
    /// defaults documented at
    /// [`LegalBasis::counter_notice_window_days`].
    pub scheduled_eviction_at: Option<DateTime<Utc>>,
    /// CEG 0.3 §8.1.10 — set true when the basis composes with the
    /// Policy J age-assurance gate. Persist emits withdraws but does
    /// NOT evict; the receiver-side display gate filters at read time.
    pub age_gate_applied: bool,
}

/// Drive the takedown-admission orchestration for a takedown_notice
/// that has already cleared `put_contribution`.
///
/// `blob_storage` is the substrate. `directory` is the
/// `FederationDirectory` for the `holds_bytes` enumerate + the
/// `withdraws` write target. `signer` produces the canonical Ed25519
/// signature over the withdraws envelope; `signer_key_id` is the
/// `federation_keys.key_id` that fills both `attesting_key_id` and
/// `attested_key_id` on the withdraws row (the self-attestation
/// convention from
/// [`emit_withdraws_attestation_helper`](crate::federation::blobs::emit_withdraws_attestation_helper)).
///
/// # Counter-notice scheduling
///
/// When the basis admits a counter notice, the report carries the
/// deadline the sweeper uses; the caller (NodeCore-side; the upstream
/// CIRISNodeCore#24 surface) is responsible for inserting the row
/// into `cirisnode.scheduled_takedown_actions` with `status =
/// 'pending'`. This is documented as upstream-blocked at the call site
/// because the row's `notice_contribution_id` FK requires the
/// takedown_notice Contribution's UUID, which lives on the
/// NodeCore-side put_contribution surface (not here).
///
/// # Errors
///
/// Returns [`Error::Backend`] for `list_holders` failures. Per-holder
/// `withdraws` / `evict_actor` failures are tallied in the report (the
/// architect's #5 fail-honest contract — orphan withdraws is worse
/// than a missing withdraws).
#[cfg(any(feature = "postgres", feature = "sqlite"))]
pub async fn process_takedown_admission<B>(
    blob_storage: &B,
    directory: &dyn FederationDirectory,
    signer: &crate::signing::LocalSigner,
    signer_key_id: &str,
    notice: &TakedownNoticePayload,
    now: DateTime<Utc>,
) -> Result<TakedownReport, Error>
where
    B: BlobStorage + Sync,
{
    process_takedown_admission_with_config(
        blob_storage,
        directory,
        signer,
        signer_key_id,
        notice,
        now,
        None,
    )
    .await
}

/// v3.6.0 (CIRISPersist#134) — config-aware sibling of
/// [`process_takedown_admission`]. When `config` is `Some`, the handler
/// consults [`MultimediaConfig::is_immediate`] for the immediate-eviction
/// decision (replacing the hardcoded
/// [`LegalBasis::requires_immediate_eviction`](super::media_sharing::LegalBasis::requires_immediate_eviction))
/// and uses [`MultimediaConfig::counter_notice_window_days`] for the
/// scheduled-eviction deadline.
///
/// Passing `None` preserves the v3.6.0 hardcoded defaults (admits both
/// callers transparently).
///
/// # TODO(CIRISNodeCore#24)
///
/// Per-LegalBasis windows + the counter-notice carrier shape are
/// pending upstream spec. Until upstream lands, this method uses
/// either the operator-config window OR the hardcoded
/// [`LegalBasis::counter_notice_window_days`] fallback for
/// non-counter-noticed bases.
#[cfg(any(feature = "postgres", feature = "sqlite"))]
#[allow(clippy::too_many_arguments)]
pub async fn process_takedown_admission_with_config<B>(
    blob_storage: &B,
    directory: &dyn FederationDirectory,
    signer: &crate::signing::LocalSigner,
    signer_key_id: &str,
    notice: &TakedownNoticePayload,
    now: DateTime<Utc>,
    config: Option<&MultimediaConfig>,
) -> Result<TakedownReport, Error>
where
    B: BlobStorage + Sync,
{
    // Decode the hex SHA-256 once; reject malformed shape here even
    // though `extract_takedown_notice_payload` already validates it
    // (defense-in-depth — the handler is also a public entry point).
    let sha = decode_hex_sha256(&notice.content_sha256)?;

    let holders = blob_storage
        .list_holders(&sha)
        .await
        .map_err(|e| Error::Backend(format!("list_holders for takedown: {e}")))?;

    let mut report = TakedownReport {
        holders_seen: holders.len(),
        ..TakedownReport::default()
    };

    let is_age_gated = match config {
        Some(cfg) => cfg.is_age_gated(notice.legal_basis),
        None => notice.legal_basis.composes_with_age_gate(),
    };
    // CEG 0.3 §8.1.10: age-gate composition emits withdraws but does
    // NOT evict. Eviction only runs when the basis is in the
    // immediate-removal set AND not in the age-gate set.
    let requires_eviction = !is_age_gated
        && match config {
            Some(cfg) => cfg.is_immediate(notice.legal_basis),
            None => notice.legal_basis.requires_immediate_eviction(),
        };
    let admits_counter = notice.legal_basis.admits_counter_notice();
    report.age_gate_applied = is_age_gated;

    for holder in &holders {
        // For each live holder, find their `holds_bytes` attestation
        // for this SHA so we can emit a `withdraws` against it. We
        // use `list_attestations_by(holder)` and filter to the
        // matching attestation_type — same filter discipline as the
        // evict_actor path uses (`emit_withdraws_attestation_helper`
        // requires the prior Attestation row).
        let by = directory.list_attestations_by(holder).await.map_err(|e| {
            Error::Backend(format!(
                "list_attestations_by for holder {holder} in takedown: {e}"
            ))
        })?;
        let target_type = crate::federation::holds_bytes_attestation_type(&sha);
        let prior_opt = by.into_iter().find(|a| a.attestation_type == target_type);
        let prior = match prior_opt {
            Some(p) => p,
            None => {
                // Holder appeared in `list_holders` but no matching
                // attestation found — a race against eviction; treat
                // as a no-op for this holder (no withdraws to emit).
                continue;
            }
        };

        let withdraws_outcome = crate::federation::blobs::emit_withdraws_attestation_helper(
            &prior,
            signer_key_id,
            signer,
            directory,
            now,
        )
        .await;
        match withdraws_outcome {
            Ok(()) => report.withdraws_emitted += 1,
            Err(e) => {
                report.withdraws_failed += 1;
                tracing::warn!(
                    error = %e,
                    holder = %holder,
                    basis = ?notice.legal_basis,
                    "ciris-persist v3.6.0 takedown: withdraws emission failed"
                );
            }
        }

        if requires_eviction {
            // CEG 0.3 §11.4 takedown-isn't-a-coup: evict_actor deletes
            // the holder's `federation_blobs` rows + emits withdraws
            // against their holds_bytes attestations. It DOES NOT
            // touch `federation_keys`. The holder's identity remains
            // in the directory; only their possession of the
            // offending content is retired.
            match blob_storage.evict_actor(holder, signer, now).await {
                Ok(_) => report.holders_evicted += 1,
                Err(e) => {
                    report.holders_evict_failed += 1;
                    tracing::warn!(
                        error = %e,
                        holder = %holder,
                        basis = ?notice.legal_basis,
                        "ciris-persist v3.6.0 takedown: evict_actor failed"
                    );
                }
            }
        }
    }

    if admits_counter {
        // Counter-notice window selection:
        //   1. If operator config installed, use its global window.
        //   2. Otherwise fall back to the per-basis hardcoded default
        //      from LegalBasis::counter_notice_window_days.
        //
        // TODO(CIRISNodeCore#24): per-LegalBasis windows + counter-notice
        // carrier shape pending upstream spec.
        let days = match config {
            Some(cfg) => Some(cfg.counter_notice_window_days),
            None => notice.legal_basis.counter_notice_window_days(),
        };
        if let Some(days) = days {
            let deadline = now + chrono::Duration::days(i64::from(days));
            report.scheduled_eviction_at = Some(deadline);
        }
    }

    Ok(report)
}

fn decode_hex_sha256(hex_str: &str) -> Result<[u8; 32], Error> {
    let mut out = [0u8; 32];
    hex::decode_to_slice(hex_str, &mut out).map_err(|e| {
        Error::InvalidArgument(format!("content_sha256 hex decode: {e} (got {hex_str:?})"))
    })?;
    Ok(out)
}

// Translation helper kept private; BlobError → Error::Backend lossy on
// purpose (the handler's caller only sees report counters or
// kind()-token-aware Error).
#[allow(dead_code)]
fn blob_err(e: BlobError, what: &str) -> Error {
    Error::Backend(format!("{what}: {e}"))
}

#[cfg(all(test, feature = "sqlite"))]
mod tests {
    use super::*;
    use crate::cirisnode::media_sharing::{LegalBasis, TakedownNoticePayload};
    use crate::federation::types::{KeyRecord, SignedKeyRecord};
    use crate::federation::{BlobBody, BlobStorage, FederationDirectory};
    use crate::signing::{LocalSigner, LocalSignerHardwareAdapter};
    use crate::store::backend::Backend;
    use crate::store::sqlite::SqliteBackend;
    use chrono::Utc;
    use sha2::Digest;

    fn fixture_notice(basis: LegalBasis, sha: &[u8; 32]) -> TakedownNoticePayload {
        TakedownNoticePayload {
            content_sha256: hex::encode(sha),
            perceptual_hash: None,
            content_holder_key_ids: vec![],
            claimant_key_id: "claimant-1".into(),
            legal_basis: basis,
            jurisdiction: "US".into(),
            good_faith_statement: "I have a good-faith belief.".into(),
            claim_text: "Copyright claim.".into(),
            evidence_refs: vec![],
            counter_notice_channel: None,
            asserted_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::days(30),
        }
    }

    fn fed_key(key_id: &str) -> KeyRecord {
        // v9.0.0 (CC 5.3.2.4.3.1) — register REAL deterministic hybrid
        // pubkeys (matching `test_signer`'s LocalSigner, keyed on the same
        // key_id) so the federation-tier withdraws the takedown handler
        // emits verifies at the ingest gate.
        let (ed_pk, mldsa_pk) =
            crate::federation::tier_ingest::test_support::hybrid_pubkeys(key_id);
        KeyRecord {
            key_id: key_id.into(),
            pubkey_ed25519_base64: ed_pk,
            pubkey_ml_dsa_65_base64: mldsa_pk,
            algorithm: crate::federation::types::algorithm::HYBRID.into(),
            identity_type: crate::federation::types::identity_type::PRIMITIVE.into(),
            identity_ref: key_id.into(),
            valid_from: "2026-05-01T00:00:00Z".parse().unwrap(),
            valid_until: None,
            registration_envelope: serde_json::json!({"id": key_id}),
            original_content_hash: "deadbeef".into(),
            scrub_signature_classical: "c2lnbmF0dXJl".into(),
            scrub_signature_pqc: None,
            scrub_key_id: key_id.into(),
            scrub_timestamp: "2026-05-01T00:00:00Z".parse().unwrap(),
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            roles: Vec::new(),
            attestation_evidence: None,
            consent_role: None,
        }
    }

    /// v9.3.0 (#247) — a `federation_keys` row keyed by `alias`'s DERIVED
    /// federation key_id but carrying `alias`'s real pubkeys, so the
    /// holds_bytes scrub_key_id + the takedown `withdraws` (both written
    /// under the signer's derived id) FK-resolve and hybrid-verify on a
    /// real node (alias ≠ derived id).
    fn fed_key_derived(alias: &str) -> KeyRecord {
        let (ed_pk_b64, _) = crate::federation::tier_ingest::test_support::hybrid_pubkeys(alias);
        let ed_pk = {
            use base64::engine::general_purpose::STANDARD as B64;
            use base64::Engine as _;
            B64.decode(ed_pk_b64).expect("ed pubkey b64")
        };
        let derived = ciris_verify_core::fedcode::derive_key_id(alias, &ed_pk);
        let mut record = fed_key(alias);
        record.key_id = derived.clone();
        record.identity_ref = derived.clone();
        record.scrub_key_id = derived.clone();
        record.registration_envelope = serde_json::json!({ "id": derived });
        record
    }

    /// v9.0.0 (CC 5.3.2.4.3.1) — a PQC-configured LocalSigner keyed on
    /// `alias` (deterministic; matches the pubkeys `fed_key(alias)`
    /// registers). The takedown handler hybrid-signs the federation-tier
    /// withdraws with this; the holder blob-seeding path wraps it in a
    /// `LocalSignerHardwareAdapter` (classical-only is fine there — the
    /// holds_bytes row is stored via put_blob's direct INSERT, not the
    /// gated put_attestation). `seed` is ignored (keying is by alias now,
    /// so signer + registered key cohere).
    fn test_signer(_seed: u8, alias: &str) -> std::sync::Arc<LocalSigner> {
        crate::federation::tier_ingest::test_support::local_signer(alias)
    }

    /// Wrap a test LocalSigner as a `&dyn HardwareSigner` for the
    /// classical-only `put_blob_signing` (holds_bytes) seeding path.
    fn blob_signer(local: &std::sync::Arc<LocalSigner>) -> LocalSignerHardwareAdapter {
        LocalSignerHardwareAdapter::new(local.clone())
    }

    async fn seed_backend(actors: &[&str]) -> SqliteBackend {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        for actor in actors {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fed_key(actor),
                })
                .await
                .unwrap();
            // v9.3.0 (#247) — also register the actor's DERIVED id row
            // (the holds_bytes scrub + the takedown withdraws are written
            // under it).
            backend
                .put_public_key(SignedKeyRecord {
                    record: fed_key_derived(actor),
                })
                .await
                .unwrap();
        }
        backend
    }

    async fn seed_blob(
        backend: &SqliteBackend,
        actor: &str,
        signer: &std::sync::Arc<LocalSigner>,
        payload: &[u8],
    ) -> [u8; 32] {
        let mut sha = [0u8; 32];
        sha.copy_from_slice(&sha2::Sha256::digest(payload));
        backend
            .put_blob_signing(
                &sha,
                BlobBody::Inline(payload.to_vec()),
                None,
                actor,
                &blob_signer(signer),
                Utc::now(),
                uuid::Uuid::new_v4(),
            )
            .await
            .unwrap();
        sha
    }

    // v3.6.4 regression (CIRISPersist#130 reopen): a takedown for
    // content with a stale holder attestation (older than the CEG
    // §10.1.2 24h TTL) MUST still see the local holder and emit
    // withdraws — the bytes are locally held; TTL is a
    // federation-discovery backstop, not an eviction grace period.
    // Without the local-truth bypass in list_holders, NCMEC/CSAM
    // content held by a node whose attestation went stale evades
    // takedown — a child-safety hole.
    #[tokio::test]
    async fn process_takedown_admission_evicts_stale_local_holder() {
        let backend = seed_backend(&["holder-stale", "admin-key"]).await;
        let h = test_signer(0x71, "holder-stale");
        let admin = test_signer(0x72, "admin-key");
        let payload = b"stale-but-locally-held";
        let mut sha = [0u8; 32];
        sha.copy_from_slice(&sha2::Sha256::digest(payload));
        let stale_ts = Utc::now() - chrono::Duration::hours(48);
        backend
            .put_blob_signing(
                &sha,
                BlobBody::Inline(payload.to_vec()),
                None,
                "holder-stale",
                &blob_signer(&h),
                stale_ts,
                uuid::Uuid::new_v4(),
            )
            .await
            .unwrap();
        let notice = fixture_notice(LegalBasis::NcmecCsam, &sha);
        let report = process_takedown_admission(
            &backend,
            &backend,
            &admin,
            "admin-key",
            &notice,
            Utc::now(),
        )
        .await
        .expect("process_takedown_admission");
        assert_eq!(
            report.holders_seen, 1,
            "stale-attested local holder must be visible to takedown"
        );
        assert_eq!(report.withdraws_emitted, 1);
        assert_eq!(report.holders_evicted, 1);
    }

    #[tokio::test]
    async fn process_takedown_admission_no_holders_is_noop() {
        let backend = seed_backend(&["admin-key"]).await;
        let admin = test_signer(0x11, "admin-key");
        let mut sha = [0u8; 32];
        sha.copy_from_slice(&sha2::Sha256::digest(b"never-stored"));
        let notice = fixture_notice(LegalBasis::Dmca512, &sha);
        let report = process_takedown_admission(
            &backend,
            &backend,
            &admin,
            "admin-key",
            &notice,
            Utc::now(),
        )
        .await
        .expect("process_takedown_admission");
        assert_eq!(report.holders_seen, 0);
        assert_eq!(report.withdraws_emitted, 0);
        assert_eq!(report.holders_evicted, 0);
        assert!(report.scheduled_eviction_at.is_some());
    }

    #[tokio::test]
    async fn process_takedown_admission_emits_withdraws_per_holder() {
        let backend = seed_backend(&["holder-1", "holder-2", "admin-key"]).await;
        let h1 = test_signer(0x21, "holder-1");
        let h2 = test_signer(0x22, "holder-2");
        let admin = test_signer(0x33, "admin-key");
        let sha_a = seed_blob(&backend, "holder-1", &h1, b"a-shared-payload").await;
        let sha_b = seed_blob(&backend, "holder-2", &h2, b"a-shared-payload").await;
        assert_eq!(sha_a, sha_b, "same payload → same SHA");

        let notice = fixture_notice(LegalBasis::DsaArticle16, &sha_a);
        let report = process_takedown_admission(
            &backend,
            &backend,
            &admin,
            "admin-key",
            &notice,
            Utc::now(),
        )
        .await
        .expect("process_takedown_admission");
        assert_eq!(report.holders_seen, 2);
        assert_eq!(report.withdraws_emitted, 2);
        assert_eq!(report.holders_evict_failed, 0);
        assert_eq!(report.holders_evicted, 0);
        assert!(report.scheduled_eviction_at.is_some());
    }

    #[tokio::test]
    async fn process_takedown_admission_evicts_for_immediate_basis_only() {
        let backend = seed_backend(&["holder-imm", "admin-key"]).await;
        let h = test_signer(0x41, "holder-imm");
        let admin = test_signer(0x42, "admin-key");
        let sha = seed_blob(&backend, "holder-imm", &h, b"immediate-payload").await;

        let notice = fixture_notice(LegalBasis::NcmecCsam, &sha);
        let report = process_takedown_admission(
            &backend,
            &backend,
            &admin,
            "admin-key",
            &notice,
            Utc::now(),
        )
        .await
        .expect("process_takedown_admission");
        assert_eq!(report.holders_seen, 1);
        assert_eq!(report.holders_evicted, 1);
        assert!(report.scheduled_eviction_at.is_none());
    }

    #[tokio::test]
    async fn process_takedown_admission_with_config_overrides_immediate_set() {
        // MultimediaConfig that DROPS NcmecCsam from the
        // immediate-eviction set — handler must observe the override
        // and emit withdraws only (no eviction).
        let backend = seed_backend(&["holder-cfg", "admin-key"]).await;
        let h = test_signer(0x71, "holder-cfg");
        let admin = test_signer(0x72, "admin-key");
        let sha = seed_blob(&backend, "holder-cfg", &h, b"cfg-payload").await;

        let mut cfg = crate::cirisnode::MultimediaConfig::default();
        cfg.immediate_legal_bases.remove(&LegalBasis::NcmecCsam);

        let notice = fixture_notice(LegalBasis::NcmecCsam, &sha);
        let report = process_takedown_admission_with_config(
            &backend,
            &backend,
            &admin,
            "admin-key",
            &notice,
            Utc::now(),
            Some(&cfg),
        )
        .await
        .expect("process_takedown_admission_with_config");
        assert_eq!(report.holders_seen, 1);
        assert_eq!(report.withdraws_emitted, 1);
        // Eviction must NOT run — the config override drops NcmecCsam.
        assert_eq!(report.holders_evicted, 0);
        // Counter-notice doesn't apply (NcmecCsam doesn't admit counter).
        assert!(report.scheduled_eviction_at.is_none());
    }

    #[tokio::test]
    async fn process_takedown_admission_with_config_uses_window_override() {
        // Config that pins a 30-day window; handler must apply it.
        let backend = seed_backend(&["admin-key"]).await;
        let admin = test_signer(0x81, "admin-key");
        let mut sha = [0u8; 32];
        sha.copy_from_slice(&sha2::Sha256::digest(b"never-stored"));

        let cfg = crate::cirisnode::MultimediaConfig {
            counter_notice_window_days: 30,
            ..crate::cirisnode::MultimediaConfig::default()
        };

        let notice = fixture_notice(LegalBasis::Dmca512, &sha);
        let now = Utc::now();
        let report = process_takedown_admission_with_config(
            &backend,
            &backend,
            &admin,
            "admin-key",
            &notice,
            now,
            Some(&cfg),
        )
        .await
        .unwrap();
        let scheduled = report.scheduled_eviction_at.expect("deadline set");
        let delta = scheduled - now;
        // Sanity: ~30 days, not 10 (the persist default for DMCA §512).
        assert!(delta.num_days() >= 29 && delta.num_days() <= 31);
    }

    /// CEG 0.3 §11.4 takedown-isn't-a-coup: a single takedown_notice
    /// cannot retire a holder's `federation_keys` row. Persist
    /// withdraws the holds_bytes attestation + (for immediate-removal
    /// bases) evicts the holder's federation_blobs row — but the
    /// holder's key MUST remain in the directory.
    #[tokio::test]
    async fn process_takedown_admission_does_not_revoke_holder_key() {
        let backend = seed_backend(&["holder-coup", "admin-key"]).await;
        let h = test_signer(0x51, "holder-coup");
        let admin = test_signer(0x52, "admin-key");
        let sha = seed_blob(&backend, "holder-coup", &h, b"coup-payload").await;

        // Confirm the holder's federation_keys row exists pre-takedown.
        let pre = FederationDirectory::lookup_public_key(&backend, "holder-coup")
            .await
            .expect("pre-lookup")
            .expect("holder key row pre-takedown");
        assert_eq!(pre.key_id, "holder-coup");

        // Use the most severe basis (CourtOrder — CEG §11.4 immediate).
        let notice = fixture_notice(LegalBasis::CourtOrder, &sha);
        let report = process_takedown_admission(
            &backend,
            &backend,
            &admin,
            "admin-key",
            &notice,
            Utc::now(),
        )
        .await
        .expect("process_takedown_admission");
        assert_eq!(report.holders_evicted, 1);
        assert_eq!(report.withdraws_emitted, 1);

        // CEG §11.4: the holder's federation_keys row MUST still be
        // present. Takedown is not a vehicle for key revocation.
        let post = FederationDirectory::lookup_public_key(&backend, "holder-coup")
            .await
            .expect("post-lookup")
            .expect("holder key row MUST remain after takedown (CEG 0.3 §11.4)");
        assert_eq!(post.key_id, "holder-coup");
    }

    /// CEG 0.3 §8.1.10 Policy J composition: AvmsdAgeInappropriate
    /// emits withdraws but does NOT trigger eviction. The blob stays
    /// in `federation_blobs`; the receiver-side display gate filters
    /// at read time. The report carries `age_gate_applied = true`.
    #[tokio::test]
    async fn process_takedown_admission_age_gate_emits_withdraws_no_eviction() {
        let backend = seed_backend(&["holder-age", "admin-key"]).await;
        let h = test_signer(0x61, "holder-age");
        let admin = test_signer(0x62, "admin-key");
        let sha = seed_blob(&backend, "holder-age", &h, b"age-gated-payload").await;

        let notice = fixture_notice(LegalBasis::AvmsdAgeInappropriate, &sha);
        let report = process_takedown_admission(
            &backend,
            &backend,
            &admin,
            "admin-key",
            &notice,
            Utc::now(),
        )
        .await
        .expect("process_takedown_admission");
        assert_eq!(report.holders_seen, 1);
        assert_eq!(report.withdraws_emitted, 1);
        // Eviction MUST NOT run for age-gated bases.
        assert_eq!(report.holders_evicted, 0);
        // No counter-notice window for age-gated bases.
        assert!(report.scheduled_eviction_at.is_none());
        // CEG §8.1.10: the report carries the age-gate-applied flag.
        assert!(report.age_gate_applied);
    }
}
