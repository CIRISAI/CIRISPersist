//! Takedown-admission orchestration (CIRISPersist#134, v3.6.0; rebuilt on the
//! CC 2.3 tombstone in v55.0.0, CIRISPersist#1007).
//!
//! A `takedown_notice` Contribution that cleared `put_contribution` (its
//! signature, and the CC 4.5.5 moderation gate) is executed by
//! [`process_takedown_admission`]: the signed envelope goes to
//! [`Engine::takedown_tombstone`](crate::Engine::takedown_tombstone), which
//! re-verifies it, re-asks CC 4.5.5 of this node's state, and writes ONE
//! bytes-plane tombstone on the steward purge's tombstone row (CC 4.5.3
//! step 2: one row shape for takedown and purge).
//!
//! Until v55.0.0 the handler withdrew every holder's `holds_bytes` claim and,
//! for an immediate-removal basis, ran `evict_actor` on each holder. Neither
//! survives: a `withdraws` of another device's holding claim is not the
//! holder's act (CC 3.1.3.3 rule 4), and `evict_actor(holder)` deleted every
//! blob the holder held, not the one taken down. The per-basis behaviour is
//! CC 4.5.3's and is read from the basis by
//! [`basis_disposition`](crate::federation::takedown_tombstone::basis_disposition);
//! `MultimediaConfig` (its immediate set, age-gate set and counter-notice
//! window) is removed: an operator narrowing CC 4.5.3's immediate set made
//! the node non-conformant.
//!
//! # AdmissionGate non-bypass (architect ambiguity #3)
//!
//! The handler does NOT bypass the existing
//! [`AdmissionGate`](crate::federation::AdmissionGate) at
//! `put_contribution`. The takedown row goes through the same
//! trust-threshold check every other Contribution does.

use super::types::ContributionEnvelope;
use crate::federation::takedown_tombstone::{token, TakedownNotice};

/// The signed `takedown_notice` Contribution as the tombstone door takes it:
/// its signature verified exactly as `put_contribution` verifies it, its
/// payload shape-checked, and the envelope serialized as the typed struct
/// serializes it (so the bytes the door re-verifies are the bytes signed).
///
/// # Errors
///
/// `takedown_unauthorised` ([`crate::federation::Error::PurgeRefused`]) for a
/// Contribution that is not a takedown notice, whose payload is malformed, or
/// whose signature does not verify.
pub fn takedown_notice_from_contribution(
    env: &ContributionEnvelope,
) -> Result<TakedownNotice, crate::federation::Error> {
    let refuse = |reason: String| crate::federation::Error::PurgeRefused {
        token: token::UNAUTHORISED,
        body: serde_json::json!({
            "contribution_id": env.contribution_id,
            "reason": reason,
        }),
    };
    super::verify::verify_envelope_signed(env, &env.signature, &env.author_id)
        .map_err(|e| refuse(format!("the notice's signature does not verify: {e}")))?;
    let subject_kind = env.subject.subject.as_deref().unwrap_or("");
    match super::media_sharing::extract_takedown_notice_payload(subject_kind, &env.payload) {
        Ok(Some(_)) => {}
        Ok(None) => {
            return Err(refuse(format!(
                "subject_kind {subject_kind:?} is not `takedown_notice`"
            )))
        }
        Err(e) => return Err(refuse(format!("{e}"))),
    }
    let envelope = serde_json::to_value(env)
        .map_err(|e| crate::federation::Error::Backend(format!("notice encode: {e}")))?;
    Ok(TakedownNotice { envelope })
}

/// v55.0.0 (CIRISPersist#1007) — **execute a takedown** on `engine`: the
/// Contribution through [`takedown_notice_from_contribution`], then
/// [`Engine::takedown_tombstone`](crate::Engine::takedown_tombstone). Returns
/// what the tombstone door did (the notice id, whether the tombstone was
/// written, the settle, whether this node destroyed its bytes or retracted
/// its own claim).
///
/// # Errors
///
/// `takedown_unauthorised`; directory and bytes-plane errors.
#[cfg(any(feature = "postgres", feature = "sqlite"))]
pub async fn process_takedown_admission(
    engine: &crate::Engine,
    contribution: &ContributionEnvelope,
) -> Result<crate::federation::takedown_tombstone::TakedownReport, crate::federation::Error> {
    let notice = takedown_notice_from_contribution(contribution)?;
    engine.takedown_tombstone(&notice).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cirisnode::types::{Cell, ContributionType, HybridSignature};
    use crate::cirisnode::{LegalBasis, TakedownNoticePayload};
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    use chrono::Utc;
    use ed25519_dalek::Signer as _;

    fn signed(key: &ed25519_dalek::SigningKey, subject: &str) -> ContributionEnvelope {
        let author = B64.encode(key.verifying_key().to_bytes());
        let payload = TakedownNoticePayload {
            content_sha256: "ab".repeat(32),
            perceptual_hash: None,
            content_holder_key_ids: vec![],
            claimant_key_id: author.clone(),
            legal_basis: LegalBasis::NcmecCsam,
            jurisdiction: "US".into(),
            good_faith_statement: "good faith".into(),
            claim_text: "claim".into(),
            evidence_refs: vec![],
            counter_notice_channel: None,
            asserted_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::days(30),
        };
        let mut env = ContributionEnvelope {
            contribution_id: uuid::Uuid::new_v4().to_string(),
            contribution_type: ContributionType::Proposal,
            author_id: author,
            subject: Cell {
                domain: "media".into(),
                language: "en".into(),
                subject: Some(subject.into()),
            },
            payload: serde_json::to_value(&payload).unwrap(),
            witness_set: None,
            signature: HybridSignature {
                ed25519: String::new(),
                ml_dsa_65: None,
                signed_at: Utc::now(),
            },
            submitted_at: Utc::now(),
        };
        let canonical = crate::cirisnode::verify::canonical_bytes_for_envelope(&env).unwrap();
        env.signature.ed25519 = B64.encode(key.sign(&canonical).to_bytes());
        env
    }

    /// I785 — the typed Contribution, serialized, is exactly what the
    /// federation door verifies: `put_contribution`'s signature and the
    /// door's agree on one envelope, and an edit after signing is refused by
    /// both.
    #[test]
    fn i785_the_typed_contribution_verifies_at_the_federation_door() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[0x5a; 32]);
        let env = signed(&key, crate::cirisnode::TAKEDOWN_NOTICE_SUBJECT_KIND);
        let notice = takedown_notice_from_contribution(&env).expect("a signed notice");
        let terms = crate::federation::takedown_tombstone::takedown_terms(&notice)
            .expect("I785: the federation door verifies the typed envelope");
        assert_eq!(terms.signer, env.author_id);
        assert_eq!(terms.legal_basis, "ncmec_csam");

        let mut tampered = env.clone();
        tampered.payload["claim_text"] = serde_json::json!("edited");
        let err = takedown_notice_from_contribution(&tampered).unwrap_err();
        assert_eq!(err.kind(), token::UNAUTHORISED, "I785: {err}");
        let mut raw = notice.clone();
        raw.envelope["payload"]["claim_text"] = serde_json::json!("edited");
        let err = crate::federation::takedown_tombstone::takedown_terms(&raw).unwrap_err();
        assert_eq!(err.kind(), token::UNAUTHORISED, "I785: {err}");

        let other = signed(&key, "arc_question");
        let err = takedown_notice_from_contribution(&other).unwrap_err();
        assert_eq!(err.kind(), token::UNAUTHORISED, "I785: {err}");
    }

    /// I785b — the federation door's basis sets and the cirisnode
    /// `LegalBasis` vocabulary are two spellings of one CC 4.5.3 table: every
    /// basis classifies the same way through both.
    #[test]
    fn i785b_the_basis_table_is_one_table() {
        use crate::federation::takedown_tombstone::{basis_disposition, TakedownDisposition};
        let all = [
            LegalBasis::Dmca512,
            LegalBasis::DsaArticle16,
            LegalBasis::TvecTerrorist,
            LegalBasis::NcmecCsam,
            LegalBasis::GifctCip,
            LegalBasis::CommunityStandards,
            LegalBasis::PerceptualHashCsam,
            LegalBasis::OsaIllegalContent,
            LegalBasis::AvmsdAgeInappropriate,
            LegalBasis::CourtOrder,
        ];
        for b in all {
            let d = basis_disposition(b.as_str())
                .unwrap_or_else(|| panic!("I785b: {} has no disposition", b.as_str()));
            let expected = if b.requires_immediate_eviction() {
                TakedownDisposition::DestroyOnReceipt
            } else if b.composes_with_age_gate() {
                TakedownDisposition::AgeGate
            } else {
                TakedownDisposition::WithholdThenDelete {
                    window_days: i64::from(
                        b.counter_notice_window_days()
                            .expect("I785b: a counter-notice basis has a window"),
                    ),
                }
            };
            assert_eq!(d, expected, "I785b: {}", b.as_str());
        }
    }
}
