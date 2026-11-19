//! CIRISPersist#1042 — witnesses for the typed, RETRYABLE ordering-gap refusal
//! (`Error::AttesterKeyUnknown`, kind `federation_attester_key_unknown`; on the
//! key plane `KeyRefusalReason::AttesterKeyUnknown`, token
//! `attester_key_unknown`), kept apart from the TERMINAL bad-signature verdict.
//! One body per plane over `&dyn FederationDirectory`, run by memory, sqlite
//! and postgres so the three cannot diverge.
//!
//! Each body is the same three steps the issue names: an unknown signer is
//! the ordering gap; a KNOWN signer with a signature over other bytes is the
//! terminal verdict; once the signer's Key row lands the SAME row admits.
//!
//! v54.1.0 (#1042 follow-ups, CIRISEdge#858): I630 — the signer-acts-for arm
//! is the retryable `federation_signer_not_acting_for` on all four doors that
//! ask it; I631 — a backend failure of the shared envelope verifier's attester
//! lookup propagates as itself, never as a verdict.
//!
//! v62 (E3): I613 (the earlier key-record plane) and I631 (the earlier
//! envelope verifier) are deleted with the earlier form; the attestation
//! legs of I615/I632/I834 run on edition-2 rows.
//!
//! v62 (E3b, round 3): I614, I630, I632 and I834 are deleted. Each drives an
//! earlier-form JSON door (the hybrid-signed `SignedIdentityOccurrence`, the
//! signed transport destination, the touch claim; each
//! `refuse_earlier_form(..)` once shut), and I630's revocation leg stands an
//! agent key as an occurrence of a person, which v62 refuses
//! (`occurrence_binds_machine_to_person`). The edition-2 occurrence wait (an
//! author's voice offered alone is the retryable `federation_attester_key_unknown`)
//! is O1's. I615 remains: the statement door names its own plane
//! (`edition2::door::PLANE`).

#[cfg(test)]
pub(crate) mod bodies {
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{attestation_tier, attestation_type};
    use crate::federation::{Attestation, Error, FederationDirectory, SignedAttestation};

    /// The kind every plane's ordering gap reports.
    const GAP: &str = "federation_attester_key_unknown";

    /// A self-scored federation-tier row by `attester`, as the door maps the
    /// attester's edition-2 statement (the erasable witnesses' shape).
    fn scored_row(attester: &str, id: &str) -> Attestation {
        let envelope = serde_json::json!({
            "id": id,
            // Edition 2: a dimension Verify registers (`trust:{job}:{version}`).
            "dimension": "trust:demo:v1",
            "score": 1.0,
            "confidence": 0.9,
        });
        let now = chrono::Utc::now();
        let row = Attestation {
            attestation_id: String::new(),
            attesting_key_id: attester.to_owned(),
            attested_key_id: attester.to_owned(),
            attestation_type: attestation_type::SCORES.to_owned(),
            weight: Some(1.0),
            asserted_at: now,
            expires_at: None,
            attestation_envelope: envelope,
            original_content_hash: String::new(),
            scrub_signature_classical: String::new(),
            scrub_signature_pqc: None,
            scrub_key_id: attester.to_owned(),
            scrub_timestamp: now,
            pqc_completed_at: Some(now),
            persist_row_hash: String::new(),
            subject_key_ids: Vec::new(),
            withdraws_admission_rule: None,
            cohort_scope: attestation_tier::FEDERATION.to_owned(),
            tier: attestation_tier::FEDERATION.to_owned(),
            promoted_at: None,
            additional_scrubs: Vec::new(),
        };
        // The door's mapping of the attester's statement over the literal.
        e2::row_of(&row, attester)
    }

    /// **I615 — the attestation plane** (`put_attestation`, the door the
    /// replication apply and the direct route share). An attester this node
    /// does not hold reports the gap at the door's attester lookup (before
    /// v54.1.0: `federation_invalid_argument`; and where that lookup is
    /// passed, the shared envelope verifier — which also serves revocations
    /// and the group planes — reported the terminal
    /// `federation_federation_tier_unverified`); a known attester with a
    /// signature over other bytes keeps that terminal kind; after the
    /// attester's Key row lands the same row admits.
    pub async fn i615_signed_envelope_plane(d: &dyn FederationDirectory, s: &str) {
        let attester = format!("i615-att-{s}");
        let row = scored_row(&attester, &format!("i615-a-{s}"));

        let gap = d
            .put_attestation(SignedAttestation {
                attestation: row.clone(),
            })
            .await
            .expect_err("I615: an unknown attester cannot be verified");
        assert_eq!(gap.kind(), GAP, "I615: {gap}");
        assert!(
            matches!(&gap, Error::AttesterKeyUnknown { attesting_key_id, plane } if *attesting_key_id == e2::kid(&attester) && *plane == crate::federation::edition2::door::PLANE),
            "I615: {gap:?}"
        );

        ts::register_hybrid_key(d, &attester).await;

        // v62 (E3): the "signature over other bytes" leg is deleted with the
        // earlier-form scrub; a statement's own signature check is witnessed
        // in `edition2::door_invariants`.
        crate::federation::edition2::fixture_switch::put_signed(d, &row)
            .await
            .expect("I615: the same row admits after the key plane");
    }
}

#[cfg(test)]
mod run {
    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()
    }
    macro_rules! runners {
        ($modname:ident, $fresh:expr) => {
            mod $modname {
                use super::super::bodies;
                #[tokio::test]
                async fn i615_signed_envelope_plane() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i615_signed_envelope_plane(&b, &super::suffix()).await
                }
            }
        };
    }
    #[cfg(feature = "sqlite")]
    runners!(sqlite, async {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    });
    #[cfg(feature = "postgres")]
    runners!(postgres, async {
        use crate::store::Backend as _;
        let dsn = crate::test_pg::empty_dsn()?;
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    });
}
