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

#[cfg(test)]
pub(crate) mod bodies {
    use crate::federation::register::{self, KeyRefusalReason, ReplicatedKeyOutcome};
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::identity_type::{AGENT, NODE, USER};
    use crate::federation::types::{attestation_tier, attestation_type};
    use crate::federation::{
        Attestation, Error, FederationDirectory, SignedAttestation, SignedKeyRecord,
    };

    /// The kind every plane's ordering gap reports.
    const GAP: &str = "federation_attester_key_unknown";

    /// **I613 — the key plane.** A record scrubbed by a key this node does not
    /// hold: the direct registration gate (`verify_key_registration`, the one
    /// `register_federation_key` runs) reports the gap, and the replicated
    /// Insert arm returns the typed `attester_key_unknown` refusal (before
    /// v54.1.0: a bare `Err`, CIRISEdge#858). A known scrubber whose signature
    /// covers other bytes is the terminal `unverifiable_signature`. After the
    /// scrubber's Key row lands, the same record is inserted.
    pub async fn i613_key_plane(d: &dyn FederationDirectory, s: &str) {
        let anchor = format!("i613-anchor-{s}");
        let k = format!("i613-k-{s}");
        let record = ts::replicated_key_record(&k, AGENT, &anchor, &anchor, "n1");

        let direct = register::verify_key_registration(d, &record)
            .await
            .expect_err("I613: an unknown scrubber cannot be verified");
        assert_eq!(direct.kind(), GAP, "I613: direct door: {direct}");
        assert!(
            matches!(&direct, Error::AttesterKeyUnknown { attesting_key_id, plane: "key_registration" } if *attesting_key_id == anchor),
            "I613: the gap names the scrubber: {direct:?}"
        );

        let out = d
            .apply_replicated_key_record(SignedKeyRecord {
                record: record.clone(),
            })
            .await
            .expect("I613: a refusal is an outcome, never a bare Err");
        assert_eq!(
            out,
            ReplicatedKeyOutcome::Refused {
                reason: KeyRefusalReason::AttesterKeyUnknown
            },
            "I613: replicated Insert, unknown scrubber"
        );
        assert_eq!(
            KeyRefusalReason::AttesterKeyUnknown.as_str(),
            "attester_key_unknown"
        );
        assert!(
            d.lookup_public_key(&k).await.unwrap().is_none(),
            "I613: nothing stored on the refusal"
        );

        // The scrubber's Key row lands.
        ts::register_identity_key(d, &anchor, NODE).await;

        // A known scrubber, a signature over OTHER bytes: terminal.
        let other = ts::replicated_key_record(&k, AGENT, &anchor, &anchor, "n2");
        let mut forged = record.clone();
        forged.scrub_signature_classical = other.scrub_signature_classical;
        forged.scrub_signature_pqc = other.scrub_signature_pqc;
        let terminal = register::verify_key_registration(d, &forged)
            .await
            .expect_err("I613: a signature over other bytes does not verify");
        assert_eq!(
            terminal.kind(),
            "federation_signature_invalid",
            "I613: direct door, known scrubber: {terminal}"
        );
        let out = d
            .apply_replicated_key_record(SignedKeyRecord { record: forged })
            .await
            .expect("I613: a refusal is an outcome");
        assert_eq!(
            out,
            ReplicatedKeyOutcome::Refused {
                reason: KeyRefusalReason::UnverifiableSignature
            },
            "I613: replicated Insert, known scrubber, bad signature"
        );
        assert!(d.lookup_public_key(&k).await.unwrap().is_none());

        // The SAME record, re-offered, now admits.
        let out = d
            .apply_replicated_key_record(SignedKeyRecord { record })
            .await
            .unwrap();
        assert_eq!(
            out,
            ReplicatedKeyOutcome::Inserted,
            "I613: re-offered after the key plane"
        );
    }

    /// **I614 — the identity_occurrence plane** (the 2026-10-08 fresh-install
    /// defect). `put_identity_occurrence` is the one door for the wire and the
    /// HTTP route. A signer this node does not hold reports the gap; a known
    /// signer with a signature over another envelope is the terminal
    /// `federation_signature_invalid`; after the signer's Key row lands the
    /// same row admits.
    pub async fn i614_occurrence_plane(d: &dyn FederationDirectory, s: &str) {
        let identity = format!("i614-id-{s}");
        let occurrence = format!("i614-occ-{s}");
        let at = chrono::Utc::now();
        // The occurrence's own Key row is held; only the SIGNER's is missing.
        ts::register_identity_key(d, &occurrence, AGENT).await;
        let signed =
            ts::signed_content_only_occurrence(&identity, &identity, &occurrence, at).await;

        let gap = d
            .put_identity_occurrence(signed.clone())
            .await
            .expect_err("I614: an unknown signer cannot be verified");
        assert_eq!(gap.kind(), GAP, "I614: {gap}");
        assert!(
            matches!(&gap, Error::AttesterKeyUnknown { attesting_key_id, plane: "identity_occurrence" } if *attesting_key_id == identity),
            "I614: {gap:?}"
        );

        ts::register_identity_key(d, &identity, USER).await;

        let other_occ = format!("i614-other-{s}");
        ts::register_identity_key(d, &other_occ, AGENT).await;
        let other = ts::signed_content_only_occurrence(&identity, &identity, &other_occ, at).await;
        let mut forged = signed.clone();
        forged.signature = other.signature;
        let terminal = d
            .put_identity_occurrence(forged)
            .await
            .expect_err("I614: a signature over another envelope does not verify");
        assert_eq!(
            terminal.kind(),
            "federation_signature_invalid",
            "I614: {terminal}"
        );

        d.put_identity_occurrence(signed)
            .await
            .expect("I614: the same row admits after the key plane");
    }

    /// A self-scored federation-tier row by `attester`, sealed (the erasable
    /// witnesses' shape).
    fn scored_row(attester: &str, id: &str) -> Attestation {
        let envelope = serde_json::json!({
            "id": id,
            "dimension": "identity_binding:v1",
            "score": 1.0,
            "confidence": 0.9,
        });
        let now = chrono::Utc::now();
        let mut row = Attestation {
            attestation_id: uuid::Uuid::new_v4().to_string(),
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
        ts::seal_row_in_place(attester, &mut row);
        row
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
            matches!(&gap, Error::AttesterKeyUnknown { attesting_key_id, plane: "attestation" } if *attesting_key_id == attester),
            "I615: {gap:?}"
        );

        ts::register_hybrid_key(d, &attester).await;

        let other = scored_row(&attester, &format!("i615-b-{s}"));
        let mut forged = row.clone();
        forged.scrub_signature_classical = other.scrub_signature_classical;
        forged.scrub_signature_pqc = other.scrub_signature_pqc;
        let terminal = d
            .put_attestation(SignedAttestation {
                attestation: forged,
            })
            .await
            .expect_err("I615: a signature over other bytes does not verify");
        assert_eq!(
            terminal.kind(),
            "federation_federation_tier_unverified",
            "I615: {terminal}"
        );

        d.put_attestation(SignedAttestation { attestation: row })
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
                async fn i613_key_plane() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i613_key_plane(&b, &super::suffix()).await
                }
                #[tokio::test]
                async fn i614_occurrence_plane() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i614_occurrence_plane(&b, &super::suffix()).await
                }
                #[tokio::test]
                async fn i615_signed_envelope_plane() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i615_signed_envelope_plane(&b, &super::suffix()).await
                }
            }
        };
    }
    runners!(memory, async {
        Some(crate::store::memory::MemoryBackend::new())
    });
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
