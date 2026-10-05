//! v53.1.2 (CIRISPersist#984 row 16, CC 3.3.3 "a `withdraws` ends a proof")
//! — **withdrawing a location proof.**
//!
//! `federation_location_proofs.withdrawn_at` (V068) had readers (the
//! geographic-constraint fold) and no writer on any backend. The door is a
//! RE-SIGNED row — the signing envelope covers `withdrawn_at`, so a column
//! stamped behind the signature would leave a held row that no longer
//! verifies, and the replication plane serves signed rows only.
//!
//! - **I519** (memory, sqlite, postgres) — the proof's own attester ends it
//!   (the fold reads it as not in force; the served row carries the
//!   withdrawal and verifies); a stranger is refused by standing; a LIVE
//!   delegate of the subject who did not attest the proof is refused by name;
//!   a re-offer that is not a withdrawal is refused; a second withdrawal is a
//!   no-op that keeps the first instant.

#[cfg(test)]
pub(crate) mod bodies {
    use crate::federation::location::member_in_geographic_constraint;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::LocationProof;
    use crate::federation::{Error, FederationDirectory};
    use chrono::{DateTime, Duration, Utc};

    /// **I519** — only the attester ends a proof.
    pub(crate) async fn i519_only_the_attester_ends_a_proof(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        let (subject, delegate, stranger) = (
            format!("i519-s-{tag}"),
            format!("i519-d-{tag}"),
            format!("i519-x-{tag}"),
        );
        for k in [&subject, &delegate, &stranger] {
            ts::register_hybrid_key(d, k).await;
        }
        let cell = h3o::LatLng::new(37.0, -122.0)
            .unwrap()
            .to_cell(h3o::Resolution::Seven)
            .to_string();
        let at: DateTime<Utc> = "2026-10-01T00:00:00Z".parse().unwrap();
        let proof = |withdrawn_at: Option<DateTime<Utc>>| LocationProof {
            subject_key_id: subject.clone(),
            cell_id: cell.clone(),
            cell_resolution: 7,
            asserted_at: at,
            valid_until: None,
            attestation_evidence: None,
            withdrawn_at,
            persist_row_hash: String::new(),
        };
        d.put_location_proof(ts::sign_location_proof(&subject, proof(None)))
            .await
            .unwrap_or_else(|e| panic!("I519 the proof: {e}"));
        let in_force = || async {
            member_in_geographic_constraint(
                &cell,
                &d.list_location_proofs_for(&subject).await.unwrap(),
                Utc::now(),
            )
        };
        assert!(
            in_force().await,
            "I519 precondition — the proof is in force"
        );
        let t1 = at + Duration::hours(1);
        // A stranger: refused by standing, nothing ends.
        let r = d
            .withdraw_location_proof(ts::sign_location_proof(&stranger, proof(Some(t1))))
            .await;
        assert!(
            matches!(r, Err(Error::LocationAuthorityUnauthorized { .. })),
            "I519 a stranger's withdrawal is refused by standing: {r:?}"
        );
        assert!(in_force().await, "I519 the stranger ended nothing");
        // A live delegate of the subject passes standing but did not attest
        // the proof: refused by name.
        ts::put_delegates_to(d, &subject, &delegate, None)
            .await
            .expect("I519 the delegation");
        let r = d
            .withdraw_location_proof(ts::sign_location_proof(&delegate, proof(Some(t1))))
            .await;
        assert!(
            r.as_ref().is_err_and(|e| e
                .to_string()
                .contains("location_proof_withdraw_not_the_attester")),
            "I519 a delegate who did not attest the proof cannot end it: {r:?}"
        );
        assert!(in_force().await, "I519 the delegate ended nothing");
        // A re-offer that is not a withdrawal.
        let r = d
            .withdraw_location_proof(ts::sign_location_proof(&subject, proof(None)))
            .await;
        assert!(
            r.as_ref().is_err_and(|e| e
                .to_string()
                .contains("location_proof_withdraw_not_a_withdrawal")),
            "I519 a row with no withdrawn_at is not a withdrawal: {r:?}"
        );
        // The attester ends it.
        d.withdraw_location_proof(ts::sign_location_proof(&subject, proof(Some(t1))))
            .await
            .unwrap_or_else(|e| panic!("I519 the attester withdraws: {e}"));
        assert!(!in_force().await, "I519 the proof is no longer in force");
        let held = d.list_location_proofs_for(&subject).await.unwrap();
        assert_eq!(held.len(), 1, "I519 one row, in history: {held:?}");
        assert_eq!(
            held[0].withdrawn_at,
            Some(t1),
            "I519 the withdrawal instant"
        );
        // Idempotent: a second withdrawal keeps the first instant.
        d.withdraw_location_proof(ts::sign_location_proof(
            &subject,
            proof(Some(t1 + Duration::hours(1))),
        ))
        .await
        .expect("I519 a re-offer is a no-op");
        let held = d.list_location_proofs_for(&subject).await.unwrap();
        assert_eq!(
            held[0].withdrawn_at,
            Some(t1),
            "I519 the first instant stands"
        );
        // The served row carries the withdrawal and verifies as signed.
        let served = d
            .list_signed_location_proofs_since(None, 10_000)
            .await
            .unwrap()
            .into_iter()
            .find(|s| s.proof.location_proof.subject_key_id == subject)
            .expect("I519 the row is served");
        assert_eq!(served.proof.location_proof.withdrawn_at, Some(t1));
        crate::federation::verify_location_proof_admission(d, &served.proof)
            .await
            .unwrap_or_else(|e| panic!("I519 the served withdrawal verifies as signed: {e}"));
    }
}

#[cfg(test)]
mod runners {
    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()[..12].to_owned()
    }

    macro_rules! runners {
        ($modname:ident, $fresh:expr) => {
            mod $modname {
                use crate::federation::FederationDirectory;
                #[tokio::test]
                async fn i519() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i519_only_the_attester_ends_a_proof(
                        &d as &dyn FederationDirectory,
                        &super::suffix(),
                    )
                    .await
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
