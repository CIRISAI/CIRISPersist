//! v51.0.0 invariants that need a real backend door (the parser-level and
//! engine-level ones live beside their code):
//!
//! - **I125 (CIRISPersist#933)** — on postgres, `put_attestation`'s three
//!   projections run INSIDE the row's transaction: a projection that fails
//!   rolls the row back (no committed, unprojected `withdraws`), and the
//!   retry — with the projection answering — inserts and projects.
//!
//! The fault is a `cfg(test)` one-shot inside the postgres door
//! (`store::test_hooks`, the PR #921 review shape): a wrapping double cannot
//! reach a backend's own transaction.

#[cfg(all(test, feature = "postgres"))]
mod postgres {
    use crate::federation::admission::steward_liveness_test_support::{register, signed_row};
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{attestation_type, identity_type as it, SignedAttestation};
    use crate::federation::{AttestationOutcome, Error, FederationDirectory};
    use crate::store::Backend as _;

    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()[..8].to_owned()
    }

    /// I125 — a failed `consent_peer_set` projection leaves NO row; the retry
    /// inserts. The same statement sequence that committed the row and then
    /// projected it as autocommit (v17.4.0 … v50.0.0) would have left the row
    /// with its revocation never folded, and the retry would have dedupped to
    /// `AlreadyHeld` without re-projecting.
    #[tokio::test]
    async fn i125_a_failed_projection_rolls_the_row_back_on_postgres() {
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        let d: &dyn FederationDirectory = &b;
        let s = suffix();
        let granter = format!("g933-{s}");
        let recipient = format!("r933-{s}");
        register(d, &granter, &[it::USER]).await;
        register(d, &recipient, &[it::PRIMITIVE]).await;
        let mut row = signed_row(
            &granter,
            &recipient,
            attestation_type::DELEGATES_TO,
            serde_json::json!({ "id": uuid::Uuid::new_v4().to_string(), "scope": ["infra:serve"] }),
        );
        ts::reseal(&mut row);
        let id = row.attestation_id.clone();

        b.test_hooks().fail_next("pg_project_consent_peer_set", 1);
        let got = d
            .put_attestation(SignedAttestation {
                attestation: row.clone(),
            })
            .await;
        assert!(
            matches!(&got, Err(Error::Backend(m)) if m.contains("injected transient")),
            "the projection's failure is the door's failure: {got:?}"
        );
        assert!(
            d.get_attestation(&id).await.unwrap().is_none(),
            "I125: a failed projection leaves no committed row (it ran inside the transaction)"
        );

        b.test_hooks().fail_next("pg_project_consent_peer_set", 0);
        let again = d
            .put_attestation(SignedAttestation { attestation: row })
            .await
            .unwrap();
        assert_eq!(
            again,
            AttestationOutcome::Inserted,
            "the retry INSERTS (never `AlreadyHeld` over an unprojected row)"
        );
        assert!(d.get_attestation(&id).await.unwrap().is_some());
    }
}
