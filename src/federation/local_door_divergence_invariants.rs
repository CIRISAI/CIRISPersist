//! v56.0.0 (CIRISPersist#934 step 1, door 2) — **the local write door on an
//! occupied `attestation_id`, decided once.**
//!
//! `attestation_upsert_local` / `attestation_insert_local` take an optional
//! caller-chosen `attestation_id`. Before door 2 the three backends' storage
//! halves disagreed when it was already held (the first divergence the
//! one-door extraction made visible). Memory returned the id before the
//! upsert's replace-DELETE; sqlite and postgres ran the DELETE of every local
//! `(attester, dimension)` row, then an insert-if-absent:
//!
//! | leg | memory before | sqlite, postgres before | all three now |
//! |---|---|---|---|
//! | (A) upsert re-uses its own row's id, new weight | old row kept | replaced | replaced |
//! | (B) upsert re-uses another dimension's row's id | Ok, nothing changed | Ok, own row DELETED, nothing stored | refused `LocalAttestationIdOccupied`, nothing changed |
//! | (C) insert re-uses a held id | Ok, nothing written | Ok, nothing written | Ok, nothing written |
//!
//! The ruling (lead, on I951): an upsert REPLACES its own `(attester,
//! dimension)` local row; an id held by any other row is a typed refusal.
//! `attestation_admit::local_occupied_id_verdict` is the one clause.
//!
//! I951 asserts the same outcome on memory, sqlite and postgres.

/// What one backend did, per scenario.
#[cfg(test)]
#[derive(Debug, PartialEq)]
pub(crate) struct Observed {
    /// (A) the weight held under the re-used id after the upsert.
    pub(crate) same_dimension_weight: Option<f64>,
    /// (B) is the held row of the upsert's dimension still there?
    pub(crate) other_dimension_row_survives: bool,
    /// (B) the dimension held under the re-used id after the upsert.
    pub(crate) reused_id_dimension: Option<String>,
    /// (B) the upsert's outcome: `Ok`, or the refusal's `kind()` token.
    pub(crate) cross_dimension_outcome: String,
    /// (C) the weight held under the id an insert re-used.
    pub(crate) insert_reuse_weight: Option<f64>,
    /// (C) the insert's outcome: the id it returned, or `kind()`.
    pub(crate) insert_reuse_outcome: String,
}

/// The backend-agnostic witness body.
#[cfg(test)]
pub(crate) mod bodies {
    use super::Observed;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{attestation_type, cohort_scope, identity_type};
    use crate::federation::FederationDirectory;

    fn input(
        id: &str,
        attester: &str,
        dimension: &str,
        weight: f64,
    ) -> crate::federation::types::LocalAttestationInput {
        crate::federation::types::LocalAttestationInput {
            attestation_id: Some(id.to_owned()),
            attesting_key_id: attester.to_owned(),
            attested_key_id: None,
            attestation_type: attestation_type::SCORES.to_owned(),
            weight: Some(weight),
            expires_at: None,
            attestation_envelope: crate::federation::envelope::EnvelopeCore::from_value(
                serde_json::json!({
                    "dimension": dimension, "score": 1.0, "confidence": 0.9,
                }),
            )
            .unwrap(),
            subject_key_ids: Vec::new(),
            cohort_scope: cohort_scope::SELF.to_owned(),
            scrub_signature_classical: None,
            scrub_signature_pqc: None,
        }
    }

    const BINDING: &str = "identity_binding:v1";
    const CAPABILITY: &str = "capability:reasoning:v1";

    pub(crate) async fn i951_observe(d: &dyn FederationDirectory, tag: &str) -> Observed {
        let a = format!("{tag}-a");
        ts::register_hybrid_key_as(d, &a, &a, identity_type::STEWARD).await;
        let id = |n: &str| {
            uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_OID, format!("{tag}-{n}").as_bytes())
                .to_string()
        };

        // (A) same dimension, same id, different weight.
        let x = id("x");
        d.attestation_insert_local(input(&x, &a, BINDING, 1.0))
            .await
            .expect("(A) the first local row");
        d.attestation_upsert_local(input(&x, &a, BINDING, 0.5))
            .await
            .expect("(A) the upsert re-using its id");
        let same_dimension_weight = d.get_attestation(&x).await.unwrap().and_then(|r| r.weight);

        // (B) a held row of another dimension's id, re-used by an upsert.
        let b = format!("{tag}-b");
        ts::register_hybrid_key_as(d, &b, &b, identity_type::STEWARD).await;
        let (y, z) = (id("y"), id("z"));
        d.attestation_insert_local(input(&y, &b, CAPABILITY, 1.0))
            .await
            .expect("(B) y, the capability row");
        d.attestation_insert_local(input(&z, &b, BINDING, 1.0))
            .await
            .expect("(B) z, the binding row");
        let cross_dimension_outcome = match d
            .attestation_upsert_local(input(&y, &b, BINDING, 1.0))
            .await
        {
            Ok(_) => "Ok".to_owned(),
            Err(e) => e.kind().to_owned(),
        };
        let other_dimension_row_survives = d.get_attestation(&z).await.unwrap().is_some();
        let reused_id_dimension = d.get_attestation(&y).await.unwrap().and_then(|r| {
            r.attestation_envelope
                .get("dimension")
                .and_then(|v| v.as_str())
                .map(str::to_owned)
        });
        // (C) an insert re-using the held id `x`, with yet another weight.
        let insert_reuse_outcome = match d
            .attestation_insert_local(input(&x, &a, BINDING, 0.25))
            .await
        {
            Ok(id) if id == x => "Ok(x)".to_owned(),
            Ok(other) => format!("Ok({other})"),
            Err(e) => e.kind().to_owned(),
        };
        let insert_reuse_weight = d.get_attestation(&x).await.unwrap().and_then(|r| r.weight);
        Observed {
            same_dimension_weight,
            other_dimension_row_survives,
            reused_id_dimension,
            cross_dimension_outcome,
            insert_reuse_weight,
            insert_reuse_outcome,
        }
    }

    /// The one outcome, on every backend (lead ruling on I951).
    pub(crate) fn ruled() -> Observed {
        Observed {
            same_dimension_weight: Some(0.5),
            other_dimension_row_survives: true,
            reused_id_dimension: Some(CAPABILITY.to_owned()),
            cross_dimension_outcome: "federation_local_attestation_id_occupied".to_owned(),
            insert_reuse_weight: Some(0.5),
            insert_reuse_outcome: "Ok(x)".to_owned(),
        }
    }
}

#[cfg(test)]
mod run {
    use super::bodies;
    use crate::federation::FederationDirectory;

    fn tag() -> String {
        format!("i951-{}", uuid::Uuid::new_v4().simple())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn i951_memory() {
        let b = crate::store::memory::MemoryBackend::new();
        let seen = bodies::i951_observe(&b as &dyn FederationDirectory, &tag()).await;
        assert_eq!(seen, bodies::ruled(), "I951 memory (see the module doc)");
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i951_sqlite() {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        let seen = bodies::i951_observe(&b as &dyn FederationDirectory, &tag()).await;
        assert_eq!(seen, bodies::ruled(), "I951 sqlite (see the module doc)");
    }

    #[cfg(feature = "postgres")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i951_postgres() {
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            eprintln!("i951_postgres: no CIRIS_PERSIST_TEST_PG base DSN — SKIPPED");
            return;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        let seen = bodies::i951_observe(&b as &dyn FederationDirectory, &tag()).await;
        assert_eq!(seen, bodies::ruled(), "I951 postgres (see the module doc)");
        eprintln!("i951_postgres: RAN");
    }
}
