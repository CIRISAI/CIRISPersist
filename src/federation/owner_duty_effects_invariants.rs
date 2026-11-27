//! v62.0.0 (D2.rev2; CC 3.4.7) — **I6609–I6610: an expiry is an EFFECT on
//! every node; only its RECORD needs the owner's `infra:attest`.**
//!
//! The consent-expiry sweep (`consent_expiry::run_consent_expiry_sweep`,
//! `Engine::run_consent_expiry_sweep`) has one step that writes: it signs a
//! `consent:state:expired` RECORD of a lapse it saw. It ends no access,
//! deletes nothing and touches no grant (READ, `consent_expiry.rs` module doc
//! and body). The lapse itself is read by INSTANT on every node, record or
//! not: `consent::fold_winner` drops a candidate whose `expires_at` has
//! passed, and `fold_scoped_stance_refs_with_winner` reads a passed
//! `retain:<window>` as `Expired`. So a node that may not sign the record
//! skips the record and nothing else.
//!
//! - **I6609** — an UNOWNED node holding a consent whose `retain:1d` window
//!   has passed: the stance reads `Expired` (access ended), the sweep reports
//!   `unowned` and signs nothing, and no `consent:state:expired` row is held.
//! - **I6610** — an OWNED node whose binding carries no `infra:attest`: the
//!   stance reads `Expired` before and after the sweep; the record the sweep
//!   signs concludes nothing (no `consent:state:expired` row is in force).
//!   With `infra:attest` in the binding (I109, `consent_scope_invariants`) the
//!   record lands.
//!
//! Engines on sqlite and postgres; the grant through the real door.

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use crate::federation::attestation_query::test_support::AllAttestations as _;
    use crate::federation::consent_scope_invariants::bodies::{put, stance};
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::hard_case::ConsentState;
    use crate::federation::types::identity_type as it;
    use crate::federation::FederationDirectory;

    fn iso(t: chrono::DateTime<chrono::Utc>) -> String {
        t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
    }

    /// The subject's `share` grant on `target` bounded by `retain:1d`,
    /// asserted two days ago: its window has passed.
    async fn lapsed_grant(d: &dyn FederationDirectory, tag: &str) -> (String, String) {
        let subject = e2::put_key(d, &format!("{tag}-subject"), &[it::USER]).await;
        let target = e2::put_key(d, &format!("{tag}-target"), &[it::USER]).await;
        let asserted = iso(chrono::Utc::now() - chrono::Duration::days(2));
        put(
            d,
            stance(
                &format!("{tag}-grant"),
                &subject,
                &target,
                "granted",
                serde_json::json!(["share", "retain:1d"]),
                serde_json::json!({}),
                &asserted,
                None,
            ),
        )
        .await
        .expect("the grant lands");
        (subject, target)
    }

    async fn stance_now(d: &dyn FederationDirectory, target: &str, subject: &str) -> ConsentState {
        d.resolve_scoped_consent(target, subject, "share", None, chrono::Utc::now())
            .await
            .expect("the stance read")
    }

    async fn expiry_records(d: &dyn FederationDirectory, target: &str) -> usize {
        d.all_attestations_for(target)
            .await
            .expect("the rows read")
            .into_iter()
            .filter(|a| {
                crate::federation::admission::envelope_dimension(&a.attestation_envelope)
                    .is_some_and(|x| x.starts_with("consent:state:expired"))
            })
            .count()
    }

    /// I6609 — unowned: the effect holds, nothing is signed.
    pub(crate) async fn i6609_an_unowned_node_ends_access_and_signs_nothing(
        engine: &crate::Engine,
        tag: &str,
    ) {
        engine
            .register_self_federation_key(it::NODE, None, None)
            .await
            .expect("I6609: the node registers");
        let dir = engine.federation_directory();
        let d: &dyn FederationDirectory = dir.as_ref();
        let (subject, target) = lapsed_grant(d, tag).await;
        assert_eq!(
            stance_now(d, &target, &subject).await,
            ConsentState::Expired,
            "I6609: the lapse ends access by its own instant, with no record held"
        );
        let report = engine
            .run_consent_expiry_sweep(chrono::Utc::now())
            .await
            .expect("I6609: the sweep answers, not an error");
        assert!(report.unowned, "I6609: reported unowned: {report:?}");
        assert_eq!(report.emitted, 0, "I6609: nothing signed: {report:?}");
        assert_eq!(
            expiry_records(d, &target).await,
            0,
            "I6609: no consent:state:expired row is held"
        );
        assert_eq!(
            stance_now(d, &target, &subject).await,
            ConsentState::Expired,
            "I6609: access stays ended"
        );
    }

    /// I6610 — owned without `infra:attest`: the effect holds, the record
    /// concludes nothing.
    pub(crate) async fn i6610_a_record_without_the_duty_concludes_nothing(
        engine: &crate::Engine,
        alias: &str,
        tag: &str,
    ) {
        engine
            .register_self_federation_key(it::NODE, None, None)
            .await
            .expect("I6610: the node registers");
        let dir = engine.federation_directory();
        let d: &dyn FederationDirectory = dir.as_ref();
        crate::federation::admission::r2_test_support::confer_from_owner(
            d,
            &format!("{tag}-owner"),
            alias,
            &[],
        )
        .await;
        let (subject, target) = lapsed_grant(d, tag).await;
        assert_eq!(
            stance_now(d, &target, &subject).await,
            ConsentState::Expired,
            "I6610: the lapse ends access by its own instant"
        );
        let report = engine
            .run_consent_expiry_sweep(chrono::Utc::now())
            .await
            .expect("I6610: the sweep answers");
        assert!(!report.unowned, "I6610: the node is owned: {report:?}");
        assert_eq!(
            expiry_records(d, &target).await,
            0,
            "I6610: the record is held reserved_family_unseated, never in force"
        );
        assert_eq!(
            stance_now(d, &target, &subject).await,
            ConsentState::Expired,
            "I6610: access stays ended"
        );
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod tests {
    use super::bodies;

    fn tag(n: &str) -> String {
        format!("{n}{}", &uuid::Uuid::new_v4().simple().to_string()[..8])
    }

    async fn engine_on(alias: &str, dsn: &str) -> crate::Engine {
        crate::Engine::with_signer(
            crate::federation::tier_ingest::test_support::local_signer(alias),
            dsn,
        )
        .await
        .expect("engine")
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i6609_sqlite() {
        let t = tag("i6609s");
        let alias = format!("{t}-node");
        let e = engine_on(&alias, "sqlite::memory:").await;
        bodies::i6609_an_unowned_node_ends_access_and_signs_nothing(&e, &t).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i6609_postgres() {
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            eprintln!("I6609 postgres: no CIRIS_PERSIST_TEST_PG base DSN — SKIPPED");
            return;
        };
        let t = tag("i6609p");
        let alias = format!("{t}-node");
        let e = engine_on(&alias, &dsn).await;
        bodies::i6609_an_unowned_node_ends_access_and_signs_nothing(&e, &t).await;
        eprintln!("i6609_postgres: RAN");
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i6610_sqlite() {
        let t = tag("i6610s");
        let alias = format!("{t}-node");
        let e = engine_on(&alias, "sqlite::memory:").await;
        bodies::i6610_a_record_without_the_duty_concludes_nothing(&e, &alias, &t).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i6610_postgres() {
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            eprintln!("I6610 postgres: no CIRIS_PERSIST_TEST_PG base DSN — SKIPPED");
            return;
        };
        let t = tag("i6610p");
        let alias = format!("{t}-node");
        let e = engine_on(&alias, &dsn).await;
        bodies::i6610_a_record_without_the_duty_concludes_nothing(&e, &alias, &t).await;
        eprintln!("i6610_postgres: RAN");
    }
}
