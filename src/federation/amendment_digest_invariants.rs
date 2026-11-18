//! v62 (CC 3.1.5 rc21; CIRISServer#1365/#1366, CIRISServer 0.5.250) —
//! **an identity amendment is the exact text the Wise Authority approved**,
//! witnessed on every backend through every door a row enters by.
//!
//! Edition-2 rows (the fixture switch): seeds sign, the stored ids are their
//! identity-refs; the amendment names its approval under `refs.also.cites`
//! (rc21) and the response its request under `refs.answers`.
//!
//! v62 (CC 2.7, "a row is never refused for what another row says") —
//! what the CITED APPROVAL decides never refuses the amendment: it is
//! admitted and HELD, and its force is `identity_amendment::amendment_standing`,
//! read now.
//!
//! - **I2931** — a `deferral:response:approved:v1` carrying `amendment_digest`
//!   is admitted (no envelope-member gate refuses the member), at the direct
//!   door and at the replicated door; an amendment whose `amendment_digest`
//!   equals the approval's is admitted and IN FORCE, at both doors.
//! - **I2932** — an amendment whose `amendment_digest` differs from the
//!   approval's is ADMITTED at both doors, held, NOT in force, reporting
//!   `amendment_digest_mismatch` (`amendment_digest_differs_from_approved`).
//! - **I2933** — an amendment citing an approval that carries no
//!   `amendment_digest` (the earlier server's shape) is admitted, held, not
//!   in force, reporting `amendment_digest_mismatch`
//!   (`response_carries_no_amendment_digest`). (An ill-shaped digest is not
//!   representable in edition 2; I2930 witnesses it over the projection.)
//! - **I2934** — an amendment that arrives AHEAD of its approval is admitted
//!   and held (`identity_amendment_unauthorized`, `response_not_held`); the
//!   matching approval arriving makes it count, with nothing re-written.
//!   `amendment_standings_for(agent)` lists every admitted amendment, and
//!   exactly the authorised ones are in force.
//! - **I2935** — the WA WITHDRAWS its approval: the amendment that was in
//!   force reads held (`identity_amendment_unauthorized`,
//!   `response_withdrawn`) and stays stored; an amendment under another
//!   approval stays in force. A `supersedes` is not followed.
//!
//! The pure-function witness is I2930 (`identity_amendment::tests`).

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::edition2::ingest::{
        apply_replicated_statement, ReplicatedStatementOutcome, StatementOutcome,
    };
    use crate::federation::identity_amendment as ia;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{attestation_type, delegation_scope as ds, owner_binding};
    use crate::federation::types::{identity_type, Attestation};
    use crate::federation::FederationDirectory;

    /// A row by `by` (a SEED) about `about` (a seed) on `dimension`, as an
    /// edition-2 statement (the fixture switch): the earlier-form shape the
    /// codec reads, signed by `by`'s key.
    fn row(by: &str, about: &str, dimension: &str, extra: serde_json::Value) -> Attestation {
        let id = uuid::Uuid::new_v4().to_string();
        let mut env = serde_json::json!({ "id": id, "dimension": dimension });
        for (k, v) in extra.as_object().expect("extra members") {
            env[k] = v.clone();
        }
        let mut r = ts::bare_attestation(&id, by, about, &env);
        r.attestation_type = attestation_type::SCORES.to_owned();
        ts::seal_row_in_place(by, &mut r);
        r
    }

    /// `[2, [-16, rid]]`, the JSON the codec writes as an edition-2 row-ref.
    fn row_ref(target: &Attestation) -> serde_json::Value {
        serde_json::json!([2, [-16, e2::rid(target)]])
    }

    /// Put `row` at the direct door: the statement it carries.
    async fn put(d: &dyn FederationDirectory, r: &Attestation) -> StatementOutcome {
        e2::put_signed(d, r)
            .await
            .unwrap_or_else(|e| panic!("put {}: {e}", r.attestation_id))
    }

    /// Offer `row` at the replicated door, under the id its bytes name.
    async fn replicate(d: &dyn FederationDirectory, r: &Attestation) -> ReplicatedStatementOutcome {
        let st = e2::carried_statement(r).expect("an edition-2 row carries its statement");
        apply_replicated_statement(d, &st, &e2::rid_digest(r))
            .await
            .unwrap_or_else(|e| panic!("replicate {}: {e}", r.attestation_id))
    }

    fn admitted(o: &ReplicatedStatementOutcome, what: &str) {
        assert!(
            matches!(
                o,
                ReplicatedStatementOutcome::Admitted(StatementOutcome::Row { .. })
            ),
            "{what}: admitted as a row, got {o:?}"
        );
    }

    /// **I2931–I2935** — see the module doc.
    pub(crate) async fn i2931_the_amendment_is_the_text_the_wa_approved(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        // Seeds (the signer names); the stored ids are their identity-refs.
        let owner = format!("{tag}-own");
        let agent_seed = format!("{tag}-agt");
        let _ = e2::put_key(d, &owner, &[identity_type::USER]).await;
        let agent = e2::put_key(d, &agent_seed, &[identity_type::AGENT]).await;

        // The owner binds the agent's key; the agent's own voice lands it
        // (CC 3.2: the bound key cosigns).
        let id = uuid::Uuid::new_v4().to_string();
        let mut binding = ts::bare_attestation(
            &id,
            &owner,
            &agent_seed,
            &serde_json::json!({
                "id": id,
                "kind": "delegates_to",
                "dimension": owner_binding::DIMENSION,
                "delegation_purpose": owner_binding::PURPOSE,
                "scope": [ds::INFRA_SERVE, ds::INFRA_NETWORK_PRESENCE],
            }),
        );
        binding.attestation_type = attestation_type::DELEGATES_TO.to_owned();
        ts::seal_row_in_place(&owner, &mut binding);
        e2::put_signed(d, &binding)
            .await
            .unwrap_or_else(|e| panic!("I2931: the owner's voice over its binding: {e}"));
        let st = e2::carried_statement(&binding).expect("the binding's statement");
        e2::put_statement(d, &e2::voice_of(&st, &agent_seed))
            .await
            .unwrap_or_else(|e| panic!("I2931: the agent's voice lands the binding: {e}"));
        assert_eq!(
            crate::federation::admission::owner_of(d, &agent)
                .await
                .unwrap()
                .as_deref(),
            Some(e2::kid(&owner).as_str()),
            "I2931 precondition: the binding seats the owner"
        );

        let request = row(
            &agent_seed,
            &agent_seed,
            ia::DEFERRAL_REQUEST_DIMENSION,
            serde_json::json!({ "deferral_id": "d-1", "reason_digest": "ab".repeat(32) }),
        );
        put(d, &request).await;

        // The owner's approval of the request (`refs.answers`); `digest` is
        // the text it names (None: no member).
        let approval = |digest: Option<&str>| {
            let mut extra = serde_json::json!({
                "deferral_id": "d-1",
                "refs": { "answers": row_ref(&request) },
            });
            if let Some(dg) = digest {
                extra[ia::AMENDMENT_DIGEST_MEMBER] = serde_json::json!(dg);
            }
            row(&owner, &agent_seed, ia::DEFERRAL_APPROVED_DIMENSION, extra)
        };
        // The agent's amendment, citing `approval` (rc21: `refs.also.cites`,
        // which the mapping projects as `authorized_by` / `evidence_refs`).
        let amendment = |digest: &str, cited: &Attestation| {
            row(
                &agent_seed,
                &agent_seed,
                ia::IDENTITY_AMENDMENT_DIMENSION,
                serde_json::json!({
                    "amendment_digest": digest,
                    "refs": { "also": { "cites": [row_ref(cited)] } },
                }),
            )
        };
        let approved_text = "cd".repeat(32);
        let other_text = "ef".repeat(32);
        let standing = |r: Attestation| async move {
            ia::amendment_standing(d, &r)
                .await
                .unwrap()
                .expect("an identity amendment")
        };

        // I2931 — the approval carrying the member admits, at both doors.
        let direct = approval(Some(&approved_text));
        put(d, &direct).await;
        let wired = approval(Some(&approved_text));
        admitted(&replicate(d, &wired).await, "I2931 (replicated approval)");
        for a in [&direct, &wired] {
            let held = d
                .get_attestation(&e2::rid(a))
                .await
                .unwrap()
                .expect("I2931: held");
            assert_eq!(
                held.attestation_envelope[ia::AMENDMENT_DIGEST_MEMBER],
                serde_json::json!(approved_text),
                "I2931: the member reads back as the hex the gate compares"
            );
        }

        // I2932 — another text: ADMITTED and HELD (CC 2.7), at both doors.
        let differs = amendment(&other_text, &direct);
        put(d, &differs).await;
        let differs_wired = amendment(&other_text, &wired);
        admitted(&replicate(d, &differs_wired).await, "I2932 (replicated)");
        for r in [&differs, &differs_wired] {
            assert!(d.get_attestation(&e2::rid(r)).await.unwrap().is_some());
            let s = standing(r.clone()).await;
            assert!(!s.is_in_force(), "I2932: not in force");
            assert_eq!(
                s.token(),
                Some(ia::AMENDMENT_DIGEST_MISMATCH),
                "I2932: {s:?}"
            );
            assert_eq!(
                s.reason(),
                Some(ia::digest_mismatch_reason::DIGESTS_DIFFER),
                "I2932: {s:?}"
            );
        }

        // I2933 — an approval naming no text (the earlier server's shape):
        // the amendment is admitted, held, not in force. (An ILL-SHAPED
        // digest is not representable in edition 2, where the member is 32
        // bytes; I2930 witnesses that case over the projection.)
        let silent = approval(None);
        put(d, &silent).await;
        let unnamed = amendment(&approved_text, &silent);
        put(d, &unnamed).await;
        let s = standing(unnamed.clone()).await;
        assert!(!s.is_in_force(), "I2933");
        assert_eq!(
            s.token(),
            Some(ia::AMENDMENT_DIGEST_MISMATCH),
            "I2933: {s:?}"
        );
        assert_eq!(
            s.reason(),
            Some(ia::digest_mismatch_reason::RESPONSE_NAMES_NO_TEXT),
            "I2933: {s:?}"
        );

        // I2934 — the approval arrives AFTER the amendment: admitted and held
        // (`response_not_held`), then the matching approval makes it count.
        let later = approval(Some(&approved_text));
        let early = amendment(&approved_text, &later);
        admitted(&replicate(d, &early).await, "I2934: ahead of its approval");
        let s = standing(early.clone()).await;
        assert!(!s.is_in_force(), "I2934: absent approval, not in force");
        assert_eq!(
            s.token(),
            Some(ia::IDENTITY_AMENDMENT_UNAUTHORIZED),
            "I2934: {s:?}"
        );
        assert_eq!(
            s.reason(),
            Some(ia::unauthorized_reason::RESPONSE_NOT_HELD),
            "I2934: {s:?}"
        );
        put(d, &later).await;
        assert_eq!(
            standing(early.clone()).await,
            ia::AmendmentStanding::InForce,
            "I2934: the matching approval makes the held amendment count"
        );

        // I2931 — the approved text is in force, at both doors.
        let ok = amendment(&approved_text, &direct);
        put(d, &ok).await;
        assert_eq!(standing(ok.clone()).await, ia::AmendmentStanding::InForce);
        let ok_wired = amendment(&approved_text, &wired);
        admitted(&replicate(d, &ok_wired).await, "I2931 (replicated)");
        assert_eq!(
            standing(ok_wired.clone()).await,
            ia::AmendmentStanding::InForce
        );

        // The reader: every amendment about the agent, each with its standing.
        let all = ia::amendment_standings_for(d, &agent).await.unwrap();
        let in_force: std::collections::BTreeSet<String> = all
            .iter()
            .filter(|(_, s)| s.is_in_force())
            .map(|(r, _)| r.attestation_id.clone())
            .collect();
        assert_eq!(
            in_force,
            [&early, &ok, &ok_wired]
                .iter()
                .map(|r| e2::rid(r))
                .collect(),
            "I2934: exactly the authorised amendments are in force"
        );
        assert_eq!(
            all.len(),
            6,
            "I2934: every admitted amendment is listed, held or not"
        );

        // I2935 — the WA WITHDRAWS its approval: the amendment that was in
        // force reads held (`response_withdrawn`); the other approval's
        // amendment is untouched.
        let withdrawal = e2::composer_of(attestation_type::WITHDRAWS, &direct, &owner);
        put(d, &withdrawal).await;
        let s = standing(ok.clone()).await;
        assert!(
            !s.is_in_force(),
            "I2935: a withdrawn approval authorises nothing"
        );
        assert_eq!(
            s.token(),
            Some(ia::IDENTITY_AMENDMENT_UNAUTHORIZED),
            "I2935: {s:?}"
        );
        assert_eq!(
            s.reason(),
            Some(ia::unauthorized_reason::RESPONSE_WITHDRAWN),
            "I2935: {s:?}"
        );
        assert!(
            d.get_attestation(&e2::rid(&ok)).await.unwrap().is_some(),
            "I2935: the amendment stays stored, held"
        );
        assert_eq!(
            standing(ok_wired.clone()).await,
            ia::AmendmentStanding::InForce,
            "I2935: the other approval's amendment stays in force"
        );
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod tests {
    use super::bodies;

    fn tag(n: &str) -> String {
        format!("{n}{}", &uuid::Uuid::new_v4().simple().to_string()[..8])
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i2931_sqlite() {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        bodies::i2931_the_amendment_is_the_text_the_wa_approved(&b, &tag("s")).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i2931_postgres() {
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            eprintln!("I2931 postgres: no CIRIS_PERSIST_TEST_PG base DSN — SKIPPED");
            return;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        bodies::i2931_the_amendment_is_the_text_the_wa_approved(&b, &tag("p")).await;
        eprintln!("i2931_postgres: RAN");
    }
}
