//! v62 (CC 3.1.5 rc21; CIRISServer#1365/#1366, CIRISServer 0.5.250) —
//! **an identity amendment is the exact text the Wise Authority approved**,
//! witnessed on every backend through every door a row enters by.
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
//!   `amendment_digest` (the earlier server's shape), or an ill-shaped one,
//!   is admitted, held, not in force, reporting `amendment_digest_mismatch`
//!   (`response_carries_no_amendment_digest` /
//!   `response_amendment_digest_not_hex64`).
//! - **I2934** — an amendment that arrives AHEAD of its approval is admitted
//!   and held (`identity_amendment_unauthorized`, `response_not_held`); the
//!   matching approval arriving makes it count, with nothing re-written.
//!   `amendment_standings_for(agent)` lists every admitted amendment, and
//!   exactly the authorised ones are in force. The door still refuses what
//!   the amendment's OWN bytes decide (`evidence_does_not_cite_response`).
//! - **I2935** — the WA WITHDRAWS its approval: the amendment that was in
//!   force reads held (`identity_amendment_unauthorized`,
//!   `response_withdrawn`) and stays stored; an amendment under another
//!   approval stays in force. A `supersedes` is not followed.
//!
//! The pure-function witness is I2930 (`identity_amendment::tests`).

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use crate::federation::identity_amendment as ia;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{attestation_type, cohort_scope, Attestation};
    use crate::federation::{Error, FederationDirectory, SignedAttestation};

    /// **I2931–I2935** — see the module doc.
    pub(crate) async fn i2931_the_amendment_is_the_text_the_wa_approved(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        let owner = format!("i2931-owner-{tag}");
        let agent = format!("i2931-agent-{tag}");
        ts::register_user_role_key(d, &owner).await;
        ts::register_hybrid_key(d, &agent).await;
        ts::put_owner_binding(d, &owner, &agent).await;

        let put = |r: Attestation| async move {
            d.put_attestation(SignedAttestation { attestation: r })
                .await
                .map(|_| ())
        };
        let replicate = |r: Attestation| async move {
            d.apply_replicated_attestation(SignedAttestation { attestation: r })
                .await
        };
        let row = |by: &str, about: &str, dimension: &str, extra: serde_json::Value| {
            let id = uuid::Uuid::new_v4().to_string();
            let mut env = serde_json::json!({ "id": id, "dimension": dimension });
            for (k, v) in extra.as_object().unwrap() {
                env[k] = v.clone();
            }
            let mut r = ts::bare_attestation(&id, by, about, &env);
            r.attestation_type = attestation_type::SCORES.to_owned();
            r.cohort_scope = cohort_scope::SELF.to_owned();
            if by == about {
                r.subject_key_ids = vec![about.to_owned()];
            }
            ts::seal_row_in_place(by, &mut r);
            r
        };

        let request = row(
            &agent,
            &agent,
            ia::DEFERRAL_REQUEST_DIMENSION,
            serde_json::json!({ "deferral_id": "d-1", "reason_digest": "ab".repeat(32) }),
        );
        let request_id = request.attestation_id.clone();
        put(request).await.expect("I2931: the deferral request");

        // The owner's approval; `digest` is what it names (None: no member).
        let approval = |digest: Option<serde_json::Value>| {
            let mut extra = serde_json::json!({ "references_attestation_id": request_id });
            if let Some(value) = digest {
                extra[ia::AMENDMENT_DIGEST_MEMBER] = value;
            }
            row(&owner, &agent, ia::DEFERRAL_APPROVED_DIMENSION, extra)
        };
        let amendment = |digest: &str, authorized_by: &str| {
            row(
                &agent,
                &agent,
                ia::IDENTITY_AMENDMENT_DIMENSION,
                serde_json::json!({
                    "amendment_digest": digest,
                    "authorized_by": authorized_by,
                    "evidence_refs": [authorized_by],
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
        let inserted = |o: crate::federation::attestation_apply::ReplicatedAttestationOutcome,
                        what: &str| {
            assert!(
                matches!(
                    o,
                    crate::federation::attestation_apply::ReplicatedAttestationOutcome::Inserted
                ),
                "{what}: inserted, got {o:?}"
            );
        };

        // I2931 — the approval carrying the member admits, at both doors.
        let direct = approval(Some(serde_json::json!(approved_text)));
        let direct_id = direct.attestation_id.clone();
        put(direct)
            .await
            .unwrap_or_else(|e| panic!("I2931: an approval carrying amendment_digest admits: {e}"));
        let wired = approval(Some(serde_json::json!(approved_text)));
        let wired_id = wired.attestation_id.clone();
        inserted(
            replicate(wired).await.unwrap_or_else(|e| {
                panic!("I2931: a replicated approval carrying amendment_digest admits: {e}")
            }),
            "I2931 (replicated approval)",
        );
        for id in [&direct_id, &wired_id] {
            let held = d.get_attestation(id).await.unwrap().expect("I2931: held");
            assert_eq!(
                held.attestation_envelope[ia::AMENDMENT_DIGEST_MEMBER],
                serde_json::json!(approved_text),
                "I2931: the member is stored as signed"
            );
        }

        // I2932 — another text: ADMITTED and HELD (CC 2.7), at both doors,
        // not in force, reporting `amendment_digest_mismatch`.
        let differs = amendment(&other_text, &direct_id);
        put(differs.clone())
            .await
            .unwrap_or_else(|e| panic!("I2932: a mismatched amendment is admitted: {e}"));
        let differs_wired = amendment(&other_text, &wired_id);
        inserted(
            replicate(differs_wired.clone()).await.unwrap_or_else(|e| {
                panic!("I2932: a replicated mismatched amendment is admitted: {e}")
            }),
            "I2932 (replicated)",
        );
        for row in [&differs, &differs_wired] {
            assert!(d
                .get_attestation(&row.attestation_id)
                .await
                .unwrap()
                .is_some());
            let s = standing(row.clone()).await;
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

        // I2933 — an approval naming no text (the earlier server's shape), or
        // an ill-shaped one: the amendment is admitted, held, not in force.
        let silent = approval(None);
        let silent_id = silent.attestation_id.clone();
        put(silent)
            .await
            .expect("I2933: the earlier shape of approval stores");
        let ill = approval(Some(serde_json::json!(approved_text.to_uppercase())));
        let ill_id = ill.attestation_id.clone();
        put(ill)
            .await
            .expect("I2933: the ill-shaped approval stores");
        for (cited, reason) in [
            (
                &silent_id,
                ia::digest_mismatch_reason::RESPONSE_NAMES_NO_TEXT,
            ),
            (
                &ill_id,
                ia::digest_mismatch_reason::RESPONSE_DIGEST_ILL_SHAPED,
            ),
        ] {
            let a = amendment(&approved_text, cited);
            put(a.clone())
                .await
                .unwrap_or_else(|e| panic!("I2933 ({reason}): admitted and held: {e}"));
            let s = standing(a).await;
            assert!(!s.is_in_force(), "I2933 ({reason})");
            assert_eq!(
                s.token(),
                Some(ia::AMENDMENT_DIGEST_MISMATCH),
                "I2933: {s:?}"
            );
            assert_eq!(s.reason(), Some(reason), "I2933: {s:?}");
        }

        // I2934 — the approval arrives AFTER the amendment: the amendment is
        // admitted and held (`response_not_held`), then the matching approval
        // makes it count. Nothing is re-written; the standing is re-read.
        let later = approval(Some(serde_json::json!(approved_text)));
        let later_id = later.attestation_id.clone();
        let early = amendment(&approved_text, &later_id);
        replicate(early.clone()).await.unwrap_or_else(|e| {
            panic!("I2934: an amendment ahead of its approval is admitted: {e}")
        });
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
        put(later).await.expect("I2934: the approval arrives");
        assert_eq!(
            standing(early.clone()).await,
            ia::AmendmentStanding::InForce,
            "I2934: the matching approval makes the held amendment count"
        );

        // I2931 — the approved text is in force, at both doors.
        let ok = amendment(&approved_text, &direct_id);
        put(ok.clone())
            .await
            .unwrap_or_else(|e| panic!("I2931: the approved text admits: {e}"));
        assert_eq!(standing(ok.clone()).await, ia::AmendmentStanding::InForce);
        let ok_wired = amendment(&approved_text, &wired_id);
        inserted(
            replicate(ok_wired.clone())
                .await
                .unwrap_or_else(|e| panic!("I2931: the replicated approved text admits: {e}")),
            "I2931 (replicated)",
        );
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
                .map(|r| r.attestation_id.clone())
                .collect(),
            "I2934: exactly the authorised amendments are in force"
        );
        assert_eq!(
            all.len(),
            7,
            "I2934: every admitted amendment is listed, held or not"
        );

        // The door still refuses what the amendment's OWN bytes decide.
        let mut uncited = amendment(&approved_text, &direct_id);
        uncited.attestation_envelope["evidence_refs"] = serde_json::json!([]);
        ts::seal_row_in_place(&agent, &mut uncited);
        let e = put(uncited).await.unwrap_err();
        assert!(
            matches!(e, Error::InvalidArgument(_))
                && e.to_string().contains(&format!(
                    "{}: {}",
                    ia::IDENTITY_AMENDMENT_UNAUTHORIZED,
                    ia::unauthorized_reason::EVIDENCE_DOES_NOT_CITE
                )),
            "the door refuses an amendment that does not cite its approval: {e}"
        );

        // I2935 — the WA WITHDRAWS its approval: the amendment that was in
        // force reads held (`response_withdrawn`); the other approval's
        // amendment is untouched. A withdrawal is followed, a supersession
        // is not (the amendment names its approval row).
        assert_eq!(standing(ok.clone()).await, ia::AmendmentStanding::InForce);
        ts::put_retraction(
            d,
            &owner,
            &agent,
            &direct_id,
            crate::federation::types::attestation_type::WITHDRAWS,
        )
        .await
        .unwrap_or_else(|e| panic!("I2935: the WA withdraws its approval: {e}"));
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
            d.get_attestation(&ok.attestation_id)
                .await
                .unwrap()
                .is_some(),
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
