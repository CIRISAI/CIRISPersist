//! v53.1.2 (CIRISPersist#984 row 12, CC 2.4.1.1) — **who may retract what.**
//!
//! - **I516** (memory, sqlite, postgres) — only the original attester
//!   `recants`; a subject's path is `withdraws` (or a contradicting `scores`).
//!   A subject-authored `recants` is refused at the door by name and, offered
//!   to the fold directly (the out-of-order shape), retires nothing; the
//!   attester's own `recants` retires the row; the subject's `withdraws`
//!   still does (rule 2, the control). One predicate decides both the door
//!   and the fold (`precedence::retraction_entitled`).
//!
//! v62.0.0 (the JSON cut): every row is an edition-2 statement
//! (`edition2::fixture_switch`), keys are live by their `key:record`, ids are
//! the identity-ref `kid(label)` and the node-computed row id `rid(row)`. A
//! composer names its target by `refs.target`.

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::precedence::retired_ids;
    use crate::federation::types::identity_type::USER;
    use crate::federation::types::{attestation_tier, attestation_type};
    use crate::federation::{Attestation, Error, FederationDirectory};

    /// A federation-tier row signed by `signer`: the earlier-form shape,
    /// mapped through its edition-2 statement (`e2::row_of`).
    fn row(
        signer: &str,
        target: &str,
        kind: &str,
        envelope: serde_json::Value,
        subject_key_ids: Vec<String>,
    ) -> Attestation {
        let at = chrono::Utc::now();
        let shape = Attestation {
            attestation_id: String::new(),
            attesting_key_id: signer.to_owned(),
            attested_key_id: target.to_owned(),
            attestation_type: kind.to_owned(),
            weight: None,
            asserted_at: at,
            expires_at: None,
            attestation_envelope: envelope,
            original_content_hash: String::new(),
            scrub_signature_classical: String::new(),
            scrub_signature_pqc: None,
            scrub_key_id: signer.to_owned(),
            scrub_timestamp: at,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids,
            withdraws_admission_rule: None,
            cohort_scope: "federation".to_owned(),
            tier: attestation_tier::FEDERATION.to_owned(),
            promoted_at: None,
            additional_scrubs: Vec::new(),
        };
        e2::row_of(&shape, signer)
    }

    /// A `scores` row by `attester` about `subject`, naming the subject.
    fn about(attester: &str, subject: &str) -> Attestation {
        row(
            attester,
            subject,
            attestation_type::SCORES,
            serde_json::json!({"dimension": "trust:i516:v1", "score": 0.5, "confidence": 0.9}),
            vec![subject.to_owned()],
        )
    }

    /// A structural composer of `kind` by `author` naming `target`
    /// (`refs.target`).
    fn composer(author: &str, kind: &str, target: &Attestation) -> Attestation {
        e2::composer_of(kind, target, author)
    }

    async fn put(d: &dyn FederationDirectory, a: Attestation) -> Result<(), Error> {
        e2::put_signed(d, &a).await.map(|_| ())
    }

    /// v62.0.0 (E2-fix3; CC 2.7.3) — **what the door said NO with**: a
    /// refusal's text, or, when the door HELD the row on a fold condition (a
    /// composer's entitlement is read from its TARGET, another row), the
    /// fold's reason token and its detail (`fold::why_held`). `None` when the
    /// row landed, or waits with no fold reason.
    async fn refused_or_held(d: &dyn FederationDirectory, a: Attestation) -> Option<String> {
        use crate::federation::edition2::ingest::StatementOutcome;
        match e2::put_signed(d, &a).await {
            Err(e) => Some(e.to_string()),
            Ok(StatementOutcome::Pending { row_id, .. }) => {
                crate::federation::edition2::fold::why_held(d, &row_id)
                    .await
                    .expect("the fold's record reads")
                    .map(|h| format!("{}: {}", h.reason, h.detail))
            }
            Ok(_) => None,
        }
    }

    /// Is `target` retired by the fold over `rows`?
    fn retired(rows: &[Attestation], target: &str) -> bool {
        let refs: Vec<&Attestation> = rows.iter().collect();
        retired_ids(&refs).contains(target)
    }

    /// **I520** (v53.1.2, CIRISPersist#984 row 13; v55.0.0 CIRISPersist#989)
    /// — **only the holder retracts its own holding claim.** The claim
    /// (`custody:ack:v1` since v55; the `holds_bytes` carrier before) is the
    /// holder's self-attestation. A third party's `withdraws` of it is
    /// refused at the door by name (v55.0.0, CIRISPersist#1007, I791) and is
    /// inert in the fold when offered directly; the holder's own `withdraws`
    /// retires it in both.
    ///
    /// v62.0.0: the leg over a replicated `withdraws_admission_rule` stamp is
    /// deleted. The stamp was a column of the earlier-form row; an edition-2
    /// statement carries no such column.
    pub(crate) async fn i520_only_the_holder_retracts_a_carrier(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        use crate::federation::attestation_query::test_support::AllAttestations as _;
        use crate::federation::types::identity_type::NODE;
        let (holder, third) = (format!("i520-h-{tag}"), format!("i520-t-{tag}"));
        for k in [&holder, &third] {
            let _ = e2::put_key(d, k, &[NODE]).await;
        }
        let sha: [u8; 32] = {
            use sha2::Digest as _;
            sha2::Sha256::digest(tag.as_bytes()).into()
        };
        let claim = row(
            &holder,
            &holder,
            attestation_type::SCORES,
            serde_json::json!({
                "dimension": crate::federation::custody_ack::CUSTODY_ACK_DIMENSION,
                "custody_state": "here",
                "evidence_refs": [hex::encode(sha)],
                "size": 4096,
                "score": 1.0,
                "confidence": 1.0,
            }),
            Vec::new(),
        );
        let claim_id = e2::rid(&claim);
        put(d, claim.clone())
            .await
            .expect("I520 the holder's claim");
        let holder_kid = e2::kid(&holder);
        let listed = || async {
            d.list_holders_sized(&sha)
                .await
                .unwrap()
                .iter()
                .any(|h| h.key_id == holder_kid)
        };
        assert!(listed().await, "I520 precondition — the holder is listed");
        // A third party's withdraws of the carrier: refused at the door by
        // name.
        let third_w = composer(&third, attestation_type::WITHDRAWS, &claim);
        // v62.0.0 (E2-fix3): the claim is another row, so the door HOLDS the
        // withdraws with the reason (CC 2.7.3), concluding nothing.
        let r = refused_or_held(d, third_w.clone()).await;
        assert!(
            r.as_ref()
                .is_some_and(|t| t.contains("custody_ack_withdraws_not_the_holder")),
            "I791 a third party's withdraws of a carrier is refused by name: {r:?}"
        );
        // …and inert in the fold even when offered directly (out of order).
        let stored = d.get_attestation(&claim_id).await.unwrap().expect("claim");
        assert!(
            !retired(&[stored, third_w], &claim_id),
            "I520 the fold never lets a third party retire a holding claim"
        );
        assert!(listed().await, "I520 the holder is still listed");
        // The holder's own withdraws retires it in the fold and the listing.
        put(d, composer(&holder, attestation_type::WITHDRAWS, &claim))
            .await
            .expect("I520 the holder withdraws its own claim");
        let mine = d.all_attestations_by(&holder_kid).await.unwrap();
        assert!(
            retired(&mine, &claim_id),
            "I520 the holder's own withdraws retires it"
        );
        assert!(!listed().await, "I520 and the listing agrees");
    }

    /// **I516** — a subject may withdraw, never recant.
    pub(crate) async fn i516_a_subject_may_withdraw_but_not_recant(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        use crate::federation::attestation_query::test_support::AllAttestations as _;
        let (attester, subject) = (format!("i516-k-{tag}"), format!("i516-s-{tag}"));
        for k in [&attester, &subject] {
            let _ = e2::put_key(d, k, &[USER]).await;
        }
        let (attester_kid, subject_kid) = (e2::kid(&attester), e2::kid(&subject));
        let t1_row = about(&attester, &subject);
        let t1 = e2::rid(&t1_row);
        put(d, t1_row.clone())
            .await
            .expect("I516 the row about the subject");
        // (a) the subject's recants: refused at the door by name…
        let s_recants = composer(&subject, attestation_type::RECANTS, &t1_row);
        // v62.0.0 (E2-fix3): the entitlement is read from the target (another
        // row), so the door HOLDS it `withdraws_not_admitted` with the
        // `recants_not_admitted` text as its detail (CC 2.7.3).
        let r = refused_or_held(d, s_recants.clone()).await;
        assert!(
            r.as_ref()
                .is_some_and(|t| t.contains("recants_not_admitted")),
            "I516 (a) a subject's recants is refused by name: {r:?}"
        );
        // …and, offered to the fold directly (out of order), retires nothing.
        let stored_t1 = d.get_attestation(&t1).await.unwrap().expect("t1 stored");
        assert!(
            !retired(&[stored_t1.clone(), s_recants], &t1),
            "I516 (a) the fold does not let a subject recant"
        );
        // (b) the attester's own recants retires it.
        put(d, composer(&attester, attestation_type::RECANTS, &t1_row))
            .await
            .expect("I516 (b) the attester recants its own row");
        let rows = d.all_attestations_for(&subject_kid).await.unwrap();
        let mut all = rows.clone();
        all.extend(d.all_attestations_by(&attester_kid).await.unwrap());
        assert!(
            retired(&all, &t1),
            "I516 (b) the attester's recants retires t1"
        );
        // (c) control: the subject's withdraws (rule 2) still retires a row.
        // A second row about the subject: a later instant, so a distinct id.
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        let t2_row = about(&attester, &subject);
        let t2 = e2::rid(&t2_row);
        assert_ne!(t1, t2, "I516 (c) a distinct second row");
        put(d, t2_row.clone())
            .await
            .expect("I516 (c) a second row about the subject");
        put(d, composer(&subject, attestation_type::WITHDRAWS, &t2_row))
            .await
            .expect("I516 (c) the subject withdraws a row about them");
        let mut all = d.all_attestations_for(&subject_kid).await.unwrap();
        all.extend(d.all_attestations_by(&subject_kid).await.unwrap());
        assert!(
            retired(&all, &t2),
            "I516 (c) the subject's withdraws retires t2"
        );
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod runners {
    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()[..12].to_owned()
    }

    macro_rules! runners {
        ($modname:ident, $fresh:expr) => {
            mod $modname {
                use crate::federation::FederationDirectory;
                #[tokio::test]
                async fn i516() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i516_a_subject_may_withdraw_but_not_recant(
                        &d as &dyn FederationDirectory,
                        &super::suffix(),
                    )
                    .await
                }
                #[tokio::test]
                async fn i520() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i520_only_the_holder_retracts_a_carrier(
                        &d as &dyn FederationDirectory,
                        &super::suffix(),
                    )
                    .await
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
