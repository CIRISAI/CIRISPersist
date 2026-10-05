//! v53.1.2 (CIRISPersist#984 row 12, CC 2.4.1.1) — **who may retract what.**
//!
//! - **I516** (memory, sqlite, postgres) — only the original attester
//!   `recants`; a subject's path is `withdraws` (or a contradicting `scores`).
//!   A subject-authored `recants` is refused at the door by name and, offered
//!   to the fold directly (the out-of-order shape), retires nothing; the
//!   attester's own `recants` retires the row; the subject's `withdraws`
//!   still does (rule 2, the control). One predicate decides both the door
//!   and the fold (`precedence::retraction_entitled`).

#[cfg(test)]
pub(crate) mod bodies {
    use crate::federation::precedence::retired_ids;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::identity_type::USER;
    use crate::federation::types::{attestation_tier, attestation_type};
    use crate::federation::{Attestation, Error, FederationDirectory, SignedAttestation};

    /// A federation-tier row signed by `signer` (sign → seal → reseal).
    fn row(
        id: &str,
        signer: &str,
        target: &str,
        kind: &str,
        envelope: serde_json::Value,
        subject_key_ids: Vec<String>,
    ) -> Attestation {
        let at = chrono::Utc::now();
        let (och, ed_sig, pqc_sig) = ts::sign_envelope(signer, &envelope);
        let mut r = Attestation {
            attestation_id: id.to_owned(),
            attesting_key_id: signer.to_owned(),
            attested_key_id: target.to_owned(),
            attestation_type: kind.to_owned(),
            weight: None,
            asserted_at: at,
            expires_at: None,
            attestation_envelope: envelope,
            original_content_hash: och,
            scrub_signature_classical: ed_sig,
            scrub_signature_pqc: pqc_sig,
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
        ts::reseal(&mut r);
        r
    }

    /// A `scores` row by `attester` about `subject`, naming the subject.
    fn about(id: &str, attester: &str, subject: &str) -> Attestation {
        row(
            id,
            attester,
            subject,
            attestation_type::SCORES,
            serde_json::json!({"dimension": "scores:i516:v1", "score": 0.5}),
            vec![subject.to_owned()],
        )
    }

    /// A structural composer of `kind` by `author` naming `target`.
    fn composer(id: &str, author: &str, kind: &str, target: &str) -> Attestation {
        row(
            id,
            author,
            author,
            kind,
            serde_json::json!({"references_attestation_id": target}),
            Vec::new(),
        )
    }

    async fn put(d: &dyn FederationDirectory, a: Attestation) -> Result<(), Error> {
        d.put_attestation(SignedAttestation { attestation: a })
            .await
            .map(|_| ())
    }

    /// Is `target` retired by the fold over `rows`?
    fn retired(rows: &[Attestation], target: &str) -> bool {
        let refs: Vec<&Attestation> = rows.iter().collect();
        retired_ids(&refs).contains(target)
    }

    /// **I516** — a subject may withdraw, never recant.
    pub(crate) async fn i516_a_subject_may_withdraw_but_not_recant(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        let (attester, subject) = (format!("i516-k-{tag}"), format!("i516-s-{tag}"));
        for k in [&attester, &subject] {
            ts::register_identity_key(d, k, USER).await;
        }
        let t1 = format!("i516-t1-{tag}");
        put(d, about(&t1, &attester, &subject))
            .await
            .expect("I516 the row about the subject");
        // (a) the subject's recants: refused at the door by name…
        let s_recants = composer(
            &format!("i516-sr-{tag}"),
            &subject,
            attestation_type::RECANTS,
            &t1,
        );
        let r = put(d, s_recants.clone()).await;
        assert!(
            r.as_ref()
                .is_err_and(|e| e.to_string().contains("recants_not_admitted")),
            "I516 (a) a subject's recants is refused by name: {r:?}"
        );
        // …and, offered to the fold directly (out of order), retires nothing.
        let stored_t1 = d.get_attestation(&t1).await.unwrap().expect("t1 stored");
        assert!(
            !retired(&[stored_t1.clone(), s_recants], &t1),
            "I516 (a) the fold does not let a subject recant"
        );
        // (b) the attester's own recants retires it.
        put(
            d,
            composer(
                &format!("i516-kr-{tag}"),
                &attester,
                attestation_type::RECANTS,
                &t1,
            ),
        )
        .await
        .expect("I516 (b) the attester recants its own row");
        let rows = d.list_attestations_for(&subject).await.unwrap();
        let mut all = rows.clone();
        all.extend(d.list_attestations_by(&attester).await.unwrap());
        assert!(
            retired(&all, &t1),
            "I516 (b) the attester's recants retires t1"
        );
        // (c) control: the subject's withdraws (rule 2) still retires a row.
        let t2 = format!("i516-t2-{tag}");
        put(d, about(&t2, &attester, &subject))
            .await
            .expect("I516 (c) a second row about the subject");
        put(
            d,
            composer(
                &format!("i516-sw-{tag}"),
                &subject,
                attestation_type::WITHDRAWS,
                &t2,
            ),
        )
        .await
        .expect("I516 (c) the subject withdraws a row about them");
        let mut all = d.list_attestations_for(&subject).await.unwrap();
        all.extend(d.list_attestations_by(&subject).await.unwrap());
        assert!(
            retired(&all, &t2),
            "I516 (c) the subject's withdraws retires t2"
        );
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
                async fn i516() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i516_a_subject_may_withdraw_but_not_recant(
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
