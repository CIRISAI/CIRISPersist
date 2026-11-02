//! v61 S2 (CIRISPersist#1161; CC 4.5.5, the shape CC gave 2026-11-01) —
//! **I1512: room moderation at community scope, in CC's row shape.**
//! sqlite and postgres.
//!
//! CC's shape: a flag (or a `moderation:*` act) names the flagged row by
//! `references_attestation_id`; its `attested_key_id` is the moderator; the
//! flagged row's author is NOT in `subject_key_ids`. Placed at the room's
//! `community` scope, AV-84 has nothing to refuse (the row names only its
//! producer). This witnesses it:
//!
//! - the room's moderator's `content_class:{class}:v1` flag and `moderation:*`
//!   act, naming the author's placed row, are admitted;
//! - a non-member is refused either (AV-45);
//! - the flagged row stays as it was: the flag is not its composer.
//!
//! v61 S2 (CIRISPersist#1161) — AV-84's `named_subject` arm is replaced by
//! CC rc15's `subject_outside_audience`. **I1516** witnesses it with the
//! retraction classes: a row naming a member is admitted and one naming an
//! outsider refused; the named member withdraws a peer's row about them, but
//! not a `moderation:*` act or a cosigned act naming them.

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use crate::federation::composer_rank_invariants::bodies::{place, self_row};
    use crate::federation::membership_acceptance_invariants::bodies::{found_community, reg};
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{attestation_type, cohort_scope, identity_type};
    use crate::federation::{Attestation, Error, FederationDirectory, SignedAttestation};

    fn act(by: &str, dimension: &str, flagged: &Attestation, room: &str) -> Attestation {
        let env = serde_json::json!({
            "dimension": dimension,
            "score": crate::federation::namespace::registry::in_class_score(dimension),
            "confidence": 0.9,
            "community_id": room,
            "community_key_id": room,
            "references_attestation_id": flagged.attestation_id,
        });
        let mut r = ts::bare_attestation(&uuid::Uuid::new_v4().to_string(), by, by, &env);
        r.attestation_type = attestation_type::SCORES.into();
        r.weight = None;
        r.cohort_scope = cohort_scope::COMMUNITY.into();
        ts::seal_row_in_place(by, &mut r);
        r
    }

    async fn put(d: &dyn FederationDirectory, r: &Attestation) -> Result<(), Error> {
        d.put_attestation(SignedAttestation {
            attestation: r.clone(),
        })
        .await
        .map(|_| ())
    }

    /// **I1512** — CC's moderation shape at community scope.
    pub(crate) async fn i1512_room_moderation_in_ccs_shape(d: &dyn FederationDirectory, s: &str) {
        let k = |n: &str| format!("i1512-{n}-{s}");
        let (moderator, author, member, stranger, room) =
            (k("mod"), k("author"), k("member"), k("stranger"), k("room"));
        for u in [&moderator, &author, &member, &stranger] {
            ts::register_hybrid_key_as(d, u, u, identity_type::USER).await;
        }
        reg(d, &[&room]).await;
        // The moderator founds the room (a founder holds `moderate` zero-hop);
        // the author and a plain member are seated with it.
        found_community(d, &room, "quorum:1/1", &[&moderator, &author, &member], &[])
            .await
            .unwrap();
        let prior = self_row(d, &author).await;
        let flagged = place(d, &prior, &room).await;
        let before = d
            .get_attestation(&flagged.attestation_id)
            .await
            .unwrap()
            .unwrap();
        let flag = act(&moderator, "content_class:reported:v1", &flagged, &room);
        put(d, &flag).await.expect("I1512: the moderator's flag");
        let mod_act = act(&moderator, "moderation:rogue_vote:v1", &flagged, &room);
        put(d, &mod_act)
            .await
            .expect("I1512: the moderator's moderation act");
        for r in [&flag, &mod_act] {
            let held = d.get_attestation(&r.attestation_id).await.unwrap().unwrap();
            assert_eq!(
                held.attested_key_id, moderator,
                "I1512: attested = the moderator"
            );
            assert!(
                !held.subject_key_ids.contains(&author),
                "I1512: the author is not a subject"
            );
        }
        put(
            d,
            &act(&stranger, "content_class:reported:v1", &flagged, &room),
        )
        .await
        .expect_err("I1512: a non-member's flag");
        put(
            d,
            &act(&stranger, "moderation:rogue_vote:v1", &flagged, &room),
        )
        .await
        .expect_err("I1512: a non-member's moderation act");
        let after = d
            .get_attestation(&flagged.attestation_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            after.persist_row_hash, before.persist_row_hash,
            "I1512: the flagged row is untouched"
        );
        // (Under quorum:1/1 every member is the room's authority, so a
        // plain member holds `moderate` zero-hop; the duty gate's refusal of
        // a non-holder is the existing moderation witnesses'.)
        let _ = member;
    }

    /// A `scores` row by `by` at the room's `community` scope naming
    /// `subject`, optionally cosigned by `cosigner` (an actor's scrub over
    /// the same envelope, not a tier-crossing co-scrub).
    fn about(
        by: &str,
        dimension: &str,
        subject: &str,
        room: &str,
        cosigner: Option<&str>,
    ) -> Attestation {
        let env = serde_json::json!({
            "dimension": dimension,
            "score": crate::federation::namespace::registry::in_class_score(dimension),
            "confidence": 0.9,
            "community_id": room,
            "community_key_id": room,
        });
        let mut r = ts::bare_attestation(&uuid::Uuid::new_v4().to_string(), by, by, &env);
        r.attestation_type = attestation_type::SCORES.into();
        r.weight = None;
        r.cohort_scope = cohort_scope::COMMUNITY.into();
        r.subject_key_ids = vec![subject.to_owned()];
        ts::seal_row_in_place(by, &mut r);
        if let Some(c) = cosigner {
            let (_h, classical, pqc) = ts::sign_envelope(c, &r.attestation_envelope);
            r.additional_scrubs
                .push(crate::federation::types::ScrubSig {
                    scrub_key_id: c.to_owned(),
                    scrub_signature_classical: classical,
                    scrub_signature_pqc: pqc,
                    cosigned_at: None,
                });
        }
        r
    }

    /// `issuer`'s `withdraws` of `target`.
    fn withdraws(issuer: &str, target: &Attestation) -> Attestation {
        let env = serde_json::json!({
            "references_attestation_id": target.attestation_id,
            "withdrawal_reason": "I1516",
        });
        let mut w = ts::bare_attestation(&uuid::Uuid::new_v4().to_string(), issuer, issuer, &env);
        w.attestation_type = attestation_type::WITHDRAWS.into();
        w.weight = None;
        ts::seal_row_in_place(issuer, &mut w);
        w
    }

    /// **I1516** (v61 S2, CIRISPersist#1161; CC rc15 2.1 and the standing
    /// rules) — a row about a person reaches only an audience that person is
    /// in, and the person withdraws a peer's row about them except an adverse
    /// or cosigned act.
    ///
    /// - a member's `scores` row naming a member of the room is admitted; one
    ///   naming a registered key outside the room is refused
    ///   `subject_outside_audience`;
    /// - the named member withdraws the peer's row (rule 2);
    /// - the named member does NOT withdraw a `moderation:*` act naming them,
    ///   nor a cosigned act (`federation_withdraws_not_admitted`); the act's
    ///   own signer still does (rule 1).
    pub(crate) async fn i1516_subject_within_audience_and_retraction_classes(
        d: &dyn FederationDirectory,
        s: &str,
    ) {
        let k = |n: &str| format!("i1516-{n}-{s}");
        let (moderator, author, member, outsider, room) =
            (k("mod"), k("author"), k("member"), k("outsider"), k("room"));
        for u in [&moderator, &author, &member, &outsider] {
            ts::register_hybrid_key_as(d, u, u, identity_type::USER).await;
        }
        reg(d, &[&room]).await;
        found_community(d, &room, "quorum:1/1", &[&moderator, &author, &member], &[])
            .await
            .unwrap();
        const PLAIN: &str = "expertise:cardiology:en:v1";
        let peer_row = about(&member, PLAIN, &author, &room, None);
        put(d, &peer_row)
            .await
            .expect("I1516: a row naming a member of its room");
        let e = put(d, &about(&member, PLAIN, &outsider, &room, None))
            .await
            .expect_err("I1516: a row naming a key outside its room");
        assert!(
            matches!(
                &e,
                Error::CohortStandingRefused {
                    reason:
                        crate::federation::admission::CohortStandingRefusal::SubjectOutsideAudience,
                    ..
                }
            ),
            "I1516: subject_outside_audience: {e:?}"
        );
        put(d, &withdraws(&author, &peer_row))
            .await
            .expect("I1516: the named person withdraws a peer's row about them");
        let mod_act = about(&moderator, "moderation:rogue_vote:v1", &author, &room, None);
        put(d, &mod_act)
            .await
            .expect("I1516: the moderator's act naming the author");
        let e = put(d, &withdraws(&author, &mod_act))
            .await
            .expect_err("I1516: the named person does not withdraw a moderation act");
        assert_eq!(e.kind(), "federation_withdraws_not_admitted", "I1516: {e}");
        let cosigned = about(&member, PLAIN, &author, &room, Some(&moderator));
        put(d, &cosigned)
            .await
            .expect("I1516: a cosigned row naming a member");
        let e = put(d, &withdraws(&author, &cosigned))
            .await
            .expect_err("I1516: the named person does not withdraw a cosigned act");
        assert_eq!(e.kind(), "federation_withdraws_not_admitted", "I1516: {e}");
        put(d, &withdraws(&moderator, &mod_act))
            .await
            .expect("I1516: the act's signer withdraws it (rule 1)");
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod runners {
    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()[..12].to_owned()
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i1512_room_moderation_in_ccs_shape_sqlite() {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        super::bodies::i1512_room_moderation_in_ccs_shape(&b, &suffix()).await;
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i1516_subject_within_audience_and_retraction_classes_sqlite() {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        super::bodies::i1516_subject_within_audience_and_retraction_classes(&b, &suffix()).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i1516_subject_within_audience_and_retraction_classes_postgres() {
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        super::bodies::i1516_subject_within_audience_and_retraction_classes(&b, &suffix()).await;
        eprintln!("i1516 postgres: RAN");
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i1512_room_moderation_in_ccs_shape_postgres() {
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        super::bodies::i1512_room_moderation_in_ccs_shape(&b, &suffix()).await;
    }
}
