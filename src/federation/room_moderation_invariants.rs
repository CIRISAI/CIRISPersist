//! v61 S2 (CIRISPersist#1161; CC 4.5.5, the shape CC gave 2026-11-01) —
//! **I1512: room moderation at community scope, in CC's row shape.**
//! sqlite and postgres.
//!
//! CC's shape: a flag (or a `moderation:*` act) names the flagged row by
//! `references_attestation_id`; its `attested_key_id` is the moderator; the
//! flagged row's author is NOT in `subject_key_ids`. Placed at the room's
//! `community` scope, AV-84 has nothing to refuse (the row names only its
//! producer), so the shape is admitted as v61 stands, without the pending
//! `subject_outside_audience` rule. This witnesses it:
//!
//! - the room's moderator's `content_class:{class}:v1` flag and `moderation:*`
//!   act, naming the author's placed row, are admitted;
//! - a non-member is refused either (AV-45);
//! - the flagged row stays as it was: the flag is not its composer.
//!
//! The AV-84 `named_subject` arm is untouched (held for the steward).

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
