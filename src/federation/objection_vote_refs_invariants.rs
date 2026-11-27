//! v62.0.0 (KR-fix34a; CC 2.6.1.3, the Constitution's ruling (a)) —
//! **I4346–I4347**: an `objection:assent` / `objection:raised` vote names the
//! ROW it answers in `refs.answers`; on sqlite and postgres.
//!
//! - **I4346** — the door's interim shape check
//!   (`edition2::payloads::check_objection_vote_refs`, replaced by Verify's
//!   export at the 23.5.1 pin): a vote naming its object in `refs.target` is
//!   REFUSED `malformed:refs`; a `self` vote carrying the earlier member
//!   `objects_to_attestation_id`, and a vote carrying BOTH that member and
//!   `refs.answers`, are REFUSED `malformed:objects_to_attestation_id`;
//!   nothing is kept.
//! - **I4347** — through the real door, built by the builders: a cohort
//!   objection to an ATTESTATION (`reverse_quorum::objection_envelope`) lands
//!   with the action in `refs.answers` and no earlier member, and reads back
//!   through `reverse_quorum::objected_object`; a cohort objection to a
//!   ROSTER EVENT (`objection_envelope_roster_event`, INTERIM until
//!   KR-fix34b) lands in the earlier shape, naming the removal record's
//!   `persist_row_hash`, and reads back the same way.

#[cfg(any(feature = "postgres", feature = "sqlite"))]
mod exercises {
    use crate::federation::cohort::Cohort;
    use crate::federation::community_dek::lifecycle_support::{
        id_of, revoke_member, seed_community,
    };
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::edition2::ingest::{put_statement, INGEST_TIER};
    use crate::federation::edition2::names::RowId;
    use crate::federation::reverse_quorum::{
        objected_object, objection_envelope, objection_envelope_roster_event, DIMENSION_OBJECTION,
    };
    use crate::federation::self_roster::DIMENSION_ASSENT;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::attestation_type;
    use crate::federation::{BlobStorage, FederationDirectory};
    use ciris_verify_core::cde::Value;
    use ciris_verify_core::edition2::{row_ref, sign_row_statement};

    /// A deterministic map: entries sorted by their keys' encodings (the
    /// door fixtures' rule).
    fn map(mut m: Vec<(&str, Value)>) -> Value {
        use ciris_verify_core::cde;
        let t = |k: &str| Value::Text(k.to_owned());
        m.sort_by_key(|(k, _)| cde::encode(&t(k)));
        Value::Map(m.into_iter().map(|(k, v)| (t(k), v)).collect())
    }

    fn now_ms() -> u64 {
        u64::try_from(crate::host::clock::now().timestamp_millis()).expect("after 1970")
    }

    /// A vote statement by `seed` about `sub` with the given extra members.
    fn vote(seed: &str, sub: &str, dimension: &str, extra: Vec<(&str, Value)>) -> Vec<u8> {
        let iss = e2::kid(seed);
        let mut members = vec![
            ("asserted_at", Value::Uint(now_ms())),
            ("author", Value::Text(iss.clone())),
            ("dimension", Value::Text(dimension.to_owned())),
            ("score", Value::Uint(1_000_000)),
            ("confidence", Value::Uint(1_000_000)),
            ("cohort", Value::Text("self".to_owned())),
            ("cohort_key_id", Value::Text(sub.to_owned())),
            ("grounds", Value::Text(String::new())),
        ];
        members.extend(extra);
        sign_row_statement(
            &e2::signing_key(seed),
            &iss,
            sub,
            attestation_type::SCORES,
            &ciris_verify_core::namespace_match::family_id("objection:{state}"),
            &map(members),
            vec![],
        )
        .expect("sign a vote")
    }

    async fn refused_with(d: &dyn FederationDirectory, st: &[u8], label: &str, what: &str) {
        match put_statement(d, st, None, INGEST_TIER).await {
            Err(e) => assert!(
                e.to_string().contains(label),
                "{what}: refused {label}: {e}"
            ),
            Ok(o) => panic!("{what}: must be refused {label}: {o:?}"),
        }
        let id = RowId::of_statement(st).expect("a row id");
        assert!(
            d.get_attestation(&id.hex()).await.expect("reads").is_none(),
            "{what}: nothing is kept"
        );
    }

    /// I4346 — the refusals.
    pub async fn exercise_i4346<B>(b: &B, tag: &str)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let d = b as &dyn FederationDirectory;
        let run = uuid::Uuid::new_v4().simple().to_string();
        let (voter, me) = (format!("i4346-v-{run}"), format!("i4346-s-{run}"));
        e2::put_key(d, &voter, &["user"]).await;
        let sub = e2::put_key(d, &me, &["user"]).await;
        let object = [0x46u8; 32];
        refused_with(
            d,
            &vote(
                &voter,
                &sub,
                DIMENSION_ASSENT,
                vec![("refs", map(vec![("target", row_ref(&object))]))],
            ),
            "malformed:refs",
            &format!("{tag} I4346: an assent naming its object in refs.target"),
        )
        .await;
        refused_with(
            d,
            &vote(
                &voter,
                &sub,
                DIMENSION_OBJECTION,
                vec![(
                    "objects_to_attestation_id",
                    Value::Text(hex::encode(object)),
                )],
            ),
            "malformed:objects_to_attestation_id",
            &format!("{tag} I4346: a self objection carrying the earlier member"),
        )
        .await;
        refused_with(
            d,
            &vote(
                &voter,
                &sub,
                DIMENSION_OBJECTION,
                vec![
                    (
                        "objects_to_attestation_id",
                        Value::Text(hex::encode(object)),
                    ),
                    ("refs", map(vec![("answers", row_ref(&object))])),
                ],
            ),
            "malformed:objects_to_attestation_id",
            &format!("{tag} I4346: a vote carrying both"),
        )
        .await;
    }

    /// Seal `envelope` as a `scores` row by `seed` about `attested` and put it
    /// through the statement door; require it LANDED and return it.
    async fn land<B>(
        b: &B,
        seed: &str,
        attested: &str,
        envelope: serde_json::Value,
        what: &str,
    ) -> crate::federation::Attestation
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let d = b as &dyn FederationDirectory;
        let mut r =
            ts::bare_attestation(&uuid::Uuid::new_v4().to_string(), seed, attested, &envelope);
        r.attestation_type = attestation_type::SCORES.into();
        r.weight = None;
        r.cohort_scope = crate::federation::types::cohort_scope::FEDERATION.into();
        r.asserted_at = crate::host::clock::now();
        r.scrub_timestamp = r.asserted_at;
        r.expires_at = None;
        ts::seal_row_in_place(seed, &mut r);
        let out = e2::put_signed(d, &r).await;
        d.get_attestation(&e2::rid(&r))
            .await
            .expect("reads")
            .unwrap_or_else(|| panic!("{what}: NOT LANDED: {out:?}"))
    }

    /// I4347 — landings through the real door.
    pub async fn exercise_i4347<B>(b: &B, tag: &str)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let d = b as &dyn FederationDirectory;
        let run = uuid::Uuid::new_v4().simple().to_string();
        let comm = format!("{tag}-i4347-comm-{run}");
        let (alice, alice_occ) = (
            format!("{tag}-i4347-a-{run}"),
            format!("{tag}-i4347-ao-{run}"),
        );
        let (bob, bob_occ) = (
            format!("{tag}-i4347-b-{run}"),
            format!("{tag}-i4347-bo-{run}"),
        );
        seed_community(b, &comm, &[(&alice, &alice_occ), (&bob, &bob_occ)]).await;
        let comm = id_of(&comm);

        // An ATTESTATION object: an ordinary row of bob's; alice objects to it.
        let ordinary = crate::federation::genesis::ordinary_scores_row(
            &uuid::Uuid::new_v4().to_string(),
            &e2::kid(&bob),
        );
        let action = land(
            b,
            &bob,
            &e2::kid(&bob),
            ordinary.attestation_envelope.clone(),
            &format!("{tag} I4347: the action"),
        )
        .await;
        let objection = land(
            b,
            &alice,
            &action.attesting_key_id,
            objection_envelope(Cohort::Community, &comm, &action.attestation_id, "no"),
            &format!("{tag} I4347: an objection to an attestation"),
        )
        .await;
        let st = e2::carried_statement(&objection).expect("I4347: the statement");
        let (_, payload) =
            crate::federation::edition2::liveness::statement_parts(&st).expect("I4347: parts");
        let named = crate::federation::edition2::names::names_of(&payload).expect("names");
        assert_eq!(
            crate::federation::edition2::names::single(&named, "answers").map(|r| r.hex()),
            Some(action.attestation_id.clone()),
            "{tag} I4347: the action is named in refs.answers"
        );
        assert!(
            payload.get_text("objects_to_attestation_id").is_none(),
            "{tag} I4347: and the earlier member is not stated"
        );
        assert_eq!(
            objected_object(&objection),
            Some(action.attestation_id.as_str()),
            "{tag} I4347: the fold's reader finds it"
        );

        // A ROSTER EVENT object (INTERIM until KR-fix34b): bob's removal.
        let rev = revoke_member(b, &comm, &id_of(&bob)).await;
        let held = b
            .list_community_membership_revocations_for(&comm)
            .await
            .expect("I4347: the removals");
        let hash = held
            .iter()
            .find(|r| r.removed_identity_key_id == id_of(&bob))
            .map(|r| r.persist_row_hash.clone())
            .expect("I4347: bob's removal is held");
        let actor = rev.authority_key_id.clone();
        let interim = land(
            b,
            &alice,
            &actor,
            objection_envelope_roster_event(Cohort::Community, &comm, &hash, "no"),
            &format!("{tag} I4347: an objection to a roster event (interim shape)"),
        )
        .await;
        assert_eq!(
            objected_object(&interim),
            Some(hash.as_str()),
            "{tag} I4347: the fold's reader finds the roster event"
        );
    }
}

#[cfg(all(test, feature = "sqlite"))]
mod sqlite {
    use super::exercises::*;
    use crate::store::sqlite::SqliteBackend;
    use crate::store::Backend as _;

    async fn fresh() -> SqliteBackend {
        let b = SqliteBackend::open_in_memory().await.unwrap();
        b.run_migrations().await.unwrap();
        b
    }

    #[tokio::test]
    async fn i4346_the_objection_vote_refs_door_sqlite() {
        exercise_i4346(&fresh().await, "sqlite").await;
    }

    #[tokio::test]
    async fn i4347_objections_land_through_the_real_door_sqlite() {
        exercise_i4347(&fresh().await, "sqlite").await;
    }
}

#[cfg(all(test, feature = "postgres"))]
mod postgres {
    use super::exercises::*;
    use crate::store::postgres::PostgresBackend;
    use crate::store::Backend as _;

    async fn fresh() -> Option<PostgresBackend> {
        let dsn = crate::test_pg::empty_dsn()?;
        let b = PostgresBackend::connect(&dsn).await.unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    }

    #[tokio::test]
    async fn i4346_the_objection_vote_refs_door_postgres() {
        let Some(b) = fresh().await else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        exercise_i4346(&b, "postgres").await;
    }

    #[tokio::test]
    async fn i4347_objections_land_through_the_real_door_postgres() {
        let Some(b) = fresh().await else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        exercise_i4347(&b, "postgres").await;
    }
}
