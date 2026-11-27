//! v62.0.0 (ROOMKEY-1; CC 3.1.3.2 "A community declares how its roster is
//! seated") — **`membership`: stated, read, and written back where it
//! stands.**
//!
//! - **I7000** (pure) — the payload door: a community version carrying
//!   `membership` `private` or `public` is admitted, and absent reads public. A
//!   FAMILY version carrying it is refused `edition2_payload_invalid`, as a
//!   member outside a family's payload is ("A `self` room and a `family`
//!   carry no `membership`").
//! - **I7001** (pure) — the founding producer states the seating. A community
//!   founding that states none writes top-level `membership: "public"` and no
//!   `policy` (lead D1, the interim). A community founding a host gave a
//!   `membership` writes it top-level, never inside `policy`. A family
//!   founding writes none.
//! - **I7002** (pure) — a received record's `membership` round-trips BYTE FOR
//!   BYTE through the codec (`roster_view_of_statement` → `record_of_roster` →
//!   the payload writer): a private founding with and without other policy, a
//!   private LATER version, and a founding stating `public`. The record reads
//!   `Seating::Private` / `Public` (`seating_of`, `is_private_room`). A public
//!   room's record keeps its `policy_blob` as it had it (`None` stays `None`).
//! - **I7003** (sqlite + postgres, through the statement door) — a founding
//!   stating `public` lands and its held record reads public, its
//!   `policy_blob` untouched. A founding stating `private` lands and its held
//!   record reads `is_private_room`.

#[cfg(test)]
mod pure {
    use chrono::{TimeZone, Utc};
    use ciris_verify_core::cde::{self, Value};

    use super::super::door_invariants::fixture::*;
    use super::super::group::{
        founding_payload, is_private_room, record_of_roster, roster_payload,
        roster_view_of_statement, seating_of, GroupRecord, Seating, GROUP_ROSTER_PREFIX,
        MEMBERSHIP_MEMBER,
    };
    use super::super::names::RowId;
    use super::super::payloads::check;
    use crate::federation::types::{Community, CommunityMember, Family, FamilyMember};
    use crate::federation::{malformed_row, Error};

    fn at(ms: i64) -> chrono::DateTime<Utc> {
        Utc.timestamp_millis_opt(ms).single().unwrap()
    }

    fn community(policy_blob: Option<serde_json::Value>) -> Community {
        Community {
            community_key_id: String::new(),
            community_name: "seating".into(),
            members: vec![CommunityMember {
                key_id: iref(&key(71)),
                joined_at: at(3_000),
                role: Some("founder".into()),
            }],
            founded_at: at(3_000),
            consensus_protocol: "majority".into(),
            policy_blob,
            prev_head_digest: String::new(),
            charter_digest: String::new(),
            persist_row_hash: String::new(),
        }
    }

    fn family() -> Family {
        Family {
            family_key_id: String::new(),
            family_name: "seating family".into(),
            members: vec![FamilyMember {
                key_id: iref(&key(72)),
                joined_at: at(3_000),
                role: Some("founder".into()),
            }],
            founded_at: at(3_000),
            consensus_protocol: "majority".into(),
            consensus_protocol_entrenched: false,
            dissolved_at: None,
            prev_head_digest: String::new(),
            charter_digest: String::new(),
            persist_row_hash: String::new(),
        }
    }

    fn sign(sub: &str, p: &Value) -> Vec<u8> {
        let k = key(71);
        ciris_verify_core::edition2::sign_row_statement(
            &k,
            &iref(&k),
            sub,
            "scores",
            &ciris_verify_core::namespace_match::family_id(GROUP_ROSTER_PREFIX),
            p,
            vec![],
        )
        .unwrap()
    }

    fn reason(e: &Error) -> &'static str {
        match e {
            Error::MalformedRow { reason, .. } => reason,
            other => other.kind(),
        }
    }

    fn with(p: &Value, member: &str, v: Option<Value>) -> Value {
        let Value::Map(m) = p else { unreachable!() };
        let mut m: Vec<(Value, Value)> = m
            .iter()
            .filter(|(k, _)| k.as_text() != Some(member))
            .cloned()
            .collect();
        if let Some(v) = v {
            m.push((Value::Text(member.into()), v));
        }
        m.sort_by_key(|(k, _)| cde::encode(k));
        Value::Map(m)
    }

    /// I7000 — the payload door on `membership`, community and family.
    #[test]
    fn i7000_membership_is_a_community_member_never_a_familys() {
        let mut c = GroupRecord::Community(community(None));
        let (_, founding) = founding_payload(&mut c, &[0x70; 32], 9_000).unwrap();
        for v in ["private", "public"] {
            let p = with(&founding, MEMBERSHIP_MEMBER, Some(Value::Text(v.into())));
            check("group:roster", &p)
                .unwrap_or_else(|e| panic!("I7000 a community states {v}: refused {e}"));
        }
        check("group:roster", &with(&founding, MEMBERSHIP_MEMBER, None))
            .expect("I7000 a community stating none (reads public) is admitted");

        let mut f = GroupRecord::Family(family());
        let (_, fam) = founding_payload(&mut f, &[0x71; 32], 9_000).unwrap();
        check("group:roster", &fam).expect("I7000 premise: the family founding is admitted");
        for v in ["private", "public"] {
            let p = with(&fam, MEMBERSHIP_MEMBER, Some(Value::Text(v.into())));
            let e = check("group:roster", &p).expect_err("I7000 a family carries no membership");
            assert_eq!(
                reason(&e),
                malformed_row::EDITION2_PAYLOAD_INVALID,
                "I7000 refused as an unlisted member is: {e}"
            );
        }
    }

    /// I7001 — the founding producer states the seating, top-level.
    #[test]
    fn i7001_the_founding_states_its_seating_top_level() {
        // None given: explicit public, and no `policy`.
        let mut c = GroupRecord::Community(community(None));
        let (_, p) = founding_payload(&mut c, &[0x72; 32], 9_000).unwrap();
        assert_eq!(
            p.get_text(MEMBERSHIP_MEMBER).and_then(Value::as_text),
            Some("public"),
            "I7001 a founding stating none states public"
        );
        assert!(
            p.get_text("policy").is_none(),
            "I7001 explicit public adds no policy"
        );

        // A host's choice, beside other policy: top-level, never in `policy`.
        let mut c = GroupRecord::Community(community(Some(
            serde_json::json!({"membership": "private", "max": 3}),
        )));
        let (_, p) = founding_payload(&mut c, &[0x73; 32], 9_000).unwrap();
        assert_eq!(
            p.get_text(MEMBERSHIP_MEMBER).and_then(Value::as_text),
            Some("private"),
            "I7001 the host's seating is the top-level member"
        );
        let policy = p.get_text("policy").expect("I7001 the other policy stays");
        assert!(
            policy.get_text(MEMBERSHIP_MEMBER).is_none(),
            "I7001 `membership` is never a member of `policy`"
        );
        assert_eq!(
            policy.get_text("max").and_then(Value::as_u64),
            Some(3),
            "I7001 the rest of the policy is kept"
        );

        // A family: none.
        let mut f = GroupRecord::Family(family());
        let (_, p) = founding_payload(&mut f, &[0x74; 32], 9_000).unwrap();
        assert!(
            p.get_text(MEMBERSHIP_MEMBER).is_none(),
            "I7001 a family founding states no membership"
        );
    }

    /// The payload a held statement's record writes back as: the founding
    /// writer for version 1 (with `nonce`), the version writer otherwise.
    fn written_back(st: &[u8], nonce: &[u8; 32], asserted: u64) -> (GroupRecord, Value) {
        let view = roster_view_of_statement(st).unwrap();
        let mut back = record_of_roster(&view, String::new()).unwrap();
        let p = if view.version == 1 {
            founding_payload(&mut back, nonce, asserted).unwrap().1
        } else {
            roster_payload(&back, view.version, view.head.as_ref(), asserted).unwrap()
        };
        (back, p)
    }

    fn community_of(r: &GroupRecord) -> &Community {
        match r {
            GroupRecord::Community(c) => c,
            GroupRecord::Family(_) => panic!("a community"),
        }
    }

    /// I7002 — `membership` round-trips byte for byte; the record reads it.
    #[test]
    fn i7002_a_received_membership_round_trips_byte_for_byte() {
        let asserted = 9_000;
        for (blob, nonce, seating) in [
            (
                Some(serde_json::json!({"membership": "private"})),
                [0x75; 32],
                Seating::Private,
            ),
            (
                Some(serde_json::json!({"membership": "private", "max": 3})),
                [0x76; 32],
                Seating::Private,
            ),
            (None, [0x77; 32], Seating::Public),
            (
                Some(serde_json::json!({"max": 4})),
                [0x78; 32],
                Seating::Public,
            ),
        ] {
            let mut rec = GroupRecord::Community(community(blob.clone()));
            let (id, p) = founding_payload(&mut rec, &nonce, asserted).unwrap();
            let st = sign(&id, &p);
            let (back, again) = written_back(&st, &nonce, asserted);
            assert_eq!(
                cde::encode(&again),
                cde::encode(&p),
                "I7002 the founding writes back byte for byte ({blob:?})"
            );
            assert_eq!(
                seating_of(community_of(&back)),
                seating,
                "I7002 seating ({blob:?})"
            );
            assert_eq!(
                is_private_room(community_of(&back)),
                seating == Seating::Private,
                "I7002 is_private_room ({blob:?})"
            );
            if seating == Seating::Public {
                assert_eq!(
                    community_of(&back).policy_blob,
                    blob,
                    "I7002 a public room's record keeps its policy blob as it had it"
                );
            }
        }

        // A private LATER version.
        let head = RowId([0x79; 32]);
        let mut rec = GroupRecord::Community(community(Some(
            serde_json::json!({"membership": "private", "max": 5}),
        )));
        let (id, _) = founding_payload(&mut rec, &[0x7a; 32], asserted).unwrap();
        let p = roster_payload(&rec, 2, Some(&head), asserted).unwrap();
        assert_eq!(
            p.get_text(MEMBERSHIP_MEMBER).and_then(Value::as_text),
            Some("private"),
            "I7002 premise: a later version states its seating top-level"
        );
        let st = sign(&id, &p);
        let (back, again) = written_back(&st, &[0x7a; 32], asserted);
        assert_eq!(
            cde::encode(&again),
            cde::encode(&p),
            "I7002 a private later version writes back byte for byte"
        );
        assert!(
            is_private_room(community_of(&back)),
            "I7002 the later version reads private"
        );
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::edition2::group::{
        founding_payload, is_private_room, seating_of, GroupRecord, Seating, GROUP_ROSTER_PREFIX,
    };
    use crate::federation::edition2::ingest::StatementOutcome;
    use crate::federation::types::{identity_type, Community, CommunityMember};
    use crate::federation::FederationDirectory;

    /// The fixture base: an input of the derived id, never the clock.
    fn founded() -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::<chrono::Utc>::from_timestamp_millis(
            i64::try_from(e2::fixture_founding_base_ms()).expect("ms"),
        )
        .expect("an instant")
    }

    /// An hour ago, whole milliseconds: the founding ROW's `asserted_at`.
    fn instant() -> chrono::DateTime<chrono::Utc> {
        let ms = (chrono::Utc::now() - chrono::Duration::hours(1)).timestamp_millis();
        chrono::DateTime::<chrono::Utc>::from_timestamp_millis(ms).expect("an instant")
    }

    fn founding(
        founder: &str,
        name: &str,
        blob: Option<serde_json::Value>,
        nonce: [u8; 32],
    ) -> (String, Vec<u8>) {
        let at = founded();
        let mut record = GroupRecord::Community(Community {
            prev_head_digest: String::new(),
            charter_digest: String::new(),
            community_key_id: String::new(),
            community_name: name.to_owned(),
            members: vec![CommunityMember {
                key_id: e2::kid(founder),
                joined_at: at,
                role: Some(crate::federation::admission::MEMBER_ROLE_FOUNDER.into()),
            }],
            founded_at: at,
            consensus_protocol: "majority".into(),
            policy_blob: blob,
            persist_row_hash: String::new(),
        });
        let (id, payload) =
            founding_payload(&mut record, &nonce, e2::ms(instant())).expect("the founding payload");
        let st = ciris_verify_core::edition2::sign_row_statement(
            &e2::signing_key(founder),
            &e2::kid(founder),
            &id,
            "scores",
            &ciris_verify_core::namespace_match::family_id(GROUP_ROSTER_PREFIX),
            &payload,
            vec![],
        )
        .expect("sign the founding");
        (id, st)
    }

    /// **I7003** — a founding's seating, held, on one store.
    pub(crate) async fn i7003_a_held_founding_reads_its_seating(
        d: &dyn FederationDirectory,
        s: &str,
    ) {
        let founder = format!("i7003-founder-{s}");
        e2::put_key(d, &founder, &[identity_type::USER]).await;

        let (public_id, public) = founding(&founder, "public room", None, [0x7b; 32]);
        assert!(
            matches!(
                e2::put_statement(d, &public)
                    .await
                    .expect("I7003 public: not refused"),
                StatementOutcome::Row { .. }
            ),
            "I7003 a founding stating public lands"
        );
        let held = d
            .lookup_community(&public_id)
            .await
            .unwrap()
            .expect("I7003 the public room is held");
        assert_eq!(seating_of(&held), Seating::Public, "I7003 it reads public");
        assert_eq!(
            held.policy_blob, None,
            "I7003 explicit public leaves the held policy blob as the record had it"
        );

        let (private_id, private) = founding(
            &founder,
            "private room",
            Some(serde_json::json!({"membership": "private"})),
            [0x7c; 32],
        );
        assert!(
            matches!(
                e2::put_statement(d, &private)
                    .await
                    .expect("I7003 private: not refused"),
                StatementOutcome::Row { .. }
            ),
            "I7003 a founding stating private lands"
        );
        let held = d
            .lookup_community(&private_id)
            .await
            .unwrap()
            .expect("I7003 the private room is held");
        assert!(
            is_private_room(&held),
            "I7003 the held record reads private"
        );
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod runners {
    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()[..12].to_owned()
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i7003_a_held_founding_reads_its_seating_sqlite() {
        use crate::store::Backend as _;
        let d = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        d.run_migrations().await.unwrap();
        Box::pin(super::bodies::i7003_a_held_founding_reads_its_seating(
            &d,
            &suffix(),
        ))
        .await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i7003_a_held_founding_reads_its_seating_postgres() {
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        let d = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        d.run_migrations().await.unwrap();
        Box::pin(super::bodies::i7003_a_held_founding_reads_its_seating(
            &d,
            &suffix(),
        ))
        .await;
        eprintln!("i7003 postgres: RAN");
    }
}
