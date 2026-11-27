//! v62.0.0 (RESIGN-1..4; CC 3.1.3.2, the Constitution's ruling "the LEAF
//! decides") — **a member's own leaving is the `membership:resignation`
//! leaf.**
//!
//! - **I6800** (pure) — the persisted leaf moves no removal's bytes: a
//!   removal's `persist_row_hash` and `signing_envelope()` equal those of
//!   the same record as JSON with no `leaf` member (the form before the
//!   column existed), for a family and a community revocation. A
//!   resignation's carry `"leaf": "resignation"` and its hash differs from
//!   the removal's by that member alone.
//! - **I6801** (pure) — the payload table maps the `resignation` leaf: the
//!   AUTHORED row (`author` = the member) with `removed_at` and `refs.head`
//!   checks, and may carry `refs.trusted_through`; one missing `refs.head`
//!   or `removed_at` is refused. A revocation record whose leaf is the
//!   member's own drafts as `membership:resignation:v1`; `resignation_draft`
//!   refuses a signer who is not the member, and `removal_draft` refuses a
//!   resignation record.
//! - **I6802** (sqlite + postgres) — a member's own resignation, its ONE
//!   voice, LANDS through the statement door in a 3-member `majority` room
//!   and a family: the member is out of the active roster, and the stored
//!   revocation reads back with leaf `resignation`.
//! - **I6803** (sqlite + postgres) — a resignation of a member authored and
//!   signed by ANOTHER member is refused `resignation_not_by_member`: no voice
//!   kept, the member still seated.
//! - **I6804** (sqlite + postgres) — a resignation by a key that holds no
//!   seat in the room is HELD `resignation_not_a_member_at_head`, concluding
//!   nothing.
//! - **I6805** (sqlite + postgres; RESIGN-3) — THE LEAF DECIDES: in a
//!   3-member `majority` room, a `membership:removal` of `c` voiced by `c`
//!   alone is a counted row short of its count, HELD `count_short`, and `c`
//!   stays seated; `c`'s own resignation lands.
//! - **I6806** (pure; RESIGN-3) — the roster fold reads the end's kind from
//!   its persisted leaf: under `unanimous` a stored revocation of `b` signed
//!   by `b` alone ends `b`'s seat only when its leaf is `resignation`; the
//!   same row under the `removal` leaf has no standing and `b` stays.
//! - **I6807** (sqlite + postgres; RESIGN-3) — an end is one end: a counted
//!   removal of `c` at the instant `c` resigned settles on the stored row (the
//!   three-part key), which keeps the `resignation` leaf; `c` stays out.
//! - **I6808** (sqlite + postgres; RESIGN-4, on kernel 0.2.2; CC 2.7.5) —
//!   a removal voiced by its subject alone is a COUNT, never a resignation:
//!   in a `quorum:1/3` room `c`'s own removal voice meets the count and
//!   LANDS AS A REMOVAL (stored leaf `removal`); in a `quorum:2/3` room the
//!   same voice is short and HELD `count_short`. The member's resignation
//!   lands in both (stored leaf `resignation`).

#[cfg(test)]
mod pure {
    use crate::federation::edition2::group::{
        membership_payload, removal_draft, resignation_draft, MembershipRecord,
    };
    use crate::federation::edition2::names::RowId;
    use crate::federation::edition2::payloads::check;
    use crate::federation::types::{
        compute_persist_row_hash, CommunityMembershipRevocation, FamilyMembershipRevocation,
        RevocationLeaf,
    };
    use chrono::{DateTime, Utc};
    use ciris_verify_core::cde::Value;

    fn at(ms: i64) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp_millis(ms).expect("I6800: instant")
    }

    fn family(leaf: RevocationLeaf) -> FamilyMembershipRevocation {
        FamilyMembershipRevocation {
            family_key_id: "fam-i6800".to_owned(),
            removed_identity_key_id: "member-i6800".to_owned(),
            removed_at: at(1_700_000_000_000),
            effective_at: at(1_700_000_000_500),
            reason: Some("7".to_owned()),
            witness_set: vec!["w-i6800".to_owned()],
            persist_row_hash: String::new(),
            leaf,
        }
    }

    fn community(leaf: RevocationLeaf) -> CommunityMembershipRevocation {
        CommunityMembershipRevocation {
            community_key_id: "room-i6800".to_owned(),
            removed_identity_key_id: "member-i6800".to_owned(),
            removed_at: at(1_700_000_000_000),
            effective_at: at(1_700_000_000_500),
            reason: None,
            witness_set: Vec::new(),
            persist_row_hash: String::new(),
            leaf,
        }
    }

    /// The record as JSON with no `leaf` member: the form the hash and the
    /// signing envelope were computed over before the column existed. Built
    /// from the same serialization with the member REMOVED, so a removal
    /// that serialized `"leaf": "removal"` would differ from it.
    fn without_leaf<T: serde::Serialize>(r: &T) -> serde_json::Value {
        let mut v = serde_json::to_value(r).expect("I6800: serialize");
        v.as_object_mut().expect("I6800: an object").remove("leaf");
        v
    }

    #[test]
    fn i6800_a_removals_bytes_do_not_move_and_a_resignation_names_its_leaf() {
        // Family.
        let removal = family(RevocationLeaf::Removal);
        let v = serde_json::to_value(&removal).unwrap();
        assert!(
            v.get("leaf").is_none(),
            "I6800: a removal serializes no `leaf` member"
        );
        assert_eq!(
            compute_persist_row_hash(&removal).unwrap(),
            compute_persist_row_hash(&without_leaf(&removal)).unwrap(),
            "I6800: a family removal's persist_row_hash is the pre-column one"
        );
        assert!(
            removal.signing_envelope().get("leaf").is_none(),
            "I6800: a family removal's signing envelope is the pre-column one"
        );
        let resignation = family(RevocationLeaf::Resignation);
        let rv = serde_json::to_value(&resignation).unwrap();
        assert_eq!(
            rv.get("leaf").and_then(serde_json::Value::as_str),
            Some("resignation"),
            "I6800: a resignation names its leaf"
        );
        assert_ne!(
            compute_persist_row_hash(&resignation).unwrap(),
            compute_persist_row_hash(&removal).unwrap(),
            "I6800: a resignation and a removal of the same seat are two objects"
        );
        assert_eq!(
            without_leaf(&resignation),
            without_leaf(&removal),
            "I6800: they differ by the leaf alone"
        );
        let back: FamilyMembershipRevocation = serde_json::from_value(rv).unwrap();
        assert_eq!(back.leaf, RevocationLeaf::Resignation, "I6800: round trip");
        let old: FamilyMembershipRevocation = serde_json::from_value(v).unwrap();
        assert_eq!(
            old.leaf,
            RevocationLeaf::Removal,
            "I6800: an object with no `leaf` reads as a removal"
        );
        // Community.
        let removal = community(RevocationLeaf::Removal);
        assert_eq!(
            compute_persist_row_hash(&removal).unwrap(),
            compute_persist_row_hash(&without_leaf(&removal)).unwrap(),
            "I6800: a community removal's persist_row_hash is the pre-column one"
        );
        assert!(removal.signing_envelope().get("leaf").is_none());
        let resignation = community(RevocationLeaf::Resignation);
        assert_eq!(
            resignation
                .signing_envelope()
                .get("leaf")
                .and_then(serde_json::Value::as_str),
            Some("resignation"),
            "I6800: a community resignation's envelope names its leaf"
        );
        assert_ne!(
            compute_persist_row_hash(&resignation).unwrap(),
            compute_persist_row_hash(&removal).unwrap()
        );
        // The closed set, both ways.
        for l in [RevocationLeaf::Removal, RevocationLeaf::Resignation] {
            assert_eq!(RevocationLeaf::parse(l.as_str()), Some(l));
        }
        assert_eq!(RevocationLeaf::parse("keeps"), None, "I6800: closed set");
    }

    fn dimension(v: &Value) -> Option<&str> {
        v.get_text("dimension").and_then(Value::as_text)
    }

    #[test]
    fn i6801_the_table_maps_the_resignation_leaf() {
        let member = ciris_verify_core::edition2::identity_ref(&[7u8; 32]);
        let other = ciris_verify_core::edition2::identity_ref(&[8u8; 32]);
        let mut rec = community(RevocationLeaf::Resignation);
        rec.removed_identity_key_id = member.clone();
        rec.community_key_id = crate::federation::edition2::group_id::derive_group_id(
            "community",
            &[member.as_str()],
            1_700_000_000_000,
            &[9u8; 32],
        );
        let record = MembershipRecord::CommunityRemoval(rec.clone());
        let head = RowId([1u8; 32]);
        let fam = ciris_verify_core::namespace_match::family_id("membership:{stage}");
        // The leaf the record persists names the stage, and the row is AUTHORED.
        let p = membership_payload(&record, Some(&head)).expect("I6801: payload");
        assert_eq!(dimension(&p), Some("membership:resignation:v1"), "I6801");
        assert_eq!(
            p.get_text("author").and_then(Value::as_text),
            Some(member.as_str()),
            "I6801: a resignation is authored by the leaving member"
        );
        check(&fam, &p).expect("I6801: the table admits a resignation");
        // A removal record of the same seat is the counted removal: no author.
        let removal = MembershipRecord::CommunityRemoval(community(RevocationLeaf::Removal));
        let rp = membership_payload(&removal, Some(&head)).unwrap();
        assert_eq!(dimension(&rp), Some("membership:removal:v1"));
        assert!(
            rp.get_text("author").is_none(),
            "I6801: a removal is counted"
        );
        // The tips ride `refs.trusted_through`, sorted, never required.
        let draft = resignation_draft(
            &MembershipRecord::CommunityRemoval(community(RevocationLeaf::Removal)),
            &head,
            &[RowId([3u8; 32]), RowId([2u8; 32]), RowId([3u8; 32])],
            "member-i6800",
        );
        assert!(
            draft.is_err(),
            "I6801: `member-i6800` is no identity-ref: refused before any signing"
        );
        let mut rec2 = rec.clone();
        rec2.leaf = RevocationLeaf::Removal;
        let d = resignation_draft(
            &MembershipRecord::CommunityRemoval(rec2),
            &head,
            &[RowId([3u8; 32]), RowId([2u8; 32]), RowId([3u8; 32])],
            &member,
        )
        .expect("I6801: the member's own resignation drafts");
        let dp = ciris_verify_core::cde::decode(&d.payload).expect("I6801: the draft's payload");
        assert_eq!(dimension(&dp), Some("membership:resignation:v1"));
        let names = crate::federation::edition2::names::names_of(&dp).expect("I6801: refs");
        let tips: Vec<RowId> = names
            .iter()
            .filter(|n| n.role == "trusted_through")
            .map(|n| n.row)
            .collect();
        assert_eq!(
            tips,
            vec![RowId([2u8; 32]), RowId([3u8; 32])],
            "I6801: the tips, a sorted set with no duplicate"
        );
        check(&fam, &dp).expect("I6801: a resignation naming its tips checks");
        let refused = resignation_draft(&record, &head, &[], &other)
            .expect_err("I6801: another's resignation of the member");
        assert!(
            refused
                .to_string()
                .contains(crate::federation::malformed_row::RESIGNATION_NOT_BY_MEMBER),
            "I6801: named: {refused}"
        );
        assert!(
            removal_draft(&record, &head, &member).is_err(),
            "I6801: a resignation record is no removal voice"
        );
        // Missing refs.head, missing removed_at: refused by the table.
        let no_head = membership_payload(&record, None).unwrap();
        assert!(
            check(&fam, &no_head).is_err(),
            "I6801: refs.head is required"
        );
        let Value::Map(mut m) = p.clone() else {
            panic!("I6801: a map")
        };
        m.retain(|(k, _)| k.as_text() != Some("removed_at"));
        assert!(
            check(&fam, &Value::Map(m)).is_err(),
            "I6801: a resignation states removed_at"
        );
    }
}

/// I6806 — the fold reads the end's kind from the leaf, not the voices.
#[cfg(test)]
mod fold_by_leaf {
    use crate::federation::types::{consensus_protocol, CommunityMember};
    use crate::federation::{authorized_roster_at, RosterEvent, RosterRules};

    fn at(s: &str) -> chrono::DateTime<chrono::Utc> {
        s.parse().expect("rfc3339")
    }

    #[test]
    fn i6806_the_fold_reads_the_leaf() {
        let t0 = at("2026-01-01T00:00:00Z");
        let t1 = at("2026-03-01T00:00:00Z");
        let member = |k: &str, role: Option<&str>| CommunityMember {
            key_id: k.into(),
            joined_at: t0,
            role: role.map(str::to_owned),
        };
        let record = vec![
            member("a", Some("founder")),
            member("b", None),
            member("c", None),
        ];
        let rules = RosterRules {
            protocol: consensus_protocol::UNANIMOUS,
            subkind: None,
            policy_blob: None,
            node_bearing: &crate::federation::NO_NODE_BEARING_SEATS,
            persons: &crate::federation::key_person::NO_KEY_SELVES,
        };
        let end = |is_resignation: bool| RosterEvent {
            effective_at: t1,
            is_add: false,
            member: CommunityMember {
                key_id: "b".into(),
                joined_at: t1,
                role: None,
            },
            signers: ["b".to_owned()].into_iter().collect(),
            moderator_roots: Default::default(),
            reversed: false,
            is_resignation,
        };
        let keys = |r: Vec<CommunityMember>| -> Vec<String> {
            let mut v: Vec<String> = r.into_iter().map(|m| m.key_id).collect();
            v.sort();
            v
        };
        assert_eq!(
            keys(authorized_roster_at(&record, rules, &[end(true)], t1)),
            vec!["a".to_owned(), "c".to_owned()],
            "I6806: b's resignation ends b's seat on b's voice alone"
        );
        assert_eq!(
            keys(authorized_roster_at(&record, rules, &[end(false)], t1)),
            vec!["a".to_owned(), "b".to_owned(), "c".to_owned()],
            "I6806: a removal b alone voiced is a count unmet: b stays"
        );
    }
}

/// The backend witnesses (I6802–I6807), sqlite and postgres.
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::edition2::group::{membership_payload, MembershipRecord};
    use crate::federation::edition2::ingest::StatementOutcome;
    use crate::federation::membership_acceptance_invariants::bodies::{
        found_community, found_family, id_of, reg,
    };
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{
        CommunityMembershipRevocation, FamilyMembershipRevocation, RevocationLeaf,
    };
    use crate::federation::{malformed_row, Error, FederationDirectory};
    use chrono::{DateTime, Duration, Utc};
    use ciris_verify_core::cde::Value;

    pub(crate) fn ms(t: DateTime<Utc>) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp_millis(t.timestamp_millis()).expect("ms instant")
    }

    pub(crate) async fn active(d: &dyn FederationDirectory, cid: &str, k: &str) -> bool {
        d.active_community_members(cid)
            .await
            .unwrap()
            .iter()
            .any(|m| m.key_id == k)
    }

    pub(crate) async fn family_active(d: &dyn FederationDirectory, fid: &str, k: &str) -> bool {
        d.active_family_members(fid)
            .await
            .unwrap()
            .iter()
            .any(|m| m.key_id == k)
    }

    /// The revocation of `member` from room `cid`, by the leaf `leaf`.
    pub(crate) fn room_end(
        cid: &str,
        member: &str,
        at: DateTime<Utc>,
        leaf: RevocationLeaf,
    ) -> CommunityMembershipRevocation {
        CommunityMembershipRevocation {
            community_key_id: cid.to_owned(),
            removed_identity_key_id: member.to_owned(),
            removed_at: ms(at),
            effective_at: ms(at),
            reason: None,
            witness_set: Vec::new(),
            persist_row_hash: String::new(),
            leaf,
        }
    }

    /// The voices of an end of `member`'s seat in room `cid`, signed by
    /// `signers` (the first the primary), over the room's held head. Its
    /// leaf decides the row: a resignation is the member's own authored
    /// `membership:resignation:v1`, a removal the counted one.
    pub(crate) async fn room_end_voices(
        d: &dyn FederationDirectory,
        cid: &str,
        member: &str,
        signers: &[&str],
        at: DateTime<Utc>,
        leaf: RevocationLeaf,
    ) -> Vec<Vec<u8>> {
        let mut r =
            ts::sign_community_membership_revocation(signers[0], room_end(cid, member, at, leaf));
        for c in &signers[1..] {
            ts::cosign_community_membership_revocation(&mut r, c);
        }
        let head = e2::held_head(d, &e2::kid(cid)).await.map(|(h, _)| h);
        e2::community_revocation_voices(&r, head.as_ref())
    }

    fn reason(e: &Error) -> String {
        match e {
            Error::MalformedRow { reason, .. } => (*reason).to_owned(),
            other => format!("{other:?}"),
        }
    }

    /// Three founders `a`, `b`, `c` of a `majority` room (and a family),
    /// their identity-refs, and the room's derived id.
    pub(crate) async fn room_of_three(
        d: &dyn FederationDirectory,
        tag: &str,
        protocol: &str,
    ) -> (String, String, String, String) {
        let k = |n: &str| format!("{tag}-{n}");
        let (a, b, c, room) = (k("a"), k("b"), k("c"), k("room"));
        reg(d, &[&a, &b, &c, &room]).await;
        let (a, b, c, room) = (id_of(&a), id_of(&b), id_of(&c), id_of(&room));
        let room = found_community(d, &room, protocol, &[&a, &b, &c], &[])
            .await
            .unwrap_or_else(|e| panic!("{tag}: the room is founded: {e}"));
        (room, a, b, c)
    }

    /// **I6802** — a member's own resignation lands on its one voice.
    pub(crate) async fn i6802_a_resignation_lands_on_the_members_own_voice(
        d: &dyn FederationDirectory,
        s: &str,
    ) {
        let (room, _a, _b, c) = room_of_three(d, &format!("i6802-{s}"), "majority").await;
        assert!(active(d, &room, &c).await, "I6802: c is seated");
        let at = Utc::now() - Duration::hours(1);
        let voices = room_end_voices(d, &room, &c, &[&c], at, RevocationLeaf::Resignation).await;
        assert_eq!(voices.len(), 1, "I6802: one voice, the member's");
        match e2::put_voices(d, &voices).await {
            Ok(StatementOutcome::Row { .. }) => {}
            other => panic!("I6802: c's own resignation lands, got {other:?}"),
        }
        assert!(!active(d, &room, &c).await, "I6802: c has left the room");
        let stored = d
            .list_community_membership_revocations_for(&room)
            .await
            .unwrap();
        let end = stored
            .iter()
            .find(|r| r.removed_identity_key_id == c)
            .expect("I6802: the typed revocation is stored");
        assert_eq!(
            end.leaf,
            RevocationLeaf::Resignation,
            "I6802: the stored end names its leaf"
        );
        // A family: the same leaf, the same end.
        let k = |n: &str| format!("i6802f-{s}-{n}");
        let (fa, fb, fam) = (k("a"), k("b"), k("fam"));
        reg(d, &[&fa, &fb, &fam]).await;
        let (fa, fb, fam) = (id_of(&fa), id_of(&fb), id_of(&fam));
        let fam = found_family(d, &fam, "majority", &[&fa, &fb], &[])
            .await
            .unwrap_or_else(|e| panic!("I6802: the family is founded: {e}"));
        assert!(family_active(d, &fam, &fb).await, "I6802: fb is seated");
        let r = ts::sign_family_membership_revocation(
            &fb,
            FamilyMembershipRevocation {
                family_key_id: fam.clone(),
                removed_identity_key_id: fb.clone(),
                removed_at: ms(at),
                effective_at: ms(at),
                reason: None,
                witness_set: Vec::new(),
                persist_row_hash: String::new(),
                leaf: RevocationLeaf::Resignation,
            },
        );
        let head = e2::held_head(d, &e2::kid(&fam)).await.map(|(h, _)| h);
        match e2::put_voices(d, &e2::family_revocation_voices(&r, head.as_ref())).await {
            Ok(StatementOutcome::Row { .. }) => {}
            other => panic!("I6802: fb's own resignation lands, got {other:?}"),
        }
        assert!(!family_active(d, &fam, &fb).await, "I6802: fb left");
        let stored = d
            .list_family_membership_revocations_for(&fam)
            .await
            .unwrap();
        assert!(
            stored
                .iter()
                .any(|r| r.removed_identity_key_id == fb && r.leaf == RevocationLeaf::Resignation),
            "I6802: the family's stored end names its leaf"
        );
    }

    /// **I6803** — another member's "resignation" of `c` is refused by name.
    pub(crate) async fn i6803_a_resignation_by_another_is_refused(
        d: &dyn FederationDirectory,
        s: &str,
    ) {
        let (room, a, _b, c) = room_of_three(d, &format!("i6803-{s}"), "majority").await;
        let at = Utc::now() - Duration::hours(1);
        let head = e2::held_head(d, &e2::kid(&room))
            .await
            .map(|(h, _)| h)
            .expect("I6803: the room's head");
        // Authored by `a` (so the statement itself is valid: `author` = its
        // `iss`), about `c`.
        let record = MembershipRecord::CommunityRemoval(room_end(
            &room,
            &c,
            at,
            RevocationLeaf::Resignation,
        ));
        let p = membership_payload(&record, Some(&head)).unwrap();
        let p = crate::federation::edition2::emit::with_member(p, "author", Value::Text(a.clone()))
            .unwrap();
        let voice = crate::federation::edition2::group_fixtures::sign_group_payload(
            &e2::signing_key(&a),
            &c,
            crate::federation::edition2::group::MEMBERSHIP_PREFIX,
            &p,
        );
        let row = crate::federation::edition2::group_fixtures::row_id_of(&voice);
        let err = e2::put_voices(d, &[voice])
            .await
            .expect_err("I6803: a resignation of c by a");
        assert_eq!(
            reason(&err),
            malformed_row::RESIGNATION_NOT_BY_MEMBER,
            "I6803: named"
        );
        assert!(
            d.edition2_voices(&row).await.unwrap().is_empty(),
            "I6803: a refusal keeps no voice"
        );
        assert!(active(d, &room, &c).await, "I6803: c is still seated");
    }

    /// **I6804** — a resignation by a key holding no seat is held.
    pub(crate) async fn i6804_a_strangers_resignation_is_held(
        d: &dyn FederationDirectory,
        s: &str,
    ) {
        let (room, _a, _b, _c) = room_of_three(d, &format!("i6804-{s}"), "majority").await;
        let stranger = format!("i6804-{s}-stranger");
        reg(d, &[&stranger]).await;
        let stranger = id_of(&stranger);
        let at = Utc::now() - Duration::hours(1);
        let voices = room_end_voices(
            d,
            &room,
            &stranger,
            &[&stranger],
            at,
            RevocationLeaf::Resignation,
        )
        .await;
        match e2::put_voices(d, &voices).await {
            Ok(StatementOutcome::Pending { row_id, .. }) => {
                let why = crate::federation::edition2::fold::why_held(d, &row_id)
                    .await
                    .unwrap()
                    .expect("I6804: a held row carries its reason");
                assert_eq!(
                    why.reason,
                    malformed_row::RESIGNATION_NOT_A_MEMBER_AT_HEAD,
                    "I6804: held by name"
                );
            }
            other => panic!("I6804: a stranger's resignation is held, got {other:?}"),
        }
        assert!(
            d.list_community_membership_revocations_for(&room)
                .await
                .unwrap()
                .is_empty(),
            "I6804: nothing concluded"
        );
    }

    /// **I6805** — the leaf decides: a self-voiced removal is a count unmet.
    pub(crate) async fn i6805_a_self_voiced_removal_is_a_count(
        d: &dyn FederationDirectory,
        s: &str,
    ) {
        let (room, _a, _b, c) = room_of_three(d, &format!("i6805-{s}"), "majority").await;
        let at = Utc::now() - Duration::hours(1);
        let removal = room_end_voices(d, &room, &c, &[&c], at, RevocationLeaf::Removal).await;
        match e2::put_voices(d, &removal).await {
            Ok(StatementOutcome::Pending { row_id, .. }) => {
                let why = crate::federation::edition2::fold::why_held(d, &row_id)
                    .await
                    .unwrap()
                    .expect("I6805: a held row carries its reason");
                assert_eq!(
                    why.reason,
                    crate::federation::edition2::fold::reason::COUNT_SHORT,
                    "I6805: short of its count, never read as a resignation"
                );
            }
            other => panic!("I6805: c's own removal voice is one of three: held, got {other:?}"),
        }
        assert!(active(d, &room, &c).await, "I6805: c stays seated");
        let resignation = room_end_voices(
            d,
            &room,
            &c,
            &[&c],
            at + Duration::minutes(1),
            RevocationLeaf::Resignation,
        )
        .await;
        match e2::put_voices(d, &resignation).await {
            Ok(StatementOutcome::Row { .. }) => {}
            other => panic!("I6805: c's resignation lands, got {other:?}"),
        }
        assert!(!active(d, &room, &c).await, "I6805: c has left");
    }

    /// **I6807** — one end: a counted removal at the resignation's instant
    /// settles on the stored resignation.
    pub(crate) async fn i6807_a_counted_removal_at_the_same_instant_is_one_end(
        d: &dyn FederationDirectory,
        s: &str,
    ) {
        let (room, a, b, c) = room_of_three(d, &format!("i6807-{s}"), "majority").await;
        let at = Utc::now() - Duration::hours(1);
        let resignation =
            room_end_voices(d, &room, &c, &[&c], at, RevocationLeaf::Resignation).await;
        match e2::put_voices(d, &resignation).await {
            Ok(StatementOutcome::Row { .. }) => {}
            other => panic!("I6807: c's resignation lands, got {other:?}"),
        }
        let removal = room_end_voices(d, &room, &c, &[&a, &b], at, RevocationLeaf::Removal).await;
        let out = e2::put_voices(d, &removal).await;
        assert!(
            !matches!(out, Err(Error::Backend(_))),
            "I6807: the counted removal is no storage fault: {out:?}"
        );
        assert!(!active(d, &room, &c).await, "I6807: c stays out");
        let ends: Vec<_> = d
            .list_community_membership_revocations_for(&room)
            .await
            .unwrap()
            .into_iter()
            .filter(|r| r.removed_identity_key_id == c)
            .collect();
        assert_eq!(ends.len(), 1, "I6807: one stored end on the three-part key");
        assert_eq!(
            ends[0].leaf,
            RevocationLeaf::Resignation,
            "I6807: the first stored end keeps its leaf"
        );
    }

    /// The stored end of `member` in `room`, by its leaf.
    async fn stored_leaf(
        d: &dyn FederationDirectory,
        room: &str,
        member: &str,
    ) -> Option<RevocationLeaf> {
        d.list_community_membership_revocations_for(room)
            .await
            .unwrap()
            .into_iter()
            .find(|r| r.removed_identity_key_id == member)
            .map(|r| r.leaf)
    }

    /// **I6808** — a self-voiced removal is a count, never a resignation.
    pub(crate) async fn i6808_a_self_voiced_removal_counts_as_a_removal(
        d: &dyn FederationDirectory,
        s: &str,
    ) {
        let at = Utc::now() - Duration::hours(1);
        // 1 of 3: c's own voice meets the count; the end is a REMOVAL.
        let (one, _a, b, c) = room_of_three(d, &format!("i6808a-{s}"), "quorum:1/3").await;
        let removal = room_end_voices(d, &one, &c, &[&c], at, RevocationLeaf::Removal).await;
        match e2::put_voices(d, &removal).await {
            Ok(StatementOutcome::Row { .. }) => {}
            other => panic!("I6808: 1 of 3 is met by c's own voice, got {other:?}"),
        }
        assert!(
            !active(d, &one, &c).await,
            "I6808: c is out of the 1/3 room"
        );
        assert_eq!(
            stored_leaf(d, &one, &c).await,
            Some(RevocationLeaf::Removal),
            "I6808: a counted end, stored as a removal"
        );
        let resign = room_end_voices(
            d,
            &one,
            &b,
            &[&b],
            at + Duration::minutes(1),
            RevocationLeaf::Resignation,
        )
        .await;
        match e2::put_voices(d, &resign).await {
            Ok(StatementOutcome::Row { .. }) => {}
            other => panic!("I6808: b's resignation lands in the 1/3 room, got {other:?}"),
        }
        assert_eq!(
            stored_leaf(d, &one, &b).await,
            Some(RevocationLeaf::Resignation)
        );
        // 2 of 3: the same voice is short and held.
        let (two, _a, _b, c) = room_of_three(d, &format!("i6808b-{s}"), "quorum:2/3").await;
        let removal = room_end_voices(d, &two, &c, &[&c], at, RevocationLeaf::Removal).await;
        match e2::put_voices(d, &removal).await {
            Ok(StatementOutcome::Pending { row_id, .. }) => {
                let why = crate::federation::edition2::fold::why_held(d, &row_id)
                    .await
                    .unwrap()
                    .expect("I6808: a held row carries its reason");
                assert_eq!(
                    why.reason,
                    crate::federation::edition2::fold::reason::COUNT_SHORT,
                    "I6808: 1 of the 2 of 3"
                );
            }
            other => panic!("I6808: c's own voice is short of 2 of 3, got {other:?}"),
        }
        assert!(active(d, &two, &c).await, "I6808: c stays in the 2/3 room");
        let resign = room_end_voices(
            d,
            &two,
            &c,
            &[&c],
            at + Duration::minutes(1),
            RevocationLeaf::Resignation,
        )
        .await;
        match e2::put_voices(d, &resign).await {
            Ok(StatementOutcome::Row { .. }) => {}
            other => panic!("I6808: c's resignation lands in the 2/3 room, got {other:?}"),
        }
        assert!(!active(d, &two, &c).await, "I6808: c has left");
        assert_eq!(
            stored_leaf(d, &two, &c).await,
            Some(RevocationLeaf::Resignation)
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
                use super::suffix;
                use crate::federation::FederationDirectory;
                #[tokio::test]
                async fn i6802_a_resignation_lands_on_the_members_own_voice() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i6802_a_resignation_lands_on_the_members_own_voice(
                        &d as &dyn FederationDirectory,
                        &suffix(),
                    )
                    .await
                }
                #[tokio::test]
                async fn i6803_a_resignation_by_another_is_refused() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i6803_a_resignation_by_another_is_refused(
                        &d as &dyn FederationDirectory,
                        &suffix(),
                    )
                    .await
                }
                #[tokio::test]
                async fn i6805_a_self_voiced_removal_is_a_count() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i6805_a_self_voiced_removal_is_a_count(
                        &d as &dyn FederationDirectory,
                        &suffix(),
                    )
                    .await
                }
                #[tokio::test]
                async fn i6807_a_counted_removal_at_the_same_instant_is_one_end() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i6807_a_counted_removal_at_the_same_instant_is_one_end(
                        &d as &dyn FederationDirectory,
                        &suffix(),
                    )
                    .await
                }
                #[tokio::test]
                async fn i6808_a_self_voiced_removal_counts_as_a_removal() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i6808_a_self_voiced_removal_counts_as_a_removal(
                        &d as &dyn FederationDirectory,
                        &suffix(),
                    )
                    .await
                }
                #[tokio::test]
                async fn i6804_a_strangers_resignation_is_held() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i6804_a_strangers_resignation_is_held(
                        &d as &dyn FederationDirectory,
                        &suffix(),
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
