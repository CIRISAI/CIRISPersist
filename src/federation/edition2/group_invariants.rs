//! v62.0.0 (wave T1) — **the group planes at the edition-2 door**, on sqlite
//! and postgres. Every voice goes through the one entry
//! (`ingest::put_statement`); every typed row is read back through the
//! directory's own readers.
//!
//! - **I2993** a founding `group:roster` is counted: each voice before the
//!   last listed member's is `Pending` and nothing is in
//!   `federation_families`; the last one lands the family, its members the
//!   voices' identity-refs. A re-put voice is `Row { new: false }`.
//! - **I2994** a later version names the version it extends by `refs.head`:
//!   short of the held protocol it is `Pending` and the head does not move;
//!   met, it is the head, its `prev_head_digest` the held version's
//!   `persist_row_hash`, the prior kept in `federation_group_versions`.
//! - **I2995** a fork (a second version naming an older head) is held as a
//!   tip beside the head (K1's `federation_group_tips`); the head stays.
//! - **I2996** a version whose `refs.head` is not held yet is HELD
//!   (`link_unheld`, `Pending`), its voices kept; when the head is
//!   delivered, G0's write-time re-fold lands it with no re-offer.
//! - **I2997** a version that does not follow its `refs.head`'s version (or a
//!   later version with no `refs.head`) is `edition2_payload_invalid`.
//! - **I2998** a counted removal short of the family's protocol is `Pending`
//!   and absent from `federation_family_membership_revocations`; the voice
//!   that meets it lands it, and the member leaves the active roster. The
//!   replicated door (an offered id) admits a voice the same way.
//! - **I2999** a widening meets the JSON door's own growth gate: with its
//!   standing met but no acceptance held, it is HELD (v62.0.0 wave GC7,
//!   CC 2.7.3: the acceptance is another row), reason
//!   `membership_acceptance_unresolved`, its voice kept and no row.
//! - **I3000** a community: its founding lands in `federation_communities`,
//!   and a counted removal in `federation_community_membership_revocations`.
//! - **I3001** while the head is forked (K1 holds the fork as a tip), the
//!   roster is the members common to all tips (CC 2.7.8): a fork that drops
//!   a member drops it from `active_family_members`.
//! - **I3002** disjoint tips leave an empty roster.
//! - **I3003** a dissolution version lands: short, the family is live; met,
//!   `dissolved_at` is held and the family has no members.
//! - **I3004** a widening lands once the member's consent (an edition-2
//!   proposal and acceptance) is held.
//! - **I3012** the one-voice countersign holds: an affiliation's single
//!   seat's removal voice is `Pending` (the member stays seated) until the
//!   designated official's voice lands it.
//! - **I3005** a held fork heals: a merge naming the head and the tip
//!   (`refs.further_heads`) is counted over their common members, becomes the
//!   one head, the tip leaves the tip store, and a later version extends the
//!   merge.

use chrono::{TimeZone, Utc};
use ciris_crypto::composite::CompositeSigningKey;
use ciris_verify_core::cde::Value;

use super::door_invariants::fixture::{iref, key, key_record};
use super::group::{
    membership_payload, roster_payload, GroupRecord, MembershipRecord, GROUP_ROSTER_PREFIX,
    MEMBERSHIP_PREFIX,
};
use super::ingest::{apply_replicated_statement, put_statement, StatementOutcome, INGEST_TIER};
use super::names::RowId;
use crate::federation::cohort::Cohort;
use crate::federation::types::{
    Community, CommunityMember, CommunityMembershipRevocation, Family, FamilyMember,
    FamilyMembershipRevocation, FamilyMembershipWidening,
};
use crate::federation::{malformed_row, Error, FederationDirectory};

type K = CompositeSigningKey;

fn at(ms: i64) -> chrono::DateTime<Utc> {
    Utc.timestamp_millis_opt(ms).single().unwrap()
}

fn sign(k: &K, sub: &str, prefix: &str, p: &Value) -> Vec<u8> {
    ciris_verify_core::edition2::sign_row_statement(
        k,
        &iref(k),
        sub,
        "scores",
        &ciris_verify_core::namespace_match::family_id(prefix),
        p,
        vec![],
    )
    .unwrap()
}

fn roster(rec: &GroupRecord, version: u64, head: Option<&RowId>, at_ms: u64, k: &K) -> Vec<u8> {
    use crate::federation::edition2::group_fixtures::{fixture_founding, fixture_record};
    // GID-fixtures-sites — a first version is founded under its DERIVED id
    // (the record's id is the room's NAME); a later one names that id.
    let (group, p) = if version == 1 && head.is_none() {
        fixture_founding(rec, at_ms)
    } else {
        let rec = &fixture_record(rec);
        let group = match rec {
            GroupRecord::Family(f) => f.family_key_id.clone(),
            GroupRecord::Community(c) => c.community_key_id.clone(),
        };
        (group, roster_payload(rec, version, head, at_ms).unwrap())
    };
    sign(k, &group, GROUP_ROSTER_PREFIX, &p)
}

fn membership(rec: &MembershipRecord, head: &RowId, k: &K) -> Vec<u8> {
    let member = match rec {
        MembershipRecord::FamilyRemoval(r) => r.removed_identity_key_id.clone(),
        MembershipRecord::CommunityRemoval(r) => r.removed_identity_key_id.clone(),
        MembershipRecord::FamilyWidening(w) => w.member_key_id.clone(),
        MembershipRecord::CommunityWidening(w) => w.member_key_id.clone(),
    };
    let p = membership_payload(rec, Some(head)).unwrap();
    sign(k, &member, MEMBERSHIP_PREFIX, &p)
}

fn family(g: &K, name: &str, protocol: &str, members: &[(&K, Option<&str>)]) -> GroupRecord {
    GroupRecord::Family(Family {
        family_key_id: iref(g),
        family_name: name.into(),
        members: members
            .iter()
            .map(|(k, role)| FamilyMember {
                key_id: iref(k),
                joined_at: at(1_000),
                role: role.map(str::to_owned),
            })
            .collect(),
        founded_at: at(1_000),
        consensus_protocol: protocol.into(),
        consensus_protocol_entrenched: false,
        dissolved_at: None,
        prev_head_digest: String::new(),
        charter_digest: String::new(),
        persist_row_hash: String::new(),
    })
}

async fn register(d: &dyn FederationDirectory, keys: &[&K]) {
    for k in keys {
        put_statement(d, &key_record(k, &["user"], 0, None), None, INGEST_TIER)
            .await
            .unwrap();
    }
}

async fn put(d: &dyn FederationDirectory, st: &[u8]) -> Result<StatementOutcome, Error> {
    put_statement(d, st, None, INGEST_TIER).await
}

fn reason(e: &Error) -> String {
    match e {
        Error::MalformedRow { reason, .. } => (*reason).to_owned(),
        other => other.kind().to_owned(),
    }
}

fn pending(o: &StatementOutcome) -> bool {
    matches!(o, StatementOutcome::Pending { new: true, .. })
}

fn landed(o: &StatementOutcome) -> Option<RowId> {
    match o {
        StatementOutcome::Row { row_id, new: true } => Some(*row_id),
        _ => None,
    }
}

fn sorted(mut v: Vec<String>) -> Vec<String> {
    v.sort();
    v
}

/// I2993–I2997: the roster's versions.
pub(crate) async fn roster_body(d: &dyn FederationDirectory) {
    let (a, b, c, g) = (key(151), key(152), key(153), key(154));
    register(d, &[&a, &b, &c]).await;
    let members = [(&a, None), (&b, None), (&c, None)];

    // I2993 — founding, counted.
    let v1 = family(&g, "fam one", "majority", &members);
    // GID-fixtures-sites — the room's DERIVED id, predicted from its first
    // version (the founding below derives exactly it).
    let gid = crate::federation::edition2::group_fixtures::fixture_group_id(&v1);
    let o = put(d, &roster(&v1, 1, None, 2_000, &a)).await.unwrap();
    assert!(pending(&o), "I2993 first voice: {o:?}");
    assert!(
        d.lookup_family(&gid).await.unwrap().is_none(),
        "I2993 not yet"
    );
    let o = put(d, &roster(&v1, 1, None, 2_000, &b)).await.unwrap();
    assert!(pending(&o), "I2993 second voice: {o:?}");
    let o = put(d, &roster(&v1, 1, None, 2_000, &c)).await.unwrap();
    let v1_id = landed(&o).unwrap_or_else(|| panic!("I2993 the last listed voice: {o:?}"));
    let held1 = d.lookup_family(&gid).await.unwrap().expect("I2993 landed");
    assert_eq!(
        sorted(held1.members.iter().map(|m| m.key_id.clone()).collect()),
        sorted(vec![iref(&a), iref(&b), iref(&c)]),
        "I2993 members"
    );
    assert_eq!(held1.consensus_protocol, "majority", "I2993 protocol");
    assert!(held1.prev_head_digest.is_empty(), "I2993 version 1");
    let o = put(d, &roster(&v1, 1, None, 2_000, &a)).await.unwrap();
    assert!(
        matches!(o, StatementOutcome::Row { new: false, .. }),
        "I2993 a re-put voice: {o:?}"
    );

    // I2994 — a later version extends the head.
    let v2 = family(&g, "fam two", "unanimous", &members);
    let o = put(d, &roster(&v2, 2, Some(&v1_id), 3_000, &a))
        .await
        .unwrap();
    assert!(
        pending(&o),
        "I2994 one of three is short of majority: {o:?}"
    );
    assert_eq!(
        d.lookup_family(&gid).await.unwrap().unwrap().family_name,
        "fam one",
        "I2994 the head did not move"
    );
    let o = put(d, &roster(&v2, 2, Some(&v1_id), 3_000, &b))
        .await
        .unwrap();
    let v2_id = landed(&o);
    assert!(v2_id.is_some(), "I2994 two of three meet majority: {o:?}");
    let held2 = d.lookup_family(&gid).await.unwrap().unwrap();
    assert_eq!(held2.family_name, "fam two", "I2994 the head moved");
    assert_eq!(held2.consensus_protocol, "unanimous", "I2994 protocol");
    assert_eq!(
        held2.prev_head_digest, held1.persist_row_hash,
        "I2994 refs.head is the held version's persist_row_hash"
    );
    let versions = d.list_group_versions(Cohort::Family, &gid).await.unwrap();
    assert_eq!(versions.len(), 2, "I2994 history");
    assert!(
        versions.iter().any(|v| v.is_current && v.version == 2),
        "I2994 version 2 is current: {versions:?}"
    );

    // I2995 — a fork is held as a tip (needs K1's federation_group_tips).
    let fork = family(&g, "fork", "majority", &members);
    for k in [&a, &b] {
        let o = put(d, &roster(&fork, 2, Some(&v1_id), 4_000, k))
            .await
            .unwrap();
        assert!(pending(&o), "I2995 short of unanimous: {o:?}");
    }
    let o = put(d, &roster(&fork, 2, Some(&v1_id), 4_000, &c))
        .await
        .unwrap();
    assert!(landed(&o).is_some(), "I2995 met: {o:?}");
    assert_eq!(
        d.lookup_family(&gid).await.unwrap().unwrap().family_name,
        "fam two",
        "I2995 the head stays"
    );
    let tips = d.list_group_tips(Cohort::Family, &gid).await.unwrap();
    assert_eq!(tips.len(), 1, "I2995 one tip: {tips:?}");
    assert_eq!(
        tips[0].prev_head_digest, held1.persist_row_hash,
        "I2995 the tip names version 1"
    );

    // I2996 — a version whose head is not held yet is HELD (`link_unheld`),
    // its voices kept; when the head is delivered, the fold re-runs it and
    // it lands with no re-offer (order independence).
    let v2_id = v2_id.expect("I2996 v2 is the head");
    let v3 = family(&g, "fam three", "majority", &members);
    let v4 = family(&g, "fam four", "majority", &members);
    // v3 extends the head v2 but is NOT delivered yet; v4 extends v3.
    let v3_voices: Vec<Vec<u8>> = [&a, &b, &c]
        .iter()
        .map(|k| roster(&v3, 3, Some(&v2_id), 5_000, k))
        .collect();
    let v3_id = RowId::of_statement(&v3_voices[0]).unwrap();
    let v4_voices: Vec<Vec<u8>> = [&a, &b]
        .iter()
        .map(|k| roster(&v4, 4, Some(&v3_id), 5_500, k))
        .collect();
    let v4_id = RowId::of_statement(&v4_voices[0]).unwrap();
    for st in &v4_voices {
        let o = put(d, st).await.unwrap_or_else(|e| {
            panic!("I2996 a version naming an unheld head is held, not refused: {e:?}")
        });
        assert!(
            matches!(o, StatementOutcome::Pending { .. }),
            "I2996 held: {o:?}"
        );
    }
    assert_eq!(
        d.edition2_voices(&v4_id).await.unwrap().len(),
        2,
        "I2996 both voices kept"
    );
    let why = super::fold::why_held(d, &v4_id)
        .await
        .unwrap()
        .expect("I2996 a held reason");
    assert_eq!(
        why.reason,
        super::fold::reason::LINK_UNHELD,
        "I2996 held for its unheld head: {why:?}"
    );
    assert_eq!(
        d.lookup_family(&gid).await.unwrap().unwrap().family_name,
        "fam two",
        "I2996 the head did not move"
    );
    // The head is delivered (unanimous at v2: all three voices). Its landing
    // re-folds v4, which lands on its own.
    for st in &v3_voices {
        put(d, st).await.unwrap();
    }
    assert_eq!(
        d.lookup_family(&gid).await.unwrap().unwrap().family_name,
        "fam four",
        "I2996 v4 landed when its head arrived, with no re-offer"
    );
    assert!(
        super::fold::why_held(d, &v4_id).await.unwrap().is_none(),
        "I2996 no longer held"
    );

    // I2997 — the version follows its head's. v62.0.0 (wave GC5): the
    // named version's number is another row's content: held, concluding
    // nothing. A later version naming no head is the row's own bytes:
    // refused.
    let st = roster(&v3, 5, Some(&v1_id), 5_000, &a);
    let o = put(d, &st).await.unwrap();
    assert!(pending(&o), "I2997 held: {o:?}");
    assert_eq!(
        super::fold::why_held(d, &RowId::of_statement(&st).unwrap())
            .await
            .unwrap()
            .map(|h| h.reason),
        Some(super::fold::reason::VERSION_DOES_NOT_FOLLOW.to_owned()),
        "I2997 version 5 after version 1"
    );
    let e = put(d, &roster(&v3, 2, None, 5_000, &a)).await.unwrap_err();
    assert_eq!(
        reason(&e),
        malformed_row::EDITION2_PAYLOAD_INVALID,
        "I2997 a later version with no refs.head"
    );
}

/// I2998–I2999: counted membership changes on a family.
pub(crate) async fn membership_body(d: &dyn FederationDirectory) {
    let (a, b, c, n, g, g3) = (key(161), key(162), key(163), key(164), key(165), key(166));
    register(d, &[&a, &b, &c, &n]).await;
    let f = family(&g, "fam", "majority", &[(&a, None), (&b, None), (&c, None)]);
    let mut head = None;
    // GID-fixtures-sites — the room's DERIVED id, predicted from its first
    // version (the founding below derives exactly it).
    let gid = crate::federation::edition2::group_fixtures::fixture_group_id(&f);
    for k in [&a, &b, &c] {
        head = landed(&put(d, &roster(&f, 1, None, 2_000, k)).await.unwrap());
    }
    let head = head.expect("I2998 the family is founded");

    // I2998 — a removal, counted at majority.
    let removal = MembershipRecord::FamilyRemoval(FamilyMembershipRevocation {
        family_key_id: gid.clone(),
        removed_identity_key_id: iref(&c),
        removed_at: at(5_000),
        effective_at: at(5_000),
        reason: None,
        witness_set: Vec::new(),
        persist_row_hash: String::new(),
        leaf: crate::federation::types::RevocationLeaf::Removal,
    });
    let o = put(d, &membership(&removal, &head, &a)).await.unwrap();
    assert!(pending(&o), "I2998 one of three: {o:?}");
    assert!(
        d.list_family_membership_revocations_for(&gid)
            .await
            .unwrap()
            .is_empty(),
        "I2998 short: no row"
    );
    // The meeting voice through the replicated door, under its offered id.
    let st = membership(&removal, &head, &b);
    let id = RowId::of_statement(&st).unwrap();
    let o = apply_replicated_statement(d, &st, &id.0).await.unwrap();
    assert!(
        matches!(
            o,
            super::ingest::ReplicatedStatementOutcome::Admitted(StatementOutcome::Row { .. })
        ),
        "I2998 met on the replicated door: {o:?}"
    );
    let held = d
        .list_family_membership_revocations_for(&gid)
        .await
        .unwrap();
    assert_eq!(held.len(), 1, "I2998 landed");
    assert_eq!(held[0].removed_identity_key_id, iref(&c), "I2998 member");
    assert_eq!(
        sorted(
            d.active_family_members(&gid)
                .await
                .unwrap()
                .into_iter()
                .map(|m| m.key_id)
                .collect()
        ),
        sorted(vec![iref(&a), iref(&b)]),
        "I2998 the member left the roster"
    );

    // I2999 — a widening meets the growth gate (founder_only: a's voice
    // alone has standing; no acceptance is held).
    let f3 = family(
        &g3,
        "fam3",
        "founder_only",
        &[(&a, Some("founder")), (&b, None)],
    );
    let mut head3 = None;
    // GID-fixtures-sites — the room's DERIVED id, predicted from its first
    // version (the founding below derives exactly it).
    let gid3 = crate::federation::edition2::group_fixtures::fixture_group_id(&f3);
    for k in [&a, &b] {
        head3 = landed(&put(d, &roster(&f3, 1, None, 2_000, k)).await.unwrap());
    }
    let head3 = head3.expect("I2999 founded");
    let widening = MembershipRecord::FamilyWidening(FamilyMembershipWidening {
        family_key_id: gid3.clone(),
        member_key_id: iref(&n),
        joined_at: at(6_000),
        effective_at: at(6_000),
        role: None,
        persist_row_hash: String::new(),
    });
    let st = membership(&widening, &head3, &a);
    let out = put(d, &st).await;
    assert!(
        matches!(out, Ok(StatementOutcome::Pending { .. })),
        "I2999 the growth gate holds: {out:?}"
    );
    assert_eq!(
        super::fold::why_held(d, &RowId::of_statement(&st).unwrap())
            .await
            .unwrap()
            .map(|h| h.reason),
        Some(crate::federation::membership_acceptance::RULE_ACCEPTANCE_UNRESOLVED.to_owned()),
        "I2999 held, reason membership_acceptance_unresolved"
    );
    assert!(
        !d.edition2_voices(&RowId::of_statement(&st).unwrap())
            .await
            .unwrap()
            .is_empty(),
        "I2999 the held voice is kept"
    );
    assert!(
        d.list_family_membership_widenings_for(&gid3)
            .await
            .unwrap()
            .is_empty(),
        "I2999 no row"
    );
}

/// I3000: a community.
pub(crate) async fn community_body(d: &dyn FederationDirectory) {
    let (a, b, g) = (key(171), key(172), key(173));
    register(d, &[&a, &b]).await;
    let gid = iref(&g);
    let c = GroupRecord::Community(Community {
        community_key_id: gid.clone(),
        community_name: "room".into(),
        members: [(&a, Some("founder")), (&b, None)]
            .iter()
            .map(|(k, role)| CommunityMember {
                key_id: iref(k),
                joined_at: at(1_000),
                role: role.map(str::to_owned),
            })
            .collect(),
        founded_at: at(1_000),
        consensus_protocol: "majority".into(),
        policy_blob: None,
        prev_head_digest: String::new(),
        charter_digest: String::new(),
        persist_row_hash: String::new(),
    });
    // GID-fixtures-sites — the room's DERIVED id, predicted from its first
    // version (the founding below derives exactly it).
    let gid = crate::federation::edition2::group_fixtures::fixture_group_id(&c);
    let o = put(d, &roster(&c, 1, None, 2_000, &a)).await.unwrap();
    assert!(pending(&o), "I3000 founding short: {o:?}");
    assert!(d.lookup_community(&gid).await.unwrap().is_none(), "I3000");
    let o = put(d, &roster(&c, 1, None, 2_000, &b)).await.unwrap();
    let head = landed(&o).unwrap_or_else(|| panic!("I3000 founded: {o:?}"));
    let held = d
        .lookup_community(&gid)
        .await
        .unwrap()
        .expect("I3000 landed");
    assert_eq!(held.community_name, "room", "I3000 name");

    let removal = MembershipRecord::CommunityRemoval(CommunityMembershipRevocation {
        community_key_id: gid.clone(),
        removed_identity_key_id: iref(&b),
        removed_at: at(5_000),
        effective_at: at(5_000),
        reason: None,
        witness_set: Vec::new(),
        persist_row_hash: String::new(),
        leaf: crate::federation::types::RevocationLeaf::Removal,
    });
    let o = put(d, &membership(&removal, &head, &a)).await.unwrap();
    assert!(pending(&o), "I3000 removal short of majority: {o:?}");
    let o = put(d, &membership(&removal, &head, &b)).await.unwrap();
    assert!(landed(&o).is_some(), "I3000 removal met: {o:?}");
    let held = d
        .list_community_membership_revocations_for(&gid)
        .await
        .unwrap();
    assert_eq!(held.len(), 1, "I3000 the removal landed");
}

/// I3001–I3002: the roster while the head is forked (CC 2.7.8: "the roster
/// is then the members common to all tips").
pub(crate) async fn fork_roster_body(d: &dyn FederationDirectory) {
    let (a, b, c, e, g, g2) = (key(181), key(182), key(183), key(184), key(185), key(186));
    register(d, &[&a, &b, &c, &e]).await;
    let active = |gid: String| async move {
        sorted(
            d.active_family_members(&gid)
                .await
                .unwrap()
                .into_iter()
                .map(|m| m.key_id)
                .collect(),
        )
    };

    // I3001 — a fork with an overlap: the common members, through the door.
    let abc = [(&a, None), (&b, None), (&c, None)];
    let v1 = family(&g, "v1", "majority", &abc);
    let mut v1_id = None;
    // GID-fixtures-sites — the room's DERIVED id, predicted from its first
    // version (the founding below derives exactly it).
    let gid = crate::federation::edition2::group_fixtures::fixture_group_id(&v1);
    for k in [&a, &b, &c] {
        v1_id = landed(&put(d, &roster(&v1, 1, None, 2_000, k)).await.unwrap());
    }
    let v1_id = v1_id.expect("I3001 founded");
    let head = family(&g, "head", "majority", &abc);
    for k in [&a, &b] {
        put(d, &roster(&head, 2, Some(&v1_id), 3_000, k))
            .await
            .unwrap();
    }
    assert_eq!(
        d.lookup_family(&gid).await.unwrap().unwrap().family_name,
        "head",
        "I3001 the head moved"
    );
    assert_eq!(
        active(gid.clone()).await,
        sorted(vec![iref(&a), iref(&b), iref(&c)]),
        "I3001 one head: its roster"
    );
    let fork = family(&g, "fork", "majority", &[(&a, None), (&b, None)]);
    for k in [&a, &b] {
        put(d, &roster(&fork, 2, Some(&v1_id), 4_000, k))
            .await
            .unwrap();
    }
    assert_eq!(
        d.list_group_tips(Cohort::Family, &gid).await.unwrap().len(),
        1,
        "I3001 the fork is a tip"
    );
    assert_eq!(
        active(gid.clone()).await,
        sorted(vec![iref(&a), iref(&b)]),
        "I3001 the roster is the members common to both tips"
    );

    // I3002 — two forks with disjoint members: an empty roster. Through the
    // door only (the earlier `supersede_group_row` snapshot plant is shut,
    // CP2): the head w2 keeps all four members, so each fork lists a subset
    // of the head (#955 Q2, judged against THIS node's head) and is held as
    // a tip. The members common to the head {a,b,c,e}, the tip {a,b} and the
    // tip {c,e} are none.
    let abce = [(&a, None), (&b, None), (&c, None), (&e, None)];
    let w1 = family(&g2, "w1", "majority", &abce);
    let mut w1_id = None;
    // GID-fixtures-sites — the room's DERIVED id, predicted from its first
    // version (the founding below derives exactly it).
    let gid2 = crate::federation::edition2::group_fixtures::fixture_group_id(&w1);
    for k in [&a, &b, &c, &e] {
        w1_id = landed(&put(d, &roster(&w1, 1, None, 2_000, k)).await.unwrap());
    }
    let w1_id = w1_id.expect("I3002 founded");
    // The head: a rename, the same four members (majority: three of four).
    let w2 = family(&g2, "w2", "majority", &abce);
    for k in [&a, &b, &c] {
        put(d, &roster(&w2, 2, Some(&w1_id), 3_000, k))
            .await
            .unwrap();
    }
    assert_eq!(
        d.lookup_family(&gid2).await.unwrap().unwrap().family_name,
        "w2",
        "I3002 the head"
    );
    // Tip one: {a,b}, naming w1, counted over the head's four (three voices).
    let ab = family(&g2, "ab", "majority", &[(&a, None), (&b, None)]);
    for k in [&a, &b, &c] {
        put(d, &roster(&ab, 2, Some(&w1_id), 4_000, k))
            .await
            .unwrap();
    }
    assert_eq!(
        active(gid2.clone()).await,
        sorted(vec![iref(&a), iref(&b)]),
        "I3002 one tip: the members common to the head and it"
    );
    // Tip two: {c,e}, naming w1, counted over the roster now common to the
    // tips, {a,b} (a majority of two is both).
    let ce = family(&g2, "ce", "majority", &[(&c, None), (&e, None)]);
    for k in [&a, &b] {
        put(d, &roster(&ce, 2, Some(&w1_id), 5_000, k))
            .await
            .unwrap();
    }
    assert_eq!(
        d.list_group_tips(Cohort::Family, &gid2)
            .await
            .unwrap()
            .len(),
        2,
        "I3002 both forks held as tips"
    );
    assert_eq!(
        d.lookup_family(&gid2).await.unwrap().unwrap().family_name,
        "w2",
        "I3002 the head stays"
    );
    assert!(
        active(gid2.clone()).await.is_empty(),
        "I3002 disjoint tips have no member in common"
    );
}

/// I3003: a dissolution version lands (CIRISPersist#956). Its payload's
/// `dissolved_at` rides the change envelope the door builds, so the door's
/// own `check_dissolution_matches_envelope` reads it as the signed one.
pub(crate) async fn dissolution_body(d: &dyn FederationDirectory) {
    let (a, b, c, g) = (key(191), key(192), key(193), key(194));
    register(d, &[&a, &b, &c]).await;
    let abc = [(&a, None), (&b, None), (&c, None)];
    let v1 = family(&g, "to dissolve", "majority", &abc);
    let mut v1_id = None;
    // GID-fixtures-sites — the room's DERIVED id, predicted from its first
    // version (the founding below derives exactly it).
    let gid = crate::federation::edition2::group_fixtures::fixture_group_id(&v1);
    for k in [&a, &b, &c] {
        v1_id = landed(&put(d, &roster(&v1, 1, None, 2_000, k)).await.unwrap());
    }
    let v1_id = v1_id.expect("I3003 founded");
    let GroupRecord::Family(mut f2) = family(&g, "to dissolve", "majority", &abc) else {
        unreachable!()
    };
    f2.dissolved_at = Some(at(7_000));
    let v2 = GroupRecord::Family(f2);
    let o = put(d, &roster(&v2, 2, Some(&v1_id), 7_000, &a))
        .await
        .unwrap();
    assert!(pending(&o), "I3003 one of three: {o:?}");
    assert!(
        d.lookup_family(&gid)
            .await
            .unwrap()
            .unwrap()
            .dissolved_at
            .is_none(),
        "I3003 short: not dissolved"
    );
    let o = put(d, &roster(&v2, 2, Some(&v1_id), 7_000, &b))
        .await
        .unwrap();
    assert!(landed(&o).is_some(), "I3003 met: {o:?}");
    let held = d.lookup_family(&gid).await.unwrap().unwrap();
    assert_eq!(held.dissolved_at, Some(at(7_000)), "I3003 dissolved");
    assert!(
        d.active_family_members(&gid).await.unwrap().is_empty(),
        "I3003 a dissolved family has no members"
    );
}

/// I3004: a widening LANDS. The member's consent is held as edition-2 rows
/// (E0's `proposal_row` / `acceptance_row`, flipped by the switch and put
/// with `put_signed`); the founder's voice then meets `founder_only` and the
/// growth gate, and the widening lands in
/// `federation_family_membership_widenings`.
pub(crate) async fn widening_body(d: &dyn FederationDirectory) {
    use super::fixture_switch as e2;
    use crate::federation::membership_acceptance::test_support::{acceptance_row, proposal_row};
    let founder = e2::put_key(d, "t1-founder", &["user"]).await;
    let other = e2::put_key(d, "t1-other", &["user"]).await;
    let joiner = e2::put_key(d, "t1-joiner", &["user"]).await;
    let (kf, ko) = (e2::signing_key("t1-founder"), e2::signing_key("t1-other"));
    let g = key(195);
    let f = family(
        &g,
        "growing",
        "founder_only",
        &[(&kf, Some("founder")), (&ko, None)],
    );
    let mut head = None;
    // GID-fixtures-sites — the room's DERIVED id, predicted from its first
    // version (the founding below derives exactly it).
    let gid = crate::federation::edition2::group_fixtures::fixture_group_id(&f);
    for k in [&kf, &ko] {
        head = landed(&put(d, &roster(&f, 1, None, 2_000, k)).await.unwrap());
    }
    let head = head.expect("I3004 founded");
    assert_eq!(
        iref(&kf),
        founder,
        "I3004 the fixture key is the registered one"
    );
    assert_eq!(iref(&ko), other, "I3004");

    let t = at(6_000);
    let p = proposal_row("t1-founder", "family", &gid, &joiner, None, t);
    e2::put_signed(d, &p).await.expect("I3004 proposal held");
    let a = acceptance_row("t1-joiner", &p, t);
    e2::put_signed(d, &a).await.expect("I3004 acceptance held");

    let widening = MembershipRecord::FamilyWidening(FamilyMembershipWidening {
        family_key_id: gid.clone(),
        member_key_id: joiner.clone(),
        joined_at: t,
        effective_at: t,
        role: None,
        persist_row_hash: String::new(),
    });
    let o = put(d, &membership(&widening, &head, &kf)).await.unwrap();
    assert!(landed(&o).is_some(), "I3004 the widening lands: {o:?}");
    let held = d.list_family_membership_widenings_for(&gid).await.unwrap();
    assert_eq!(held.len(), 1, "I3004 one widening");
    assert_eq!(held[0].member_key_id, joiner, "I3004 the member");
    assert!(
        d.active_family_members(&gid)
            .await
            .unwrap()
            .iter()
            .any(|m| m.key_id == joiner),
        "I3004 the member joined the roster"
    );
}

/// I3005: a held fork HEALS (CC 2.7.8: "until a version naming the tips
/// makes one head again"; a version is counted over the members of the heads
/// it names). A merge naming the head (`refs.head`) and the tip
/// (`refs.further_heads`) is counted over the members common to them: one
/// voice of the two is short; both make it the head, and the tip leaves the
/// tip store.
pub(crate) async fn fork_heals_body(d: &dyn FederationDirectory) {
    let (a, b, c, g) = (key(201), key(202), key(203), key(204));
    register(d, &[&a, &b, &c]).await;
    let abc = [(&a, None), (&b, None), (&c, None)];
    let ab = [(&a, None), (&b, None)];
    let v1 = family(&g, "v1", "majority", &abc);
    let mut v1_id = None;
    // GID-fixtures-sites — the room's DERIVED id, predicted from its first
    // version (the founding below derives exactly it).
    let gid = crate::federation::edition2::group_fixtures::fixture_group_id(&v1);
    for k in [&a, &b, &c] {
        v1_id = landed(&put(d, &roster(&v1, 1, None, 2_000, k)).await.unwrap());
    }
    let v1_id = v1_id.expect("I3005 founded");
    let head = family(&g, "head", "majority", &abc);
    let mut head_id = None;
    for k in [&a, &b] {
        head_id = landed(
            &put(d, &roster(&head, 2, Some(&v1_id), 3_000, k))
                .await
                .unwrap(),
        );
    }
    let head_id = head_id.expect("I3005 the head");
    let fork = family(&g, "fork", "majority", &ab);
    let mut fork_id = None;
    for k in [&a, &b] {
        fork_id = landed(
            &put(d, &roster(&fork, 2, Some(&v1_id), 4_000, k))
                .await
                .unwrap(),
        );
    }
    let fork_id = fork_id.expect("I3005 the fork");
    assert_eq!(
        d.list_group_tips(Cohort::Family, &gid).await.unwrap().len(),
        1,
        "I3005 forked"
    );

    let merge = family(&g, "healed", "majority", &ab);
    let voice = |k: &K| {
        // GID-fix6 — the merge names the family's DERIVED id (`fixture_record`).
        let p = super::group::roster_payload_merging(
            &crate::federation::edition2::group_fixtures::fixture_record(&merge),
            3,
            Some(&head_id),
            &[fork_id],
            5_000,
        )
        .unwrap();
        sign(k, &gid, GROUP_ROSTER_PREFIX, &p)
    };
    let o = put(d, &voice(&a)).await.unwrap();
    assert!(
        pending(&o),
        "I3005 one of the two common members is short: {o:?}"
    );
    assert_eq!(
        d.lookup_family(&gid).await.unwrap().unwrap().family_name,
        "head",
        "I3005 short: still forked"
    );
    let o = put(d, &voice(&b)).await.unwrap();
    assert!(landed(&o).is_some(), "I3005 the merge is met: {o:?}");
    let held = d.lookup_family(&gid).await.unwrap().unwrap();
    assert_eq!(held.family_name, "healed", "I3005 one head again");
    assert!(
        d.list_group_tips(Cohort::Family, &gid)
            .await
            .unwrap()
            .is_empty(),
        "I3005 the merged tip left the tip store"
    );
    assert_eq!(
        sorted(
            d.active_family_members(&gid)
                .await
                .unwrap()
                .into_iter()
                .map(|m| m.key_id)
                .collect()
        ),
        sorted(vec![iref(&a), iref(&b)]),
        "I3005 the merged head's roster"
    );
    // A version after the merge extends it (its chain reads through both
    // parents of the merge).
    let after = family(&g, "after", "majority", &ab);
    let mut after_id = None;
    for k in [&a, &b] {
        after_id = landed(
            &put(d, &roster(&after, 4, Some(&o_row(&o)), 6_000, k))
                .await
                .unwrap(),
        );
    }
    assert!(after_id.is_some(), "I3005 a version extends the merge");
    assert_eq!(
        d.lookup_family(&gid).await.unwrap().unwrap().family_name,
        "after",
        "I3005 the head moved past the merge"
    );
}

fn o_row(o: &StatementOutcome) -> RowId {
    match o {
        StatementOutcome::Row { row_id, .. } | StatementOutcome::Pending { row_id, .. } => *row_id,
        other => panic!("not a group row: {other:?}"),
    }
}

/// I3012: the one-voice countersign HOLDS (CC 4.4.3.2.8,
/// `affiliation_member_action`). An affiliation with ONE deciding seat (its
/// founder) and a designated official: the founder's removal voice alone is
/// short of the countersign, so it is `Pending` (kept, not refused) and the
/// member is still seated; the official's voice over the same removal lands
/// it.
pub(crate) async fn countersign_body(d: &dyn FederationDirectory) {
    let (f, m, official, g) = (key(241), key(242), key(243), key(244));
    register(d, &[&f, &m, &official]).await;
    let gid = iref(&g);
    let room = GroupRecord::Community(Community {
        community_key_id: gid.clone(),
        community_name: "sole practice".into(),
        members: [(&f, Some("founder")), (&m, None)]
            .iter()
            .map(|(k, role)| CommunityMember {
                key_id: iref(k),
                joined_at: at(1_000),
                role: role.map(str::to_owned),
            })
            .collect(),
        founded_at: at(1_000),
        consensus_protocol: "founder_only".into(),
        policy_blob: Some(serde_json::json!({
            crate::federation::affiliation_config::POLICY_COHORT_FIELD: "affiliations",
            crate::federation::affiliation_config::POLICY_AFFILIATION_CONFIG_FIELD: {
                "designated_officials": [{ "role": "privacy_officer", "key_id": iref(&official) }],
            },
        })),
        prev_head_digest: String::new(),
        charter_digest: String::new(),
        persist_row_hash: String::new(),
    });
    let mut head = None;
    // GID-fixtures-sites — the room's DERIVED id, predicted from its first
    // version (the founding below derives exactly it).
    let gid = crate::federation::edition2::group_fixtures::fixture_group_id(&room);
    for k in [&f, &m] {
        head = landed(&put(d, &roster(&room, 1, None, 2_000, k)).await.unwrap());
    }
    let head = head.expect("I3012 the affiliation is founded");
    let removal = MembershipRecord::CommunityRemoval(CommunityMembershipRevocation {
        community_key_id: gid.clone(),
        removed_identity_key_id: iref(&m),
        removed_at: at(5_000),
        effective_at: at(5_000),
        reason: None,
        witness_set: Vec::new(),
        persist_row_hash: String::new(),
        leaf: crate::federation::types::RevocationLeaf::Removal,
    });
    let seated = |gid: String| async move {
        d.active_community_members(&gid)
            .await
            .unwrap()
            .iter()
            .any(|x| x.key_id == iref(&key(242)))
    };
    let o = put(d, &membership(&removal, &head, &f)).await.unwrap();
    assert!(
        pending(&o),
        "I3012 the one seat alone is short of its countersign: {o:?}"
    );
    assert!(seated(gid.clone()).await, "I3012 still a member");
    assert!(
        d.list_community_membership_revocations_for(&gid)
            .await
            .unwrap()
            .is_empty(),
        "I3012 short: no removal row"
    );
    let o = put(d, &membership(&removal, &head, &official))
        .await
        .unwrap();
    assert!(
        landed(&o).is_some(),
        "I3012 the official's countersign lands it: {o:?}"
    );
    assert!(!seated(gid.clone()).await, "I3012 removed");
    assert_eq!(
        d.list_community_membership_revocations_for(&gid)
            .await
            .unwrap()
            .len(),
        1,
        "I3012 the removal landed"
    );
}

/// I6121 (HEAD-6; CC 2.4.1.1, `end_names_old_head`) — **an end that acts
/// from an old head concludes nothing**, at the statement door: a family's
/// version 2 extends version 1; a member's act at the family names version
/// 2; the member's own withdrawal of it naming version 1 is refused
/// `end_names_old_head` (the act it ends, in its own past, names the newer
/// head), and the same withdrawal naming version 2 is not.
pub(crate) async fn end_old_head_body(d: &dyn FederationDirectory) {
    use super::door_invariants::fixture::map;
    let (a, b, c, g) = (key(171), key(172), key(173), key(174));
    register(d, &[&a, &b, &c]).await;
    let members = [(&a, None), (&b, None), (&c, None)];
    let v1 = family(&g, "end one", "majority", &members);
    let mut v1_id = None;
    // GID-fixtures-sites — the room's DERIVED id, predicted from its first
    // version (the founding below derives exactly it).
    let gid = crate::federation::edition2::group_fixtures::fixture_group_id(&v1);
    for k in [&a, &b, &c] {
        let o = put(d, &roster(&v1, 1, None, 2_000, k)).await.unwrap();
        v1_id = v1_id.or(landed(&o));
    }
    let v1_id = v1_id.expect("I6121 version 1 lands");
    let v2 = family(&g, "end two", "majority", &members);
    let mut v2_id = None;
    for k in [&a, &b] {
        let o = put(d, &roster(&v2, 2, Some(&v1_id), 3_000, k))
            .await
            .unwrap();
        v2_id = v2_id.or(landed(&o));
    }
    let v2_id = v2_id.expect("I6121 version 2 lands");
    let head_ref = |h: &RowId| ciris_verify_core::edition2::row_ref(&h.0);
    let act = sign(
        &a,
        &iref(&a),
        "chat:*",
        &map(vec![
            ("asserted_at", Value::Uint(5_000)),
            ("author", Value::Text(iref(&a))),
            ("dimension", Value::Text("chat:message:v1".into())),
            ("cohort_scope", Value::Text("family".into())),
            ("family_id", Value::Text(gid.clone())),
            ("refs", map(vec![("head", head_ref(&v2_id))])),
        ]),
    );
    let act_id = RowId::of_statement(&act).expect("I6121 a row");
    put(d, &act)
        .await
        .unwrap_or_else(|e| panic!("I6121 the act at version 2 lands: {e:?}"));
    let end = |head: &RowId| {
        ciris_verify_core::edition2::sign_row_statement(
            &a,
            &iref(&a),
            &iref(&a),
            "withdraws",
            &ciris_verify_core::namespace_match::family_id("chat:*"),
            &map(vec![
                ("asserted_at", Value::Uint(6_000)),
                ("author", Value::Text(iref(&a))),
                (
                    "refs",
                    map(vec![
                        ("head", head_ref(head)),
                        ("target", head_ref(&act_id)),
                    ]),
                ),
            ]),
            vec![],
        )
        .unwrap()
    };
    let e = put(d, &end(&v1_id))
        .await
        .expect_err("I6121 an end naming the old head");
    assert_eq!(
        reason(&e),
        malformed_row::END_NAMES_OLD_HEAD,
        "I6121 refused end_names_old_head: {e:?}"
    );
    if let Err(e) = put(d, &end(&v2_id)).await {
        assert_ne!(
            reason(&e),
            malformed_row::END_NAMES_OLD_HEAD,
            "I6121 an end naming the newest head is not refused by the rule: {e:?}"
        );
    }
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i6121_an_end_naming_an_old_head_sqlite() {
    Box::pin(end_old_head_body(&sqlite().await)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i6121_an_end_naming_an_old_head_postgres() {
    let Some(b) = postgres().await else {
        return;
    };
    Box::pin(end_old_head_body(&b)).await;
}

#[cfg(feature = "sqlite")]
async fn sqlite() -> crate::store::sqlite::SqliteBackend {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    b
}

#[cfg(feature = "postgres")]
async fn postgres() -> Option<crate::store::postgres::PostgresBackend> {
    use crate::store::Backend as _;
    let dsn = crate::test_pg::empty_dsn()?;
    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Some(b)
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i2993_i2997_roster_versions_sqlite() {
    Box::pin(roster_body(&sqlite().await)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i2993_i2997_roster_versions_postgres() {
    let Some(b) = postgres().await else {
        return;
    };
    Box::pin(roster_body(&b)).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i2998_i2999_membership_sqlite() {
    Box::pin(membership_body(&sqlite().await)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i2998_i2999_membership_postgres() {
    let Some(b) = postgres().await else {
        return;
    };
    Box::pin(membership_body(&b)).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i3000_community_sqlite() {
    Box::pin(community_body(&sqlite().await)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i3000_community_postgres() {
    let Some(b) = postgres().await else {
        return;
    };
    Box::pin(community_body(&b)).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i3001_i3002_fork_roster_sqlite() {
    Box::pin(fork_roster_body(&sqlite().await)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i3001_i3002_fork_roster_postgres() {
    let Some(b) = postgres().await else {
        return;
    };
    Box::pin(fork_roster_body(&b)).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i3003_dissolution_sqlite() {
    Box::pin(dissolution_body(&sqlite().await)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i3003_dissolution_postgres() {
    let Some(b) = postgres().await else {
        return;
    };
    Box::pin(dissolution_body(&b)).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i3004_widening_lands_sqlite() {
    Box::pin(widening_body(&sqlite().await)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i3004_widening_lands_postgres() {
    let Some(b) = postgres().await else {
        return;
    };
    Box::pin(widening_body(&b)).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i3005_fork_heals_sqlite() {
    Box::pin(fork_heals_body(&sqlite().await)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i3005_fork_heals_postgres() {
    let Some(b) = postgres().await else {
        return;
    };
    Box::pin(fork_heals_body(&b)).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i3012_one_voice_countersign_holds_sqlite() {
    Box::pin(countersign_body(&sqlite().await)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i3012_one_voice_countersign_holds_postgres() {
    let Some(b) = postgres().await else {
        return;
    };
    Box::pin(countersign_body(&b)).await;
}

/// **I2191 (v62.0.0, PX-fix3) — a forked group reads as FORKED through the
/// capsule proxy.** I3001's shape, written on the backend and read through
/// the proxy (backend ← capsule dispatch ← `OpsDirectory`): with a fork held
/// as a tip, `list_group_tips` through the proxy answers the backend's tip,
/// and the authorized roster a consumer composes over the proxy
/// (`active_family_members`, a trait default over `forked_tip_members`) is
/// the members COMMON to both tips — never the head's own roster. Before
/// PX-fix3 the proxy answered `list_group_tips` `Unsupported` and
/// `forked_tip_members` read that as "not forked" (fail-open: `c`, whom the
/// fork drops, stayed a member).
pub(crate) async fn fork_through_proxy_body(dir: std::sync::Arc<dyn FederationDirectory>) {
    let proxy = crate::ffi::directory_capsule::test_proxy(dir.clone());
    let (d, p) = (dir.as_ref(), proxy.as_ref());
    let (a, b, c, g) = (key(191), key(192), key(193), key(194));
    register(d, &[&a, &b, &c]).await;
    let active = |x: &'static str, gid: String| {
        let dd: &dyn FederationDirectory = if x == "proxy" { p } else { d };
        async move {
            sorted(
                dd.active_family_members(&gid)
                    .await
                    .unwrap_or_else(|e| panic!("I2191 {x}: active_family_members: {e}"))
                    .into_iter()
                    .map(|m| m.key_id)
                    .collect(),
            )
        }
    };
    let abc = [(&a, None), (&b, None), (&c, None)];
    let v1 = family(&g, "v1", "majority", &abc);
    let mut v1_id = None;
    // GID-fixtures-sites — the room's DERIVED id, predicted from its first
    // version (the founding below derives exactly it).
    let gid = crate::federation::edition2::group_fixtures::fixture_group_id(&v1);
    for k in [&a, &b, &c] {
        v1_id = landed(&put(d, &roster(&v1, 1, None, 2_000, k)).await.unwrap());
    }
    let v1_id = v1_id.expect("I2191 founded");
    let head = family(&g, "head", "majority", &abc);
    for k in [&a, &b] {
        put(d, &roster(&head, 2, Some(&v1_id), 3_000, k))
            .await
            .unwrap();
    }
    let all = sorted(vec![iref(&a), iref(&b), iref(&c)]);
    assert_eq!(active("direct", gid.clone()).await, all, "I2191 one head");
    assert_eq!(
        active("proxy", gid.clone()).await,
        all,
        "I2191 one head, through the proxy"
    );
    let fork = family(&g, "fork", "majority", &[(&a, None), (&b, None)]);
    for k in [&a, &b] {
        put(d, &roster(&fork, 2, Some(&v1_id), 4_000, k))
            .await
            .unwrap();
    }
    let direct_tips = d.list_group_tips(Cohort::Family, &gid).await.unwrap();
    assert_eq!(direct_tips.len(), 1, "I2191 the fork is a tip");
    assert_eq!(
        p.list_group_tips(Cohort::Family, &gid)
            .await
            .expect("I2191 the proxy routes list_group_tips"),
        direct_tips,
        "I2191 the proxy reads the backend's tip"
    );
    let common = sorted(vec![iref(&a), iref(&b)]);
    assert_eq!(
        active("direct", gid.clone()).await,
        common,
        "I2191 forked: the members common to both tips"
    );
    assert_eq!(
        active("proxy", gid.clone()).await,
        common,
        "I2191 forked THROUGH THE PROXY: the common members, never the head's roster"
    );
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i2191_a_fork_reads_forked_through_the_proxy_sqlite() {
    Box::pin(fork_through_proxy_body(std::sync::Arc::new(sqlite().await))).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i2191_a_fork_reads_forked_through_the_proxy_postgres() {
    let Some(b) = postgres().await else {
        return;
    };
    Box::pin(fork_through_proxy_body(std::sync::Arc::new(b))).await;
}
