//! v62.0.0 (wave T1) — **a group's statements replicate to its members**, on
//! sqlite and postgres. A group voice maps to no attestation row
//! ([`super::group`]); `serve::servable_to` decides its audience from the
//! statement ([`super::group_serve`]).
//!
//! - **I3006** a founding roster voice still gathering voices (`Pending`)
//!   is served to the members it lists, so they can sign it; it is not
//!   served to a stranger, nor to an anonymous read.
//! - **I3007** a landed roster is served to a member and not to a stranger
//!   (E4's I1488 shape).
//! - **I3008** a removal is served to the removed member (the member it
//!   names) and to a member, and not to a stranger.
//! - **I3011** an INVITEE is served its own invitation: the proposal is
//!   DELIVERED to its key, so it is in the audience before it joins (CC 2.1);
//!   the founder is served it, a stranger is not. And there is no blanket
//!   "about the requester" rule: a moderation row at the family's scope naming
//!   a non-member subject is not served to that subject.
//! - **I3013** the copy rule (CC 2.7.5): an invitation citing its family's
//!   roster head carries the head to the invitee (the head's own rule
//!   withholds it); not to a stranger, never to an anonymous read.
//! - **I3010** a statement-only row is served by the `cohort_scope` its
//!   payload states (CC: `admission:unit` like any scores row): `self` to
//!   its author only (not another key, not anonymous), `federation` to
//!   anyone, and no stated scope as `federation` (the attestation default).
//! - **I3009** a `cosign:pending` voice (no scope of its own) is served to
//!   the audience of the group event it cosigns: a member, not a stranger,
//!   not an anonymous read.

use chrono::{TimeZone, Utc};
use ciris_crypto::composite::CompositeSigningKey;
use ciris_verify_core::cde::Value;

use super::door_invariants::fixture::{iref, key, key_record};
use super::group::{
    membership_payload, roster_payload, GroupRecord, MembershipRecord, GROUP_ROSTER_PREFIX,
    MEMBERSHIP_PREFIX,
};
use super::ingest::{put_statement, StatementOutcome, INGEST_TIER};
use super::serve::servable_to;
use crate::federation::types::{Family, FamilyMember, FamilyMembershipRevocation};
use crate::federation::FederationDirectory;

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

async fn put(d: &dyn FederationDirectory, st: &[u8]) -> StatementOutcome {
    put_statement(d, st, None, INGEST_TIER).await.unwrap()
}

async fn served(d: &dyn FederationDirectory, st: &[u8], to: Option<&K>) -> bool {
    let peer = to.map(iref);
    servable_to(d, st, peer.as_deref()).await.unwrap()
}

pub(crate) async fn body(d: &dyn FederationDirectory) {
    let (a, b, c, stranger, g) = (key(211), key(212), key(213), key(214), key(215));
    for k in [&a, &b, &c, &stranger] {
        put_statement(d, &key_record(k, &["user"], 0, None), None, INGEST_TIER)
            .await
            .unwrap();
    }
    let gid = iref(&g);
    let record = GroupRecord::Family(Family {
        family_key_id: gid.clone(),
        family_name: "served".into(),
        members: [&a, &b, &c]
            .iter()
            .map(|k| FamilyMember {
                key_id: iref(k),
                joined_at: at(1_000),
                role: None,
            })
            .collect(),
        founded_at: at(1_000),
        consensus_protocol: "majority".into(),
        consensus_protocol_entrenched: false,
        dissolved_at: None,
        prev_head_digest: String::new(),
        charter_digest: String::new(),
        persist_row_hash: String::new(),
    });
    let p = roster_payload(&record, 1, None, 2_000).unwrap();
    let voices: Vec<Vec<u8>> = [&a, &b, &c]
        .iter()
        .map(|k| sign(k, &gid, GROUP_ROSTER_PREFIX, &p))
        .collect();

    // I3006 — pending, served to the members it lists.
    let o = put(d, &voices[0]).await;
    assert!(matches!(o, StatementOutcome::Pending { .. }), "I3006 {o:?}");
    assert!(
        d.get_attestation(&super::names::RowId::of_statement(&voices[0]).unwrap().hex())
            .await
            .unwrap()
            .is_none(),
        "I3006 a group voice maps to no attestation row"
    );
    assert!(
        served(d, &voices[0], Some(&b)).await,
        "I3006 a listed member"
    );
    assert!(
        !served(d, &voices[0], Some(&stranger)).await,
        "I3006 a stranger"
    );
    assert!(!served(d, &voices[0], None).await, "I3006 anonymous");

    // I3007 — landed, served to a member and not to a stranger.
    put(d, &voices[1]).await;
    let o = put(d, &voices[2]).await;
    let StatementOutcome::Row { row_id: head, .. } = o else {
        panic!("I3007 landed: {o:?}");
    };
    for v in &voices {
        assert!(served(d, v, Some(&a)).await, "I3007 a member");
        assert!(served(d, v, Some(&c)).await, "I3007 a member");
        assert!(!served(d, v, Some(&stranger)).await, "I3007 a stranger");
    }

    // I3008 — a removal, served to the removed member.
    let removal = MembershipRecord::FamilyRemoval(FamilyMembershipRevocation {
        family_key_id: gid.clone(),
        removed_identity_key_id: iref(&c),
        removed_at: at(5_000),
        effective_at: at(5_000),
        reason: None,
        witness_set: Vec::new(),
        persist_row_hash: String::new(),
    });
    let mp = membership_payload(&removal, Some(&head)).unwrap();
    let rv: Vec<Vec<u8>> = [&a, &b]
        .iter()
        .map(|k| sign(k, &iref(&c), MEMBERSHIP_PREFIX, &mp))
        .collect();
    put(d, &rv[0]).await;
    let o = put(d, &rv[1]).await;
    assert!(
        matches!(o, StatementOutcome::Row { .. }),
        "I3008 landed: {o:?}"
    );
    for v in &rv {
        assert!(served(d, v, Some(&c)).await, "I3008 the removed member");
        assert!(served(d, v, Some(&a)).await, "I3008 a member");
        assert!(!served(d, v, Some(&stranger)).await, "I3008 a stranger");
    }

    // I3009 — a cosign over the roster event follows the event's audience.
    super::fixture_switch::put_key(d, "t1-cosigner", &["user"]).await;
    let cosign =
        super::typed_fixtures::cosign_statement("t1-cosigner", "pending", &gid, &head, 6_000);
    put_statement(d, &cosign, None, INGEST_TIER)
        .await
        .unwrap_or_else(|e| panic!("I3009 the cosign is held: {e:?}"));
    assert!(
        d.get_attestation(&super::names::RowId::of_statement(&cosign).unwrap().hex())
            .await
            .unwrap()
            .is_none(),
        "I3009 a cosign maps to no attestation row"
    );
    assert!(
        served(d, &cosign, Some(&a)).await,
        "I3009 a member of the event's group"
    );
    assert!(
        !served(d, &cosign, Some(&stranger)).await,
        "I3009 a stranger"
    );
    assert!(!served(d, &cosign, None).await, "I3009 anonymous");
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i3006_i3009_group_voices_served_sqlite() {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(body(&b)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i3006_i3009_group_voices_served_postgres() {
    use crate::store::Backend as _;
    let Some(dsn) = crate::test_pg::empty_dsn() else {
        return;
    };
    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(body(&b)).await;
}

/// I3010 — the scope rule for a statement that maps to no row.
pub(crate) async fn scope_body(d: &dyn FederationDirectory) {
    let (author, other) = (key(221), key(222));
    for k in [&author, &other] {
        put_statement(d, &key_record(k, &["user"], 0, None), None, INGEST_TIER)
            .await
            .unwrap();
    }
    let unit = |scope: Option<&str>| {
        let mut m = vec![
            ("asserted_at", Value::Uint(3_000)),
            ("author", Value::Text(iref(&author))),
            ("dimension", Value::Text("admission:unit:v1".into())),
        ];
        if let Some(s) = scope {
            m.push(("cohort_scope", Value::Text(s.into())));
        }
        sign(
            &author,
            &iref(&author),
            "admission:unit",
            &super::door_invariants::fixture::map(m),
        )
    };
    // Never put: the serve rule reads the statement alone (no row is held).
    let own = unit(Some("self"));
    assert!(
        served(d, &own, Some(&author)).await,
        "I3010 self: its author"
    );
    assert!(
        !served(d, &own, Some(&other)).await,
        "I3010 self: not another key"
    );
    assert!(!served(d, &own, None).await, "I3010 self: not anonymous");
    let commons = unit(Some("federation"));
    assert!(
        served(d, &commons, Some(&other)).await,
        "I3010 federation: anyone"
    );
    assert!(
        served(d, &commons, None).await,
        "I3010 federation: anonymous too"
    );
    let none = unit(None);
    assert!(
        served(d, &none, Some(&other)).await,
        "I3010 no scope: served as federation, to anyone"
    );
    assert!(
        served(d, &none, None).await,
        "I3010 no scope: served as federation, anonymous too"
    );
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i3010_statement_scope_served_sqlite() {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(scope_body(&b)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i3010_statement_scope_served_postgres() {
    use crate::store::Backend as _;
    let Some(dsn) = crate::test_pg::empty_dsn() else {
        return;
    };
    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(scope_body(&b)).await;
}

/// I3011 — an invitee is served the invitation about it.
pub(crate) async fn invitee_body(d: &dyn FederationDirectory) {
    use super::fixture_switch as e2;
    use crate::federation::membership_acceptance::test_support::proposal_row;
    let founder = e2::put_key(d, "t1s-founder", &["user"]).await;
    let joiner = e2::put_key(d, "t1s-joiner", &["user"]).await;
    let stranger = e2::put_key(d, "t1s-stranger", &["user"]).await;
    let kf = e2::signing_key("t1s-founder");
    let g = key(231);
    let gid = iref(&g);
    let record = GroupRecord::Family(Family {
        family_key_id: gid.clone(),
        family_name: "inviting".into(),
        members: vec![FamilyMember {
            key_id: founder.clone(),
            joined_at: at(1_000),
            role: Some("founder".into()),
        }],
        founded_at: at(1_000),
        consensus_protocol: "founder_only".into(),
        consensus_protocol_entrenched: false,
        dissolved_at: None,
        prev_head_digest: String::new(),
        charter_digest: String::new(),
        persist_row_hash: String::new(),
    });
    let p = roster_payload(&record, 1, None, 2_000).unwrap();
    let o = put(d, &sign(&kf, &gid, GROUP_ROSTER_PREFIX, &p)).await;
    assert!(
        matches!(o, StatementOutcome::Row { .. }),
        "I3011 founded: {o:?}"
    );

    let invitation = proposal_row("t1s-founder", "family", &gid, &joiner, None, at(6_000));
    e2::put_signed(d, &invitation)
        .await
        .unwrap_or_else(|e| panic!("I3011 the invitation is held: {e:?}"));
    let st = e2::carried_statement(&invitation).expect("I3011 a flipped row carries its statement");
    let st = &st;
    let served_to = |k: String| async move { servable_to(d, st, Some(&k)).await.unwrap() };
    assert!(served_to(joiner.clone()).await, "I3011 the invitee");
    assert!(served_to(founder.clone()).await, "I3011 a member");
    assert!(!served_to(stranger.clone()).await, "I3011 a stranger");

    // CC 2.1: no blanket "served to anyone it names". A moderation row at the
    // family's scope naming a NON-member subject (outside its audience; the
    // admission rule holds it `subject_outside_audience`, so it is never
    // put here) is not served to that subject: the delivered key is an
    // invitee's, a grant recipient's or an owner-binding's node, never a
    // subject's.
    let moderation = super::door_invariants::fixture::map(vec![
        ("asserted_at", Value::Uint(7_000)),
        ("author", Value::Text(founder.clone())),
        ("cohort_scope", Value::Text("family".into())),
        ("family_id", Value::Text(gid.clone())),
        (
            "subject_key_ids",
            Value::Array(vec![Value::Text(stranger.clone())]),
        ),
    ]);
    let mst = ciris_verify_core::edition2::sign_row_statement(
        &kf,
        &founder,
        &stranger,
        "scores",
        "moderation:.action",
        &moderation,
        vec![],
    )
    .unwrap();
    assert!(
        !servable_to(d, &mst, Some(&stranger)).await.unwrap(),
        "I3011 a moderation row is not served to a non-member subject"
    );
    assert!(
        !servable_to(d, &mst, None).await.unwrap(),
        "I3011 nor to an anonymous read"
    );
}

/// I3013 — the copy rule (CC 2.7.5): a row carries its audience to the rows
/// it names. An invitation that cites the family's roster head
/// (`refs.also.cites`) is concluded, sits in the family's room, and its
/// signer (the founder) is in the head's audience: so the head, which its own
/// rule withholds from the invitee (not a member, not listed), is served to
/// the invitee with the invitation, and still not to a stranger.
pub(crate) async fn carried_body(d: &dyn FederationDirectory) {
    use super::fixture_switch as e2;
    use crate::federation::membership_acceptance::test_support::proposal_row;
    let founder = e2::put_key(d, "t1c-founder", &["user"]).await;
    let joiner = e2::put_key(d, "t1c-joiner", &["user"]).await;
    let stranger = e2::put_key(d, "t1c-stranger", &["user"]).await;
    let kf = e2::signing_key("t1c-founder");
    let g = key(232);
    let gid = iref(&g);
    let record = GroupRecord::Family(Family {
        family_key_id: gid.clone(),
        family_name: "citing".into(),
        members: vec![FamilyMember {
            key_id: founder.clone(),
            joined_at: at(1_000),
            role: Some("founder".into()),
        }],
        founded_at: at(1_000),
        consensus_protocol: "founder_only".into(),
        consensus_protocol_entrenched: false,
        dissolved_at: None,
        prev_head_digest: String::new(),
        charter_digest: String::new(),
        persist_row_hash: String::new(),
    });
    let p = roster_payload(&record, 1, None, 2_000).unwrap();
    let head_st = sign(&kf, &gid, GROUP_ROSTER_PREFIX, &p);
    let StatementOutcome::Row { row_id: head, .. } = put(d, &head_st).await else {
        panic!("I3013 founded");
    };
    let head_st = &head_st;
    let served = |k: String| async move { servable_to(d, head_st, Some(&k)).await.unwrap() };
    assert!(
        !served(joiner.clone()).await,
        "I3013 before: the head's own rule withholds it from the invitee"
    );

    // The invitation, citing the head it stands on.
    // CP2 skeleton: the builder's unsigned shape, re-signed as edition 2
    // (`row_of`) before any door.
    let mut literal = e2::with_earlier_form(|| {
        proposal_row("t1c-founder", "family", &gid, &joiner, None, at(6_000))
    });
    if let Some(o) = literal.attestation_envelope.as_object_mut() {
        o.insert(
            "refs".to_owned(),
            serde_json::json!({ "also": { "cites": [[2, [-16, head.hex()]]] } }),
        );
    }
    let invitation = e2::row_of(&literal, "t1c-founder");
    e2::put_signed(d, &invitation)
        .await
        .unwrap_or_else(|e| panic!("I3013 the citing invitation is held: {e:?}"));
    assert!(
        served(joiner.clone()).await,
        "I3013 the cited head travels with the invitation to the invitee"
    );
    assert!(served(founder.clone()).await, "I3013 a member, as before");
    assert!(
        !served(stranger.clone()).await,
        "I3013 not to a stranger: the invitation is not served to it"
    );
    assert!(
        !servable_to(d, head_st, None).await.unwrap(),
        "I3013 never to an anonymous read"
    );
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i3011_invitee_served_sqlite() {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(invitee_body(&b)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i3011_invitee_served_postgres() {
    use crate::store::Backend as _;
    let Some(dsn) = crate::test_pg::empty_dsn() else {
        return;
    };
    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(invitee_body(&b)).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i3013_cited_ancestor_carried_sqlite() {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(carried_body(&b)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i3013_cited_ancestor_carried_postgres() {
    use crate::store::Backend as _;
    let Some(dsn) = crate::test_pg::empty_dsn() else {
        return;
    };
    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(carried_body(&b)).await;
}
