//! v62.0.0 (wave GC6; CC 2.7.2, 2.7.3) — **the membership replies are a
//! fold**, on sqlite and postgres. Through the edition-2 door
//! (`fixture_switch::put_signed`, a fold attempt), never the earlier-form JSON
//! door (whose refusals are unchanged and witnessed by I211/I213).
//!
//! - **I3871** a reply naming a proposal this node does not hold is HELD
//!   (`membership_proposal_unresolved`, no typed row), and CONCLUDES by the
//!   re-fold when the proposal lands; proposal first, it concludes at once.
//!   Either arrival order ends with both rows concluded.
//! - **I3872** two opposite replies of one member to one proposal: the
//!   EARLIER-SIGNED stands and the later is held
//!   (`membership_reply_conflict`), whichever arrived first. Later-signed
//!   first, it concludes, and is UN-concluded (re-folded out of its typed
//!   table, its statement still held) when the earlier one lands.
//! - **I3873** (CC 2.7 rc21 X14) a public room joiner's acceptance of the
//!   founder's STANDING proposal counts only from a key with a live
//!   federation-scope owner binding: without one it is HELD
//!   (`joiner_owner_unbound`); it concludes by the re-fold when the binding
//!   lands, concludes at once when the binding came first (the same end
//!   state), and is UN-concluded when the owner withdraws the binding.

use chrono::{Duration, Utc};

use super::edition2::fixture_switch as e2;
use super::edition2::fold::{self, reason};
use super::edition2::ingest::StatementOutcome;
use super::edition2::names::RowId;
use super::membership_acceptance_invariants::bodies::{
    found_community, found_public_room, proposal, reg, reply,
};
use super::types::cohort_scope::COMMUNITY;
use super::types::{attestation_type, identity_type};
use super::{Attestation, FederationDirectory};

fn id_of(row: &Attestation) -> RowId {
    super::edition2::voices::carried_row_id(row).expect("GC6: the row carries its statement")
}

async fn concluded(d: &dyn FederationDirectory, row: &Attestation) -> bool {
    d.get_attestation(&id_of(row).hex())
        .await
        .unwrap()
        .is_some()
}

async fn held_reason(d: &dyn FederationDirectory, row: &Attestation) -> Option<String> {
    fold::why_held(d, &id_of(row))
        .await
        .unwrap()
        .map(|h| h.reason)
}

fn suffix() -> String {
    uuid::Uuid::new_v4().simple().to_string()[..10].to_owned()
}

/// A room founded by `founder` and its proposal inviting `k`.
async fn room_and_proposal(d: &dyn FederationDirectory, tag: &str) -> (String, Attestation) {
    let s = suffix();
    let (cid, founder, k) = (
        format!("{tag}-c-{s}"),
        format!("{tag}-f-{s}"),
        format!("{tag}-k-{s}"),
    );
    reg(d, &[&cid, &founder, &k]).await;
    found_community(d, &cid, "quorum:1/1", &[&founder], &[])
        .await
        .expect("GC6: the founder founds the room");
    let p = proposal(
        &founder,
        COMMUNITY,
        &cid,
        &k,
        None,
        Utc::now() - Duration::minutes(10),
        Some(Duration::days(7)),
    );
    (k, p)
}

/// I3871 — reply first: held, then concluded when the proposal lands.
pub(crate) async fn reply_first_body(d: &dyn FederationDirectory) {
    let (k, p) = room_and_proposal(d, "i3871a").await;
    let early = reply(&k, &k, &p, true, Utc::now() - Duration::minutes(5));
    let o = e2::put_signed(d, &early)
        .await
        .expect("I3871: a reply ahead of its proposal is HELD, never refused");
    assert!(
        matches!(o, StatementOutcome::Pending { .. }),
        "I3871: held: {o:?}"
    );
    assert!(!concluded(d, &early).await, "I3871: no typed row");
    assert_eq!(
        held_reason(d, &early).await.as_deref(),
        Some(reason::MEMBERSHIP_PROPOSAL_UNRESOLVED),
        "I3871: the reason is the refusal token it replaces"
    );
    let o = e2::put_signed(d, &p).await.expect("I3871: the proposal");
    assert!(
        matches!(o, StatementOutcome::Row { .. }),
        "I3871: the proposal concludes: {o:?}"
    );
    assert!(
        concluded(d, &early).await,
        "I3871: the re-fold concludes the reply when its proposal lands"
    );
    assert_eq!(held_reason(d, &early).await, None, "I3871: no reason left");
}

/// I3871 — proposal first: the reply concludes at once (the same end state).
pub(crate) async fn proposal_first_body(d: &dyn FederationDirectory) {
    let (k, p) = room_and_proposal(d, "i3871b").await;
    let o = e2::put_signed(d, &p).await.expect("I3871: the proposal");
    assert!(matches!(o, StatementOutcome::Row { .. }), "I3871: {o:?}");
    let r = reply(&k, &k, &p, true, Utc::now() - Duration::minutes(5));
    let o = e2::put_signed(d, &r).await.expect("I3871: the reply");
    assert!(
        matches!(o, StatementOutcome::Row { .. }),
        "I3871: concluded at once: {o:?}"
    );
    assert!(
        concluded(d, &p).await && concluded(d, &r).await,
        "I3871: both rows concluded, as when the reply came first"
    );
}

/// I3872 — the later-signed acceptance arrives FIRST: it concludes, then the
/// earlier-signed decline lands and un-concludes it.
pub(crate) async fn later_first_body(d: &dyn FederationDirectory) {
    let (k, p) = room_and_proposal(d, "i3872a").await;
    e2::put_signed(d, &p).await.expect("I3872: the proposal");
    let decline = reply(&k, &k, &p, false, Utc::now() - Duration::minutes(5));
    let accept = reply(&k, &k, &p, true, Utc::now() - Duration::minutes(1));
    let o = e2::put_signed(d, &accept)
        .await
        .expect("I3872: the later acceptance");
    assert!(
        matches!(o, StatementOutcome::Row { .. }),
        "I3872: nothing earlier stands against it yet: {o:?}"
    );
    let o = e2::put_signed(d, &decline)
        .await
        .expect("I3872: the earlier decline");
    assert!(
        matches!(o, StatementOutcome::Row { .. }),
        "I3872: the earlier-signed reply concludes: {o:?}"
    );
    assert!(concluded(d, &decline).await, "I3872: the decline stands");
    assert!(
        !concluded(d, &accept).await,
        "I3872: the later acceptance is UN-concluded"
    );
    assert_eq!(
        held_reason(d, &accept).await.as_deref(),
        Some(reason::MEMBERSHIP_REPLY_CONFLICT),
        "I3872: held, and says why"
    );
    assert!(
        !d.edition2_voices(&id_of(&accept)).await.unwrap().is_empty(),
        "I3872: its statement is still held"
    );
}

/// I3872 — the earlier-signed decline arrives first: the later acceptance is
/// held at once (the same end state).
pub(crate) async fn earlier_first_body(d: &dyn FederationDirectory) {
    let (k, p) = room_and_proposal(d, "i3872b").await;
    e2::put_signed(d, &p).await.expect("I3872: the proposal");
    let decline = reply(&k, &k, &p, false, Utc::now() - Duration::minutes(5));
    let accept = reply(&k, &k, &p, true, Utc::now() - Duration::minutes(1));
    let o = e2::put_signed(d, &decline).await.expect("I3872: decline");
    assert!(matches!(o, StatementOutcome::Row { .. }), "I3872: {o:?}");
    let o = e2::put_signed(d, &accept)
        .await
        .expect("I3872: the later acceptance is HELD, never refused");
    assert!(
        matches!(o, StatementOutcome::Pending { .. }),
        "I3872: held: {o:?}"
    );
    assert!(
        concluded(d, &decline).await && !concluded(d, &accept).await,
        "I3872: the same concluded set as the other order"
    );
    assert_eq!(
        held_reason(d, &accept).await.as_deref(),
        Some(reason::MEMBERSHIP_REPLY_CONFLICT),
        "I3872: the reason"
    );
}

/// An open public room, its founder's standing proposal, a joiner NODE key
/// and its (user) owner; the joiner's acceptance and the owner binding over
/// the joiner, not yet put.
async fn public_room_joiner(
    d: &dyn FederationDirectory,
    tag: &str,
) -> (Attestation, Attestation, String, String) {
    let s = suffix();
    let (cid, founder, owner, joiner) = (
        format!("{tag}-c-{s}"),
        format!("{tag}-f-{s}"),
        format!("{tag}-o-{s}"),
        format!("{tag}-j-{s}"),
    );
    reg(d, &[&cid, &founder]).await;
    let _ = e2::put_key(d, &owner, &[identity_type::USER]).await;
    let _ = e2::put_key(d, &joiner, &[identity_type::NODE]).await;
    found_public_room(
        d,
        &cid,
        super::types::consensus_protocol::OPEN_SELF_ADMIT,
        &[&founder],
        &[],
    )
    .await
    .expect("I3873: an open public room");
    let at = Utc::now() - Duration::hours(1);
    let mut p = proposal(
        &founder,
        COMMUNITY,
        &cid,
        "",
        None,
        at,
        Some(Duration::days(7)),
    );
    p.subject_key_ids.clear();
    crate::federation::tier_ingest::test_support::seal_row_in_place(&founder, &mut p);
    let o = e2::put_signed(d, &p)
        .await
        .expect("I3873: the founder's standing proposal");
    assert!(matches!(o, StatementOutcome::Row { .. }), "I3873: {o:?}");
    let acc = reply(&joiner, &joiner, &p, true, at + Duration::seconds(1));
    let binding = crate::federation::tier_ingest::test_support::owner_binding_attestation(
        &uuid::Uuid::new_v4().to_string(),
        &owner,
        &joiner,
    );
    (acc, binding, owner, joiner)
}

/// Land the owner binding over `node`: the owner's voice, then the node's.
async fn land_binding(d: &dyn FederationDirectory, binding: &Attestation, node: &str) {
    let _ = e2::put_signed(d, binding)
        .await
        .expect("I3873: the owner's voice over the binding");
    let st = e2::carried_statement(binding).expect("I3873: the binding's statement");
    let o = e2::put_statement(d, &e2::voice_of(&st, node))
        .await
        .expect("I3873: the node's voice over its binding");
    assert!(
        matches!(o, StatementOutcome::Row { .. }),
        "I3873: the binding lands: {o:?}"
    );
}

/// I3873 — acceptance first: held, concluded when the binding lands, and
/// un-concluded when the owner withdraws it.
pub(crate) async fn joiner_first_body(d: &dyn FederationDirectory) {
    let (acc, binding, owner, joiner) = public_room_joiner(d, "i3873a").await;
    let o = e2::put_signed(d, &acc)
        .await
        .expect("I3873: an unbound joiner's acceptance is HELD, never refused");
    assert!(
        matches!(o, StatementOutcome::Pending { .. }),
        "I3873: held: {o:?}"
    );
    assert!(!concluded(d, &acc).await, "I3873: it does not count");
    assert_eq!(
        held_reason(d, &acc).await.as_deref(),
        Some(reason::JOINER_OWNER_UNBOUND),
        "I3873: the reason"
    );
    land_binding(d, &binding, &joiner).await;
    assert!(
        concluded(d, &acc).await,
        "I3873: the re-fold concludes it when the binding lands"
    );
    let w = e2::composer_of(attestation_type::WITHDRAWS, &binding, &owner);
    let o = e2::put_signed(d, &w)
        .await
        .expect("I3873: the owner withdraws the binding");
    assert!(matches!(o, StatementOutcome::Row { .. }), "I3873: {o:?}");
    assert!(
        !concluded(d, &acc).await,
        "I3873: the withdrawal UN-concludes the acceptance"
    );
    assert_eq!(
        held_reason(d, &acc).await.as_deref(),
        Some(reason::JOINER_OWNER_UNBOUND),
        "I3873: held again, for the same reason"
    );
}

/// I3873 — binding first: the acceptance concludes at once.
pub(crate) async fn binding_first_body(d: &dyn FederationDirectory) {
    let (acc, binding, _owner, joiner) = public_room_joiner(d, "i3873b").await;
    land_binding(d, &binding, &joiner).await;
    let o = e2::put_signed(d, &acc)
        .await
        .expect("I3873: a bound joiner's acceptance");
    assert!(
        matches!(o, StatementOutcome::Row { .. }),
        "I3873: concluded at once, as when the acceptance came first: {o:?}"
    );
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

macro_rules! both {
    ($sq:ident, $pg:ident, $body:path) => {
        #[cfg(feature = "sqlite")]
        #[tokio::test]
        async fn $sq() {
            Box::pin($body(&sqlite().await)).await;
        }

        #[cfg(feature = "postgres")]
        #[tokio::test]
        async fn $pg() {
            let Some(b) = postgres().await else {
                return;
            };
            Box::pin($body(&b)).await;
        }
    };
}

both!(
    i3871_reply_first_held_then_concluded_sqlite,
    i3871_reply_first_held_then_concluded_postgres,
    reply_first_body
);
both!(
    i3871_proposal_first_concluded_sqlite,
    i3871_proposal_first_concluded_postgres,
    proposal_first_body
);
both!(
    i3872_later_reply_first_unconcluded_by_the_earlier_sqlite,
    i3872_later_reply_first_unconcluded_by_the_earlier_postgres,
    later_first_body
);
both!(
    i3872_earlier_reply_first_later_held_sqlite,
    i3872_earlier_reply_first_later_held_postgres,
    earlier_first_body
);
both!(
    i3873_joiner_first_held_then_concluded_then_withdrawn_sqlite,
    i3873_joiner_first_held_then_concluded_then_withdrawn_postgres,
    joiner_first_body
);
both!(
    i3873_binding_first_concluded_sqlite,
    i3873_binding_first_concluded_postgres,
    binding_first_body
);
