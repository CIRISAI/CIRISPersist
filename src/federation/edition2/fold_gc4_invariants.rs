//! v62.0.0 (wave GC4; CC 2.7) — witnesses of the GC4 conversions to the
//! held/concluded fold ([`super::fold`]). Each store-facing body runs on
//! sqlite and postgres. (The halt replay's order witness, I3790/I3791, is in
//! `halt_invariants`, beside the halt door's own fixtures.)
//!
//! - **I3792** GC4's reason tokens are its `reason::gc4` slice, in order,
//!   registered (`reason::is_registered`), none a core token, none repeated.
//! - **I3793** `hold_refusal` marks a fold refusal and lets a substrate
//!   failure through unmarked; `hold_detail` marks without an error.
//! - **I3794** the community-trust capture grant, binding FIRST: the node's
//!   own grant naming the node, its owner and its agent concludes.
//! - **I3795** the capture grant, grant FIRST: HELD
//!   `community_trust_owner_unbound` (never refused), still held while the
//!   owner binding is short of the node's voice, and concluded by the
//!   re-fold when the binding lands. With I3794, the concluded set is the
//!   same in either arrival order. (No un-conclusion leg: by CC 3.3.1 the
//!   grant reads the owner AT ITS OWN INSTANT, so a later withdrawal of the
//!   binding does not un-admit it — `owner_granters_in_force_at`.)

use super::fixture_switch as e2;
use super::fold::{self, reason};
use super::ingest::StatementOutcome;
use super::names::RowId;
use crate::federation::types::{identity_type, Attestation};
use crate::federation::{Error, FederationDirectory};

/// I3792: GC4's tokens, in `reason::gc4::ALL`, registered, none core.
#[test]
fn i3792_gc4_reason_tokens_are_appended_in_order() {
    let gc4 = [
        "group_record_withdraws_refused",
        "conflicting_record",
        "degrades_conformance",
        "not_in_audience",
        "held_object_differs",
        "community_trust_owner_unbound",
        "community_trust_attester_not_owner",
        "community_trust_owner_unlisted",
        "community_trust_subjects_incomplete",
        "identity_amendment_unauthorized",
        "serve_transit_pair_rotation_before_rebind",
        "accord_invocation_replayed",
    ];
    assert_eq!(
        reason::gc4::ALL,
        &gc4[..],
        "I3792: GC4's tokens, in append order, in its own registry slice"
    );
    for t in gc4 {
        assert!(reason::is_registered(t), "I3792: {t} is registered");
        assert!(
            !reason::ALL.contains(&t),
            "I3792: {t} is a wave token, not a core one"
        );
    }
    let mut seen = std::collections::BTreeSet::new();
    for t in reason::gc4::ALL {
        assert!(seen.insert(*t), "I3792: {t} is in GC4's slice once");
    }
}

/// I3793: the GC4 helpers.
#[tokio::test]
async fn i3793_hold_refusal_and_hold_detail() {
    let (out, att) = fold::attempt(RowId([9; 32]), None, async {
        let substrate = fold::hold_refusal(
            reason::GROUP_DISSOLVED,
            Error::Backend("pool closed".into()),
        );
        assert!(
            matches!(substrate, Error::Backend(_)),
            "I3793: a substrate failure comes back unchanged"
        );
        Err::<(), Error>(substrate)
    })
    .await;
    assert!(out.is_err(), "I3793: the error is returned");
    assert!(
        att.held.is_none(),
        "I3793: a substrate failure is never a fold condition"
    );

    let (_, att) = fold::attempt(RowId([9; 32]), None, async {
        Err::<(), Error>(fold::hold_refusal(
            reason::GROUP_DISSOLVED,
            Error::InvalidArgument("dissolved".into()),
        ))
    })
    .await;
    assert_eq!(
        att.held.map(|(r, _)| r).as_deref(),
        Some(reason::GROUP_DISSOLVED),
        "I3793: a refusal is held with the reason"
    );

    let (_, att) = fold::attempt(RowId([9; 32]), None, async {
        fold::hold_detail(reason::NOT_IN_AUDIENCE, "not party");
    })
    .await;
    assert_eq!(
        att.held,
        Some((reason::NOT_IN_AUDIENCE.to_owned(), "not party".to_owned())),
        "I3793: hold_detail marks with its detail"
    );
}

fn id_of(row: &Attestation) -> RowId {
    super::voices::carried_row_id(row).expect("GC4: the row carries its statement")
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

fn pending(o: &StatementOutcome) -> bool {
    matches!(o, StatementOutcome::Pending { .. })
}

/// The owner binding of `owner` over `node` (the owner's statement).
fn owner_binding(owner: &str, node: &str) -> Attestation {
    // G0-fix3/fix4 — K2's builder, dated from the key-window rule (the
    // shared fixture's fixed 2026-05-01 was before a node key's window).
    super::fold_invariants::owner_binding(owner, node)
}

/// The node's own capture grant naming the node, its owner and its agent.
fn grant(node: &str, owner: &str, agent: &str) -> Attestation {
    let mut a = crate::federation::genesis::ordinary_scores_row(
        &uuid::Uuid::new_v4().to_string(),
        &e2::kid(node),
    );
    a.attested_key_id = e2::kid(node);
    a.attestation_envelope = serde_json::json!({
        "id": a.attestation_id,
        "dimension": crate::federation::community_trust_consent::COMMUNITY_TRUST_DIMENSION,
        "score": 1.0,
    });
    a.subject_key_ids = vec![e2::kid(node), e2::kid(owner), e2::kid(agent)];
    e2::row_of(&a, node)
}

/// Land the owner binding: the owner's voice (held), then the node's.
async fn land_binding(d: &dyn FederationDirectory, binding: &Attestation, node: &str) {
    let o = e2::put_signed(d, binding)
        .await
        .expect("GC4: the owner's voice over the binding is kept");
    assert!(pending(&o), "GC4: the binding waits for the node: {o:?}");
    let st = e2::carried_statement(binding).expect("GC4: the binding's statement");
    let o = e2::put_statement(d, &e2::voice_of(&st, node))
        .await
        .expect("GC4: the node's voice over its binding");
    assert!(
        matches!(o, StatementOutcome::Row { .. }),
        "GC4: the node's voice lands the binding: {o:?}"
    );
}

async fn keys(d: &dyn FederationDirectory, owner: &str, node: &str, agent: &str) {
    let _ = e2::put_key(d, owner, &[identity_type::USER]).await;
    let _ = e2::put_key(d, node, &[identity_type::NODE]).await;
    let _ = e2::put_key(d, agent, &[identity_type::AGENT]).await;
}

/// I3794: binding first; the grant concludes.
pub(crate) async fn trust_binding_first_body(d: &dyn FederationDirectory) {
    let (owner, node, agent) = ("gc4-ct1-o", "gc4-ct1-n", "gc4-ct1-a");
    keys(d, owner, node, agent).await;
    land_binding(d, &owner_binding(owner, node), node).await;
    let g = grant(node, owner, agent);
    let o = e2::put_signed(d, &g)
        .await
        .expect("I3794: the node's grant");
    assert!(
        matches!(o, StatementOutcome::Row { .. }),
        "I3794: concluded: {o:?}"
    );
    assert!(concluded(d, &g).await, "I3794: the typed row is held");
    assert_eq!(held_reason(d, &g).await, None, "I3794: no reason");
}

/// I3795: grant first; held, then concluded by the re-fold.
pub(crate) async fn trust_grant_first_body(d: &dyn FederationDirectory) {
    let (owner, node, agent) = ("gc4-ct2-o", "gc4-ct2-n", "gc4-ct2-a");
    keys(d, owner, node, agent).await;
    let g = grant(node, owner, agent);
    let o = e2::put_signed(d, &g)
        .await
        .expect("I3795: a grant over an unbound node is HELD, never refused");
    assert!(pending(&o), "I3795: held: {o:?}");
    assert!(!concluded(d, &g).await, "I3795: no typed row");
    assert_eq!(
        held_reason(d, &g).await.as_deref(),
        Some(reason::COMMUNITY_TRUST_OWNER_UNBOUND),
        "I3795: the reason"
    );

    // The owner's voice alone: the binding is short; the grant stays held.
    let binding = owner_binding(owner, node);
    let o = e2::put_signed(d, &binding)
        .await
        .expect("I3795: the owner's voice");
    assert!(pending(&o), "I3795: the binding is held: {o:?}");
    assert!(
        !concluded(d, &g).await,
        "I3795: a held binding binds nobody: still held"
    );

    // The node's voice lands the binding; the re-fold concludes the grant.
    let st = e2::carried_statement(&binding).expect("I3795: statement");
    let o = e2::put_statement(d, &e2::voice_of(&st, node))
        .await
        .expect("I3795: the node's voice");
    assert!(
        matches!(o, StatementOutcome::Row { .. }),
        "I3795: the binding concludes: {o:?}"
    );
    assert!(
        concluded(d, &g).await,
        "I3795: the grant is concluded, as when the binding came first (I3794)"
    );
    assert_eq!(held_reason(d, &g).await, None, "I3795: no reason left");
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
    i3794_trust_grant_binding_first_sqlite,
    i3794_trust_grant_binding_first_postgres,
    trust_binding_first_body
);
both!(
    i3795_trust_grant_first_concludes_on_the_binding_sqlite,
    i3795_trust_grant_first_concludes_on_the_binding_postgres,
    trust_grant_first_body
);
