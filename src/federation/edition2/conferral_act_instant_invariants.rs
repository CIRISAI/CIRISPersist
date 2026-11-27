//! v62.0.0 (KR-fix19; CC 2.6.7 W, normative) — **I4319: an act under a
//! conferral is judged at its OWN signed instant, inside W, so two nodes
//! that receive it at different times agree.**
//!
//! "Every row whose admission walks a delegates_to chain … is judged at its
//! signed asserted_at at the node that receives it. That instant is
//! signer-chosen, so it is bounded." The doors that hold the act row
//! (`admission::check_reserved_prefix_admission`,
//! `admission::check_revocation_authority`) ask
//! `trust_root::conferred_for_act`; before, they asked the walk at the
//! node's clock, so an act signed while the grant stood and delivered after
//! its end was refused on the late node and admitted on the early one.
//!
//! Two nodes A and B, each holding the test bundle, accepting its root, and
//! holding the same worker, owner, counted grant, acceptance (at `T0`) and
//! the owner's withdrawal of the acceptance (dated `T0 + 2 s`), every row
//! through the statement door (B is given A's own statements). On BOTH:
//!
//! - an act dated `T0 + 1 s` (while the conferral stood), received at
//!   `T0 + 3 s` (after the withdrawal's instant, inside W): CONFERRED;
//! - the same act received more than W later: refused `asserted_at_stale`,
//!   a fold hold of that name;
//! - an act dated `T0 + 3 s` (after the withdrawal): not conferred, whenever
//!   received;
//! - an act dated before the acceptance: not conferred.
//!
//! The receiving clock is the function's `received_at`, stated per case, so
//! the two receipts are exact and no test sleeps.
//!
//! NOT witnessed through a statement: the doors' rules need scopes
//! (`infra:detect`, `infra:attest_assurance`, `infra:record_hard_case`,
//! `slash`) that the test bundle's charter (`infra:attest`, `infra:serve`)
//! cannot confer, so no reserved-family act can be driven to these doors
//! under a counted root grant in this tree. The shared function is asked
//! directly, with the scope the test charter does cover.

use chrono::{DateTime, Duration, Utc};

use super::fixture_genesis::install_v2;
use super::fixture_switch as e2;
use super::fold::{self, reason};
use super::names::RowId;
use super::scope_resolution_invariants::{
    accepting_node, grant_instant, land_grant, owner_accepts, worker_with_owner,
};
use crate::federation::self_roster::PAST_FRESHNESS_W_SECS;
use crate::federation::trust_root::conferred_for_act;
use crate::federation::types::attestation_type;
use crate::federation::FederationDirectory;

const SCOPE: &str = "infra:attest:build:registered";

/// `conferred_for_act`, run as a fold attempt: `(conferred, the refusal's
/// text, the held reason)`.
async fn judged(
    d: &dyn FederationDirectory,
    node: &str,
    worker: &str,
    act_at: DateTime<Utc>,
    received_at: DateTime<Utc>,
    tag: u8,
) -> (bool, Option<String>, Option<String>) {
    let (out, att) = fold::attempt(RowId([tag; 32]), None, async {
        conferred_for_act(d, node, worker, SCOPE, act_at, received_at).await
    })
    .await;
    let held = att.held.map(|(r, _)| r);
    match out {
        Ok(g) => (g.is_some(), None, held),
        Err(e) => (false, Some(e.to_string()), held),
    }
}

/// **I4319.**
pub(crate) async fn i4319_an_act_is_judged_at_its_own_instant_within_w(
    a: &dyn FederationDirectory,
    b: &dyn FederationDirectory,
) {
    // Both nodes first hold the bundle, accept its root and know the worker
    // and its owner: every standing row predates the acceptance's instant.
    let head = install_v2(a).await.expect("I4319: A installs").object_id;
    install_v2(b).await.expect("I4319: B installs");
    let nodes = [
        accepting_node(a, "kr-i4319-node-a").await,
        accepting_node(b, "kr-i4319-node-b").await,
    ];
    let (worker, owner) = worker_with_owner(a, "kr-i4319").await;
    let (worker_b, _) = worker_with_owner(b, "kr-i4319").await;
    assert_eq!(worker_b, worker, "I4319: one worker key on both nodes");

    // On A: the grant, the owner's acceptance (T0), the owner's withdrawal of
    // it (T0 + 2 s).
    let at = grant_instant(a).await;
    let grant = land_grant(a, &worker, SCOPE, &head, at, "I4319 A").await;
    owner_accepts(a, &owner, &grant, "I4319 A").await;
    let acc_id = crate::federation::admission::root_grants_for(
        a,
        &worker,
        crate::host::clock::now() + Duration::seconds(1),
    )
    .await
    .expect("I4319: root_grants_for")
    .first()
    .and_then(|g| g.acceptance_row_id.clone())
    .expect("I4319: the acceptance that gives the consent");
    let acc = a
        .get_attestation(&acc_id)
        .await
        .expect("I4319: reads")
        .expect("I4319: the acceptance is held");
    let t0 = acc.asserted_at;
    let w = e2::composer_of_at(
        attestation_type::WITHDRAWS,
        &acc,
        &owner,
        t0 + Duration::seconds(2),
    );
    // On B: the same grant (the same two voices), then A's own acceptance and
    // withdrawal statements.
    let grant_b = land_grant(b, &worker, SCOPE, &head, at, "I4319 B").await;
    assert_eq!(
        grant_b.attestation_id, grant.attestation_id,
        "I4319: one grant row on both nodes"
    );
    for (who, d) in [("A", a), ("B", b)] {
        if who == "B" {
            e2::put_signed(d, &acc)
                .await
                .unwrap_or_else(|e| panic!("I4319 {who}: the acceptance: {e}"));
        }
        e2::put_signed(d, &w)
            .await
            .unwrap_or_else(|e| panic!("I4319 {who}: the owner's withdrawal: {e}"));
        for (what, row) in [("the acceptance", &acc), ("the withdrawal", &w)] {
            let rid = RowId(e2::rid_digest(row));
            // KR-fix29 — on a red, name where the row went (held, and why;
            // or no fold record at all).
            assert!(
                d.get_attestation(&e2::rid(row))
                    .await
                    .expect("I4319: reads")
                    .is_some(),
                "I4319 {who}: {what} LANDED; fold state {:?}; held {:?}",
                d.fold_state(&rid).await,
                fold::why_held(d, &rid).await
            );
        }
    }

    let live = t0 + Duration::seconds(1);
    let after = t0 + Duration::seconds(3);
    let w_later = live + Duration::seconds(PAST_FRESHNESS_W_SECS) + Duration::hours(1);
    for (i, (who, d, node)) in [("A", a, &nodes[0]), ("B", b, &nodes[1])]
        .into_iter()
        .enumerate()
    {
        let tag = 0x50 + 8 * u8::try_from(i).expect("two nodes");
        // Signed while the conferral stood; received after the withdrawal's
        // instant, inside W.
        let (conferred, refused, held) = judged(d, node, &worker, live, after, tag).await;
        assert!(
            conferred && held.is_none(),
            "I4319 {who}: an act signed while the conferral stood, received after its end and \
             inside W, is CONFERRED: {refused:?} {held:?}"
        );
        // The same act, received more than W later.
        let (conferred, refused, held) = judged(d, node, &worker, live, w_later, tag + 1).await;
        assert!(
            !conferred
                && refused
                    .as_deref()
                    .is_some_and(|t| t.contains(reason::ASSERTED_AT_STALE)),
            "I4319 {who}: received more than W after its signed instant, with the conferral \
             ended: refused asserted_at_stale: {refused:?}"
        );
        assert_eq!(
            held.as_deref(),
            Some(reason::ASSERTED_AT_STALE),
            "I4319 {who}: and held under that name"
        );
        // Dated after the withdrawal: not conferred, whenever received.
        for (j, received) in [after + Duration::seconds(1), w_later]
            .into_iter()
            .enumerate()
        {
            let (conferred, refused, _) = judged(
                d,
                node,
                &worker,
                after,
                received,
                tag + 2 + u8::try_from(j).expect("two"),
            )
            .await;
            assert!(
                !conferred && refused.is_none(),
                "I4319 {who}: an act dated after the withdrawal is not conferred (received \
                 {received}): {refused:?}"
            );
        }
        // Dated before the acceptance: not conferred.
        let (conferred, _, _) =
            judged(d, node, &worker, t0 - Duration::seconds(1), after, tag + 4).await;
        assert!(
            !conferred,
            "I4319 {who}: an act dated before the acceptance is not conferred"
        );
    }
}

#[cfg(feature = "sqlite")]
mod sqlite {
    async fn store() -> crate::store::sqlite::SqliteBackend {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        b
    }

    #[tokio::test]
    async fn i4319_an_act_is_judged_at_its_own_instant_within_w_sqlite() {
        Box::pin(super::i4319_an_act_is_judged_at_its_own_instant_within_w(
            &store().await,
            &store().await,
        ))
        .await;
    }
}

#[cfg(feature = "postgres")]
mod postgres {
    async fn store() -> Option<crate::store::postgres::PostgresBackend> {
        use crate::store::Backend as _;
        let dsn = crate::test_pg::empty_dsn()?;
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    }

    #[tokio::test]
    async fn i4319_an_act_is_judged_at_its_own_instant_within_w_postgres() {
        let (Some(a), Some(b)) = (store().await, store().await) else {
            return;
        };
        Box::pin(super::i4319_an_act_is_judged_at_its_own_instant_within_w(
            &a, &b,
        ))
        .await;
    }
}
