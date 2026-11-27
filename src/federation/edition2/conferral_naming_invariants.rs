//! v62.0.0 (DUTY-D7; Constitution "confers-by-naming, the four", 11-24) —
//! **a root grant confers on an act BY NAMING**, through
//! [`confers_on_act`] (sqlite + postgres):
//!
//! - **I6645** — an act naming the bundle alone (`refs.head` only) counts for
//!   nobody; an act naming the grant's acceptance (`refs.also.stands_on`)
//!   stands: counted and in force.
//! - **I6646** — an act naming an acceptance of ANOTHER grant counts for
//!   nobody; an act dated long before the grant that does not name the
//!   acceptance gains nothing (no stamp is consulted either way); a machine's
//!   acceptance that cites no binding LANDS and confers nothing.
//! - **I6647** — the handover: once a NEW owner's binding of the worker is
//!   held, an act under the old acceptance is not in force (counted at its
//!   head; "in force for nobody unless it was receipted"); the new owner's
//!   own acceptance stands for an act that names it.
//! - **I6648** — the reading (`holds_now`): the worker holds the scope NOW
//!   while the acceptance stands, and not after its owner withdraws it.

use chrono::{Duration, Utc};
use ciris_verify_core::cde::{self, Value};
use ciris_verify_core::edition2::{row_ref, sign_row_statement, Digest32};

use super::conferral_naming::{confers_on_act, holds_now, ConfersOnAct};
use super::fixture_genesis::install_v2;
use super::fixture_switch as e2;
use super::names::RowId;
use super::scope_resolution_invariants::{
    accepting_node, grant_instant, land_grant, worker_with_owner,
};
use crate::federation::membership_acceptance::{reply_input, root_grant_reply_input};
use crate::federation::types::attestation_type;
use crate::federation::{Attestation, FederationDirectory};

const SCOPE: &str = "infra:attest:build:registered";

fn map(members: Vec<(&str, Value)>) -> Value {
    let mut m: Vec<(Value, Value)> = members
        .into_iter()
        .map(|(k, v)| (Value::Text(k.to_owned()), v))
        .collect();
    m.sort_by_key(|(k, _)| cde::encode(k));
    Value::Map(m)
}

/// An act by `seed` at `at_ms`, naming `head` and, when given, `stands_on`.
fn act(
    seed: &str,
    head: &Digest32,
    stands_on: Option<&RowId>,
    at_ms: u64,
) -> (Attestation, Vec<u8>) {
    let mut refs = vec![("head", row_ref(head))];
    if let Some(a) = stands_on {
        refs.push((
            "also",
            map(vec![("stands_on", Value::Array(vec![row_ref(&a.0)]))]),
        ));
    }
    let payload = map(vec![
        ("asserted_at", Value::Uint(at_ms)),
        (
            "dimension",
            Value::Text("provenance:build_manifest:registered:v1".into()),
        ),
        ("refs", map(refs)),
    ]);
    let iss = e2::kid(seed);
    let st = sign_row_statement(
        &e2::signing_key(seed),
        &iss,
        &iss,
        attestation_type::SCORES,
        &ciris_verify_core::namespace_match::family_id("provenance:build_manifest:{target}"),
        &payload,
        vec![],
    )
    .expect("sign an act");
    let mut row = e2::row_of_statement(&st, crate::federation::types::attestation_tier::FEDERATION);
    row.attesting_key_id = iss;
    (row, st)
}

fn now_ms() -> u64 {
    u64::try_from(Utc::now().timestamp_millis()).expect("after 1970")
}

async fn accept(
    d: &dyn FederationDirectory,
    owner_seed: &str,
    input: crate::federation::types::EmitAttestationInput,
) -> RowId {
    let signer = crate::federation::tier_ingest::test_support::local_signer(owner_seed);
    let out = crate::federation::attestation_emit::emit_with_local_signer(d, &signer, input)
        .await
        .expect("the acceptance");
    RowId(super::store::id_of_hex(&out.attestation_id).expect("a row id"))
}

struct World {
    head: Digest32,
    worker_seed: String,
    owner_seed: String,
    grant: Attestation,
    acceptance: RowId,
}

async fn world(d: &dyn FederationDirectory, tag: &str) -> World {
    let head = install_v2(d).await.expect("installs").object_id;
    let _ = accepting_node(d, &format!("d7-node-{tag}")).await;
    let (worker, owner_seed) = worker_with_owner(d, &format!("d7-{tag}")).await;
    let at = grant_instant(d).await;
    let grant = land_grant(d, &worker, SCOPE, &head, at, "D7").await;
    let input = root_grant_reply_input(d, &grant, true, None)
        .await
        .expect("the acceptance cites the worker's federation binding");
    let acceptance = accept(d, &owner_seed, input).await;
    World {
        head,
        worker_seed: format!("w-d7-{tag}"),
        owner_seed,
        grant,
        acceptance,
    }
}

/// **I6645.**
pub(crate) async fn i6645_an_act_stands_only_on_the_acceptance_it_names(
    d: &dyn FederationDirectory,
    tag: &str,
) {
    let w = world(d, tag).await;
    let (bare, st) = act(&w.worker_seed, &w.head, None, now_ms());
    assert_eq!(
        confers_on_act(d, &bare, &st, SCOPE)
            .await
            .expect("the verdict"),
        ConfersOnAct::Nothing("stands_on_names_not_one_acceptance"),
        "[{tag}] I6645: an act naming the bundle alone counts for nobody"
    );
    let (named, st) = act(&w.worker_seed, &w.head, Some(&w.acceptance), now_ms());
    let v = confers_on_act(d, &named, &st, SCOPE)
        .await
        .expect("the verdict");
    assert!(
        matches!(
            v,
            ConfersOnAct::Stands {
                counted: true,
                in_force: true,
                ..
            }
        ),
        "[{tag}] I6645: an act naming the acceptance stands: {v:?}"
    );
}

/// **I6646.**
pub(crate) async fn i6646_another_grant_a_backdate_and_an_uncited_acceptance_count_for_nobody(
    d: &dyn FederationDirectory,
    tag: &str,
) {
    let w = world(d, tag).await;
    // Another worker's grant, accepted by its owner.
    let (other, other_owner) = worker_with_owner(d, &format!("d7o-{tag}")).await;
    let at = grant_instant(d).await;
    let other_grant = land_grant(d, &other, SCOPE, &w.head, at, "D7 other").await;
    let other_acc = accept(
        d,
        &other_owner,
        root_grant_reply_input(d, &other_grant, true, None)
            .await
            .expect("cites"),
    )
    .await;
    let (x, st) = act(&w.worker_seed, &w.head, Some(&other_acc), now_ms());
    assert!(
        !confers_on_act(d, &x, &st, SCOPE)
            .await
            .expect("verdict")
            .in_force(),
        "[{tag}] I6646: naming an acceptance of another grant counts for nobody"
    );
    // A backdated act that names no acceptance gains nothing.
    let long_ago = now_ms() - u64::try_from(Duration::days(30).num_milliseconds()).unwrap();
    let (y, st) = act(&w.worker_seed, &w.head, None, long_ago);
    assert!(
        !confers_on_act(d, &y, &st, SCOPE)
            .await
            .expect("verdict")
            .in_force(),
        "[{tag}] I6646: a backdated act naming no acceptance gains nothing"
    );
    // DUTY-D7a3 — the producer refuses to state an uncited machine
    // acceptance (it would confer nothing) ...
    let signer = crate::federation::tier_ingest::test_support::local_signer(&w.owner_seed);
    let refused = crate::federation::attestation_emit::emit_with_local_signer(
        d,
        &signer,
        reply_input(&w.grant, true),
    )
    .await;
    assert!(
        refused
            .as_ref()
            .err()
            .is_some_and(|e| e.to_string().contains("cites the owner binding")),
        "[{tag}] I6646 (D7a3): the producer refuses an uncited machine acceptance: {:?}",
        refused.map(|o| o.attestation_id)
    );
    // ... but one a PEER states lands at the door (no refusal on the row
    // alone), and confers nothing.
    let uncited = {
        use crate::federation::tier_ingest::test_support as ts;
        let env = serde_json::json!({
            "id": uuid::Uuid::new_v4().to_string(),
            "dimension": crate::federation::membership_acceptance::ACCEPTANCE_DIMENSION,
            "references_attestation_id": w.grant.attestation_id,
        });
        let mut a = ts::bare_attestation(
            &uuid::Uuid::new_v4().to_string(),
            &w.owner_seed,
            &w.grant.attested_key_id,
            &env,
        );
        a.attestation_type = attestation_type::SCORES.into();
        a.weight = None;
        a.cohort_scope = crate::federation::types::cohort_scope::FEDERATION.into();
        a.expires_at = None;
        a.subject_key_ids = Vec::new();
        ts::seal_row_in_place(&w.owner_seed, &mut a);
        e2::put_signed(d, &a)
            .await
            .expect("I6646: a peer's uncited acceptance at the door");
        RowId(e2::rid_digest(&a))
    };
    assert!(
        d.get_attestation(&uncited.hex())
            .await
            .expect("reads")
            .is_some(),
        "[{tag}] I6646 premise: an uncited machine acceptance is not refused on the row alone"
    );
    let (z, st) = act(&w.worker_seed, &w.head, Some(&uncited), now_ms());
    assert_eq!(
        confers_on_act(d, &z, &st, SCOPE).await.expect("verdict"),
        ConfersOnAct::Nothing("acceptance_cites_no_binding"),
        "[{tag}] I6646: an act naming an uncited machine acceptance stands on nothing"
    );
}

/// **I6647.**
pub(crate) async fn i6647_a_handover_needs_the_new_owners_acceptance(
    d: &dyn FederationDirectory,
    tag: &str,
) {
    let w = world(d, tag).await;
    let (before, st_before) = act(&w.worker_seed, &w.head, Some(&w.acceptance), now_ms());
    // The old owner's binding is withdrawn by the old owner, and a new owner
    // binds the worker.
    let worker = e2::kid(&w.worker_seed);
    let crate::federation::admission::MachineOwner::Bound { bindings, .. } =
        crate::federation::admission::machine_owner_binding_at(d, &worker, Utc::now())
            .await
            .expect("the owner read")
    else {
        panic!("[{tag}] I6647 premise: the worker is bound");
    };
    let old = d
        .get_attestation(&bindings[0])
        .await
        .expect("reads")
        .expect("the old binding");
    e2::put_signed(
        d,
        &e2::composer_of_at(attestation_type::WITHDRAWS, &old, &w.owner_seed, Utc::now()),
    )
    .await
    .expect("I6647: the old owner withdraws its binding");
    let new_owner = format!("o2-d7-{tag}");
    let _ = e2::put_key(d, &new_owner, &["user"]).await;
    crate::federation::admission::steward_liveness_test_support::bind_machine_owner(
        d,
        &new_owner,
        &w.worker_seed,
    )
    .await;
    let v = confers_on_act(d, &before, &st_before, SCOPE)
        .await
        .expect("verdict");
    assert!(
        !v.in_force(),
        "[{tag}] I6647: after the handover the old acceptance is in force for nobody: {v:?}"
    );
    let new_acc = accept(
        d,
        &new_owner,
        root_grant_reply_input(d, &w.grant, true, None)
            .await
            .expect("the new owner's acceptance cites its binding"),
    )
    .await;
    let (after, st_after) = act(&w.worker_seed, &w.head, Some(&new_acc), now_ms());
    let v = confers_on_act(d, &after, &st_after, SCOPE)
        .await
        .expect("verdict");
    assert!(
        v.in_force(),
        "[{tag}] I6647: an act naming the new owner's acceptance stands: {v:?}"
    );
}

/// **I6648.**
pub(crate) async fn i6648_the_reading_holds_now(d: &dyn FederationDirectory, tag: &str) {
    let w = world(d, tag).await;
    let worker = e2::kid(&w.worker_seed);
    let now = holds_now(d, &worker, SCOPE).await.expect("the reading");
    assert_eq!(
        now.map(|h| h.acceptance),
        Some(w.acceptance),
        "[{tag}] I6648: the worker holds the scope now"
    );
    let acc = d
        .get_attestation(&w.acceptance.hex())
        .await
        .expect("reads")
        .expect("the acceptance");
    e2::put_signed(
        d,
        &e2::composer_of_at(attestation_type::WITHDRAWS, &acc, &w.owner_seed, Utc::now()),
    )
    .await
    .expect("I6648: the owner withdraws its acceptance");
    assert!(
        holds_now(d, &worker, SCOPE)
            .await
            .expect("the reading")
            .is_none(),
        "[{tag}] I6648: withdrawn, the reading says no"
    );
}

#[cfg(feature = "sqlite")]
mod sqlite {
    use crate::store::Backend as _;

    async fn store(node: &str) -> crate::store::sqlite::SqliteBackend {
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        b.set_node_key_id(super::e2::kid(node));
        b
    }

    #[tokio::test]
    async fn i6645_sqlite() {
        let b = store("d7-node-s5").await;
        Box::pin(super::i6645_an_act_stands_only_on_the_acceptance_it_names(
            &b, "s5",
        ))
        .await;
    }

    #[tokio::test]
    async fn i6646_sqlite() {
        let b = store("d7-node-s6").await;
        Box::pin(
            super::i6646_another_grant_a_backdate_and_an_uncited_acceptance_count_for_nobody(
                &b, "s6",
            ),
        )
        .await;
    }

    #[tokio::test]
    async fn i6647_sqlite() {
        let b = store("d7-node-s7").await;
        Box::pin(super::i6647_a_handover_needs_the_new_owners_acceptance(
            &b, "s7",
        ))
        .await;
    }

    #[tokio::test]
    async fn i6648_sqlite() {
        let b = store("d7-node-s8").await;
        Box::pin(super::i6648_the_reading_holds_now(&b, "s8")).await;
    }
}

#[cfg(feature = "postgres")]
mod postgres {
    use crate::store::Backend as _;

    async fn store(node: &str) -> Option<crate::store::postgres::PostgresBackend> {
        let dsn = crate::test_pg::empty_dsn()?;
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        b.set_node_key_id(super::e2::kid(node));
        Some(b)
    }

    #[tokio::test]
    async fn i6645_postgres() {
        let Some(b) = store("d7-node-p5").await else {
            return;
        };
        Box::pin(super::i6645_an_act_stands_only_on_the_acceptance_it_names(
            &b, "p5",
        ))
        .await;
    }

    #[tokio::test]
    async fn i6646_postgres() {
        let Some(b) = store("d7-node-p6").await else {
            return;
        };
        Box::pin(
            super::i6646_another_grant_a_backdate_and_an_uncited_acceptance_count_for_nobody(
                &b, "p6",
            ),
        )
        .await;
    }

    #[tokio::test]
    async fn i6647_postgres() {
        let Some(b) = store("d7-node-p7").await else {
            return;
        };
        Box::pin(super::i6647_a_handover_needs_the_new_owners_acceptance(
            &b, "p7",
        ))
        .await;
    }

    #[tokio::test]
    async fn i6648_postgres() {
        let Some(b) = store("d7-node-p8").await else {
            return;
        };
        Box::pin(super::i6648_the_reading_holds_now(&b, "p8")).await;
    }
}
