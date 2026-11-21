//! v62.0.0 (RL-fix2) — **I2247–I2252: first contact between two rootless
//! nodes by node code**, on sqlite and postgres, delivered through the real
//! doors (`edition2::contact`).
//!
//! B is a person's node: B's node key (`node`) and its own self-pair
//! `identity:occurrence` bind carrying a route and a transit X-Wing key, and
//! B's owner (a person) bound to it by an owner binding. A decodes B's code
//! (the node kid, the transport identity, two hints, the owner's identity)
//! and dials first.
//!
//! - **I2247** the hint alone: A records the dial hint in the code's order,
//!   and it yields NO transit pair, no X-Wing key, no route and no key — it
//!   is not confusable with a signed row.
//! - **I2248** a wrong key under the right destination: the pre-seal answer's
//!   key record is another key's, so `code_node_key_mismatch`, nothing stored.
//! - **I2249** a route row signed by another key: `code_route_signer_mismatch`,
//!   nothing stored.
//! - **I2250** the happy path: B's own key record and bind admitted with NO
//!   root, NO owner row and NO prior key for B on A; `transit_kex_pair_for`
//!   answers from the edition-2 bind arm (no cycle: a node's self-pair bind
//!   needs no owner's voice). The hint list is replaced in order; a hint whose
//!   transport Ed25519 half is the node's federation key is refused
//!   `fedcode_transport_is_federation_key`.
//! - **I2251** an owner mismatch (`code_owner_mismatch`) and a binding of
//!   another node (`code_owner_binding_not_for_node`): refused, the owner
//!   rows store nothing and confer nothing.
//! - **I2252** the owner rows: admitted after the seal, the node's one live
//!   owner is the code's identity; removing the contact removes the hint and
//!   leaves the signed route.

use ciris_verify_core::cde::Value;

use super::contact::{
    admit_contact_owner_rows, admit_pre_seal_answer, dial_hints_for, list_dial_hints,
    record_dial_hints, remove_dial_hints, ContactKind, DialHint, DialHints,
};
use super::fixture_occurrence::{occurrence_bind_voices, BindOptions};
use super::fixture_switch as e2;
use super::ingest::{put_statement, StatementOutcome, INGEST_TIER};
use super::names::RowId;
use crate::federation::self_at_login::{
    transit_kex_pair_for, transit_xwing_pubkey_for, XWingPublicKey,
};
use crate::federation::{Error, FederationDirectory};

fn reason(e: &Error) -> String {
    match e {
        Error::MalformedRow { reason, .. } => (*reason).to_owned(),
        other => other.kind().to_owned(),
    }
}

/// `seed`'s self-pair bind on `head` (its key record's row), carrying a
/// route `(x, e)` and the transit key `transit`.
fn self_bind(seed: &str, head: RowId, route: (u8, u8), transit: &[u8]) -> Vec<u8> {
    let opts = BindOptions {
        extra: vec![
            (
                "transport_destination",
                super::rootless_mesh_invariants::transport(route.0, route.1),
            ),
            ("transit_xwing_pubkey", Value::Bytes(transit.to_vec())),
        ],
        head: Some(head),
        ..BindOptions::default()
    };
    let mut v = occurrence_bind_voices(seed, seed, seed, "server", &opts);
    assert_eq!(v.len(), 1, "a self pair is one statement");
    v.remove(0)
}

/// The code A decodes for `node` (owned by `owner`): the node kid, the
/// transport identity X25519 ‖ Ed25519, and `hints` in order.
fn code(node: &str, owner: &str, x: u8, ed: &[u8], hints: &[(u16, &[u8])]) -> DialHints {
    let mut transport_identity = vec![x; 32];
    transport_identity.extend_from_slice(ed);
    DialHints {
        node: e2::kid(node),
        transport_identity,
        hints: hints
            .iter()
            .map(|(t, b)| DialHint {
                tag: *t,
                body: b.to_vec(),
            })
            .collect(),
        identity: Some(e2::kid(owner)),
        kind: Some(ContactKind::User),
        recorded_at_ms: 0,
    }
}

pub(crate) async fn body(a: &dyn FederationDirectory, b: &dyn FederationDirectory, tag: &str) {
    use super::rootless_mesh_invariants::assert_rootless;
    assert_rootless(a, &format!("{tag} A")).await;
    assert_rootless(b, &format!("{tag} B")).await;
    let run = uuid::Uuid::new_v4().simple().to_string();
    let node = format!("rl2-node-{tag}-{run}");
    let owner = format!("rl2-owner-{tag}-{run}");
    let other = format!("rl2-other-{tag}-{run}");
    let transit = vec![0x71u8; 1216];

    // B stands itself up: its node key and its own bind (a self pair).
    let n = e2::put_key(b, &node, &["node"]).await;
    let (head, _) = super::occurrence::current_roster_heads(b, &n)
        .await
        .unwrap()
        .expect("B's node key heads its own roster");
    let bind = self_bind(&node, head, (7, 8), &transit);
    let out = put_statement(b, &bind, None, INGEST_TIER).await.unwrap();
    assert!(
        matches!(out, StatementOutcome::Row { .. }),
        "[{tag}] B's own bind lands: {out:?}"
    );
    // What B answers a pre-seal route request with (E1 step 6).
    let node_record = e2::key_record(&node, &["node"]);

    // ── I2247: the hint alone ──
    let hint = code(
        &node,
        &owner,
        7,
        &[8; 32],
        &[(1, &b"10.0.0.2:4242"[..]), (0x7f00, &b"\x01\x02"[..])],
    );
    record_dial_hints(a, hint.clone())
        .await
        .unwrap_or_else(|e| panic!("[{tag}] I2247: A records the hint: {e}"));
    let held = dial_hints_for(a, &n).await.unwrap().expect("I2247: held");
    assert_eq!(held.hints, hint.hints, "[{tag}] I2247: in the code's order");
    assert_eq!(list_dial_hints(a).await.unwrap().len(), 1);
    assert!(
        transit_kex_pair_for(a, &n).await.unwrap().is_none()
            && transit_xwing_pubkey_for(a, &n).await.unwrap().is_none(),
        "[{tag}] I2247: a hint is never a transit pair"
    );
    assert!(
        a.list_transport_destinations_for(&n)
            .await
            .unwrap()
            .is_empty()
            && a.lookup_public_key(&n).await.unwrap().is_none(),
        "[{tag}] I2247: a hint is no route and no key"
    );

    // ── I2248: a wrong key under the right destination ──
    let other_record = e2::key_record(&other, &["node"]);
    let e = admit_pre_seal_answer(a, &n, &other_record, &bind)
        .await
        .expect_err("I2248: another key's record is refused");
    assert_eq!(reason(&e), "code_node_key_mismatch", "[{tag}] I2248");
    assert!(
        a.edition2_statements_since(None, 100)
            .await
            .unwrap()
            .is_empty(),
        "[{tag}] I2248: nothing stored"
    );

    // ── I2249: a route signed by another key ──
    let other_head = RowId::of_statement(&other_record).expect("a row id");
    let other_bind = self_bind(&other, other_head, (9, 10), &[0x72; 1216]);
    let e = admit_pre_seal_answer(a, &n, &node_record, &other_bind)
        .await
        .expect_err("I2249: another key's route is refused");
    assert_eq!(reason(&e), "code_route_signer_mismatch", "[{tag}] I2249");
    assert!(
        a.edition2_statements_since(None, 100)
            .await
            .unwrap()
            .is_empty(),
        "[{tag}] I2249: nothing stored"
    );

    // ── I2250: the happy path, no root, no owner row, no prior key ──
    let admitted = admit_pre_seal_answer(a, &n, &node_record, &bind)
        .await
        .unwrap_or_else(|e| panic!("[{tag}] I2250: the pre-seal answer: {e}"));
    assert!(
        admitted.transit_ready,
        "[{tag}] I2250: transit_kex_pair_for answers: {admitted:?}"
    );
    assert_eq!(
        transit_xwing_pubkey_for(a, &n).await.unwrap(),
        XWingPublicKey::from_bytes(&transit),
        "[{tag}] I2250: the edition-2 bind arm answers the node's own transit key"
    );
    assert_eq!(
        a.list_transport_destinations_for(&n).await.unwrap().len(),
        1,
        "[{tag}] I2250: the signed route projects"
    );
    // Re-adding the code replaces the list, in order.
    let mut again = hint.clone();
    again.hints.reverse();
    record_dial_hints(a, again.clone()).await.unwrap();
    assert_eq!(
        dial_hints_for(a, &n).await.unwrap().expect("held").hints,
        again.hints,
        "[{tag}] I2250: re-adding replaces the list"
    );
    // A transport identity whose Ed25519 half is the node's federation key.
    let fed = {
        use base64::Engine as _;
        let k = a.lookup_public_key(&n).await.unwrap().expect("held now");
        base64::engine::general_purpose::STANDARD
            .decode(k.pubkey_ed25519_base64)
            .unwrap()
    };
    let e = record_dial_hints(a, code(&node, &owner, 7, &fed, &[]))
        .await
        .expect_err("I2250: a transport key that is a federation key is refused");
    assert_eq!(
        reason(&e),
        "fedcode_transport_is_federation_key",
        "[{tag}] I2250"
    );
    assert_eq!(
        dial_hints_for(a, &n).await.unwrap().expect("held").hints,
        again.hints,
        "[{tag}] I2250: the refused record wrote nothing"
    );

    // ── I2251: owner mismatches ──
    let owner_record = e2::key_record(&owner, &["user"]);
    let at =
        crate::federation::key_grant_invariants::two_node::owner_binding_instant(a, &node).await;
    let binding =
        crate::federation::key_grant_invariants::two_node::owner_binding_voices(&owner, &node, at);
    let stranger_record = e2::key_record(&other, &["user"]);
    let e = admit_contact_owner_rows(a, &n, &e2::kid(&owner), &stranger_record, &binding)
        .await
        .expect_err("I2251: another key's record is not the code's owner");
    assert_eq!(reason(&e), "code_owner_mismatch", "[{tag}] I2251");
    let other_node = format!("rl2-node2-{tag}-{run}");
    let wrong = crate::federation::key_grant_invariants::two_node::owner_binding_voices(
        &owner,
        &other_node,
        at,
    );
    let e = admit_contact_owner_rows(a, &n, &e2::kid(&owner), &owner_record, &wrong)
        .await
        .expect_err("I2251: a binding of another node is refused");
    assert_eq!(
        reason(&e),
        "code_owner_binding_not_for_node",
        "[{tag}] I2251"
    );
    assert!(
        a.lookup_public_key(&e2::kid(&owner))
            .await
            .unwrap()
            .is_none()
            && crate::federation::admission::owner_of_unmarked(a, &n)
                .await
                .unwrap()
                .is_none(),
        "[{tag}] I2251: nothing of the owner rows stored, nothing conferred"
    );

    // ── I2252: the owner rows after the seal ──
    let owned = admit_contact_owner_rows(a, &n, &e2::kid(&owner), &owner_record, &binding)
        .await
        .unwrap_or_else(|e| panic!("[{tag}] I2252: the owner rows: {e}"));
    assert!(
        owned.owner_resolved,
        "[{tag}] I2252: the node's one live owner is the code's identity: {owned:?}"
    );
    assert!(remove_dial_hints(a, &n).await.unwrap());
    assert!(dial_hints_for(a, &n).await.unwrap().is_none());
    assert_eq!(
        a.list_transport_destinations_for(&n).await.unwrap().len(),
        1,
        "[{tag}] I2252: removing the hint leaves the signed route"
    );
    assert_rootless(a, &format!("{tag} A after")).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i2247_to_i2252_first_contact_by_node_code_sqlite() {
    use crate::store::Backend as _;
    let open = || async {
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        b
    };
    let (a, b) = (open().await, open().await);
    Box::pin(body(&a, &b, "sqlite")).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i2247_to_i2252_first_contact_by_node_code_postgres() {
    use crate::store::Backend as _;
    let (Some(da), Some(db)) = (crate::test_pg::empty_dsn(), crate::test_pg::empty_dsn()) else {
        eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
        return;
    };
    let mut nodes = Vec::new();
    for dsn in [da, db] {
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        nodes.push(b);
    }
    Box::pin(body(&nodes[0], &nodes[1], "postgres")).await;
}
