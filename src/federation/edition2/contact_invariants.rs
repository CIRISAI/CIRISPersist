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
//! - **I2296** (HT-fix1; CC rc22 2.6.8, 3004759) the store's cap IS
//!   Verify's (`FEDCODE_E2_MAX_HINTS` = `edition2::DIAL_HINTS_MAX`), eight: a
//!   code with eight entries (types 1, 2, 4–8 and one unknown) is recorded
//!   and read back in order, byte for byte; a ninth is refused
//!   `dial_hint_out_of_bounds`, nothing written.
//! - **I2298** an unknown type (200) is carried, not refused ("a decoder
//!   carries a hint of any other type as unknown and a dialler skips it"):
//!   stored and returned in its place, counted toward the eight, and never
//!   offered as dialable (no route, no transit pair).
//! - **I2309** (ruling: the tag is the wire's u8) tags 255 and 0 are stored
//!   and returned (sqlite + pg); the host parser refuses a tag above 255 by
//!   name, `dial_hint_out_of_bounds`, never truncating (pure).

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
fn code(node: &str, owner: &str, x: u8, ed: &[u8], hints: &[(u8, &[u8])]) -> DialHints {
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
        &[(1, &b"10.0.0.2:4242"[..]), (0x7f, &b"\x01\x02"[..])],
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

/// **I2296 / I2298** — the cap is Verify's; an unknown type is carried,
/// counted toward it, and never offered as dialable.
pub(crate) async fn cap_body(a: &dyn FederationDirectory, tag: &str) {
    use super::contact::MAX_DIAL_HINTS;
    let run = uuid::Uuid::new_v4().simple().to_string();
    let node = format!("ht1-node-{tag}-{run}");
    let owner = format!("ht1-owner-{tag}-{run}");
    let n = e2::kid(&node);
    assert_eq!(
        MAX_DIAL_HINTS,
        ciris_verify_core::edition2::DIAL_HINTS_MAX,
        "I2296: the store reads Verify's cap"
    );
    assert_eq!(
        MAX_DIAL_HINTS, 8,
        "I2296: eight (CC rc22, Verify 23.4.0 final)"
    );
    let i2p = [0x5au8; 32];
    let kiss: &[u8] = b"\x19\xc8\x2f\x40\x00\x00\x04\xb0N0CALL-7";
    // Seven assigned types and one unknown (tag 200): eight entries.
    let eight: Vec<(u8, &[u8])> = vec![
        (1, &b"\x10\x92seat.example"[..]),
        (2, &b"\x10\x92seat.example"[..]),
        (200, &b"\x01\x02\x03"[..]),
        (
            4,
            &[0x36, 0x7a, 0x74, 0x40, 0x00, 0x01, 0xe8, 0x48, 0x09, 0x05][..],
        ),
        (5, &b"https://seat.example/"[..]),
        (6, &i2p[..]),
        (7, kiss),
        (8, &b""[..]),
    ];
    let code8 = code(&node, &owner, 7, &[8; 32], &eight);
    record_dial_hints(a, code8.clone())
        .await
        .unwrap_or_else(|e| panic!("[{tag}] I2296: eight hints are admitted: {e}"));
    let held = dial_hints_for(a, &n).await.unwrap().expect("I2296: held");
    // I2298: the unknown hint is stored and returned in its place.
    assert_eq!(
        held.hints, code8.hints,
        "[{tag}] I2296/I2298: every hint, the unknown one included, in order, byte for byte"
    );
    // ... and never offered as dialable: a hint is no route and no transit.
    assert!(
        a.list_transport_destinations_for(&n)
            .await
            .unwrap()
            .is_empty()
            && transit_kex_pair_for(a, &n).await.unwrap().is_none(),
        "[{tag}] I2298: no route is derived from a hint"
    );
    // A ninth (the unknown counted toward the eight): refused by name.
    let mut nine = eight.clone();
    nine.push((3, &b"\x02ciris"[..]));
    let e = record_dial_hints(a, code(&node, &owner, 7, &[8; 32], &nine))
        .await
        .expect_err("I2296: nine hints exceed the cap");
    assert_eq!(
        reason(&e),
        crate::federation::malformed_row::DIAL_HINT_OUT_OF_BOUNDS,
        "[{tag}] I2296: {e:?}"
    );
    assert_eq!(
        dial_hints_for(a, &n).await.unwrap().expect("held").hints,
        code8.hints,
        "[{tag}] I2296: the refused record wrote nothing"
    );
    // I2309 (ruling: the tag is the wire's one byte): the widest tag, 255,
    // and tag 0 (an unknown type, carried) are stored and returned.
    let edges = code(
        &node,
        &owner,
        7,
        &[8; 32],
        &[
            (255, &b"\xff"[..]),
            (0, &b""[..]),
            (1, &b"\x10\x92seat.example"[..]),
        ],
    );
    record_dial_hints(a, edges.clone())
        .await
        .unwrap_or_else(|e| panic!("[{tag}] I2309: tags 255 and 0 are stored: {e}"));
    assert_eq!(
        dial_hints_for(a, &n).await.unwrap().expect("held").hints,
        edges.hints,
        "[{tag}] I2309: returned as stored"
    );
}

/// **I2309 (pure)** — the host surfaces' hint parser validates the tag as the
/// wire's one byte: 255 and 0 read; 256 is refused by name
/// (`dial_hint_out_of_bounds`), never truncated; a non-integer tag or a body
/// that is not hex is `InvalidArgument`.
#[test]
fn i2309_a_hint_tag_is_one_byte_at_the_door() {
    use super::contact::dial_hint_from_json;
    let ok = |t: u64| dial_hint_from_json(0, &serde_json::json!({"tag": t, "body_hex": "0102"}));
    assert_eq!(
        ok(255).unwrap(),
        DialHint {
            tag: 255,
            body: vec![1, 2]
        }
    );
    assert_eq!(
        ok(0).unwrap().tag,
        0,
        "I2309: tag 0 is an unknown type, carried"
    );
    for t in [256u64, 0x7f00, u64::from(u32::MAX)] {
        let e = ok(t).expect_err("I2309: above 255 is refused");
        assert_eq!(
            reason(&e),
            crate::federation::malformed_row::DIAL_HINT_OUT_OF_BOUNDS,
            "I2309 {t}: {e:?}"
        );
        assert!(
            e.to_string().contains(&t.to_string()),
            "I2309 {t}: names the tag: {e}"
        );
    }
    for bad in [
        serde_json::json!({"tag": "1", "body_hex": "00"}),
        serde_json::json!({"tag": -1, "body_hex": "00"}),
        serde_json::json!({"body_hex": "00"}),
        serde_json::json!({"tag": 1, "body_hex": "zz"}),
    ] {
        assert!(
            matches!(dial_hint_from_json(3, &bad), Err(Error::InvalidArgument(_))),
            "I2309: {bad}"
        );
    }
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i2296_i2298_dial_hint_cap_sqlite() {
    use crate::store::Backend as _;
    let a = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    a.run_migrations().await.unwrap();
    Box::pin(cap_body(&a, "sqlite")).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i2296_i2298_dial_hint_cap_postgres() {
    use crate::store::Backend as _;
    let Some(dsn) = crate::test_pg::empty_dsn() else {
        eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
        return;
    };
    let a = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    a.run_migrations().await.unwrap();
    Box::pin(cap_body(&a, "postgres")).await;
}
