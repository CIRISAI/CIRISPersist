//! v62.0.0 (RL-fix1; release-blocking, Eric 2026-11-20: "rootless is a
//! state we are supposed to be able to support: the agent does not run but
//! the P2P mesh does") — **a rootless node runs the P2P mesh**, on sqlite and
//! postgres, through the real planes. Nothing is written into the receiving
//! node's tables: what crosses is what the sending node's serve rule hands
//! the requester ([`statements_served_to`]), offered to the receiver's
//! replicated statement door ([`apply_replicated_statement`]), retried while
//! a statement waits on another, as a replication loop retries a held
//! cursor.
//!
//! v62.0 bakes no genesis bundle, so every v62.0 node is rootless: no bundle
//! is held and no trust root is accepted. CC 5.3.4 (rc21, "What crosses
//! before Rooted"): "what the peer's own standing admits still crosses: the
//! bootstrap kinds and the allegiance facts; the pairing plane; rows
//! addressed to the peer; and every row a bounded cohort delivers to that
//! peer as its member under CC 5.2 (`self`, `family`, `community`,
//! `affiliations`), because cohort delivery is consent and membership, not
//! service." CC 3.2 T1: the base self-root "is never sufficient for
//! federation", and "the un-federated deployment keeps its data and its
//! owner's own access on the base".
//!
//! - **I2240** — a rootless `Engine` opens, reports `pre_genesis` as a STATE
//!   (`genesis_in_force` answers `Ok`, not held; the posture and its banner
//!   say so), registers its own key and serves it; a second rootless engine
//!   admits what the first served, and stays rootless.
//! - **I2241** — first contact between two rootless nodes: each one's person
//!   and device key records and the device's `identity:occurrence` bind
//!   carrying a `transport_destination` and a `transit_xwing_pubkey` cross to
//!   the other through the serve rule. On the receiver the route projects and
//!   the transit key resolves (`transit_xwing_pubkey_for`): it can dial.
//! - **I2242** — a community's roster, its epoch DEK's key grant addressed to
//!   the peer and the sealed blob cross between two rootless nodes, and the
//!   peer's member opens the blob (the I61 exercise, on nodes asserted
//!   rootless before and after).
//! - **I2243** — a family blob published by one member opens on the other
//!   member's rootless node (the I199 exercise, asserted rootless).
//! - **I2245** — (lead ruling (A)(ii)) a rootless node serves its own key
//!   records and its device's bind to an ANONYMOUS pre-seal requester, with
//!   nothing counted as waiting; a federation-tier row that is no bootstrap
//!   kind waits ([`SERVE_WAITS_FOR_ROOTED`](super::serve::SERVE_WAITS_FOR_ROOTED);
//!   I3010 in `group_serve_invariants`), and cohort rows still reach members
//!   (I2242, I2243; I113c delivers community rows through the serve rule on
//!   rootless backends).
//! - **I2244** — what is the agent's, or the federation's, does not run on a
//!   rootless node, and says so: an `admission:unit` reads not runnable
//!   (`admission_none`), a conferral from a trusted root (a detector's
//!   `infra:attest`) is absent, no identity is canonical, and the accord-root
//!   chokepoint answers the typed `federation_no_constitutional_root_yet`
//!   (a fold hold, GC8) — and once the ceremony's bundle is installed the
//!   same chokepoint passes, while the mesh planes above never asked.

use ciris_crypto::composite::CompositeSigningKey;
use ciris_verify_core::cde::Value;
use ciris_verify_core::edition2::sign_row_statement;

use super::door_invariants::fixture::{iref, key, key_record, map};
use super::ingest::{apply_replicated_statement, put_statement, StatementOutcome, INGEST_TIER};
use super::names::RowId;
use super::occurrence::OCCURRENCE_FAMILY;
use super::serve::statements_served_to;
use crate::federation::self_at_login::{transit_xwing_pubkey_for, XWingPublicKey};
use crate::federation::{Error, FederationDirectory};

const APP: &str = "ciris.federation";
const ASPECT: &str = "serve";

/// **The node is rootless, and says so as a state.** `genesis_in_force`
/// answers (never an error) and holds no bundle, no seat; the posture is
/// `pre_genesis` with its banner.
pub(crate) async fn assert_rootless(d: &dyn FederationDirectory, tag: &str) {
    let held = super::genesis::genesis_in_force(d)
        .await
        .unwrap_or_else(|e| panic!("[{tag}] genesis_in_force is a state, never an error: {e}"));
    assert!(!held.is_held(), "[{tag}] no genesis bundle is held");
    assert!(held.seats().is_empty(), "[{tag}] no seat");
    let posture = crate::federation::genesis::genesis_posture(d).await;
    assert_eq!(
        posture.as_str(),
        "pre_genesis",
        "[{tag}] the posture reports pre-genesis: {posture:?}"
    );
    assert!(
        posture.banner().is_some(),
        "[{tag}] a pre-genesis node renders its banner"
    );
}

/// Offer one statement to `to` as a peer delivered it: under its own row id
/// through the replicated door, or (a signed object, which is no row)
/// through the one entry.
async fn offer(to: &dyn FederationDirectory, st: &[u8]) -> Result<(), Error> {
    match RowId::of_statement(st) {
        Some(id) => Box::pin(apply_replicated_statement(to, st, &id.0))
            .await
            .map(|_| ()),
        None => Box::pin(put_statement(to, st, None, INGEST_TIER))
            .await
            .map(|_| ()),
    }
}

/// **What `from` serves `requester`, delivered to `to`**: every page of
/// `from`'s filtered serve listing ([`statements_served_to`]), each
/// statement offered to `to` ([`offer`]); a statement that waits on another
/// is re-offered after the rest. Returns how many statements `from` served.
///
/// # Panics
/// A pass that lands nothing while statements still wait (the first
/// waiting statement's refusal is named).
pub(crate) async fn deliver(
    from: &dyn FederationDirectory,
    to: &dyn FederationDirectory,
    requester: &str,
    tag: &str,
) -> usize {
    let mut cursor = None;
    let mut served: Vec<Vec<u8>> = Vec::new();
    loop {
        let page = statements_served_to(from, cursor.as_ref(), 256, Some(requester))
            .await
            .unwrap_or_else(|e| panic!("[{tag}] the serve listing: {e}"));
        let Some(next) = page.next else { break };
        cursor = Some(next);
        served.extend(page.statements.into_iter().map(|s| s.bytes));
    }
    let total = served.len();
    let mut pending = served;
    loop {
        let before = pending.len();
        let mut waiting: Vec<Vec<u8>> = Vec::new();
        let mut first_err: Option<Error> = None;
        for st in pending {
            if let Err(e) = offer(to, &st).await {
                if first_err.is_none() {
                    first_err = Some(e);
                }
                waiting.push(st);
            }
        }
        if waiting.is_empty() {
            return total;
        }
        assert!(
            waiting.len() < before,
            "[{tag}] {} served statement(s) never land on the peer; the first: {:?}",
            waiting.len(),
            first_err
        );
        pending = waiting;
    }
}

/// A `transport_destination` member (CC 3.3.6.2) for Reticulum keys
/// `[x; 32]`, `[e; 32]`, its `destination_hash` derived (CC 3.3.6.3).
pub(crate) fn transport(x: u8, e: u8) -> Value {
    let (rx, re) = (vec![x; 32], vec![e; 32]);
    let dh = ciris_verify_core::transport_binding::compute_destination_hash(
        APP,
        &[ASPECT.to_owned()],
        &rx,
        &re,
    )
    .expect("a destination hash derives");
    map(vec![
        ("reticulum_x25519_pubkey", Value::Bytes(rx)),
        ("reticulum_ed25519_pubkey", Value::Bytes(re)),
        ("app_name", Value::Text(APP.into())),
        ("aspects", Value::Array(vec![Value::Text(ASPECT.into())])),
        ("destination_hash", Value::Bytes(dh.to_vec())),
    ])
}

/// One voice (`signer`'s) over the bind of `occurrence` to `identity` at
/// `asserted_at`, standing on the identity's roster head as `d` holds it
/// (CC 3.3.6.4), carrying `extra`.
async fn bind_voice(
    d: &dyn FederationDirectory,
    signer: &CompositeSigningKey,
    identity: &str,
    occurrence: &str,
    asserted_at: u64,
    extra: Vec<(&str, Value)>,
) -> Vec<u8> {
    let head = super::occurrence::current_roster_head(d, identity)
        .await
        .expect("the roster head read")
        .expect("the identity's key record is held");
    let mut m = vec![
        ("asserted_at", Value::Uint(asserted_at)),
        ("author", Value::Text(identity.to_owned())),
        ("identity_key_id", Value::Text(identity.to_owned())),
        ("occurrence_key_id", Value::Text(occurrence.to_owned())),
        ("device_class", Value::Text("laptop".to_owned())),
        (
            "refs",
            map(vec![(
                "head",
                ciris_verify_core::edition2::row_ref(&head.0),
            )]),
        ),
    ];
    m.extend(extra);
    sign_row_statement(
        signer,
        &iref(signer),
        occurrence,
        "scores",
        OCCURRENCE_FAMILY,
        &map(m),
        vec![],
    )
    .expect("sign a bind voice")
}

/// **One rootless node's own planes**: `owner` (a person) and `device` (its
/// laptop key), each a self-signed `user` `key:record` from 0 with no end,
/// and the device's bind under the owner (the device's voice, then the
/// owner's) carrying a route and the transit X-Wing key `transit`, dated
/// `at` inside both keys' windows. The bind lands and projects one route
/// here, and the transit key resolves here.
async fn stand_up(
    d: &dyn FederationDirectory,
    owner: &CompositeSigningKey,
    device: &CompositeSigningKey,
    at: u64,
    route: (u8, u8),
    transit: &[u8],
    tag: &str,
) {
    for k in [owner, device] {
        Box::pin(put_statement(
            d,
            &key_record(k, &["user"], 0, None),
            None,
            INGEST_TIER,
        ))
        .await
        .unwrap_or_else(|e| panic!("[{tag}] a key record lands on a rootless node: {e}"));
    }
    let (u, k) = (iref(owner), iref(device));
    let extra = || {
        vec![
            ("transport_destination", transport(route.0, route.1)),
            ("transit_xwing_pubkey", Value::Bytes(transit.to_vec())),
        ]
    };
    let own = bind_voice(d, device, &u, &k, at, extra()).await;
    Box::pin(put_statement(d, &own, None, INGEST_TIER))
        .await
        .unwrap_or_else(|e| panic!("[{tag}] the device's bind voice: {e}"));
    let author = bind_voice(d, owner, &u, &k, at, extra()).await;
    let out = Box::pin(put_statement(d, &author, None, INGEST_TIER))
        .await
        .unwrap_or_else(|e| panic!("[{tag}] the owner's bind voice: {e}"));
    assert!(
        matches!(out, StatementOutcome::Row { .. }),
        "[{tag}] the bind lands on a rootless node: {out:?}"
    );
    assert_eq!(
        d.list_transport_destinations_for(&k).await.unwrap().len(),
        1,
        "[{tag}] the bind projects its route on a rootless node"
    );
    assert_eq!(
        transit_xwing_pubkey_for(d, &k).await.unwrap(),
        XWingPublicKey::from_bytes(transit),
        "[{tag}] the device's transit key resolves on its own node"
    );
}

/// **I2241** on one backend pair.
pub(crate) async fn i2241_first_contact(
    a: &dyn FederationDirectory,
    b: &dyn FederationDirectory,
    tag: &str,
) {
    assert_rootless(a, &format!("{tag} A")).await;
    assert_rootless(b, &format!("{tag} B")).await;
    let (owner_a, dev_a) = (key(240), key(241));
    let (owner_b, dev_b) = (key(242), key(243));
    let (transit_a, transit_b) = (vec![0x51u8; 1216], vec![0x52u8; 1216]);
    // Instants inside the keys' windows (records from 0, no end): never the
    // wall clock.
    stand_up(a, &owner_a, &dev_a, 20_000, (7, 8), &transit_a, tag).await;
    stand_up(b, &owner_b, &dev_b, 21_000, (9, 10), &transit_b, tag).await;

    // I2245 (lead ruling (A)(ii); CC 5.3.4, CC 3.3.6.2 "pre-seal route
    // fetch") — a rootless node still serves its own bootstrap rows to an
    // ANONYMOUS pre-seal requester: both key records and both bind voices,
    // nothing waiting on a root.
    for (d, side) in [(a, "A"), (b, "B")] {
        let page = statements_served_to(d, None, 256, None)
            .await
            .unwrap_or_else(|e| panic!("[{tag} {side}] the anonymous serve: {e}"));
        let held = d.edition2_statements_since(None, 256).await.unwrap();
        assert!(
            held.len() >= 4 && page.statements.len() == held.len(),
            "[{tag} {side}] I2245: every held statement (the key records and the bind's \
             voices) is served anonymously: {} of {}",
            page.statements.len(),
            held.len()
        );
        assert_eq!(
            page.waiting_for_rooted, 0,
            "[{tag} {side}] I2245: no bootstrap row waits for a root"
        );
    }

    // First contact: each device is the requester the other's transport
    // authenticated (CC 5.3.4: two peers holding each other's signed route
    // rows seal and root each other directly).
    let (ka, kb) = (iref(&dev_a), iref(&dev_b));
    assert!(
        deliver(a, b, &kb, tag).await > 0,
        "[{tag}] A serves B something"
    );
    assert!(
        deliver(b, a, &ka, tag).await > 0,
        "[{tag}] B serves A something"
    );

    for (from_ref, to, transit, side) in [(&ka, b, &transit_a, "A→B"), (&kb, a, &transit_b, "B→A")]
    {
        assert!(
            to.lookup_public_key(from_ref).await.unwrap().is_some(),
            "[{tag} {side}] the peer device's key record crossed"
        );
        assert_eq!(
            to.list_transport_destinations_for(from_ref)
                .await
                .unwrap()
                .len(),
            1,
            "[{tag} {side}] the peer device's route projected on the receiver"
        );
        assert_eq!(
            transit_xwing_pubkey_for(to, from_ref).await.unwrap(),
            XWingPublicKey::from_bytes(transit),
            "[{tag} {side}] the receiver resolves the peer's transit key: it can dial"
        );
    }
    // Nothing above needed, or produced, a root.
    assert_rootless(a, &format!("{tag} A after")).await;
    assert_rootless(b, &format!("{tag} B after")).await;
}

/// **I2244** on one backend.
pub(crate) async fn i2244_agent_and_federation_wait(d: &dyn FederationDirectory, tag: &str) {
    assert_rootless(d, tag).await;
    let unit =
        super::receipts::admission_unit_receipt(d, &RowId([0x77; 32]), crate::host::clock::now())
            .await
            .unwrap_or_else(|e| panic!("[{tag}] the receipt leg reads: {e}"));
    assert!(
        !unit.is_runnable() && unit.token().is_some(),
        "[{tag}] an admission:unit is never runnable on a rootless node: {unit:?}"
    );
    let (node, detector) = (iref(&key(244)), iref(&key(245)));
    assert!(
        crate::federation::trust_root::capability_roots_to_trusted_root(
            d,
            &node,
            &detector,
            crate::federation::types::delegation_scope::INFRA_ATTEST,
            crate::host::clock::now(),
        )
        .await
        .unwrap_or_else(|e| panic!("[{tag}] the conferral walk reads: {e}"))
        .is_none(),
        "[{tag}] no root: no conferral from a trusted root"
    );
    for seat in super::fixture_genesis::bundle_v2().serve_node_identity_refs() {
        assert!(
            !crate::federation::admission::is_canonical(d, &seat)
                .await
                .unwrap_or_else(|e| panic!("[{tag}] is_canonical reads: {e}")),
            "[{tag}] {seat} is canonical nowhere on a rootless node"
        );
    }
    let waits = crate::federation::genesis::require_constitutional_root(d, "rl_fix1_witness")
        .await
        .expect_err("the accord-root chokepoint waits on a rootless node");
    assert_eq!(
        waits.kind(),
        "federation_no_constitutional_root_yet",
        "[{tag}] typed, never a silent pass: {waits:?}"
    );
    super::fixture_genesis::install_v2(d)
        .await
        .unwrap_or_else(|e| panic!("[{tag}] the ceremony installs on a rootless node: {e}"));
    crate::federation::genesis::require_constitutional_root(d, "rl_fix1_witness")
        .await
        .unwrap_or_else(|e| panic!("[{tag}] the bundle held, the chokepoint passes: {e}"));
}

/// **I2240** on one DSN pair: two rootless engines.
async fn i2240_engine_opens_and_serves(dsn_a: &str, dsn_b: &str, tag: &str) {
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::identity_type::USER;
    let run = uuid::Uuid::new_v4().simple().to_string();
    let open = |alias: String, dsn: String| async move {
        crate::Engine::with_signer_pre_genesis(ts::local_signer(&alias), &dsn)
            .await
            .unwrap_or_else(|e| panic!("a rootless engine opens: {e:?}"))
    };
    let ea = open(format!("i2240-a-{run}"), dsn_a.to_owned()).await;
    let eb = open(format!("i2240-b-{run}"), dsn_b.to_owned()).await;
    for (e, side) in [(&ea, "A"), (&eb, "B")] {
        let held = e
            .genesis_in_force()
            .await
            .unwrap_or_else(|err| panic!("[{tag} {side}] a state, not an error: {err}"));
        assert!(!held.is_held(), "[{tag} {side}] no genesis held");
        assert_eq!(e.genesis_posture().await.as_str(), "pre_genesis");
    }
    let ka = ea
        .register_self_federation_key(USER, None, None)
        .await
        .unwrap_or_else(|e| panic!("[{tag}] a rootless engine registers its own key: {e}"));
    let page = ea
        .edition2_statements_served_to(None, 256, None)
        .await
        .unwrap_or_else(|e| panic!("[{tag}] a rootless engine serves: {e}"));
    assert!(
        !page.statements.is_empty(),
        "[{tag}] a rootless engine serves its own key record"
    );
    let (da, db) = (ea.federation_directory(), eb.federation_directory());
    let kb = eb.local_derived_key_id().await.expect("B's key id");
    deliver(da.as_ref(), db.as_ref(), &kb, tag).await;
    assert!(
        db.lookup_public_key(&ka).await.unwrap().is_some(),
        "[{tag}] B holds A's key record, delivered through the planes"
    );
    assert_rootless(da.as_ref(), &format!("{tag} A after")).await;
    assert_rootless(db.as_ref(), &format!("{tag} B after")).await;
}

#[cfg(feature = "sqlite")]
mod sqlite {
    use super::*;
    use crate::federation::key_grant_invariants::two_node::{
        exercise_i199_family_member_publishes_and_another_opens, exercise_i61_end_to_end,
        introduce, introduce_as, node, node_as,
    };
    use crate::store::sqlite::SqliteBackend;
    use crate::store::Backend as _;

    async fn fresh() -> SqliteBackend {
        let b = SqliteBackend::open_in_memory().await.unwrap();
        b.run_migrations().await.unwrap();
        b
    }

    /// I2240 — a rootless engine opens, reports pre-genesis as a state, and
    /// serves.
    #[tokio::test]
    async fn i2240_a_rootless_engine_opens_and_serves_sqlite() {
        i2240_engine_opens_and_serves("sqlite::memory:", "sqlite::memory:", "sqlite").await;
    }

    /// I2241 — first contact between two rootless nodes.
    #[tokio::test]
    async fn i2241_two_rootless_nodes_make_first_contact_sqlite() {
        let (a, b) = (fresh().await, fresh().await);
        Box::pin(i2241_first_contact(&a, &b, "sqlite")).await;
    }

    /// I2242 — community roster, key grant to the peer and sealed blob cross
    /// between two rootless nodes.
    #[tokio::test]
    async fn i2242_a_community_blob_opens_across_rootless_nodes_sqlite() {
        use crate::federation::types::identity_type::NODE;
        let (ba, bb) = (fresh().await, fresh().await);
        let a = node_as(&ba, "i2242-a", NODE).await;
        let b = node_as(&bb, "i2242-b", NODE).await;
        introduce_as(&[&a, &b], &["i2242-a", "i2242-b"], NODE).await;
        assert_rootless(&ba, "sqlite A").await;
        assert_rootless(&bb, "sqlite B").await;
        Box::pin(exercise_i61_end_to_end(&a, &b, "i2242-sqlite")).await;
        assert_rootless(&ba, "sqlite A after").await;
        assert_rootless(&bb, "sqlite B after").await;
    }

    /// I2244 — agent and federation operations wait on a rootless node.
    #[tokio::test]
    async fn i2244_agent_and_federation_wait_on_a_rootless_node_sqlite() {
        let d = fresh().await;
        Box::pin(i2244_agent_and_federation_wait(&d, "sqlite")).await;
    }

    /// I2243 — a family blob opens on the other member's rootless node.
    #[tokio::test]
    async fn i2243_a_family_blob_opens_across_rootless_nodes_sqlite() {
        let (ba, bb) = (fresh().await, fresh().await);
        let a = node(&ba, "i2243-a").await;
        let b = node(&bb, "i2243-b").await;
        introduce(&[&a, &b], &["i2243-a", "i2243-b"]).await;
        assert_rootless(&ba, "sqlite A").await;
        assert_rootless(&bb, "sqlite B").await;
        Box::pin(exercise_i199_family_member_publishes_and_another_opens(
            &a,
            &b,
            "i2243-sqlite",
        ))
        .await;
        assert_rootless(&ba, "sqlite A after").await;
        assert_rootless(&bb, "sqlite B after").await;
    }
}

#[cfg(feature = "postgres")]
mod postgres {
    use super::*;
    use crate::federation::key_grant_invariants::two_node::{
        exercise_i199_family_member_publishes_and_another_opens, exercise_i61_end_to_end,
        introduce, introduce_as, node, node_as,
    };
    use crate::store::postgres::PostgresBackend;
    use crate::store::Backend as _;

    async fn fresh() -> Option<PostgresBackend> {
        let dsn = crate::test_pg::empty_dsn()?;
        let b = PostgresBackend::connect(&dsn).await.unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    }

    #[tokio::test]
    async fn i2240_a_rootless_engine_opens_and_serves_postgres() {
        let (Some(da), Some(db)) = (
            crate::test_pg::isolated_dsn(),
            crate::test_pg::isolated_dsn(),
        ) else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        i2240_engine_opens_and_serves(&da, &db, "postgres").await;
    }

    #[tokio::test]
    async fn i2241_two_rootless_nodes_make_first_contact_postgres() {
        let (Some(a), Some(b)) = (fresh().await, fresh().await) else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        Box::pin(i2241_first_contact(&a, &b, "postgres")).await;
    }

    #[tokio::test]
    async fn i2242_a_community_blob_opens_across_rootless_nodes_postgres() {
        use crate::federation::types::identity_type::NODE;
        let (Some(ba), Some(bb)) = (fresh().await, fresh().await) else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let a = node_as(&ba, "i2242-a", NODE).await;
        let b = node_as(&bb, "i2242-b", NODE).await;
        introduce_as(&[&a, &b], &["i2242-a", "i2242-b"], NODE).await;
        assert_rootless(&ba, "postgres A").await;
        assert_rootless(&bb, "postgres B").await;
        Box::pin(exercise_i61_end_to_end(&a, &b, "i2242-postgres")).await;
        assert_rootless(&ba, "postgres A after").await;
        assert_rootless(&bb, "postgres B after").await;
    }

    #[tokio::test]
    async fn i2244_agent_and_federation_wait_on_a_rootless_node_postgres() {
        let Some(d) = fresh().await else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        Box::pin(i2244_agent_and_federation_wait(&d, "postgres")).await;
    }

    #[tokio::test]
    async fn i2243_a_family_blob_opens_across_rootless_nodes_postgres() {
        let (Some(ba), Some(bb)) = (fresh().await, fresh().await) else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let a = node(&ba, "i2243-a").await;
        let b = node(&bb, "i2243-b").await;
        introduce(&[&a, &b], &["i2243-a", "i2243-b"]).await;
        assert_rootless(&ba, "postgres A").await;
        assert_rootless(&bb, "postgres B").await;
        Box::pin(exercise_i199_family_member_publishes_and_another_opens(
            &a,
            &b,
            "i2243-postgres",
        ))
        .await;
        assert_rootless(&ba, "postgres A after").await;
        assert_rootless(&bb, "postgres B after").await;
    }
}
