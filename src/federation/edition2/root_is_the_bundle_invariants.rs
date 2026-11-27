//! v62.0.0 (KB-fix1; CC 3.2 at rc22 `87abd2d`, "The root is the bundle's
//! lineage") — **the root a node accepts is the lineage of a genesis bundle,
//! named by its `family_key_id`**: its charter is the bundle's `charter`, its
//! conferring roster the holders in force, its seats the `serve_nodes`. Each
//! body runs on sqlite and postgres, through the real doors on `install_v2`.
//!
//! - **I2400** a node's `trust:accepts:v1` edge names the lineage by its
//!   `family_key_id` and the bundle it attaches on by object id; it lands at
//!   the T4a gate (`check_attach_freshness`, the bundle branch), and the
//!   root is then VALID (`trust_root_valid`, the bundle arm: edge, the
//!   bundle's charter, its recovery commitments), reported as a family root.
//!   Before the edge, the same root is not valid (no edge).
//! - **I2401** an edge naming no bundle of that lineage this node holds is
//!   HELD (`trust_root_head_stale`), never admitted.
//! - **I2402** a later bundle of the lineage (`later_v2`: four new holders)
//!   needs NO re-acceptance: the same edge, the same root, still valid.
//! - **I2403** the serve wait's rooting (`serve::node_is_rooted`) reads the
//!   accepted bundle root, no room chain: not rooted before the edge, rooted
//!   after it.
//! - **I2404** mesh config (CC 4.2.1): the bundle root's author is a holder
//!   in force (`root_authorizes_author` answers `Holder`); any other key is
//!   not authorized by it (`None`).
//! - **I6408** (R2-gaps 3) an acceptance superseded by the node's own
//!   successor naming the newest tip: the successor is in force; withdrawn,
//!   nothing is (the replaced acceptance is not revived).
//! - **I6409** (R2-gaps 3) a forged acceptance (the node's `iss` under a
//!   stranger's key; the owner's `iss` under the node's key) is refused
//!   `kid_not_of_iss` at the authored and the wire door.
//! - **I6411** (R2-gaps-1) a counted root grant is replaced only by the
//!   root's counted successor: one holder's authored `supersedes` is refused
//!   `supersedes_not_a_replacement` and the grant stays live and conferring
//!   (both doors); one voice of the counted successor does not land; two
//!   land it and, accepted, it confers in place of the grant, its scope
//!   narrowing. **I6416** (R2-rest-b2): `root_grants_for` lists the same
//!   standing grant as the walk at each step (the successor, once counted;
//!   never the grant it retires).
//! - **I6412** (R2-gaps-1, sqlite) the walk's own guard: a key-matched
//!   `supersedes` planted below the door retires no counted grant.

use super::fixture_genesis as fg;
use super::fixture_switch as e2;
use crate::federation::trust_root::{trust_root_valid, RootKind};
use crate::federation::FederationDirectory;

/// I2400–I2404 on one empty directory.
pub(crate) async fn root_is_the_bundle(d: &dyn FederationDirectory, tag: &str) {
    fg::install_v2(d)
        .await
        .unwrap_or_else(|e| panic!("[{tag}] the ceremony installs: {e}"));
    let in_force = super::genesis::genesis_in_force(d)
        .await
        .unwrap_or_else(|e| panic!("[{tag}] the genesis reads: {e}"));
    let root = in_force
        .family_key_id()
        .unwrap_or_else(|| panic!("[{tag}] a bundle is in force"))
        .to_owned();
    assert_eq!(root, fg::FAMILY_KEY_ID, "[{tag}] the lineage's name");
    let tip = hex::encode(
        in_force
            .tips()
            .first()
            .unwrap_or_else(|| panic!("[{tag}] a tip"))
            .object_id,
    );

    let seed = "kb1-accepting-node";
    let node = e2::put_key(d, seed, &["node"]).await;
    let key = e2::signing_key(seed);
    let now = crate::host::clock::now;

    // Before any edge: not valid, not rooted.
    let before = trust_root_valid(d, &node, &root, now())
        .await
        .unwrap_or_else(|e| panic!("[{tag}] trust_root_valid reads: {e}"));
    assert!(
        !before.valid && !before.edge_exists,
        "[{tag}] I2400: no edge, no root: {before:?}"
    );
    assert!(
        !super::serve::node_is_rooted(d, &node, e2::ms(now()))
            .await
            .unwrap_or_else(|e| panic!("[{tag}] node_is_rooted reads: {e}")),
        "[{tag}] I2403: not rooted before the edge"
    );

    // I2401 — an edge naming a bundle this node does not hold waits.
    let stray =
        super::fixture_trust_root::bundle_acceptance_statement(d, &key, &node, &"00".repeat(32))
            .await
            .unwrap_or_else(|e| panic!("[{tag}] I2401: the stray edge signs: {e}"));
    // v62.0.0 (FX-fix2) — the fixture asserts the hold itself (`put_held`).
    assert_eq!(
        e2::put_held(d, &stray, &format!("[{tag}] I2401")).await,
        super::fold::reason::gc8::TRUST_ROOT_HEAD_STALE,
        "[{tag}] I2401: an edge naming no held bundle of the lineage is held"
    );

    // I2400 — the edge naming the bundle in force lands; the root is valid.
    let edge = super::fixture_trust_root::bundle_acceptance_statement(d, &key, &node, &tip)
        .await
        .unwrap_or_else(|e| panic!("[{tag}] I2400: the edge signs: {e}"));
    e2::put_statement(d, &edge)
        .await
        .unwrap_or_else(|e| panic!("[{tag}] I2400: the edge lands: {e}"));
    let edge_id = super::group_fixtures::row_id_of(&edge);
    assert!(
        d.get_attestation(&edge_id.hex())
            .await
            .unwrap_or_else(|e| panic!("[{tag}] get_attestation reads: {e}"))
            .is_some(),
        "[{tag}] I2400: the acceptance edge concluded"
    );
    let v = trust_root_valid(d, &node, &root, now())
        .await
        .unwrap_or_else(|e| panic!("[{tag}] trust_root_valid reads: {e}"));
    assert!(
        v.valid && v.edge_exists && v.root_self_declares && v.charter_has_recovery,
        "[{tag}] I2400: the bundle root is valid: {v:?}"
    );
    assert_eq!(v.root_kind, RootKind::Family, "[{tag}] I2400: {v:?}");
    assert!(
        super::serve::node_is_rooted(d, &node, e2::ms(now()))
            .await
            .unwrap_or_else(|e| panic!("[{tag}] node_is_rooted reads: {e}")),
        "[{tag}] I2403: rooted once it accepts the bundle root"
    );

    // I2404 — mesh config: a holder in force is the root's author.
    use crate::federation::mesh_config::{root_authorizes_author, AuthorAuthority};
    assert_eq!(
        root_authorizes_author(d, &root, &fg::identity_ref_of(fg::HOLDER_SEEDS[0]))
            .await
            .unwrap_or_else(|e| panic!("[{tag}] root_authorizes_author reads: {e}")),
        AuthorAuthority::Holder,
        "[{tag}] I2404: a holder in force authors for the bundle root"
    );
    assert_eq!(
        root_authorizes_author(d, &root, &node)
            .await
            .unwrap_or_else(|e| panic!("[{tag}] root_authorizes_author reads: {e}")),
        AuthorAuthority::None,
        "[{tag}] I2404: a key that holds no seat does not"
    );

    // I2402 — a later bundle of the lineage: no re-acceptance.
    let later = fg::later_v2(
        fg::bundle_v2(),
        &[1, 2, 3, 4, 5, 6, 7],
        &fg::SERVE_NODE_SEEDS,
        &[1, 2, 3, 4, 5, 6, 7],
    );
    fg::install_ceremony_v2(d, &later)
        .await
        .unwrap_or_else(|e| panic!("[{tag}] I2402: the later bundle installs: {e}"));
    let after = trust_root_valid(d, &node, &root, now())
        .await
        .unwrap_or_else(|e| panic!("[{tag}] trust_root_valid reads: {e}"));
    assert!(
        after.valid,
        "[{tag}] I2402: still valid across the lineage, no new edge: {after:?}"
    );
}

/// The two doors an acceptance edge arrives at.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Door {
    /// THIS node's own act (`Engine::accept_root`).
    Authored,
    /// A peer's edge, from the feed.
    Wire,
}

async fn put_at(d: &dyn FederationDirectory, st: &[u8], door: Door) {
    let _ = put_answer(d, st, door).await;
}

/// The door's answer to `st` at `door`.
async fn put_answer(
    d: &dyn FederationDirectory,
    st: &[u8],
    door: Door,
) -> Result<super::ingest::StatementOutcome, crate::federation::Error> {
    use crate::federation::replication::admission::WriteOrigin;
    let origin = match door {
        Door::Authored => WriteOrigin::Authored,
        Door::Wire => WriteOrigin::Wire,
    };
    super::ingest::put_statement_with_origin(d, st, None, super::ingest::INGEST_TIER, origin).await
}

async fn edge_of(d: &dyn FederationDirectory, seed: &str, head: Option<&str>) -> Vec<u8> {
    let node = e2::put_key(d, seed, &["node"]).await;
    let at = e2::ms(crate::host::clock::now()) + 1_000;
    super::fixture_trust_root::root_acceptance_statement(
        &e2::signing_key(seed),
        &node,
        fg::FAMILY_KEY_ID,
        head,
        at,
    )
    .expect("the acceptance edge signs")
}

async fn landed(d: &dyn FederationDirectory, st: &[u8]) -> bool {
    let id = super::group_fixtures::row_id_of(st);
    d.get_attestation(&id.hex())
        .await
        .expect("get_attestation reads")
        .is_some()
}

async fn held_reason(d: &dyn FederationDirectory, st: &[u8]) -> Option<String> {
    let id = super::group_fixtures::row_id_of(st);
    super::fold::why_held(d, &id)
        .await
        .expect("why_held reads")
        .map(|h| h.reason)
}

/// **I2460–I2463 (RL-fix15)** — the bundle-root acceptance table at `door`:
/// `none` a fresh directory, `held` another (the bundle installed there).
///
/// - **I2460 (a)** names no bundle, none held: held, and never lands, the
///   import included (R2-accept: at the import its re-fold is (b));
/// - **I2461 (b)** names no bundle, the lineage held: REFUSED
///   `trust_root_head_unnamed`, never held, never landed (R2-accept; the
///   Constitution's `trust-accepts` rule: "a new edge without it is
///   refused");
/// - **I2462 (c)** names the held tip: lands;
/// - **I2463 (d)** names a bundle not held: HELD `trust_root_head_stale`,
///   never landed, at the wire door as at the authored one.
/// - **I2466 (d) then import** an edge naming a LATER bundle of the lineage
///   this node does not hold yet is held, and lands when that bundle is
///   imported: arrival order does not matter.
pub(crate) async fn attach_table(
    none: &dyn FederationDirectory,
    held: &dyn FederationDirectory,
    door: Door,
    tag: &str,
) {
    // (a)
    let a = edge_of(none, &format!("rl15a-{tag}"), None).await;
    put_at(none, &a, door).await;
    assert!(
        !landed(none, &a).await && held_reason(none, &a).await.is_some(),
        "[{tag} {door:?}] I2460: no bundle held: the edge waits"
    );
    fg::install_v2(none).await.expect("the ceremony installs");
    assert!(
        !landed(none, &a).await,
        "[{tag} {door:?}] I2460: the import does not land an edge naming no bundle"
    );
    // (b), (c), (d)
    fg::install_v2(held).await.expect("the ceremony installs");
    let tip = hex::encode(
        super::genesis::genesis_in_force(held)
            .await
            .expect("genesis")
            .tips()
            .first()
            .expect("a tip")
            .object_id,
    );
    let b = edge_of(held, &format!("rl15b-{tag}"), None).await;
    let answer = put_answer(held, &b, door).await;
    assert!(
        matches!(
            answer,
            Err(crate::federation::Error::TrustRootHeadUnnamed { .. })
        ),
        "[{tag} {door:?}] I2461: no bundle named, the lineage held: refused by name: {answer:?}"
    );
    assert!(
        !landed(held, &b).await && held_reason(held, &b).await.is_none(),
        "[{tag} {door:?}] I2461: refused: neither landed nor held"
    );
    let c = edge_of(held, &format!("rl15c-{tag}"), Some(&tip)).await;
    put_at(held, &c, door).await;
    assert!(
        landed(held, &c).await,
        "[{tag} {door:?}] I2462: the held tip: lands"
    );
    let dd = edge_of(held, &format!("rl15d-{tag}"), Some(&"00".repeat(32))).await;
    put_at(held, &dd, door).await;
    assert!(
        !landed(held, &dd).await,
        "[{tag} {door:?}] I2463: a bundle not held: never landed"
    );
    assert_eq!(
        held_reason(held, &dd).await,
        Some(super::fold::reason::gc8::TRUST_ROOT_HEAD_STALE.to_owned()),
        "[{tag} {door:?}] I2463: held trust_root_head_stale"
    );
    // (d) then import
    let first = fg::bundle_v2();
    let later = fg::later_v2(first, &[1, 2, 4], &[11, 12], &[1, 2, 4]);
    let ee = edge_of(
        held,
        &format!("rl15e-{tag}"),
        Some(&hex::encode(later.object_id)),
    )
    .await;
    put_at(held, &ee, door).await;
    assert_eq!(
        held_reason(held, &ee).await,
        Some(super::fold::reason::gc8::TRUST_ROOT_HEAD_STALE.to_owned()),
        "[{tag} {door:?}] I2466: a later bundle not held yet: held"
    );
    fg::install_ceremony_v2(held, &later)
        .await
        .expect("the later bundle installs");
    assert!(
        landed(held, &ee).await,
        "[{tag} {door:?}] I2466: the import of that bundle lands it"
    );
}

#[cfg(feature = "sqlite")]
async fn sqlite_fresh() -> crate::store::sqlite::SqliteBackend {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    b
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i2460_i2466_the_attach_table_sqlite() {
    for door in [Door::Authored, Door::Wire] {
        let (none, held) = (sqlite_fresh().await, sqlite_fresh().await);
        Box::pin(attach_table(&none, &held, door, "sqlite")).await;
    }
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i2460_i2466_the_attach_table_postgres() {
    use crate::store::Backend as _;
    for door in [Door::Authored, Door::Wire] {
        let (Some(a), Some(b)) = (crate::test_pg::empty_dsn(), crate::test_pg::empty_dsn()) else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let none = crate::store::postgres::PostgresBackend::connect(&a)
            .await
            .unwrap();
        none.run_migrations().await.unwrap();
        let held = crate::store::postgres::PostgresBackend::connect(&b)
            .await
            .unwrap();
        held.run_migrations().await.unwrap();
        Box::pin(attach_table(&none, &held, door, "postgres")).await;
    }
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i2400_the_root_is_the_bundle_sqlite() {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(root_is_the_bundle(&b, "sqlite")).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i2400_the_root_is_the_bundle_postgres() {
    use crate::store::Backend as _;
    let Some(dsn) = crate::test_pg::empty_dsn() else {
        eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
        return;
    };
    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(root_is_the_bundle(&b, "postgres")).await;
}

/// **I6408** (v62.0.0 R2-gaps 3; CC 3.2 T2, the Constitution's
/// `trust-accepts`) — **an acceptance superseded by its own successor on the
/// same lineage**. The node accepts the lineage naming the first bundle;
/// a later bundle of the lineage is imported; the node's own `supersedes` of
/// that acceptance names the newest tip. The successor is the edge in force:
/// the root is valid through it, and withdrawing the SUCCESSOR un-roots the
/// node. The acceptance it replaced is not revived (a key match or a
/// non-retiring `supersedes` would leave it live and keep the root valid).
pub(crate) async fn successor_acceptance(d: &dyn FederationDirectory, tag: &str) {
    use ciris_verify_core::cde::Value;
    fg::install_v2(d).await.expect("the ceremony installs");
    let tip1 = hex::encode(
        super::genesis::genesis_in_force(d)
            .await
            .expect("genesis")
            .tips()
            .first()
            .expect("a tip")
            .object_id,
    );
    let seed = format!("r2g3-succ-{tag}");
    let first = edge_of(d, &seed, Some(&tip1)).await;
    put_at(d, &first, Door::Authored).await;
    assert!(
        landed(d, &first).await,
        "[{tag}] I6408: the first acceptance lands"
    );
    let node = e2::kid(&seed);
    let later = fg::later_v2(fg::bundle_v2(), &[1, 2, 4], &[11, 12], &[1, 2, 4]);
    fg::install_ceremony_v2(d, &later)
        .await
        .expect("the later bundle installs");
    let at = e2::ms(crate::host::clock::now()) + 2_000;
    let first_id = super::group_fixtures::row_id_of(&first);
    let mut payload: Vec<(Value, Value)> = vec![
        (Value::Text("author".into()), Value::Text(node.clone())),
        (Value::Text("asserted_at".into()), Value::Uint(at)),
        (
            Value::Text("dimension".into()),
            Value::Text(crate::federation::trust_root::TRUST_ACCEPTS_DIMENSION.into()),
        ),
        (
            Value::Text(crate::federation::envelope::paths::ATTACHED_HEAD_DIGEST.into()),
            Value::Array(vec![
                Value::Nint(15),
                Value::Bytes(later.object_id.to_vec()),
            ]),
        ),
        (
            Value::Text("refs".into()),
            Value::Map(vec![(
                Value::Text("target".into()),
                ciris_verify_core::edition2::row_ref(&first_id.0),
            )]),
        ),
    ];
    payload.sort_by_key(|(k, _)| ciris_verify_core::cde::encode(k));
    let successor = ciris_verify_core::edition2::sign_row_statement(
        &e2::signing_key(&seed),
        &node,
        fg::FAMILY_KEY_ID,
        crate::federation::types::attestation_type::SUPERSEDES,
        &ciris_verify_core::namespace_match::family_id(super::typed::TRUST_PREFIX),
        &Value::Map(payload),
        vec![],
    )
    .expect("the successor signs");
    let answer = put_answer(d, &successor, Door::Authored).await;
    assert!(
        answer.is_ok() && landed(d, &successor).await,
        "[{tag}] I6408: the successor naming the newest tip lands: {answer:?}"
    );
    let now = crate::host::clock::now() + chrono::Duration::seconds(5);
    let v = trust_root_valid(d, &node, fg::FAMILY_KEY_ID, now)
        .await
        .expect("trust_root_valid reads");
    assert!(
        v.valid && v.edge_exists,
        "[{tag}] I6408: rooted through the successor: {v:?}"
    );
    let successor_id = super::group_fixtures::row_id_of(&successor);
    let w = e2::trust_withdraws_statement(&seed, fg::FAMILY_KEY_ID, &successor_id, at + 1_000);
    e2::put_statement(d, &w)
        .await
        .expect("I6408: the node withdraws its successor");
    let v = trust_root_valid(
        d,
        &node,
        fg::FAMILY_KEY_ID,
        now + chrono::Duration::seconds(5),
    )
    .await
    .expect("trust_root_valid reads");
    assert!(
        !v.edge_exists && !v.valid,
        "[{tag}] I6408: the successor withdrawn, nothing is in force: the acceptance it \
         replaced is not revived: {v:?}"
    );
}

/// **I6409** (v62.0.0 R2-gaps 3; CC 2.6.1.7) — **a forged acceptance is
/// refused by name at both doors**: (a) an acceptance stating THIS node's
/// `iss` signed by another key, and (b) one stating the OWNER's `iss` signed
/// by a key outside the owner's roster (the node's own key), are each refused
/// `kid_not_of_iss`, neither landed nor held, at the authored door and at the
/// wire door.
pub(crate) async fn forged_acceptance(d: &dyn FederationDirectory, door: Door, tag: &str) {
    fg::install_v2(d).await.expect("the ceremony installs");
    let tip = hex::encode(
        super::genesis::genesis_in_force(d)
            .await
            .expect("genesis")
            .tips()
            .first()
            .expect("a tip")
            .object_id,
    );
    let at = e2::ms(crate::host::clock::now()) + 1_000;
    let node_seed = format!("r2g3-node-{tag}");
    let node = e2::put_key(d, &node_seed, &["node"]).await;
    let stranger_seed = format!("r2g3-stranger-{tag}");
    e2::put_key(d, &stranger_seed, &["user"]).await;
    let owner_seed = format!("r2g3-owner-{tag}");
    let owner = e2::put_key(d, &owner_seed, &["user"]).await;
    for (what, signer, iss) in [
        ("the node's iss, a stranger's key", &stranger_seed, &node),
        ("the owner's iss, the node's key", &node_seed, &owner),
    ] {
        let forged = super::fixture_trust_root::root_acceptance_statement(
            &e2::signing_key(signer),
            iss,
            fg::FAMILY_KEY_ID,
            Some(&tip),
            at,
        )
        .expect("the forged edge signs");
        let answer = put_answer(d, &forged, door).await;
        assert!(
            matches!(
                &answer,
                Err(crate::federation::Error::MalformedRow { reason, .. })
                    if *reason == crate::federation::malformed_row::KID_NOT_OF_ISS
            ),
            "[{tag} {door:?}] I6409 ({what}): refused kid_not_of_iss: {answer:?}"
        );
        assert!(
            !landed(d, &forged).await && held_reason(d, &forged).await.is_none(),
            "[{tag} {door:?}] I6409 ({what}): neither landed nor held"
        );
    }
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i6408_successor_acceptance_sqlite() {
    Box::pin(successor_acceptance(&sqlite_fresh().await, "sqlite")).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i6408_successor_acceptance_postgres() {
    use crate::store::Backend as _;
    let Some(dsn) = crate::test_pg::empty_dsn() else {
        eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
        return;
    };
    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(successor_acceptance(&b, "postgres")).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i6409_forged_acceptance_sqlite() {
    for door in [Door::Authored, Door::Wire] {
        Box::pin(forged_acceptance(&sqlite_fresh().await, door, "sqlite")).await;
    }
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i6409_forged_acceptance_postgres() {
    use crate::store::Backend as _;
    for door in [Door::Authored, Door::Wire] {
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Box::pin(forged_acceptance(&b, door, "postgres")).await;
    }
}

/// R2-gaps-1 — a `supersedes` of the counted grant `target` to `grantee`,
/// signed by holder `i` of the test ceremony: `authored` states `author` (one
/// key's act); otherwise the root's counted shape (no `author`, `refs.head` =
/// `head`).
fn grant_successor_voice(
    i: usize,
    grantee: &str,
    target: &super::names::RowId,
    head: &ciris_verify_core::edition2::Digest32,
    scope: &[&str],
    authored: bool,
    at: u64,
) -> Vec<u8> {
    use ciris_verify_core::cde::Value;
    let c = fg::bundle_v2();
    let iss = c.holder_identity_ref(i).to_owned();
    let mut refs = vec![(
        Value::Text("target".into()),
        ciris_verify_core::edition2::row_ref(&target.0),
    )];
    if !authored {
        refs.push((
            Value::Text("head".into()),
            ciris_verify_core::edition2::row_ref(head),
        ));
    }
    refs.sort_by_key(|(k, _)| ciris_verify_core::cde::encode(k));
    let mut m: Vec<(Value, Value)> = vec![
        (Value::Text("asserted_at".into()), Value::Uint(at)),
        (
            Value::Text("dimension".into()),
            Value::Text(crate::federation::trust_root::TRUST_CONFERS_DIMENSION.into()),
        ),
        (Value::Text("refs".into()), Value::Map(refs)),
        (
            Value::Text("scope".into()),
            Value::Array(scope.iter().map(|s| Value::Text((*s).into())).collect()),
        ),
    ];
    if authored {
        m.push((Value::Text("author".into()), Value::Text(iss.clone())));
    }
    m.sort_by_key(|(k, _)| ciris_verify_core::cde::encode(k));
    ciris_verify_core::edition2::sign_row_statement(
        &c.holder_key(i),
        &iss,
        grantee,
        crate::federation::types::attestation_type::SUPERSEDES,
        &ciris_verify_core::namespace_match::family_id(super::typed::TRUST_PREFIX),
        &Value::Map(m),
        vec![],
    )
    .expect("a successor voice signs")
}

/// R2-rest-b2 — the host verb's list for `subject`
/// (`admission::root_grants_for`): each listed grant's row id and whether it
/// confers.
async fn listed(d: &dyn FederationDirectory, subject: &str) -> Vec<(String, bool)> {
    crate::federation::admission::root_grants_for(
        d,
        subject,
        crate::host::clock::now() + chrono::Duration::seconds(5),
    )
    .await
    .expect("root_grants_for reads")
    .into_iter()
    .map(|g| (g.row_id, g.confers))
    .collect()
}

/// The capability walk's answer for `subject` holding `scope`, from THIS
/// node: the conferring row's id.
async fn conferring(d: &dyn FederationDirectory, subject: &str, scope: &str) -> Option<String> {
    let node = d.node_key_id().expect("the runner set the node key");
    crate::federation::trust_root::capability_roots_to_trusted_root(
        d,
        &node,
        subject,
        scope,
        crate::host::clock::now() + chrono::Duration::seconds(5),
    )
    .await
    .expect("the walk reads")
    .map(|g| g.grant_attestation_id)
}

/// **I6411** (v62.0.0 R2-gaps-1; CC 3.2 T2, "A grant is superseded when the
/// root issues the successor grant, to a rotated key or with a changed scope,
/// as a `supersedes` on the old one"; CC 3.2, "A grant from the root is a row
/// counted over the holders of the bundle in force, and it names the bundle
/// it is counted over") — **a counted root grant is replaced only by the
/// root's counted successor**, at `door`:
///
/// - THE ATTACK: one holder's AUTHORED `supersedes` of the counted grant is
///   refused `supersedes_not_a_replacement`, nothing kept, and the grant stays
///   LIVE and conferring;
/// - one holder's voice of the COUNTED successor does not land (short of the
///   strict majority), and the grant stays live and conferring;
/// - the second holder's voice lands the successor; once the grantee accepts
///   it, the SUCCESSOR confers and the superseded grant does not; its scope
///   is the successor's (a narrowed scope narrows).
/// - **I6416** (R2-rest-b2) the host verb `root_grants_for` agrees with the
///   walk at every step: it lists the grant (conferring) before and after the
///   attack and the short successor, and, once the successor lands, lists
///   the SUCCESSOR and not the grant it retires.
pub(crate) async fn counted_grant_rotation(d: &dyn FederationDirectory, door: Door, tag: &str) {
    use crate::federation::trust_root::INFRA_SERVE_SCOPE;
    const ATTEST: &str = "infra:attest:provenance:build_manifest";
    let r = super::fixture_trust_root::rooted_trust_root(d, &fg::HOLDER_SEEDS, "quorum:2/3").await;
    let subject_seed = format!("r2g1-subject-{tag}");
    let subject = e2::kid(&subject_seed);
    let grant = super::fixture_trust_root::put_conferral(
        d,
        &r,
        &subject_seed,
        &[INFRA_SERVE_SCOPE, ATTEST],
    )
    .await
    .expect("I6411: the root's counted grant and the grantee's acceptance land");
    assert_eq!(
        conferring(d, &subject, ATTEST).await.as_deref(),
        Some(grant.hex().as_str()),
        "[{tag} {door:?}] I6411 CONTROL: the counted grant confers"
    );
    assert_eq!(
        listed(d, &subject).await,
        vec![(grant.hex(), true)],
        "[{tag} {door:?}] I6416 CONTROL: the host verb lists the counted grant"
    );
    let at = e2::ms(crate::host::clock::now()) + 1_000;

    // THE ATTACK — holder 0's authored supersedes.
    let attack =
        grant_successor_voice(0, &subject, &grant, &r.head, &[INFRA_SERVE_SCOPE], true, at);
    let answer = put_answer(d, &attack, door).await;
    assert!(
        matches!(
            &answer,
            Err(crate::federation::Error::MalformedRow { reason, .. })
                if *reason == crate::federation::malformed_row::SUPERSEDES_NOT_A_REPLACEMENT
        ),
        "[{tag} {door:?}] I6411: one holder's authored supersedes is refused by name: {answer:?}"
    );
    assert!(
        !landed(d, &attack).await,
        "[{tag} {door:?}] I6411: nothing kept"
    );
    // The counted successor, one voice: short.
    let short = grant_successor_voice(
        0,
        &subject,
        &grant,
        &r.head,
        &[INFRA_SERVE_SCOPE],
        false,
        at,
    );
    let _ = put_answer(d, &short, door).await;
    assert!(
        !landed(d, &short).await,
        "[{tag} {door:?}] I6411: one holder's voice of the counted successor does not land"
    );
    assert_eq!(
        conferring(d, &subject, ATTEST).await.as_deref(),
        Some(grant.hex().as_str()),
        "[{tag} {door:?}] I6411: after the attack the grant is LIVE and conferring"
    );
    assert_eq!(
        listed(d, &subject).await,
        vec![(grant.hex(), true)],
        "[{tag} {door:?}] I6416: neither the attack nor the short successor retires the \
         grant in the host verb's list, and neither is listed"
    );
    if matches!(door, Door::Wire) {
        return;
    }

    // The rotation: holder 1's voice lands the successor; the grantee accepts.
    let second = grant_successor_voice(
        1,
        &subject,
        &grant,
        &r.head,
        &[INFRA_SERVE_SCOPE],
        false,
        at,
    );
    put_answer(d, &second, Door::Authored)
        .await
        .expect("I6411: the second holder's voice");
    assert!(
        landed(d, &short).await,
        "[{tag}] I6411: two of three holders land the successor"
    );
    let successor_id = super::group_fixtures::row_id_of(&short);
    let successor = d
        .get_attestation(&successor_id.hex())
        .await
        .expect("reads")
        .expect("the successor is held");
    let signer = crate::federation::tier_ingest::test_support::local_signer(&subject_seed);
    crate::federation::attestation_emit::emit_with_local_signer(
        d,
        &signer,
        crate::federation::membership_acceptance::reply_input(&successor, true),
    )
    .await
    .expect("I6411: the grantee accepts the successor");
    assert_eq!(
        conferring(d, &subject, INFRA_SERVE_SCOPE).await.as_deref(),
        Some(successor_id.hex().as_str()),
        "[{tag}] I6411: the successor confers, not the grant it superseded"
    );
    assert_eq!(
        conferring(d, &subject, ATTEST).await,
        None,
        "[{tag}] I6411: the successor's narrower scope narrows (the superseded grant's \
         attest scope confers nothing)"
    );
    assert_eq!(
        listed(d, &subject).await,
        vec![(successor_id.hex(), true)],
        "[{tag}] I6416: the host verb lists the root's counted successor, and not the grant \
         it retired"
    );
}

/// **I6412** (R2-gaps-1; sqlite: the store's below-the-door seam) — the
/// WALK's own guard, apart from the door: a holder's authored `supersedes` of
/// a counted grant PLANTED below every door (the shape a key match read as a
/// rotation: its `attesting_key_id` is the grant's first voice) retires
/// nothing, and the grant stays live and conferring. Mutation: reverting
/// `trust_root::live_conferrals`'s counted branch to the key match
/// (`r.attesting_key_id == row.attesting_key_id`) turns this red.
#[cfg(feature = "sqlite")]
pub(crate) async fn walk_ignores_a_key_matched_supersedes(b: &crate::store::sqlite::SqliteBackend) {
    use crate::federation::trust_root::INFRA_SERVE_SCOPE;
    let r = super::fixture_trust_root::rooted_trust_root(b, &fg::HOLDER_SEEDS, "quorum:2/3").await;
    let subject_seed = "r2g1-planted-subject";
    let subject = e2::kid(subject_seed);
    let grant = super::fixture_trust_root::put_conferral(b, &r, subject_seed, &[INFRA_SERVE_SCOPE])
        .await
        .expect("I6412: the counted grant lands");
    let held = b
        .get_attestation(&grant.hex())
        .await
        .expect("reads")
        .expect("the grant is held");
    let mut planted = held.clone();
    planted.attestation_id = "11".repeat(32);
    planted.attestation_type = crate::federation::types::attestation_type::SUPERSEDES.into();
    planted.attestation_envelope["author"] =
        serde_json::Value::String(held.attesting_key_id.clone());
    planted.attestation_envelope["references_attestation_id"] =
        serde_json::Value::String(held.attestation_id.clone());
    b.plant_attestation_below_the_door(planted);
    assert_eq!(
        conferring(b, &subject, INFRA_SERVE_SCOPE).await.as_deref(),
        Some(grant.hex().as_str()),
        "I6412: a key-matched supersedes retires no counted grant"
    );
}

#[cfg(feature = "sqlite")]
async fn sqlite_with_node(seed: &str) -> crate::store::sqlite::SqliteBackend {
    let b = sqlite_fresh().await;
    b.set_node_key_id(e2::put_key(&b, seed, &["node"]).await);
    b
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i6411_counted_grant_rotation_sqlite() {
    for door in [Door::Authored, Door::Wire] {
        let b = sqlite_with_node("r2g1-node-sq").await;
        Box::pin(counted_grant_rotation(&b, door, "sqlite")).await;
    }
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i6411_counted_grant_rotation_postgres() {
    use crate::store::Backend as _;
    for door in [Door::Authored, Door::Wire] {
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        b.set_node_key_id(&e2::put_key(&b, "r2g1-node-pg", &["node"]).await);
        Box::pin(counted_grant_rotation(&b, door, "postgres")).await;
    }
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i6412_walk_ignores_a_key_matched_supersedes_sqlite() {
    let b = sqlite_with_node("r2g1-planted-node").await;
    Box::pin(walk_ignores_a_key_matched_supersedes(&b)).await;
}
