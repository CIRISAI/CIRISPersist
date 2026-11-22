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
//!   in force (`root_authorizes_author` answers `Inherent`); any other key is
//!   not authorized by it (`None`).

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
        root_authorizes_author(d, &root, &fg::identity_ref_of(fg::HOLDER_SEEDS[0]), now())
            .await
            .unwrap_or_else(|e| panic!("[{tag}] root_authorizes_author reads: {e}")),
        AuthorAuthority::Inherent,
        "[{tag}] I2404: a holder in force authors for the bundle root"
    );
    assert_eq!(
        root_authorizes_author(d, &root, &node, now())
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
    use crate::federation::replication::admission::WriteOrigin;
    let origin = match door {
        Door::Authored => WriteOrigin::Authored,
        Door::Wire => WriteOrigin::Wire,
    };
    let _ =
        super::ingest::put_statement_with_origin(d, st, None, super::ingest::INGEST_TIER, origin)
            .await;
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
/// - **I2460 (a)** names no bundle, none held: held, then lands at import;
/// - **I2461 (b)** names no bundle, the lineage held: lands (audit-only id);
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
        landed(none, &a).await,
        "[{tag} {door:?}] I2460: the import lands it"
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
    put_at(held, &b, door).await;
    assert!(
        landed(held, &b).await,
        "[{tag} {door:?}] I2461: no bundle named, the lineage held: lands"
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
