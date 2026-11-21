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
    let _ = e2::put_statement(d, &stray).await;
    let stray_id = super::group_fixtures::row_id_of(&stray);
    assert_eq!(
        super::fold::why_held(d, &stray_id)
            .await
            .unwrap_or_else(|e| panic!("[{tag}] why_held reads: {e}"))
            .map(|h| h.reason),
        Some(super::fold::reason::gc8::TRUST_ROOT_HEAD_STALE.to_owned()),
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
