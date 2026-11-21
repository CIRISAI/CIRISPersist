//! v62.0.0 (RL-fix11; lead ruling 2026-11-21, CC 5.3.4) — **under the
//! rootless serve rule the parties to a row are its subject and EVERY key
//! that signed a verifying voice of it** (`serve::is_party_to_row`), plus
//! whom the row's own family designates. Through the serve feed
//! (`serve::statements_served_to`) of a ROOTLESS node (no node key, so no
//! root it accepts), on sqlite and postgres, over a counted root grant that
//! two holders voiced and that has concluded:
//!
//! - **I2412** the SECOND voice's signer (a holder who is neither the row's
//!   attester nor its subject) receives the concluded row's voices;
//! - **I2413** a stranger receives none of them;
//! - **I2414** an anonymous reader receives none of them, as before.

use super::fixture_genesis as fg;
use super::fixture_switch as e2;
use super::names::RowId;
use super::scope_resolution_invariants as sr;
use crate::federation::trust_root::INFRA_SERVE_SCOPE;
use crate::federation::FederationDirectory;

/// The statements of row `id` that `requester` is served.
async fn served_of(d: &dyn FederationDirectory, id: &RowId, requester: Option<&str>) -> usize {
    let mut cursor = None;
    let mut n = 0;
    loop {
        let page = super::serve::statements_served_to(d, cursor.as_ref(), 256, requester)
            .await
            .expect("the serve feed reads");
        n += page
            .statements
            .iter()
            .filter(|s| RowId::of_statement(&s.bytes).as_ref() == Some(id))
            .count();
        if page.next.is_none() {
            return n;
        }
        cursor = page.next;
    }
}

/// I2412–I2414 on one directory with no node key.
pub(crate) async fn parties_body(d: &dyn FederationDirectory, tag: &str) {
    assert!(
        d.node_key_id().is_none(),
        "[{tag}] a rootless node: no node key"
    );
    fg::install_v2(d).await.expect("the ceremony installs");
    let (worker, _owner) = sr::worker_with_owner(d, "rl11").await;
    let head = super::genesis::genesis_in_force(d)
        .await
        .expect("genesis")
        .tips()
        .first()
        .expect("a tip")
        .object_id;
    let at = sr::grant_instant(d).await;
    let grant = sr::land_grant(d, &worker, INFRA_SERVE_SCOPE, &head, at, "I2412").await;
    let id = super::voices::carried_row_id(&grant).expect("a row id");
    let c = fg::bundle_v2();
    let second = c.holder_identity_ref(1).to_owned();
    assert_ne!(
        grant.attesting_key_id, second,
        "[{tag}] the second voice is not the attester"
    );
    assert_ne!(grant.attested_key_id, second, "[{tag}] nor the subject");

    assert_eq!(
        served_of(d, &id, Some(&second)).await,
        2,
        "[{tag}] I2412: the second voice's signer receives both voices of the row it signed"
    );
    assert_eq!(
        served_of(d, &id, Some(&e2::kid("rl11-stranger"))).await,
        0,
        "[{tag}] I2413: a stranger receives none"
    );
    assert_eq!(
        served_of(d, &id, None).await,
        0,
        "[{tag}] I2414: an anonymous reader receives none, as before"
    );
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i2412_the_parties_to_a_row_sqlite() {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(parties_body(&b, "sqlite")).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i2412_the_parties_to_a_row_postgres() {
    use crate::store::Backend as _;
    let Some(dsn) = crate::test_pg::empty_dsn() else {
        eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
        return;
    };
    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(parties_body(&b, "postgres")).await;
}
