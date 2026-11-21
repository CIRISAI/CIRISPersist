//! v62.0.0 (RL-fix2b; CC 5.3.4, lead ruling (A): one rule, every serve path)
//! — **I2253: the JSON attestation serve plane waits in the SQL**, on sqlite
//! and postgres. A node whose own standing chain reaches no root (its node
//! key set, no root accepted) pages `list_attestations_since`,
//! `list_attestations_since_by_prefixes` and the #1225 subject read past the
//! federation-tier rows that wait, TO THE END: no page stalls and none is
//! truncated, because the rows are excluded before the page is cut. The
//! wire-index point read hands none of them out. Persist's own reads
//! (`as_internal_read`: the consent sweep, the key plane's walk, the held
//! check) still see every row. Once the node is rooted (the bundle's holders
//! found a trust root, it charters itself, THIS node accepts it) the same
//! walks return every row, the waiting ones included. The Attestation wire
//! hash advertisement follows the same rule.
//!
//! **I2254** — a store with no node key is not rooted outside lib tests.

use crate::federation::edition2::fixture_switch as e2;
use crate::federation::subject_read_1225_invariants::bodies as n;
use crate::federation::FederationDirectory;

/// Every id `list_attestations_since` serves, `limit` per page, to the end.
async fn since_walk(d: &dyn FederationDirectory, limit: u32) -> Vec<String> {
    let mut out = Vec::new();
    let mut since = None;
    for _ in 0..1_000 {
        let page = d
            .list_attestations_since(since.clone(), limit)
            .await
            .unwrap();
        let Some(last) = page.last() else {
            return out;
        };
        since = Some(last.resume_pair());
        out.extend(page.iter().map(|r| r.attestation.attestation_id.clone()));
    }
    panic!("the walk does not end");
}

/// Every id the family read serves, `limit` per page, to the end.
async fn prefix_walk(d: &dyn FederationDirectory, family: &str, limit: i64) -> Vec<String> {
    let mut out = Vec::new();
    let mut since = None;
    for _ in 0..1_000 {
        let p = d
            .list_attestations_since_by_prefixes(since.clone(), &[family.to_owned()], limit)
            .await
            .unwrap();
        out.extend(p.items.iter().map(|r| r.attestation.attestation_id.clone()));
        match p.next_cursor {
            Some(c) => since = Some(c),
            None => return out,
        }
    }
    panic!("the family walk does not end");
}

/// Every Attestation hash the wire index advertises, to the end.
async fn advertised(d: &dyn FederationDirectory) -> Vec<String> {
    let mut out = Vec::new();
    let mut after: Option<String> = None;
    for _ in 0..1_000 {
        let page = d
            .list_wire_hashes_since("Attestation", after.as_deref(), 2)
            .await
            .unwrap();
        let Some(last) = page.last().cloned() else {
            return out;
        };
        after = Some(last);
        out.extend(page);
    }
    panic!("the advertisement walk does not end");
}

/// The wire hash of each row `ids` names, as stored.
async fn hashes_of(d: &dyn FederationDirectory, ids: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for id in ids {
        let key = crate::federation::wire_index::record_key(&[("attestation_id", id.as_str())]);
        out.push(
            crate::federation::wire_index::entry_as_stored(d, "Attestation", &key)
                .await
                .unwrap()
                .expect("the row hashes"),
        );
    }
    out
}

/// I2253 on one backend whose node key is `e2::kid("i2253-node")`.
pub(crate) async fn body(d: &dyn FederationDirectory, tag: &str) {
    let (a, k) = n::keys(d, tag).await;
    let mut mine = Vec::new();
    for i in 0..5 {
        mine.push(n::put_naming(d, &a, &[&k], n::DIM, n::at(50 - i), None).await);
    }
    // Rootless: every walk pages past the five to the end.
    let since = since_walk(d, 2).await;
    assert!(
        mine.iter().all(|id| !since.contains(id)),
        "[{tag}] I2253: the federation-tier rows wait in list_attestations_since"
    );
    let fam = prefix_walk(d, "chat:", 2).await;
    assert!(
        mine.iter().all(|id| !fam.contains(id)),
        "[{tag}] I2253: and in the family read"
    );
    let (named, _) = n::walk(d, &k, n::DIM, 2).await;
    assert!(named.is_empty(), "[{tag}] I2253: and in the subject read");
    // The advertisement and the point read: no waiting row is advertised,
    // and none is handed out.
    let hashes = hashes_of(d, &mine).await;
    let ads = advertised(d).await;
    assert!(
        hashes.iter().all(|h| !ads.contains(h)),
        "[{tag}] I2253: a waiting row's hash is not advertised"
    );
    assert!(
        d.lookup_signed_record_by_content_hash("Attestation", &hashes[0])
            .await
            .unwrap()
            .is_none(),
        "[{tag}] I2253: nor handed out by the point read"
    );
    let internal = crate::federation::edition2::serve::as_internal_read(since_walk(d, 2)).await;
    assert!(
        mine.iter().all(|id| internal.contains(id)),
        "[{tag}] I2253: persist's own read sees every row"
    );

    // Rooted: the same walks, the same paging, every row.
    crate::federation::edition2::fixture_trust_root::rooted_trust_root(
        d,
        &crate::federation::edition2::fixture_genesis::HOLDER_SEEDS,
        "quorum:2/3",
    )
    .await;
    let since = since_walk(d, 2).await;
    assert!(
        mine.iter().all(|id| since.contains(id)),
        "[{tag}] I2253: rooted, list_attestations_since serves them"
    );
    let fam = prefix_walk(d, "chat:", 2).await;
    assert!(
        mine.iter().all(|id| fam.contains(id)),
        "[{tag}] I2253: rooted, the family read serves them"
    );
    let (named, _) = n::walk(d, &k, n::DIM, 2).await;
    assert_eq!(
        named.len(),
        mine.len(),
        "[{tag}] I2253: rooted, the subject read"
    );
}

/// **I2254** — a store with no node key is a node that is not rooted, in
/// every build (the serve wait applies); its MIRROR: the same store with a
/// node key and a rooted trust root it accepts is rooted.
pub(crate) async fn i2254_body<B>(b: &B, seed: &str, tag: &str)
where
    B: test_support::SetsNodeKey + FederationDirectory,
{
    use crate::federation::edition2::serve::this_node_is_rooted;
    assert!(b.node_key_id().is_none(), "[{tag}] I2254: precondition");
    assert!(
        !this_node_is_rooted(b).await.unwrap(),
        "[{tag}] I2254: no node key is no root (the wait applies)"
    );
    let st = crate::federation::edition2::serve::serve_standing(b)
        .await
        .unwrap();
    assert!(
        st.node_key_id.is_none() && !st.rooted && st.withholds_federation_tier,
        "[{tag}] I2254: the host-readable standing says so: {st:?}"
    );
    test_support::root_the_serving_node(b, seed).await;
    assert!(
        this_node_is_rooted(b).await.unwrap(),
        "[{tag}] I2254 mirror: a node key and a root it accepts is rooted"
    );
    let st = crate::federation::edition2::serve::serve_standing(b)
        .await
        .unwrap();
    assert!(
        st.node_key_id.is_some() && st.rooted && !st.withholds_federation_tier,
        "[{tag}] I2254 mirror: and the standing reads it: {st:?}"
    );
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i2254_no_node_key_is_not_rooted_sqlite() {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(i2254_body(&b, "i2254-node", "sqlite")).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i2254_no_node_key_is_not_rooted_postgres() {
    use crate::store::Backend as _;
    let Some(dsn) = crate::test_pg::empty_dsn() else {
        eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
        return;
    };
    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(i2254_body(&b, "i2254-node", "postgres")).await;
}

/// v62.0.0 (RL-fix2c) — **the ONE shared helper** the raw-backend serve
/// witnesses use: make the store a node (a node key) whose own standing
/// chain is ROOTED (`fixture_trust_root::rooted_trust_root`: the bundle's
/// holders found a trust root, it charters itself, THIS node accepts it), so
/// a stranger is served its federation-tier rows exactly as before RL-fix2.
pub(crate) mod test_support {
    use crate::federation::FederationDirectory;

    /// A raw backend whose node key a witness can set.
    pub(crate) trait SetsNodeKey: Sync {
        /// Set this store's node key.
        fn set_test_node_key(&self, key: &str);
    }

    #[cfg(feature = "sqlite")]
    impl SetsNodeKey for crate::store::sqlite::SqliteBackend {
        fn set_test_node_key(&self, key: &str) {
            self.set_node_key_id(key);
        }
    }

    #[cfg(feature = "postgres")]
    impl SetsNodeKey for crate::store::postgres::PostgresBackend {
        fn set_test_node_key(&self, key: &str) {
            self.set_node_key_id(key);
        }
    }

    /// Give `b` the node key `kid(seed)` (unless it has one) and stand up a
    /// rooted trust root it accepts. Returns the node key.
    pub(crate) async fn root_the_serving_node<B>(b: &B, seed: &str) -> String
    where
        B: SetsNodeKey + FederationDirectory,
    {
        let node = match b.node_key_id() {
            Some(n) => n,
            None => {
                let n = crate::federation::edition2::fixture_switch::kid(seed);
                b.set_test_node_key(&n);
                n
            }
        };
        root_this_node(b).await;
        node
    }

    /// Stand up a rooted trust root on a store that already has a node key
    /// (an `Engine`'s directory).
    ///
    /// # Panics
    /// The store has no node key.
    pub(crate) async fn root_this_node(d: &(dyn FederationDirectory + '_)) {
        assert!(
            d.node_key_id().is_some(),
            "root_this_node: the store has no node key (use root_the_serving_node)"
        );
        crate::federation::edition2::fixture_trust_root::rooted_trust_root(
            d,
            &crate::federation::edition2::fixture_genesis::HOLDER_SEEDS,
            "quorum:2/3",
        )
        .await;
    }
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i2253_the_json_serve_plane_waits_in_the_sql_sqlite() {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    b.set_node_key_id(e2::kid("i2253-node"));
    Box::pin(body(&b, "sqlite")).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i2253_the_json_serve_plane_waits_in_the_sql_postgres() {
    use crate::store::Backend as _;
    let Some(dsn) = crate::test_pg::empty_dsn() else {
        eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
        return;
    };
    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    b.set_node_key_id(e2::kid("i2253-node"));
    Box::pin(body(&b, "postgres")).await;
}
