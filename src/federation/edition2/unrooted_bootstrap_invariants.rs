//! v62.0.0 (BIND-6a; CC part_5 l.1129, CC 5.3.4; a rootless node RUNS THE
//! MESH) — **an unrooted node serves everything a peer needs to root it, and
//! nothing else waits less than it did.**
//!
//! - **I6636** (pure): the row test of the serve wait
//!   ([`serve::row_waits_unrooted`], whose SQL twin is
//!   `read_plan::served_while_unrooted_sql`, one list) exempts every
//!   bootstrap kind the statement test exempts and the allegiance rows: a key
//!   record, a key revocation, an occurrence bind, a typed revocation, a
//!   seat's route re-bind, the accord's invocation and lifecycle rows, an
//!   owner binding at `federation` (BIND-6b: an acceptance edge only through
//!   I6639's owner read). An ordinary
//!   federation row still waits; a row at a non-commons placement never does.
//! - **I6637** (sqlite + postgres): on a store whose node key is set and
//!   which reaches no root, this node's OWN `key:record:v1` row is returned by
//!   the waited held read (`list_attestations_since`), its hash is advertised
//!   (`list_wire_hashes_since("Attestation")`) and the point read
//!   (`lookup_signed_record_by_content_hash`) hands its bytes out; an ordinary
//!   federation row of the same store stays withheld on all three. BIND-6:
//!   the held reads stop waiting (the ordinary row is returned and
//!   advertised), `may_receive` withholds it from a peer that is no party,
//!   and the point read keeps its wait.
//! - **I6638** (BIND-6, sqlite + postgres): the rooted wait is
//!   `may_receive`'s, with the parties, this node and persist's own reads
//!   exempt, the rooting read once per `ServeRooting` handle.

use crate::federation::edition2::fixture_switch as e2;
use crate::federation::edition2::serve;
use crate::federation::types::{attestation_tier, attestation_type, cohort_scope};
use crate::federation::{Attestation, FederationDirectory};

fn row(dimension: &str, scope: &str) -> Attestation {
    let mut a = crate::federation::genesis::ordinary_scores_row("i6636", "k");
    a.attestation_type = attestation_type::SCORES.to_owned();
    a.cohort_scope = scope.to_owned();
    a.tier = attestation_tier::FEDERATION.to_owned();
    a.attestation_envelope = serde_json::json!({ "dimension": dimension, "score": 1.0 });
    a
}

/// **I6636.**
#[test]
fn i6636_every_bootstrap_and_allegiance_kind_crosses_unrooted() {
    for dim in [
        crate::federation::key_plane::KEY_RECORD_DIMENSION,
        crate::federation::key_plane::KEY_REVOCATION_DIMENSION,
        crate::federation::key_plane::IDENTITY_OCCURRENCE_DIMENSION,
        "revocation:node:compromise",
        crate::federation::transport_rebind::REBIND_DIMENSION,
        "accord:invoke:constitutional:h1",
        "accord:lifecycle:retire",
    ] {
        assert!(
            !serve::row_waits_unrooted(&row(dim, cohort_scope::FEDERATION)),
            "I6636: `{dim}` at federation crosses before Rooted"
        );
    }
    let mut binding = row(
        crate::federation::types::owner_binding::DIMENSION,
        cohort_scope::FEDERATION,
    );
    binding.attestation_type = attestation_type::DELEGATES_TO.to_owned();
    assert!(
        !serve::row_waits_unrooted(&binding),
        "I6636: an owner binding at federation is an allegiance row"
    );
    assert!(
        serve::row_waits_unrooted(&row("trust:demo:v1", cohort_scope::FEDERATION)),
        "I6636: an ordinary federation row still waits"
    );
    // v62.0.0 (BIND-6b) — an acceptance edge is an allegiance row only as
    // THIS node's owner's own (a directory read, I6639): the pure test
    // holds every acceptance edge.
    assert!(
        serve::row_waits_unrooted(&row(
            crate::federation::trust_root::TRUST_ACCEPTS_DIMENSION,
            cohort_scope::FEDERATION
        )),
        "I6636 (BIND-6b): the pure test holds an acceptance edge"
    );
    assert!(
        serve::row_waits_unrooted(&row("key:recordx", cohort_scope::FEDERATION)),
        "I6636: a dimension that only begins like a key record waits (the prefix ends at `:`)"
    );
    assert!(
        !serve::row_waits_unrooted(&row("trust:demo:v1", cohort_scope::SELF)),
        "I6636: a non-commons row never waits (its audience rule is the serve path's)"
    );
}

async fn held(d: &dyn FederationDirectory) -> Vec<Attestation> {
    let mut out = Vec::new();
    let mut since = None;
    for _ in 0..1_000 {
        let page = d
            .list_attestations_since(since.clone(), 50)
            .await
            .expect("the held read");
        let Some(last) = page.last() else {
            return out;
        };
        since = Some(last.resume_pair());
        out.extend(page.into_iter().map(|s| s.attestation));
    }
    panic!("the walk does not end");
}

async fn advertised(d: &dyn FederationDirectory) -> Vec<String> {
    let mut out = Vec::new();
    let mut after: Option<String> = None;
    for _ in 0..1_000 {
        let page = d
            .list_wire_hashes_since("Attestation", after.as_deref(), 50)
            .await
            .expect("the advertisement");
        let Some(last) = page.last().cloned() else {
            return out;
        };
        after = Some(last);
        out.extend(page);
    }
    panic!("the advertisement walk does not end");
}

/// **I6637** on a store whose node key is `e2::kid("i6637-node")`.
pub(crate) async fn i6637_an_unrooted_node_serves_its_own_key_record(
    d: &dyn FederationDirectory,
    tag: &str,
) {
    assert!(
        !serve::rooted_for_serve(d).await.expect("the standing read"),
        "[{tag}] I6637: precondition, this node reaches no root"
    );
    let node = e2::put_key(d, "i6637-node", &["node"]).await;
    let mut ordinary =
        crate::federation::genesis::ordinary_scores_row(&uuid::Uuid::new_v4().to_string(), &node);
    ordinary.cohort_scope = cohort_scope::FEDERATION.to_owned();
    let ordinary = e2::row_of(&ordinary, "i6637-node");
    e2::put_signed(d, &ordinary)
        .await
        .expect("I6637: the ordinary row");
    let all = serve::as_internal_read(held(d)).await;
    let own = all
        .iter()
        .find(|a| {
            a.attested_key_id == node
                && crate::federation::admission::envelope_dimension(&a.attestation_envelope)
                    == Some(crate::federation::key_plane::KEY_RECORD_DIMENSION)
        })
        .cloned()
        .unwrap_or_else(|| panic!("[{tag}] I6637 premise: the node's key record row is held"));
    let ord = all
        .iter()
        .find(|a| a.attestation_id == e2::rid(&ordinary))
        .cloned()
        .unwrap_or_else(|| panic!("[{tag}] I6637 premise: the ordinary row is held"));
    let waited = held(d).await;
    let ads = advertised(d).await;
    let own_hash = crate::federation::wire_index::attestation_wire_hash_hex(&own);
    let ord_hash = crate::federation::wire_index::attestation_wire_hash_hex(&ord);
    assert!(
        waited
            .iter()
            .any(|a| a.attestation_id == own.attestation_id),
        "[{tag}] I6637: the waited held read returns this node's own key record"
    );
    assert!(
        ads.contains(&own_hash),
        "[{tag}] I6637: its hash is advertised"
    );
    assert!(
        d.lookup_signed_record_by_content_hash("Attestation", &own_hash)
            .await
            .expect("the point read")
            .is_some(),
        "[{tag}] I6637: the point read hands it out"
    );
    // v62.0.0 (BIND-6) — the held reads no longer wait: the ordinary row is
    // returned and advertised (a HELD read is what this node holds); the
    // per-recipient check withholds it from a peer that is no party, and the
    // point read keeps its wait until Edge confirms its fetch sub-paths.
    assert!(
        waited
            .iter()
            .any(|a| a.attestation_id == ord.attestation_id)
            && ads.contains(&ord_hash),
        "[{tag}] I6637 (BIND-6): the held reads return and advertise the ordinary row"
    );
    assert!(
        d.lookup_signed_record_by_content_hash("Attestation", &ord_hash)
            .await
            .expect("the point read")
            .is_none(),
        "[{tag}] I6637: the point read withholds the ordinary row"
    );
    let peer = e2::put_key(d, "i6637-peer", &["node"]).await;
    assert_eq!(
        crate::federation::replication_audience::may_receive(d, &peer, &ord)
            .await
            .expect("may_receive"),
        crate::federation::replication_audience::Verdict::No(
            crate::federation::replication_audience::Reason::NotInAudience
        ),
        "[{tag}] I6637 (BIND-6): may_receive withholds the waiting row from a peer that is no party"
    );
    assert_eq!(
        crate::federation::replication_audience::may_receive(d, &peer, &own)
            .await
            .expect("may_receive"),
        crate::federation::replication_audience::Verdict::Yes(
            crate::federation::replication_audience::Reason::Public
        ),
        "[{tag}] I6637 (BIND-6): and passes this node's own key record"
    );
}

/// **I6638** (BIND-6; Edge's five conditions) — the rooted wait in
/// `may_receive`, on a store that reaches no root: a waiting commons row is
/// `No(NotInAudience)` to a peer that is no party; its ORIGIN and the key it
/// REFERS TO still receive it (the parties are exempt, as the statement
/// serve's `commons_servable` exempts them); this node itself as the
/// recipient, persist's own read (`as_internal_read`) and a handle that
/// already knows the node is rooted (`ServeRooting::known(true)`) are not
/// waited; once the node is rooted the same call answers `Yes(Public)`.
pub(crate) async fn i6638_the_rooted_wait_is_may_receives(d: &dyn FederationDirectory, tag: &str) {
    use crate::federation::replication_audience::{
        may_receive, may_receive_with, Reason, ServeRooting, Verdict,
    };
    let node = e2::put_key(d, "i6638-node", &["node"]).await;
    let author = e2::put_key(d, "i6638-author", &["user"]).await;
    let subject = e2::put_key(d, "i6638-subject", &["user"]).await;
    let peer = e2::put_key(d, "i6638-peer", &["node"]).await;
    let mut r =
        crate::federation::genesis::ordinary_scores_row(&uuid::Uuid::new_v4().to_string(), &author);
    r.attested_key_id = subject.clone();
    r.cohort_scope = cohort_scope::FEDERATION.to_owned();
    let r = e2::row_of(&r, "i6638-author");
    e2::put_signed(d, &r).await.expect("I6638: the row");
    let row = d
        .get_attestation(&e2::rid(&r))
        .await
        .expect("reads")
        .unwrap_or_else(|| panic!("[{tag}] I6638 premise: the row is held"));
    assert!(
        serve::row_waits_unrooted(&row),
        "[{tag}] I6638 premise: it waits"
    );
    let v = |x: Result<Verdict, crate::federation::Error>| x.expect("may_receive");
    assert_eq!(
        v(may_receive(d, &peer, &row).await),
        Verdict::No(Reason::NotInAudience),
        "[{tag}] I6638: a peer that is no party waits"
    );
    assert_eq!(
        v(may_receive(d, &author, &row).await),
        Verdict::Yes(Reason::Origin),
        "[{tag}] I6638: the origin is exempt"
    );
    assert_eq!(
        v(may_receive(d, &subject, &row).await),
        Verdict::Yes(Reason::RefersTo),
        "[{tag}] I6638: the key it refers to is exempt"
    );
    assert_eq!(
        v(may_receive(d, &node, &row).await),
        Verdict::Yes(Reason::Public),
        "[{tag}] I6638: this node itself is not waited (the put-time gate)"
    );
    assert_eq!(
        v(serve::as_internal_read(may_receive(d, &peer, &row)).await),
        Verdict::Yes(Reason::Public),
        "[{tag}] I6638: persist's own read is not waited"
    );
    assert_eq!(
        v(may_receive_with(d, &peer, &row, &ServeRooting::known(true)).await),
        Verdict::Yes(Reason::Public),
        "[{tag}] I6638: a sweep handle that read the node rooted passes"
    );
    let sweep = ServeRooting::new();
    for _ in 0..3 {
        assert_eq!(
            v(may_receive_with(d, &peer, &row, &sweep).await),
            Verdict::No(Reason::NotInAudience),
            "[{tag}] I6638: one handle, the same answer every row"
        );
    }
    crate::federation::edition2::serve_wait_invariants::test_support::root_this_node(d).await;
    assert_eq!(
        v(may_receive(d, &peer, &row).await),
        Verdict::Yes(Reason::Public),
        "[{tag}] I6638: rooted, the peer receives it"
    );
}

/// **I6639** (BIND-6b; CC 5.3.4 l.1143 "a sender's OWN allegiance rows") —
/// an acceptance edge crosses before Rooted only where its signer is THIS
/// node's owner: on a store that reaches no root, whose node key is bound to
/// an owner (the real door), the owner's `trust:accepts:v1` edge does not
/// wait (`row_waits_unrooted_here`) and `may_receive` passes it to a peer
/// that is no party; a stranger's edge waits on both; before the node is
/// owned, the owner's edge waits too (no owner, no own allegiance row).
pub(crate) async fn i6639_only_the_owners_acceptance_edge_crosses(
    d: &dyn FederationDirectory,
    tag: &str,
) {
    use crate::federation::replication_audience::{may_receive, Reason, Verdict};
    let _ = e2::put_key(d, "i6639-node", &["node"]).await;
    let owner = e2::put_key(d, "i6639-owner", &["user"]).await;
    let stranger = e2::put_key(d, "i6639-stranger", &["user"]).await;
    let peer = e2::put_key(d, "i6639-peer", &["node"]).await;
    let edge = |signer: &str| {
        let mut a = row(
            crate::federation::trust_root::TRUST_ACCEPTS_DIMENSION,
            cohort_scope::FEDERATION,
        );
        a.attestation_type = attestation_type::DELEGATES_TO.to_owned();
        a.attestation_id = format!("i6639-{signer}");
        a.attesting_key_id = signer.to_owned();
        a.attested_key_id = "i6639-root".to_owned();
        a
    };
    let (mine, theirs) = (edge(&owner), edge(&stranger));
    let waits = |a: Attestation| async move {
        serve::row_waits_unrooted_here(d, &a)
            .await
            .expect("the row test")
    };
    assert!(
        waits(mine.clone()).await,
        "[{tag}] I6639: before the node is owned, no acceptance edge is its own"
    );
    crate::federation::admission::steward_liveness_test_support::bind_machine_owner(
        d,
        "i6639-owner",
        "i6639-node",
    )
    .await;
    assert!(
        !waits(mine.clone()).await,
        "[{tag}] I6639: this node's owner's acceptance edge crosses before Rooted"
    );
    assert!(
        waits(theirs.clone()).await,
        "[{tag}] I6639: a stranger's acceptance edge this node holds waits"
    );
    assert_eq!(
        may_receive(d, &peer, &mine).await.expect("may_receive"),
        Verdict::Yes(Reason::Public),
        "[{tag}] I6639: may_receive passes the owner's edge"
    );
    assert_eq!(
        may_receive(d, &peer, &theirs).await.expect("may_receive"),
        Verdict::No(Reason::NotInAudience),
        "[{tag}] I6639: and withholds the stranger's"
    );
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i6639_only_the_owners_acceptance_edge_crosses_sqlite() {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    b.set_node_key_id(e2::kid("i6639-node"));
    Box::pin(i6639_only_the_owners_acceptance_edge_crosses(&b, "sqlite")).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i6639_only_the_owners_acceptance_edge_crosses_postgres() {
    use crate::store::Backend as _;
    let Some(dsn) = crate::test_pg::empty_dsn() else {
        return;
    };
    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    b.set_node_key_id(e2::kid("i6639-node"));
    Box::pin(i6639_only_the_owners_acceptance_edge_crosses(
        &b, "postgres",
    ))
    .await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i6638_the_rooted_wait_is_may_receives_sqlite() {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    b.set_node_key_id(e2::kid("i6638-node"));
    Box::pin(i6638_the_rooted_wait_is_may_receives(&b, "sqlite")).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i6637_an_unrooted_node_serves_its_own_key_record_sqlite() {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    b.set_node_key_id(e2::kid("i6637-node"));
    Box::pin(i6637_an_unrooted_node_serves_its_own_key_record(
        &b, "sqlite",
    ))
    .await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i6638_the_rooted_wait_is_may_receives_postgres() {
    use crate::store::Backend as _;
    let Some(dsn) = crate::test_pg::empty_dsn() else {
        return;
    };
    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    b.set_node_key_id(e2::kid("i6638-node"));
    Box::pin(i6638_the_rooted_wait_is_may_receives(&b, "postgres")).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i6637_an_unrooted_node_serves_its_own_key_record_postgres() {
    use crate::store::Backend as _;
    let Some(dsn) = crate::test_pg::empty_dsn() else {
        return;
    };
    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    b.set_node_key_id(e2::kid("i6637-node"));
    Box::pin(i6637_an_unrooted_node_serves_its_own_key_record(
        &b, "postgres",
    ))
    .await;
}
