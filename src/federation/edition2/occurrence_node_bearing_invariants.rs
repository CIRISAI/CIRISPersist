//! **I3040–I3041** (wave O1; E7's finding; CC 3.2 "Infrastructure does not
//! vote", CC 3.3.6): `is_node_bearing_key` reads the edition-2 facts, on
//! sqlite and postgres.
//!
//! - I3040: a key whose own edition-2 `key:record` carries `node` is
//!   node-bearing; and a non-person key bound by an edition-2 bind under a
//!   node identity (the node's statement plus the key's own) is
//!   node-bearing through that occurrence, its own voice the agreement.
//! - I3041: a user key is not node-bearing, and a node cannot make it so: a
//!   bind of a person's key under a node identity is refused
//!   `occurrence_binds_machine_to_person`.

use ciris_crypto::composite::CompositeSigningKey;
use ciris_verify_core::cde::Value;
use ciris_verify_core::edition2::sign_row_statement;

use super::door_invariants::fixture::{iref, key, key_record, map};
use super::ingest::{put_statement, StatementOutcome, INGEST_TIER};
use super::occurrence::OCCURRENCE_FAMILY;
use crate::federation::{
    is_node_bearing_key, malformed_row, occurrence_agreed_from, Error, FederationDirectory,
};

fn now_ms() -> u64 {
    u64::try_from(crate::host::clock::now().timestamp_millis()).unwrap()
}

async fn bind(
    d: &dyn FederationDirectory,
    signer: &CompositeSigningKey,
    iss: &str,
    identity: &str,
    occurrence: &str,
    device_class: &str,
    asserted_at: u64,
) -> Vec<u8> {
    // CC 3.3.6.4: the roster row the bind stands on.
    let head = super::occurrence::current_roster_head(d, identity)
        .await
        .unwrap()
        .expect("the identity's key record is held");
    let m = vec![
        ("asserted_at", Value::Uint(asserted_at)),
        ("author", Value::Text(identity.to_owned())),
        ("identity_key_id", Value::Text(identity.to_owned())),
        ("occurrence_key_id", Value::Text(occurrence.to_owned())),
        ("device_class", Value::Text(device_class.to_owned())),
        (
            "refs",
            map(vec![(
                "head",
                ciris_verify_core::edition2::row_ref(&head.0),
            )]),
        ),
    ];
    sign_row_statement(
        signer,
        iss,
        occurrence,
        "scores",
        OCCURRENCE_FAMILY,
        &map(m),
        vec![],
    )
    .unwrap()
}

async fn put(d: &dyn FederationDirectory, st: &[u8]) -> Result<StatementOutcome, Error> {
    Box::pin(put_statement(d, st, None, INGEST_TIER)).await
}

pub(crate) async fn body(d: &dyn FederationDirectory) {
    let node = key(120);
    let service = key(121);
    let user = key(122);
    let t = now_ms();
    put(
        d,
        &key_record(&node, &["node"], t - 86_400_000, Some(t + 200 * 86_400_000)),
    )
    .await
    .unwrap();
    put(d, &key_record(&service, &["primitive"], 0, None))
        .await
        .unwrap();
    put(d, &key_record(&user, &["user"], 0, None))
        .await
        .unwrap();
    let (n, s, u) = (iref(&node), iref(&service), iref(&user));

    // I3040: the key's own record.
    assert!(
        is_node_bearing_key(d, &n).await.unwrap(),
        "I3040: a node-typed key:record is node-bearing"
    );
    assert!(
        !is_node_bearing_key(d, &s).await.unwrap(),
        "I3040: unbound, a primitive key is not"
    );
    // I3040: a bind under the node, the key's own voice first.
    let at = t - 3_600_000;
    assert!(matches!(
        put(d, &bind(d, &service, &s, &n, &s, "service", at).await).await,
        Ok(StatementOutcome::Voice { .. })
    ));
    assert!(matches!(
        put(d, &bind(d, &node, &n, &n, &s, "service", at).await).await,
        Ok(StatementOutcome::Row { .. })
    ));
    assert!(
        occurrence_agreed_from(d, &n, &s).await.unwrap().is_some(),
        "I3040: the key's own voice is its agreement"
    );
    assert!(
        is_node_bearing_key(d, &s).await.unwrap(),
        "I3040: bound under a node, with its agreement, it is node-bearing"
    );

    // I3041: a user key is not node-bearing, and no node bind makes it so.
    assert!(
        !is_node_bearing_key(d, &u).await.unwrap(),
        "I3041: a user key is not node-bearing"
    );
    let e = put(d, &bind(d, &user, &u, &n, &u, "laptop", at).await)
        .await
        .unwrap_err();
    assert!(
        matches!(&e, Error::MalformedRow { reason, .. }
            if *reason == malformed_row::OCCURRENCE_BINDS_MACHINE_TO_PERSON),
        "I3041: {e}"
    );
    assert!(
        !is_node_bearing_key(d, &u).await.unwrap(),
        "I3041: still not node-bearing"
    );
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i3040_i3041_sqlite() {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(body(&b)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i3040_i3041_postgres() {
    use crate::store::Backend as _;
    let Some(dsn) = crate::test_pg::empty_dsn() else {
        return;
    };
    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(body(&b)).await;
}
